package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A1 — RFC 9110 §7.6.3: Via header appended on every forwarded message
// ---------------------------------------------------------------------------

// TestA1_RFC9110_ViaAppendedOnForwardedRequest verifies that a request with
// no prior Via header is forwarded with a Via entry containing the protocol
// version and proxy pseudonym.
func TestA1_RFC9110_ViaAppendedOnForwardedRequest(t *testing.T) {
	upReq := proxyRoundTrip(t, nil)

	via := upReq.Header.Get("Via")
	want := "HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA1_RFC9110_ViaPreservesExistingEntries verifies that existing Via
// entries from upstream proxies are preserved and our entry is appended.
func TestA1_RFC9110_ViaPreservesExistingEntries(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Via": {"1.1 other-proxy"},
	})

	via := upReq.Header.Get("Via")
	want := "1.1 other-proxy, HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA1_RFC9110_ViaAppendedOnResponse verifies that the proxy adds a Via
// header to responses relayed from the upstream back to the client.
func TestA1_RFC9110_ViaAppendedOnResponse(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/a1-resp", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertStatusCode(t, resp, http.StatusOK)

	via := resp.Header.Get("Via")
	want := "HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("response Via header: want %q, got %q", want, via)
	}
}

// ---------------------------------------------------------------------------
// A2 — RFC 9110 §7.6.3: Loop detection via own identifier in Via header
// ---------------------------------------------------------------------------

// TestA2_RFC9110_LoopDetectionReturns502 verifies that a request whose Via
// header already contains this proxy's pseudonym is rejected with 502 and
// not forwarded to the upstream.
func TestA2_RFC9110_LoopDetectionReturns502(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/a2-loop", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertStatusCode(t, resp, http.StatusBadGateway)

	wantPS := "spnego-proxy; error=proxy_loop_detected"
	if ps := resp.Header.Get("Proxy-Status"); ps != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, ps)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: proxy_loop_detected") {
		t.Errorf("body should contain error type, got: %q", body)
	}
	if !strings.Contains(string(body), "routing loop was detected") {
		t.Errorf("body should describe loop detection, got: %q", body)
	}

	// The upstream must NOT have received the request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	// Token acquisition must be skipped when a loop is detected.
	if calls := proxy.Provider.calls.Load(); calls != 0 {
		t.Errorf("expected 0 token provider calls, got %d", calls)
	}
}

// TestA2_RFC9110_DifferentPseudonymNotDetectedAsLoop verifies that a Via
// header containing a different proxy's identifier does not trigger loop
// detection — only this instance's own pseudonym indicates a loop.
func TestA2_RFC9110_DifferentPseudonymNotDetectedAsLoop(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Via": {"1.1 some-other-proxy"},
	})

	via := upReq.Header.Get("Via")
	want := "1.1 some-other-proxy, HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA2_RFC9110_SubstringPseudonymDetectedAsLoop documents that loop
// detection uses strings.Contains, so a Via entry containing our pseudonym
// as a substring triggers loop detection. This is acceptable because
// production pseudonyms use random hex suffixes, making prefix collisions
// extremely unlikely.
func TestA2_RFC9110_SubstringPseudonymDetectedAsLoop(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Via entry contains our pseudonym as a prefix of a longer identifier.
	req, _ := http.NewRequest("GET", "http://example.com/a2-substr", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym+"-extended")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// Current behavior: substring match triggers loop detection.
	assertStatusCode(t, resp, http.StatusBadGateway)

	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for injectVia
// ---------------------------------------------------------------------------

func TestInjectVia_EmptyHeader(t *testing.T) {
	h := make(http.Header)
	injectVia(h, "HTTP/1.1", "test-proxy")

	if got := h.Get("Via"); got != "HTTP/1.1 test-proxy" {
		t.Errorf("Via: want %q, got %q", "HTTP/1.1 test-proxy", got)
	}
}

func TestInjectVia_AppendsToExisting(t *testing.T) {
	h := http.Header{"Via": {"1.0 first-proxy"}}
	injectVia(h, "HTTP/1.1", "second-proxy")

	want := "1.0 first-proxy, HTTP/1.1 second-proxy"
	if got := h.Get("Via"); got != want {
		t.Errorf("Via: want %q, got %q", want, got)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for generateViaPseudonym
// ---------------------------------------------------------------------------

func TestGenerateViaPseudonym_HasPrefix(t *testing.T) {
	p := generateViaPseudonym()
	if !strings.HasPrefix(p, "spnego-proxy-") {
		t.Errorf("pseudonym %q should have prefix %q", p, "spnego-proxy-")
	}
}

func TestGenerateViaPseudonym_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		p := generateViaPseudonym()
		if seen[p] {
			t.Fatalf("duplicate pseudonym after %d iterations: %s", len(seen), p)
		}
		seen[p] = true
	}
}
