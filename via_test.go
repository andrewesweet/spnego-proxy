package main

import (
	"bufio"
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
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          http.NoBody,
			ContentLength: 0,
		}
	})
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/a1-resp", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/a2-loop", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusBadGateway)

	ps := resp.Header.Get("Proxy-Status")
	if !strings.Contains(ps, "proxy_loop_detected") {
		t.Errorf("Proxy-Status: want proxy_loop_detected, got %q", ps)
	}

	// The upstream must NOT have received the request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
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
	if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via %q should contain our pseudonym %q", via, testPseudonym)
	}
	if !strings.Contains(via, "some-other-proxy") {
		t.Errorf("Via %q should preserve the existing entry", via)
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
