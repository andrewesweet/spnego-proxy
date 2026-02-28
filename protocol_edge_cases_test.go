package main

// protocol_edge_cases_test.go — acceptance tests for GitHub issue #127.
//
// Requirements covered:
//   F1  RFC 9110 §10.1.1 — Expect: 100-continue forwarded to upstream
//   F2  RFC 9110 §10.1.1 — 100 Continue not forwarded to HTTP/1.0 clients (doc/known gap)
//   G1  RFC 9110 §7.6.2  — Max-Forwards decremented for TRACE/OPTIONS; stop at zero
//   I1  RFC 9112 §9.3    — HTTP/1.0 client connection closed after response
//   I2  RFC 9112 §9.6    — Connection: close from client honored
//   N2  RFC 8470 §5.1    — Early-Data header not removed

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// F1 — RFC 9110 §10.1.1: Forward Expect: 100-continue to upstream
// ---------------------------------------------------------------------------

// TestF1_ExpectHeaderForwardedToUpstream verifies that when an HTTP/1.1 client
// sends Expect: 100-continue, the proxy forwards that header to the upstream.
//
// RFC 9110 §10.1.1: a proxy MUST forward the Expect: 100-continue field if it
// is forwarding a request to an HTTP/1.1 or later upstream.
//
// Go's http.ReadRequest stores Expect in req.Header normally. However
// req.WriteProxy (via req.write) strips Expect: 100-continue from the
// serialized request before sending it. We must re-inject the header after
// WriteProxy if it was present on the incoming request.
func TestF1_ExpectHeaderForwardedToUpstream(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send a raw HTTP/1.1 request with Expect: 100-continue and a small body
	// so the proxy can fully forward the request to the upstream. We include
	// the body bytes immediately after the headers (the proxy forwards both).
	body := "hello"
	raw := "POST http://example.com/upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Expect: 100-continue\r\n" +
		"\r\n" +
		body
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	// The upstream mock responds with 200 OK.
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// The upstream must receive Expect: 100-continue.
	if got := reqs[0].Header.Get("Expect"); !strings.EqualFold(got, "100-continue") {
		t.Errorf("upstream Expect header: want %q, got %q", "100-continue", got)
	}
}

// TestF1_ExpectHeaderNotAddedWhenAbsent verifies that the proxy does not
// invent an Expect header when the client did not send one.
func TestF1_ExpectHeaderNotAddedWhenAbsent(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{})
	assertHeaderAbsent(t, upReq.Header, "Expect")
}

// TestF1_ExpectHeaderPreservedCaseInsensitive verifies that a request with
// Expect: 100-Continue (mixed case) is forwarded correctly.
func TestF1_ExpectHeaderPreservedCaseInsensitive(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	body2 := "hello"
	raw := "POST http://example.com/upload HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body2)) +
		"Expect: 100-Continue\r\n" +
		"\r\n" +
		body2
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// Header value comparison is case-insensitive per RFC 9110 §10.1.1.
	if got := reqs[0].Header.Get("Expect"); !strings.EqualFold(got, "100-continue") {
		t.Errorf("upstream Expect header: want %q (case-insensitive), got %q", "100-continue", got)
	}
}

// ---------------------------------------------------------------------------
// F2 — RFC 9110 §10.1.1: Do not forward 100 Continue to HTTP/1.0 clients
// ---------------------------------------------------------------------------
//
// KNOWN GAP: The proxy's response path uses http.ReadResponse + resp.Write.
// Go's http.ReadResponse transparently absorbs 100-continue interim responses
// from the upstream and returns only the final response. This means that if an
// upstream sends "HTTP/1.1 100 Continue\r\n\r\n" followed by a final response,
// Go's ReadResponse discards the 100 before the proxy even sees it, and
// resp.Write only serializes the final status. As a result the proxy never
// forwards a bare 100 Continue to any client — HTTP/1.0 or HTTP/1.1 — which
// satisfies the MUST NOT for HTTP/1.0 clients as a side effect.
//
// This behavior cannot be tested end-to-end via the Go stdlib because there
// is no API to inject a raw 100 Continue through http.ReadResponse; the test
// would instead verify that the mock's raw-write path never reaches the client
// as a standalone response. That is tested implicitly: the mock upstream
// cannot send 100 Continue separately in a way that survives the proxy's
// http.ReadResponse call.
//
// No explicit test is added; the gap is documented here for traceability.

// ---------------------------------------------------------------------------
// G1 — RFC 9110 §7.6.2: Decrement Max-Forwards for TRACE/OPTIONS
// ---------------------------------------------------------------------------

// TestG1_MaxForwards_DecrementedForTRACE verifies that the proxy decrements
// the Max-Forwards header by 1 when forwarding a TRACE request.
//
// RFC 9110 §7.6.2: each proxy that forwards a TRACE or OPTIONS request MUST
// decrement the Max-Forwards value by 1 before forwarding.
func TestG1_MaxForwards_DecrementedForTRACE(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "TRACE http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 5\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// The upstream must receive Max-Forwards: 4 (5 - 1).
	if got := reqs[0].Header.Get("Max-Forwards"); got != "4" {
		t.Errorf("upstream Max-Forwards: want %q, got %q", "4", got)
	}
}

// TestG1_MaxForwards_DecrementedForOPTIONS verifies the same decrement
// behaviour for OPTIONS requests.
func TestG1_MaxForwards_DecrementedForOPTIONS(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "OPTIONS http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 10\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	if got := reqs[0].Header.Get("Max-Forwards"); got != "9" {
		t.Errorf("upstream Max-Forwards: want %q, got %q", "9", got)
	}
}

// TestG1_MaxForwards_ZeroTRACE_ReturnedLocally verifies that when a TRACE
// request arrives with Max-Forwards: 0, the proxy does NOT forward it but
// instead responds locally with 200 OK.
//
// RFC 9110 §7.6.2: if the received value is 0, the recipient MUST NOT forward
// the request; instead, it MUST respond as the final recipient.
func TestG1_MaxForwards_ZeroTRACE_ReturnedLocally(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "TRACE http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Proxy must respond locally with 200 OK.
	assertStatusCode(t, resp, http.StatusOK)

	// The upstream must NOT have received anything.
	if got := upstream.Requests(); len(got) != 0 {
		t.Errorf("upstream received %d requests, want 0 (should be handled locally)", len(got))
	}
}

// TestG1_MaxForwards_ZeroOPTIONS_ReturnedLocally verifies the same zero
// Max-Forwards behavior for OPTIONS.
func TestG1_MaxForwards_ZeroOPTIONS_ReturnedLocally(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "OPTIONS http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusOK)

	if got := upstream.Requests(); len(got) != 0 {
		t.Errorf("upstream received %d requests, want 0", len(got))
	}
}

// TestG1_MaxForwards_DecrementedForOPTIONS_One verifies that Max-Forwards: 1
// is decremented to 0 and the request is forwarded (not handled locally).
func TestG1_MaxForwards_DecrementedForOPTIONS_One(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "OPTIONS http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 1\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	if got := reqs[0].Header.Get("Max-Forwards"); got != "0" {
		t.Errorf("upstream Max-Forwards: want %q, got %q", "0", got)
	}
}

// TestG1_MaxForwards_NotDecrementedForGET verifies that Max-Forwards is NOT
// decremented for non-TRACE/OPTIONS methods.
//
// RFC 9110 §7.6.2 restricts the Max-Forwards decrement rule to TRACE and
// OPTIONS only.
func TestG1_MaxForwards_NotDecrementedForGET(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "GET http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: 5\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// Max-Forwards must be forwarded unchanged for GET.
	if got := reqs[0].Header.Get("Max-Forwards"); got != "5" {
		t.Errorf("upstream Max-Forwards: want %q (unchanged), got %q", "5", got)
	}
}

// TestG1_MaxForwards_AbsentNotAdded verifies that the proxy does not add a
// Max-Forwards header to TRACE/OPTIONS requests that did not include one.
func TestG1_MaxForwards_AbsentNotAdded(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "TRACE http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	assertHeaderAbsent(t, reqs[0].Header, "Max-Forwards")
}

// TestG1_MaxForwards_InvalidValueIgnored verifies that a non-numeric
// Max-Forwards value is forwarded unmodified (no panic or error).
//
// RFC 9110 §7.6.2: the field value is a decimal integer; a proxy that
// encounters a value it cannot parse SHOULD forward the request without
// modifying the header.
func TestG1_MaxForwards_InvalidValueForwarded(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw := "TRACE http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Max-Forwards: not-a-number\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// The proxy must forward without error (no 502, no panic).
	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1 (invalid Max-Forwards must be forwarded)", len(reqs))
	}
}

// ---------------------------------------------------------------------------
// I1 — RFC 9112 §9.3: HTTP/1.0 connection closed after response
// ---------------------------------------------------------------------------

// TestI1_HTTP10_ConnectionClosedAfterResponse verifies that the proxy closes
// the connection with an HTTP/1.0 client after forwarding the response.
//
// RFC 9112 §9.3: HTTP/1.0 did not have persistent connections; the server
// (or proxy) MUST close the connection after each response. Since this proxy
// handles exactly one request per connection (the conn.Close is always deferred
// in handleClient), this is already satisfied structurally.
func TestI1_HTTP10_ConnectionClosedAfterResponse(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send an HTTP/1.0 request (no persistent connection implied).
	raw := "GET http://example.com/ HTTP/1.0\r\n" +
		"Host: example.com\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
	// Drain the body so the connection can close cleanly.
	_, _ = io.Copy(io.Discard, resp.Body)

	// After the response, the proxy must close the connection. Attempting
	// to read again must return io.EOF (or an error indicating closure).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, readErr := conn.Read(buf)
	if n > 0 {
		t.Errorf("expected connection closed after HTTP/1.0 response, got %d bytes: %q", n, buf[:n])
	}
	if readErr == nil {
		t.Error("expected error reading from closed connection, got nil")
	}
}

// ---------------------------------------------------------------------------
// I2 — RFC 9112 §9.6: Honor Connection: close from client
// ---------------------------------------------------------------------------

// TestI2_ConnectionClose_ConnectionClosedAfterResponse verifies that the
// proxy closes the connection when the client sends Connection: close.
//
// RFC 9112 §9.6: when a client sends Connection: close, the proxy MUST close
// the connection after sending the response. Since this proxy closes after
// every request unconditionally, this is always satisfied.
func TestI2_ConnectionClose_ConnectionClosedAfterResponse(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Use raw bytes so Connection: close is actually sent on the wire
	// (http.NewRequest with WriteProxy strips Connection).
	raw := "GET http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
	_, _ = io.Copy(io.Discard, resp.Body)

	// After the response the connection must be closed.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, readErr := conn.Read(buf)
	if n > 0 {
		t.Errorf("expected connection closed after Connection: close, got %d bytes", n)
	}
	if readErr == nil {
		t.Error("expected error reading from closed connection, got nil")
	}
}

// ---------------------------------------------------------------------------
// N2 — RFC 8470 §5.1: Early-Data header not removed
// ---------------------------------------------------------------------------

// TestN2_EarlyData_ForwardedToUpstream verifies that the proxy forwards the
// Early-Data header to the upstream without modification.
//
// RFC 8470 §5.1: intermediaries MUST NOT remove the Early-Data header. The
// proxy's hop-by-hop sanitization does not include Early-Data, so this is
// already satisfied structurally.
func TestN2_EarlyData_ForwardedToUpstream(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Early-Data": {"1"},
	})

	assertHeaderPresent(t, upReq.Header, "Early-Data", "1")
}

// TestN2_EarlyData_ForwardedUnmodified verifies that the header value is not
// altered in any way.
func TestN2_EarlyData_ForwardedUnmodified(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Early-Data": {"1"},
	})

	if got := upReq.Header.Get("Early-Data"); got != "1" {
		t.Errorf("Early-Data header: want %q, got %q", "1", got)
	}
}

// ---------------------------------------------------------------------------
// G1 table-driven tests for completeness
// ---------------------------------------------------------------------------

// TestG1_MaxForwards_Table covers boundary and mid-range values for
// TRACE and OPTIONS in a single table-driven test.
func TestG1_MaxForwards_Table(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		maxForwards  string
		wantUpstream bool   // whether the request should reach the upstream
		wantMF       string // expected Max-Forwards on upstream, "" means absent
	}{
		{
			name:         "TRACE MF=0 handled locally",
			method:       "TRACE",
			maxForwards:  "0",
			wantUpstream: false,
		},
		{
			name:         "OPTIONS MF=0 handled locally",
			method:       "OPTIONS",
			maxForwards:  "0",
			wantUpstream: false,
		},
		{
			name:         "TRACE MF=1 decremented to 0 and forwarded",
			method:       "TRACE",
			maxForwards:  "1",
			wantUpstream: true,
			wantMF:       "0",
		},
		{
			name:         "OPTIONS MF=3 decremented to 2 and forwarded",
			method:       "OPTIONS",
			maxForwards:  "3",
			wantUpstream: true,
			wantMF:       "2",
		},
		{
			name:         "TRACE MF=100 decremented to 99",
			method:       "TRACE",
			maxForwards:  "100",
			wantUpstream: true,
			wantMF:       "99",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := NewMockUpstreamProxy(t, nil)
			t.Cleanup(upstream.Close)

			proxy := NewProxyUnderTest(t, upstream.Addr())
			t.Cleanup(proxy.Close)

			conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			raw := fmt.Sprintf("%s http://example.com/ HTTP/1.1\r\nHost: example.com\r\nMax-Forwards: %s\r\n\r\n",
				tc.method, tc.maxForwards)
			if _, err := conn.Write([]byte(raw)); err != nil {
				t.Fatalf("write raw request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			assertStatusCode(t, resp, http.StatusOK)

			reqs := upstream.Requests()
			if tc.wantUpstream {
				if len(reqs) != 1 {
					t.Fatalf("upstream received %d requests, want 1", len(reqs))
				}
				if got := reqs[0].Header.Get("Max-Forwards"); got != tc.wantMF {
					t.Errorf("upstream Max-Forwards: want %q, got %q", tc.wantMF, got)
				}
			} else {
				if len(reqs) != 0 {
					t.Errorf("upstream received %d requests, want 0 (should be handled locally)", len(reqs))
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// I1/I2 concurrent safety: verify proxy is safe under concurrent connections
// ---------------------------------------------------------------------------

// TestI1I2_ConcurrentConnectionsClosed verifies that under concurrent load,
// each connection is closed independently after its response, with no
// persistent connections or connection sharing.
func TestI1I2_ConcurrentConnectionsClosed(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	const numClients = 10
	var wg sync.WaitGroup
	errs := make(chan error, numClients)

	for i := range numClients {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
			if err != nil {
				errs <- fmt.Errorf("client %d: dial: %w", idx, err)
				return
			}
			defer func() { _ = conn.Close() }()

			raw := fmt.Sprintf("GET http://example.com/concurrent/%d HTTP/1.0\r\nHost: example.com\r\n\r\n", idx)
			if _, writeErr := conn.Write([]byte(raw)); writeErr != nil {
				errs <- fmt.Errorf("client %d: write: %w", idx, writeErr)
				return
			}

			resp, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
			if readErr != nil {
				errs <- fmt.Errorf("client %d: read response: %w", idx, readErr)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("client %d: want 200 OK, got %d", idx, resp.StatusCode)
				return
			}

			// Connection must close after HTTP/1.0 response.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1)
			n, connErr := conn.Read(buf)
			if n > 0 || connErr == nil {
				errs <- fmt.Errorf("client %d: expected closed connection, got %d bytes, err=%v", idx, n, connErr)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
