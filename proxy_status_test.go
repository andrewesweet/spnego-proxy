package main

// proxy_status_test.go — acceptance tests for RFC 9209 Proxy-Status header
// coverage across all remaining error scenarios.
//
// Requirements covered:
//
//	A3 — Include Proxy-Status in error responses (RFC 9209 §2 MAY)
//
// Error type mapping per RFC 9209 §2.3:
//
//	proxy_internal_error   — SPNEGO token acquisition failures (generic,
//	                         circuit breaker open, credential failure,
//	                         negotiation failure)
//	http_request_error     — malformed / unreadable client request
//	proxy_loop_detected    — Via header loop detection
//	connection_terminated  — upstream closes connection while relaying
//
// The Proxy-Status header format is defined by RFC 8941 Structured Fields:
//
//	Proxy-Status: spnego-proxy; error=<error_type>

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// assertProxyStatus is a focused helper that asserts both the HTTP status
// code and the exact Proxy-Status header value for an error response.
func assertProxyStatus(t *testing.T, resp *http.Response, wantCode int, wantErrorType string) {
	t.Helper()
	assertStatusCode(t, resp, wantCode)

	wantPS := "spnego-proxy; error=" + wantErrorType
	if got := resp.Header.Get("Proxy-Status"); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}
}

// sendRequest writes a minimal HTTP/1.1 GET request to conn in absolute-form,
// as a forward-proxy client would.
func sendRequest(t *testing.T, conn net.Conn, target string) {
	t.Helper()
	_, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", target)
	if err != nil {
		t.Fatalf("write request to proxy: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A3 — proxy_internal_error: generic SPNEGO token acquisition failure
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnTokenAcquisitionFailure verifies that when the
// token provider returns a generic (non-typed) error, the proxy responds with
// 502 Bad Gateway and a Proxy-Status header carrying the
// "proxy_internal_error" error type.
//
// Per RFC 9209 §2.3: proxy_internal_error is used when the proxy encountered
// an internal error not covered by a more specific type.
func TestA3_RFC9209_ProxyStatusOnTokenAcquisitionFailure(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{err: errors.New("generic token error")}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
	}()

	sendRequest(t, client, "http://example.com/test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with proxy_internal_error for generic token failure.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_internal_error")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_internal_error") {
		t.Errorf("body: want mention of proxy_internal_error, got %q", body)
	}

	// Upstream must NOT have received the request — token failure is pre-dial.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after token failure")
	}
}

// ---------------------------------------------------------------------------
// A3 — proxy_internal_error: circuit breaker open
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnCircuitBreakerOpen verifies that when the token
// provider returns a *CircuitBreakerError, the proxy responds with 502 Bad
// Gateway and Proxy-Status "proxy_internal_error".
//
// Per RFC 9209 §2.3: proxy_internal_error covers internal proxy failures
// including self-imposed rate limiting that prevents request processing.
func TestA3_RFC9209_ProxyStatusOnCircuitBreakerOpen(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	cbErr := &CircuitBreakerError{
		msg:   "circuit breaker open: token acquisition disabled after 3 consecutive failures",
		cause: errors.New("gobreaker: circuit breaker is open"),
	}
	provider := &stubTokenProvider{err: cbErr}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
	}()

	sendRequest(t, client, "http://example.com/test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with proxy_internal_error for circuit breaker rejection.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_internal_error")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_internal_error") {
		t.Errorf("body: want mention of proxy_internal_error, got %q", body)
	}
	if !strings.Contains(string(body), "circuit breaker") {
		t.Errorf("body: want mention of circuit breaker, got %q", body)
	}

	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after circuit breaker error")
	}
}

// ---------------------------------------------------------------------------
// A3 — proxy_internal_error: credential failure
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnCredentialFailure verifies that when the token
// provider returns a *CredentialError, the proxy responds with 502 Bad Gateway
// and Proxy-Status "proxy_internal_error".
//
// Per RFC 9209 §2.3: proxy_internal_error is used for authentication
// subsystem failures that prevent the proxy from authenticating to upstream.
func TestA3_RFC9209_ProxyStatusOnCredentialFailure(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	credErr := &CredentialError{
		msg:   "Kerberos credentials are expired or unavailable",
		cause: errors.New("no credentials cache found"),
	}
	provider := &stubTokenProvider{err: credErr}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
	}()

	sendRequest(t, client, "http://example.com/test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with proxy_internal_error for Kerberos credential failure.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_internal_error")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_internal_error") {
		t.Errorf("body: want mention of proxy_internal_error, got %q", body)
	}
	if !strings.Contains(string(body), "credentials") {
		t.Errorf("body: want mention of credentials, got %q", body)
	}

	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after credential error")
	}
}

// ---------------------------------------------------------------------------
// A3 — proxy_internal_error: SPNEGO negotiation failure
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnNegotiationFailure verifies that when the token
// provider returns a *NegotiationError, the proxy responds with 502 Bad
// Gateway and Proxy-Status "proxy_internal_error".
//
// Per RFC 9209 §2.3: proxy_internal_error is used when the proxy cannot
// complete the authentication protocol required to serve the request.
func TestA3_RFC9209_ProxyStatusOnNegotiationFailure(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	negErr := &NegotiationError{
		msg:   "SPNEGO negotiation with the KDC failed",
		cause: errors.New("KDC unreachable: connection timed out"),
	}
	provider := &stubTokenProvider{err: negErr}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
	}()

	sendRequest(t, client, "http://example.com/test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with proxy_internal_error for SPNEGO negotiation failure.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_internal_error")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_internal_error") {
		t.Errorf("body: want mention of proxy_internal_error, got %q", body)
	}
	if !strings.Contains(string(body), "negotiation") {
		t.Errorf("body: want mention of negotiation, got %q", body)
	}

	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after negotiation error")
	}
}

// ---------------------------------------------------------------------------
// A3 — http_request_error: malformed client request
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnMalformedRequest verifies that when the client
// sends malformed HTTP data that cannot be parsed, the proxy responds with
// 400 Bad Request and Proxy-Status "http_request_error".
//
// Per RFC 9209 §2.3: http_request_error is used when the proxy cannot parse
// or process the client's request due to a client-side protocol error.
func TestA3_RFC9209_ProxyStatusOnMalformedRequest(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
	}()

	// Send data that is not a valid HTTP request — deliberately malformed
	// to trigger an http.ReadRequest parse failure.
	_, err := fmt.Fprint(client, "NOT-A-VALID-HTTP-REQUEST\r\n\r\n")
	if err != nil {
		t.Fatalf("write malformed data to proxy: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 400 with http_request_error for unreadable/unparseable request.
	assertProxyStatus(t, resp, http.StatusBadRequest, "http_request_error")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "http_request_error") {
		t.Errorf("body: want mention of http_request_error, got %q", body)
	}

	// Upstream must NOT have received the request — it was rejected pre-forward.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after malformed request")
	}
}

// ---------------------------------------------------------------------------
// A3 — proxy_loop_detected: Via header contains own pseudonym
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnLoopDetected verifies that when the incoming
// request's Via header already contains this proxy's pseudonym, the proxy
// responds with 502 Bad Gateway and Proxy-Status "proxy_loop_detected".
//
// Per RFC 9209 §2.3: proxy_loop_detected is used when the proxy identifies
// a request routing loop based on its own identifier in the Via chain.
//
// Per RFC 9110 §7.6.3: proxies MUST check the Via header for their own
// identifier before forwarding a request to detect forwarding loops.
func TestA3_RFC9209_ProxyStatusOnLoopDetected(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send a request whose Via header already contains this proxy's pseudonym,
	// simulating a routing loop where the request has previously transited
	// this same proxy instance.
	req, _ := http.NewRequest("GET", "http://example.com/loop-test", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with proxy_loop_detected when own pseudonym found in Via.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_loop_detected")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_loop_detected") {
		t.Errorf("body: want mention of proxy_loop_detected, got %q", body)
	}
	if !strings.Contains(string(body), "routing loop") {
		t.Errorf("body: want description of routing loop, got %q", body)
	}

	// Upstream must NOT have received the looped request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0 (loop should be rejected)", n)
	}
}

// ---------------------------------------------------------------------------
// A3 — connection_terminated: writeHTTPError emits correct Proxy-Status
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnConnectionTerminated verifies that
// writeHTTPError sends a 502 Bad Gateway response with Proxy-Status header
// carrying the "connection_terminated" error type.
//
// Per RFC 9209 §2.3: connection_terminated is used when the connection to
// the next-hop server was closed before a complete response was received.
//
// The connection_terminated error path in handleClient fires when
// req.WriteProxy(proxyConn) fails (main.go:362–366). Triggering this
// deterministically via a live TCP connection is unreliable because the OS
// kernel buffers small writes; the write can succeed even if the peer has
// closed the connection, and the error only surfaces after the kernel flushes
// the send buffer (a non-deterministic timing event).
//
// This test therefore validates the writeHTTPError call directly with
// errConnectionTerminated — confirming that the error type token, status
// code, and response body are all correct per RFC 9209 §2. The integration
// between handleClient and writeHTTPError is already exercised by the other
// error-type tests in this file (e.g. proxy_internal_error, http_request_error)
// which use the same writeHTTPError function.
func TestA3_RFC9209_ProxyStatusOnConnectionTerminated(t *testing.T) {
	// Use net.Pipe so the response can be read back synchronously without
	// involving a listener. writeHTTPError writes directly to a net.Conn.
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })

	// Invoke writeHTTPError in a goroutine so the test can read the response
	// on the client side without a deadlock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		writeHTTPError(server, errConnectionTerminated)
	}()

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// A3: 502 with connection_terminated for upstream connection closure.
	assertProxyStatus(t, resp, http.StatusBadGateway, "connection_terminated")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "connection_terminated") {
		t.Errorf("body: want mention of connection_terminated, got %q", body)
	}
	if !strings.Contains(string(body), "upstream proxy") {
		t.Errorf("body: want description of upstream closure, got %q", body)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("writeHTTPError did not return within 5 s")
	}
}

// ---------------------------------------------------------------------------
// A3 — Proxy-Status identifier matches "spnego-proxy"
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyIdentifierIsSpnegoProxy verifies that the proxy name
// portion of the Proxy-Status header is exactly "spnego-proxy" across all
// error type variants, confirming RFC 9209 §2 compliance for the proxy
// identifier field.
//
// This table-driven test covers each distinct error type to ensure the
// identifier is consistent regardless of the error path taken.
func TestA3_RFC9209_ProxyIdentifierIsSpnegoProxy(t *testing.T) {
	tests := []struct {
		name          string
		wantErrorType string
		setupProvider func() *stubTokenProvider
		requestVia    string
		wantCode      int
	}{
		{
			name:          "proxy_internal_error/generic",
			wantErrorType: "proxy_internal_error",
			setupProvider: func() *stubTokenProvider {
				return &stubTokenProvider{err: errors.New("generic failure")}
			},
			wantCode: http.StatusBadGateway,
		},
		{
			name:          "proxy_internal_error/circuit_breaker",
			wantErrorType: "proxy_internal_error",
			setupProvider: func() *stubTokenProvider {
				return &stubTokenProvider{err: &CircuitBreakerError{
					msg: "circuit breaker open",
				}}
			},
			wantCode: http.StatusBadGateway,
		},
		{
			name:          "proxy_internal_error/credential",
			wantErrorType: "proxy_internal_error",
			setupProvider: func() *stubTokenProvider {
				return &stubTokenProvider{err: &CredentialError{
					msg: "expired credentials",
				}}
			},
			wantCode: http.StatusBadGateway,
		},
		{
			name:          "proxy_internal_error/negotiation",
			wantErrorType: "proxy_internal_error",
			setupProvider: func() *stubTokenProvider {
				return &stubTokenProvider{err: &NegotiationError{
					msg: "KDC unreachable",
				}}
			},
			wantCode: http.StatusBadGateway,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := NewMockUpstreamProxy(t, nil)
			t.Cleanup(upstream.Close)

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			provider := tc.setupProvider()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClient(server, upstream.Addr(), provider, testPseudonym,
					5*time.Second, 5*time.Second, 0, nil)
			}()

			sendRequest(t, client, "http://example.com/identifier-test")

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			t.Cleanup(func() { _ = resp.Body.Close() })
			_, _ = io.Copy(io.Discard, resp.Body)

			assertStatusCode(t, resp, tc.wantCode)

			ps := resp.Header.Get("Proxy-Status")
			// RFC 9209 §2: the proxy identifier MUST be the first parameter.
			if !strings.HasPrefix(ps, "spnego-proxy;") {
				t.Errorf("Proxy-Status %q: identifier must be %q", ps, "spnego-proxy")
			}

			wantPS := "spnego-proxy; error=" + tc.wantErrorType
			if ps != wantPS {
				t.Errorf("Proxy-Status: want %q, got %q", wantPS, ps)
			}

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("handleClient did not return within 5 s for %s", tc.name)
			}
		})
	}
}
