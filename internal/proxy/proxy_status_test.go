package proxy

// proxy_status_test.go — acceptance tests for RFC 9209 Proxy-Status header
// coverage across all remaining error scenarios, plus status-code and
// response-framing requirements.
//
// Requirements covered:
//
//	A3 — Include Proxy-Status in error responses (RFC 9209 §2 MAY)
//	J1 — Advertise HTTP/1.1 in all proxy-generated responses (RFC 9112 §2.1 MUST)
//	L1 — 502 Bad Gateway for upstream connection/response failures
//	     (RFC 9112 §6.1 MUST)
//	L2 — 504 Gateway Timeout for upstream timeouts
//	     (RFC 9110 §15.6.5 SHOULD)
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
	if got := resp.Header.Get(headerProxyStatus); got != wantPS {
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
// A3 — proxy_internal_error: all SPNEGO token acquisition failure variants
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnProxyInternalError is a table-driven test that
// verifies that token-acquisition error types produce a 502 Bad Gateway
// response with the correct Proxy-Status header, proxy identifier prefix,
// and error-specific body content.
func TestA3_RFC9209_ProxyStatusOnProxyInternalError(t *testing.T) {
	tests := []struct {
		name string
		// providerErr is the error the stubTokenProvider returns.
		providerErr error
		// rawRequest, if non-empty, is sent instead of the default GET.
		// This allows testing CONNECT and other method-specific paths.
		rawRequest string
		// wantBodyContains lists substrings that MUST appear in the body.
		wantBodyContains []string
		// wantBodyExcludes lists substrings that MUST NOT appear in the body
		// (used to confirm each error type produces a distinct message).
		wantBodyExcludes []string
	}{
		{
			name:        "generic_token_error",
			providerErr: errors.New("GSS-API error: An unsupported mechanism was requested"),
			wantBodyContains: []string{
				"proxy_internal_error",
				"failed to acquire a SPNEGO authentication token",
				"Suggested action:",
			},
		},
		{
			name:        "generic_token_error_CONNECT",
			providerErr: errors.New("GSS-API error: An unsupported mechanism was requested"),
			rawRequest:  "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			wantBodyContains: []string{
				"proxy_internal_error",
				"failed to acquire a SPNEGO authentication token",
			},
		},
		{
			name: "circuit_breaker_open",
			providerErr: &CircuitBreakerError{authError{
				msg:   "circuit breaker open: token acquisition disabled after 3 consecutive failures",
				cause: errors.New("gobreaker: circuit breaker is open"),
			}},
			wantBodyContains: []string{
				"proxy_internal_error",
				"circuit breaker open",
				"temporarily disabled after repeated failures",
			},
			wantBodyExcludes: []string{
				"failed to acquire a SPNEGO authentication token",
			},
		},
		{
			name: "credential_failure",
			providerErr: &CredentialError{authError{
				msg:   "could not acquire client credential: KDC_ERR_PREAUTH_FAILED",
				cause: errors.New("KDC_ERR_PREAUTH_FAILED"),
			}},
			wantBodyContains: []string{
				"proxy_internal_error",
				"Kerberos credentials are expired or unavailable",
				"kinit",
			},
			wantBodyExcludes: []string{
				"failed to acquire a SPNEGO authentication token",
			},
		},
		{
			name: "negotiation_failure",
			providerErr: &NegotiationError{authError{
				msg:   "could not initialize context: SPN mismatch",
				cause: errors.New("SPN mismatch"),
			}},
			wantBodyContains: []string{
				"proxy_internal_error",
				"SPNEGO negotiation with the KDC failed",
				"service principal name",
			},
			wantBodyExcludes: []string{
				"failed to acquire a SPNEGO authentication token",
				"Kerberos credentials are expired or unavailable",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := NewMockUpstreamProxy(t, nil)
			t.Cleanup(upstream.Close)

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			provider := &stubTokenProvider{err: tc.providerErr}
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClient(server, defaultTestConfig(upstream.Addr(), provider))
			}()

			if tc.rawRequest != "" {
				_, err := fmt.Fprint(client, tc.rawRequest)
				if err != nil {
					t.Fatalf("write raw request to proxy: %v", err)
				}
			} else {
				sendRequest(t, client, "http://example.com/test")
			}

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			t.Cleanup(func() { _ = resp.Body.Close() })

			// A3: 502 with proxy_internal_error for all token failure variants.
			assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_internal_error")

			// Verify the proxy identifier prefix is exactly "spnego-proxy;".
			ps := resp.Header.Get(headerProxyStatus)
			if !strings.HasPrefix(ps, "spnego-proxy;") {
				t.Errorf("Proxy-Status %q: identifier must start with %q", ps, "spnego-proxy;")
			}

			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			for _, want := range tc.wantBodyContains {
				if !strings.Contains(bodyStr, want) {
					t.Errorf("body: want substring %q, got %q", want, bodyStr)
				}
			}
			for _, exclude := range tc.wantBodyExcludes {
				if strings.Contains(bodyStr, exclude) {
					t.Errorf("body: must NOT contain %q, got %q", exclude, bodyStr)
				}
			}

			// Upstream must NOT have received the request — token failure occurs before the request is forwarded.
			if n := len(upstream.Requests()); n != 0 {
				t.Errorf("upstream received %d requests, want 0", n)
			}

			waitForDone(t, done)
		})
	}
}

// ---------------------------------------------------------------------------
// A3 — http_request_error: malformed client request
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnMalformedRequest verifies that when the client
// sends malformed HTTP data that cannot be parsed, the proxy responds with
// 400 Bad Request and Proxy-Status "http_request_error".
func TestA3_RFC9209_ProxyStatusOnMalformedRequest(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, defaultTestConfig(upstream.Addr(), provider))
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

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// A3 — connection_terminated: writeHTTPError emits correct Proxy-Status
// ---------------------------------------------------------------------------

// TestA3_RFC9209_ProxyStatusOnConnectionTerminated verifies that
// writeHTTPError sends a 502 Bad Gateway response with Proxy-Status header
// carrying the "connection_terminated" error type.
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

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// L2 — RFC 9110 §15.6.5: 504 Gateway Timeout on upstream dial timeout
// ---------------------------------------------------------------------------

// TestL2_RFC9110_GatewayTimeoutOnDialTimeout verifies that when the upstream
// proxy is unreachable and the dial times out, the proxy returns 504 with the
// RFC 9209 Proxy-Status error token "connection_timeout".
func TestL2_RFC9110_GatewayTimeoutOnDialTimeout(t *testing.T) {
	// RFC 5737 TEST-NET-1: guaranteed unreachable documentation address.
	const unreachable = "192.0.2.1:1"

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	const testDialTimeout = 50 * time.Millisecond
	cfg := defaultTestConfig(unreachable, provider)
	cfg.DialTimeout = testDialTimeout
	cfg.UpstreamTLS.Dialer = &net.Dialer{Timeout: testDialTimeout}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, cfg)
	}()

	// Send a request so handleClient can read it before attempting to dial.
	sendRequest(t, client, "http://example.com/timeout-test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// L2: proxy MUST return 504 for upstream dial timeout.
	assertStatusCode(t, resp, http.StatusGatewayTimeout)

	// RFC 9209: Proxy-Status MUST carry the connection_timeout error token.
	const wantPS = "spnego-proxy; error=connection_timeout"
	if got := resp.Header.Get(headerProxyStatus); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "connection_timeout") {
		t.Errorf("body: want mention of connection_timeout, got %q", body)
	}
	if !strings.Contains(string(body), "timed out connecting to the upstream proxy") {
		t.Errorf("body: want description of timeout, got %q", body)
	}
	if !strings.Contains(string(body), "Suggested action:") {
		t.Errorf("body: want suggested action, got %q", body)
	}

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// L1 — RFC 9112 §6.1: 502 Bad Gateway on upstream connection failure
// ---------------------------------------------------------------------------

// TestL1_RFC9112_BadGatewayOnConnectionRefused verifies that when the upstream
// proxy actively refuses the connection (non-timeout dial error), the proxy
// returns 502 with the RFC 9209 Proxy-Status error token "connection_refused".
func TestL1_RFC9112_BadGatewayOnConnectionRefused(t *testing.T) {
	// Bind then immediately close a listener to produce a free-then-closed
	// port. Any subsequent connection attempt will be refused by the OS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	refusedAddr := ln.Addr().String()
	_ = ln.Close()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, defaultTestConfig(refusedAddr, provider))
	}()

	// Send a request so handleClient can read it before attempting to dial.
	sendRequest(t, client, "http://example.com/refused-test")

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// L1: proxy MUST return 502 for upstream connection failure.
	assertStatusCode(t, resp, http.StatusBadGateway)

	// RFC 9209: Proxy-Status MUST carry the connection_refused error token.
	const wantPS = "spnego-proxy; error=connection_refused"
	if got := resp.Header.Get(headerProxyStatus); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "connection_refused") {
		t.Errorf("body: want mention of connection_refused, got %q", body)
	}

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// J1 — RFC 9112 §2.1: HTTP/1.1 in all proxy-generated responses
// ---------------------------------------------------------------------------

// TestJ1_RFC9112_HTTP11AdvertisedInProxyGeneratedResponses verifies that all
// error responses synthesised by the proxy carry "HTTP/1.1" in the status line.
func TestJ1_RFC9112_HTTP11AdvertisedInProxyGeneratedResponses(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		wantStatus  int
		dialTimeout time.Duration
	}{
		{
			name: "504 GatewayTimeout",
			setupFunc: func(_ *testing.T) string {
				// RFC 5737 TEST-NET-1: unreachable, forces dial timeout.
				return "192.0.2.1:1"
			},
			wantStatus:  http.StatusGatewayTimeout,
			dialTimeout: 50 * time.Millisecond,
		},
		{
			name: "502 BadGateway_ConnectionRefused",
			setupFunc: func(t *testing.T) string {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen: %v", err)
				}
				addr := ln.Addr().String()
				_ = ln.Close()
				return addr
			},
			wantStatus:  http.StatusBadGateway,
			dialTimeout: 5 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstreamAddr := tc.setupFunc(t)

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			provider := &stubTokenProvider{token: "tok"}
			cfg := defaultTestConfig(upstreamAddr, provider)
			cfg.DialTimeout = tc.dialTimeout
			cfg.UpstreamTLS.Dialer = &net.Dialer{Timeout: tc.dialTimeout}

			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClient(server, cfg)
			}()

			// Send a request so handleClient can read it before attempting to dial.
			sendRequest(t, client, "http://example.com/j1-test")

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			// J1: all proxy-generated responses MUST advertise HTTP/1.1.
			if resp.Proto != "HTTP/1.1" {
				t.Errorf("response Proto: want %q, got %q", "HTTP/1.1", resp.Proto)
			}

			// Sanity-check the expected status code for this error path.
			assertStatusCode(t, resp, tc.wantStatus)

			waitForDone(t, done)
		})
	}
}
