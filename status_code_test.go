package main

// status_code_test.go — acceptance tests for RFC-mandated status codes and
// response framing in proxy-generated messages.
//
// Requirements covered:
//
//	L1 — 502 Bad Gateway for upstream connection/response failures
//	     (RFC 9112 §6.1 MUST)
//	L2 — 504 Gateway Timeout for upstream timeouts
//	     (RFC 9110 §15.6.5 SHOULD)
//	D3 — No Transfer-Encoding in CONNECT 2xx response
//	     (RFC 9112 §6.1 MUST NOT)
//	J1 — Advertise HTTP/1.1 in all proxy-generated responses
//	     (RFC 9112 §2.1 MUST)

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// L2 — RFC 9110 §15.6.5: 504 Gateway Timeout on upstream dial timeout
// ---------------------------------------------------------------------------

// TestL2_RFC9110_GatewayTimeoutOnDialTimeout verifies that when the upstream
// proxy is unreachable and the dial times out, the proxy returns 504 with the
// RFC 9209 Proxy-Status error token "connection_timeout".
//
// The RFC 5737 TEST-NET address 192.0.2.1 is documentation-only and is
// guaranteed never to route to a live host, making it ideal for triggering a
// reliable dial timeout without flaky host-specific behaviour.
//
// net.Pipe() is used (following main_test.go's TestHandleClientDialTimeout)
// because it gives the test full control of the client side and avoids the
// race condition that arises when setting ProxyUnderTest.DialTimeout after
// the accept goroutine has already started.
func TestL2_RFC9110_GatewayTimeoutOnDialTimeout(t *testing.T) {
	// RFC 5737 TEST-NET-1: guaranteed unreachable documentation address.
	const unreachable = "192.0.2.1:1"

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 50 ms dial timeout: short enough for a fast test, long enough
		// to let the OS attempt the connection before cancelling.
		handleClient(server, unreachable, provider, testPseudonym,
			50*time.Millisecond, 5*time.Second, 0, nil, ForwardingConfig{})
	}()

	// The proxy dials upstream immediately on accepting a connection,
	// before reading the client request. When the dial times out the
	// proxy synthesises an error response and closes the connection.
	// We read the response directly without sending a request.
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// L2: proxy MUST return 504 for upstream dial timeout.
	assertStatusCode(t, resp, http.StatusGatewayTimeout)

	// RFC 9209: Proxy-Status MUST carry the connection_timeout error token.
	const wantPS = "spnego-proxy; error=connection_timeout"
	if got := resp.Header.Get("Proxy-Status"); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "connection_timeout") {
		t.Errorf("body: want mention of connection_timeout, got %q", body)
	}

	select {
	case <-done:
		// handleClient returned promptly after dial timeout — expected.
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s; dial timeout not effective")
	}
}

// ---------------------------------------------------------------------------
// L1 — RFC 9112 §6.1: 502 Bad Gateway on upstream connection failure
// ---------------------------------------------------------------------------

// TestL1_RFC9112_BadGatewayOnConnectionRefused verifies that when the upstream
// proxy actively refuses the connection (non-timeout dial error), the proxy
// returns 502 with the RFC 9209 Proxy-Status error token "connection_refused".
//
// A listener is bound then immediately closed so that the OS will reply to
// subsequent SYN packets with RST, producing a reliable "connection refused"
// error without requiring any special network configuration.
//
// net.Pipe() is used so that we can read the proxy error response directly
// without sending a request first. The proxy dials upstream before reading
// the client request, so the connection-refused error response is returned
// to the client connection before any request bytes are needed.
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
		handleClient(server, refusedAddr, provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil, ForwardingConfig{})
	}()

	// Read the proxy error response without sending a request. The proxy
	// dials upstream immediately and returns 502 on refusal.
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// L1: proxy MUST return 502 for upstream connection failure.
	assertStatusCode(t, resp, http.StatusBadGateway)

	// RFC 9209: Proxy-Status MUST carry the connection_refused error token.
	const wantPS = "spnego-proxy; error=connection_refused"
	if got := resp.Header.Get("Proxy-Status"); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "connection_refused") {
		t.Errorf("body: want mention of connection_refused, got %q", body)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5 s after connection refusal")
	}
}

// ---------------------------------------------------------------------------
// D3 — RFC 9112 §6.1: No Transfer-Encoding in CONNECT 2xx response
// ---------------------------------------------------------------------------

// TestD3_RFC9112_NoTransferEncodingInCONNECTResponse verifies that when the
// upstream returns a 200 Connection Established response to a CONNECT request,
// the proxy does not add or forward a Transfer-Encoding header to the client.
//
// RFC 9112 §6.1: "A server MUST NOT send Transfer-Encoding in response to
// CONNECT when the request succeeded."
//
// ProxyUnderTest + MockUpstreamProxy are used here because the CONNECT path
// requires a successful upstream dial followed by a request/response exchange.
func TestD3_RFC9112_NoTransferEncodingInCONNECTResponse(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, func(req *http.Request) *http.Response {
		if req.Method != http.MethodConnect {
			t.Errorf("expected CONNECT, got %s", req.Method)
		}
		// Return a minimal 200 Connection Established. The proxy must
		// not inject Transfer-Encoding into the forwarded response.
		return &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
	})
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Send a CONNECT request as a tunnel client would (e.g. HTTPS through
	// an HTTP proxy). The target host is arbitrary; only the response
	// headers matter for this assertion.
	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	// Note: do not close resp.Body — for CONNECT 200 the body represents
	// the open tunnel; closing it would close the underlying connection.

	// The upstream returned 200; verify the forwarded response.
	assertStatusCode(t, resp, http.StatusOK)

	// D3: Transfer-Encoding MUST NOT appear in the CONNECT 2xx response.
	assertHeaderAbsent(t, resp.Header, "Transfer-Encoding")
}

// ---------------------------------------------------------------------------
// J1 — RFC 9112 §2.1: HTTP/1.1 in all proxy-generated responses
// ---------------------------------------------------------------------------

// TestJ1_RFC9112_HTTP11AdvertisedInProxyGeneratedResponses verifies that all
// error responses synthesised by the proxy (i.e. not relayed from the
// upstream) carry "HTTP/1.1" in the status line.
//
// RFC 9112 §2.1: "An HTTP/1.1 server MUST send a response with an HTTP-version
// of HTTP/1.1."
//
// Two error paths are exercised (504 and 502) to confirm the version
// advertisement is consistent across all proxy-generated responses.
// http.ReadResponse is used to parse the full response; the Proto field
// reflects the version string from the raw status line.
func TestJ1_RFC9112_HTTP11AdvertisedInProxyGeneratedResponses(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		wantStatus  int
		dialTimeout time.Duration
	}{
		{
			name: "504 GatewayTimeout",
			setupFunc: func(t *testing.T) string {
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
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClient(server, upstreamAddr, provider, testPseudonym,
					tc.dialTimeout, 5*time.Second, 0, nil, ForwardingConfig{})
			}()

			// Read the full response so that handleClient can complete
			// writing and return. resp.Proto reflects the HTTP version
			// string from the raw status line (e.g. "HTTP/1.1").
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

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("handleClient did not return within 5 s for %s", tc.name)
			}
		})
	}
}
