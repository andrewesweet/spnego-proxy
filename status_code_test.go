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
func TestL2_RFC9110_GatewayTimeoutOnDialTimeout(t *testing.T) {
	// RFC 5737 TEST-NET-1: guaranteed unreachable documentation address.
	const unreachable = "192.0.2.1:1"

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(unreachable, provider)
	cfg.DialTimeout = 50 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, cfg)
	}()

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

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// D3 — RFC 9112 §6.1: No Transfer-Encoding in CONNECT 2xx response
// ---------------------------------------------------------------------------

// TestD3_RFC9112_NoTransferEncodingInCONNECTResponse verifies that when the
// upstream returns a 200 Connection Established response to a CONNECT request,
// the proxy does not add or forward a Transfer-Encoding header to the client.
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

	_, err = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The upstream returned 200; verify the forwarded response.
	assertStatusCode(t, resp, http.StatusOK)

	// D3: Transfer-Encoding MUST NOT appear in the CONNECT 2xx response.
	assertHeaderAbsent(t, resp.Header, "Transfer-Encoding")
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

			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClient(server, cfg)
			}()

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
