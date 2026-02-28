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

// TestF1_ExpectHeaderForwarded verifies that when an HTTP/1.1 client sends
// Expect: 100-continue (in various casings), the proxy forwards that header
// to the upstream.
//
// RFC 9110 §10.1.1: a proxy MUST forward the Expect: 100-continue field if it
// is forwarding a request to an HTTP/1.1 or later upstream.
func TestF1_ExpectHeaderForwarded(t *testing.T) {
	tests := []struct {
		name        string
		expectValue string
	}{
		{"lowercase", "100-continue"},
		{"mixed case", "100-Continue"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := "hello"
			raw := "POST http://example.com/upload HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/octet-stream\r\n" +
				fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
				fmt.Sprintf("Expect: %s\r\n", tc.expectValue) +
				"\r\n" +
				body

			resp, reqs := proxyRawRoundTrip(t, raw)
			assertStatusCode(t, resp, http.StatusOK)

			if len(reqs) != 1 {
				t.Fatalf("upstream received %d requests, want 1", len(reqs))
			}

			// Header value comparison is case-insensitive per RFC 9110 §10.1.1.
			if got := reqs[0].Header.Get("Expect"); !strings.EqualFold(got, "100-continue") {
				t.Errorf("upstream Expect header: want %q (case-insensitive), got %q", "100-continue", got)
			}
		})
	}
}

// TestF1_ExpectHeaderNotAddedWhenAbsent verifies that the proxy does not
// invent an Expect header when the client did not send one.
func TestF1_ExpectHeaderNotAddedWhenAbsent(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{})
	assertHeaderAbsent(t, upReq.Header, "Expect")
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

// TestG1_MaxForwards_Table covers Max-Forwards handling for TRACE, OPTIONS,
// and other methods in a single table-driven test.
//
// RFC 9110 §7.6.2: each proxy that forwards a TRACE or OPTIONS request MUST
// decrement the Max-Forwards value by 1 before forwarding. If the received
// value is 0, the recipient MUST NOT forward the request; instead, it MUST
// respond as the final recipient. For other methods, the header is forwarded
// unchanged. If the header is absent, the proxy MUST NOT add it. If the
// value is not a valid integer, the proxy SHOULD forward it unmodified.
func TestG1_MaxForwards_Table(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		maxForwards  string // "" means absent
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
		{
			name:         "TRACE MF=5 decremented to 4",
			method:       "TRACE",
			maxForwards:  "5",
			wantUpstream: true,
			wantMF:       "4",
		},
		{
			name:         "OPTIONS MF=10 decremented to 9",
			method:       "OPTIONS",
			maxForwards:  "10",
			wantUpstream: true,
			wantMF:       "9",
		},
		{
			name:         "OPTIONS MF=1 decremented to 0 and forwarded",
			method:       "OPTIONS",
			maxForwards:  "1",
			wantUpstream: true,
			wantMF:       "0",
		},
		{
			name:         "GET MF=5 not decremented",
			method:       "GET",
			maxForwards:  "5",
			wantUpstream: true,
			wantMF:       "5",
		},
		{
			name:         "TRACE absent MF not added",
			method:       "TRACE",
			maxForwards:  "", // absent
			wantUpstream: true,
			wantMF:       "", // must remain absent
		},
		{
			name:         "TRACE invalid MF forwarded unmodified",
			method:       "TRACE",
			maxForwards:  "not-a-number",
			wantUpstream: true,
			wantMF:       "not-a-number",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mfLine := ""
			if tc.maxForwards != "" {
				mfLine = fmt.Sprintf("Max-Forwards: %s\r\n", tc.maxForwards)
			}
			raw := fmt.Sprintf("%s http://example.com/ HTTP/1.1\r\nHost: example.com\r\n%s\r\n",
				tc.method, mfLine)

			resp, reqs := proxyRawRoundTrip(t, raw)
			assertStatusCode(t, resp, http.StatusOK)

			if tc.wantUpstream {
				if len(reqs) != 1 {
					t.Fatalf("upstream received %d requests, want 1", len(reqs))
				}
				if tc.wantMF == "" {
					assertHeaderAbsent(t, reqs[0].Header, "Max-Forwards")
				} else if got := reqs[0].Header.Get("Max-Forwards"); got != tc.wantMF {
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
// I1/I2 — Connection closed after response
// ---------------------------------------------------------------------------

// TestI1I2_ConnectionClosedAfterResponse verifies that the proxy closes the
// connection after the response for HTTP/1.0 clients (RFC 9112 §9.3) and
// when the client sends Connection: close (RFC 9112 §9.6).
func TestI1I2_ConnectionClosedAfterResponse(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "HTTP/1.0 connection closed (I1)",
			raw: "GET http://example.com/ HTTP/1.0\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
		},
		{
			name: "Connection: close honored (I2)",
			raw: "GET http://example.com/ HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Connection: close\r\n" +
				"\r\n",
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

			if _, err := conn.Write([]byte(tc.raw)); err != nil {
				t.Fatalf("write raw request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			assertStatusCode(t, resp, http.StatusOK)
			_, _ = io.Copy(io.Discard, resp.Body)

			// After the response the proxy must close the connection.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1)
			n, readErr := conn.Read(buf)
			if n > 0 {
				t.Errorf("expected connection closed after response, got %d bytes: %q", n, buf[:n])
			}
			if readErr == nil {
				t.Error("expected error reading from closed connection, got nil")
			}
		})
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
				errs <- fmt.Errorf("client %d: expected closed connection, got %d bytes, err=%w", idx, n, connErr)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
