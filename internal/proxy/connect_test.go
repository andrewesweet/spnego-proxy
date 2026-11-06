package proxy

// connect_test.go — RFC compliance tests for CONNECT tunnel handling.
//
// Requirements covered:
//
//	D2 — Drain buffered data on tunnel close (RFC 9110 §9.3.6 MUST)
//	D3 — No Transfer-Encoding in CONNECT 2xx response (RFC 9112 §6.1 MUST NOT)
//	D4 — Restrict CONNECT to safe ports (RFC 9110 §9.3.6 SHOULD)
//	D5 — Close connection when rejecting a CONNECT request (RFC 9112 §11.2 MUST)
//	D6 — Wait for upstream 2xx before forwarding client payload (RFC 9110 §9.3.6 MUST)
//	D7 — Do not send 2xx to client without established upstream connection (RFC 9110 §9.3.6 MUST NOT)

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newMockConnectUpstream starts a TCP listener on a random port, spawns an
// accept goroutine that performs the CONNECT handshake (reads the request,
// validates it is a CONNECT, writes HTTP 200), and then calls afterConnect
// with the raw net.Conn so the caller can implement custom post-handshake
// behaviour (idle, echo, payload inspection, etc.).
//
// The accept goroutine is bound to t.Context() so it unblocks and exits
// cleanly if the test panics or its deadline expires. The listener is
// registered for cleanup via t.Cleanup.
func newMockConnectUpstream(t *testing.T, afterConnect func(ctx context.Context, conn net.Conn)) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("newMockConnectUpstream: listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx := t.Context()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Unblock the blocking conn operations when the test context is done.
		go func() {
			<-ctx.Done()
			_ = conn.SetDeadline(time.Now())
		}()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if req.Method != http.MethodConnect {
			return
		}
		_ = req.Body.Close()

		resp := &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header),
		}
		if err := resp.Write(conn); err != nil {
			return
		}

		if afterConnect != nil {
			afterConnect(ctx, conn)
		}
	}()

	return ln
}

// ---------------------------------------------------------------------------
// D4 — Port restriction
// ---------------------------------------------------------------------------

// TestD4_ConnectPortRestriction verifies that when connectPorts is set, the
// proxy allows CONNECT to listed ports and rejects unlisted ones with 403.
// It also verifies that a CONNECT target with no explicit port defaults to 443.
func TestD4_ConnectPortRestriction(t *testing.T) {
	tests := []struct {
		name       string
		ports      []string
		target     string
		wantStatus int
	}{
		{"allowed port", []string{"443", "8443"}, "example.com:443", http.StatusOK},
		{"disallowed port", []string{"443", "8443"}, "example.com:25", http.StatusForbidden},
		{"default port 443 when absent", []string{"443"}, "example.com", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := "CONNECT " + tc.target + " HTTP/1.1\r\nHost: " + tc.target + "\r\n\r\n"

			resp, reqs := proxyRawRoundTrip(t, raw, func(p *ProxyUnderTest) {
				p.SetConnectPorts(tc.ports)
			})
			defer func() { _ = resp.Body.Close() }()

			assertStatusCode(t, resp, tc.wantStatus)

			if tc.wantStatus == http.StatusForbidden {
				wantPS := "spnego-proxy; error=http_request_denied"
				if got := resp.Header.Get(headerProxyStatus); got != wantPS {
					t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
				}

				body, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(body), "http_request_denied") {
					t.Errorf("body: want mention of http_request_denied, got %q", body)
				}

				// Upstream must not have received any request.
				if n := len(reqs); n != 0 {
					t.Errorf("upstream received %d request(s), want 0", n)
				}
			}
		})
	}
}

// TestD4_EmptyPortListAllowsAll verifies that when connectPorts is empty
// (the default), any port is allowed for CONNECT.
func TestD4_EmptyPortListAllowsAll(t *testing.T) {
	// nil respFunc: the default 200 OK mock is sufficient for CONNECT.
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	// ConnectPorts is left empty — all ports allowed.
	t.Cleanup(proxy.Close)

	for _, port := range []string{"25", "443", "8080", "9999"} {
		t.Run("port_"+port, func(t *testing.T) {
			client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })

			target := "example.com:" + port
			_, err = io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
			if err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response for port %s: %v", port, err)
			}
			defer func() { _ = resp.Body.Close() }()

			assertStatusCode(t, resp, http.StatusOK)
		})
	}
}

// TestConnectPortWildcard verifies that using "*" in the allowed ports list
// permits CONNECT to any port, including non-standard ones like 8080.
func TestConnectPortWildcard(t *testing.T) {
	raw := "CONNECT example.com:8080 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
	resp, _ := proxyRawRoundTrip(t, raw, func(p *ProxyUnderTest) {
		p.SetConnectPorts([]string{"*"})
	})
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
}

// ---------------------------------------------------------------------------
// D6 — Payload gating: client payload must not reach upstream before 2xx
// ---------------------------------------------------------------------------

// TestD6_ClientPayloadNotSentBeforeUpstream2xx verifies that the proxy does
// not forward any client-side tunnel data to the upstream until after the
// upstream responds with 2xx for the CONNECT request.
//
// The test injects a 100ms upstream delay before sending the CONNECT response,
// then checks whether any payload bytes arrived at the upstream before the
// response was sent.
func TestD6_ClientPayloadNotSentBeforeUpstream2xx(t *testing.T) {
	const clientHello = "TLS-CLIENT-HELLO-BYTES"

	// payloadBeforeResponse tracks whether any tunnel bytes (beyond the
	// CONNECT request itself) arrived at the upstream before the response
	// was dispatched.
	var payloadBeforeResponse atomic.Bool

	upstreamReady := make(chan net.Conn, 1)

	ctx := t.Context()

	// Start a manual upstream server so we can interleave reading and writing
	// with precise timing control.  This test cannot use newMockConnectUpstream
	// because it must inspect the upstream read buffer *before* writing the 200
	// response — the timing of the 200 is deliberately part of the test.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = upstreamLn.Close() })

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Unblock blocking I/O when the test context is cancelled.
		go func() {
			<-ctx.Done()
			_ = conn.SetDeadline(time.Now())
		}()

		reader := bufio.NewReader(conn)

		// Read the forwarded CONNECT request.
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()

		// Delay before responding — this is the window during which a
		// broken implementation would forward the client's TLS handshake.
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return
		}

		// Check whether the upstream bufio.Reader already has bytes beyond
		// the CONNECT request (i.e. the client payload arrived early).
		if reader.Buffered() > 0 {
			payloadBeforeResponse.Store(true)
		}

		// Send 200 Connection Established.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		upstreamReady <- conn
	}()

	// Set up the proxy.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, defaultTestConfig(upstreamLn.Addr().String(), provider))
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Send CONNECT immediately followed by the simulated TLS ClientHello
	// in the same write so it lands in the proxy's bufio buffer.
	connectMsg := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + clientHello
	if _, err := io.WriteString(client, connectMsg); err != nil {
		t.Fatalf("write CONNECT+payload: %v", err)
	}

	// Read the 200 response relayed back from upstream.
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusOK)

	// Let upstream connection finish.
	select {
	case upConn := <-upstreamReady:
		_ = upConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive connection in time")
	}

	// D6: The client payload must NOT have been forwarded before the 2xx response.
	if payloadBeforeResponse.Load() {
		t.Error("D6 violation: client payload bytes were forwarded to upstream before 2xx response was sent")
	}

	_ = client.Close()
	waitForDone(t, done)
}

func TestD6D7_ConnectInterimResponsesBeforeFinal(t *testing.T) {
	for _, proto := range []string{"HTTP/1.1", "HTTP/1.0"} {
		for _, status := range []int{http.StatusOK, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", proto, status), func(t *testing.T) {
				const clientPayload = "CLIENT-TUNNEL-DATA"
				const serverPayload = "SERVER-TUNNEL-DATA"
				upstream, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("listen upstream: %v", err)
				}
				t.Cleanup(func() { _ = upstream.Close() })
				go func() {
					conn, err := upstream.Accept()
					if err != nil {
						return
					}
					defer func() { _ = conn.Close() }()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					reader := bufio.NewReader(conn)
					req, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					_ = req.Body.Close()
					response := "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
					if status == http.StatusForbidden {
						_, _ = io.WriteString(conn, response+"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
						return
					}
					if _, err := io.WriteString(conn, response+"HTTP/1.1 200 Connection Established\r\n\r\n"+serverPayload); err != nil {
						return
					}
					_, _ = io.Copy(conn, reader)
				}()

				proxy := NewProxyUnderTest(t, upstream.Addr().String())
				t.Cleanup(proxy.Close)
				client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				t.Cleanup(func() { _ = client.Close() })
				_ = client.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.WriteString(client, "CONNECT example.com:443 "+proto+"\r\nHost: example.com:443\r\n\r\n"+clientPayload); err != nil {
					t.Fatalf("write CONNECT and payload: %v", err)
				}
				reader := bufio.NewReader(client)
				resp, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatalf("read CONNECT response: %v", err)
				}
				if proto == "HTTP/1.1" {
					assertStatusCode(t, resp, http.StatusEarlyHints)
					assertHeaderPresent(t, resp.Header, "Link", "</style.css>; rel=preload")
					if via := resp.Header.Get("Via"); !strings.Contains(via, testPseudonym) {
						t.Errorf("interim Via: got %q, want proxy pseudonym", via)
					}
					_ = resp.Body.Close()
					resp, err = http.ReadResponse(reader, nil)
					if err != nil {
						t.Fatalf("read final CONNECT response after 103 (RFC 9110 section 15.2): %v", err)
					}
				}
				defer func() { _ = resp.Body.Close() }()
				assertStatusCode(t, resp, status)
				if status == http.StatusForbidden {
					body, err := io.ReadAll(resp.Body)
					if err != nil || string(body) != "denied" {
						t.Fatalf("CONNECT rejection body: got %q, %v; want denied", body, err)
					}
					if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
						t.Fatalf("CONNECT rejection must close connection: got %v", err)
					}
					return
				}
				assertHeaderAbsent(t, resp.Header, "Content-Length")
				assertHeaderAbsent(t, resp.Header, "Transfer-Encoding")
				got := make([]byte, len(serverPayload)+len(clientPayload))
				if _, err := io.ReadFull(reader, got); err != nil {
					t.Fatalf("read established CONNECT tunnel (RFC 9110 section 9.3.6): %v", err)
				}
				if string(got) != serverPayload+clientPayload {
					t.Fatalf("tunnel payload: got %q, want %q", got, serverPayload+clientPayload)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// D7 — No premature 2xx: upstream non-2xx must be relayed to client, not 200
// ---------------------------------------------------------------------------

// TestD7_UpstreamNon2xxRelayedToClient verifies that when the upstream proxy
// rejects a CONNECT request with a non-2xx response (e.g. 403), the proxy
// relays the upstream status code to the client rather than synthesising its
// own 200.
func TestD7_UpstreamNon2xxRelayedToClient(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
		body := "CONNECT denied by upstream"
		return &http.Response{
			StatusCode:    http.StatusForbidden,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	})
	t.Cleanup(upstream.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, defaultTestConfig(upstream.Addr(), provider))
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_, err = io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// D7: client must receive the upstream's actual status, not a synthetic 200.
	assertStatusCode(t, resp, http.StatusForbidden)

	// Verify the upstream rejection body is forwarded intact.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != "CONNECT denied by upstream" {
		t.Fatalf("body = %q, want %q", got, "CONNECT denied by upstream")
	}

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// D5 — Close on rejection: connection closed after CONNECT rejection
// ---------------------------------------------------------------------------

// TestD5_ConnectionClosedAfterConnectRejection verifies that when a CONNECT
// request is rejected (due to port restriction), the proxy closes the client
// connection after sending the error response per RFC 9112 §11.2.
func TestD5_ConnectionClosedAfterConnectRejection(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	proxy.SetConnectPorts([]string{"443"}) // only 443 allowed
	t.Cleanup(proxy.Close)

	client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Send CONNECT to disallowed port 25.
	_, err = io.WriteString(client, "CONNECT example.com:25 HTTP/1.1\r\nHost: example.com:25\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	assertStatusCode(t, resp, http.StatusForbidden)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// D5: after the error response the proxy must close the connection.
	// Attempting to read from the connection should return EOF promptly.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = client.Read(buf)
	if err == nil {
		t.Error("D5 violation: expected connection to be closed after CONNECT rejection, but read succeeded")
	} else if !isEOForClosed(err) {
		t.Errorf("D5 violation: expected EOF or closed error after CONNECT rejection, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// D2 — Drain buffered data on tunnel close
// ---------------------------------------------------------------------------

// TestD2_UpstreamBufferedDataDrainedOnClose verifies that when the upstream
// closes its side of the CONNECT tunnel with pending data, all buffered bytes
// are delivered to the client before EOF. This tests the upstream->client
// direction of D2 (RFC 9110 §9.3.6).
func TestD2_UpstreamBufferedDataDrainedOnClose(t *testing.T) {
	const tunnelPayload = "TUNNEL-DATA-FROM-UPSTREAM-THAT-MUST-ARRIVE"

	// We need to inject tunnel data after the 200 response, so use a raw
	// listener instead of MockUpstreamProxy.
	rawUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = rawUpstream.Close() }()

	go func() {
		conn, err := rawUpstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the CONNECT request from the proxy.
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}

		// Send 200 response.
		resp := &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
		_ = resp.Write(conn)

		// Write tunnel data and close — the proxy must drain all of it
		// to the client.
		_, _ = conn.Write([]byte(tunnelPayload))
		// Connection closes via defer, signaling EOF to the proxy.
	}()

	proxy := NewProxyUnderTest(t, rawUpstream.Addr().String())
	defer proxy.Close()

	client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send CONNECT request.
	_, err = io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read the 200 response.
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	assertStatusCode(t, resp, http.StatusOK)

	// Read all tunnel data — the proxy must deliver every byte before EOF.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read tunnel data: %v", err)
	}
	if string(data) != tunnelPayload {
		t.Errorf("D2 violation: want tunnel payload %q, got %q", tunnelPayload, string(data))
	}
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

	// Content-Length and Connection: close MUST NOT appear in the CONNECT
	// 2xx response — they cause Bun/undici to close the connection before
	// the TLS handshake through the tunnel can begin.
	assertHeaderAbsent(t, resp.Header, headerContentLength)
	assertHeaderAbsent(t, resp.Header, headerConnection)
}

// ---------------------------------------------------------------------------
// VR-006 — Idle timeout for CONNECT tunnels (issue #145)
// ---------------------------------------------------------------------------

// TestConnectTunnelIdleTimeout verifies that a CONNECT tunnel is closed by the
// proxy when no data flows in either direction within the idle timeout window.
func TestConnectTunnelIdleTimeout(t *testing.T) {
	// Mock upstream that accepts CONNECT and then idles.
	connectUpstream := newMockConnectUpstream(t, func(_ context.Context, conn net.Conn) {
		// Idle — block until either data arrives or the test context cancels.
		// The deadline-setter goroutine in newMockConnectUpstream ensures we
		// unblock on context cancellation, so a plain Read is sufficient.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	})

	proxy := NewProxyUnderTest(t, connectUpstream.Addr().String())
	proxy.SetIdleTimeout(100 * time.Millisecond)
	t.Cleanup(proxy.Close)

	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// Tunnel should close within the idle timeout + slack.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed due to idle timeout")
	}
}

func TestTunnelClockKeepsLatestProgress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 2 * time.Second
		clock := newTunnelClock(timeout)
		time.Sleep(time.Second)
		sampled := make(chan struct{})
		resume := make(chan struct{})
		published := make(chan struct{})
		go func() {
			elapsed := time.Since(clock.origin)
			close(sampled)
			<-resume
			clock.touchAt(elapsed)
			close(published)
		}()
		<-sampled
		time.Sleep(time.Second)
		clock.touch()
		close(resume)
		<-published
		if got := clock.quietFor(); got != 0 {
			t.Fatalf("late publication replaced newer progress: quiet for %v, want 0", got)
		}
		time.Sleep(time.Second)
		if got := clock.remaining(); got != time.Second || clock.idle() {
			t.Fatalf("latest progress lost: remaining = %v, idle = %v", got, clock.idle())
		}
		time.Sleep(time.Second)
		if got := clock.remaining(); got != 0 || !clock.idle() {
			t.Fatalf("latest progress should expire: remaining = %v, idle = %v", got, clock.idle())
		}
	})
}

func TestTunnelClockRevalidatesProgressDuringInactivitySampling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clock := newTunnelClock(100 * time.Millisecond)
		time.Sleep(20 * time.Millisecond)
		clock.touch()
		time.Sleep(80 * time.Millisecond)

		sampling := make(chan struct{})
		published := make(chan struct{})
		go func() {
			<-sampling
			time.Sleep(10 * time.Millisecond)
			clock.touch()
			close(published)
		}()
		var pause sync.Once
		quiet := clock.quietForSince(func(origin time.Time) time.Duration {
			pause.Do(func() {
				close(sampling)
				<-published
				time.Sleep(20 * time.Millisecond)
			})
			return time.Since(origin)
		})
		if quiet != 20*time.Millisecond {
			t.Fatalf("progress at 110ms sampled at 130ms: inactivity = %v, want 20ms", quiet)
		}
		if got := clock.remaining(); got != 80*time.Millisecond || clock.idle() {
			t.Fatalf("latest progress lost: remaining = %v, idle = %v", got, clock.idle())
		}
		time.Sleep(80 * time.Millisecond)
		if got := clock.remaining(); got != 0 || !clock.idle() {
			t.Fatalf("inactivity should exhaust the budget: remaining = %v, idle = %v", got, clock.idle())
		}
	})
}

func TestTunnelClockConcurrentProgressHasNonnegativeInactivity(t *testing.T) {
	clock := newTunnelClock(time.Second)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			<-start
			for range 20000 {
				clock.touch()
			}
		})
	}
	close(start)
	for range 20000 {
		if quiet := clock.quietFor(); quiet < 0 {
			t.Errorf("observed progress lies in the future: inactivity = %v", quiet)
			break
		}
	}
	workers.Wait()
}

func TestTunnelClockElapsedOffsets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 5 * time.Second
		clock := newTunnelClock(timeout)
		if got := clock.remaining(); got != timeout {
			t.Fatalf("initial idle budget = %v, want %v", got, timeout)
		}

		clock.last.Store(-int64(2 * time.Second))
		if got := clock.quietFor(); got != 2*time.Second {
			t.Fatalf("activity two seconds before tunnel origin: quiet for %v, want 2s", got)
		}
		time.Sleep(time.Second)
		if got := clock.remaining(); got != 2*time.Second || clock.idle() {
			t.Fatalf("after three seconds of inactivity: remaining = %v, idle = %v", got, clock.idle())
		}

		clock.touch()
		if got := clock.quietFor(); got != 0 {
			t.Fatalf("activity reset: quiet for %v, want 0", got)
		}
		if got := clock.remaining(); got != timeout || clock.idle() {
			t.Fatalf("activity reset: remaining = %v, idle = %v", got, clock.idle())
		}
		time.Sleep(timeout)
		if got := clock.remaining(); got != 0 || !clock.idle() {
			t.Fatalf("idle timeout reached: remaining = %v, idle = %v", got, clock.idle())
		}
	})
}

// TestConnectTunnelIdleTimeoutResetOnData verifies that observed transport
// progress within each idle window keeps the tunnel open.
func TestConnectTunnelIdleTimeoutResetOnData(t *testing.T) {
	// Mock upstream that echoes data back.
	connectUpstream := newMockConnectUpstream(t, func(_ context.Context, conn net.Conn) {
		// Echo data back until the connection is closed (including when the
		// test context cancels and newMockConnectUpstream sets the deadline).
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	})

	proxy := NewProxyUnderTest(t, connectUpstream.Addr().String())
	proxy.SetIdleTimeout(200 * time.Millisecond)
	t.Cleanup(proxy.Close)

	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// Send data every 100ms for 500ms total — all within the 200ms idle timeout
	// because each send resets the deadline.
	for range 5 {
		time.Sleep(100 * time.Millisecond)
		msg := []byte("ping")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write through tunnel: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo response: %v", err)
		}
		if string(buf) != "ping" {
			t.Fatalf("echo mismatch: got %q", buf)
		}
	}
}

// TestConnectTunnelOneWayTransferOutlastsIdleTimeout verifies that the idle
// timeout measures the tunnel as a whole rather than each direction. Observed
// upload progress within each idle window keeps the silent reverse direction
// available for the upstream's reply.
func TestConnectTunnelOneWayTransferOutlastsIdleTimeout(t *testing.T) {
	const (
		idleTimeout = 500 * time.Millisecond
		chunk       = "chunk\n"
		chunks      = 30 // 3x the idle timeout at one chunk per idleTimeout/10.
		reply       = "done\n"
	)

	uploadDone := make(chan struct{})
	connectUpstream := newMockConnectUpstream(t, func(_ context.Context, conn net.Conn) {
		defer close(uploadDone)
		body := make([]byte, chunks*len(chunk))
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, body); err != nil {
			t.Errorf("upstream read upload: %v", err)
			return
		}
		_, _ = io.WriteString(conn, reply)
	})

	proxy := NewProxyUnderTest(t, connectUpstream.Addr().String())
	proxy.SetIdleTimeout(idleTimeout)
	t.Cleanup(proxy.Close)

	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// Upload for 3x the idle timeout while the upstream sends nothing.
	uploadStart := time.Now()
	for range chunks {
		if _, err := conn.Write([]byte(chunk)); err != nil {
			t.Fatalf("upload through tunnel: %v", err)
		}
		time.Sleep(idleTimeout / 10)
	}
	if elapsed := time.Since(uploadStart); elapsed <= idleTimeout {
		t.Fatalf("upload lasted %v, want longer than the idle timeout %v", elapsed, idleTimeout)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(br)
	<-uploadDone
	if err != nil {
		t.Fatalf("read upstream reply: %v", err)
	}
	if string(got) != reply {
		t.Fatalf("client read %q, want the upstream reply %q after a one-way upload lasting %v (idle timeout %v)",
			got, reply, chunks*idleTimeout/10, idleTimeout)
	}
}

// TestConnectTunnelOneWayDownloadOutlastsIdleTimeout is the mirror of
// TestConnectTunnelOneWayTransferOutlastsIdleTimeout: observed download progress
// within each idle window keeps the silent upload direction open. An upstream
// that reads EOF treats it as a disconnect and stops sending.
func TestConnectTunnelOneWayDownloadOutlastsIdleTimeout(t *testing.T) {
	const (
		idleTimeout = 500 * time.Millisecond
		chunk       = "chunk\n"
		chunks      = 30 // 3x the idle timeout at one chunk per idleTimeout/10.
	)

	var mu sync.Mutex
	sent := 0
	readReturned := make(chan int, 1)
	downloadDone := make(chan struct{})
	connectUpstream := newMockConnectUpstream(t, func(_ context.Context, conn net.Conn) {
		defer close(downloadDone)
		// Report how much had been sent when the client side of the tunnel
		// first reads EOF, i.e. when the proxy half-closes the quiet direction.
		go func() {
			_, _ = conn.Read(make([]byte, 1))
			mu.Lock()
			n := sent
			mu.Unlock()
			readReturned <- n
		}()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		for range chunks {
			if _, err := io.WriteString(conn, chunk); err != nil {
				return
			}
			mu.Lock()
			sent++
			mu.Unlock()
			time.Sleep(idleTimeout / 10)
		}
	})

	proxy := NewProxyUnderTest(t, connectUpstream.Addr().String())
	proxy.SetIdleTimeout(idleTimeout)
	t.Cleanup(proxy.Close)

	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// Read the whole download without sending anything back.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(br)
	<-downloadDone
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if want := strings.Repeat(chunk, chunks); string(got) != want {
		t.Fatalf("client read %d bytes, want %d", len(got), len(want))
	}

	var stalledAt int
	select {
	case stalledAt = <-readReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never saw its client side of the tunnel close")
	}
	if stalledAt < chunks {
		t.Fatalf("upstream read returned EOF after %d of %d chunks: the proxy half-closed the quiet direction while data was still flowing",
			stalledAt, chunks)
	}
}

// TestConnectTunnelStalledReaderCloses verifies that a tunnel whose reader
// stops reading is closed by the idle timeout. Without a write deadline the
// proxy blocks in dst.Write once the socket buffers fill, and nothing ends the
// tunnel until the stalled peer closes its socket.
func TestConnectTunnelStalledReaderCloses(t *testing.T) {
	const idleTimeout = 500 * time.Millisecond

	var uploaded atomic.Int64
	connectUpstream := newMockConnectUpstream(t, func(_ context.Context, conn net.Conn) {
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				uploaded.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		chunk := make([]byte, 64*1024)
		for {
			if _, err := conn.Write(chunk); err != nil {
				return
			}
		}
	})

	cfg := defaultTestConfig(connectUpstream.Addr().String(), &stubTokenProvider{token: "test-token"})
	cfg.IdleTimeout = idleTimeout
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Handle exactly one client so the test can observe when its session ends.
	sessionDone := make(chan struct{})
	go func() {
		clientConn, err := ln.Accept()
		if err != nil {
			close(sessionDone)
			return
		}
		handleClient(clientConn, cfg)
		close(sessionDone)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	raw := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		for {
			if _, err := conn.Write([]byte("upload")); err != nil {
				return
			}
			time.Sleep(idleTimeout / 10)
		}
	}()
	defer func() {
		_ = conn.Close()
		<-uploadDone
	}()

	// Never read the tunnel body again: the proxy's writes to this client must
	// eventually stall and the idle timeout must end the session.
	const closeBudget = 10 * idleTimeout
	select {
	case <-sessionDone:
	case <-time.After(closeBudget):
		t.Fatalf("session with a stalled reader still running %v after CONNECT with idle timeout %v",
			closeBudget, idleTimeout)
	}
	if got := uploaded.Load(); got < 2*int64(len("upload")) {
		t.Fatalf("upstream received %d reverse-traffic bytes, want at least two uploads", got)
	}

	// The tunnel must have carried payload before it closed, so this test
	// cannot pass on a session that ended before forwarding anything.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffered, _ := io.ReadAll(br)
	if len(buffered) == 0 {
		t.Fatal("stalled tunnel delivered no upstream payload before closing")
	}
}

func newTunnelTestTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, conn := range []*net.TCPConn{client, server} {
		if err := conn.SetWriteBuffer(1024); err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadBuffer(32 * 1024); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}

func newTunnelTestConnections(t *testing.T, transport string) (client, conn, peer, upstream net.Conn) {
	t.Helper()
	if transport == "pipe" {
		client, conn = net.Pipe()
		peer, upstream = net.Pipe()
	} else {
		client, conn = newTunnelTestTCPPair(t)
		peer, upstream = newTunnelTestTCPPair(t)
	}
	for _, c := range []net.Conn{client, conn, peer, upstream} {
		t.Cleanup(func() { _ = c.Close() })
		if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if transport == "tls" {
		certPEM, keyPEM := generateTestCert(t)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certPEM) {
			t.Fatal("add test TLS root")
		}
		raw := &tunnelConn{Conn: peer}
		tlsClient := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
		tlsServer := tls.Server(upstream, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		handshakeDone := make(chan error, 1)
		go func() { handshakeDone <- tlsServer.Handshake() }()
		if err := tlsClient.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-handshakeDone; err != nil {
			t.Fatal(err)
		}
		peer = &upstreamTLSConn{Conn: tlsClient, transport: raw}
		upstream = tlsServer
	}
	return
}

func TestForwardTunnelTransportProgressWithinTimeoutKeepsBothDirectionsOpen(t *testing.T) {
	for _, transport := range []string{"pipe", "tcp", "tls"} {
		for _, direction := range []string{"upload", "download"} {
			t.Run(transport+"/"+direction, func(t *testing.T) {
				run := func(t *testing.T) {
					timeout := 500 * time.Millisecond
					if transport != "pipe" {
						timeout = 2 * time.Second
					}
					client, conn, peer, upstream := newTunnelTestConnections(t, transport)
					tunnelDone := make(chan struct{})
					go func() {
						defer close(tunnelDone)
						forwardTunnel(conn, peer, bufio.NewReader(conn), bufio.NewReader(peer), timeout)
					}()
					src, dst := client, upstream
					if direction == "download" {
						src, dst = upstream, client
					}
					payload := strings.Repeat("0123456789abcdef", 64*1024)
					buf := make([]byte, 1024)
					interval := 5 * time.Millisecond
					if transport == "pipe" {
						payload = "slow transfer across the tunnel"
						buf = make([]byte, 1)
						interval = timeout / 4
					}
					writeDone := make(chan error, 1)
					producerDone := make(chan struct{})
					producerDuration := make(chan time.Duration, 1)
					start := time.Now()
					go func() {
						_, err := io.WriteString(src, payload)
						producerDuration <- time.Since(start)
						writeDone <- err
						close(producerDone)
					}()
					lastRead := start
					var got strings.Builder
					for got.Len() < len(payload) {
						n, err := dst.Read(buf)
						if err != nil {
							t.Fatalf("transfer with transport progress delivered %d/%d bytes: %v", got.Len(), len(payload), err)
						}
						if gap := time.Since(lastRead); gap >= timeout {
							t.Fatalf("test fixture paused byte delivery for %v, idle timeout %v", gap, timeout)
						}
						lastRead = time.Now()
						_, _ = got.Write(buf[:n])
						if transport != "pipe" {
							select {
							case <-producerDone:
								interval = 0
							default:
							}
						}
						time.Sleep(interval)
					}
					if got.String() != payload {
						t.Fatal("transfer with transport progress changed the payload")
					}
					if elapsed := time.Since(start); elapsed <= timeout {
						t.Fatalf("transfer lasted %v, want longer than %v", elapsed, timeout)
					}
					if err := <-writeDone; err != nil {
						t.Fatalf("source write: %v", err)
					}
					if elapsed := <-producerDuration; transport != "pipe" && elapsed <= timeout {
						t.Fatalf("source write completed in %v, want backpressure lasting longer than %v", elapsed, timeout)
					}
					go func() {
						_, err := io.WriteString(dst, "ack")
						writeDone <- err
					}()
					ack := make([]byte, 3)
					if _, err := io.ReadFull(src, ack); err != nil || string(ack) != "ack" {
						t.Fatalf("quiet direction after slow transfer: %q, %v", ack, err)
					}
					if err := <-writeDone; err != nil {
						t.Fatalf("acknowledgment write: %v", err)
					}
					_ = client.Close()
					_ = upstream.Close()
					select {
					case <-tunnelDone:
					case <-time.After(5 * time.Second):
						t.Fatal("tunnel did not stop after both peers closed")
					}
				}
				if transport == "pipe" {
					synctest.Test(t, run)
				} else {
					run(t)
				}
			})
		}
	}
}

func TestForwardTunnelStalledReaderClosesBothDirections(t *testing.T) {
	for _, transport := range []string{"pipe", "tcp", "tls"} {
		for _, direction := range []string{"upload", "download"} {
			t.Run(transport+"/"+direction, func(t *testing.T) {
				run := func(t *testing.T) {
					const timeout = time.Second
					// The budget absorbs the platform ramp before the stall
					// solidifies: darwin's receive autotuning
					// delays the solid stall past Linux's millisecond-scale
					// saturation. pipe has no kernel buffer, so the virtual-time
					// budget stays tight.
					closeBudget := 30 * timeout
					if transport == "pipe" {
						closeBudget = 2 * timeout
					}
					client, conn, peer, upstream := newTunnelTestConnections(t, transport)
					fixtureDeadline := time.Now().Add(2 * closeBudget)
					for _, c := range []net.Conn{client, conn, peer, upstream} {
						if err := c.SetDeadline(fixtureDeadline); err != nil {
							t.Fatal(err)
						}
					}
					tunnelDone := make(chan struct{})
					go func() {
						defer close(tunnelDone)
						forwardTunnel(conn, peer, bufio.NewReader(conn), bufio.NewReader(peer), timeout)
					}()
					src, dst := client, upstream
					if direction == "download" {
						src, dst = upstream, client
					}
					var workers sync.WaitGroup
					defer func() {
						_ = client.Close()
						_ = upstream.Close()
						workers.Wait()
					}()
					workers.Go(func() {
						payload := strings.Repeat("blocked", 16*1024)
						for {
							if _, err := io.WriteString(src, payload); err != nil {
								return
							}
						}
					})
					var reverseBytes atomic.Int64
					workers.Go(func() {
						buf := make([]byte, 1)
						for {
							n, err := src.Read(buf)
							reverseBytes.Add(int64(n))
							if err != nil {
								return
							}
						}
					})
					workers.Go(func() {
						for {
							if _, err := io.WriteString(dst, "a"); err != nil {
								return
							}
							time.Sleep(timeout / 10)
						}
					})
					time.Sleep(timeout / 2)
					if got := reverseBytes.Load(); got < 2 {
						t.Fatalf("reverse traffic delivered %d bytes, want at least two", got)
					}
					select {
					case <-tunnelDone:
						if !time.Now().Before(fixtureDeadline) {
							t.Fatal("tunnel closed after test fixture deadline expired")
						}
					case <-time.After(closeBudget):
						dump := make([]byte, 1<<20)
						n := runtime.Stack(dump, true)
						t.Logf("goroutines at failure:\n%s", dump[:n])
						t.Fatalf("stalled reader kept tunnel alive with reverse traffic (reverse=%d bytes, budget %v)", reverseBytes.Load(), closeBudget)
					}
				}
				if transport == "pipe" {
					synctest.Test(t, run)
				} else {
					run(t)
				}
			})
		}
	}
}

func TestForwardTunnelEOFAllowsReverseReply(t *testing.T) {
	for _, transport := range []string{"tcp", "tls"} {
		for _, timeout := range []time.Duration{0, time.Second} {
			t.Run(fmt.Sprintf("%s/%v", transport, timeout), func(t *testing.T) {
				client, conn, peer, upstream := newTunnelTestConnections(t, transport)
				tunnelDone := make(chan struct{})
				go func() {
					defer close(tunnelDone)
					forwardTunnel(conn, peer, bufio.NewReader(conn), bufio.NewReader(peer), timeout)
				}()
				if _, err := io.WriteString(client, "request"); err != nil {
					t.Fatal(err)
				}
				if err := closeWrite(client); err != nil {
					t.Fatalf("half-close client: %v", err)
				}
				request, err := io.ReadAll(upstream)
				if err != nil || string(request) != "request" {
					t.Fatalf("half-closed request: %q, %v", request, err)
				}
				if _, err := io.WriteString(upstream, "reply"); err != nil {
					t.Fatal(err)
				}
				if err := closeWrite(upstream); err != nil {
					t.Fatalf("half-close upstream: %v", err)
				}
				reply, err := io.ReadAll(client)
				if err != nil || string(reply) != "reply" {
					t.Fatalf("reply after EOF: %q, %v", reply, err)
				}
				select {
				case <-tunnelDone:
				case <-time.After(5 * time.Second):
					t.Fatal("tunnel did not stop after both peers half-closed")
				}
			})
		}
	}
}

// isEOForClosed returns true if the error indicates a closed or EOF connection.
func isEOForClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "closed") ||
		strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "broken pipe")
}
