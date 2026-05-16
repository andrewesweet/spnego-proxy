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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
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
				if got := resp.Header.Get("Proxy-Status"); got != wantPS {
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
	assertHeaderAbsent(t, resp.Header, "Content-Length")
	assertHeaderAbsent(t, resp.Header, "Connection")
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

// TestConnectTunnelIdleTimeoutResetOnData verifies that active tunnels that
// continuously exchange data are NOT interrupted by the idle timeout, because
// each successful read resets the deadline.
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
