package main

// connect_test.go — RFC compliance tests for CONNECT tunnel handling.
//
// Requirements covered:
//
//	D4 — Restrict CONNECT to safe ports (RFC 9110 §9.3.6 SHOULD)
//	D5 — Close connection when rejecting a CONNECT request (RFC 9112 §11.2 MUST)
//	D6 — Wait for upstream 2xx before forwarding client payload (RFC 9112 §11.2 MUST)
//	D2 — Drain buffered data on tunnel close (RFC 9110 §9.3.6 MUST)
//	D7 — Do not send 2xx to client without established upstream connection (RFC 9110 §9.3.6 MUST NOT)

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// D4 — Port restriction
// ---------------------------------------------------------------------------

// TestD4_ConnectToAllowedPortSucceeds verifies that when connectPorts is set
// and the target port is in the allowed list, the CONNECT tunnel is established
// successfully.
func TestD4_ConnectToAllowedPortSucceeds(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
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
	proxy.SetConnectPorts([]string{"443", "8443"})
	t.Cleanup(proxy.Close)

	client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
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

	assertStatusCode(t, resp, http.StatusOK)
}

// TestD4_ConnectToDisallowedPortReturnsForbidden verifies that when
// connectPorts is non-empty and the target port is not in the allowed list,
// the proxy returns 403 Forbidden.
func TestD4_ConnectToDisallowedPortReturnsForbidden(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	proxy.SetConnectPorts([]string{"443", "8443"})
	t.Cleanup(proxy.Close)

	client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_, err = io.WriteString(client, "CONNECT example.com:25 HTTP/1.1\r\nHost: example.com:25\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusForbidden)

	wantPS := "spnego-proxy; error=http_request_denied"
	if got := resp.Header.Get("Proxy-Status"); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "http_request_denied") {
		t.Errorf("body: want mention of http_request_denied, got %q", body)
	}

	// Upstream must not have received any request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d request(s), want 0", n)
	}
}

// TestD4_EmptyPortListAllowsAll verifies that when connectPorts is empty
// (the default), any port is allowed for CONNECT.
func TestD4_EmptyPortListAllowsAll(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
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
	// ConnectPorts is left empty — all ports allowed.
	t.Cleanup(proxy.Close)

	for _, port := range []string{"25", "443", "8080", "9999"} {
		port := port
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

// TestD4_DefaultPort443WhenNoPortSpecified verifies that a CONNECT target
// with no explicit port (e.g. "example.com") is treated as port 443 when
// checking against the allowed port list.
func TestD4_DefaultPort443WhenNoPortSpecified(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
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
	proxy.SetConnectPorts([]string{"443"}) // only 443 allowed
	t.Cleanup(proxy.Close)

	client, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Send CONNECT without a port — should default to 443 and be allowed.
	_, err = io.WriteString(client, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
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

	// Start a manual upstream server so we can interleave reading and writing
	// with precise timing control.
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

		reader := bufio.NewReader(conn)

		// Read the forwarded CONNECT request.
		req, err := http.ReadRequest(reader)
		if err != nil {
			_ = conn.Close()
			return
		}
		_ = req.Body.Close()

		// Delay before responding — this is the window during which a
		// broken implementation would forward the client's TLS handshake.
		time.Sleep(100 * time.Millisecond)

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
		handleClient(conn, upstreamLn.Addr().String(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
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
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
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
		handleClient(conn, upstream.Addr(), provider, testPseudonym,
			5*time.Second, 5*time.Second, 0, nil)
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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
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
// are delivered to the client before EOF. This tests the upstream→client
// direction of D2 (RFC 9110 §9.3.6).
func TestD2_UpstreamBufferedDataDrainedOnClose(t *testing.T) {
	const tunnelPayload = "TUNNEL-DATA-FROM-UPSTREAM-THAT-MUST-ARRIVE"

	// The mock upstream sends a 200 for CONNECT, then writes tunnel data
	// and closes the connection.
	upstream := NewMockUpstreamProxy(t, func(req *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}
	})
	// We need to inject tunnel data after the 200 response. Override the
	// mock's handleConn by using a raw listener instead.
	upstream.Close()

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

// isEOForClosed returns true if the error indicates a closed or EOF connection.
func isEOForClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return err == io.EOF ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "closed") ||
		strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "broken pipe")
}
