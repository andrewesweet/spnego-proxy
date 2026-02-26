package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/netutil"
)

// closeWriteConn wraps a net.Conn and adds a CloseWrite method so the
// type assertion in the forward() half-close path succeeds.
type closeWriteConn struct {
	net.Conn
	closeWriteCalls atomic.Int32
}

func (c *closeWriteConn) CloseWrite() error {
	c.closeWriteCalls.Add(1)
	// Delegate to the underlying conn's CloseWrite if available,
	// otherwise just return nil.
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func TestHandleClientDialTimeout(t *testing.T) {
	// Use an unreachable address (RFC 5737 TEST-NET) to trigger a dial timeout.
	unreachable := "192.0.2.1:1"

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, unreachable, provider, testPseudonym, 50*time.Millisecond, time.Second, 0)
	}()

	// The proxy should respond with 504 when the dial times out (RFC 9209 connection_timeout).
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Errorf("expected status 504, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=connection_timeout" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=connection_timeout", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: connection_timeout") {
		t.Errorf("expected body to contain %q, got: %q", "spnego-proxy error: connection_timeout", body)
	}
	if !strings.Contains(string(body), "timed out connecting to the upstream proxy") {
		t.Errorf("expected body to describe timeout, got: %q", body)
	}
	if !strings.Contains(string(body), "Suggested action:") {
		t.Errorf("expected body to contain suggested action, got: %q", body)
	}

	select {
	case <-done:
		// handleClient returned promptly — dial timed out as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s; dial timeout not effective")
	}
}

func TestHandleClientReadTimeout(t *testing.T) {
	// Start a fake upstream proxy that accepts but does nothing.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// Create a client connection that connects but never sends data.
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 50*time.Millisecond, 0)
	}()

	// The proxy should respond with 400 when it can't read the client request.
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=http_request_error" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=http_request_error", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: http_request_error") {
		t.Errorf("expected body to contain %q, got: %q", "spnego-proxy error: http_request_error", body)
	}
	if !strings.Contains(string(body), "could not read or parse the HTTP request") {
		t.Errorf("expected body to describe request read failure, got: %q", body)
	}
	if !strings.Contains(string(body), "Suggested action:") {
		t.Errorf("expected body to contain suggested action, got: %q", body)
	}

	select {
	case <-done:
		// handleClient returned promptly — read deadline fired as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s; read timeout not effective")
	}
}

func TestLimitListenerBlocksAtCapacity(t *testing.T) {
	const limit = 2

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	ln = netutil.LimitListener(ln, limit)

	// acceptCh delivers server-side accepted connections for coordination.
	acceptCh := make(chan net.Conn, limit+1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			acceptCh <- c
		}
	}()

	// Fill all slots.
	clients := make([]net.Conn, limit)
	servers := make([]net.Conn, limit)
	for i := 0; i < limit; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		clients[i] = c
		select {
		case servers[i] = <-acceptCh:
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for server to accept connection %d", i)
		}
	}

	// The next dial may succeed at the TCP level (kernel SYN queue), but
	// LimitListener.Accept will block on its semaphore.
	extra, dialErr := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if dialErr == nil {
		defer func() { _ = extra.Close() }()
	}

	// Verify Accept has not delivered a third connection yet.
	select {
	case c := <-acceptCh:
		_ = c.Close()
		t.Fatal("LimitListener accepted beyond its capacity")
	case <-time.After(100 * time.Millisecond):
		// Expected: Accept is blocked.
	}

	// Release one slot by closing a server-side connection (this releases
	// the LimitListener semaphore).
	_ = servers[0].Close()
	_ = clients[0].Close()

	// If the extra dial succeeded, its connection should now be accepted.
	if extra != nil {
		select {
		case c := <-acceptCh:
			_ = c.Close()
			// Success: the blocked Accept proceeded after a slot was freed.
		case <-time.After(time.Second):
			t.Error("expected blocked connection to be accepted after releasing a slot")
		}
	}

	// Clean up remaining connections.
	for _, c := range clients[1:] {
		_ = c.Close()
	}
	for _, c := range servers[1:] {
		_ = c.Close()
	}
}

// TestShutdownStopsAcceptingNewConnections verifies that cancelling the
// context and closing the listener causes the accept loop to stop and
// prevents new connections from being accepted — the core mechanism that
// makes graceful shutdown work (issue #60).
func TestShutdownStopsAcceptingNewConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Run the same accept-loop pattern used in main().
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			_, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
		}
	}()

	// Simulate signal: cancel context, then close listener.
	cancel()
	_ = ln.Close()

	select {
	case <-acceptDone:
		// Accept loop exited as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop did not exit after context cancellation and listener close")
	}

	// New connections should be refused.
	_, err = net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial to fail after listener closed")
	}
}

// TestShutdownDrainsInFlightConnections verifies that in-flight handleClient
// goroutines are allowed to complete before shutdown proceeds, and that
// provider.Close() is called afterward (issue #60).
func TestShutdownDrainsInFlightConnections(t *testing.T) {
	// Start a fake upstream proxy that echoes a valid HTTP response.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Read the request, then send a minimal HTTP response.
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	provider := &stubTokenProvider{token: "tok"}
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
			}()
		}
	}()

	// Establish a connection and send a request through the proxy.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read response to confirm the handler is processing.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	_ = conn.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Now simulate shutdown.
	cancel()
	_ = ln.Close()

	// Wait for drain (same pattern as main).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		// All in-flight connections drained.
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight connections did not drain within 5s")
	}

	// Verify provider cleanup runs after drain.
	_ = provider.Close()
	if !provider.closed.Load() {
		t.Error("expected provider to be closed after shutdown")
	}
}

// TestShutdownDrainTimeout verifies that the drain timeout mechanism works:
// if in-flight connections don't complete within the timeout, shutdown
// proceeds anyway rather than blocking forever (issue #60).
func TestShutdownDrainTimeout(t *testing.T) {
	// Start a fake upstream that holds connections open indefinitely.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				// Read request then hold the connection open.
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				resp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
				_, _ = c.Write([]byte(resp))
				// Block until closed externally.
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	provider := &stubTokenProvider{token: "tok"}
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
			}()
		}
	}()

	// Establish a connection through the proxy.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	// Wait briefly for the handler to start processing.
	time.Sleep(100 * time.Millisecond)

	// Simulate shutdown.
	cancel()
	_ = ln.Close()

	// Use a short drain timeout (like main does with --drain-timeout).
	drainTimeout := 200 * time.Millisecond
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)
		select {
		case <-done:
			// Drained in time.
		case <-time.After(drainTimeout):
			// Timeout exceeded — shutdown proceeds anyway.
		}
		_ = provider.Close()
	}()

	select {
	case <-shutdownComplete:
		// Shutdown completed (via timeout, since the connection is held open).
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete within 5s; drain timeout mechanism broken")
	}

	if !provider.closed.Load() {
		t.Error("expected provider to be closed after drain timeout")
	}
}

func TestHandleClientTokenErrorReturns502(t *testing.T) {
	// Start a fake upstream that holds connections open.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &stubTokenProvider{err: errors.New("GSS-API error: An unsupported mechanism was requested")}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	// Send a request through the client side of the pipe.
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	_ = req.WriteProxy(client)

	// The proxy should respond with 502 instead of just closing.
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=proxy_internal_error" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=proxy_internal_error", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: proxy_internal_error") {
		t.Errorf("expected body to contain %q, got: %q", "spnego-proxy error: proxy_internal_error", body)
	}
	if !strings.Contains(string(body), "failed to acquire a SPNEGO authentication token") {
		t.Errorf("expected body to describe token acquisition failure, got: %q", body)
	}
	if !strings.Contains(string(body), "Suggested action:") {
		t.Errorf("expected body to contain suggested action, got: %q", body)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

func TestHandleClientCircuitBreakerErrorReturnsDistinctBody(t *testing.T) {
	// Verify that a circuit breaker error produces a distinct body from
	// a regular token acquisition error (issue #113, section 4).
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	// Use a CircuitBreakerError to simulate the circuit breaker being open.
	provider := &stubTokenProvider{err: &CircuitBreakerError{
		msg:   "circuit breaker open: token acquisition disabled after 3 consecutive failures",
		cause: errors.New("gobreaker: open state"),
	}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	_ = req.WriteProxy(client)

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=proxy_internal_error" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=proxy_internal_error", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "circuit breaker open") {
		t.Errorf("expected body to mention circuit breaker, got: %q", body)
	}
	if !strings.Contains(bodyStr, "temporarily disabled after repeated failures") {
		t.Errorf("expected body to describe circuit breaker state, got: %q", body)
	}
	// The circuit breaker body should NOT contain the regular token error message.
	if strings.Contains(bodyStr, "failed to acquire a SPNEGO authentication token") {
		t.Errorf("expected circuit breaker body to differ from regular token error, got: %q", body)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

func TestHandleClientTokenErrorCONNECTReturns502(t *testing.T) {
	// Verify CONNECT requests also get a 502 (this is the common case
	// for HTTPS traffic through a proxy, and what curl uses).
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	// Use a real TCP listener so the client and server are decoupled
	// (net.Pipe has strict synchronous semantics that can interact
	// poorly with CONNECT request parsing).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{err: errors.New("GSS-API error: An unsupported mechanism was requested")}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send a CONNECT request (what curl does for HTTPS through a proxy).
	_, err = io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=proxy_internal_error" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=proxy_internal_error", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: proxy_internal_error") {
		t.Errorf("expected CONNECT body to contain %q, got: %q", "spnego-proxy error: proxy_internal_error", body)
	}
	if !strings.Contains(string(body), "failed to acquire a SPNEGO authentication token") {
		t.Errorf("expected CONNECT body to describe token acquisition failure, got: %q", body)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestHandleClientForwardsBufferedData verifies that data buffered by
// bufio.NewReader beyond the initial HTTP request is forwarded to the
// upstream proxy (issue #67). This simulates an HTTP pipelining scenario
// where the client sends additional bytes in the same segment as the
// request headers.
func TestHandleClientForwardsBufferedData(t *testing.T) {
	// extraPayload is additional data sent immediately after the HTTP
	// request, in the same write — it will be buffered by bufio.NewReader
	// but never consumed by http.ReadRequest.
	const extraPayload = "EXTRA-PIPELINED-DATA"

	// Start a fake upstream proxy that echoes back the CONNECT 200,
	// then reads and records everything the proxy sends after the
	// initial request.
	gotExtra := make(chan string, 1)
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the initial CONNECT request forwarded by handleClient.
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			gotExtra <- "READ_ERR: " + err.Error()
			gotVia <- "READ_ERR: " + err.Error()
			return
		}
		gotVia <- req.Header.Get("Via")
		_ = req.Body.Close()

		// Send 200 to complete the CONNECT handshake.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		// Now read whatever comes next — this should include extraPayload
		// that was buffered by the proxy's bufio.NewReader.
		buf := make([]byte, 4096)
		n, _ := reader.Read(buf)
		gotExtra <- string(buf[:n])
	}()

	// Set up the local proxy listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	// Connect to the local proxy and send a CONNECT request followed
	// immediately by extra data in the same write, so it lands in the
	// same bufio buffer as the request headers.
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	connectReq := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + extraPayload
	if _, err := io.WriteString(client, connectReq); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read the 200 response relayed back from upstream.
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Close client side to unblock forwarding goroutines.
	_ = client.Close()

	// Verify upstream received the extra payload.
	select {
	case got := <-gotExtra:
		if got != extraPayload {
			t.Errorf("upstream received %q, want %q", got, extraPayload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive extra payload")
	}

	// Verify the Via header was added to the forwarded CONNECT request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != wantVia {
			t.Errorf("Via header = %q, want %q", got, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream Via header")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestCloseWriteCalledOnForwardCompletion verifies that the half-close
// path (CloseWrite) is exercised when forwarding completes. net.Pipe
// does not implement CloseWrite, so this test uses a wrapper that
// tracks invocations (issue #75).
func TestCloseWriteCalledOnForwardCompletion(t *testing.T) {
	// Start a fake upstream proxy that reads the request then sends
	// a short response and closes.
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			gotVia <- "READ_ERR: " + err.Error()
		} else {
			gotVia <- req.Header.Get("Via")
			_ = req.Body.Close()
		}
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
		_, _ = conn.Write([]byte(resp))
	}()

	// Set up the local proxy listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	wrapped := &closeWriteConn{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wrapped.Conn = conn
		handleClient(wrapped, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	// Connect to the local proxy and send a request.
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(client); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Close client to unblock forwarding goroutines.
	_ = client.Close()

	// Verify the Via header was added to the forwarded request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != wantVia {
			t.Errorf("Via header = %q, want %q", got, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream Via header")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}

	// The forward() function sends data proxy→client via the wrapped
	// conn, so CloseWrite must have been called on it at least once.
	if n := wrapped.closeWriteCalls.Load(); n == 0 {
		t.Error("expected CloseWrite to be called on the client connection, but it was not")
	}
}

func TestEnableKeepAlive(t *testing.T) {
	// enableKeepAlive should configure keepalive on real TCP connections
	// without error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.Close() }()

	select {
	case serverConn := <-accepted:
		defer func() { _ = serverConn.Close() }()
		// Should succeed on TCP connections without panic.
		enableKeepAlive(serverConn, 30*time.Second)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accept")
	}
	enableKeepAlive(clientConn, 30*time.Second)

	// Should be a silent no-op on non-TCP connections (e.g. net.Pipe).
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	enableKeepAlive(a, 30*time.Second)
	enableKeepAlive(b, 30*time.Second)
}

// TestHandleClientKeepAlive verifies that handleClient works correctly
// when TCP keepalive is enabled on forwarded connections (issue #74).
func TestHandleClientKeepAlive(t *testing.T) {
	// Start a fake upstream proxy that echoes a valid HTTP response.
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					gotVia <- "READ_ERR: " + err.Error()
				} else {
					gotVia <- req.Header.Get("Via")
					_ = req.Body.Close()
				}
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Pass a non-zero keepalive to exercise the keepalive code path.
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 30*time.Second)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(client); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("expected body %q, got %q", "OK", body)
	}

	_ = client.Close()

	// Verify the Via header was added to the forwarded request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != wantVia {
			t.Errorf("Via header = %q, want %q", got, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream Via header")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestHandleClientAddsViaHeader verifies that handleClient adds a Via header
// to requests forwarded to the upstream proxy (RFC 9110 §7.6.3).
func TestHandleClientAddsViaHeader(t *testing.T) {
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			gotVia <- "READ_ERR: " + err.Error()
			return
		}
		_ = req.Body.Close()
		gotVia <- req.Header.Get("Via")
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
		_, _ = conn.Write([]byte(resp))
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(client); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = client.Close()

	want := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != want {
			t.Errorf("Via header = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive request")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestHandleClientAppendsToExistingVia verifies that handleClient appends to
// an existing Via header rather than replacing it (RFC 9110 §7.6.3).
func TestHandleClientAppendsToExistingVia(t *testing.T) {
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			gotVia <- "READ_ERR: " + err.Error()
			return
		}
		_ = req.Body.Close()
		gotVia <- req.Header.Get("Via")
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
		_, _ = conn.Write([]byte(resp))
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send a request that already has a Via header from a prior proxy.
	_, err = io.WriteString(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nVia: 1.0 other-proxy\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = client.Close()

	want := "1.0 other-proxy, HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != want {
			t.Errorf("Via header = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive request")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestHandleClientLoopDetection verifies that handleClient detects routing
// loops by checking whether its own pseudonym appears in an incoming Via
// header, returning 502 with proxy_loop_detected (issue #114, Section 2).
func TestHandleClientLoopDetection(t *testing.T) {
	// Start a fake upstream that holds connections open.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send a request with a Via header that already contains our pseudonym,
	// simulating a routing loop.
	_, err = io.WriteString(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nVia: HTTP/1.1 "+testPseudonym+"\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("expected HTTP error response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}
	if ps := resp.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=proxy_loop_detected" {
		t.Errorf("expected Proxy-Status header %q, got %q", "spnego-proxy; error=proxy_loop_detected", ps)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: proxy_loop_detected") {
		t.Errorf("expected body to contain %q, got: %q", "spnego-proxy error: proxy_loop_detected", body)
	}
	if !strings.Contains(string(body), "routing loop was detected") {
		t.Errorf("expected body to describe loop detection, got: %q", body)
	}

	// Verify the token provider was NOT called (loop detected before token acquisition).
	if calls := provider.calls.Load(); calls != 0 {
		t.Errorf("expected 0 token provider calls, got %d", calls)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// TestHandleClientNoLoopWithDifferentPseudonym verifies that a Via header
// containing a different spnego-proxy instance's pseudonym does NOT trigger
// loop detection — only our own pseudonym indicates a loop.
func TestHandleClientNoLoopWithDifferentPseudonym(t *testing.T) {
	gotVia := make(chan string, 1)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			gotVia <- "READ_ERR: " + err.Error()
			return
		}
		_ = req.Body.Close()
		gotVia <- req.Header.Get("Via")
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
		_, _ = conn.Write([]byte(resp))
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, upstream.Addr().String(), provider, testPseudonym, 5*time.Second, 5*time.Second, 0)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send a request with a Via header from a DIFFERENT spnego-proxy instance.
	// This should NOT trigger loop detection.
	_, err = io.WriteString(client, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nVia: HTTP/1.1 spnego-proxy-other123\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = client.Close()

	// Should get a 200 (request forwarded successfully), not a 502.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Verify upstream received the request with both Via entries.
	want := "HTTP/1.1 spnego-proxy-other123, HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != want {
			t.Errorf("Via header = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive request")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}
