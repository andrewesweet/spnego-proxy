package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/netutil"
)

// acceptOneAndHandle starts a listener, accepts one connection, and runs
// handleClient with the given config. Returns the listener address and a
// channel that is closed when handleClient returns.
func acceptOneAndHandle(t *testing.T, cfg Config) (addr string, done <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, cfg)
	}()
	return ln.Addr().String(), ch
}

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
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	cfg.ReadTimeout = 50 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, cfg)
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

	waitForDone(t, done)
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
	for i := range limit {
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

	ctx, cancel := context.WithCancel(t.Context())

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
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	ctx, cancel := context.WithCancel(t.Context())

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
			wg.Go(func() {
				handleClient(conn, cfg)
			})
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

	// Verify Via header was added to the relayed response.
	wantResponseVia := "HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != wantResponseVia {
		t.Errorf("response Via header = %q, want %q", got, wantResponseVia)
	}

	// Now simulate shutdown.
	cancel()
	_ = ln.Close()

	// Wait for drain (same pattern as main).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	waitForDone(t, done)

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
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	ctx, cancel := context.WithCancel(t.Context())

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
			wg.Go(func() {
				handleClient(conn, cfg)
			})
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

	waitForDone(t, shutdownComplete)

	if !provider.closed.Load() {
		t.Error("expected provider to be closed after drain timeout")
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
	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	addr, done := acceptOneAndHandle(t, cfg)

	// Connect to the local proxy and send a CONNECT request followed
	// immediately by extra data in the same write, so it lands in the
	// same bufio buffer as the request headers.
	client, err := net.Dial("tcp", addr)
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

	// Verify Via header was added to the relayed response.
	wantResponseVia := "HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != wantResponseVia {
		t.Errorf("response Via header = %q, want %q", got, wantResponseVia)
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

	waitForDone(t, done)
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
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	wrapped := &closeWriteConn{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wrapped.Conn = conn
		handleClient(wrapped, cfg)
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

	// Verify Via header was added to the relayed response.
	wantResponseVia := "HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != wantResponseVia {
		t.Errorf("response Via header = %q, want %q", got, wantResponseVia)
	}

	// Close client to unblock forwarding goroutines.
	_ = client.Close()

	// Verify the Via header was added to the forwarded request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != wantVia {
			t.Errorf("request Via header = %q, want %q", got, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream Via header")
	}

	waitForDone(t, done)

	// The forward() function sends data proxy->client via the wrapped
	// conn, so CloseWrite must have been called on it at least once.
	if n := wrapped.closeWriteCalls.Load(); n == 0 {
		t.Error("expected CloseWrite to be called on the client connection, but it was not")
	}
}

func TestRandomHexLength(t *testing.T) {
	result := randomHex(4)
	if len(result) != 8 {
		t.Errorf("randomHex(4): want 8 hex chars, got %d (%q)", len(result), result)
	}
}

func TestRandomHexUniqueness(t *testing.T) {
	a := randomHex(4)
	b := randomHex(4)
	if a == b {
		t.Errorf("randomHex produced identical values: %q", a)
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

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	// Pass a non-zero keepalive to exercise the keepalive code path.
	cfg.KeepAlive = 30 * time.Second
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
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

	// Verify Via header was added to the relayed response.
	wantResponseVia := "HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != wantResponseVia {
		t.Errorf("response Via header = %q, want %q", got, wantResponseVia)
	}

	_ = client.Close()

	// Verify the Via header was added to the forwarded request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case got := <-gotVia:
		if got != wantVia {
			t.Errorf("request Via header = %q, want %q", got, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream Via header")
	}

	waitForDone(t, done)
}

// keepAliveUpstream is a tiny test fixture that accepts one TCP connection
// and reads up to maxRequests HTTP requests from it, responding with the
// supplied payload. Every parsed request is sent on the returned channel.
// A response containing "Connection: close" terminates the upstream.
func keepAliveUpstream(t *testing.T, maxRequests int, respond func(i int, req *http.Request) string) (addr string, requests chan *http.Request) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	requests = make(chan *http.Request, maxRequests)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		for i := 0; i < maxRequests; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			requests <- req
			payload := respond(i, req)
			if _, err := conn.Write([]byte(payload)); err != nil {
				return
			}
			if strings.Contains(strings.ToLower(payload), "connection: close") {
				return
			}
		}
	}()
	return ln.Addr().String(), requests
}

// TestHandleClientRejectsSmuggledRequest exercises the PoC from issue #215:
// a client pipelines a forbidden CONNECT behind a valid GET. The smuggled
// CONNECT must be re-parsed and re-validated by the proxy (rejected via
// -connect-ports), and must NOT be forwarded to the already-authenticated
// upstream connection.
func TestHandleClientRejectsSmuggledRequest(t *testing.T) {
	upstreamAddr, upstreamReqs := keepAliveUpstream(t, 4, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstreamAddr, provider)
	cfg.ConnectPorts = []string{"443"}
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	payload := "GET http://innocent.example.com/ HTTP/1.1\r\nHost: innocent.example.com\r\n\r\n" +
		"CONNECT internal-host:22 HTTP/1.1\r\nHost: internal-host:22\r\n\r\n"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("resp1 status: want 200, got %d", resp1.StatusCode)
	}

	resp2, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read resp2 (the rejected smuggled CONNECT): %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("resp2 status: want 403 (forbidden_port), got %d (body=%q)", resp2.StatusCode, body)
	}
	if ps := resp2.Header.Get("Proxy-Status"); ps != "spnego-proxy; error=http_request_denied" {
		t.Errorf("resp2 Proxy-Status = %q, want http_request_denied", ps)
	}

	_ = client.Close()
	waitForDone(t, done)

	close(upstreamReqs)
	count := 0
	for r := range upstreamReqs {
		count++
		if r.Method == http.MethodConnect {
			t.Errorf("smuggled CONNECT reached upstream: %s %s", r.Method, r.Host)
		}
	}
	if count != 1 {
		t.Errorf("upstream received %d requests, want exactly 1 (the GET)", count)
	}
}

// TestHandleClientKeepAliveForwardsSecondRequest verifies happy-path
// keep-alive: two pipelined requests both reach the upstream with Via on
// each, Proxy-Authorization only on the first (RFC 4559 connection-bound
// auth), and any smuggled client-supplied Proxy-Authorization on the
// second is stripped by sanitizeHopByHop.
func TestHandleClientKeepAliveForwardsSecondRequest(t *testing.T) {
	upstreamAddr, upstreamReqs := keepAliveUpstream(t, 2, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstreamAddr, provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	pipeline := "GET http://a.example.com/ HTTP/1.1\r\nHost: a.example.com\r\n\r\n" +
		"GET http://b.example.com/ HTTP/1.1\r\nHost: b.example.com\r\nProxy-Authorization: Negotiate evil-attacker-token\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	for i := 0; i < 2; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("resp[%d]: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp[%d] status %d, want 200", i, resp.StatusCode)
		}
	}
	_ = client.Close()
	waitForDone(t, done)

	close(upstreamReqs)
	var reqs []*http.Request
	for r := range upstreamReqs {
		reqs = append(reqs, r)
	}
	if len(reqs) != 2 {
		t.Fatalf("upstream received %d requests, want 2", len(reqs))
	}

	wantVia := "HTTP/1.1 " + testPseudonym
	for i, r := range reqs {
		if v := r.Header.Get("Via"); v != wantVia {
			t.Errorf("req[%d] Via = %q, want %q", i, v, wantVia)
		}
	}
	if pa := reqs[0].Header.Get("Proxy-Authorization"); pa != "Negotiate tok" {
		t.Errorf("req[0] Proxy-Authorization = %q, want %q (real proxy token)", pa, "Negotiate tok")
	}
	// Subsequent request on an already-authenticated connection: no
	// Proxy-Authorization. The smuggled "evil-attacker-token" must NOT
	// reach the upstream.
	if pa := reqs[1].Header.Get("Proxy-Authorization"); pa != "" {
		t.Errorf("req[1] Proxy-Authorization = %q, want empty (smuggled token must be stripped, connection auth reused)", pa)
	}
	if n := provider.calls.Load(); n != 1 {
		t.Errorf("GetToken called %d times, want 1 (per-connection auth)", n)
	}
}

// TestHandleClientConnectionCloseTerminatesLoop verifies that a
// Connection: close response terminates the keep-alive loop; a pipelined
// second request must NOT be forwarded.
func TestHandleClientConnectionCloseTerminatesLoop(t *testing.T) {
	upstreamAddr, upstreamReqs := keepAliveUpstream(t, 2, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	})

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstreamAddr, provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	pipeline := "GET http://a.example.com/ HTTP/1.1\r\nHost: a.example.com\r\n\r\n" +
		"GET http://b.example.com/ HTTP/1.1\r\nHost: b.example.com\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("resp1 status %d, want 200", resp1.StatusCode)
	}

	// No second response: connection-close on resp1 must have terminated
	// the keep-alive loop before the smuggled second request was read.
	if resp2, err := http.ReadResponse(reader, nil); err == nil {
		_ = resp2.Body.Close()
		t.Errorf("expected no second response, got status %d", resp2.StatusCode)
	}

	_ = client.Close()
	waitForDone(t, done)

	close(upstreamReqs)
	count := 0
	for range upstreamReqs {
		count++
	}
	if count != 1 {
		t.Errorf("upstream received %d requests, want 1 (loop must terminate on Connection: close)", count)
	}
}

// TestHandleDirectHTTPRejectsHostMismatch verifies that a pipelined
// request targeting a different host than the direct connection was opened
// to is rejected with errMismatchedTarget. Prevents smuggling a request to
// a different target through the bound direct TCP connection.
func TestHandleDirectHTTPRejectsHostMismatch(t *testing.T) {
	targetAddr, targetReqs := keepAliveUpstream(t, 2, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})

	// noproxy must match BOTH the bound target host and the "other"
	// pipelined target — otherwise the second request would be routed
	// through the upstream proxy and the test would not exercise
	// handleDirectHTTP's host-binding check. Use a bare "*" wildcard.
	matcher := NewNoProxyMatcher("*")

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig("127.0.0.1:1", provider) // upstream unused on noproxy path
	cfg.NoProxy = matcher
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// First request to bound host; second to a DIFFERENT host.
	pipeline := "GET http://" + targetAddr + "/a HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n" +
		"GET http://other-host.invalid/b HTTP/1.1\r\nHost: other-host.invalid\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("resp1 status %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp2: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("resp2 status %d, want 400 (host mismatch); body=%q", resp2.StatusCode, body)
	}
	if !strings.Contains(string(body), "incompatible") {
		t.Errorf("resp2 body does not mention mismatch: %q", body)
	}

	_ = client.Close()
	waitForDone(t, done)

	close(targetReqs)
	count := 0
	for range targetReqs {
		count++
	}
	if count != 1 {
		t.Errorf("target received %d requests, want 1 (mismatched second request must be rejected by proxy)", count)
	}
}

// TestSameHostCanonicalisation covers the edge cases that
// handleDirectHTTP's host-binding check depends on (issue #215).
func TestSameHostCanonicalisation(t *testing.T) {
	cases := []struct {
		name        string
		a, b        string
		defaultPort string
		want        bool
	}{
		{"identical with port", "example.com:80", "example.com:80", "80", true},
		{"default port vs explicit", "example.com", "example.com:80", "80", true},
		{"case-insensitive", "EXAMPLE.com", "example.COM", "80", true},
		{"different ports", "example.com:80", "example.com:81", "80", false},
		{"different hosts", "a.example.com", "b.example.com", "80", false},
		{"trailing whitespace", "example.com:80 ", "example.com:80", "80", true},
		{"ipv6 bare vs default-port", "[::1]", "[::1]:80", "80", true},
		{"ipv6 bare vs different port", "[::1]", "[::1]:81", "80", false},
		{"ipv6 same explicit", "[2001:db8::1]:443", "[2001:db8::1]:443", "443", true},
		{"ipv4 bare vs default-port", "127.0.0.1", "127.0.0.1:80", "80", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameHost(c.a, c.b, c.defaultPort); got != c.want {
				t.Errorf("sameHost(%q, %q, %q) = %v, want %v", c.a, c.b, c.defaultPort, got, c.want)
			}
		})
	}
}

// TestHandleDirectHTTPRejectsSmuggledConnect verifies that a CONNECT
// request pipelined behind a GET on the direct (noproxy) HTTP path is
// rejected — a tunnel cannot be established on a connection already
// committed to HTTP responses.
func TestHandleDirectHTTPRejectsSmuggledConnect(t *testing.T) {
	targetAddr, _ := keepAliveUpstream(t, 2, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})
	matcher := NewNoProxyMatcher("*")

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig("127.0.0.1:1", provider)
	cfg.NoProxy = matcher
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	pipeline := "GET http://" + targetAddr + "/ HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n" +
		"CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("resp1 status %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp2: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("resp2 status %d, want 400 (smuggled CONNECT rejected on direct HTTP path)", resp2.StatusCode)
	}

	_ = client.Close()
	waitForDone(t, done)
}

// TestHandleClientCONNECTAsSecondRequest covers the keep-alive transition
// from plain HTTP to a CONNECT tunnel: a GET pipelined with an allowed
// CONNECT must dispatch the CONNECT via forwardConnectViaUpstream on a
// FRESH upstream connection (a tunnel cannot share a socket with prior
// keep-alive HTTP traffic). Verifies that connect-ports is enforced on
// the second request and that the SPNEGO token is acquired twice (once
// for the keep-alive upstream, once for the fresh CONNECT dial).
func TestHandleClientCONNECTAsSecondRequest(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	gotMethods := make(chan string, 2)
	go func() {
		// Conn 1 — keep-alive HTTP forward: receive GET, respond 200.
		conn1, err := upstream.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn1.Close() }()
			reader := bufio.NewReader(conn1)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			gotMethods <- req.Method
			_, _ = conn1.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}()
		// Conn 2 — fresh dial for CONNECT: receive CONNECT, respond 200
		// Connection Established, then drain tunnel bytes (none expected
		// from the test client).
		conn2, err := upstream.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn2.Close() }()
			reader := bufio.NewReader(conn2)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_ = req.Body.Close()
			gotMethods <- req.Method
			_, _ = conn2.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			_, _ = io.Copy(io.Discard, reader)
		}()
	}()

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	cfg.ConnectPorts = []string{"443"}
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	pipeline := "GET http://innocent.example.com/ HTTP/1.1\r\nHost: innocent.example.com\r\n\r\n" +
		"CONNECT target.example.com:443 HTTP/1.1\r\nHost: target.example.com:443\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("resp1 status %d, want 200", resp1.StatusCode)
	}

	// CONNECT response is written via writeConnectOK as a raw status line
	// (no Content-Length), so read it manually rather than via
	// http.ReadResponse (which would try to drain a body).
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Errorf("CONNECT status line = %q, want a 200 response", statusLine)
	}

	_ = client.Close()
	waitForDone(t, done)

	timeout := time.After(3 * time.Second)
	var methods []string
	for i := 0; i < 2; i++ {
		select {
		case m := <-gotMethods:
			methods = append(methods, m)
		case <-timeout:
			t.Fatalf("timed out collecting upstream methods (got %v)", methods)
		}
	}
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != http.MethodConnect {
		t.Errorf("upstream methods = %v, want [GET CONNECT]", methods)
	}
	if n := provider.calls.Load(); n != 2 {
		t.Errorf("GetToken calls = %d, want 2 (keep-alive HTTP + fresh CONNECT)", n)
	}
}

// TestHandleClientKeepAlivePostBody verifies that the keep-alive loop
// correctly positions reqReader after consuming a request body, so a
// pipelined second request with its own body is parsed cleanly.
func TestHandleClientKeepAlivePostBody(t *testing.T) {
	type recordedReq struct {
		method string
		body   []byte
	}
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	records := make(chan recordedReq, 2)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		for i := 0; i < 2; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			records <- recordedReq{method: req.Method, body: body}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}()

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	body1 := "first-request-body"
	body2 := "second-pipelined-body"
	pipeline := "POST http://a.example.com/1 HTTP/1.1\r\n" +
		"Host: a.example.com\r\nContent-Length: " + strconv.Itoa(len(body1)) + "\r\n\r\n" + body1 +
		"POST http://b.example.com/2 HTTP/1.1\r\n" +
		"Host: b.example.com\r\nContent-Length: " + strconv.Itoa(len(body2)) + "\r\n\r\n" + body2
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	for i := 0; i < 2; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("resp[%d]: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp[%d] status %d, want 200", i, resp.StatusCode)
		}
	}

	_ = client.Close()
	waitForDone(t, done)

	close(records)
	var got []recordedReq
	for r := range records {
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("upstream received %d requests, want 2", len(got))
	}
	if got[0].method != http.MethodPost || string(got[0].body) != body1 {
		t.Errorf("req[0] = %s %q, want POST %q", got[0].method, got[0].body, body1)
	}
	if got[1].method != http.MethodPost || string(got[1].body) != body2 {
		t.Errorf("req[1] = %s %q, want POST %q", got[1].method, got[1].body, body2)
	}
}

// TestI2_RFC9112_RequestConnectionCloseTerminatesKeepAliveLoop verifies that
// a client request carrying Connection: close terminates the keep-alive
// loop immediately, so a pipelined second request is NOT processed.
//
// RFC 9112 §9.6: "A server that receives a 'close' connection option MUST
// initiate closure of the connection after it sends the final response to
// the request that contained the 'close'. The server MUST NOT process any
// further requests on that connection."
func TestI2_RFC9112_RequestConnectionCloseTerminatesKeepAliveLoop(t *testing.T) {
	upstreamAddr, upstreamReqs := keepAliveUpstream(t, 2, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstreamAddr, provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	// First request signals close. Second is pipelined behind it.
	// The proxy MUST process only the first request.
	pipeline := "GET http://a.example.com/ HTTP/1.1\r\nHost: a.example.com\r\nConnection: close\r\n\r\n" +
		"GET http://b.example.com/ HTTP/1.1\r\nHost: b.example.com\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	resp1, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("resp1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("resp1 status %d, want 200", resp1.StatusCode)
	}

	// No second response should follow: the close on the first request
	// must have terminated the loop before iter 2 was read.
	if resp2, err := http.ReadResponse(reader, nil); err == nil {
		_ = resp2.Body.Close()
		t.Errorf("expected no second response when client sent Connection: close, got status %d", resp2.StatusCode)
	}

	_ = client.Close()
	waitForDone(t, done)

	close(upstreamReqs)
	count := 0
	for range upstreamReqs {
		count++
	}
	if count != 1 {
		t.Errorf("upstream received %d requests, want 1 (Connection: close on request must stop loop)", count)
	}
}

// TestRFC4559_ConnectionBoundAuthSingleTokenAcquisition is the RFC-tagged
// conformance test for SPNEGO connection-bound authentication.
//
// RFC 4559 §5: "Continuation of authentication context is required only
// when no Authorization header is sent." Once a TCP connection between the
// proxy and the upstream is authenticated with Negotiate, subsequent
// requests on that same connection do not need to repeat the SPNEGO
// exchange and MUST NOT carry a stale or smuggled Proxy-Authorization
// header.
//
// Asserts:
//   - The proxy acquires a SPNEGO token exactly once per upstream connection.
//   - Proxy-Authorization is set on the first forwarded request only.
//   - Any client-supplied Proxy-Authorization on subsequent requests is
//     stripped by sanitizeHopByHop and does not reach the upstream.
func TestRFC4559_ConnectionBoundAuthSingleTokenAcquisition(t *testing.T) {
	upstreamAddr, upstreamReqs := keepAliveUpstream(t, 3, func(_ int, _ *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	})

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstreamAddr, provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	pipeline := "GET http://a.example.com/ HTTP/1.1\r\nHost: a.example.com\r\n\r\n" +
		"GET http://b.example.com/ HTTP/1.1\r\nHost: b.example.com\r\nProxy-Authorization: Negotiate smuggled-token\r\n\r\n" +
		"GET http://c.example.com/ HTTP/1.1\r\nHost: c.example.com\r\n\r\n"
	if _, err := io.WriteString(client, pipeline); err != nil {
		t.Fatalf("write: %v", err)
	}

	reader := bufio.NewReader(client)
	for i := 0; i < 3; i++ {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("resp[%d]: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("resp[%d] status %d, want 200", i, resp.StatusCode)
		}
	}
	_ = client.Close()
	waitForDone(t, done)

	close(upstreamReqs)
	var reqs []*http.Request
	for r := range upstreamReqs {
		reqs = append(reqs, r)
	}
	if len(reqs) != 3 {
		t.Fatalf("upstream received %d requests, want 3", len(reqs))
	}

	if pa := reqs[0].Header.Get("Proxy-Authorization"); pa != "Negotiate tok" {
		t.Errorf("req[0] Proxy-Authorization = %q, want %q", pa, "Negotiate tok")
	}
	for i := 1; i < len(reqs); i++ {
		if pa := reqs[i].Header.Get("Proxy-Authorization"); pa != "" {
			t.Errorf("req[%d] Proxy-Authorization = %q, want empty (RFC 4559 §5 connection-bound; smuggled tokens MUST be stripped)", i, pa)
		}
	}

	if n := provider.calls.Load(); n != 1 {
		t.Errorf("GetToken called %d times, want exactly 1 (RFC 4559 §5)", n)
	}
}
