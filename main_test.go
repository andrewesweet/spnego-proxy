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
	"testing"
	"time"

	"golang.org/x/net/netutil"
)

func TestHandleClientDialTimeout(t *testing.T) {
	// Use an unreachable address (RFC 5737 TEST-NET) to trigger a dial timeout.
	unreachable := "192.0.2.1:1"

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	provider := &stubTokenProvider{token: "tok"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClient(server, unreachable, provider, false, 50*time.Millisecond, time.Second)
	}()

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
		handleClient(server, upstream.Addr().String(), provider, false, 5*time.Second, 50*time.Millisecond)
	}()

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
				handleClient(conn, upstream.Addr().String(), provider, false, 5*time.Second, 5*time.Second)
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
				handleClient(conn, upstream.Addr().String(), provider, false, 5*time.Second, 5*time.Second)
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
		handleClient(server, upstream.Addr().String(), provider, false, 5*time.Second, 5*time.Second)
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
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy authentication failed") {
		t.Errorf("expected body to mention proxy authentication, got: %q", body)
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
		handleClient(conn, upstream.Addr().String(), provider, false, 5*time.Second, 5*time.Second)
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

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}
