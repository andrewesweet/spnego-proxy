package main

import (
	"net"
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
