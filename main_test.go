package main

import (
	"net"
	"testing"
	"time"
)

func TestHandleClientDialTimeout(t *testing.T) {
	// Use an unreachable address (RFC 5737 TEST-NET) to trigger a dial timeout.
	unreachable := "192.0.2.1:1"

	client, server := net.Pipe()
	defer client.Close()

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
	defer upstream.Close()
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	// Create a client connection that connects but never sends data.
	client, server := net.Pipe()
	defer client.Close()

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
