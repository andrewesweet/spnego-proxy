//go:build darwin

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestGSSTokenProviderWithEphemeralKDC verifies that the macOS GSS-API code
// path can acquire a valid SPNEGO token from an ephemeral MIT KDC. This is
// the primary integration test for the darwin-only GSSTokenProvider.
func TestGSSTokenProviderWithEphemeralKDC(t *testing.T) {
	kdc := setupIntegrationKDC(t)

	provider, err := NewGSSTokenProvider("localhost", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.spn != "HTTP@localhost" {
		t.Errorf("expected SPN HTTP@localhost, got %s", provider.spn)
	}

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	decoded := validateSPNEGOToken(t, token)
	t.Logf("acquired valid SPNEGO token: %d bytes base64, %d bytes decoded", len(token), len(decoded))

	// Use kdc to verify the CCachePath is set.
	if kdc.CCachePath == "" {
		t.Error("expected non-empty CCachePath from ephemeral KDC")
	}
}

// TestGSSTokenProviderExplicitSPNWithKDC verifies token acquisition when the
// SPN is passed explicitly in Kerberos principal format (HTTP/host), which
// NewGSSTokenProvider normalizes to GSS-API hostbased format (HTTP@host).
func TestGSSTokenProviderExplicitSPNWithKDC(t *testing.T) {
	setupIntegrationKDC(t)

	provider, err := NewGSSTokenProvider("localhost", "HTTP/localhost", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.spn != "HTTP@localhost" {
		t.Errorf("expected normalized SPN HTTP@localhost, got %s", provider.spn)
	}

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken with explicit SPN: %v", err)
	}

	validateSPNEGOToken(t, token)
}

// TestGSSTokenProviderHostWithPort verifies that SPN derivation correctly
// strips the port from proxyHost when acquiring a real token. This exercises
// the extractHost -> "HTTP@localhost" derivation path with a port suffix.
func TestGSSTokenProviderHostWithPort(t *testing.T) {
	setupIntegrationKDC(t)

	provider, err := NewGSSTokenProvider("localhost:8080", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.spn != "HTTP@localhost" {
		t.Errorf("expected SPN HTTP@localhost, got %s", provider.spn)
	}

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	validateSPNEGOToken(t, token)
}

// TestGSSTokenProviderReacquire verifies that GetToken can be called
// multiple times, producing a valid SPNEGO token each time. This catches
// stale GSS context state or credential cache file-locking issues.
func TestGSSTokenProviderReacquire(t *testing.T) {
	setupIntegrationKDC(t)

	provider, err := NewGSSTokenProvider("localhost", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	for i := range 3 {
		token, err := provider.GetToken()
		if err != nil {
			t.Fatalf("GetToken call %d: %v", i+1, err)
		}

		decoded := validateSPNEGOToken(t, token)
		t.Logf("call %d: acquired %d-byte SPNEGO token", i+1, len(decoded))
	}
}

// TestGSSTokenProviderMissingCache verifies that GetToken returns a clear
// error when the credential cache has been removed (simulating expired or
// missing Kerberos credentials).
func TestGSSTokenProviderMissingCache(t *testing.T) {
	kdc := setupIntegrationKDC(t)

	// Remove the credential cache to simulate expired/missing credentials.
	if err := os.Remove(kdc.CCachePath); err != nil {
		t.Fatalf("remove ccache: %v", err)
	}

	provider, err := NewGSSTokenProvider("localhost", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	_, err = provider.GetToken()
	if err == nil {
		t.Fatal("expected error from GetToken with removed credential cache, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "credential") && !strings.Contains(errMsg, "GSS-API") {
		t.Errorf("expected error mentioning credentials or GSS-API, got: %v", err)
	}
	t.Logf("got expected error with missing cache: %v", err)
}

// TestGSSTokenProviderUnregisteredSPN verifies that GetToken returns an
// error when the target service principal is not registered in the KDC.
func TestGSSTokenProviderUnregisteredSPN(t *testing.T) {
	setupIntegrationKDC(t)

	// Use an SPN that was never registered as a principal in the KDC.
	provider, err := NewGSSTokenProvider("unknown.host.example", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	_, err = provider.GetToken()
	if err == nil {
		t.Fatal("expected error from GetToken with unregistered SPN, got nil")
	}
	t.Logf("got expected error with unregistered SPN: %v", err)
}

// TestGSSProxyChainWithEphemeralKDC verifies the full proxy chain: ephemeral
// KDC -> GSSTokenProvider -> handleClient -> upstream receives a valid SPNEGO
// token in the Proxy-Authorization header. This is the E2E integration test
// analogous to TestProxyChainWithRealToken in gokrb5_integration_test.go.
func TestGSSProxyChainWithEphemeralKDC(t *testing.T) {
	setupIntegrationKDC(t)

	provider, err := NewGSSTokenProvider("localhost", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	// Start a fake upstream proxy that captures the Proxy-Authorization and Via headers.
	gotAuth := make(chan string, 1)
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
			gotAuth <- "READ_ERR: " + err.Error()
			gotVia <- "READ_ERR: " + err.Error()
			return
		}
		_ = req.Body.Close()
		gotAuth <- req.Header.Get("Proxy-Authorization")
		gotVia <- req.Header.Get("Via")

		resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
		_, _ = conn.Write([]byte(resp))
	}()

	// Set up the local proxy listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleClient(conn, ProxyConfig{Upstream: upstream.Addr().String(), Provider: provider, Pseudonym: testPseudonym, DialTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second})
	}()

	// Connect and send a request through the proxy.
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(clientConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "OK" {
		t.Errorf("expected body 'OK', got %q", body)
	}

	// Close client to unblock the forwarding goroutines in handleClient.
	_ = clientConn.Close()

	// Validate the Proxy-Authorization header received by upstream.
	select {
	case auth := <-gotAuth:
		if !strings.HasPrefix(auth, "Negotiate ") {
			t.Fatalf("expected Proxy-Authorization starting with 'Negotiate ', got %q", auth)
		}
		tokenPart := strings.TrimPrefix(auth, "Negotiate ")
		decoded := validateSPNEGOToken(t, tokenPart)
		t.Logf("upstream received valid SPNEGO Proxy-Authorization: %d bytes", len(decoded))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive request")
	}

	// Validate the Via header was added to the forwarded request.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case via := <-gotVia:
		if via != wantVia {
			t.Errorf("Via header = %q, want %q", via, wantVia)
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
