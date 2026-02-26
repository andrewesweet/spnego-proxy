package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/krb5test"
)

func skipIfNoIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("skipping integration test; set INTEGRATION=1 to run")
	}
}

// writeMockKDCKrb5Conf writes a minimal krb5.conf pointing to the mock KDC's
// ephemeral address, forcing TCP and restricting enctypes to aes256.
func writeMockKDCKrb5Conf(t *testing.T, kdcAddr, realm string) string {
	t.Helper()
	content := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96
  udp_preference_limit = 1

[realms]
  %s = {
    kdc = %s
  }

[domain_realm]
  .test.realm.com = %s
  test.realm.com = %s
`, realm, realm, kdcAddr, realm, realm)
	f := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatalf("write krb5.conf: %v", err)
	}
	return f
}

// startMockKDC creates and starts a mock KDC, then returns a Gokrb5TokenProvider
// configured to authenticate as user against servicePrincipal. Call the returned
// cleanup function to shut down the KDC and close the provider.
func startMockKDC(t *testing.T, user, servicePrincipal string) (*Gokrb5TokenProvider, func()) {
	t.Helper()

	l := log.New(os.Stderr, "KDC: ", log.LstdFlags)
	principals := map[string][]string{
		user:             {"testgroup"},
		servicePrincipal: {},
	}

	kdc, err := krb5test.NewKDC(principals, l)
	if err != nil {
		t.Fatalf("create mock KDC: %v", err)
	}
	kdc.Start()

	cfgFile := writeMockKDCKrb5Conf(t, kdc.TCPListener.Addr().String(), kdc.Realm)
	pwFile := writePasswordFile(t, kdc.Principals[user].Password, 0o600)

	provider, err := NewGokrb5TokenProvider(
		user, kdc.Realm, cfgFile, pwFile,
		"proxy.test.realm.com:3128",
		servicePrincipal,
		false,
	)
	if err != nil {
		kdc.Close()
		t.Fatalf("create token provider: %v", err)
	}

	return provider, func() {
		_ = provider.Close()
		kdc.Close()
	}
}

// spnegoOID is the DER-encoded SPNEGO mechanism OID (1.3.6.1.5.5.2).
var spnegoOID = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}

// ---------------------------------------------------------------------------
// Test A: Gokrb5TokenProvider.GetToken() returns a valid SPNEGO token
// ---------------------------------------------------------------------------

// TestGokrb5TokenProviderGetToken verifies that GetToken returns a valid
// base64-encoded SPNEGO token when backed by a real mock KDC.
func TestGokrb5TokenProviderGetToken(t *testing.T) {
	skipIfNoIntegration(t)

	provider, cleanup := startMockKDC(t, "testuser", "HTTP/proxy.test.realm.com")
	defer cleanup()

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken() failed: %v", err)
	}
	if token == "" {
		t.Fatal("GetToken() returned empty token")
	}

	// Verify valid base64.
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}

	// Verify SPNEGO structure: starts with ASN.1 Application[0] tag (0x60).
	if len(decoded) == 0 || decoded[0] != 0x60 {
		t.Errorf("expected SPNEGO token to start with 0x60 (Application[0]), got 0x%02x", decoded[0])
	}

	// Verify token contains the SPNEGO OID.
	if !bytes.Contains(decoded, spnegoOID) {
		t.Error("SPNEGO token does not contain the SPNEGO OID (1.3.6.1.5.5.2)")
	}
}

// ---------------------------------------------------------------------------
// Test B: Full proxy chain with real SPNEGO token
// ---------------------------------------------------------------------------

// TestProxyChainWithRealToken verifies the full proxy chain: mock KDC →
// Gokrb5TokenProvider → handleClient → upstream receives a valid SPNEGO token.
func TestProxyChainWithRealToken(t *testing.T) {
	skipIfNoIntegration(t)

	provider, cleanup := startMockKDC(t, "testuser", "HTTP/proxy.test.realm.com")
	defer cleanup()

	// Start a fake upstream proxy that captures the Proxy-Authorization header.
	gotAuth := make(chan string, 1)
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
			return
		}
		_ = req.Body.Close()
		gotAuth <- req.Header.Get("Proxy-Authorization")

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
		handleClient(conn, upstream.Addr().String(), provider, false, 5*time.Second, 5*time.Second, 0)
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
		decoded, err := base64.StdEncoding.DecodeString(tokenPart)
		if err != nil {
			t.Fatalf("token in header is not valid base64: %v", err)
		}
		if len(decoded) == 0 || decoded[0] != 0x60 {
			t.Errorf("expected SPNEGO token to start with 0x60, got 0x%02x", decoded[0])
		}
		if !bytes.Contains(decoded, spnegoOID) {
			t.Error("SPNEGO token in header does not contain the SPNEGO OID")
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

// ---------------------------------------------------------------------------
// Test C: Token acquisition failure modes
// ---------------------------------------------------------------------------

// TestGokrb5TokenProviderWrongPassword verifies that GetToken returns a
// meaningful error when the provider is configured with an incorrect password.
func TestGokrb5TokenProviderWrongPassword(t *testing.T) {
	skipIfNoIntegration(t)

	l := log.New(os.Stderr, "KDC: ", log.LstdFlags)
	principals := map[string][]string{
		"testuser":                  {"testgroup"},
		"HTTP/proxy.test.realm.com": {},
	}

	kdc, err := krb5test.NewKDC(principals, l)
	if err != nil {
		t.Fatalf("create mock KDC: %v", err)
	}
	kdc.Start()
	defer kdc.Close()

	cfgFile := writeMockKDCKrb5Conf(t, kdc.TCPListener.Addr().String(), kdc.Realm)
	pwFile := writePasswordFile(t, "wrongpassword", 0o600)

	provider, err := NewGokrb5TokenProvider(
		"testuser", kdc.Realm, cfgFile, pwFile,
		"proxy.test.realm.com:3128",
		"HTTP/proxy.test.realm.com",
		false,
	)
	if err != nil {
		t.Fatalf("create token provider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	_, err = provider.GetToken()
	if err == nil {
		t.Fatal("expected error from GetToken with wrong password")
	}
	t.Logf("got expected error: %v", err)
}

// TestGokrb5TokenProviderWrongRealm verifies that GetToken returns a
// meaningful error when the provider is configured with a mismatched realm.
func TestGokrb5TokenProviderWrongRealm(t *testing.T) {
	skipIfNoIntegration(t)

	l := log.New(os.Stderr, "KDC: ", log.LstdFlags)
	principals := map[string][]string{
		"testuser":                  {"testgroup"},
		"HTTP/proxy.test.realm.com": {},
	}

	kdc, err := krb5test.NewKDC(principals, l)
	if err != nil {
		t.Fatalf("create mock KDC: %v", err)
	}
	kdc.Start()
	defer kdc.Close()

	wrongRealm := "WRONG.REALM.COM"
	cfgFile := writeMockKDCKrb5Conf(t, kdc.TCPListener.Addr().String(), wrongRealm)
	pwFile := writePasswordFile(t, kdc.Principals["testuser"].Password, 0o600)

	provider, err := NewGokrb5TokenProvider(
		"testuser", wrongRealm, cfgFile, pwFile,
		"proxy.test.realm.com:3128",
		"HTTP/proxy.test.realm.com",
		false,
	)
	if err != nil {
		t.Fatalf("create token provider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	_, err = provider.GetToken()
	if err == nil {
		t.Fatal("expected error from GetToken with wrong realm")
	}
	t.Logf("got expected error: %v", err)
}

// ---------------------------------------------------------------------------
// Test D: Circuit breaker integration with real provider
// ---------------------------------------------------------------------------

// TestCircuitBreakerWithRealProvider verifies the circuit breaker works with
// a real Gokrb5TokenProvider: successful calls pass through, and when the KDC
// becomes unavailable, the circuit opens after consecutive failures.
func TestCircuitBreakerWithRealProvider(t *testing.T) {
	skipIfNoIntegration(t)

	// Phase 1: Verify successful token acquisition passes through.
	provider, cleanup := startMockKDC(t, "testuser", "HTTP/proxy.test.realm.com")

	cb := NewCircuitBreakerTokenProvider(provider)
	token, err := cb.GetToken()
	if err != nil {
		cleanup()
		t.Fatalf("GetToken through circuit breaker failed: %v", err)
	}
	if token == "" {
		cleanup()
		t.Fatal("expected non-empty token through circuit breaker")
	}
	cleanup()

	// Phase 2: Create a fresh provider pointing to a closed KDC address.
	// Using a fresh provider avoids cached tickets from the first phase.
	// Grab a port and close it immediately so the provider gets ECONNREFUSED.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	cfgFile := writeMockKDCKrb5Conf(t, closedAddr, "TEST.REALM.COM")
	pwFile := writePasswordFile(t, "somepassword", 0o600)

	failProvider, err := NewGokrb5TokenProvider(
		"testuser", "TEST.REALM.COM", cfgFile, pwFile,
		"proxy.test.realm.com:3128",
		"HTTP/proxy.test.realm.com",
		false,
	)
	if err != nil {
		t.Fatalf("create failing provider: %v", err)
	}
	defer func() { _ = failProvider.Close() }()

	cb2 := NewCircuitBreakerTokenProvider(failProvider)

	// Drive consecutive failures to trip the circuit breaker.
	for i := 0; i < int(cbConsecutiveFailures); i++ {
		_, err := cb2.GetToken()
		if err == nil {
			t.Fatalf("expected error on call %d with closed KDC, got success", i+1)
		}
	}

	// The circuit should now be open — the next call should be rejected
	// without reaching the inner provider.
	_, err = cb2.GetToken()
	if err == nil {
		t.Fatal("expected circuit breaker to reject after consecutive failures")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected 'circuit breaker open' error, got: %v", err)
	}
}
