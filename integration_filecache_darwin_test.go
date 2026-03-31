//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Helpers ---

// setupIntegrationKDC skips the test if INTEGRATION is not set, creates an
// ephemeral KDC, registers cleanup, and configures the Kerberos environment.
func setupIntegrationKDC(t *testing.T) *EphemeralKDC {
	t.Helper()
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	kdc := NewEphemeralKDC(t)
	t.Cleanup(kdc.Close)
	kdc.SetEnv(t)
	return kdc
}

// newFileCacheTestProvider creates a FileCacheTokenProvider backed by the
// current Kerberos environment. The caller must have already configured the
// environment (e.g. via setupIntegrationKDC). It registers cleanup via t.Cleanup.
func newFileCacheTestProvider(t *testing.T) *FileCacheTokenProvider {
	t.Helper()
	provider, err := NewFileCacheTokenProvider("localhost", "")
	if err != nil {
		t.Fatalf("NewFileCacheTokenProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return provider
}

// mustKlist runs MIT krb5 klist against the given cache path and returns the
// output. It skips the test if klist is not available.
func mustKlist(t *testing.T, ccachePath string) string {
	t.Helper()
	prefix := findKrb5Prefix(t)
	klistBin := prefix + "/bin/klist"

	cmd := exec.Command(klistBin, "-c", "FILE:"+ccachePath) //nolint:gosec // test only
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("klist -c FILE:%s failed: %v\noutput: %s", ccachePath, err, out)
	}
	return string(out)
}

// validateSPNEGOToken performs the standard 3-level token validation used
// across integration tests: base64, ASN.1 0x60 tag, and SPNEGO OID.
func validateSPNEGOToken(t *testing.T, token string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	if len(decoded) == 0 || decoded[0] != 0x60 {
		t.Errorf("expected SPNEGO token (ASN.1 tag 0x60), got 0x%02x", decoded[0])
	}
	if !bytes.Contains(decoded, spnegoOID) {
		t.Error("SPNEGO token does not contain the SPNEGO OID")
	}
	return decoded
}

// --- Ephemeral KDC Integration Tests (INTEGRATION=1) ---

func TestFileCacheCopyProducesValidFileCache(t *testing.T) {
	setupIntegrationKDC(t)

	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// Verify the copied cache with klist.
	out := mustKlist(t, m.CachePath())
	t.Logf("klist output for copied cache:\n%s", out)

	if !strings.Contains(out, ephemeralKDCRealm) {
		t.Errorf("copied cache does not contain realm %s", ephemeralKDCRealm)
	}

	// Verify file permissions.
	info, err := os.Stat(m.CachePath())
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache file permissions = %04o, want group/other bits unset", perm)
	}
}

func TestFileCacheTokenAcquisitionWithNoPreflightFunction(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	decoded := validateSPNEGOToken(t, token)
	t.Logf("acquired valid SPNEGO token via file-cache path: %d bytes", len(decoded))
}

func TestFileCacheGSSTokenProviderEndToEnd(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	// Acquire token multiple times to verify reuse and refresh logic.
	for i := range 3 {
		token, err := provider.GetToken()
		if err != nil {
			t.Fatalf("GetToken call %d: %v", i+1, err)
		}
		decoded := validateSPNEGOToken(t, token)
		t.Logf("call %d: %d-byte SPNEGO token", i+1, len(decoded))
	}
}

func TestFileCacheReacquireAfterCacheDeletion(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	// First acquisition should succeed.
	if _, err := provider.GetToken(); err != nil {
		t.Fatalf("first GetToken: %v", err)
	}

	// Delete the file cache to simulate corruption/expiry.
	_ = os.Remove(provider.fileCache.CachePath())
	provider.fileCache.ForceRefresh()

	// Retry should re-copy and succeed.
	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken after cache deletion: %v", err)
	}
	validateSPNEGOToken(t, token)
}

func TestFileCacheExpiryTriggersRecopy(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	// First acquisition populates the cache.
	if _, err := provider.GetToken(); err != nil {
		t.Fatalf("first GetToken: %v", err)
	}

	// Manually expire the cache.
	provider.fileCache.expiry = time.Now().Add(-1 * time.Minute)
	provider.fileCache.lastCopy = time.Now().Add(-1 * time.Minute)

	// Next call should trigger re-copy.
	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken after expiry: %v", err)
	}
	validateSPNEGOToken(t, token)

	// Expiry should have been updated.
	if time.Until(provider.fileCache.expiry) < fileCacheRefreshMargin {
		t.Error("expiry was not updated after re-copy")
	}
}

func TestFileCacheIterCredsFindsCredential(t *testing.T) {
	setupIntegrationKDC(t)

	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// The lifetime should be positive and reasonable (KDC configures 1h max).
	if m.expiry.Before(time.Now()) {
		t.Error("expiry is in the past after EnsureCache")
	}
	lifetime := time.Until(m.expiry)
	t.Logf("credential lifetime: %v", lifetime)
	if lifetime > 25*time.Hour {
		t.Errorf("lifetime %v seems unreasonably long", lifetime)
	}
}

func TestFileCacheIterCredsWithNoCredentials(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}

	// Point to a nonexistent cache so there are no credentials to find.
	t.Setenv("KRB5CCNAME", "FILE:/nonexistent/krb5cc_test_"+t.Name())

	m := newTestFCM(t)

	err = m.EnsureCache()
	if err == nil {
		t.Fatal("expected error with no credentials, got nil")
	}

	var credErr *CredentialError
	if !errors.As(err, &credErr) {
		t.Errorf("expected CredentialError, got %T: %v", err, err)
	}
	t.Logf("got expected error: %v", err)
}

func TestFileCacheCcacheNameRedirectsTokenAcquisition(t *testing.T) {
	setupIntegrationKDC(t)

	// Copy credentials to a file cache.
	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// Now point KRB5CCNAME to a bogus path. If gss_krb5_ccache_name works,
	// the token acquisition should still succeed using the FILE: cache.
	t.Setenv("KRB5CCNAME", "FILE:/nonexistent/krb5cc_bogus")

	provider := newFileCacheTestProvider(t)

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken with bogus KRB5CCNAME but valid file cache: %v", err)
	}
	validateSPNEGOToken(t, token)
	t.Log("gss_krb5_ccache_name successfully overrides KRB5CCNAME env var")
}

func TestFileCacheErrorWhenNoCredentialsExist(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}

	// No KDC, no kinit, no credentials.
	t.Setenv("KRB5CCNAME", "FILE:/nonexistent/krb5cc_test_"+t.Name())

	provider, err := NewFileCacheTokenProvider("proxy.example.com:8080", "")
	if err != nil {
		t.Fatalf("NewFileCacheTokenProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	_, err = provider.GetToken()
	if err == nil {
		t.Fatal("expected error with no credentials, got nil")
	}

	var credErr *CredentialError
	if !errors.As(err, &credErr) {
		t.Errorf("expected CredentialError, got %T: %v", err, err)
	}
	t.Logf("got expected error: %v", err)
}

func TestFileCacheCorruptCacheFileRecovery(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	// First acquisition should succeed.
	if _, err := provider.GetToken(); err != nil {
		t.Fatalf("first GetToken: %v", err)
	}

	// Corrupt the cache file.
	if err := os.WriteFile(provider.fileCache.CachePath(), []byte("CORRUPT"), 0o600); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}
	provider.fileCache.ForceRefresh()

	// Next call should re-copy and succeed.
	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken after corruption: %v", err)
	}
	validateSPNEGOToken(t, token)
}

func TestFileCacheConcurrentGetToken(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

	const goroutines = 20
	var wg sync.WaitGroup
	errc := make(chan error, goroutines)

	for range goroutines {
		wg.Go(func() {
			token, err := provider.GetToken()
			if err != nil {
				errc <- err
				return
			}
			decoded, decErr := base64.StdEncoding.DecodeString(token)
			if decErr != nil {
				errc <- decErr
				return
			}
			if len(decoded) == 0 || decoded[0] != 0x60 {
				errc <- errors.New("invalid SPNEGO token structure")
			}
		})
	}

	wg.Wait()
	close(errc)

	for err := range errc {
		t.Errorf("concurrent GetToken error: %v", err)
	}
}

func TestFileCacheProxyChainWithEphemeralKDC(t *testing.T) {
	setupIntegrationKDC(t)
	provider := newFileCacheTestProvider(t)

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
		handleClient(conn, ProxyConfig{
			Upstream:    upstream.Addr().String(),
			Provider:    provider,
			Pseudonym:   testPseudonym,
			DialTimeout: 5 * time.Second,
			ReadTimeout: 5 * time.Second,
		})
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

	_ = clientConn.Close()

	// Validate the Proxy-Authorization header.
	select {
	case auth := <-gotAuth:
		if !strings.HasPrefix(auth, "Negotiate ") {
			t.Fatalf("expected Proxy-Authorization 'Negotiate ...', got %q", auth)
		}
		tokenPart := strings.TrimPrefix(auth, "Negotiate ")
		decoded := validateSPNEGOToken(t, tokenPart)
		t.Logf("upstream received valid SPNEGO token via file-cache path: %d bytes", len(decoded))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}

	// Validate Via header.
	wantVia := "HTTP/1.1 " + testPseudonym
	select {
	case via := <-gotVia:
		if via != wantVia {
			t.Errorf("Via = %q, want %q", via, wantVia)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Via header")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}
