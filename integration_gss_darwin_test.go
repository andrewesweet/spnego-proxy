//go:build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestGSSTokenProviderWithEphemeralKDC verifies that the macOS GSS-API code
// path can acquire a valid SPNEGO token from an ephemeral MIT KDC. This is
// the primary integration test for the darwin-only GSSTokenProvider.
func TestGSSTokenProviderWithEphemeralKDC(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run GSS-API integration tests")
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	kdc.SetEnv(t)

	provider, err := NewGSSTokenProvider("localhost", "")
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.SPN() != "HTTP@localhost" {
		t.Errorf("expected SPN HTTP@localhost, got %s", provider.SPN())
	}

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}

	// Validate the SPNEGO token structure.
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

	t.Logf("acquired valid SPNEGO token: %d bytes base64, %d bytes decoded", len(token), len(decoded))
}

// TestGSSTokenProviderExplicitSPNWithKDC verifies token acquisition when the
// SPN is passed explicitly in Kerberos principal format (HTTP/host), which
// NewGSSTokenProvider normalizes to GSS-API hostbased format (HTTP@host).
func TestGSSTokenProviderExplicitSPNWithKDC(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run GSS-API integration tests")
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	kdc.SetEnv(t)

	provider, err := NewGSSTokenProvider("localhost", "HTTP/localhost")
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	defer func() { _ = provider.Close() }()

	if provider.SPN() != "HTTP@localhost" {
		t.Errorf("expected normalized SPN HTTP@localhost, got %s", provider.SPN())
	}

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken with explicit SPN: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	if len(decoded) == 0 || decoded[0] != 0x60 {
		t.Errorf("expected SPNEGO token (ASN.1 tag 0x60), got 0x%02x", decoded[0])
	}
}

// TestGSSTokenProviderMissingCache verifies that GetToken returns a clear
// error when the credential cache has been removed (simulating expired or
// missing Kerberos credentials).
func TestGSSTokenProviderMissingCache(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run GSS-API integration tests")
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	kdc.SetEnv(t)

	// Remove the credential cache to simulate expired/missing credentials.
	if err := os.Remove(kdc.CCachePath); err != nil {
		t.Fatalf("remove ccache: %v", err)
	}

	provider, err := NewGSSTokenProvider("localhost", "")
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
