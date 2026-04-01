//go:build darwin

package main

import (
	"testing"
)

// newTestGSSProvider creates a GSSTokenProvider and registers cleanup.
func newTestGSSProvider(t *testing.T, host, spn string) *GSSTokenProvider {
	t.Helper()
	provider, err := NewGSSTokenProvider(host, spn)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	return provider
}

func TestGSSTokenProviderInit(t *testing.T) {
	provider := newTestGSSProvider(t, "proxy.example.com:8080", "")

	if provider.spn != "HTTP@proxy.example.com" {
		t.Errorf("Expected SPN HTTP@proxy.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenProviderExplicitSPN(t *testing.T) {
	provider := newTestGSSProvider(t, "proxy.example.com:8080", "HTTP@custom.example.com")

	if provider.spn != "HTTP@custom.example.com" {
		t.Errorf("Expected SPN HTTP@custom.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenProviderNoPort(t *testing.T) {
	provider := newTestGSSProvider(t, "proxy.example.com", "")

	if provider.spn != "HTTP@proxy.example.com" {
		t.Errorf("Expected SPN HTTP@proxy.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenProviderNormalizesKrb5SPN(t *testing.T) {
	// A user passing the Kerberos principal format should have it automatically
	// converted to the GSS-API hostbased service name format (HTTP@host).
	provider := newTestGSSProvider(t, "proxy.example.com:8080", "HTTP/custom.example.com")

	if provider.spn != "HTTP@custom.example.com" {
		t.Errorf("Expected SPN HTTP@custom.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenAcquisitionWithoutTickets(t *testing.T) {
	// This test verifies the GSS-API call path works even when no tickets
	// are available. It should return an error (no credentials) rather than crash.
	provider := newTestGSSProvider(t, "proxy.example.com:8080", "")

	_, err := provider.GetToken()
	if err == nil {
		t.Log("GetToken succeeded — Kerberos tickets must be available in this environment")
	} else {
		t.Logf("GetToken returned expected error (no tickets): %v", err)
	}
}
