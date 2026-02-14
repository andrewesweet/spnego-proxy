//go:build darwin

package main

import (
	"testing"
)

func TestGSSTokenProviderInit(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "")
	if err != nil {
		t.Fatalf("Failed to create GSSTokenProvider: %v", err)
	}
	defer provider.Close()

	if provider.spn != "HTTP@proxy.example.com" {
		t.Errorf("Expected SPN HTTP@proxy.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenProviderExplicitSPN(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "HTTP@custom.example.com")
	if err != nil {
		t.Fatalf("Failed to create GSSTokenProvider: %v", err)
	}
	defer provider.Close()

	if provider.spn != "HTTP@custom.example.com" {
		t.Errorf("Expected SPN HTTP@custom.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenProviderNoPort(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com", "")
	if err != nil {
		t.Fatalf("Failed to create GSSTokenProvider: %v", err)
	}
	defer provider.Close()

	if provider.spn != "HTTP@proxy.example.com" {
		t.Errorf("Expected SPN HTTP@proxy.example.com, got %s", provider.spn)
	}
}

func TestGSSTokenAcquisitionWithoutTickets(t *testing.T) {
	// This test verifies the GSS-API call path works even when no tickets
	// are available. It should return an error (no credentials) rather than crash.
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "")
	if err != nil {
		t.Fatalf("Failed to create GSSTokenProvider: %v", err)
	}
	defer provider.Close()

	_, err = provider.GetToken("proxy.example.com:8080")
	if err == nil {
		t.Log("GetToken succeeded — Kerberos tickets must be available in this environment")
	} else {
		t.Logf("GetToken returned expected error (no tickets): %v", err)
	}
}
