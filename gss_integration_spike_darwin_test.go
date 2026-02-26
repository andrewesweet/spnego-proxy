//go:build darwin

package main

import (
	"encoding/base64"
	"os"
	"testing"
)

// TestEphemeralKDCSpike is a proof-of-concept spike that validates whether
// Apple's Heimdal GSS-API can acquire a SPNEGO token from an ephemeral MIT
// KDC started on the local machine using the EphemeralKDC helper.
//
// Prerequisites: MIT Kerberos via Homebrew (brew install krb5).
// Run with: INTEGRATION=1 go test -v -count=1 -run TestEphemeralKDCSpike ./...
func TestEphemeralKDCSpike(t *testing.T) {
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

	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken failed: %v\n\nDiagnostics:\n"+
			"  KRB5_CONFIG=%s\n"+
			"  KRB5CCNAME=FILE:%s\n"+
			"  Hint: check if Apple Heimdal respects KRB5_CONFIG overrides",
			err, kdc.KRB5Conf, kdc.CCachePath)
	}

	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid base64: %v", err)
	}
	if len(decoded) == 0 || decoded[0] != 0x60 {
		t.Fatalf("expected SPNEGO token (ASN.1 Application tag 0x60), got 0x%02x", decoded[0])
	}

	t.Logf("SPIKE SUCCESS: acquired valid SPNEGO token (%d bytes base64, %d bytes decoded, ASN.1 tag 0x%02x)",
		len(token), len(decoded), decoded[0])
}
