package main

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// minimalKrb5Conf is a minimal krb5.conf sufficient to construct a client
// without hitting the network.
const minimalKrb5Conf = `[libdefaults]
  default_realm = TEST.REALM
[realms]
  TEST.REALM = {
    kdc = 127.0.0.1
  }
`

// newTestGokrb5TokenProvider creates a Gokrb5TokenProvider backed by a real
// (but unconfigured) gokrb5 client, suitable for testing lifecycle methods.
func newTestGokrb5TokenProvider(t *testing.T) *Gokrb5TokenProvider {
	t.Helper()
	cfg, err := config.NewFromString(minimalKrb5Conf)
	if err != nil {
		t.Fatalf("failed to parse krb5 config: %v", err)
	}
	cli := client.NewWithPassword("user", "TEST.REALM", "pass", cfg)
	return &Gokrb5TokenProvider{
		krbClient:    cli,
		spnegoClient: spnego.SPNEGOClient(cli, "HTTP/proxy.test"),
	}
}

func TestGokrb5TokenProviderCloseDestroysClient(t *testing.T) {
	p := newTestGokrb5TokenProvider(t)
	if p.krbClient == nil {
		t.Fatal("expected non-nil krbClient before Close")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if p.krbClient != nil {
		t.Error("expected krbClient to be nil after Close")
	}
}

func TestGokrb5TokenProviderCloseIsIdempotent(t *testing.T) {
	p := newTestGokrb5TokenProvider(t)

	// First close should succeed.
	if err := p.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}

	// Second close must not panic or return an error.
	if err := p.Close(); err != nil {
		t.Fatalf("second Close() returned error: %v", err)
	}
}
