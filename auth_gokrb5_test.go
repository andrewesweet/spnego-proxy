package main

import (
	"os"
	"path/filepath"
	"strings"
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

// writePasswordFile creates a temporary file with the given content and
// permissions, returning its path. It uses os.Chmod after writing to set
// the exact permissions regardless of the process umask. The file is
// automatically removed when the test finishes.
func writePasswordFile(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write password file: %v", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("failed to chmod password file: %v", err)
	}
	return path
}

// writeTempKrb5Conf writes minimalKrb5Conf to a temporary file and returns
// its path, cleaned up automatically when the test finishes.
func writeTempKrb5Conf(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(path, []byte(minimalKrb5Conf), 0o600); err != nil {
		t.Fatalf("failed to write krb5.conf: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// getPassword tests
// ---------------------------------------------------------------------------

func TestGetPasswordReadsFile(t *testing.T) {
	path := writePasswordFile(t, "s3cret", 0o600)

	pw, err := getPassword(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(pw) != "s3cret" {
		t.Errorf("got %q, want %q", pw, "s3cret")
	}
}

func TestGetPasswordTrimsTrailingCRLF(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"trailing LF", "password\n", "password"},
		{"trailing CRLF", "password\r\n", "password"},
		{"trailing CR", "password\r", "password"},
		{"multiple trailing newlines", "password\n\n\n", "password"},
		{"no trailing newline", "password", "password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePasswordFile(t, tt.content, 0o600)
			pw, err := getPassword(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(pw) != tt.want {
				t.Errorf("got %q, want %q", pw, tt.want)
			}
		})
	}
}

func TestGetPasswordRejectsInsecurePermissions(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission checks are not enforced for root")
	}
	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"group readable (0640)", 0o640},
		{"world readable (0644)", 0o644},
		{"group writable (0620)", 0o620},
		{"world writable (0602)", 0o602},
		{"group executable (0610)", 0o610},
		{"all permissions (0777)", 0o777},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePasswordFile(t, "secret", tt.perm)
			_, err := getPassword(path)
			if err == nil {
				t.Fatal("expected error for insecure permissions")
			}
			if !strings.Contains(err.Error(), "insecure permissions") {
				t.Errorf("error should mention insecure permissions, got: %v", err)
			}
		})
	}
}

func TestGetPasswordAcceptsSecurePermissions(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
	}{
		{"owner only (0600)", 0o600},
		{"owner read-only (0400)", 0o400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePasswordFile(t, "secret", tt.perm)
			pw, err := getPassword(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(pw) != "secret" {
				t.Errorf("got %q, want %q", pw, "secret")
			}
		})
	}
}

func TestGetPasswordEnforcesSizeLimit(t *testing.T) {
	// The implementation uses io.LimitReader(f, 4096) and reads the result.
	// A file exactly at the limit should be read successfully; a file
	// exceeding the limit should be truncated to 4096 bytes.
	const maxSize = 4096
	large := strings.Repeat("A", maxSize+100)

	path := writePasswordFile(t, large, 0o600)
	pw, err := getPassword(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pw) != maxSize {
		t.Errorf("expected password to be truncated to %d bytes, got %d", maxSize, len(pw))
	}
}

func TestGetPasswordReturnsErrorForMissingFile(t *testing.T) {
	_, err := getPassword("/nonexistent/path/password")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "failed to open password file") {
		t.Errorf("error should mention opening, got: %v", err)
	}
}

func TestGetPasswordReturnsErrorForNonTerminalStdin(t *testing.T) {
	// With an empty passwordFile argument, getPassword falls back to reading
	// from the terminal. In CI (and tests), stdin is not a terminal.
	_, err := getPassword("")
	if err == nil {
		t.Fatal("expected error when stdin is not a terminal")
	}
	if !strings.Contains(err.Error(), "stdin is not a terminal") {
		t.Errorf("error should mention non-terminal stdin, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewGokrb5TokenProvider tests
// ---------------------------------------------------------------------------

func TestNewGokrb5TokenProviderRequiresConfigAndRealm(t *testing.T) {
	tests := []struct {
		name   string
		realm  string
		config string
	}{
		{"missing both", "", ""},
		{"missing config", "TEST.REALM", ""},
		{"missing realm", "", "/some/path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGokrb5TokenProvider("user", tt.realm, tt.config, "", "proxy:3128", "", false)
			if err == nil {
				t.Fatal("expected error for missing config/realm")
			}
			if !strings.Contains(err.Error(), "-config and -realm are required") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}

func TestNewGokrb5TokenProviderReturnsErrorForMissingConfig(t *testing.T) {
	pwFile := writePasswordFile(t, "pass", 0o600)

	_, err := NewGokrb5TokenProvider("user", "TEST.REALM", "/nonexistent/krb5.conf", pwFile, "proxy:3128", "", false)
	if err == nil {
		t.Fatal("expected error for missing kerberos config")
	}
	if !strings.Contains(err.Error(), "failed to load kerberos config") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewGokrb5TokenProviderReturnsErrorForBadPasswordFile(t *testing.T) {
	cfgFile := writeTempKrb5Conf(t)

	_, err := NewGokrb5TokenProvider("user", "TEST.REALM", cfgFile, "/nonexistent/password", "proxy:3128", "", false)
	if err == nil {
		t.Fatal("expected error for missing password file")
	}
	if !strings.Contains(err.Error(), "failed to get password") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNewGokrb5TokenProviderInfersSPN(t *testing.T) {
	tests := []struct {
		name     string
		proxy    string
		wantHost string
	}{
		{"host:port", "proxy.example.com:3128", "proxy.example.com"},
		{"host only", "proxy.example.com", "proxy.example.com"},
		{"IP:port", "10.0.0.1:8080", "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgFile := writeTempKrb5Conf(t)
			pwFile := writePasswordFile(t, "pass", 0o600)

			p, err := NewGokrb5TokenProvider("user", "TEST.REALM", cfgFile, pwFile, tt.proxy, "", false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer func() { _ = p.Close() }()

			// The provider should have been created successfully with the
			// inferred SPN. We can't directly inspect the SPN, but
			// successful construction proves extractHost + SPN inference
			// worked without error.
			if p.spnegoClient == nil {
				t.Fatal("expected non-nil spnegoClient")
			}
		})
	}
}

func TestNewGokrb5TokenProviderNormalizesExplicitSPN(t *testing.T) {
	cfgFile := writeTempKrb5Conf(t)
	pwFile := writePasswordFile(t, "pass", 0o600)

	// Providing an SPN with '@' separator should still succeed — the
	// constructor normalizes it to '/' for gokrb5.
	p, err := NewGokrb5TokenProvider("user", "TEST.REALM", cfgFile, pwFile, "proxy:3128", "HTTP@proxy.example.com", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Close() }()

	if p.spnegoClient == nil {
		t.Fatal("expected non-nil spnegoClient")
	}
}

func TestNewGokrb5TokenProviderSucceeds(t *testing.T) {
	cfgFile := writeTempKrb5Conf(t)
	pwFile := writePasswordFile(t, "pass", 0o600)

	p, err := NewGokrb5TokenProvider("user", "TEST.REALM", cfgFile, pwFile, "proxy:3128", "HTTP/proxy.example.com", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = p.Close() }()

	if p.krbClient == nil {
		t.Fatal("expected non-nil krbClient")
	}
	if p.spnegoClient == nil {
		t.Fatal("expected non-nil spnegoClient")
	}
}

// ---------------------------------------------------------------------------
// GetToken error paths
// ---------------------------------------------------------------------------

func TestGetTokenReturnsErrorWithInvalidCredentials(t *testing.T) {
	// A provider constructed with a local-only config and no real KDC
	// will fail when trying to acquire credentials.
	p := newTestGokrb5TokenProvider(t)
	defer func() { _ = p.Close() }()

	_, err := p.GetToken()
	if err == nil {
		t.Fatal("expected error from GetToken with invalid credentials")
	}
	// The error should come from credential acquisition or context init.
	if !strings.Contains(err.Error(), "could not") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetPasswordBytesCanBeZeroed(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(tmpFile, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, err := getPassword(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(pw) != "secret" {
		t.Fatalf("want %q, got %q", "secret", pw)
	}
	// Zero it — must not panic.
	clear(pw)
	if string(pw) != "\x00\x00\x00\x00\x00\x00" {
		t.Error("password bytes were not zeroed")
	}
}

// ---------------------------------------------------------------------------
// Close tests (pre-existing)
// ---------------------------------------------------------------------------

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
