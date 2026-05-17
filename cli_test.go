package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andrewesweet/spnego-proxy/internal/proxy"
)

// minimalKrb5Conf is a minimal krb5.conf sufficient for config.Load to succeed
// and client.NewWithPassword to construct a client without hitting the network.
const minimalKrb5Conf = `[libdefaults]
  default_realm = TEST.REALM
[realms]
  TEST.REALM = {
    kdc = 127.0.0.1
  }
`

// writeFile writes content to a temp file, then chmods it to perm. The file
// is always created at 0600 and the exact mode applied via os.Chmod (a literal
// perm arg to os.WriteFile/os.Chmod trips gosec G306/G302; a variable does
// not — same pattern as internal/proxy's writePasswordFile helper).
func writeFile(t *testing.T, name, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
	return path
}

// TestParseFlagsDefaults pins the default flag values. These defaults are part
// of the SemVer CLI contract surface (see CLAUDE.md § Versioning): changing any
// of them is a breaking change, so this test must fail loudly if one drifts.
func TestParseFlagsDefaults(t *testing.T) {
	c, fs, err := parseFlags(nil)
	if err != nil {
		t.Fatalf("parseFlags(nil) error: %v", err)
	}
	if fs == nil {
		t.Fatal("parseFlags returned nil FlagSet")
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"addr", c.Addr, "127.0.0.1:8080"},
		{"proxy", c.Proxy, ""},
		{"spn", c.SPN, ""},
		{"debug", c.Debug, false},
		{"dial-timeout", c.DialTimeout, 30 * time.Second},
		{"read-timeout", c.ReadTimeout, 30 * time.Second},
		{"drain-timeout", c.DrainTimeout, 30 * time.Second},
		{"keepalive", c.KeepAlive, 30 * time.Second},
		{"idle-timeout", c.IdleTimeout, 5 * time.Minute},
		{"max-conns", c.MaxConns, 512},
		{"connect-ports", c.ConnectPorts, "443"},
		{"allowed-ips", c.AllowedIPs, ""},
		{"noproxy", c.NoProxy, ""},
		{"cb-threshold", c.CBThreshold, uint(proxy.CBConsecutiveFailures)},
		{"cb-timeout", c.CBTimeout, proxy.CBTimeout},
		{"forwarded", c.Forwarded, false},
		{"x-forwarded-for", c.XForwardedFor, false},
		{"upstream-tls", c.UpstreamTLS, false},
		{"upstream-ca", c.UpstreamCA, ""},
		{"upstream-tls-insecure", c.UpstreamTLSInsecure, false},
		{"version", c.ShowVersion, false},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("default %s = %v, want %v (CLI contract change?)", ch.name, ch.got, ch.want)
		}
	}
}

func TestParseFlagsOverrides(t *testing.T) {
	c, _, err := parseFlags([]string{
		"-addr", ":9999",
		"-proxy", "proxy.example:3128",
		"-dial-timeout", "5s",
		"-connect-ports", "443,8443",
		"-cb-threshold", "7",
		"-forwarded",
	})
	if err != nil {
		t.Fatalf("parseFlags error: %v", err)
	}
	if c.Addr != ":9999" || c.Proxy != "proxy.example:3128" {
		t.Errorf("addr/proxy not applied: %q %q", c.Addr, c.Proxy)
	}
	if c.DialTimeout != 5*time.Second {
		t.Errorf("dial-timeout = %v, want 5s", c.DialTimeout)
	}
	if c.ConnectPorts != "443,8443" {
		t.Errorf("connect-ports = %q", c.ConnectPorts)
	}
	if c.CBThreshold != 7 {
		t.Errorf("cb-threshold = %d, want 7", c.CBThreshold)
	}
	if !c.Forwarded {
		t.Error("forwarded not set")
	}
}

func TestParseFlagsUnknownFlag(t *testing.T) {
	_, fs, err := parseFlags([]string{"-no-such-flag"})
	if err == nil {
		t.Fatal("expected error for unknown flag, got nil")
	}
	if fs == nil {
		t.Error("FlagSet must be returned even on parse error (main renders usage)")
	}
}

// TestParseFlagsHelp pins the contract main.go relies on: -h yields
// flag.ErrHelp, which main maps to exit code 0 (vs exit 2 for other errors).
func TestParseFlagsHelp(t *testing.T) {
	_, _, err := parseFlags([]string{"-h"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-h) = %v, want flag.ErrHelp", err)
	}
}

func TestParseFlagsVersion(t *testing.T) {
	c, _, err := parseFlags([]string{"-version"})
	if err != nil {
		t.Fatalf("parseFlags(-version) error: %v", err)
	}
	if !c.ShowVersion {
		t.Error("ShowVersion not set by -version")
	}
}

// TestBuildProviderGokrb5MissingConfigRealm covers the gokrb5 fast-fail branch:
// -user set but -config/-realm absent.
func TestBuildProviderGokrb5MissingConfigRealm(t *testing.T) {
	p, err := buildProvider(&cliConfig{User: "alice"})
	if err == nil {
		t.Fatal("expected error when -config/-realm missing, got nil")
	}
	if p != nil {
		t.Error("provider must be nil on error")
	}
	if !strings.Contains(err.Error(), "-config and -realm are required") {
		t.Errorf("error = %v, want mention of required -config/-realm", err)
	}
}

func TestBuildProviderGokrb5BadPasswordFile(t *testing.T) {
	cfg := writeFile(t, "krb5.conf", minimalKrb5Conf, 0o600)
	p, err := buildProvider(&cliConfig{
		User:         "alice",
		Realm:        "TEST.REALM",
		CfgFile:      cfg,
		PasswordFile: "/nonexistent/password",
	})
	if err == nil {
		t.Fatal("expected error for missing password file, got nil")
	}
	if p != nil {
		t.Error("provider must be nil on error")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error = %v, want password-related failure", err)
	}
}

// TestBuildProviderGokrb5InsecurePasswordPerms pins the security behaviour that
// a group/other-readable password file is rejected.
func TestBuildProviderGokrb5InsecurePasswordPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not enforced on Windows")
	}
	cfg := writeFile(t, "krb5.conf", minimalKrb5Conf, 0o600)
	pw := writeFile(t, "pw", "secret\n", 0o644)
	_, err := buildProvider(&cliConfig{
		User: "alice", Realm: "TEST.REALM", CfgFile: cfg, PasswordFile: pw,
	})
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("error = %v, want insecure-permissions rejection", err)
	}
}

// TestBuildProviderWrapsInCircuitBreaker is the load-bearing assertion: the
// selected provider is ALWAYS wrapped in the circuit breaker. The wrap is the
// account-lockout defence (circuit_breaker.go), so a regression that returned
// the bare provider would be a security regression, not just a behaviour change.
func TestBuildProviderWrapsInCircuitBreaker(t *testing.T) {
	cfg := writeFile(t, "krb5.conf", minimalKrb5Conf, 0o600)
	pw := writeFile(t, "pw", "secret\n", 0o600)
	p, err := buildProvider(&cliConfig{
		User:         "alice",
		Realm:        "TEST.REALM",
		CfgFile:      cfg,
		PasswordFile: pw,
		Proxy:        "proxy.example:3128",
		CBThreshold:  3,
		CBTimeout:    30 * time.Second,
	})
	if err != nil {
		t.Fatalf("buildProvider error: %v", err)
	}
	defer func() { _ = p.Close() }()
	if _, ok := p.(*proxy.CircuitBreakerTokenProvider); !ok {
		t.Fatalf("buildProvider returned %T, want *proxy.CircuitBreakerTokenProvider", p)
	}
}

// TestBuildProviderNativeUnsupportedPlatform pins the else-branch error on
// platforms without native GSS-API. On darwin the native path probes real
// credentials (non-deterministic in CI), so it is skipped there.
func TestBuildProviderNativeUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin native path probes real GSS credentials; not deterministic")
	}
	p, err := buildProvider(&cliConfig{Proxy: "proxy.example:3128"})
	if err == nil {
		t.Fatal("expected native-unsupported error, got nil")
	}
	if p != nil {
		t.Error("provider must be nil on error")
	}
	if !strings.Contains(err.Error(), "native GSS-API") {
		t.Errorf("error = %v, want native-GSS-API message", err)
	}
}
