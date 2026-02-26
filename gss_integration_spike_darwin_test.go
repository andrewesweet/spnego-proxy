//go:build darwin

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestEphemeralKDCSpike is a proof-of-concept spike that validates whether
// Apple's Heimdal GSS-API can acquire a SPNEGO token from an ephemeral MIT
// KDC started on the local machine.
//
// Prerequisites: MIT Kerberos via Homebrew (brew install krb5).
// Run with: INTEGRATION=1 go test -v -count=1 -run TestEphemeralKDCSpike ./...
func TestEphemeralKDCSpike(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run GSS-API integration tests")
	}

	// Locate MIT krb5 binaries from Homebrew.
	krb5Prefix := findKrb5Prefix(t)
	t.Logf("MIT krb5 prefix: %s", krb5Prefix)

	binDir := filepath.Join(krb5Prefix, "bin")
	sbinDir := filepath.Join(krb5Prefix, "sbin")
	kdb5Util := filepath.Join(sbinDir, "kdb5_util")
	kadminLocal := filepath.Join(sbinDir, "kadmin.local")
	krb5kdcBin := filepath.Join(sbinDir, "krb5kdc")
	kinitBin := filepath.Join(binDir, "kinit")

	for _, bin := range []string{kdb5Util, kadminLocal, krb5kdcBin, kinitBin} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("required binary not found: %s (install with: brew install krb5)", bin)
		}
	}

	// Create temp directory for KDC state.
	tmpDir := t.TempDir()

	// Find an ephemeral port for the KDC.
	port := findFreePort(t)
	t.Logf("KDC will listen on port %d", port)

	const (
		realm            = "TEST.SPNEGO"
		userPrincipal    = "testuser"
		userPassword     = "testpass123"
		servicePrincipal = "HTTP/localhost"
	)

	// Write KDC configuration files.
	kdcConfPath := filepath.Join(tmpDir, "kdc.conf")
	krb5ConfPath := filepath.Join(tmpDir, "krb5.conf")
	aclPath := filepath.Join(tmpDir, "kadm5.acl")

	mustWriteFile(t, kdcConfPath, fmt.Sprintf(`[kdcdefaults]
    kdc_listen = %d
    kdc_tcp_listen = %d

[realms]
    %s = {
        database_name = %s/principal
        key_stash_file = %s/.k5.%s
        acl_file = %s/kadm5.acl
        max_life = 1h
        max_renewable_life = 7d
    }
`, port, port, realm, tmpDir, tmpDir, realm, tmpDir))

	mustWriteFile(t, krb5ConfPath, fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    udp_preference_limit = 1
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    %s = {
        kdc = tcp/127.0.0.1:%d
        admin_server = 127.0.0.1:%d
    }

[domain_realm]
    localhost = %s
    .localhost = %s
`, realm, realm, port, port, realm, realm))

	mustWriteFile(t, aclPath, "*/admin@"+realm+" *\n")

	// Environment for MIT krb5 utilities.
	kdcEnv := append(os.Environ(),
		"KRB5_CONFIG="+krb5ConfPath,
		"KRB5_KDC_PROFILE="+kdcConfPath,
	)

	// Initialize the KDC database.
	mustRunCmd(t, kdb5Util, kdcEnv, "create", "-s", "-r", realm, "-P", "masterkey")
	t.Log("KDC database created")

	// Create test principals.
	mustRunCmd(t, kadminLocal, kdcEnv, "-r", realm, "-q",
		fmt.Sprintf("addprinc -pw %s %s@%s", userPassword, userPrincipal, realm))
	mustRunCmd(t, kadminLocal, kdcEnv, "-r", realm, "-q",
		fmt.Sprintf("addprinc -randkey %s@%s", servicePrincipal, realm))
	t.Logf("created principals: %s@%s, %s@%s", userPrincipal, realm, servicePrincipal, realm)

	// Start krb5kdc in foreground mode (-n prevents daemonizing).
	kdcCmd := exec.Command(krb5kdcBin, "-n")
	kdcCmd.Env = kdcEnv
	kdcCmd.Stdout = os.Stderr
	kdcCmd.Stderr = os.Stderr
	if err := kdcCmd.Start(); err != nil {
		t.Fatalf("start krb5kdc: %v", err)
	}
	t.Cleanup(func() {
		_ = kdcCmd.Process.Kill()
		_ = kdcCmd.Wait()
	})

	// Wait for the KDC to accept connections.
	waitForPort(t, port, 5*time.Second)
	t.Log("KDC is ready")

	// Populate a FILE: credential cache using MIT kinit.
	ccachePath := filepath.Join(tmpDir, "ccache")
	kinitCmd := exec.Command(kinitBin, userPrincipal+"@"+realm)
	kinitCmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+krb5ConfPath,
		"KRB5CCNAME=FILE:"+ccachePath,
	)
	kinitCmd.Stdin = strings.NewReader(userPassword + "\n")
	kinitCmd.Stdout = os.Stderr
	kinitCmd.Stderr = os.Stderr
	if err := kinitCmd.Run(); err != nil {
		t.Fatalf("kinit failed: %v", err)
	}
	t.Log("credential cache populated")

	// Override environment so Apple's Heimdal uses our KDC and cache.
	t.Setenv("KRB5_CONFIG", krb5ConfPath)
	t.Setenv("KRB5CCNAME", "FILE:"+ccachePath)

	// Acquire a SPNEGO token using the GSS-API code path.
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
			err, krb5ConfPath, ccachePath)
	}

	// Validate the SPNEGO token structure.
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

// findKrb5Prefix locates the Homebrew MIT krb5 installation prefix.
func findKrb5Prefix(t *testing.T) string {
	t.Helper()

	// Try brew --prefix krb5 first (works regardless of architecture).
	if out, err := exec.Command("brew", "--prefix", "krb5").Output(); err == nil {
		prefix := strings.TrimSpace(string(out))
		if _, err := os.Stat(filepath.Join(prefix, "sbin", "krb5kdc")); err == nil {
			return prefix
		}
	}

	// Fallback to well-known Homebrew paths.
	for _, prefix := range []string{
		"/opt/homebrew/opt/krb5", // Apple Silicon
		"/usr/local/opt/krb5",   // Intel
	} {
		if _, err := os.Stat(filepath.Join(prefix, "sbin", "krb5kdc")); err == nil {
			return prefix
		}
	}

	t.Skip("MIT krb5 not found (install with: brew install krb5)")
	return ""
}

// findFreePort returns an available TCP port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// waitForPort polls until a TCP connection to 127.0.0.1:port succeeds.
func waitForPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %d did not become ready within %v", port, timeout)
}

// mustWriteFile writes content to the given path, failing the test on error.
func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mustRunCmd runs a command with the given environment, failing the test on error.
func mustRunCmd(t *testing.T, name string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\noutput: %s", filepath.Base(name), strings.Join(args, " "), err, out)
	}
	if testing.Verbose() {
		t.Logf("%s: %s", filepath.Base(name), strings.TrimSpace(string(out)))
	}
}
