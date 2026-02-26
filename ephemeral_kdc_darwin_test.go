//go:build darwin

package main

import (
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

const (
	ephemeralKDCRealm     = "TEST.SPNEGO"
	ephemeralKDCUser      = "testuser"
	ephemeralKDCPassword  = "testpass123"
	ephemeralKDCService   = "HTTP/localhost"
	ephemeralKDCMasterKey = "masterkey"
)

// EphemeralKDC manages the lifecycle of a local MIT Kerberos KDC for testing.
// It requires MIT krb5 utilities (kdb5_util, kadmin.local, krb5kdc, kinit)
// to be installed, typically via `brew install krb5` on macOS.
type EphemeralKDC struct {
	Realm      string // Kerberos realm (e.g. "TEST.SPNEGO")
	KDCPort    int    // ephemeral port the KDC listens on
	KRB5Conf   string // path to generated krb5.conf
	CCachePath string // path to FILE: credential cache

	kdcCmd *exec.Cmd
	closed bool
}

// NewEphemeralKDC creates and starts an ephemeral MIT KDC for testing.
// It locates MIT krb5 binaries from Homebrew, creates the KDC database,
// adds test principals (testuser and HTTP/localhost), starts krb5kdc on an
// ephemeral port, and populates a FILE: credential cache via kinit.
//
// The KDC is stopped automatically via t.Cleanup. Call Close() for explicit
// early teardown if needed.
//
// Skips the test if MIT krb5 is not installed.
func NewEphemeralKDC(t *testing.T) *EphemeralKDC {
	t.Helper()

	// Locate MIT krb5 binaries.
	krb5Prefix := findKrb5Prefix(t)
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

	tmpDir := t.TempDir()
	port := findFreePort(t)

	kdc := &EphemeralKDC{
		Realm:   ephemeralKDCRealm,
		KDCPort: port,
	}

	// Write configuration files.
	kdcConfPath := filepath.Join(tmpDir, "kdc.conf")
	kdc.KRB5Conf = filepath.Join(tmpDir, "krb5.conf")
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
`, port, port, ephemeralKDCRealm, tmpDir, tmpDir, ephemeralKDCRealm, tmpDir))

	mustWriteFile(t, kdc.KRB5Conf, fmt.Sprintf(`[libdefaults]
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
`, ephemeralKDCRealm, ephemeralKDCRealm, port, port, ephemeralKDCRealm, ephemeralKDCRealm))

	mustWriteFile(t, aclPath, "*/admin@"+ephemeralKDCRealm+" *\n")

	// Environment for MIT krb5 utilities.
	kdcEnv := append(os.Environ(),
		"KRB5_CONFIG="+kdc.KRB5Conf,
		"KRB5_KDC_PROFILE="+kdcConfPath,
	)

	// Initialize the KDC database.
	mustRunCmd(t, kdb5Util, kdcEnv, "create", "-s", "-r", ephemeralKDCRealm, "-P", ephemeralKDCMasterKey)

	// Create test principals.
	mustRunCmd(t, kadminLocal, kdcEnv, "-r", ephemeralKDCRealm, "-q",
		fmt.Sprintf("addprinc -pw %s %s@%s", ephemeralKDCPassword, ephemeralKDCUser, ephemeralKDCRealm))
	mustRunCmd(t, kadminLocal, kdcEnv, "-r", ephemeralKDCRealm, "-q",
		fmt.Sprintf("addprinc -randkey %s@%s", ephemeralKDCService, ephemeralKDCRealm))

	// Start krb5kdc in foreground mode (-n prevents daemonizing).
	kdcLogPath := filepath.Join(tmpDir, "krb5kdc.log")
	kdcLogFile, err := os.Create(kdcLogPath)
	if err != nil {
		t.Fatalf("create KDC log file: %v", err)
	}
	kdc.kdcCmd = exec.Command(krb5kdcBin, "-n") //nolint:gosec // G204: binary path from Homebrew krb5
	kdc.kdcCmd.Env = kdcEnv
	kdc.kdcCmd.Stdout = kdcLogFile
	kdc.kdcCmd.Stderr = kdcLogFile
	if err := kdc.kdcCmd.Start(); err != nil {
		t.Fatalf("start krb5kdc: %v", err)
	}
	t.Logf("krb5kdc started (pid %d, port %d)", kdc.kdcCmd.Process.Pid, port)

	t.Cleanup(func() {
		kdc.Close()
		_ = kdcLogFile.Close()
		if logData, err := os.ReadFile(kdcLogPath); err == nil && len(logData) > 0 {
			t.Logf("krb5kdc log:\n%s", logData)
		}
	})

	// Verify krb5kdc is still running after a brief pause.
	time.Sleep(200 * time.Millisecond)
	if kdc.kdcCmd.ProcessState != nil {
		t.Fatalf("krb5kdc exited prematurely")
	}

	// Wait for the KDC to accept connections.
	waitForPort(t, port, 5*time.Second)
	t.Logf("krb5kdc is listening on port %d", port)

	// Populate a FILE: credential cache using MIT kinit.
	kdc.CCachePath = filepath.Join(tmpDir, "ccache")
	kinitCmd := exec.Command(kinitBin, ephemeralKDCUser+"@"+ephemeralKDCRealm) //nolint:gosec // G204: binary path from Homebrew krb5
	kinitCmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+kdc.KRB5Conf,
		"KRB5CCNAME=FILE:"+kdc.CCachePath,
	)
	kinitCmd.Stdin = strings.NewReader(ephemeralKDCPassword + "\n")
	kinitOut, err := kinitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kinit failed: %v\noutput: %s", err, kinitOut)
	}

	// Verify the credential cache was populated using klist.
	klistBin := filepath.Join(binDir, "klist")
	klistCmd := exec.Command(klistBin) //nolint:gosec // G204: binary path from Homebrew krb5
	klistCmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+kdc.KRB5Conf,
		"KRB5CCNAME=FILE:"+kdc.CCachePath,
	)
	klistOut, err := klistCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("klist failed after kinit: %v\noutput: %s", err, klistOut)
	}
	t.Logf("credential cache populated:\n%s", klistOut)

	return kdc
}

// SetEnv overrides KRB5_CONFIG and KRB5CCNAME so that Apple's Heimdal
// GSS-API framework uses the ephemeral KDC and credential cache.
func (k *EphemeralKDC) SetEnv(t *testing.T) {
	t.Helper()
	t.Setenv("KRB5_CONFIG", k.KRB5Conf)
	t.Setenv("KRB5CCNAME", "FILE:"+k.CCachePath)
}

// Close stops the KDC process. It is safe to call multiple times.
// Also registered via t.Cleanup in NewEphemeralKDC.
func (k *EphemeralKDC) Close() {
	if k.closed {
		return
	}
	k.closed = true
	if k.kdcCmd != nil && k.kdcCmd.Process != nil {
		_ = k.kdcCmd.Process.Kill()
		_ = k.kdcCmd.Wait()
	}
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
		"/usr/local/opt/krb5",    // Intel
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
	cmd := exec.Command(name, args...) //nolint:gosec // G204: test helper launching MIT krb5 utilities
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\noutput: %s", filepath.Base(name), strings.Join(args, " "), err, out)
	}
	if testing.Verbose() {
		t.Logf("%s: %s", filepath.Base(name), strings.TrimSpace(string(out)))
	}
}
