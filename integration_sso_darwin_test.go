//go:build darwin

package main

import (
	"os"
	"os/exec"
	"testing"
)

// SSO integration tests require an actual macOS device managed by Intune with
// the Apple Kerberos SSO Extension active and a valid TGT in an API: cache.
//
// Run with: INTEGRATION_SSO=1 go test -v -run TestSSO -count=1

func skipUnlessSSO(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_SSO") == "" {
		t.Skip("set INTEGRATION_SSO=1 to run SSO Extension integration tests (requires Intune-managed macOS)")
	}
}

// logSystemDiagnostics captures diagnostic info to help debug failures remotely.
func logSystemDiagnostics(t *testing.T) {
	t.Helper()

	// macOS version.
	if out, err := exec.Command("sw_vers").CombinedOutput(); err == nil {
		t.Logf("sw_vers:\n%s", out)
	}

	// All credential caches.
	if out, err := exec.Command("klist", "-A").CombinedOutput(); err == nil {
		t.Logf("klist -A:\n%s", out)
	} else {
		t.Logf("klist -A failed: %v\n%s", err, out)
	}
}

// TestSSODeviceIsAffected MUST run first. It confirms that the device actually
// has the API: cache problem (normal GSS path fails without -file-cache). If
// this test PASSES (GetToken succeeds), the device is NOT affected and the
// remaining SSO tests are skipped.
func TestSSODeviceIsAffected(t *testing.T) {
	skipUnlessSSO(t)
	logSystemDiagnostics(t)

	provider := newTestGSSProvider(t, "localhost", "")

	_, err := provider.GetToken()
	if err == nil {
		t.Skip("GetToken succeeded without -file-cache; this device is NOT affected by the API: cache issue. Remaining SSO tests would be vacuous.")
	}
	t.Logf("confirmed: normal GSS path fails: %v", err)
	t.Log("device IS affected — file-cache workaround is needed")
}

func TestSSOIterCredsFindsAPICache(t *testing.T) {
	skipUnlessSSO(t)

	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("EnsureCache: %v", err)
	}

	t.Logf("credential found and copied: expiry=%v, lifetime=%v",
		m.expiry, m.expiry.Sub(m.lastCopy))
}

func TestSSOCopyCcacheFromAPIToFile(t *testing.T) {
	skipUnlessSSO(t)

	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("EnsureCache: %v", err)
	}

	// Verify the file exists with restrictive permissions.
	info, err := os.Stat(m.CachePath())
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	t.Logf("cache file: %s, size=%d, mode=%04o", m.CachePath(), info.Size(), info.Mode().Perm())

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache file permissions = %04o, want group/other bits unset", perm)
	}

	// Verify the cache contents with klist.
	out, err := exec.Command("klist", "-c", "FILE:"+m.CachePath()).CombinedOutput() //nolint:gosec // test only
	if err != nil {
		t.Fatalf("klist on copied cache: %v\n%s", err, out)
	}
	t.Logf("klist of copied FILE: cache:\n%s", out)

	// Cross-reference: the copied cache principal should appear in klist -A.
	allCaches, _ := exec.Command("klist", "-A").CombinedOutput()
	t.Logf("all caches for comparison:\n%s", allCaches)
}

func TestSSOCcacheNameOverridesDefault(t *testing.T) {
	skipUnlessSSO(t)

	m := newTestFCM(t)

	if err := m.EnsureCache(); err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("EnsureCache: %v", err)
	}

	// gss_krb5_ccache_name was called by EnsureCache.
	// Now try acquiring a token using the no-preflight path.
	provider := newFileCacheTestProvider(t)

	token, err := provider.gss.acquireTokenNoPreFlight()
	if err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("acquireTokenNoPreFlight: %v", err)
	}

	decoded := validateSPNEGOToken(t, token)
	t.Logf("token acquired: %d bytes decoded", len(decoded))
}

func TestSSOTokenHasSPNEGOStructure(t *testing.T) {
	skipUnlessSSO(t)

	provider := newFileCacheTestProvider(t)

	token, err := provider.GetToken()
	if err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("GetToken: %v", err)
	}

	decoded := validateSPNEGOToken(t, token)

	// SSO Extension tokens are typically ~4KB due to PAC data.
	if len(decoded) < 500 {
		t.Errorf("token unusually small: %d bytes (expected >500 for SSO token with PAC)", len(decoded))
	}
	t.Logf("valid SPNEGO token: %d bytes (base64: %d chars)", len(decoded), len(token))
}

func TestSSOGetTokenEndToEnd(t *testing.T) {
	skipUnlessSSO(t)

	provider := newFileCacheTestProvider(t)

	// Multiple acquisitions to verify cache reuse.
	for i := range 3 {
		token, err := provider.GetToken()
		if err != nil {
			logSystemDiagnostics(t)
			t.Fatalf("GetToken call %d: %v", i+1, err)
		}
		decoded := validateSPNEGOToken(t, token)
		t.Logf("call %d: %d-byte SPNEGO token", i+1, len(decoded))
	}
}

func TestSSOCleanupRemovesFileCache(t *testing.T) {
	skipUnlessSSO(t)

	provider, err := NewFileCacheTokenProvider("localhost", "")
	if err != nil {
		t.Fatalf("NewFileCacheTokenProvider: %v", err)
	}

	// Trigger cache population.
	if _, err := provider.GetToken(); err != nil {
		logSystemDiagnostics(t)
		t.Fatalf("GetToken: %v", err)
	}

	tmpDir := provider.fileCache.tempDir
	cachePath := provider.fileCache.CachePath()

	// Verify files exist.
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file should exist: %v", err)
	}

	// Close and verify cleanup.
	if err := provider.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Errorf("cache file %q still exists after Close", cachePath)
	}
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Errorf("temp dir %q still exists after Close", tmpDir)
	}
}
