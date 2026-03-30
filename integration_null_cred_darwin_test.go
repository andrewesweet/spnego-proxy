//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileCacheKrb5DirectCopyFallback verifies that the krb5 direct-copy
// fallback works when gss_iter_creds_f returns NULL credential handles.
//
// It uses DYLD_INSERT_LIBRARIES to interpose gss_iter_creds_f with a version
// that always passes NULL to the callback, simulating the Apple SSO Extension
// behavior on affected devices. The ephemeral KDC provides real Kerberos
// tickets that the krb5 fallback path reads via krb5_cc_default.
//
// Run with: INTEGRATION=1 go test -v -run TestFileCacheKrb5DirectCopyFallback -count=1
func TestFileCacheKrb5DirectCopyFallback(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}

	// Inner invocation: the actual test, running with interposed gss_iter_creds_f.
	if os.Getenv("NULL_CRED_INNER") == "1" {
		testKrb5DirectCopyInner(t)
		return
	}

	// Outer invocation: set up KDC, build dylib, re-exec.
	kdc := NewEphemeralKDC(t)
	defer kdc.Close()

	dylibPath := buildInterposeDylib(t)
	t.Logf("built interpose dylib: %s", dylibPath)

	// Re-exec this test binary with DYLD_INSERT_LIBRARIES to interpose
	// gss_iter_creds_f. The inner invocation runs testKrb5DirectCopyInner.
	cmd := exec.Command(os.Args[0], //nolint:gosec // G204: re-exec of own test binary
		"-test.run=^TestFileCacheKrb5DirectCopyFallback$",
		"-test.v",
		"-test.count=1",
	)
	cmd.Env = append(os.Environ(),
		"NULL_CRED_INNER=1",
		"INTEGRATION=1",
		"DYLD_INSERT_LIBRARIES="+dylibPath,
		"KRB5_CONFIG="+kdc.KRB5Conf,
		"KRB5CCNAME=FILE:"+kdc.CCachePath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("inner test failed: %v", err)
	}
}

// testKrb5DirectCopyInner runs inside the re-execed process with interposed
// gss_iter_creds_f. It verifies that EnsureCache succeeds via the krb5
// direct-copy fallback and produces a valid credential cache.
func testKrb5DirectCopyInner(t *testing.T) {
	t.Helper()

	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// EnsureCache should succeed via the krb5 direct-copy fallback,
	// since gss_iter_creds_f is interposed to return NULL handles.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache with interposed NULL creds: %v", err)
	}

	// Verify the cache file exists and has restrictive permissions.
	info, err := os.Stat(m.CachePath())
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache file permissions = %04o, want group/other bits unset", perm)
	}
	t.Logf("cache file: %s, size=%d, mode=%04o", m.CachePath(), info.Size(), info.Mode().Perm())

	// Verify the credential cache contains valid tickets using klist.
	out := mustKlist(t, m.CachePath())
	t.Logf("klist output for krb5 direct-copy cache:\n%s", out)

	if !strings.Contains(out, ephemeralKDCRealm) {
		t.Errorf("copied cache does not contain realm %s", ephemeralKDCRealm)
	}

	// Verify only TGTs were copied (no service tickets).
	if strings.Contains(out, "HTTP/") {
		t.Error("cache contains service tickets; expected only TGTs")
	}

	// The lifetime should be positive.
	if m.expiry.Before(m.lastCopy) {
		t.Error("expiry is before lastCopy — lifetime computation is wrong")
	}
	t.Logf("lifetime: %v", m.expiry.Sub(m.lastCopy))
}

// buildInterposeDylib compiles testdata/interpose_null_cred.c into a dynamic
// library. Returns the path to the built dylib.
func buildInterposeDylib(t *testing.T) string {
	t.Helper()

	srcPath := filepath.Join("testdata", "interpose_null_cred.c")
	if _, err := os.Stat(srcPath); err != nil {
		t.Fatalf("interpose source not found: %v", err)
	}

	dylibPath := filepath.Join(t.TempDir(), "interpose_null_cred.dylib")
	cmd := exec.Command("clang",
		"-dynamiclib",
		"-framework", "GSS",
		"-o", dylibPath,
		srcPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build interpose dylib: %v\n%s", err, out)
	}

	return dylibPath
}
