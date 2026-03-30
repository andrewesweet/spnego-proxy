//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- DYLD interposition test infrastructure ---
//
// These tests use DYLD_INSERT_LIBRARIES to replace GSS-API functions at
// runtime, simulating macOS-specific failure modes that only occur with
// the Apple Kerberos SSO Extension on Intune-managed devices.
//
// Each test follows the re-exec pattern:
//   - Outer invocation: starts ephemeral KDC, builds dylib, re-execs self
//   - Inner invocation: runs the actual test with interposed functions
//
// Run all: INTEGRATION=1 go test -v -run 'TestFileCache.*Interpose' -count=1

// buildDylib compiles a C source file from testdata/ into a .dylib.
func buildDylib(t *testing.T, srcName string) string {
	t.Helper()
	srcPath := filepath.Join("testdata", srcName)
	if _, err := os.Stat(srcPath); err != nil {
		t.Fatalf("interpose source not found: %v", err)
	}

	dylibName := strings.TrimSuffix(srcName, ".c") + ".dylib"
	dylibPath := filepath.Join(t.TempDir(), dylibName)
	cmd := exec.Command("clang", //nolint:gosec // G204: building test dylib from known source
		"-dynamiclib",
		"-framework", "GSS",
		"-framework", "Kerberos",
		"-Wno-deprecated-declarations",
		"-o", dylibPath,
		srcPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", srcName, err, out)
	}
	return dylibPath
}

// runInnerTest re-execs the current test binary with DYLD_INSERT_LIBRARIES
// set to the given dylib, plus the KDC environment. The inner invocation
// is identified by the innerEnvVar being set to "1".
func runInnerTest(t *testing.T, testName, dylibPath, innerEnvVar string, kdc *EphemeralKDC) {
	t.Helper()
	cmd := exec.Command(os.Args[0], //nolint:gosec // G204: re-exec of own test binary
		"-test.run=^"+testName+"$",
		"-test.v",
		"-test.count=1",
	)
	cmd.Env = append(os.Environ(),
		innerEnvVar+"=1",
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

// --- Test 1: NULL credential fallback (single NULL) ---

// TestFileCacheInterposeNullCred verifies that the krb5 direct-copy
// fallback works when gss_iter_creds_f returns a single NULL credential
// handle, simulating the Apple SSO Extension behavior.
func TestFileCacheInterposeNullCred(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Getenv("INTERPOSE_NULL_INNER") == "1" {
		testNullCredInner(t)
		return
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	dylibPath := buildDylib(t, "interpose_null_cred.c")
	runInnerTest(t, "TestFileCacheInterposeNullCred", dylibPath, "INTERPOSE_NULL_INNER", kdc)
}

func testNullCredInner(t *testing.T) {
	t.Helper()

	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache with interposed NULL creds: %v", err)
	}

	// Verify cache contents.
	info, err := os.Stat(m.CachePath())
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache file permissions = %04o, want group/other bits unset", perm)
	}
	t.Logf("cache file: size=%d, mode=%04o", info.Size(), info.Mode().Perm())

	out := mustKlist(t, m.CachePath())
	t.Logf("klist output:\n%s", out)

	if !strings.Contains(out, ephemeralKDCRealm) {
		t.Errorf("cache does not contain realm %s", ephemeralKDCRealm)
	}

	// Only TGTs should be copied.
	if strings.Contains(out, "HTTP/") {
		t.Error("cache contains service tickets; expected only TGTs")
	}

	// Lifetime should be positive and reasonable.
	lifetime := m.expiry.Sub(m.lastCopy)
	if lifetime <= 0 {
		t.Errorf("lifetime = %v, want positive", lifetime)
	}
	if lifetime > 25*time.Hour {
		t.Errorf("lifetime = %v, seems unreasonably long", lifetime)
	}
	t.Logf("lifetime: %v", lifetime)
}

// --- Test 2: Multiple NULL credentials (multi-realm) ---

// TestFileCacheInterposeMultiNullCred verifies the fallback works when
// gss_iter_creds_f calls the callback multiple times with NULL handles,
// simulating a multi-realm SSO Extension environment.
func TestFileCacheInterposeMultiNullCred(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Getenv("INTERPOSE_MULTI_NULL_INNER") == "1" {
		// Same validation as single-NULL — the fallback should still work.
		testNullCredInner(t)
		return
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	dylibPath := buildDylib(t, "interpose_multi_null_cred.c")
	runInnerTest(t, "TestFileCacheInterposeMultiNullCred", dylibPath, "INTERPOSE_MULTI_NULL_INNER", kdc)
}

// --- Test 3: gss_krb5_copy_ccache always fails ---

// TestFileCacheInterposeCopyCcacheFail verifies the try_initialize_and_copy
// fallback path within the GSS callback. gss_krb5_copy_ccache is interposed
// to always return GSS_S_FAILURE, forcing the manual initialize+copy path.
func TestFileCacheInterposeCopyCcacheFail(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Getenv("INTERPOSE_COPY_FAIL_INNER") == "1" {
		testCopyCcacheFailInner(t)
		return
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	dylibPath := buildDylib(t, "interpose_copy_ccache_fail.c")
	runInnerTest(t, "TestFileCacheInterposeCopyCcacheFail", dylibPath, "INTERPOSE_COPY_FAIL_INNER", kdc)
}

func testCopyCcacheFailInner(t *testing.T) {
	t.Helper()

	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// EnsureCache should succeed via the try_initialize_and_copy fallback,
	// since gss_krb5_copy_ccache is interposed to always fail.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache with interposed copy_ccache failure: %v", err)
	}

	out := mustKlist(t, m.CachePath())
	t.Logf("klist output:\n%s", out)

	if !strings.Contains(out, ephemeralKDCRealm) {
		t.Errorf("cache does not contain realm %s", ephemeralKDCRealm)
	}

	lifetime := m.expiry.Sub(m.lastCopy)
	if lifetime <= 0 {
		t.Errorf("lifetime = %v, want positive", lifetime)
	}
	t.Logf("try_initialize_and_copy succeeded, lifetime: %v", lifetime)
}

// --- Test 4: End-to-end token acquisition via NULL cred fallback ---

// TestFileCacheInterposeNullCredEndToEnd verifies that after the krb5
// direct-copy fallback populates the FILE: cache, gss_init_sec_context
// can actually use it to acquire a SPNEGO token.
func TestFileCacheInterposeNullCredEndToEnd(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Getenv("INTERPOSE_E2E_INNER") == "1" {
		testNullCredEndToEndInner(t)
		return
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	dylibPath := buildDylib(t, "interpose_null_cred.c")
	runInnerTest(t, "TestFileCacheInterposeNullCredEndToEnd", dylibPath, "INTERPOSE_E2E_INNER", kdc)
}

func testNullCredEndToEndInner(t *testing.T) {
	t.Helper()

	provider, err := NewGSSTokenProvider("localhost", "", true)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	// GetToken triggers EnsureCache (krb5 fallback) then gss_init_sec_context.
	token, err := provider.GetToken()
	if err != nil {
		t.Fatalf("GetToken with interposed NULL creds: %v", err)
	}

	decoded := validateSPNEGOToken(t, token)
	t.Logf("acquired valid SPNEGO token via krb5 fallback: %d bytes", len(decoded))
}

// --- Test 5: Refresh cycle under interposition ---

// TestFileCacheInterposeNullCredRefresh verifies that the cache refresh
// cycle works correctly when the GSS path is permanently broken (all NULL
// handles). After initial copy, expiring the cache should trigger a
// successful re-copy via the same krb5 fallback.
func TestFileCacheInterposeNullCredRefresh(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("set INTEGRATION=1 to run integration tests")
	}
	if os.Getenv("INTERPOSE_REFRESH_INNER") == "1" {
		testNullCredRefreshInner(t)
		return
	}

	kdc := NewEphemeralKDC(t)
	defer kdc.Close()
	dylibPath := buildDylib(t, "interpose_null_cred.c")
	runInnerTest(t, "TestFileCacheInterposeNullCredRefresh", dylibPath, "INTERPOSE_REFRESH_INNER", kdc)
}

func testNullCredRefreshInner(t *testing.T) {
	t.Helper()

	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// Initial copy.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("first EnsureCache: %v", err)
	}
	firstExpiry := m.expiry
	t.Logf("first copy: expiry=%v", firstExpiry)

	// Simulate cache expiry.
	m.expiry = time.Now().Add(-1 * time.Minute)
	m.lastCopy = time.Now().Add(-1 * time.Minute)

	// Re-copy should succeed.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache after simulated expiry: %v", err)
	}

	if m.expiry.Before(time.Now()) {
		t.Error("expiry is in the past after re-copy")
	}
	t.Logf("refresh succeeded: new expiry=%v", m.expiry)

	// Verify cache is still valid.
	out := mustKlist(t, m.CachePath())
	if !strings.Contains(out, ephemeralKDCRealm) {
		t.Errorf("cache does not contain realm %s after refresh", ephemeralKDCRealm)
	}
}
