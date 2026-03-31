//go:build darwin

package main

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCredentialCache is a test implementation of credentialCache that
// records calls and returns configurable results.
type mockCredentialCache struct {
	mu sync.Mutex

	// CopyCreds behavior
	copyCredsLifetime time.Duration
	copyCredsMethod   string
	copyCredsErr      error
	copyCredsCalls    []string // dest paths passed to CopyCreds

	// SetDefaultCCacheName behavior
	setCCNameErr   error
	setCCNameCalls []string // names passed to SetDefaultCCacheName

	// DestroyCache behavior
	destroyCacheErr   error
	destroyCacheCalls []string // paths passed to DestroyCache

	// If set, CopyCreds writes a dummy file at destPath so that
	// EnsureCache's permission check succeeds.
	writeDummyFile bool
}

func (m *mockCredentialCache) CopyCreds(destPath string) (time.Duration, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.copyCredsCalls = append(m.copyCredsCalls, destPath)
	if m.copyCredsErr != nil {
		return 0, "", m.copyCredsErr
	}
	if m.writeDummyFile {
		_ = os.WriteFile(destPath, []byte("mock-cred-data"), 0o600)
	}
	return m.copyCredsLifetime, m.copyCredsMethod, nil
}

func (m *mockCredentialCache) SetDefaultCCacheName(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCCNameCalls = append(m.setCCNameCalls, name)
	return m.setCCNameErr
}

func (m *mockCredentialCache) DestroyCache(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.destroyCacheCalls = append(m.destroyCacheCalls, path)
	return m.destroyCacheErr
}

// newTestFileCacheManager creates a FileCacheManager with the given mock,
// backed by a real temp directory. The caller should defer m.Close() or
// t.Cleanup the temp dir.
func newTestFileCacheManager(t *testing.T, mock *mockCredentialCache) *FileCacheManager {
	t.Helper()
	tmpDir := t.TempDir()
	cachePath := tmpDir + "/krb5cc"
	return &FileCacheManager{
		cc:        mock,
		cachePath: cachePath,
		tempDir:   tmpDir,
	}
}

// ---------------------------------------------------------------------------
// EnsureCache tests
// ---------------------------------------------------------------------------

func TestEnsureCacheHappyPath(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// State should be updated.
	if !m.copied {
		t.Error("copied should be true after successful EnsureCache")
	}
	if m.forceRefresh {
		t.Error("forceRefresh should be cleared after successful EnsureCache")
	}
	if m.expiry.IsZero() {
		t.Error("expiry should be set")
	}
	if m.lastCopy.IsZero() {
		t.Error("lastCopy should be set")
	}
	if !m.ccacheNameSet {
		t.Error("ccacheNameSet should be true")
	}

	// Verify CopyCreds was called with the right path.
	if len(mock.copyCredsCalls) != 1 {
		t.Fatalf("CopyCreds called %d times, want 1", len(mock.copyCredsCalls))
	}
	if mock.copyCredsCalls[0] != m.cachePath {
		t.Errorf("CopyCreds path = %q, want %q", mock.copyCredsCalls[0], m.cachePath)
	}

	// Verify SetDefaultCCacheName was called with FILE: prefix.
	if len(mock.setCCNameCalls) != 1 {
		t.Fatalf("SetDefaultCCacheName called %d times, want 1", len(mock.setCCNameCalls))
	}
	want := "FILE:" + m.cachePath
	if mock.setCCNameCalls[0] != want {
		t.Errorf("SetDefaultCCacheName = %q, want %q", mock.setCCNameCalls[0], want)
	}
}

func TestEnsureCacheKrb5DirectMethod(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 10 * time.Minute,
		copyCredsMethod:   copyMethodKrb5Direct,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	if !m.copied {
		t.Error("copied should be true")
	}
}

func TestEnsureCacheCopyCredsFailure(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsErr: errors.New("no credentials found"),
	}
	m := newTestFileCacheManager(t, mock)

	err := m.EnsureCache()
	if err == nil {
		t.Fatal("EnsureCache should fail when CopyCreds fails")
	}

	// State should be unchanged.
	if m.copied {
		t.Error("copied should remain false after CopyCreds failure")
	}
	if m.ccacheNameSet {
		t.Error("ccacheNameSet should remain false after CopyCreds failure")
	}
	if !m.expiry.IsZero() {
		t.Error("expiry should remain zero after CopyCreds failure")
	}

	// SetDefaultCCacheName should not have been called.
	if len(mock.setCCNameCalls) != 0 {
		t.Errorf("SetDefaultCCacheName called %d times, want 0", len(mock.setCCNameCalls))
	}
}

func TestEnsureCacheSetCCNameFailure(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
		setCCNameErr:      errors.New("gss_krb5_ccache_name failed"),
	}
	m := newTestFileCacheManager(t, mock)

	err := m.EnsureCache()
	if err == nil {
		t.Fatal("EnsureCache should fail when SetDefaultCCacheName fails")
	}

	// Copy state should be updated (the copy itself succeeded).
	if !m.copied {
		t.Error("copied should be true (copy succeeded before ccache_name failed)")
	}
	// But ccacheNameSet should remain false.
	if m.ccacheNameSet {
		t.Error("ccacheNameSet should be false when SetDefaultCCacheName fails")
	}
}

func TestEnsureCacheSkipsWhenFresh(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	// First call should copy.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("first EnsureCache: %v", err)
	}
	if len(mock.copyCredsCalls) != 1 {
		t.Fatalf("CopyCreds called %d times after first EnsureCache, want 1", len(mock.copyCredsCalls))
	}

	// Second call should skip (cache is fresh).
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("second EnsureCache: %v", err)
	}
	if len(mock.copyCredsCalls) != 1 {
		t.Errorf("CopyCreds called %d times after second EnsureCache, want 1 (should skip)", len(mock.copyCredsCalls))
	}
}

func TestEnsureCacheRefreshesNearExpiry(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	// First call.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("first EnsureCache: %v", err)
	}

	// Simulate near-expiry and elapsed min interval.
	m.expiry = time.Now().Add(2 * time.Minute) // within fileCacheRefreshMargin
	m.lastCopy = time.Now().Add(-fileCacheMinRefreshInterval - time.Second)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("second EnsureCache: %v", err)
	}
	if len(mock.copyCredsCalls) != 2 {
		t.Errorf("CopyCreds called %d times, want 2 (should refresh near expiry)", len(mock.copyCredsCalls))
	}
}

func TestEnsureCacheForceRefreshTriggersCopy(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	// First call.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("first EnsureCache: %v", err)
	}

	// Force refresh and simulate elapsed min interval.
	m.ForceRefresh()
	m.lastCopy = time.Now().Add(-fileCacheMinRefreshInterval - time.Second)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("second EnsureCache after ForceRefresh: %v", err)
	}
	if len(mock.copyCredsCalls) != 2 {
		t.Errorf("CopyCreds called %d times, want 2", len(mock.copyCredsCalls))
	}
	if m.forceRefresh {
		t.Error("forceRefresh should be cleared after successful EnsureCache")
	}
}

func TestEnsureCacheTightensPermissions(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
	}
	m := newTestFileCacheManager(t, mock)

	// Pre-create file with overly permissive mode. The mock won't create
	// it, so we do it manually to test the permission-tightening path.
	if err := os.WriteFile(m.cachePath, []byte("creds"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	info, err := os.Stat(m.cachePath)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache file permissions = %04o, want 0600", perm)
	}
}

func TestEnsureCacheExpiryCalculation(t *testing.T) {
	const lifetime = 45 * time.Minute
	mock := &mockCredentialCache{
		copyCredsLifetime: lifetime,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	before := time.Now()
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}
	after := time.Now()

	// Expiry should be approximately now + lifetime.
	earliestExpiry := before.Add(lifetime)
	latestExpiry := after.Add(lifetime)
	if m.expiry.Before(earliestExpiry) || m.expiry.After(latestExpiry) {
		t.Errorf("expiry = %v, want between %v and %v", m.expiry, earliestExpiry, latestExpiry)
	}
}

// ---------------------------------------------------------------------------
// Close tests with mock
// ---------------------------------------------------------------------------

func TestCloseCallsSetCCNameResetWhenSet(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	// EnsureCache sets ccacheNameSet = true.
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Should have: first call = "FILE:<path>" from EnsureCache,
	// second call = "" from Close reset.
	if len(mock.setCCNameCalls) != 2 {
		t.Fatalf("SetDefaultCCacheName called %d times, want 2", len(mock.setCCNameCalls))
	}
	if mock.setCCNameCalls[1] != "" {
		t.Errorf("Close reset call = %q, want empty string", mock.setCCNameCalls[1])
	}
}

func TestCloseSkipsCCNameResetWhenNotSet(t *testing.T) {
	mock := &mockCredentialCache{}
	m := newTestFileCacheManager(t, mock)

	// Close without ever calling EnsureCache.
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if len(mock.setCCNameCalls) != 0 {
		t.Errorf("SetDefaultCCacheName called %d times, want 0 (ccacheNameSet=false)", len(mock.setCCNameCalls))
	}
}

func TestCloseCallsDestroyCacheWhenCopied(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if len(mock.destroyCacheCalls) != 1 {
		t.Fatalf("DestroyCache called %d times, want 1", len(mock.destroyCacheCalls))
	}
	if mock.destroyCacheCalls[0] != m.cachePath {
		t.Errorf("DestroyCache path = %q, want %q", mock.destroyCacheCalls[0], m.cachePath)
	}
}

func TestCloseSkipsDestroyCacheWhenNotCopied(t *testing.T) {
	mock := &mockCredentialCache{}
	m := newTestFileCacheManager(t, mock)

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if len(mock.destroyCacheCalls) != 0 {
		t.Errorf("DestroyCache called %d times, want 0 (copied=false)", len(mock.destroyCacheCalls))
	}
}

func TestCloseSetCCNameErrorIsNonFatal(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// Make the reset call fail.
	mock.setCCNameErr = errors.New("ccache_name reset failed")

	// Close should still succeed (error is logged, not returned).
	if err := m.Close(); err != nil {
		t.Fatalf("Close should succeed despite SetDefaultCCacheName error: %v", err)
	}
}

func TestCloseDestroyCacheErrorIsNonFatal(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
		destroyCacheErr:   errors.New("destroy failed"),
	}
	m := newTestFileCacheManager(t, mock)

	if err := m.EnsureCache(); err != nil {
		t.Fatalf("EnsureCache: %v", err)
	}

	// Close should still succeed.
	if err := m.Close(); err != nil {
		t.Fatalf("Close should succeed despite DestroyCache error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error recovery
// ---------------------------------------------------------------------------

func TestEnsureCacheRecoversAfterFailure(t *testing.T) {
	callCount := 0
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    true,
	}
	m := newTestFileCacheManager(t, mock)

	// First call fails.
	mock.copyCredsErr = errors.New("temporary failure")
	err := m.EnsureCache()
	if err == nil {
		t.Fatal("first EnsureCache should fail")
	}
	callCount++

	// Second call succeeds.
	mock.copyCredsErr = nil
	if err := m.EnsureCache(); err != nil {
		t.Fatalf("second EnsureCache should succeed: %v", err)
	}
	callCount++

	if len(mock.copyCredsCalls) != callCount {
		t.Errorf("CopyCreds called %d times, want %d", len(mock.copyCredsCalls), callCount)
	}
	if !m.copied {
		t.Error("copied should be true after recovery")
	}
}

func TestEnsureCacheRepeatedFailuresDoNotCorruptState(t *testing.T) {
	mock := &mockCredentialCache{
		copyCredsErr: errors.New("persistent failure"),
	}
	m := newTestFileCacheManager(t, mock)

	for i := range 5 {
		err := m.EnsureCache()
		if err == nil {
			t.Fatalf("EnsureCache call %d should fail", i)
		}
	}

	if m.copied {
		t.Error("copied should remain false after repeated failures")
	}
	if m.ccacheNameSet {
		t.Error("ccacheNameSet should remain false after repeated failures")
	}
	if !m.expiry.IsZero() {
		t.Error("expiry should remain zero after repeated failures")
	}
	if !m.lastCopy.IsZero() {
		t.Error("lastCopy should remain zero after repeated failures")
	}

	// Each call should have attempted CopyCreds (NeedsRefresh stays true).
	if len(mock.copyCredsCalls) != 5 {
		t.Errorf("CopyCreds called %d times, want 5 (each failure retries)", len(mock.copyCredsCalls))
	}

	// No calls to SetDefaultCCacheName or DestroyCache.
	if len(mock.setCCNameCalls) != 0 {
		t.Errorf("SetDefaultCCacheName called %d times, want 0", len(mock.setCCNameCalls))
	}
}

func TestEnsureCacheMissingFileAfterCopy(t *testing.T) {
	// CopyCreds "succeeds" but doesn't write a file — EnsureCache should
	// catch this via the os.Stat check.
	mock := &mockCredentialCache{
		copyCredsLifetime: 30 * time.Minute,
		copyCredsMethod:   copyMethodGSS,
		writeDummyFile:    false, // no file written
	}
	m := newTestFileCacheManager(t, mock)

	err := m.EnsureCache()
	if err == nil {
		t.Fatal("EnsureCache should fail when cache file is not created")
	}
	if !strings.Contains(err.Error(), "cache file not created") {
		t.Errorf("error = %q, want substring %q", err, "cache file not created")
	}
}
