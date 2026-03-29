//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileCacheManagerCreatesSecureTempDir(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	info, err := os.Stat(m.tempDir)
	if err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("temp dir is not a directory")
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("temp dir permissions = %04o, want 0700", perm)
	}
}

func TestFileCacheManagerCachePathInsideTempDir(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	dir := filepath.Dir(m.CachePath())
	if dir != m.tempDir {
		t.Errorf("cache path %q is not inside temp dir %q", m.CachePath(), m.tempDir)
	}
}

func TestFileCacheManagerCachePathNotPredictable(t *testing.T) {
	m1, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager (1): %v", err)
	}
	t.Cleanup(func() { _ = m1.Close() })

	m2, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager (2): %v", err)
	}
	t.Cleanup(func() { _ = m2.Close() })

	if m1.CachePath() == m2.CachePath() {
		t.Error("two FileCacheManagers produced identical cache paths")
	}
	if m1.tempDir == m2.tempDir {
		t.Error("two FileCacheManagers produced identical temp dirs")
	}
}

func TestFileCacheManagerCloseRemovesTempDir(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	tmpDir := m.tempDir

	// Create a dummy file at the cache path so Close has something to clean.
	if err := os.WriteFile(m.CachePath(), []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write dummy cache: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Errorf("temp dir %q still exists after Close", tmpDir)
	}
}

func TestFileCacheManagerCloseIsIdempotent(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}

	if err := m.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestFileCacheManagerCloseIdempotentUnderConcurrency(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	// Create a dummy file so close has work to do.
	_ = os.WriteFile(m.CachePath(), []byte("dummy"), 0o600)

	errc := make(chan error, 10)
	for range 10 {
		go func() {
			errc <- m.Close()
		}()
	}
	for range 10 {
		if err := <-errc; err != nil {
			t.Errorf("concurrent Close: %v", err)
		}
	}
}

func TestFileCacheManagerZeroFileContents(t *testing.T) {
	m, err := NewFileCacheManager()
	if err != nil {
		t.Fatalf("NewFileCacheManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	// Write known non-zero data.
	data := []byte("KERBEROS_CREDENTIAL_DATA_SENSITIVE")
	if err := os.WriteFile(m.CachePath(), data, 0o600); err != nil {
		t.Fatalf("write test data: %v", err)
	}

	// Zero the file.
	if err := m.ZeroFileContents(); err != nil {
		t.Fatalf("ZeroFileContents: %v", err)
	}

	// Read back and verify all zeros.
	contents, err := os.ReadFile(m.CachePath())
	if err != nil {
		t.Fatalf("read zeroed file: %v", err)
	}
	if len(contents) != len(data) {
		t.Errorf("zeroed file length = %d, want %d", len(contents), len(data))
	}
	for i, b := range contents {
		if b != 0 {
			t.Errorf("byte %d = 0x%02x, want 0x00", i, b)
			break
		}
	}
}

func TestFileCacheManagerNeedsRefresh(t *testing.T) {
	tests := []struct {
		name        string
		copied      bool
		expiry      time.Time
		lastCopy    time.Time
		wantRefresh bool
	}{
		{
			name:        "initially needs refresh",
			copied:      false,
			wantRefresh: true,
		},
		{
			name:        "near expiry needs refresh",
			copied:      true,
			expiry:      time.Now().Add(4 * time.Minute),
			lastCopy:    time.Now().Add(-1 * time.Minute),
			wantRefresh: true,
		},
		{
			name:        "far from expiry does not need refresh",
			copied:      true,
			expiry:      time.Now().Add(30 * time.Minute),
			lastCopy:    time.Now().Add(-1 * time.Minute),
			wantRefresh: false,
		},
		{
			name:        "short lifetime respects min refresh interval",
			copied:      true,
			expiry:      time.Now().Add(2 * time.Minute),
			lastCopy:    time.Now(), // just copied
			wantRefresh: false,      // min interval not elapsed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewFileCacheManager()
			if err != nil {
				t.Fatalf("NewFileCacheManager: %v", err)
			}
			t.Cleanup(func() { _ = m.Close() })

			m.copied = tt.copied
			m.expiry = tt.expiry
			m.lastCopy = tt.lastCopy

			if got := m.NeedsRefresh(); got != tt.wantRefresh {
				t.Errorf("NeedsRefresh() = %v, want %v", got, tt.wantRefresh)
			}
		})
	}
}

func TestGSSTokenProviderFileCacheInit(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "", true)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider with file-cache: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	if provider.fileCache == nil {
		t.Fatal("expected non-nil fileCache when fileCacheEnabled=true")
	}

	// Verify the temp dir was actually created on disk with correct perms.
	info, err := os.Stat(provider.fileCache.tempDir)
	if err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("temp dir permissions = %04o, want 0700", perm)
	}
}

func TestGSSTokenProviderNoFileCacheByDefault(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "", false)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	if provider.fileCache != nil {
		t.Error("expected nil fileCache when fileCacheEnabled=false")
	}
}

func TestGSSTokenProviderCloseCallsFileCacheClose(t *testing.T) {
	provider, err := NewGSSTokenProvider("proxy.example.com:8080", "", true)
	if err != nil {
		t.Fatalf("NewGSSTokenProvider: %v", err)
	}

	tmpDir := provider.fileCache.tempDir

	if err := provider.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Errorf("temp dir %q still exists after provider.Close()", tmpDir)
	}
}

func TestNewNativeTokenProviderFileCacheFlagPassthrough(t *testing.T) {
	// This test verifies that the file-cache flag is accepted and creates
	// a provider with file-cache enabled. The initial credential probe will
	// fail (no KDC), but the provider should still be created.
	provider, err := newNativeTokenProvider("proxy.example.com:8080", "", true)
	if err != nil {
		t.Fatalf("newNativeTokenProvider with file-cache: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	// Verify it's a GSSTokenProvider with file cache.
	gss, ok := provider.(*GSSTokenProvider)
	if !ok {
		t.Fatalf("expected *GSSTokenProvider, got %T", provider)
	}
	if gss.fileCache == nil {
		t.Error("expected non-nil fileCache")
	}
}
