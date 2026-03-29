//go:build darwin

package main

/*
#cgo darwin CFLAGS: -DGSS_USE_APPLE_FRAMEWORK
#cgo darwin LDFLAGS: -framework GSS
#include "filecache_darwin.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"
)

// fileCacheRefreshMargin is the time before TGT expiry at which the file
// cache will be proactively refreshed. A refresh is also triggered on
// demand if token acquisition fails.
const fileCacheRefreshMargin = 5 * time.Minute

// fileCacheMinRefreshInterval prevents perpetual re-copy loops when the
// TGT lifetime is shorter than the refresh margin.
const fileCacheMinRefreshInterval = 30 * time.Second

// FileCacheManager manages the lifecycle of a FILE: credential cache
// populated from the system credential cache (typically the SSO Extension's
// API: cache). It is safe for concurrent use; all public methods are
// serialized by the caller's mutex (GSSTokenProvider.mu).
type FileCacheManager struct {
	cachePath     string    // path to the FILE: cache on disk
	tempDir       string    // parent temp directory (0700)
	expiry        time.Time // estimated TGT expiry
	lastCopy      time.Time // time of last successful copy
	copied        bool      // whether at least one copy has succeeded
	ccacheNameSet bool      // whether gss_krb5_ccache_name has been called
	closed        bool
	mu            sync.Mutex // protects closed flag for idempotent Close()
}

// NewFileCacheManager creates a secure temporary directory and returns a
// manager that will populate a FILE: credential cache inside it. The cache
// is not populated until EnsureCache is called (lazy initialization).
func NewFileCacheManager() (*FileCacheManager, error) {
	tmpDir, err := os.MkdirTemp("", "spnego-proxy-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Verify permissions are restrictive (defense-in-depth).
	info, err := os.Stat(tmpDir)
	if err != nil {
		_ = os.Remove(tmpDir)
		return nil, fmt.Errorf("failed to stat temp directory: %w", err)
	}
	if info.Mode().Perm() != 0o700 {
		_ = os.Remove(tmpDir)
		return nil, fmt.Errorf("temp directory has unexpected permissions: %o", info.Mode().Perm())
	}

	cachePath := filepath.Join(tmpDir, "krb5cc")
	slog.Info("file cache manager initialized", "cache_path", cachePath)

	return &FileCacheManager{
		cachePath: cachePath,
		tempDir:   tmpDir,
	}, nil
}

// CachePath returns the path to the FILE: credential cache on disk.
func (m *FileCacheManager) CachePath() string {
	return m.cachePath
}

// NeedsRefresh reports whether the cache needs to be (re-)populated.
// This returns true if no copy has been done, or if the TGT is near expiry.
func (m *FileCacheManager) NeedsRefresh() bool {
	if !m.copied {
		return true
	}

	// If the TGT lifetime was very short (< refresh margin), avoid a
	// perpetual re-copy loop by enforcing a minimum interval.
	if time.Since(m.lastCopy) < fileCacheMinRefreshInterval {
		return false
	}

	return time.Until(m.expiry) < fileCacheRefreshMargin
}

// ForceRefresh marks the cache as needing refresh on the next EnsureCache
// call. This is used after a token acquisition failure to force a re-copy.
func (m *FileCacheManager) ForceRefresh() {
	m.copied = false
}

// EnsureCache populates the FILE: credential cache if needed (first call
// or near TGT expiry). It enumerates system credentials via GSS-API,
// copies the best credential to the FILE: cache, and sets the process-default
// cache name via gss_krb5_ccache_name.
func (m *FileCacheManager) EnsureCache() error {
	if !m.NeedsRefresh() {
		return nil
	}

	cpath := C.CString(m.cachePath)
	defer C.free(unsafe.Pointer(cpath))

	result := C.copy_creds_to_file_cache(cpath)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		return &CredentialError{authError{
			msg: fmt.Sprintf("file cache copy failed: %s", msg),
		}}
	}

	// Verify the cache file was created with restrictive permissions.
	info, err := os.Stat(m.cachePath)
	if err != nil {
		return &CredentialError{authError{
			msg: fmt.Sprintf("cache file not created: %v", err),
		}}
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		slog.Warn("cache file has unexpected permissions, tightening",
			"path", m.cachePath, "mode", fmt.Sprintf("%04o", perm))
		if err := os.Chmod(m.cachePath, 0o600); err != nil {
			return fmt.Errorf("failed to restrict cache file permissions: %w", err)
		}
	}

	// Track expiry. lifetime is in seconds.
	lifetime := time.Duration(result.lifetime) * time.Second
	m.expiry = time.Now().Add(lifetime)
	m.lastCopy = time.Now()
	m.copied = true

	slog.Info("credentials copied to file cache",
		"cache_path", m.cachePath,
		"lifetime_seconds", result.lifetime,
		"expiry", m.expiry.Format(time.RFC3339))

	// Set the process-default cache name so that subsequent GSS-API calls
	// (gss_init_sec_context with GSS_C_NO_CREDENTIAL) use this FILE: cache.
	ccname := C.CString("FILE:" + m.cachePath)
	defer C.free(unsafe.Pointer(ccname))

	if C.set_default_ccache_name(ccname) != 0 {
		return &CredentialError{authError{
			msg: "failed to set default credential cache name via gss_krb5_ccache_name",
		}}
	}
	m.ccacheNameSet = true

	return nil
}

// ZeroFileContents overwrites the cache file with zeros. Exported for testing.
func (m *FileCacheManager) ZeroFileContents() error {
	cpath := C.CString(m.cachePath)
	defer C.free(unsafe.Pointer(cpath))

	if C.zero_file_contents(cpath) != 0 {
		return fmt.Errorf("failed to zero cache file: %s", m.cachePath)
	}
	return nil
}

// Close securely destroys the FILE: credential cache and removes the
// temporary directory. It is safe to call multiple times.
func (m *FileCacheManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	// Reset the process-default cache name before destroying the file,
	// so that any subsequent (unlikely) GSS calls don't reference a
	// deleted file.
	if m.ccacheNameSet {
		if C.set_default_ccache_name(nil) != 0 {
			slog.Warn("failed to reset default credential cache name")
		}
	}

	// Destroy the cache: zero contents, unlink, free krb5 resources.
	if m.copied {
		cpath := C.CString(m.cachePath)
		C.destroy_file_cache(cpath)
		C.free(unsafe.Pointer(cpath))
	}

	// Remove the temp directory (should be empty after cache destruction).
	if err := os.Remove(m.tempDir); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove temp directory", "path", m.tempDir, "error", err)
	}

	slog.Info("file cache manager closed", "cache_path", m.cachePath)
	return nil
}
