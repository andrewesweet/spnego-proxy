//go:build darwin

package main

/*
#cgo darwin CFLAGS: -DGSS_USE_APPLE_FRAMEWORK -Wno-deprecated-declarations
#cgo darwin LDFLAGS: -framework GSS -framework Kerberos
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
	"syscall"
	"time"
	"unsafe"
)

// newCredentialError creates a CredentialError with a formatted message.
func newCredentialError(format string, args ...any) *CredentialError {
	return &CredentialError{authError{msg: fmt.Sprintf(format, args...)}}
}

// Copy method identifiers returned by credentialCache.CopyCreds.
const (
	copyMethodGSS        = "gss"
	copyMethodKrb5Direct = "krb5_direct"
)

// fileCacheRefreshMargin is the time before TGT expiry at which the file
// cache will be proactively refreshed. A refresh is also triggered on
// demand if token acquisition fails.
const fileCacheRefreshMargin = 5 * time.Minute

// fileCacheMinRefreshInterval prevents perpetual re-copy loops when the
// TGT lifetime is shorter than the refresh margin.
const fileCacheMinRefreshInterval = 30 * time.Second

// credentialCache abstracts the low-level credential cache operations,
// decoupling FileCacheManager from CGo. This enables testing with
// alternative implementations.
type credentialCache interface {
	// CopyCreds copies credentials from the system cache to destPath.
	// Returns the remaining TGT lifetime, the copy method used, and any error.
	CopyCreds(destPath string) (lifetime time.Duration, method string, err error)

	// SetDefaultCCacheName sets the process-default credential cache name.
	// Pass empty string to reset to system default.
	SetDefaultCCacheName(name string) error

	// DestroyCache removes and deallocates the FILE: cache at path.
	DestroyCache(path string) error
}

// cgoCredentialCache implements credentialCache using CGo calls to the
// native GSS-API and krb5 libraries.
type cgoCredentialCache struct{}

func (c *cgoCredentialCache) CopyCreds(destPath string) (time.Duration, string, error) {
	cpath := C.CString(destPath)
	defer C.free(unsafe.Pointer(cpath))

	result := C.copy_creds_to_file_cache(cpath)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		return 0, "", newCredentialError("file cache copy failed: %s", msg)
	}

	lifetime := time.Duration(result.lifetime) * time.Second
	method := copyMethodGSS
	if result.copy_method == C.FILECACHE_COPY_METHOD_KRB5_DIRECT {
		method = copyMethodKrb5Direct
	}

	return lifetime, method, nil
}

func (c *cgoCredentialCache) SetDefaultCCacheName(name string) error {
	var cname *C.char
	if name != "" {
		cname = C.CString(name)
		defer C.free(unsafe.Pointer(cname))
	}
	if C.set_default_ccache_name(cname) != 0 {
		return newCredentialError("failed to set default credential cache name via gss_krb5_ccache_name")
	}
	return nil
}

func (c *cgoCredentialCache) DestroyCache(path string) error {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	if C.destroy_file_cache(cpath) != 0 {
		return fmt.Errorf("failed to destroy file cache at %s", path)
	}
	return nil
}

// FileCacheManager manages the lifecycle of a FILE: credential cache
// populated from the system credential cache (typically the SSO Extension's
// API: cache). It is safe for concurrent use; all public methods are
// serialized by the caller's mutex (FileCacheTokenProvider.mu).
type FileCacheManager struct {
	cc            credentialCache // abstracted credential cache operations
	cachePath     string          // path to the FILE: cache on disk
	tempDir       string          // parent temp directory (0700)
	expiry        time.Time       // estimated TGT expiry
	lastCopy      time.Time       // time of last successful copy
	copied        bool            // whether at least one copy has succeeded
	forceRefresh  bool            // set by ForceRefresh(); cleared after next copy
	ccacheNameSet bool            // whether gss_krb5_ccache_name has been called
	closed        bool
	mu            sync.Mutex // protects closed flag for idempotent Close()
}

// userTempDir returns the per-user temporary directory on macOS.
// It prefers $TMPDIR (set by launchd for user sessions), falling back to
// confstr(_CS_DARWIN_USER_TEMP_DIR) which works even in LaunchDaemon
// contexts where $TMPDIR is not set by launchd. This avoids falling back
// to /tmp, which may be restricted on corporate-managed devices.
func userTempDir() string {
	if dir := os.Getenv("TMPDIR"); dir != "" {
		return dir
	}
	cdir := C.darwin_user_temp_dir()
	if cdir != nil {
		defer C.free(unsafe.Pointer(cdir))
		return C.GoString(cdir)
	}
	return os.TempDir()
}

// cleanStaleCaches removes leftover spnego-proxy-* temp directories from
// previous runs that were not cleaned up (e.g., due to SIGKILL or crash).
// This is best-effort; errors are logged but not returned.
func cleanStaleCaches() {
	pattern := filepath.Join(userTempDir(), "spnego-proxy-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, dir := range matches {
		// Zero the cache file before removing, in case it contains credentials.
		cachePath := filepath.Join(dir, "krb5cc")
		if err := zeroFileContents(cachePath); err == nil {
			slog.Debug("zeroed stale cache file", "path", cachePath)
		}
		if err := os.RemoveAll(dir); err != nil {
			slog.Warn("failed to remove stale cache directory", "path", dir, "error", err)
		} else {
			slog.Info("removed stale cache directory", "path", dir)
		}
	}
}

// NewFileCacheManager creates a secure temporary directory and returns a
// manager that will populate a FILE: credential cache inside it. The cache
// is not populated until EnsureCache is called (lazy initialization).
func NewFileCacheManager() (*FileCacheManager, error) {
	// Clean up any stale cache directories from crashed previous runs.
	cleanStaleCaches()

	tmpDir, err := os.MkdirTemp(userTempDir(), "spnego-proxy-")
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
		cc:        &cgoCredentialCache{},
		cachePath: cachePath,
		tempDir:   tmpDir,
	}, nil
}

// CachePath returns the path to the FILE: credential cache on disk.
func (m *FileCacheManager) CachePath() string {
	return m.cachePath
}

// NeedsRefresh reports whether the cache needs to be (re-)populated.
// This returns true if no copy has been done, if a forced refresh was
// requested, or if the TGT is near expiry. The minimum refresh interval
// is always enforced to prevent re-copy storms.
func (m *FileCacheManager) NeedsRefresh() bool {
	if !m.copied {
		return true
	}

	// Enforce minimum interval to prevent re-copy storms, even when
	// ForceRefresh has been called.
	if time.Since(m.lastCopy) < fileCacheMinRefreshInterval {
		return false
	}

	if m.forceRefresh {
		return true
	}

	return time.Until(m.expiry) < fileCacheRefreshMargin
}

// ForceRefresh marks the cache as needing refresh on the next EnsureCache
// call. This is used after a token acquisition failure to force a re-copy.
// The minimum refresh interval is still enforced to prevent re-copy storms.
func (m *FileCacheManager) ForceRefresh() {
	m.forceRefresh = true
}

// EnsureCache populates the FILE: credential cache if needed (first call
// or near TGT expiry). It enumerates system credentials via GSS-API,
// copies the best credential to the FILE: cache, and sets the process-default
// cache name via gss_krb5_ccache_name.
func (m *FileCacheManager) EnsureCache() error {
	if !m.NeedsRefresh() {
		return nil
	}

	lifetime, method, err := m.cc.CopyCreds(m.cachePath)
	if err != nil {
		return err
	}

	// Verify the cache file was created with restrictive permissions.
	info, err := os.Stat(m.cachePath)
	if err != nil {
		return newCredentialError("cache file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		slog.Warn("cache file has unexpected permissions, tightening",
			"path", m.cachePath, "mode", fmt.Sprintf("%04o", perm))
		if err := os.Chmod(m.cachePath, 0o600); err != nil {
			return newCredentialError("failed to restrict cache file permissions: %v", err)
		}
	}

	now := time.Now()
	m.expiry = now.Add(lifetime)
	m.lastCopy = now
	m.copied = true
	m.forceRefresh = false

	slog.Info("credentials copied to file cache",
		"cache_path", m.cachePath,
		"method", method,
		"lifetime", lifetime,
		"expiry", m.expiry.Format(time.RFC3339))

	// Set the process-default cache name so that subsequent GSS-API calls
	// (gss_init_sec_context with GSS_C_NO_CREDENTIAL) use this FILE: cache.
	if err := m.cc.SetDefaultCCacheName("FILE:" + m.cachePath); err != nil {
		return err
	}
	m.ccacheNameSet = true

	return nil
}

// zeroFileContents overwrites the file at path with zero bytes.
// It opens with O_NOFOLLOW to prevent symlink attacks and verifies
// the target is a regular file before writing.
func zeroFileContents(path string) (retErr error) {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", path)
	}

	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		chunk := int64(len(zeros))
		if chunk > remaining {
			chunk = remaining
		}
		n, err := f.Write(zeros[:chunk])
		if err != nil {
			return err
		}
		remaining -= int64(n)
	}

	return f.Sync()
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
		if err := m.cc.SetDefaultCCacheName(""); err != nil {
			slog.Warn("failed to reset default credential cache name", "error", err)
		}
	}

	// Zero the cache file unconditionally if it exists on disk. A partial
	// write (e.g., krb5_cc_initialize succeeded but copy failed) may have
	// left credential data even when m.copied is false.
	if err := zeroFileContents(m.cachePath); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to zero cache file", "path", m.cachePath, "error", err)
	}

	// Destroy the cache: unlink + free krb5 resources.
	if m.copied {
		if err := m.cc.DestroyCache(m.cachePath); err != nil {
			slog.Warn("failed to destroy file cache", "path", m.cachePath, "error", err)
		}
	}

	// Remove the temp directory (should be empty after cache destruction,
	// but use RemoveAll for robustness if destroy_file_cache failed to unlink).
	if err := os.RemoveAll(m.tempDir); err != nil {
		slog.Warn("failed to remove temp directory", "path", m.tempDir, "error", err)
	}

	slog.Info("file cache manager closed", "cache_path", m.cachePath)
	return nil
}
