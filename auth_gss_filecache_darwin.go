//go:build darwin

package main

import (
	"fmt"
	"log/slog"
	"sync"
)

// FileCacheTokenProvider wraps a GSSTokenProvider with a FileCacheManager
// for environments where the system credential cache (e.g., Apple SSO
// Extension's API: cache) cannot be used directly by gss_init_sec_context.
// It copies credentials to a FILE: cache before each token acquisition.
type FileCacheTokenProvider struct {
	gss       *GSSTokenProvider
	fileCache *FileCacheManager
	mu        sync.Mutex
}

// NewFileCacheTokenProvider creates a token provider that copies credentials
// from the system cache to a FILE: cache before token acquisition.
func NewFileCacheTokenProvider(proxyHost, explicitSPN string) (*FileCacheTokenProvider, error) {
	gss, err := NewGSSTokenProvider(proxyHost, explicitSPN)
	if err != nil {
		return nil, err
	}

	fc, err := NewFileCacheManager()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file cache: %w", err)
	}

	slog.Info("using file cache workaround", "spn", gss.spn)
	return &FileCacheTokenProvider{gss: gss, fileCache: fc}, nil
}

// GetToken ensures the FILE: cache is populated, then acquires a token
// without the gss_acquire_cred pre-flight. On failure, it forces a
// re-copy and retries once.
func (f *FileCacheTokenProvider) GetToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.fileCache.EnsureCache(); err != nil {
		return "", err
	}

	token, err := f.gss.acquireTokenNoPreFlight()
	if err != nil {
		// Retry once: force a re-copy from the system cache (the SSO
		// Extension may have refreshed the API: cache since our last copy).
		slog.Debug("token acquisition failed, forcing file cache refresh", "error", err)
		f.fileCache.ForceRefresh()
		if retryErr := f.fileCache.EnsureCache(); retryErr != nil {
			return "", retryErr
		}
		token, err = f.gss.acquireTokenNoPreFlight()
		if err != nil {
			return "", err
		}
	}

	return token, nil
}

func (f *FileCacheTokenProvider) Close() error {
	return f.fileCache.Close()
}

// newFileCacheTokenProvider creates a FileCacheTokenProvider and probes
// credentials at startup. A probe failure is not fatal.
func newFileCacheTokenProvider(proxy, spn string) (*FileCacheTokenProvider, error) {
	f, err := NewFileCacheTokenProvider(proxy, spn)
	if err != nil {
		return nil, err
	}
	if _, err := f.GetToken(); err != nil {
		slog.Warn("initial credential check failed", "error", err)
		slog.Warn("the proxy will retry on each request; ensure the Apple Kerberos SSO Extension has valid credentials")
	}
	return f, nil
}
