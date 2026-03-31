//go:build darwin

package main

import "log/slog"

// getTokenFileCache acquires a token via the file-cache workaround path.
// It ensures the FILE: cache is populated (copying from the system cache if
// needed), then acquires a token without the gss_acquire_cred pre-flight.
// On failure, it forces a re-copy and retries once.
func (g *GSSTokenProvider) getTokenFileCache() (string, error) {
	if err := g.fileCache.EnsureCache(); err != nil {
		return "", err
	}

	token, err := g.acquireTokenNoPreFlight()
	if err != nil {
		// Retry once: force a re-copy from the system cache (the SSO
		// Extension may have refreshed the API: cache since our last copy).
		slog.Debug("token acquisition failed, forcing file cache refresh", "error", err)
		g.fileCache.ForceRefresh()
		if retryErr := g.fileCache.EnsureCache(); retryErr != nil {
			return "", retryErr
		}
		token, err = g.acquireTokenNoPreFlight()
		if err != nil {
			return "", err
		}
	}

	return token, nil
}
