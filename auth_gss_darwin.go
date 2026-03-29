//go:build darwin

package main

/*
#cgo darwin CFLAGS: -DGSS_USE_APPLE_FRAMEWORK
#cgo darwin LDFLAGS: -framework GSS
#include "gss_darwin.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"unsafe"
)

// GSSTokenProvider uses the macOS native GSS-API framework (Heimdal) for
// SPNEGO token acquisition. It reads credentials from the default Kerberos
// credential cache, including the macOS Keychain-based API: cache type.
//
// When fileCache is non-nil, the provider operates in file-cache mode:
// credentials are copied from the system cache (e.g., SSO Extension's API:
// cache) to a FILE: cache before token acquisition. This works around an
// Apple GSS.framework limitation where gss_init_sec_context cannot use
// API: caches directly.
type GSSTokenProvider struct {
	spn       string // e.g., "HTTP@proxy.host.com"
	mu        sync.Mutex
	fileCache *FileCacheManager // nil when -file-cache is not used
}

// NewGSSTokenProvider creates a token provider that uses the macOS GSS-API framework.
// If explicitSPN is empty, the SPN is derived as HTTP@<proxy-hostname>.
// If fileCacheEnabled is true, a FileCacheManager is created to copy credentials
// from the system cache to a FILE: cache before token acquisition.
func NewGSSTokenProvider(proxyHost, explicitSPN string, fileCacheEnabled bool) (*GSSTokenProvider, error) {
	spn := explicitSPN
	if spn == "" {
		spn = "HTTP@" + extractHost(proxyHost)
	} else {
		spn = normalizeSPN(spn, '@', '/')
	}

	var fc *FileCacheManager
	if fileCacheEnabled {
		var err error
		fc, err = NewFileCacheManager()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize file cache: %w", err)
		}
		slog.Info("using macOS GSS-API with file cache workaround", "spn", spn)
	} else {
		slog.Info("using macOS GSS-API", "spn", spn)
	}

	return &GSSTokenProvider{spn: spn, fileCache: fc}, nil
}

func (g *GSSTokenProvider) GetToken() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.fileCache != nil {
		return g.getTokenFileCache()
	}
	return g.getTokenDefault()
}

// getTokenDefault is the standard token acquisition path using the system's
// default credential cache and the gss_acquire_cred pre-flight check.
func (g *GSSTokenProvider) getTokenDefault() (string, error) {
	cspn := C.CString(g.spn)
	defer C.free(unsafe.Pointer(cspn))

	result := C.acquire_spnego_token(cspn)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		hint := ""
		if ccname := os.Getenv("KRB5CCNAME"); ccname != "" {
			hint = fmt.Sprintf(" (KRB5CCNAME=%s; try 'klist' to check credentials or 'kinit' to refresh)", ccname)
		} else {
			hint = " (try 'klist' to check credentials or 'kinit' to refresh)"
		}
		return "", newCredentialError("GSS-API error: %s%s", msg, hint)
	}
	if result.data == nil || result.length == 0 {
		return "", &NegotiationError{authError{msg: "GSS-API returned empty token"}}
	}
	defer C.free(result.data)

	tokenBytes := C.GoBytes(result.data, C.int(result.length))
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

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

// acquireTokenNoPreFlight calls the C function that skips the gss_acquire_cred
// pre-flight and uses GSS_C_NO_CREDENTIAL with relaxed error checking.
func (g *GSSTokenProvider) acquireTokenNoPreFlight() (string, error) {
	cspn := C.CString(g.spn)
	defer C.free(unsafe.Pointer(cspn))

	result := C.acquire_spnego_token_no_preflight(cspn)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		return "", newCredentialError("GSS-API error (file-cache): %s (cache=%s)", msg, g.fileCache.CachePath())
	}
	if result.data == nil || result.length == 0 {
		return "", &NegotiationError{authError{msg: "GSS-API returned empty token (file-cache)"}}
	}
	defer C.free(result.data)

	tokenBytes := C.GoBytes(result.data, C.int(result.length))
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

func (g *GSSTokenProvider) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.fileCache != nil {
		return g.fileCache.Close()
	}
	return nil
}

// newNativeTokenProvider on darwin uses the GSS-API framework.
// It probes credentials at startup so the user gets an early warning
// if kinit is needed, but a probe failure is not fatal.
func newNativeTokenProvider(proxy, spn string, fileCacheEnabled bool) (TokenProvider, error) {
	g, err := NewGSSTokenProvider(proxy, spn, fileCacheEnabled)
	if err != nil {
		return nil, err
	}
	if _, err := g.GetToken(); err != nil {
		slog.Warn("initial credential check failed", "error", err)
		if fileCacheEnabled {
			slog.Warn("the proxy will retry on each request; ensure the Apple Kerberos SSO Extension has valid credentials")
		} else {
			slog.Warn("the proxy will retry on each request; run 'kinit' to obtain credentials")
		}
	}
	return g, nil
}
