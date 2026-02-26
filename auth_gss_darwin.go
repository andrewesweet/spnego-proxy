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
type GSSTokenProvider struct {
	spn string // e.g., "HTTP@proxy.host.com"
	mu  sync.Mutex
}

// NewGSSTokenProvider creates a token provider that uses the macOS GSS-API framework.
// If explicitSPN is empty, the SPN is derived as HTTP@<proxy-hostname>.
func NewGSSTokenProvider(proxyHost, explicitSPN string) (*GSSTokenProvider, error) {
	spn := explicitSPN
	if spn == "" {
		spn = "HTTP@" + extractHost(proxyHost)
	} else {
		spn = normalizeSPN(spn, '@', '/')
	}
	slog.Info("using macOS GSS-API", "spn", spn)
	g := &GSSTokenProvider{spn: spn}

	// Validate credentials are available at startup. This is a warning,
	// not a fatal error, because credentials may become available later
	// (e.g. kinit run after the proxy starts).
	if _, err := g.GetToken(); err != nil {
		slog.Warn("initial credential check failed", "error", err)
		slog.Warn("the proxy will retry on each request; run 'kinit' to obtain credentials")
	}

	return g, nil
}

// SPN returns the service principal name used for token acquisition.
func (g *GSSTokenProvider) SPN() string {
	return g.spn
}

func (g *GSSTokenProvider) GetToken() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	cspn := C.CString(g.spn)
	defer C.free(unsafe.Pointer(cspn))

	result := C.acquire_spnego_token(cspn)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		if ccname := os.Getenv("KRB5CCNAME"); ccname != "" {
			return "", fmt.Errorf("GSS-API error: %s (KRB5CCNAME=%s; try 'klist' to check credentials or 'kinit' to refresh)", msg, ccname)
		}
		return "", fmt.Errorf("GSS-API error: %s (try 'klist' to check credentials or 'kinit' to refresh)", msg)
	}
	if result.data == nil || result.length == 0 {
		return "", fmt.Errorf("GSS-API returned empty token")
	}
	defer C.free_token_data(result.data)

	tokenBytes := C.GoBytes(result.data, C.int(result.length))
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

func (g *GSSTokenProvider) Close() error {
	return nil
}

// newNativeTokenProvider on darwin uses the GSS-API framework.
func newNativeTokenProvider(proxy, spn string) (TokenProvider, error) {
	return NewGSSTokenProvider(proxy, spn)
}
