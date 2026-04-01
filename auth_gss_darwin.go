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
	"unsafe"
)

// GSSTokenProvider uses the macOS native GSS-API framework (Heimdal) for
// SPNEGO token acquisition. It reads credentials from the default Kerberos
// credential cache, including the macOS Keychain-based API: cache type.
type GSSTokenProvider struct {
	spn string // e.g., "HTTP@proxy.host.com"
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
	return &GSSTokenProvider{spn: spn}, nil
}

func (g *GSSTokenProvider) GetToken() (string, error) {
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

// acquireTokenNoPreFlight calls the C function that skips the gss_acquire_cred
// pre-flight and uses GSS_C_NO_CREDENTIAL with relaxed error checking. This is
// used by FileCacheTokenProvider after populating the FILE: cache.
func (g *GSSTokenProvider) acquireTokenNoPreFlight() (string, error) {
	cspn := C.CString(g.spn)
	defer C.free(unsafe.Pointer(cspn))

	result := C.acquire_spnego_token_no_preflight(cspn)
	if result.error_code != 0 {
		msg := C.GoString(&result.error_msg[0])
		return "", newCredentialError("GSS-API error (no-preflight): %s", msg)
	}
	if result.data == nil || result.length == 0 {
		return "", &NegotiationError{authError{msg: "GSS-API returned empty token (no-preflight)"}}
	}
	defer C.free(result.data)

	tokenBytes := C.GoBytes(result.data, C.int(result.length))
	return base64.StdEncoding.EncodeToString(tokenBytes), nil
}

func (g *GSSTokenProvider) Close() error {
	return nil
}

// newNativeTokenProvider on darwin uses the GSS-API framework.
// It probes credentials at startup so the user gets an early warning
// if kinit is needed, but a probe failure is not fatal.
func newNativeTokenProvider(proxy, spn string, fileCacheEnabled bool) (TokenProvider, error) {
	if fileCacheEnabled {
		return newFileCacheTokenProvider(proxy, spn)
	}

	g, err := NewGSSTokenProvider(proxy, spn)
	if err != nil {
		return nil, err
	}
	if _, err := g.GetToken(); err != nil {
		slog.Warn("initial credential check failed", "error", err)
		slog.Warn("the proxy will retry on each request; run 'kinit' to obtain credentials")
	}
	return g, nil
}
