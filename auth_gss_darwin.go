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
	"net"
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
		host := proxyHost
		if h, _, err := net.SplitHostPort(proxyHost); err == nil {
			host = h
		}
		spn = "HTTP@" + host
	}
	logger.Printf("using macOS GSS-API with SPN: %s", spn)
	return &GSSTokenProvider{spn: spn}, nil
}

func (g *GSSTokenProvider) GetToken(_ string) (string, error) {
	cspn := C.CString(g.spn)
	defer C.free(unsafe.Pointer(cspn))

	result := C.acquire_spnego_token(cspn)
	if result.error_code != 0 {
		return "", fmt.Errorf("GSS-API error: %s", C.GoString(&result.error_msg[0]))
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
