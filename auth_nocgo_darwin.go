//go:build darwin && !cgo

package main

import "errors"

// newNativeTokenProvider on darwin without CGO cannot use the GSS-API framework.
func newNativeTokenProvider(proxy, spn string) (TokenProvider, error) {
	return nil, errors.New("native GSS-API requires CGO; rebuild with CGO_ENABLED=1 on macOS, or use -user for password-based authentication")
}
