//go:build !darwin

package main

import "errors"

// newNativeTokenProvider on non-darwin platforms returns an error directing
// the user to provide explicit credentials for gokrb5 password-based auth.
func newNativeTokenProvider(_, _ string) (TokenProvider, error) {
	return nil, errors.New("native GSS-API is only available on macOS; use -user, -realm, -config, and -password-file for password-based authentication")
}
