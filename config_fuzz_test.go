package main

import (
	"net"
	"slices"
	"testing"
)

// FuzzConnectPortChain mirrors the production CONNECT port-gate chain
// (prepareForwardRequest, forward.go:40-49): the client-controlled authority
// is split by net.SplitHostPort, defaulting to "443" on error, and the port is
// checked against the configured allow set.
//
// The oracle is the security-direction implication only — connectPortAllowed
// does a pure byte-wise string compare (config.go:135), so a numeric/uint16
// equivalence oracle would be unsound (it would false-positive on "0443",
// "+443", etc., which the function correctly rejects). The sound, security-
// relevant property is: an accepted port under a non-empty, non-wildcard allow
// set must be byte-identical to a configured entry. No input may smuggle a
// port past the gate that is not literally listed.
func FuzzConnectPortChain(f *testing.F) {
	f.Add("host:443", "443")
	f.Add("host", "443")
	f.Add("host:0443", "443")
	f.Add("host:443\x00", "443")
	f.Add("[::1]:8443", "8443, *")
	f.Add("h:443 ", "443")
	f.Add("h:+443", "443")
	f.Add("h:0x1bb", "443")
	f.Add("[::1", "443")
	f.Add("h:99999", "443")
	f.Add("h:443:evil", "443")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, authority, allowedCSV string) {
		allowed := splitCSV(allowedCSV)

		_, port, err := net.SplitHostPort(authority)
		if err != nil {
			port = "443"
		}

		accepted := connectPortAllowed(port, allowed)

		if accepted && len(allowed) > 0 && !slices.Contains(allowed, connectPortWildcard) {
			if !slices.Contains(allowed, port) {
				t.Fatalf("port smuggled past gate: authority=%q port=%q allowed=%v accepted=true but port not listed",
					authority, port, allowed)
			}
		}
	})
}
