package main

import (
	"net"
	"net/netip"
	"slices"
	"strings"
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

// ipAllowRef is an independent netip-based re-derivation of the allowlist
// membership decision under the ratified Option A policy (RFC 4291): the
// client address is Unmap-ed so an IPv4-in-IPv6 form is the same identity as
// the bare IPv4 address.
//
// To keep the oracle sound it is scoped to a grammar where net and netip agree
// unambiguously: allowlist tokens must be pure (non IPv4-in-IPv6) IPs or CIDRs.
// A mapped form on the *client* side is fully exercised — that is the
// security-critical attacker-controlled input. applicable=false means the
// input is outside the sound differential grammar and no claim is made.
func ipAllowRef(clientHost, allowCSV string) (decision bool, applicable bool) {
	ca, err := netip.ParseAddr(clientHost)
	if err != nil {
		return false, false
	}
	ca = ca.Unmap()

	var prefixes []netip.Prefix
	for _, tok := range splitCSV(allowCSV) {
		if strings.Contains(tok, "/") {
			p, e := netip.ParsePrefix(tok)
			if e != nil || p.Addr().Is4In6() {
				return false, false
			}
			prefixes = append(prefixes, p.Masked())
		} else {
			a, e := netip.ParseAddr(tok)
			if e != nil || a.Is4In6() {
				return false, false
			}
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	if len(prefixes) == 0 {
		return false, false
	}
	for _, p := range prefixes {
		if p.Contains(ca) {
			return true, true
		}
	}
	return false, true
}

// FuzzIPAllowlistChain mirrors the production client-IP gate
// (extractHost(RemoteAddr) -> net.ParseIP -> ipAllowed over parseAllowList)
// and asserts the membership decision matches an independent netip
// re-derivation under Option A. A divergence is a real allowlist
// bypass/escape (an attacker IP wrongly admitted, or a permitted client
// wrongly denied).
func FuzzIPAllowlistChain(f *testing.F) {
	f.Add("1.2.3.4:5", "1.2.3.0/24")
	f.Add("::ffff:127.0.0.1", "127.0.0.0/8")
	f.Add("[::ffff:1.2.3.4]:80", "1.2.3.4/32")
	f.Add("10.0.0.1", "10.0.0.0/8")
	f.Add("not-an-ip", "0.0.0.0/0")
	f.Add("[fe80::1%eth0]:80", "fe80::/10")
	f.Add("", "1.2.3.4")
	f.Add("192.168.1.5:9", "192.168.1.5")
	f.Add("2001:db8::1", "2001:db8::/32")

	f.Fuzz(func(t *testing.T, rawRemote, allowCSV string) {
		clientHost := extractHost(rawRemote)

		// (1) Production chain never panics.
		nets, perr := parseAllowList(allowCSV)
		prodIP := net.ParseIP(clientHost)
		prodDecision := ipAllowed(prodIP, nets)

		// (2) Sound differential, gated on both sides fully parsing.
		if perr != nil || prodIP == nil {
			return
		}
		refDecision, applicable := ipAllowRef(clientHost, allowCSV)
		if !applicable {
			return
		}
		if prodDecision != refDecision {
			t.Fatalf("allowlist decision divergence: clientHost=%q allow=%q prod=%v ref=%v",
				clientHost, allowCSV, prodDecision, refDecision)
		}
	})
}
