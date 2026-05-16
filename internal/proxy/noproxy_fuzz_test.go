package proxy

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

// scopeNoProxyForDifferential filters a raw comma-separated no-proxy pattern
// list down to only the pattern forms whose match semantics are simple and
// unambiguous enough to re-derive independently from the documented NO_PROXY
// contract:
//
//   - leading-dot domain suffix (".corp.com")
//   - bare IP literal ("10.0.0.5", "::1")
//   - CIDR ("10.0.0.0/8", "fd00::/8")
//
// Excluded (still exercised by the no-panic check, never the differential):
//   - bare hostnames ("corp.com") — the de-facto NO_PROXY rule treats these as
//     suffix-capable; this matcher treats them as exact-only. By design.
//   - "*" and "*.corp.com" wildcards — not part of the portable contract.
//
// Returns the filtered list and whether any usable token survived.
func scopeNoProxyForDifferential(raw string) (string, bool) {
	var kept []string
	for tok := range strings.SplitSeq(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case strings.HasPrefix(tok, ".") && len(tok) > 1:
			kept = append(kept, tok)
		case isParsablePrefix(tok):
			kept = append(kept, tok)
		case isParsableAddr(tok):
			kept = append(kept, tok)
		}
	}
	return strings.Join(kept, ","), len(kept) > 0
}

func isParsableAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func isParsablePrefix(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// canonicalHost mirrors the documented host-extraction contract of
// NoProxyMatcher.Match ("host with or without a port", IPv6 brackets stripped,
// case-insensitive). The differential deliberately shares this extraction step
// with production: host extraction is NOT what is being differentially tested
// (the one extraction bug — bracketed IPv6 without a port — is already fixed
// and pinned by a regression seed). What IS independently re-derived is the
// rule classification + matching logic in referenceNoProxyBypass.
func canonicalHost(raw string) string {
	h := raw
	if x, _, err := net.SplitHostPort(h); err == nil {
		h = x
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return strings.ToLower(h)
}

// differentiableHost reports whether h (already canonicalised) is a well-formed
// IP literal or a clean DNS-charset name, so that the scoped rule grammar has
// unambiguous semantics. Pathological non-authorities are not asserted on.
func differentiableHost(h string) bool {
	if h == "" {
		return false
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for i := range len(h) {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// referenceNoProxyBypass is an independent, clean-room implementation of the
// NO_PROXY bypass decision for the scoped grammar only, given an
// already-canonical host. It does NOT reuse production's rule structs or
// classify chain: a divergence indicates a bug in noproxy.go's classification
// or matching, not a shared assumption.
//
// golang.org/x/net/http/httpproxy is deliberately NOT used as the oracle: it
// transitively imports golang.org/x/net/idna -> golang.org/x/text, which would
// add a new dependency to a security-sensitive proxy that otherwise has none.
func referenceNoProxyBypass(scoped, host string) bool {
	hostIP, _ := netip.ParseAddr(host)
	for tok := range strings.SplitSeq(scoped, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, ".") {
			suffix := strings.ToLower(tok)
			if host == suffix[1:] || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if pfx, err := netip.ParsePrefix(tok); err == nil {
			if hostIP.IsValid() && pfx.Contains(hostIP) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			if hostIP.IsValid() && hostIP == a {
				return true
			}
		}
	}
	return false
}

// FuzzNoProxyMatch is the highest-value fuzz target: a NoProxyMatcher.Match
// that returns true when it should return false causes a request to bypass
// the authenticated upstream proxy entirely (direct dial, no SPNEGO).
//
// Assertions:
//  1. Match never panics for ANY (patterns, host) input.
//  2. For the differentially-sound grammar and a well-formed host, the bypass
//     decision must agree with an independent re-derivation of the contract.
func FuzzNoProxyMatch(f *testing.F) {
	f.Add(".corp.com", "foo.corp.com")
	f.Add(".corp.com", "corp.com")
	f.Add("10.0.0.0/8", "10.1.2.3")
	f.Add("192.168.1.5", "192.168.1.5:443")
	f.Add("*", "anything")
	f.Add("*.corp.com", "a.corp.com")
	f.Add("", "x")
	f.Add(".com", "sub..com")
	f.Add("[::1", "[::1")
	f.Add("\x00", "\x00")
	f.Add(".x", "A.X")
	f.Add("1.2.3.0/24", "1.2.3.255")
	f.Add("corp.com.", "corp.com")
	f.Add("fd00::/8", "[fd00::1]:443")

	f.Fuzz(func(t *testing.T, rawPatterns, rawHost string) {
		// (1) Unconditional no-panic check on the full, unrestricted grammar.
		_, _ = NewNoProxyMatcher(rawPatterns).Match(rawHost)

		// (2) Sound differential, restricted to the congruent grammar and a
		// well-formed host.
		scoped, ok := scopeNoProxyForDifferential(rawPatterns)
		if !ok {
			return
		}
		host := canonicalHost(rawHost)
		if !differentiableHost(host) {
			return
		}

		ourBypass, _ := NewNoProxyMatcher(scoped).Match(rawHost)
		refBypass := referenceNoProxyBypass(scoped, host)

		if ourBypass != refBypass {
			t.Fatalf("noproxy bypass divergence: patterns=%q rawHost=%q host=%q ourBypass=%v refBypass=%v",
				scoped, rawHost, host, ourBypass, refBypass)
		}
	})
}
