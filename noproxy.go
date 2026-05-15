package main

import (
	"cmp"
	"net"
	"net/netip"
	"os"
	"strings"
)

type noProxyRuleKind int

const (
	ruleHostname noProxyRuleKind = iota
	ruleWildcard
	ruleIP
	ruleCIDR
	ruleAll // bare "*" — matches every host
)

type noProxyRule struct {
	raw    string // original pattern (for debug logging)
	kind   noProxyRuleKind
	host   string       // lowercase exact hostname (ruleHostname)
	suffix string       // lowercase ".corp.com" (ruleWildcard)
	ip     netip.Addr   // parsed IP (ruleIP)
	prefix netip.Prefix // parsed CIDR (ruleCIDR)
}

// NoProxyMatcher pre-parses a comma-separated list of no-proxy bypass patterns
// for fast matching at request time. Supported pattern forms are: exact
// hostnames, wildcard domains (*.x or .x), bare IP addresses, and CIDRs.
type NoProxyMatcher struct {
	rules []noProxyRule
}

// NewNoProxyMatcher parses a comma-separated string of bypass patterns and
// returns a ready-to-use NoProxyMatcher. Each pattern is classified at parse
// time so that Match performs no allocations on the hot path.
func NewNoProxyMatcher(patterns string) *NoProxyMatcher {
	m := &NoProxyMatcher{}
	for pat := range strings.SplitSeq(patterns, ",") {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		rule := noProxyRule{raw: pat}
		if pat == "*" {
			rule.kind = ruleAll
		} else if prefix, err := netip.ParsePrefix(pat); err == nil {
			rule.kind = ruleCIDR
			rule.prefix = prefix
		} else if ip, err := netip.ParseAddr(pat); err == nil {
			rule.kind = ruleIP
			rule.ip = ip
		} else if suffix, ok := strings.CutPrefix(pat, "*"); ok && strings.HasPrefix(suffix, ".") {
			rule.kind = ruleWildcard
			// Normalize to a leading-dot suffix regardless of whether the
			// caller wrote "*.corp.com" or ".corp.com".
			rule.suffix = strings.ToLower(suffix)
		} else if strings.HasPrefix(pat, ".") {
			rule.kind = ruleWildcard
			rule.suffix = strings.ToLower(pat)
		} else {
			rule.kind = ruleHostname
			rule.host = strings.ToLower(pat)
		}
		m.rules = append(m.rules, rule)
	}
	return m
}

// Match reports whether host (with or without a port) is covered by any
// bypass pattern. On a match it also returns the original pattern string so
// callers can include it in debug log messages.
func (m *NoProxyMatcher) Match(host string) (matched bool, pattern string) {
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		// Bare bracketed IPv6 literal with no port (e.g. "[::1]"): strip the
		// brackets so it parses as an IP for IP/CIDR rule matching, mirroring
		// sameHost in direct.go.
		host = host[1 : len(host)-1]
	}
	host = strings.ToLower(host)

	// Try to parse as an IP once so we can use it for IP/CIDR rules.
	hostIP, _ := netip.ParseAddr(host)

	for _, rule := range m.rules {
		switch rule.kind {
		case ruleAll:
			return true, rule.raw
		case ruleHostname:
			if host == rule.host {
				return true, rule.raw
			}
		case ruleWildcard:
			// Match the base domain itself (e.g. "corp.com" matches ".corp.com").
			base := rule.suffix[1:] // strip leading '.'
			if host == base {
				return true, rule.raw
			}
			// Match any subdomain (e.g. "foo.corp.com" matches ".corp.com").
			if strings.HasSuffix(host, rule.suffix) {
				return true, rule.raw
			}
		case ruleIP:
			if hostIP.IsValid() && hostIP == rule.ip {
				return true, rule.raw
			}
		case ruleCIDR:
			if hostIP.IsValid() && rule.prefix.Contains(hostIP) {
				return true, rule.raw
			}
		}
	}
	return false, ""
}

// resolveNoProxy returns the effective no-proxy value by applying the
// following precedence: explicit flag value > NO_PROXY env var > no_proxy
// env var. An empty string is returned when none of the sources is set.
func resolveNoProxy(flagValue string) string {
	return cmp.Or(flagValue, os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
}
