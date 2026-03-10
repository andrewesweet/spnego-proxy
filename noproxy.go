package main

import (
	"net"
	"os"
	"strings"
)

type noProxyRuleKind int

const (
	ruleHostname noProxyRuleKind = iota
	ruleWildcard
	ruleIP
	ruleCIDR
)

type noProxyRule struct {
	raw     string     // original pattern (for debug logging)
	kind    noProxyRuleKind
	host    string     // lowercase exact hostname (ruleHostname)
	suffix  string     // lowercase ".corp.com" (ruleWildcard)
	ip      net.IP     // parsed IP (ruleIP)
	network *net.IPNet // parsed CIDR (ruleCIDR)
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
		if _, network, err := net.ParseCIDR(pat); err == nil {
			rule.kind = ruleCIDR
			rule.network = network
		} else if ip := net.ParseIP(pat); ip != nil {
			rule.kind = ruleIP
			rule.ip = ip
		} else if strings.HasPrefix(pat, "*.") || strings.HasPrefix(pat, ".") {
			rule.kind = ruleWildcard
			// Normalize to a leading-dot suffix regardless of whether the
			// caller wrote "*.corp.com" or ".corp.com".
			rule.suffix = strings.ToLower(strings.TrimPrefix(pat, "*"))
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
	}
	host = strings.ToLower(host)

	// Try to parse as an IP once so we can use it for IP/CIDR rules.
	hostIP := net.ParseIP(host)

	for _, rule := range m.rules {
		switch rule.kind {
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
			if hostIP != nil && hostIP.Equal(rule.ip) {
				return true, rule.raw
			}
		case ruleCIDR:
			if hostIP != nil && rule.network.Contains(hostIP) {
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
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("NO_PROXY"); v != "" {
		return v
	}
	return os.Getenv("no_proxy")
}
