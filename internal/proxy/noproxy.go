package proxy

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
	for _, pat := range SplitCSV(patterns) {
		rule := noProxyRule{raw: pat}
		if pat == "*" {
			rule.kind = ruleAll
		} else if prefix, err := netip.ParsePrefix(pat); err == nil {
			rule.kind = ruleCIDR
			rule.prefix = prefix
		} else if ip, err := netip.ParseAddr(pat); err == nil {
			rule.kind = ruleIP
			rule.ip = ip
		} else if suffix := strings.TrimPrefix(pat, "*"); strings.HasPrefix(suffix, ".") {
			rule.kind = ruleWildcard
			// Normalize to a leading-dot suffix regardless of whether the
			// caller wrote "*.corp.com" or ".corp.com".
			rule.suffix = strings.ToLower(suffix)
		} else {
			rule.kind = ruleHostname
			rule.host = strings.ToLower(pat)
		}
		m.rules = append(m.rules, rule)
	}
	return m
}

// matches reports whether this single rule covers the given host. hostIP is
// the host pre-parsed as an IP address (invalid when the host is a name); an
// invalid Addr never equals a rule IP nor is contained by a rule prefix, so no
// separate validity check is needed.
func (r noProxyRule) matches(host string, hostIP netip.Addr) bool {
	switch r.kind {
	case ruleAll:
		return true
	case ruleHostname:
		return host == r.host
	case ruleWildcard:
		// ".corp.com" matches the base domain "corp.com" and any subdomain.
		return host == r.suffix[1:] || strings.HasSuffix(host, r.suffix)
	case ruleIP:
		return hostIP == r.ip
	default: // ruleCIDR
		return r.prefix.Contains(hostIP)
	}
}

// Match reports whether host (with or without a port) is covered by any
// bypass pattern. On a match it also returns the original pattern string so
// callers can include it in debug log messages.
func (m *NoProxyMatcher) Match(host string) (matched bool, pattern string) {
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		// Bare bracketed IPv6 literal with no port must lose its brackets to
		// parse as an IP for IP/CIDR rule matching.
		host = stripIPv6Brackets(host)
	}
	host = strings.ToLower(host)

	// Try to parse as an IP once so we can use it for IP/CIDR rules.
	hostIP, _ := netip.ParseAddr(host)

	for _, rule := range m.rules {
		if rule.matches(host, hostIP) {
			return true, rule.raw
		}
	}
	return false, ""
}

// ResolveNoProxy returns the effective no-proxy value by applying the
// following precedence: explicit flag value > NO_PROXY env var > no_proxy
// env var. An empty string is returned when none of the sources is set.
func ResolveNoProxy(flagValue string) string {
	return cmp.Or(flagValue, os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
}
