package main

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
)

var logLevel = new(slog.LevelVar) // default Info

// connectPortWildcard is the sentinel value meaning "allow all ports" in the
// -connect-ports flag and connectPortAllowed logic.
const connectPortWildcard = "*"

// copyBufPool pools 32 KiB buffers used by idleCopy to avoid a heap
// allocation on every tunnel connection.
var copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// normalizeSPN converts an explicit SPN between GSS-API hostbased format
// (service@host) and Kerberos principal format (service/host) so the user
// need not know which backend is active. targetSep is the separator the
// active backend expects ('@' for GSS-API, '/' for gokrb5); alternateSep
// is the other backend's separator.
func normalizeSPN(spn string, targetSep, alternateSep byte) string {
	if strings.IndexByte(spn, targetSep) >= 0 {
		return spn // already contains the target separator
	}
	if i := strings.IndexByte(spn, alternateSep); i >= 0 {
		return spn[:i] + string(targetSep) + spn[i+1:]
	}
	return spn // no recognized separator; return as-is
}

// ForwardingConfig controls which forwarding headers the proxy injects into
// outbound requests.
//
// Both fields default to false (disabled) to preserve the existing behaviour
// where no forwarding headers are added. Operators opt in via CLI flags.
type ForwardingConfig struct {
	// ForwardedEnabled enables the RFC 7239 Forwarded header (H1).
	// The header uses an obfuscated identifier for the client address.
	ForwardedEnabled bool

	// XForwardedForEnabled enables the de-facto X-Forwarded-For header (H2)
	// and, when the headers are absent, also sets X-Forwarded-Proto (H3) and
	// X-Forwarded-Host (H4).
	XForwardedForEnabled bool
}

// ProxyConfig groups the non-connection parameters for handleClient.
type ProxyConfig struct {
	Upstream     string
	Provider     TokenProvider
	Pseudonym    string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	KeepAlive    time.Duration
	IdleTimeout  time.Duration
	ConnectPorts []string
	AllowedIPs   []*net.IPNet
	NoProxy      *NoProxyMatcher
	Forwarding   ForwardingConfig
	UpstreamTLS  UpstreamTLSConfig
}

// TokenProvider acquires SPNEGO tokens for proxy authentication.
type TokenProvider interface {
	// GetToken returns a base64-encoded SPNEGO token.
	GetToken() (string, error)
	// Close cleans up any resources.
	Close() error
}

// splitCSV splits a comma-separated string into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseAllowList parses a comma-separated string of IPs and CIDR ranges
// into a slice of *net.IPNet entries for use with ipAllowed.
func parseAllowList(s string) ([]*net.IPNet, error) {
	if s == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, entry := range splitCSV(s) {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %q", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets, nil
}

// ipAllowed returns true if the given IP is in the allow list.
// A nil or empty allow list permits all IPs.
func ipAllowed(ip net.IP, allowList []*net.IPNet) bool {
	if len(allowList) == 0 {
		return true
	}
	for _, n := range allowList {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// connectPortAllowed reports whether port is in the allowed set.
// An empty allowedPorts slice means all ports are permitted.
func connectPortAllowed(port string, allowedPorts []string) bool {
	return len(allowedPorts) == 0 || slices.ContainsFunc(allowedPorts, func(p string) bool { return p == connectPortWildcard || p == port })
}
