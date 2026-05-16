package proxy

import (
	"testing"
)

// ----------------------------------------------------------------------------
// NoProxyMatcher tests
// ----------------------------------------------------------------------------

func TestNoProxyMatcher_Empty(t *testing.T) {
	m := NewNoProxyMatcher("")
	hosts := []string{"example.com", "192.168.1.1", "10.0.0.1", "foo.bar.com"}
	for _, h := range hosts {
		t.Run(h, func(t *testing.T) {
			if matched, pat := m.Match(h); matched {
				t.Errorf("empty matcher matched %q with pattern %q", h, pat)
			}
		})
	}
}

func TestNoProxyMatcher_Hostname(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
		wantPat string
	}{
		{"exact match", "example.com", "example.com", true, "example.com"},
		{"case insensitive upper input", "example.com", "EXAMPLE.COM", true, "example.com"},
		{"case insensitive mixed pattern", "EXAMPLE.COM", "example.com", true, "EXAMPLE.COM"},
		{"with port", "example.com", "example.com:8080", true, "example.com"},
		{"no match different host", "example.com", "other.com", false, ""},
		{"no match subdomain", "example.com", "sub.example.com", false, ""},
		{"no match prefix", "example.com", "notexample.com", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewNoProxyMatcher(tc.pattern)
			matched, pat := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) matched=%v, want %v", tc.host, matched, tc.want)
			}
			if pat != tc.wantPat {
				t.Errorf("Match(%q) pattern=%q, want %q", tc.host, pat, tc.wantPat)
			}
		})
	}
}

func TestNoProxyMatcher_Wildcard_StarDot(t *testing.T) {
	m := NewNoProxyMatcher("*.corp.com")
	tests := []struct {
		host string
		want bool
	}{
		{"foo.corp.com", true},
		{"bar.corp.com", true},
		{"corp.com", true},         // base domain itself must also match
		{"CORP.COM", true},         // case insensitive
		{"foo.corp.com:443", true}, // with port
		{"nested.foo.corp.com", true},
		{"notcorp.com", false},
		{"corp.com.evil.com", false},
		{"othercorp.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			matched, pat := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v (pat=%q), want %v", tc.host, matched, pat, tc.want)
			}
			if tc.want && pat != "*.corp.com" {
				t.Errorf("Match(%q) pattern = %q, want %q", tc.host, pat, "*.corp.com")
			}
		})
	}
}

func TestNoProxyMatcher_Wildcard_LeadingDot(t *testing.T) {
	m := NewNoProxyMatcher(".corp.com")
	tests := []struct {
		host string
		want bool
	}{
		{"foo.corp.com", true},
		{"bar.corp.com", true},
		{"corp.com", true}, // base domain itself must also match
		{"nested.foo.corp.com", true},
		{"corp.com:8080", true},
		{"notcorp.com", false},
		{"othercorp.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			matched, pat := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v (pat=%q), want %v", tc.host, matched, pat, tc.want)
			}
			if tc.want && pat != ".corp.com" {
				t.Errorf("Match(%q) pattern = %q, want %q", tc.host, pat, ".corp.com")
			}
		})
	}
}

func TestNoProxyMatcher_IP(t *testing.T) {
	m := NewNoProxyMatcher("192.168.1.100,::1")
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"IPv4 exact", "192.168.1.100", true},
		{"IPv4 with port", "192.168.1.100:8080", true},
		{"IPv4 different", "192.168.1.101", false},
		{"IPv6 loopback", "::1", true},
		{"IPv6 with brackets and port", "[::1]:443", true},
		{"IPv6 different", "::2", false},
		{"hostname not matched by IP rule", "example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, _ := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.host, matched, tc.want)
			}
		})
	}
}

func TestNoProxyMatcher_CIDR(t *testing.T) {
	m := NewNoProxyMatcher("10.0.0.0/8,192.168.0.0/16")
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"10.x in range", "10.1.2.3", true},
		{"10.0.0.0 network address", "10.0.0.0", true},
		{"10.255.255.255 broadcast", "10.255.255.255", true},
		{"10.x with port", "10.42.0.1:3128", true},
		{"192.168.x in range", "192.168.100.200", true},
		{"192.168.0.0 with port", "192.168.0.0:80", true},
		{"172.16.x out of range", "172.16.0.1", false},
		{"11.x out of 10/8", "11.0.0.1", false},
		{"hostname not matched", "example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, _ := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.host, matched, tc.want)
			}
		})
	}
}

func TestNoProxyMatcher_MultiplePatterns(t *testing.T) {
	m := NewNoProxyMatcher("localhost,127.0.0.1,*.internal,10.0.0.0/8")
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"localhost:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:9000", true},
		{"foo.internal", true},
		{"internal", true},
		{"10.5.5.5", true},
		{"example.com", false},
		{"192.168.1.1", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			matched, _ := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.host, matched, tc.want)
			}
		})
	}
}

func TestNoProxyMatcher_WhitespaceTrimming(t *testing.T) {
	m := NewNoProxyMatcher("  example.com , *.corp.com ,  127.0.0.1  ")
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"foo.corp.com", true},
		{"corp.com", true},
		{"127.0.0.1", true},
		{"other.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			matched, _ := m.Match(tc.host)
			if matched != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.host, matched, tc.want)
			}
		})
	}
}

func TestNoProxyMatcher_ReturnedPatternMatchesOriginalInput(t *testing.T) {
	// Verify that the raw original pattern (before lowercasing) is returned.
	tests := []struct {
		pattern string
		host    string
		wantPat string
	}{
		{"EXAMPLE.COM", "example.com", "EXAMPLE.COM"},
		{"*.CORP.COM", "foo.corp.com", "*.CORP.COM"},
		{".CORP.COM", "corp.com", ".CORP.COM"},
		{"192.168.1.1", "192.168.1.1", "192.168.1.1"},
		{"10.0.0.0/8", "10.5.6.7", "10.0.0.0/8"},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			m := NewNoProxyMatcher(tc.pattern)
			matched, pat := m.Match(tc.host)
			if !matched {
				t.Fatalf("expected match for host %q against pattern %q", tc.host, tc.pattern)
			}
			if pat != tc.wantPat {
				t.Errorf("returned pattern = %q, want %q", pat, tc.wantPat)
			}
		})
	}
}

func TestNoProxyMatcher_BareStarMatchesAll(t *testing.T) {
	m := NewNoProxyMatcher("*")
	tests := []struct {
		host string
	}{
		{"example.com"},
		{"10.0.0.1"},
		{"localhost"},
		{"foo.bar.baz:8080"},
		{"[::1]:443"},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			matched, pat := m.Match(tc.host)
			if !matched {
				t.Errorf("bare * should match %q", tc.host)
			}
			if pat != "*" {
				t.Errorf("pattern = %q, want %q", pat, "*")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// resolveNoProxy tests
// ----------------------------------------------------------------------------

func TestResolveNoProxy_FlagTakesPrecedence(t *testing.T) {
	t.Setenv("NO_PROXY", "env-no-proxy.com")
	t.Setenv("no_proxy", "env-noproxy-lower.com")
	got := resolveNoProxy("flag-value.com")
	if got != "flag-value.com" {
		t.Errorf("resolveNoProxy = %q, want %q", got, "flag-value.com")
	}
}

func TestResolveNoProxy_EmptyFlagFallsToNO_PROXY(t *testing.T) {
	t.Setenv("NO_PROXY", "from-NO_PROXY.com")
	t.Setenv("no_proxy", "from-no_proxy.com")
	got := resolveNoProxy("")
	if got != "from-NO_PROXY.com" {
		t.Errorf("resolveNoProxy = %q, want %q", got, "from-NO_PROXY.com")
	}
}

func TestResolveNoProxy_NO_PROXYEmptyFallsToLowercase(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "from-no_proxy.com")
	got := resolveNoProxy("")
	if got != "from-no_proxy.com" {
		t.Errorf("resolveNoProxy = %q, want %q", got, "from-no_proxy.com")
	}
}

func TestResolveNoProxy_AllEmptyReturnsEmpty(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	got := resolveNoProxy("")
	if got != "" {
		t.Errorf("resolveNoProxy = %q, want empty string", got)
	}
}

func TestResolveNoProxy_OnlyFlagSet(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	got := resolveNoProxy("only-flag.com")
	if got != "only-flag.com" {
		t.Errorf("resolveNoProxy = %q, want %q", got, "only-flag.com")
	}
}
