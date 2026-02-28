package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers specific to forwarding-header tests
// ---------------------------------------------------------------------------

// newProxyWithFwdConfig creates a ProxyUnderTest with the given ForwardingConfig.
// It wires up an upstream mock and returns both so the caller can inspect
// recorded requests.
func newProxyWithFwdConfig(t *testing.T, cfg ForwardingConfig) (*ProxyUnderTest, *MockUpstreamProxy) {
	t.Helper()
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	proxy.SetForwardingConfig(cfg)
	t.Cleanup(proxy.Close)
	return proxy, upstream
}

// sendGetAndRecord sends a single GET http://example.com/test through the
// proxy (optionally with extra headers) and returns the upstream's recorded
// request.
func sendGetAndRecord(t *testing.T, proxy *ProxyUnderTest, upstream *MockUpstreamProxy, extraHeaders http.Header) *RecordedRequest {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	for k, vs := range extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}
	return reqs[0]
}

// ---------------------------------------------------------------------------
// H1: Forwarded header (RFC 7239)
// ---------------------------------------------------------------------------

// TestForwardedDisabledByDefault verifies that the Forwarded header is NOT
// added when ForwardingConfig.ForwardedEnabled is false (the zero value).
func TestForwardedDisabledByDefault(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{})
	rec := sendGetAndRecord(t, proxy, upstream, nil)
	assertHeaderAbsent(t, rec.Header, "Forwarded")
}

// TestForwardedHeaderAdded verifies that when ForwardedEnabled is true the
// proxy injects a Forwarded header whose "for" token matches the RFC 7239
// §6.3 obfuscated identifier format (_xxxxxxxx).
func TestForwardedHeaderAdded(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{ForwardedEnabled: true})
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	fwd := rec.Header.Get("Forwarded")
	if fwd == "" {
		t.Fatal("expected Forwarded header, got none")
	}
	// Must contain an obfuscated "for" token: for=_<hex>
	obfRE := regexp.MustCompile(`for=_[0-9a-f]+`)
	if !obfRE.MatchString(fwd) {
		t.Errorf("Forwarded header %q: expected obfuscated for=_<hex> token", fwd)
	}
	// Must contain proto=http
	if !strings.Contains(fwd, "proto=http") {
		t.Errorf("Forwarded header %q: expected proto=http", fwd)
	}
}

// TestForwardedChaining verifies that when the client sends a pre-existing
// Forwarded header, the proxy appends its entry rather than replacing it.
func TestForwardedChaining(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{ForwardedEnabled: true})

	existing := "for=192.0.2.60;proto=http;by=203.0.113.43"
	rec := sendGetAndRecord(t, proxy, upstream, http.Header{"Forwarded": {existing}})

	fwd := rec.Header.Get("Forwarded")
	if fwd == "" {
		t.Fatal("expected Forwarded header, got none")
	}
	// Original value must be preserved at the start.
	if !strings.HasPrefix(fwd, existing) {
		t.Errorf("Forwarded header %q: expected to start with existing value %q", fwd, existing)
	}
	// Must contain a comma-separated new entry.
	if !strings.Contains(fwd, ", ") {
		t.Errorf("Forwarded header %q: expected comma-separated chaining", fwd)
	}
	// The new entry must include an obfuscated for token.
	obfRE := regexp.MustCompile(`for=_[0-9a-f]+`)
	if !obfRE.MatchString(fwd) {
		t.Errorf("Forwarded header %q: expected obfuscated for=_<hex> in appended entry", fwd)
	}
}

// TestForwardedObfuscatedFormat verifies the exact token format: _<8 lowercase
// hex chars>.  generateObfuscatedID uses 4 random bytes → 8 hex chars.
func TestForwardedObfuscatedFormat(t *testing.T) {
	for i := 0; i < 10; i++ {
		id := generateObfuscatedID()
		if !strings.HasPrefix(id, "_") {
			t.Errorf("generateObfuscatedID() = %q: missing underscore prefix", id)
		}
		hex := id[1:]
		if len(hex) != 8 {
			t.Errorf("generateObfuscatedID() = %q: hex part length want 8, got %d", id, len(hex))
		}
		for _, c := range hex {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("generateObfuscatedID() = %q: non-lowercase-hex char %q", id, c)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// H2: X-Forwarded-For
// ---------------------------------------------------------------------------

// TestXForwardedForDisabledByDefault verifies that X-Forwarded-For is NOT
// added when ForwardingConfig.XForwardedForEnabled is false (the zero value).
func TestXForwardedForDisabledByDefault(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{})
	rec := sendGetAndRecord(t, proxy, upstream, nil)
	assertHeaderAbsent(t, rec.Header, "X-Forwarded-For")
}

// TestXForwardedForAdded verifies that when XForwardedForEnabled is true, the
// proxy adds an X-Forwarded-For header containing the client IP (127.0.0.1).
func TestXForwardedForAdded(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	xff := rec.Header.Get("X-Forwarded-For")
	if xff == "" {
		t.Fatal("expected X-Forwarded-For header, got none")
	}
	// The proxy test client connects from 127.0.0.1.
	if !strings.Contains(xff, "127.0.0.1") {
		t.Errorf("X-Forwarded-For %q: expected 127.0.0.1 to be present", xff)
	}
}

// TestXForwardedForChaining verifies that an existing X-Forwarded-For value
// is preserved and the new IP is appended.
func TestXForwardedForChaining(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})

	existing := "10.0.0.1"
	rec := sendGetAndRecord(t, proxy, upstream, http.Header{"X-Forwarded-For": {existing}})

	xff := rec.Header.Get("X-Forwarded-For")
	if !strings.HasPrefix(xff, existing) {
		t.Errorf("X-Forwarded-For %q: expected to start with existing value %q", xff, existing)
	}
	if !strings.Contains(xff, ", 127.0.0.1") {
		t.Errorf("X-Forwarded-For %q: expected appended 127.0.0.1", xff)
	}
}

// ---------------------------------------------------------------------------
// H3: X-Forwarded-Proto
// ---------------------------------------------------------------------------

// TestXForwardedProtoAddedWithXFF verifies that X-Forwarded-Proto is set to
// "http" when XForwardedForEnabled is true and the header is absent.
func TestXForwardedProtoAddedWithXFF(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	if got := rec.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto: want %q, got %q", "http", got)
	}
}

// TestXForwardedProtoNotOverwritten verifies that a pre-existing
// X-Forwarded-Proto value is not replaced.
func TestXForwardedProtoNotOverwritten(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})

	rec := sendGetAndRecord(t, proxy, upstream, http.Header{"X-Forwarded-Proto": {"https"}})

	if got := rec.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto: want existing %q preserved, got %q", "https", got)
	}
}

// TestXForwardedProtoAbsentWhenDisabled verifies that X-Forwarded-Proto is
// not injected when XForwardedForEnabled is false.
func TestXForwardedProtoAbsentWhenDisabled(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{})
	rec := sendGetAndRecord(t, proxy, upstream, nil)
	assertHeaderAbsent(t, rec.Header, "X-Forwarded-Proto")
}

// ---------------------------------------------------------------------------
// H4: X-Forwarded-Host
// ---------------------------------------------------------------------------

// TestXForwardedHostAddedWithXFF verifies that X-Forwarded-Host is set to the
// request Host when XForwardedForEnabled is true and the header is absent.
func TestXForwardedHostAddedWithXFF(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	if got := rec.Header.Get("X-Forwarded-Host"); got != "example.com" {
		t.Errorf("X-Forwarded-Host: want %q, got %q", "example.com", got)
	}
}

// TestXForwardedHostNotOverwritten verifies that a pre-existing
// X-Forwarded-Host value is not replaced.
func TestXForwardedHostNotOverwritten(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{XForwardedForEnabled: true})

	rec := sendGetAndRecord(t, proxy, upstream, http.Header{"X-Forwarded-Host": {"original.example.com"}})

	if got := rec.Header.Get("X-Forwarded-Host"); got != "original.example.com" {
		t.Errorf("X-Forwarded-Host: want existing %q preserved, got %q", "original.example.com", got)
	}
}

// TestXForwardedHostAbsentWhenDisabled verifies that X-Forwarded-Host is not
// injected when XForwardedForEnabled is false.
func TestXForwardedHostAbsentWhenDisabled(t *testing.T) {
	proxy, upstream := newProxyWithFwdConfig(t, ForwardingConfig{})
	rec := sendGetAndRecord(t, proxy, upstream, nil)
	assertHeaderAbsent(t, rec.Header, "X-Forwarded-Host")
}

// ---------------------------------------------------------------------------
// Combined: both Forwarded and X-Forwarded-For enabled simultaneously
// ---------------------------------------------------------------------------

// TestBothForwardingHeadersEnabled verifies that both header families can be
// enabled at the same time without interfering with each other.
func TestBothForwardingHeadersEnabled(t *testing.T) {
	cfg := ForwardingConfig{
		ForwardedEnabled:     true,
		XForwardedForEnabled: true,
	}
	proxy, upstream := newProxyWithFwdConfig(t, cfg)
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	if fwd := rec.Header.Get("Forwarded"); fwd == "" {
		t.Error("expected Forwarded header, got none")
	}
	if xff := rec.Header.Get("X-Forwarded-For"); xff == "" {
		t.Error("expected X-Forwarded-For header, got none")
	}
	if xfp := rec.Header.Get("X-Forwarded-Proto"); xfp != "http" {
		t.Errorf("X-Forwarded-Proto: want %q, got %q", "http", xfp)
	}
	if xfh := rec.Header.Get("X-Forwarded-Host"); xfh != "example.com" {
		t.Errorf("X-Forwarded-Host: want %q, got %q", "example.com", xfh)
	}
}

// ---------------------------------------------------------------------------
// generateObfuscatedID unit tests
// ---------------------------------------------------------------------------

// TestGenerateObfuscatedIDUniqueness verifies that repeated calls produce
// different values (probabilistic; failure probability is 1/2^32 per pair).
func TestGenerateObfuscatedIDUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		id := generateObfuscatedID()
		if seen[id] {
			t.Errorf("generateObfuscatedID() produced duplicate %q in 20 iterations", id)
		}
		seen[id] = true
	}
}

// TestGenerateObfuscatedIDRFC7239Compliance verifies the format matches
// RFC 7239 §6.3 obfnode production: "_" 1*( ALPHA / DIGIT / "." / "_" / "-")
func TestGenerateObfuscatedIDRFC7239Compliance(t *testing.T) {
	re := regexp.MustCompile(`^_[A-Za-z0-9._-]+$`)
	for i := 0; i < 20; i++ {
		id := generateObfuscatedID()
		if !re.MatchString(id) {
			t.Errorf("generateObfuscatedID() = %q does not match RFC 7239 obfnode pattern", id)
		}
	}
}

// ---------------------------------------------------------------------------
// IPv6 quoting (RFC 7239 §4)
// ---------------------------------------------------------------------------

// TestForwardedIPv6QuotingInForValue verifies that IPv6 addresses used in
// the for= parameter of the Forwarded header are properly quoted as per
// RFC 7239 §4: for="[IPv6Address]".
//
// This test exercises the formatForwardedFor helper directly since the
// proxy's obfuscated-identifier path never produces raw IPv6 addresses.
func TestForwardedIPv6QuotingInForValue(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{
			name: "IPv4 unquoted",
			ip:   "192.0.2.1",
			want: "192.0.2.1",
		},
		{
			name: "IPv6 quoted with brackets",
			ip:   "2001:db8::1",
			want: `"[2001:db8::1]"`,
		},
		{
			name: "obfuscated token unchanged",
			ip:   "_abc123",
			want: "_abc123",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatForwardedFor(tc.ip)
			if got != tc.want {
				t.Errorf("formatForwardedFor(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate that forwarding headers do not interfere with existing headers
// ---------------------------------------------------------------------------

// TestForwardingHeadersDoNotAffectVia confirms that the existing Via header
// machinery is unaffected when forwarding headers are enabled.
func TestForwardingHeadersDoNotAffectVia(t *testing.T) {
	cfg := ForwardingConfig{
		ForwardedEnabled:     true,
		XForwardedForEnabled: true,
	}
	proxy, upstream := newProxyWithFwdConfig(t, cfg)
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	via := rec.Header.Get("Via")
	if via == "" {
		t.Error("Via header absent when forwarding headers enabled")
	}
	if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via header %q does not contain testPseudonym %q", via, testPseudonym)
	}
}

// TestForwardingHeadersDoNotAffectProxyAuthorization confirms that
// Proxy-Authorization is still injected when forwarding headers are enabled.
func TestForwardingHeadersDoNotAffectProxyAuthorization(t *testing.T) {
	cfg := ForwardingConfig{
		ForwardedEnabled:     true,
		XForwardedForEnabled: true,
	}
	proxy, upstream := newProxyWithFwdConfig(t, cfg)
	rec := sendGetAndRecord(t, proxy, upstream, nil)

	assertHeaderPresent(t, rec.Header, "Proxy-Authorization", fmt.Sprintf("Negotiate %s", proxy.Provider.token))
}
