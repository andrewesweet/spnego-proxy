package proxy

// forwarding_fidelity_test.go — acceptance tests for GitHub issue #125.
//
// Requirements covered:
//   C1  RFC 9110 §5.3    — same-name header order preserved
//   C2  RFC 9110 §5.1    — unrecognized headers forwarded
//   C3  RFC 9112 §3.2.2  — Host regenerated from request-target URI
//   C4  RFC 9112 §3.2.2  — path and query of request-target not modified
//   C5  RFC 9110 §11.7.2 — Authorization header passed through unmodified
//   C7  RFC 9110 §7.7    — content not transformed when no-transform is present
//   B3  RFC 9110 §11.7.2 — Proxy-Authenticate not forwarded to client
//
// Non-testable requirements (handled transparently by Go stdlib):
//   C6  RFC 9112 §5.2 — whitespace between header name and colon stripped
//       Go's http.ReadResponse + resp.Write always re-serializes headers
//       without such whitespace; no explicit test is possible via Go's HTTP
//       library since it never emits non-conformant wire bytes.
//   E3  RFC 9112 §5.2 — obs-fold (line folding) in response headers handled
//       Go's http.ReadResponse normalizes obs-fold during parsing; there is
//       no way to inject a raw folded header through Go's HTTP client layer.

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// C1 — RFC 9110 §5.3: Preserve header field order for same-name headers
// ---------------------------------------------------------------------------

// TestForwardingC1_SameNameHeaderOrderPreserved verifies that when a client
// sends multiple values for the same header name, the proxy forwards them to
// the upstream in the same order they were received.
//
// RFC 9110 §5.3 states that a recipient MUST NOT change the order of field
// values with the same field name. Go's http.ReadRequest stores multi-value
// headers as a slice preserving insertion order; req.WriteProxy emits them in
// that same order.
func TestForwardingC1_SameNameHeaderOrderPreserved(t *testing.T) {
	// Send the request as raw bytes to guarantee wire order of the three
	// X-Custom values. http.NewRequest+WriteProxy would canonicalize them
	// into a single comma-joined header, defeating the order assertion.
	raw := "GET http://example.com/c1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Custom: alpha\r\n" +
		"X-Custom: beta\r\n" +
		"X-Custom: gamma\r\n" +
		"\r\n"

	resp, reqs := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// http.ReadRequest on the upstream side also preserves insertion order
	// in the slice, so we can compare directly.
	got := reqs[0].Header["X-Custom"]
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("X-Custom header: want %v (len %d), got %v (len %d)", want, len(want), got, len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("X-Custom[%d]: want %q, got %q", i, want[i], got[i])
		}
	}
}

// ---------------------------------------------------------------------------
// C2 — RFC 9110 §5.1: Forward unrecognized headers
// ---------------------------------------------------------------------------

// TestForwardingC2_UnrecognizedHeadersForwarded verifies that the proxy
// forwards headers it does not recognise to the upstream unchanged.
//
// RFC 9110 §5.1 requires intermediaries to forward unrecognized header fields
// unless they are listed in the Connection header or are otherwise hop-by-hop.
func TestForwardingC2_UnrecognizedHeadersForwarded(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"X-Exotic-Widget": {"foo"},
	})

	assertHeaderPresent(t, upReq.Header, "X-Exotic-Widget", "foo")
}

// TestForwardingC2_MultipleUnrecognizedHeadersForwarded verifies that several
// unrecognized headers are all forwarded.
func TestForwardingC2_MultipleUnrecognizedHeadersForwarded(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"X-App-Request-Id": {"req-abc-123"},
		"X-Trace-Context":  {"traceparent=00-abc"},
		"X-Custom-Vendor":  {"v1.2.3"},
	})

	assertHeaderPresent(t, upReq.Header, "X-App-Request-Id", "req-abc-123")
	assertHeaderPresent(t, upReq.Header, "X-Trace-Context", "traceparent=00-abc")
	assertHeaderPresent(t, upReq.Header, "X-Custom-Vendor", "v1.2.3")
}

// ---------------------------------------------------------------------------
// C3 — RFC 9112 §3.2.2: Regenerate Host from request-target URI
// ---------------------------------------------------------------------------

// TestForwardingC3_HostRegeneratedFromRequestTarget verifies that the proxy
// uses the host from the absolute-form request-target URI as the Host header
// sent to the upstream, rather than any Host header supplied by the client.
//
// RFC 9112 §3.2.2: a proxy MUST use the host extracted from the request-target
// URI when forwarding. req.WriteProxy implements this: it sets Host from
// req.URL.Host, overriding req.Header["Host"] and req.Host.
func TestForwardingC3_HostRegeneratedFromRequestTarget(t *testing.T) {
	// Send a request whose Host header differs from the absolute-form URI.
	// The proxy must forward Host: example.com (from the URI), not other.com.
	raw := "GET http://example.com/c3 HTTP/1.1\r\n" +
		"Host: other.com\r\n" +
		"\r\n"

	resp, reqs := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// req.WriteProxy derives Host from req.URL, which ReadRequest populates
	// from the absolute-form request-target — not from the Host header field.
	if got := reqs[0].Host; got != "example.com" {
		t.Errorf("upstream Host: want %q, got %q", "example.com", got)
	}
}

// ---------------------------------------------------------------------------
// C4 — RFC 9112 §3.2.2: Do not modify path and query of request-target
// ---------------------------------------------------------------------------

// TestForwardingC4_PathAndQueryPreserved verifies that the proxy forwards the
// request to the upstream with the path and query string exactly as received.
//
// RFC 9112 §3.2.2 states that an intermediary MUST NOT modify the
// request-target path or query string. Go's req.WriteProxy writes req.URL
// unchanged, so path and query survive the proxy hop unmodified.
func TestForwardingC4_PathAndQueryPreserved(t *testing.T) {
	// The path contains segments and the query contains a percent-encoded space.
	targetPath := "/path/to/resource"
	targetQuery := "q=1&r=2%20"
	raw := "GET http://example.com" + targetPath + "?" + targetQuery + " HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n"

	resp, reqs := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	upReq := reqs[0]
	if upReq.URL.Path != targetPath {
		t.Errorf("upstream path: want %q, got %q", targetPath, upReq.URL.Path)
	}
	if upReq.URL.RawQuery != targetQuery {
		t.Errorf("upstream query: want %q, got %q", targetQuery, upReq.URL.RawQuery)
	}
}

// ---------------------------------------------------------------------------
// C5 — RFC 9110 §11.7.2: Pass Authorization header through unmodified
// ---------------------------------------------------------------------------

// TestForwardingC5_AuthorizationPassedThrough verifies that the proxy forwards
// the Authorization header unmodified.
//
// RFC 9110 §11.7.2 distinguishes Authorization (end-to-end credential for the
// origin server) from Proxy-Authorization (credential for the proxy). The
// proxy must not alter Authorization.
func TestForwardingC5_AuthorizationPassedThrough(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Authorization": {"Bearer token123"},
	})

	assertHeaderPresent(t, upReq.Header, "Authorization", "Bearer token123")
}

// TestForwardingC5_AuthorizationNotModifiedForDifferentSchemes verifies that
// Basic and other Authorization schemes are also forwarded intact.
func TestForwardingC5_AuthorizationNotModifiedForDifferentSchemes(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"Bearer", "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig"},
		{"Basic", "Basic dXNlcjpwYXNz"},
		{"NTLM", "NTLM TlRMTVNTUA"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upReq := proxyRoundTrip(t, http.Header{
				"Authorization": {tc.value},
			})
			assertHeaderPresent(t, upReq.Header, "Authorization", tc.value)
		})
	}
}

// ---------------------------------------------------------------------------
// C7 — RFC 9110 §7.7: Do not transform content when no-transform is present
// ---------------------------------------------------------------------------

// TestForwardingC7_NoTransformBodyPreserved verifies that the proxy relays the
// response body byte-for-byte when the upstream includes Cache-Control:
// no-transform.
//
// RFC 9110 §7.7: an intermediary MUST NOT transform a message body when the
// no-transform directive is present. The proxy currently performs no content
// transformation at all — it relays the body via resp.Write — so this
// invariant holds unconditionally. The test documents and enforces that
// contract.
func TestForwardingC7_NoTransformBodyPreserved(t *testing.T) {
	const body = "exact body content: binary\xFF\x00\x01"

	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Cache-Control":   {"no-transform"},
				headerContentType: {"application/octet-stream"},
			},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	})
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/c7", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// Cache-Control: no-transform must be forwarded to the client.
	assertHeaderPresent(t, resp.Header, "Cache-Control", "no-transform")

	// The body must be byte-for-byte identical to what the upstream sent.
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body: want %q (%d bytes), got %q (%d bytes)", body, len(body), got, len(got))
	}
}

// ---------------------------------------------------------------------------
// B3 — RFC 9110 §11.7.2: Proxy-Authenticate not forwarded to client
// ---------------------------------------------------------------------------

// TestForwardingB3_ProxyAuthenticateNotForwardedToClient verifies that the
// proxy strips the Proxy-Authenticate header from upstream responses before
// relaying them to the client.
//
// RFC 9110 §11.7.2: Proxy-Authenticate is a hop-by-hop header that applies
// only between the client and the next inbound proxy; it MUST NOT be
// forwarded downstream.
func TestForwardingB3_ProxyAuthenticateNotForwardedToClient(t *testing.T) {
	respFunc := func(_ *http.Request) *http.Response {
		return &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				headerProxyAuthenticate: {"Negotiate"},
			},
			Body:          http.NoBody,
			ContentLength: 0,
		}
	}

	raw := "GET http://example.com/b3 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"\r\n"

	resp, _ := proxyRawRoundTripWithUpstream(t, raw, respFunc)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	// B3: Proxy-Authenticate MUST NOT be forwarded to the client.
	assertHeaderAbsent(t, resp.Header, headerProxyAuthenticate)
}
