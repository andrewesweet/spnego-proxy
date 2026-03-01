package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// B1 — RFC 9110 §7.6.1: Connection header and named headers removed
// ---------------------------------------------------------------------------

func TestB1_RFC9110_ConnectionHeaderAndNamedHeadersRemoved(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Connection":   {"X-Custom-Hop"},
		"X-Custom-Hop": {"secret"},
		"X-Legitimate": {"keep-me"},
	})

	assertHeaderAbsent(t, upReq.Header, "Connection")
	assertHeaderAbsent(t, upReq.Header, "X-Custom-Hop")
	assertHeaderPresent(t, upReq.Header, "X-Legitimate", "keep-me")
}

func TestB1_RFC9110_ConnectionHeaderMultipleValues(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Connection":   {"X-Hop-A, X-Hop-B"},
		"X-Hop-A":      {"a-value"},
		"X-Hop-B":      {"b-value"},
		"X-End-To-End": {"preserved"},
	})

	assertHeaderAbsent(t, upReq.Header, "Connection")
	assertHeaderAbsent(t, upReq.Header, "X-Hop-A")
	assertHeaderAbsent(t, upReq.Header, "X-Hop-B")
	assertHeaderPresent(t, upReq.Header, "X-End-To-End", "preserved")
}

// ---------------------------------------------------------------------------
// Well-known hop-by-hop headers stripped (table-driven)
// ---------------------------------------------------------------------------

func TestHopByHop_WellKnownHeadersStripped(t *testing.T) {
	tests := []struct {
		name   string
		header string
		value  string
	}{
		{"B1/Keep-Alive", "Keep-Alive", "timeout=5"},
		{"K3/Proxy-Connection", "Proxy-Connection", "keep-alive"},
		{"J2/Upgrade", "Upgrade", "websocket"},
		{"B1/TE", "TE", "trailers"},
		{"B1/Trailer", "Trailer", "X-Checksum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upReq := proxyRoundTrip(t, http.Header{tc.header: {tc.value}})
			assertHeaderAbsent(t, upReq.Header, tc.header)
		})
	}
}

// ---------------------------------------------------------------------------
// B2 — RFC 9110 §11.7.1: Client Proxy-Authorization consumed
// ---------------------------------------------------------------------------

func TestB2_RFC9110_ClientProxyAuthorizationConsumed(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Proxy-Authorization": {"Basic abc123"},
	})

	// The proxy must inject its own Negotiate token, NOT forward the
	// client's Basic credential.
	pa := upReq.Header.Get("Proxy-Authorization")
	if pa == "Basic abc123" {
		t.Error("client's Proxy-Authorization was forwarded; expected proxy's own Negotiate token")
	}
	if !strings.HasPrefix(pa, "Negotiate ") {
		t.Errorf("expected Proxy-Authorization to start with 'Negotiate ', got %q", pa)
	}
}

// ---------------------------------------------------------------------------
// E1 — RFC 9112 §6.1: TE + CL conflict resolved by removing CL
// ---------------------------------------------------------------------------

func TestE1_RFC9112_TEAndCLConflictRemovesCL(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Build the request manually to include both Transfer-Encoding and
	// Content-Length, which Go's http.NewRequest would normally suppress.
	raw := "GET http://example.com/e1 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Length: 100\r\n" +
		"\r\n" +
		"0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// Content-Length must be absent.
	assertHeaderAbsent(t, reqs[0].Header, "Content-Length")

	// Transfer-Encoding (chunked framing) must still be present so the
	// upstream can correctly decode the body.
	if len(reqs[0].TransferEncoding) == 0 || reqs[0].TransferEncoding[0] != "chunked" {
		t.Errorf("expected Transfer-Encoding: chunked to be preserved, got %v", reqs[0].TransferEncoding)
	}
}

// ---------------------------------------------------------------------------
// E2 — RFC 9112 §6.1: Invalid Content-Length in upstream response → 502
// ---------------------------------------------------------------------------

func TestE2_RFC9112_InvalidContentLengthInResponse(t *testing.T) {
	// Create a raw upstream that sends an invalid Content-Length.
	rawUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = rawUpstream.Close() }()

	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := rawUpstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read the request first.
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		// Write a response with an invalid Content-Length.
		resp := "HTTP/1.1 200 OK\r\n" +
			"Content-Length: not-a-number\r\n" +
			"\r\n" +
			"body"
		_, _ = conn.Write([]byte(resp))
	})
	t.Cleanup(wg.Wait)

	proxy := NewProxyUnderTest(t, rawUpstream.Addr().String())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/e2", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusBadGateway)
	if ps := resp.Header.Get("Proxy-Status"); !strings.Contains(ps, "http_protocol_error") {
		t.Errorf("expected Proxy-Status to contain 'http_protocol_error', got %q", ps)
	}
}

// ---------------------------------------------------------------------------
// E2 — RFC 9112 §6.1: Valid response Content-Length passes through
// ---------------------------------------------------------------------------

func TestE2_RFC9112_ValidContentLengthInResponsePassesThrough(t *testing.T) {
	const body = "hello"
	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	})
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/e2-valid", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusOK)
	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != body {
		t.Errorf("body: want %q, got %q", body, string(respBody))
	}
}

// ---------------------------------------------------------------------------
// E1 — RFC 9112 §6.1: Response-side TE + CL conflict → CL removed
// ---------------------------------------------------------------------------

func TestE1_RFC9112_ResponseTEAndCLConflictRemovesCL(t *testing.T) {
	// A raw upstream sends a response with both Transfer-Encoding: chunked
	// and Content-Length. The proxy must strip Content-Length before
	// relaying to the client per RFC 9112 §6.1.
	rawUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = rawUpstream.Close() }()

	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := rawUpstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		// Both Transfer-Encoding and Content-Length — the proxy must
		// strip Content-Length and use chunked framing.
		resp := "HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Content-Length: 5\r\n" +
			"\r\n" +
			"5\r\nhello\r\n0\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
	})
	t.Cleanup(wg.Wait)

	proxy := NewProxyUnderTest(t, rawUpstream.Addr().String())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/e1-resp", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusOK)
	assertHeaderAbsent(t, resp.Header, "Content-Length")

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Errorf("body: want %q, got %q", "hello", string(body))
	}
}

// ---------------------------------------------------------------------------
// Unit tests for sanitizeHopByHop
// ---------------------------------------------------------------------------

func TestSanitizeHopByHop_Unit(t *testing.T) {
	tests := []struct {
		name             string
		headers          http.Header
		transferEncoding []string // simulates req.TransferEncoding set by ReadRequest
		wantAbsent       []string
		wantKeep         map[string]string
	}{
		{
			name: "B1: Connection names single header",
			headers: http.Header{
				"Connection":   {"X-Hop"},
				"X-Hop":        {"val"},
				"X-Persistent": {"val"},
			},
			wantAbsent: []string{"Connection", "X-Hop"},
			wantKeep:   map[string]string{"X-Persistent": "val"},
		},
		{
			name: "B1: Connection names multiple comma-separated headers",
			headers: http.Header{
				"Connection": {"X-A, X-B"},
				"X-A":        {"a"},
				"X-B":        {"b"},
			},
			wantAbsent: []string{"Connection", "X-A", "X-B"},
		},
		{
			name: "B2: Proxy-Authorization removed",
			headers: http.Header{
				"Proxy-Authorization": {"Basic abc"},
			},
			wantAbsent: []string{"Proxy-Authorization"},
		},
		{
			name: "K3: Proxy-Connection removed",
			headers: http.Header{
				"Proxy-Connection": {"keep-alive"},
			},
			wantAbsent: []string{"Proxy-Connection"},
		},
		{
			name: "J2: Upgrade removed",
			headers: http.Header{
				"Upgrade": {"websocket"},
			},
			wantAbsent: []string{"Upgrade"},
		},
		{
			name: "Well-known hop-by-hop: Keep-Alive, TE, Trailer",
			headers: http.Header{
				"Keep-Alive": {"timeout=5"},
				"Te":         {"trailers"},
				"Trailer":    {"X-Checksum"},
			},
			wantAbsent: []string{"Keep-Alive", "Te", "Trailer"},
		},
		{
			name:             "E1: TE + CL conflict removes CL",
			headers:          http.Header{"Content-Length": {"100"}},
			transferEncoding: []string{"chunked"},
			wantAbsent:       []string{"Content-Length"},
		},
		{
			name:     "E1: CL without TE is preserved",
			headers:  http.Header{"Content-Length": {"42"}},
			wantKeep: map[string]string{"Content-Length": "42"},
		},
		{
			name:    "empty Connection header",
			headers: http.Header{"Connection": {""}},
			// Connection itself is removed; no crash on empty values.
			wantAbsent: []string{"Connection"},
		},
		{
			name: "Connection names Proxy-Authorization",
			// A malicious client could try to strip the proxy's own
			// Proxy-Authorization by naming it in Connection. This is
			// safe because sanitizeHopByHop runs before token injection.
			headers: http.Header{
				"Connection":          {"Proxy-Authorization"},
				"Proxy-Authorization": {"Basic attacker"},
			},
			wantAbsent: []string{"Connection", "Proxy-Authorization"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{
				Header:           tc.headers,
				TransferEncoding: tc.transferEncoding,
			}
			sanitizeHopByHop(req)
			for _, h := range tc.wantAbsent {
				if vals, ok := req.Header[http.CanonicalHeaderKey(h)]; ok {
					t.Errorf("header %q: want absent, got %q", h, vals)
				}
			}
			for k, v := range tc.wantKeep {
				if got := req.Header.Get(k); got != v {
					t.Errorf("header %q: want %q, got %q", k, v, got)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for validateResponseContentLength
// ---------------------------------------------------------------------------

func TestValidateResponseContentLength_Unit(t *testing.T) {
	tests := []struct {
		name    string
		cl      []string // raw Content-Length header values
		wantErr bool
	}{
		{name: "absent", cl: nil, wantErr: false},
		{name: "valid single", cl: []string{"42"}, wantErr: false},
		{name: "valid zero", cl: []string{"0"}, wantErr: false},
		{name: "non-numeric", cl: []string{"abc"}, wantErr: true},
		{name: "negative", cl: []string{"-1"}, wantErr: true},
		{name: "floating point", cl: []string{"3.14"}, wantErr: true},
		{name: "comma-separated identical", cl: []string{"42, 42"}, wantErr: false},
		{name: "comma-separated differing", cl: []string{"42, 99"}, wantErr: true},
		{name: "multiple headers identical", cl: []string{"42", "42"}, wantErr: false},
		{name: "multiple headers differing", cl: []string{"42", "99"}, wantErr: true},
		{name: "hex value", cl: []string{"0xff"}, wantErr: true},
		{name: "empty value", cl: []string{""}, wantErr: false},
		{name: "space-padded valid", cl: []string{" 42 "}, wantErr: false},
		{name: "leading zeros equivalent", cl: []string{"042", "42"}, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			for _, v := range tc.cl {
				resp.Header.Add("Content-Length", v)
			}
			pe := validateResponseContentLength(resp)
			if tc.wantErr && pe == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && pe != nil {
				t.Errorf("expected nil, got error: %s", pe.errorType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// End-to-end headers preserved (sanity check)
// ---------------------------------------------------------------------------

func TestHopByHop_EndToEndHeadersPreserved(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Accept":        {"text/html"},
		"Authorization": {"Bearer token123"},
		"Cache-Control": {"no-cache"},
		"Content-Type":  {"application/json"},
		"X-Custom-App":  {"my-value"},
	})

	assertHeaderPresent(t, upReq.Header, "Accept", "text/html")
	assertHeaderPresent(t, upReq.Header, "Authorization", "Bearer token123")
	assertHeaderPresent(t, upReq.Header, "Cache-Control", "no-cache")
	assertHeaderPresent(t, upReq.Header, "Content-Type", "application/json")
	assertHeaderPresent(t, upReq.Header, "X-Custom-App", "my-value")
}

// ---------------------------------------------------------------------------
// E2 — RFC 9112 §6.1: Multiple differing Content-Length in response → 502
// ---------------------------------------------------------------------------

func TestE2_RFC9112_MultipleDifferingCLInResponse(t *testing.T) {
	// Go's http.ReadResponse rejects responses with differing
	// Content-Length headers before our validateResponseContentLength
	// runs. This test verifies the proxy returns 502 (via the
	// strings.Contains "Content-Length" check in the ReadResponse
	// error path) rather than silently raw-relaying the smuggling
	// attempt.
	rawUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = rawUpstream.Close() }()

	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := rawUpstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		// Two differing Content-Length headers — a smuggling attempt.
		resp := "HTTP/1.1 200 OK\r\n" +
			"Content-Length: 5\r\n" +
			"Content-Length: 10\r\n" +
			"\r\n" +
			"hello"
		_, _ = conn.Write([]byte(resp))
	})
	t.Cleanup(wg.Wait)

	proxy := NewProxyUnderTest(t, rawUpstream.Addr().String())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/e2-dup", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusBadGateway)
	if ps := resp.Header.Get("Proxy-Status"); !strings.Contains(ps, "http_protocol_error") {
		t.Errorf("expected Proxy-Status to contain 'http_protocol_error', got %q", ps)
	}
}

// ---------------------------------------------------------------------------
// Regression: Via header still injected after hop-by-hop sanitization
// ---------------------------------------------------------------------------

func TestHopByHop_ViaHeaderStillInjected(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/via", nil)
	req.Header.Set("Connection", "close")
	req.Header.Set("Proxy-Connection", "keep-alive")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	// Via must be present on the forwarded request.
	via := reqs[0].Header.Get("Via")
	if via == "" {
		t.Error("expected Via header in upstream request, got empty")
	}
	if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via %q does not contain pseudonym %q", via, testPseudonym)
	}

	// Via must also be present on the response.
	if resp.Header.Get("Via") == "" {
		t.Error("expected Via header in response, got empty")
	}
}

// ---------------------------------------------------------------------------
// Regression: Proxy-Authorization injected after hop-by-hop sanitization
// ---------------------------------------------------------------------------

func TestHopByHop_ProxyAuthInjectedAfterSanitization(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	proxy.Provider.token = "spnego-test-token"
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/auth-inject", nil)
	req.Header.Set("Proxy-Authorization", "Basic should-be-removed")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}

	assertHeaderPresent(t, reqs[0].Header, "Proxy-Authorization",
		"Negotiate "+proxy.Provider.token)
}

// ---------------------------------------------------------------------------
// Regression: Connection: Via cannot bypass loop detection
// ---------------------------------------------------------------------------

func TestHopByHop_ConnectionViaCannotBypassLoopDetection(t *testing.T) {
	// A malicious client sends "Connection: Via" to try to strip the Via
	// header before loop detection. The proxy must detect the loop because
	// loop detection runs before sanitizeHopByHop.
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/loop-bypass", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym)
	req.Header.Set("Connection", "Via")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The proxy must return 502 with proxy_loop_detected, not forward
	// the request with the Via header stripped.
	assertStatusCode(t, resp, http.StatusBadGateway)
	if ps := resp.Header.Get("Proxy-Status"); !strings.Contains(ps, "proxy_loop_detected") {
		t.Errorf("expected Proxy-Status to contain 'proxy_loop_detected', got %q", ps)
	}
}

// ---------------------------------------------------------------------------
// Via header injection and loop detection (RFC 9110 §7.6.3)
// ---------------------------------------------------------------------------

// TestA1_RFC9110_ViaAppendedOnForwardedRequest verifies that a request with
// no prior Via header is forwarded with a Via entry containing the protocol
// version and proxy pseudonym.
func TestA1_RFC9110_ViaAppendedOnForwardedRequest(t *testing.T) {
	upReq := proxyRoundTrip(t, nil)

	via := upReq.Header.Get("Via")
	want := "HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA1_RFC9110_ViaPreservesExistingEntries verifies that existing Via
// entries from upstream proxies are preserved and our entry is appended.
func TestA1_RFC9110_ViaPreservesExistingEntries(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Via": {"1.1 other-proxy"},
	})

	via := upReq.Header.Get("Via")
	want := "1.1 other-proxy, HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA1_RFC9110_ViaAppendedOnResponse verifies that the proxy adds a Via
// header to responses relayed from the upstream back to the client.
func TestA1_RFC9110_ViaAppendedOnResponse(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/a1-resp", nil)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertStatusCode(t, resp, http.StatusOK)

	via := resp.Header.Get("Via")
	want := "HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("response Via header: want %q, got %q", want, via)
	}
}

// loopDetectionScenario sets up a proxy with its own pseudonym already
// present in the incoming Via header and returns the proxy's response.
// It is shared between TestA2_RFC9110_LoopDetectionReturns502 and
// TestA3_RFC9209_ProxyStatusOnLoopDetected so both can assert different
// RFC requirements against the same scenario without duplicating setup.
func loopDetectionScenario(t *testing.T) (*http.Response, *ProxyUnderTest, *MockUpstreamProxy) {
	t.Helper()

	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/loop-test", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym)
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp, proxy, upstream
}

// TestA2_RFC9110_LoopDetectionReturns502 verifies that a request whose Via
// header already contains this proxy's pseudonym is rejected with 502 and
// not forwarded to the upstream.
func TestA2_RFC9110_LoopDetectionReturns502(t *testing.T) {
	resp, proxy, upstream := loopDetectionScenario(t)
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusBadGateway)

	wantPS := "spnego-proxy; error=proxy_loop_detected"
	if ps := resp.Header.Get("Proxy-Status"); ps != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, ps)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "spnego-proxy error: proxy_loop_detected") {
		t.Errorf("body should contain error type, got: %q", body)
	}
	if !strings.Contains(string(body), "routing loop was detected") {
		t.Errorf("body should describe loop detection, got: %q", body)
	}

	// The upstream must NOT have received the request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}

	// Token acquisition must be skipped when a loop is detected.
	if calls := proxy.Provider.calls.Load(); calls != 0 {
		t.Errorf("expected 0 token provider calls, got %d", calls)
	}
}

// TestA3_RFC9209_ProxyStatusOnLoopDetected verifies that when the incoming
// request's Via header already contains this proxy's pseudonym, the proxy
// responds with 502 Bad Gateway and Proxy-Status "proxy_loop_detected".
func TestA3_RFC9209_ProxyStatusOnLoopDetected(t *testing.T) {
	resp, _, upstream := loopDetectionScenario(t)
	defer func() { _ = resp.Body.Close() }()

	// A3: 502 with proxy_loop_detected when own pseudonym found in Via.
	assertProxyStatus(t, resp, http.StatusBadGateway, "proxy_loop_detected")

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_loop_detected") {
		t.Errorf("body: want mention of proxy_loop_detected, got %q", body)
	}
	if !strings.Contains(string(body), "routing loop") {
		t.Errorf("body: want description of routing loop, got %q", body)
	}

	// Upstream must NOT have received the looped request.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0 (loop should be rejected)", n)
	}
}

// TestA2_RFC9110_DifferentPseudonymNotDetectedAsLoop verifies that a Via
// header containing a different proxy's identifier does not trigger loop
// detection — only this instance's own pseudonym indicates a loop.
func TestA2_RFC9110_DifferentPseudonymNotDetectedAsLoop(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Via": {"1.1 some-other-proxy"},
	})

	via := upReq.Header.Get("Via")
	want := "1.1 some-other-proxy, HTTP/1.1 " + testPseudonym
	if via != want {
		t.Errorf("Via header: want %q, got %q", want, via)
	}
}

// TestA2_RFC9110_SubstringPseudonymDetectedAsLoop documents that loop
// detection uses strings.Contains, so a Via entry containing our pseudonym
// as a substring triggers loop detection. This is acceptable because
// production pseudonyms use random hex suffixes, making prefix collisions
// extremely unlikely.
func TestA2_RFC9110_SubstringPseudonymDetectedAsLoop(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Via entry contains our pseudonym as a prefix of a longer identifier.
	req, _ := http.NewRequest("GET", "http://example.com/a2-substr", nil)
	req.Header.Set("Via", "1.1 "+testPseudonym+"-extended")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// Current behavior: substring match triggers loop detection.
	assertStatusCode(t, resp, http.StatusBadGateway)

	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for injectVia
// ---------------------------------------------------------------------------

func TestInjectVia_EmptyHeader(t *testing.T) {
	h := make(http.Header)
	injectVia(h, "HTTP/1.1", "test-proxy")

	if got := h.Get("Via"); got != "HTTP/1.1 test-proxy" {
		t.Errorf("Via: want %q, got %q", "HTTP/1.1 test-proxy", got)
	}
}

func TestInjectVia_AppendsToExisting(t *testing.T) {
	h := http.Header{"Via": {"1.0 first-proxy"}}
	injectVia(h, "HTTP/1.1", "second-proxy")

	want := "1.0 first-proxy, HTTP/1.1 second-proxy"
	if got := h.Get("Via"); got != want {
		t.Errorf("Via: want %q, got %q", want, got)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for generateViaPseudonym
// ---------------------------------------------------------------------------

func TestGenerateViaPseudonym_HasPrefix(t *testing.T) {
	p := generateViaPseudonym()
	if !strings.HasPrefix(p, "spnego-proxy-") {
		t.Errorf("pseudonym %q should have prefix %q", p, "spnego-proxy-")
	}
}

func TestGenerateViaPseudonym_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		p := generateViaPseudonym()
		if seen[p] {
			t.Fatalf("duplicate pseudonym after %d iterations: %s", len(seen), p)
		}
		seen[p] = true
	}
}

// ---------------------------------------------------------------------------
// A1 — Via header injection on responses (RFC 9110 §7.6.3)
// ---------------------------------------------------------------------------

// TestHandleClientAppendsToExistingResponseVia verifies that handleClient
// appends to an existing Via header on upstream responses rather than
// replacing it (RFC 9110 §7.6.3).
func TestHandleClientAppendsToExistingResponseVia(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		// Send a response that already has a Via header from the upstream proxy.
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nVia: 1.0 upstream-proxy\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
	}()

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.WriteProxy(client); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = client.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	want := "1.0 upstream-proxy, HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != want {
		t.Errorf("response Via header = %q, want %q", got, want)
	}

	waitForDone(t, done)
}

// ---------------------------------------------------------------------------
// VR-004 — Unparseable upstream response returns 502 instead of raw relay
// ---------------------------------------------------------------------------

func TestUnparseableUpstreamReturns502(t *testing.T) {
	// Start a custom upstream that sends garbage instead of HTTP.
	garbageUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = garbageUpstream.Close() }()

	go func() {
		conn, err := garbageUpstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		reader := bufio.NewReader(conn)
		_, _ = http.ReadRequest(reader)
		_, _ = conn.Write([]byte("THIS IS NOT HTTP\r\n"))
	}()

	proxy := NewProxyUnderTest(t, garbageUpstream.Addr().String())
	t.Cleanup(proxy.Close)

	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("expected 502 response, got read error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	assertStatusCode(t, resp, http.StatusBadGateway)

	wantPS := "spnego-proxy; error=http_protocol_error"
	if got := resp.Header.Get("Proxy-Status"); got != wantPS {
		t.Errorf("Proxy-Status: want %q, got %q", wantPS, got)
	}
}

// TestHandleClientAddsViaToConnectResponse verifies that handleClient adds
// a Via header to CONNECT 200 responses and that the tunnel data still flows
// correctly after the Via-injected response is written (RFC 9110 §7.6.3).
func TestHandleClientAddsViaToConnectResponse(t *testing.T) {
	const tunnelPayload = "TUNNEL-DATA-FROM-UPSTREAM"

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = req.Body.Close()
		// Send CONNECT 200 response, then tunnel data.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		_, _ = conn.Write([]byte(tunnelPayload))
	}()

	provider := &stubTokenProvider{token: "tok"}
	cfg := defaultTestConfig(upstream.Addr().String(), provider)
	addr, done := acceptOneAndHandle(t, cfg)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = io.WriteString(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	clientReader := bufio.NewReader(client)
	resp, err := http.ReadResponse(clientReader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify Via header on the CONNECT response.
	want := "HTTP/1.1 " + testPseudonym
	if got := resp.Header.Get("Via"); got != want {
		t.Errorf("response Via header = %q, want %q", got, want)
	}

	// Verify tunnel data still flows through after the Via-injected response.
	buf := make([]byte, 4096)
	n, err := clientReader.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read tunnel data: %v", err)
	}
	if got := string(buf[:n]); got != tunnelPayload {
		t.Errorf("tunnel data = %q, want %q", got, tunnelPayload)
	}

	_ = client.Close()

	waitForDone(t, done)
}
