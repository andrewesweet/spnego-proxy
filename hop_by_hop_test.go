package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// B1 — RFC 9110 §7.6.1: Connection header and named headers removed
// ---------------------------------------------------------------------------

func TestB1_RFC9110_ConnectionHeaderAndNamedHeadersRemoved(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/b1", nil)
	req.Header.Set("Connection", "X-Custom-Hop")
	req.Header.Set("X-Custom-Hop", "secret")
	req.Header.Set("X-Legitimate", "keep-me")
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
	upReq := reqs[0]

	assertHeaderAbsent(t, upReq.Header, "Connection")
	assertHeaderAbsent(t, upReq.Header, "X-Custom-Hop")
	assertHeaderPresent(t, upReq.Header, "X-Legitimate", "keep-me")
}

func TestB1_RFC9110_ConnectionHeaderMultipleValues(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/b1-multi", nil)
	req.Header.Set("Connection", "X-Hop-A, X-Hop-B")
	req.Header.Set("X-Hop-A", "a-value")
	req.Header.Set("X-Hop-B", "b-value")
	req.Header.Set("X-End-To-End", "preserved")
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
	upReq := reqs[0]

	assertHeaderAbsent(t, upReq.Header, "Connection")
	assertHeaderAbsent(t, upReq.Header, "X-Hop-A")
	assertHeaderAbsent(t, upReq.Header, "X-Hop-B")
	assertHeaderPresent(t, upReq.Header, "X-End-To-End", "preserved")
}

// ---------------------------------------------------------------------------
// B1 — Keep-Alive is a well-known hop-by-hop header
// ---------------------------------------------------------------------------

func TestB1_RFC9110_KeepAliveStripped(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/keepalive", nil)
	req.Header.Set("Keep-Alive", "timeout=5")
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
	assertHeaderAbsent(t, reqs[0].Header, "Keep-Alive")
}

// ---------------------------------------------------------------------------
// B2 — RFC 9110 §11.7.1: Client Proxy-Authorization consumed
// ---------------------------------------------------------------------------

func TestB2_RFC9110_ClientProxyAuthorizationConsumed(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/b2", nil)
	req.Header.Set("Proxy-Authorization", "Basic abc123")
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
	upReq := reqs[0]

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
// K3 — RFC 9113 §8.2.2: Proxy-Connection stripped
// ---------------------------------------------------------------------------

func TestK3_RFC9113_ProxyConnectionStripped(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/k3", nil)
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
	assertHeaderAbsent(t, reqs[0].Header, "Proxy-Connection")
}

// ---------------------------------------------------------------------------
// J2 — RFC 9110 §7.8: Upgrade stripped
// ---------------------------------------------------------------------------

func TestJ2_RFC9110_UpgradeStripped(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/j2", nil)
	req.Header.Set("Upgrade", "websocket")
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
	assertHeaderAbsent(t, reqs[0].Header, "Upgrade")
}

// ---------------------------------------------------------------------------
// B1 — TE and Trailer (well-known hop-by-hop) stripped
// ---------------------------------------------------------------------------

func TestB1_RFC9110_TEAndTrailerStripped(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/te-trailer", nil)
	req.Header.Set("TE", "trailers")
	req.Header.Set("Trailer", "X-Checksum")
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
	assertHeaderAbsent(t, reqs[0].Header, "TE")
	assertHeaderAbsent(t, reqs[0].Header, "Trailer")
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
	upReq := reqs[0]

	// Transfer-Encoding should be present (or the body should have
	// been forwarded correctly); Content-Length must be absent.
	assertHeaderAbsent(t, upReq.Header, "Content-Length")
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

	go func() {
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
	}()

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
// All hop-by-hop headers stripped together (combined test)
// ---------------------------------------------------------------------------

func TestHopByHop_AllHeadersStrippedTogether(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/all-hop-by-hop", nil)
	req.Header.Set("Connection", "X-Named-Hop")
	req.Header.Set("X-Named-Hop", "should-be-removed")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic attacker-creds")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Trailer", "X-Checksum")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-End-To-End", "must-survive")
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
	upReq := reqs[0]

	// All hop-by-hop headers must be absent.
	for _, h := range []string{
		"Connection", "X-Named-Hop", "Keep-Alive",
		"Proxy-Connection", "TE", "Trailer", "Upgrade",
	} {
		assertHeaderAbsent(t, upReq.Header, h)
	}

	// Proxy-Authorization must be the proxy's own Negotiate token.
	pa := upReq.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(pa, "Negotiate ") {
		t.Errorf("Proxy-Authorization: want 'Negotiate ...', got %q", pa)
	}

	// End-to-end headers must survive.
	assertHeaderPresent(t, upReq.Header, "X-End-To-End", "must-survive")
}

// ---------------------------------------------------------------------------
// Unit tests for sanitizeHopByHop
// ---------------------------------------------------------------------------

func TestSanitizeHopByHop_Unit(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantAbsent []string
		wantKeep   map[string]string
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
			name: "E1: TE + CL conflict removes CL",
			headers: http.Header{
				"Transfer-Encoding": {"chunked"},
				"Content-Length":    {"100"},
			},
			wantAbsent: []string{"Content-Length"},
		},
		{
			name: "E1: CL without TE is preserved",
			headers: http.Header{
				"Content-Length": {"42"},
			},
			wantKeep: map[string]string{"Content-Length": "42"},
		},
		{
			name:    "empty Connection header",
			headers: http.Header{"Connection": {""}},
			// Connection itself is removed; no crash on empty values.
			wantAbsent: []string{"Connection"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sanitizeHopByHop(tc.headers)
			for _, h := range tc.wantAbsent {
				if v := tc.headers.Get(h); v != "" {
					t.Errorf("header %q: want absent, got %q", h, v)
				}
			}
			for k, v := range tc.wantKeep {
				if got := tc.headers.Get(k); got != v {
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
	upstream := NewMockUpstreamProxy(t, nil)
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/e2e", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent/1.0")
	req.Header.Set("X-Custom-App", "my-value")
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
	upReq := reqs[0]

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
	// Create a raw upstream that sends duplicate, differing Content-Length.
	rawUpstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = rawUpstream.Close() }()

	go func() {
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
	}()

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
		// Go's ReadResponse may itself reject the response; either way
		// the client must not receive the smuggling attempt.
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// If we get a parseable response, it must be a 502 from our proxy.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for differing Content-Length, got %d", resp.StatusCode)
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
	// Include hop-by-hop headers that get stripped — Via should still appear.
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
	respVia := resp.Header.Get("Via")
	if respVia == "" {
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
		fmt.Sprintf("Negotiate %s", proxy.Provider.token))
}
