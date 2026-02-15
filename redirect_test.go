package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestIsRedirect(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{200, false},
		{204, false},
		{301, true},
		{302, true},
		{303, true},
		{304, false}, // Not Modified is not a redirect we follow
		{307, true},
		{308, true},
		{400, false},
		{404, false},
		{500, false},
	}
	for _, tt := range tests {
		if got := isRedirect(tt.code); got != tt.want {
			t.Errorf("isRedirect(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestRedirectPreservesMethod(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{301, false},
		{302, false},
		{303, false},
		{307, true},
		{308, true},
	}
	for _, tt := range tests {
		if got := redirectPreservesMethod(tt.code); got != tt.want {
			t.Errorf("redirectPreservesMethod(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestResolveRedirectURL(t *testing.T) {
	base, _ := url.Parse("http://example.com/a/b")
	tests := []struct {
		location string
		want     string
	}{
		// Absolute URL
		{"http://other.com/c", "http://other.com/c"},
		// Protocol-relative
		{"//other.com/d", "http://other.com/d"},
		// Absolute path
		{"/e/f", "http://example.com/e/f"},
		// Relative path
		{"g", "http://example.com/a/g"},
		// With query string
		{"/x?q=1", "http://example.com/x?q=1"},
		// HTTPS upgrade
		{"https://example.com/secure", "https://example.com/secure"},
	}
	for _, tt := range tests {
		got, err := resolveRedirectURL(base, tt.location)
		if err != nil {
			t.Errorf("resolveRedirectURL(%q, %q) error: %v", base, tt.location, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("resolveRedirectURL(%q, %q) = %q, want %q", base, tt.location, got.String(), tt.want)
		}
	}
}

func TestResolveRedirectURL_Invalid(t *testing.T) {
	base, _ := url.Parse("http://example.com/a")
	_, err := resolveRedirectURL(base, "://bad")
	if err == nil {
		t.Error("expected error for invalid Location, got nil")
	}
}

func TestRequestURL(t *testing.T) {
	// Proxy-style request with absolute URI.
	req := &http.Request{
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com",
			Path:   "/foo",
		},
		Host: "example.com",
	}
	u := requestURL(req)
	if u.String() != "http://example.com/foo" {
		t.Errorf("requestURL = %q, want %q", u.String(), "http://example.com/foo")
	}

	// Request with missing scheme.
	req2 := &http.Request{
		URL:  &url.URL{Path: "/bar"},
		Host: "other.com",
	}
	u2 := requestURL(req2)
	if u2.Scheme != "http" || u2.Host != "other.com" {
		t.Errorf("requestURL = scheme=%q host=%q, want scheme=http host=other.com", u2.Scheme, u2.Host)
	}
}

func TestHostWithPort(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"http://example.com/path", "example.com:80"},
		{"https://example.com/path", "example.com:443"},
		{"http://example.com:9090/path", "example.com:9090"},
		{"https://example.com:8443/path", "example.com:8443"},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.rawURL)
		got := hostWithPort(u)
		if got != tt.want {
			t.Errorf("hostWithPort(%q) = %q, want %q", tt.rawURL, got, tt.want)
		}
	}
}

// fakeTokenProvider returns a fixed token for testing.
type fakeTokenProvider struct {
	token string
}

func (f *fakeTokenProvider) GetToken(string) (string, error) { return f.token, nil }
func (f *fakeTokenProvider) Close() error                    { return nil }

// TestFollowRedirects_Integration starts a fake "upstream proxy" that returns
// a chain of redirects and verifies the proxy follows them, returning the
// final response to the client.
func TestFollowRedirects_Integration(t *testing.T) {
	// Fake upstream proxy: returns redirect chain then a 200.
	upstream := startFakeUpstreamProxy(t, []fakeResponse{
		{statusCode: 302, location: "http://example.com/step2"},
		{statusCode: 301, location: "http://example.com/step3"},
		{statusCode: 200, body: "final body"},
	})
	defer upstream.Close()

	provider := &fakeTokenProvider{token: "dGVzdA=="}

	// Start the redirect-following handler on a listener.
	clientConn, proxyConn := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleClientFollowRedirects(proxyConn, upstream.Addr().String(), provider, 10, false)
	}()

	// Send a plain HTTP proxy request.
	fmt.Fprintf(clientConn, "GET http://example.com/step1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "final body" {
		t.Errorf("body = %q, want %q", string(body), "final body")
	}
	clientConn.Close()
	wg.Wait()
}

// TestFollowRedirects_MaxExceeded verifies that the proxy returns the
// redirect response when the maximum number of redirects is reached.
func TestFollowRedirects_MaxExceeded(t *testing.T) {
	// Every response is a redirect — we should hit the cap.
	responses := make([]fakeResponse, 5)
	for i := range responses {
		responses[i] = fakeResponse{
			statusCode: 302,
			location:   fmt.Sprintf("http://example.com/step%d", i+2),
		}
	}
	upstream := startFakeUpstreamProxy(t, responses)
	defer upstream.Close()

	provider := &fakeTokenProvider{token: "dGVzdA=="}
	clientConn, proxyConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleClientFollowRedirects(proxyConn, upstream.Addr().String(), provider, 3, false)
	}()

	fmt.Fprintf(clientConn, "GET http://example.com/step1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// After 3 redirects the 4th redirect should be returned as-is.
	if resp.StatusCode != 302 {
		t.Errorf("status = %d, want 302 (max redirects exceeded)", resp.StatusCode)
	}
	clientConn.Close()
	wg.Wait()
}

// TestFollowRedirects_CONNECT verifies that CONNECT requests bypass the
// redirect-following path and use normal pass-through.
func TestFollowRedirects_CONNECT(t *testing.T) {
	// Upstream proxy: accepts CONNECT, tunnels data back.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tunnelBody := "hello from tunnel"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method != http.MethodConnect {
			fmt.Fprintf(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// Echo something back through the tunnel.
		fmt.Fprint(c, tunnelBody)
	}()

	provider := &fakeTokenProvider{token: "dGVzdA=="}
	clientConn, proxyConn := net.Pipe()

	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		handleClientFollowRedirects(proxyConn, ln.Addr().String(), provider, 10, false)
	}()

	fmt.Fprintf(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")

	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Read the tunnel data.
	buf := make([]byte, len(tunnelBody))
	_, err = io.ReadFull(br, buf)
	if err != nil {
		t.Fatalf("reading tunnel data: %v", err)
	}
	if string(buf) != tunnelBody {
		t.Errorf("tunnel data = %q, want %q", string(buf), tunnelBody)
	}
	clientConn.Close()
	wg.Wait()
	wg2.Wait()
}

// --- Test helpers ---

type fakeResponse struct {
	statusCode int
	location   string // for redirects
	body       string // for final responses
}

// startFakeUpstreamProxy creates a TCP listener that acts as an upstream
// proxy.  It accepts sequential connections (one per redirect hop) and
// returns the next response from the list for each incoming request.
func startFakeUpstreamProxy(t *testing.T, responses []fakeResponse) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	idx := 0

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_, err := http.ReadRequest(br)
				if err != nil {
					return
				}

				mu.Lock()
				if idx >= len(responses) {
					mu.Unlock()
					return
				}
				r := responses[idx]
				idx++
				mu.Unlock()

				if r.location != "" {
					fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
						r.statusCode, http.StatusText(r.statusCode), r.location)
				} else {
					fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
						r.statusCode, http.StatusText(r.statusCode), len(r.body), r.body)
				}
			}(c)
		}
	}()
	return ln
}
