package main

// noproxy_integration_test.go — integration tests for noproxy bypass paths.
//
// Task 6: HTTP bypass (handleDirectHTTP)
// Task 7: CONNECT bypass (handleDirectConnect)
// Task 8: Environment variable integration

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
// startDirectTarget — minimal HTTP server for bypass verification
// ---------------------------------------------------------------------------

// startDirectTarget starts a minimal HTTP server that responds with 200 OK
// and an X-Direct: true header so tests can verify the request went direct.
// Returns the listener address as "host:port".
func startDirectTarget(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startDirectTarget: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				resp := &http.Response{
					StatusCode:    http.StatusOK,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        http.Header{"X-Direct": {"true"}},
					Body:          http.NoBody,
					ContentLength: 0,
					Request:       req,
				}
				_ = resp.Write(conn)
			}()
		}
	}()
	return l.Addr().String()
}

// ---------------------------------------------------------------------------
// Task 6 — HTTP bypass integration tests
// ---------------------------------------------------------------------------

// TestNoProxyHTTPBypassGoesToTarget verifies that when the target host matches
// a noproxy pattern the proxy connects directly to the target, injects a Via
// header on the response, and does not contact the upstream proxy or acquire
// a SPNEGO token.
func TestNoProxyHTTPBypassGoesToTarget(t *testing.T) {
	targetAddr := startDirectTarget(t)

	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	// Match the exact loopback IP that the target is listening on.
	proxy.SetNoProxy(NewNoProxyMatcher("127.0.0.1"))

	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Send request in proxy (absolute) form.
	rawReq := fmt.Sprintf("GET http://%s/test HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(client, rawReq); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertStatusCode(t, resp, http.StatusOK)

	// X-Direct confirms the response came from the target, not the upstream.
	assertHeaderPresent(t, resp.Header, "X-Direct", "true")

	// Via must be injected by the proxy per RFC 9110 §7.6.3.
	via := resp.Header.Get("Via")
	if via == "" {
		t.Error("expected Via header in response, got empty")
	} else if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via header %q does not contain pseudonym %q", via, testPseudonym)
	}

	// Upstream must have received zero requests.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d request(s), want 0", n)
	}

	// Token provider must not have been called.
	if calls := proxy.Provider.calls.Load(); calls != 0 {
		t.Errorf("token provider called %d time(s), want 0", calls)
	}
}

// TestNoProxyNonMatchGoesUpstream verifies that when the target host does NOT
// match any noproxy pattern the proxy forwards the request to the upstream
// with a Proxy-Authorization header.
func TestNoProxyNonMatchGoesUpstream(t *testing.T) {
	recorded := proxyRoundTrip(t, nil, func(p *ProxyUnderTest) {
		// Pattern does not cover example.com, which proxyRoundTrip targets.
		p.SetNoProxy(NewNoProxyMatcher("*.internal.corp"))
	})

	// Upstream must have received the request.
	assertHeaderPresent(t, recorded.Header, "Proxy-Authorization", "Negotiate test-token")
}

// TestNoProxyHTTPRequestInOriginForm verifies that when a request is bypassed
// via noproxy, the proxy rewrites the request from absolute (proxy) form to
// origin form before forwarding to the target.
func TestNoProxyHTTPRequestInOriginForm(t *testing.T) {
	// capturedURI holds the RequestURI seen at the target server.
	capturedURI := make(chan string, 1)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			capturedURI <- ""
			return
		}
		capturedURI <- req.RequestURI

		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"X-Direct": {"true"}},
			Body:          http.NoBody,
			ContentLength: 0,
			Request:       req,
		}
		_ = resp.Write(conn)
	}()

	targetAddr := l.Addr().String()

	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)
	proxy.SetNoProxy(NewNoProxyMatcher("127.0.0.1"))

	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Client sends proxy (absolute) form.
	rawReq := fmt.Sprintf("GET http://%s/some/path?q=1 HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(client, rawReq); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	assertStatusCode(t, resp, http.StatusOK)

	// Collect the URI the target saw.
	var uri string
	select {
	case uri = <-capturedURI:
	case <-t.Context().Done():
		t.Fatal("target did not receive request before test timeout")
	}

	// The target must see origin form: /some/path?q=1, not the absolute URI.
	if strings.HasPrefix(uri, "http://") {
		t.Errorf("target received request in absolute form %q; want origin form", uri)
	}
	if uri != "/some/path?q=1" {
		t.Errorf("target RequestURI = %q, want %q", uri, "/some/path?q=1")
	}
}

// ---------------------------------------------------------------------------
// Task 7 — CONNECT bypass integration tests
// ---------------------------------------------------------------------------

// startEchoServer starts a raw TCP echo server and returns its address.
// It echoes every byte it receives back to the sender.
func startEchoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startEchoServer: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().String()
}

// TestNoProxyCONNECTBypassEstablishesDirectTunnel verifies that when a CONNECT
// target matches a noproxy pattern the proxy establishes a direct tunnel
// (bypassing the upstream), responds with 200 Connection Established with a
// Via header, and actually proxies data through the tunnel.
func TestNoProxyCONNECTBypassEstablishesDirectTunnel(t *testing.T) {
	echoAddr := startEchoServer(t)

	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	// Allow CONNECT on any port and match 127.0.0.1 for bypass.
	proxy.SetConnectPorts([]string{connectPortWildcard})
	proxy.SetNoProxy(NewNoProxyMatcher("127.0.0.1"))

	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", proxy.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Send CONNECT to the echo server address.
	connectMsg := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	if _, err := io.WriteString(client, connectMsg); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// Proxy must respond with 200 Connection Established.
	assertStatusCode(t, resp, http.StatusOK)

	// Via must appear on the 200 response per RFC 9110 §7.6.3.
	via := resp.Header.Get("Via")
	if via == "" {
		t.Error("expected Via header in CONNECT 200 response, got empty")
	} else if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via header %q does not contain pseudonym %q", via, testPseudonym)
	}

	// Content-Length and Connection: close MUST NOT appear — they cause
	// Bun/undici clients to close the connection before the TLS handshake.
	assertHeaderAbsent(t, resp.Header, "Content-Length")
	assertHeaderAbsent(t, resp.Header, "Connection")

	// Verify the tunnel actually works: send data and read the echo back.
	const payload = "hello-direct-tunnel"
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(buf) != payload {
		t.Errorf("tunnel echo: want %q, got %q", payload, string(buf))
	}

	// Upstream must have received zero requests.
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream received %d request(s), want 0", n)
	}

	// Token provider must not have been called.
	if calls := proxy.Provider.calls.Load(); calls != 0 {
		t.Errorf("token provider called %d time(s), want 0", calls)
	}
}

// ---------------------------------------------------------------------------
// Task 8 — Environment variable integration tests
// ---------------------------------------------------------------------------

// TestNoProxyEnvVarIntegration verifies the full precedence chain of
// resolveNoProxy + NewNoProxyMatcher: flag overrides env, NO_PROXY is used
// when flag is empty, and no_proxy is the final fallback.
func TestNoProxyEnvVarIntegration(t *testing.T) {
	t.Run("flag overrides NO_PROXY env", func(t *testing.T) {
		t.Setenv("NO_PROXY", "env-value.com")
		t.Setenv("no_proxy", "lower-env-value.com")

		patterns := resolveNoProxy("flag-value.com")
		m := NewNoProxyMatcher(patterns)

		if matched, _ := m.Match("flag-value.com"); !matched {
			t.Error("flag-value.com should be matched when flag takes precedence")
		}
		if matched, _ := m.Match("env-value.com"); matched {
			t.Error("env-value.com should not be matched when flag overrides env")
		}
		if matched, _ := m.Match("lower-env-value.com"); matched {
			t.Error("lower-env-value.com should not be matched when flag overrides env")
		}
	})

	t.Run("NO_PROXY used when flag empty", func(t *testing.T) {
		t.Setenv("NO_PROXY", "no-proxy-host.com")
		t.Setenv("no_proxy", "lower-no-proxy-host.com")

		patterns := resolveNoProxy("")
		m := NewNoProxyMatcher(patterns)

		if matched, _ := m.Match("no-proxy-host.com"); !matched {
			t.Error("no-proxy-host.com should be matched via NO_PROXY env")
		}
		// NO_PROXY takes precedence over no_proxy so lower variant is not used.
		if matched, _ := m.Match("lower-no-proxy-host.com"); matched {
			t.Error("lower-no-proxy-host.com should not be matched when NO_PROXY is set")
		}
	})

	t.Run("no_proxy fallback when NO_PROXY empty", func(t *testing.T) {
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "fallback-host.com")

		patterns := resolveNoProxy("")
		m := NewNoProxyMatcher(patterns)

		if matched, _ := m.Match("fallback-host.com"); !matched {
			t.Error("fallback-host.com should be matched via no_proxy fallback")
		}
	})

	t.Run("empty flag and empty envs matches nothing", func(t *testing.T) {
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")

		patterns := resolveNoProxy("")
		m := NewNoProxyMatcher(patterns)

		for _, host := range []string{"example.com", "127.0.0.1", "anything.internal"} {
			if matched, _ := m.Match(host); matched {
				t.Errorf("host %q should not match when all sources are empty", host)
			}
		}
	})
}
