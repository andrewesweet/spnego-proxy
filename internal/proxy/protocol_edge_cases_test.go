package proxy

// protocol_edge_cases_test.go — acceptance tests for GitHub issue #127.
//
// Requirements covered:
//   F1  RFC 9110 §10.1.1 — Expect: 100-continue forwarded to upstream
//   F2  RFC 9110 §15.2   — 1xx interim responses relayed to HTTP/1.1 clients,
//                          dropped for HTTP/1.0 clients, final response still read.
//                          (HTTP/1.0 half was a documented known gap before D3.)
//   G1  RFC 9110 §7.6.2  — Max-Forwards decremented for TRACE/OPTIONS; stop at zero
//   I1  RFC 9112 §9.3    — HTTP/1.0 client connection closed after response
//   I2  RFC 9112 §9.6    — Connection: close from client honored
//   N2  RFC 8470 §5.1    — Early-Data header not removed

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// F1 — RFC 9110 §10.1.1: Forward Expect: 100-continue to upstream
// ---------------------------------------------------------------------------

// TestF1_ExpectHeaderForwarded verifies that when an HTTP/1.1 client sends
// Expect: 100-continue (in various casings), the proxy forwards that header
// to the upstream.
//
// RFC 9110 §10.1.1: a proxy MUST forward the Expect: 100-continue field if it
// is forwarding a request to an HTTP/1.1 or later upstream.
func TestF1_ExpectHeaderForwarded(t *testing.T) {
	tests := []struct {
		name        string
		expectValue string
	}{
		{"lowercase", "100-continue"},
		{"mixed case", "100-Continue"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := "hello"
			raw := "POST http://example.com/upload HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Content-Type: application/octet-stream\r\n" +
				fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
				fmt.Sprintf("Expect: %s\r\n", tc.expectValue) +
				"\r\n" +
				body

			resp, reqs := proxyRawRoundTrip(t, raw)
			defer func() { _ = resp.Body.Close() }()
			assertStatusCode(t, resp, http.StatusOK)

			if len(reqs) != 1 {
				t.Fatalf("upstream received %d requests, want 1", len(reqs))
			}

			// Header value comparison is case-insensitive per RFC 9110 §10.1.1.
			if got := reqs[0].Header.Get("Expect"); !strings.EqualFold(got, "100-continue") {
				t.Errorf("upstream Expect header: want %q (case-insensitive), got %q", "100-continue", got)
			}
		})
	}
}

// TestF1_ExpectHeaderNotAddedWhenAbsent verifies that the proxy does not
// invent an Expect header when the client did not send one.
func TestF1_ExpectHeaderNotAddedWhenAbsent(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{})
	assertHeaderAbsent(t, upReq.Header, "Expect")
}

// ---------------------------------------------------------------------------
// F2 — RFC 9110 §15.2: interim (1xx) responses before the final response
// ---------------------------------------------------------------------------
//
// RFC 9110 §15.2: a client MUST be able to parse one or more 1xx responses
// received before a final response, and a proxy MUST forward 1xx responses it
// did not itself request. RFC 9110 §15.2 also forbids sending a 1xx response
// to an HTTP/1.0 client, which cannot parse one.
//
// The proxy must therefore keep reading after every 1xx other than 101 (101 is
// the final response of a protocol upgrade) until the final response arrives.
// Go's http.ReadResponse returns a 1xx as an ordinary bodyless response; only
// http.Transport loops past interim responses, and the proxy does not use it.
//
// The upstream side of these tests is a raw TCP listener because
// http.Response.Write cannot emit a bare 1xx response.

// clientMessage is one response as the client saw it on the wire.
//
// header keeps every field, so a test can assert on the Via header (RFC 9110
// §7.6.3 requires a proxy to add it to every response it forwards, interim
// ones included) or on a marker the origin set.
type clientMessage struct {
	statusCode int
	header     http.Header
	body       string
}

// forwardRequest builds the raw bytes of one request routed through the
// upstream proxy (direct=false) or the -noproxy direct path (direct=true).
// The upstream path targets the fixed authority example.test, which the raw
// origin answers like any other absolute-form authority; the -noproxy path
// must name origin itself for the matcher to take it. A non-empty body adds
// Content-Length and Expect: 100-continue, the shape curl uses for a large
// upload over plain HTTP.
func forwardRequest(direct bool, origin, method, path, proto, body string) string {
	authority := "example.test"
	if direct {
		authority = origin
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s http://%s%s %s\r\nHost: %s\r\n", method, authority, path, proto, authority)
	if body != "" {
		fmt.Fprintf(&b, "Content-Length: %d\r\nExpect: 100-continue\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// startRawInterimOrigin starts a raw TCP origin (also usable as an upstream
// proxy, since it accepts absolute-form request targets) that answers every
// request on a connection with interim written verbatim, followed by the
// response final returns for that request. Raw bytes are needed because
// http.Response.Write cannot emit a bare 1xx response.
func startRawInterimOrigin(t *testing.T, interim string, final func(*http.Request) string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen interim origin: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				for {
					req, rerr := http.ReadRequest(br)
					if rerr != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					_, _ = io.WriteString(conn, interim+final(req))
				}
			}()
		}
	}()
	return l.Addr().String()
}

// startInterimOrigin starts a raw origin whose final response is a 200 whose
// body echoes the request path.
func startInterimOrigin(t *testing.T, interim string) string {
	t.Helper()
	return startRawInterimOrigin(t, interim, func(req *http.Request) string {
		p := req.URL.Path
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(p), p)
	})
}

// startBodylessInterimOrigin starts a raw origin whose final response is a
// bodyless 200 that names the request path in X-Request-Path.
func startBodylessInterimOrigin(t *testing.T, interim string) string {
	t.Helper()
	return startRawInterimOrigin(t, interim, func(req *http.Request) string {
		return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Request-Path: " + req.URL.Path + "\r\n\r\n"
	})
}

// startInterimProxy starts a proxy that reaches origin through the upstream
// proxy path (direct=false) or the -noproxy direct path (direct=true) and
// returns its address.
func startInterimProxy(t *testing.T, origin string, direct bool) string {
	t.Helper()
	proxy := NewProxyUnderTest(t, origin)
	if direct {
		proxy.SetNoProxy(NewNoProxyMatcher("127.0.0.1"))
	}
	t.Cleanup(proxy.Close)
	return proxy.Addr()
}

// readThroughFinal reads responses the way net/http.Transport does: each 1xx
// response is followed by another one, and the first non-1xx response is
// final. It fails the test on a read error or when every response received so
// far is still an interim one.
func readThroughFinal(t *testing.T, conn net.Conn, br *bufio.Reader) []clientMessage {
	t.Helper()
	const maxInterim = 4
	msgs := make([]clientMessage, 0, 2)
	for range maxInterim + 1 {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read response %d (received %v so far): %v", len(msgs)+1, msgs, err)
		}
		body, berr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if berr != nil {
			t.Fatalf("read body of %s: %v", resp.Status, berr)
		}
		msgs = append(msgs, clientMessage{statusCode: resp.StatusCode, header: resp.Header, body: string(body)})
		if resp.StatusCode >= 200 {
			return msgs
		}
	}
	t.Fatalf("no final response after %d interim responses: %v", maxInterim, msgs)
	return nil
}

// interimPaths names the two proxy routes that relay a response read from the
// wire: through the SPNEGO upstream proxy and through -noproxy direct.
var interimPaths = []struct {
	name   string
	direct bool
}{
	{"upstream", false},
	{"noproxy direct", true},
}

// TestF2_InterimResponsesRelayedBeforeFinal verifies that a 1xx response from
// upstream is relayed to an HTTP/1.1 client in order and before the final
// response, and that the final response is still delivered with its own body.
func TestF2_InterimResponsesRelayedBeforeFinal(t *testing.T) {
	tests := []struct {
		name         string
		interim      string
		wantInterims []int
	}{
		{
			name:         "100 Continue",
			interim:      "HTTP/1.1 100 Continue\r\n\r\n",
			wantInterims: []int{100},
		},
		{
			name:         "103 Early Hints",
			interim:      "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n",
			wantInterims: []int{103},
		},
		{
			name:         "two interim responses",
			interim:      "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\n\r\n",
			wantInterims: []int{100, 103},
		},
	}

	for _, path := range interimPaths {
		for _, tc := range tests {
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				origin := startInterimOrigin(t, tc.interim)
				proxyAddr := startInterimProxy(t, origin, path.direct)
				conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				defer func() { _ = conn.Close() }()
				if _, werr := io.WriteString(conn, forwardRequest(path.direct, origin, "POST", "/upload", "HTTP/1.1", "hello")); werr != nil {
					t.Fatalf("write request: %v", werr)
				}

				msgs := readThroughFinal(t, conn, bufio.NewReader(conn))
				if len(msgs) != len(tc.wantInterims)+1 {
					t.Fatalf("client received %d responses, want %d interim + 1 final: %v", len(msgs), len(tc.wantInterims), msgs)
				}
				for i, want := range tc.wantInterims {
					if msgs[i].statusCode != want {
						t.Errorf("response %d: want interim status %d, got %d", i, want, msgs[i].statusCode)
					}
					if via := msgs[i].header.Get("Via"); !strings.Contains(via, testPseudonym) {
						t.Errorf("interim response %d: want Via containing %q, got %q", i, testPseudonym, via)
					}
				}
				last := msgs[len(msgs)-1]
				if last.statusCode != http.StatusOK {
					t.Errorf("final response: want 200, got %d", last.statusCode)
				}
				if last.body != "/upload" {
					t.Errorf("final response body: want %q, got %q", "/upload", last.body)
				}
			})
		}
	}
}

func TestF2_InterimResponsesHaveNoBodyFraming(t *testing.T) {
	const interim = "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 102 Processing\r\n\r\n" +
		"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n" +
		"HTTP/1.1 199 Custom\r\n\r\n"
	for _, path := range interimPaths {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
			t.Run(path.name+"/"+method, func(t *testing.T) {
				origin := startBodylessInterimOrigin(t, interim)
				proxyAddr := startInterimProxy(t, origin, path.direct)
				conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				defer func() { _ = conn.Close() }()
				body := ""
				if method == "POST" || method == "PUT" || method == "PATCH" {
					body = "hello"
				}
				if _, err := io.WriteString(conn, forwardRequest(path.direct, origin, method, "/upload", "HTTP/1.1", body)); err != nil {
					t.Fatalf("write request: %v", err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(conn)
				reader := textproto.NewReader(br)
				for _, wantStatus := range []string{"100 Continue", "102 Processing", "103 Early Hints", "199 Custom"} {
					status, err := reader.ReadLine()
					if err != nil {
						t.Fatalf("read interim status: %v", err)
					}
					if status != "HTTP/1.1 "+wantStatus {
						t.Fatalf("interim status: got %q, want %q", status, "HTTP/1.1 "+wantStatus)
					}
					header, err := reader.ReadMIMEHeader()
					if err != nil {
						t.Fatalf("read interim headers: %v", err)
					}
					for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
						if values, ok := header[name]; ok {
							t.Errorf("%s: forbidden interim framing %s: %v (RFC 9110 section 8.6; RFC 9112 sections 6.1, 6.3)", status, name, values)
						}
					}
					if via := header.Get("Via"); !strings.Contains(via, testPseudonym) {
						t.Errorf("%s: missing proxy Via: %q", status, via)
					}
					if wantStatus == "103 Early Hints" && header.Get("Link") != "</style.css>; rel=preload" {
						t.Errorf("Early Hints Link: got %q", header.Get("Link"))
					}
				}
				msgs := readThroughFinal(t, conn, br)
				if len(msgs) != 1 || msgs[0].statusCode != http.StatusOK || msgs[0].header.Get("X-Request-Path") != "/upload" {
					t.Fatalf("final response: got %v, want one 200 for /upload", msgs)
				}
			})
		}
	}
}

// TestF2_InterimResponsesDroppedForHTTP10Client verifies that no 1xx response
// reaches an HTTP/1.0 client, which cannot parse one, while the final response
// still does.
func TestF2_InterimResponsesDroppedForHTTP10Client(t *testing.T) {
	for _, path := range interimPaths {
		t.Run(path.name, func(t *testing.T) {
			const interim = "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
			origin := startInterimOrigin(t, interim)
			proxyAddr := startInterimProxy(t, origin, path.direct)
			conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if _, werr := io.WriteString(conn, forwardRequest(path.direct, origin, "GET", "/page", "HTTP/1.0", "")); werr != nil {
				t.Fatalf("write request: %v", werr)
			}

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			raw, _ := io.ReadAll(conn)
			got := string(raw)
			if strings.Contains(got, "Early Hints") {
				t.Errorf("HTTP/1.0 client received an interim response: %q", got)
			}
			if !strings.HasPrefix(got, "HTTP/1.1 200 OK\r\n") {
				t.Fatalf("HTTP/1.0 client response: want a 200 OK status line first, got %q", got)
			}
			if !strings.HasSuffix(got, "/page") {
				t.Errorf("HTTP/1.0 client response body: want %q at the end, got %q", "/page", got)
			}
		})
	}
}

// TestF2_EachRequestGetsOwnFinalResponse checks HTTP/1.1 persistence: sequential
// and pipelined requests on one connection must each receive their own complete
// final response body, with or without preceding interim responses.
func TestF2_EachRequestGetsOwnFinalResponse(t *testing.T) {
	for _, path := range interimPaths {
		for _, tc := range []struct {
			name      string
			interim   string
			pipelined bool
		}{
			{"sequential interim", "HTTP/1.1 100 Continue\r\n\r\n", false},
			{"pipelined interim", "HTTP/1.1 100 Continue\r\n\r\n", true},
			{"sequential final only", "", false},
			{"pipelined final only", "", true},
		} {
			t.Run(path.name+"/"+tc.name, func(t *testing.T) {
				origin := startInterimOrigin(t, tc.interim)
				proxyAddr := startInterimProxy(t, origin, path.direct)
				conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
				if err != nil {
					t.Fatalf("dial proxy: %v", err)
				}
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				paths := []string{"/first", "/second"}
				if tc.pipelined {
					var requests strings.Builder
					for _, wantPath := range paths {
						requests.WriteString(forwardRequest(path.direct, origin, "GET", wantPath, "HTTP/1.1", ""))
					}
					if _, werr := io.WriteString(conn, requests.String()); werr != nil {
						t.Fatalf("write pipelined requests: %v", werr)
					}
				}

				for _, wantPath := range paths {
					if !tc.pipelined {
						if _, werr := io.WriteString(conn, forwardRequest(path.direct, origin, "GET", wantPath, "HTTP/1.1", "")); werr != nil {
							t.Fatalf("write request %s: %v", wantPath, werr)
						}
					}
					msgs := readThroughFinal(t, conn, br)
					last := msgs[len(msgs)-1]
					if last.statusCode != http.StatusOK {
						t.Errorf("request %s: want final 200, got %d", wantPath, last.statusCode)
					}
					if got := last.body; got != wantPath {
						t.Errorf("request %s was answered by the final response for %q", wantPath, got)
					}
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// G1 — RFC 9110 §7.6.2: Decrement Max-Forwards for TRACE/OPTIONS
// ---------------------------------------------------------------------------

// TestG1_MaxForwards_Table covers Max-Forwards handling for TRACE, OPTIONS,
// and other methods in a single table-driven test.
//
// RFC 9110 §7.6.2: each proxy that forwards a TRACE or OPTIONS request MUST
// decrement the Max-Forwards value by 1 before forwarding. If the received
// value is 0, the recipient MUST NOT forward the request; instead, it MUST
// respond as the final recipient. For other methods, the header is forwarded
// unchanged. If the header is absent, the proxy MUST NOT add it. If the
// value is not a valid integer, the proxy SHOULD forward it unmodified.
func TestG1_MaxForwards_Table(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		maxForwards  string // "" means absent
		wantUpstream bool   // whether the request should reach the upstream
		wantMF       string // expected Max-Forwards on upstream, "" means absent
	}{
		{
			name:         "TRACE MF=0 handled locally",
			method:       "TRACE",
			maxForwards:  "0",
			wantUpstream: false,
		},
		{
			name:         "OPTIONS MF=0 handled locally",
			method:       "OPTIONS",
			maxForwards:  "0",
			wantUpstream: false,
		},
		{
			name:         "TRACE MF=1 decremented to 0 and forwarded",
			method:       "TRACE",
			maxForwards:  "1",
			wantUpstream: true,
			wantMF:       "0",
		},
		{
			name:         "OPTIONS MF=3 decremented to 2 and forwarded",
			method:       "OPTIONS",
			maxForwards:  "3",
			wantUpstream: true,
			wantMF:       "2",
		},
		{
			name:         "GET MF=5 not decremented",
			method:       "GET",
			maxForwards:  "5",
			wantUpstream: true,
			wantMF:       "5",
		},
		{
			name:         "TRACE absent MF not added",
			method:       "TRACE",
			maxForwards:  "", // absent
			wantUpstream: true,
			wantMF:       "", // must remain absent
		},
		{
			name:         "TRACE invalid MF forwarded unmodified",
			method:       "TRACE",
			maxForwards:  "not-a-number",
			wantUpstream: true,
			wantMF:       "not-a-number",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mfLine := ""
			if tc.maxForwards != "" {
				mfLine = fmt.Sprintf("Max-Forwards: %s\r\n", tc.maxForwards)
			}
			raw := fmt.Sprintf("%s http://example.com/ HTTP/1.1\r\nHost: example.com\r\n%s\r\n",
				tc.method, mfLine)

			resp, reqs := proxyRawRoundTrip(t, raw)
			defer func() { _ = resp.Body.Close() }()
			assertStatusCode(t, resp, http.StatusOK)

			if tc.wantUpstream {
				if len(reqs) != 1 {
					t.Fatalf("upstream received %d requests, want 1", len(reqs))
				}
				if tc.wantMF == "" {
					assertHeaderAbsent(t, reqs[0].Header, headerMaxForwards)
				} else if got := reqs[0].Header.Get(headerMaxForwards); got != tc.wantMF {
					t.Errorf("upstream Max-Forwards: want %q, got %q", tc.wantMF, got)
				}
			} else {
				if len(reqs) != 0 {
					t.Errorf("upstream received %d requests, want 0 (should be handled locally)", len(reqs))
				}
				// The local response body should be empty or minimal.
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				if len(body) != 0 {
					t.Errorf("expected empty body for MF=0 local response, got %d bytes: %q", len(body), body)
				}
				// OPTIONS MF=0: Allow header must be present per RFC 9110
				// §9.3.7, and carry the proxy's exact advertised method set
				// (RFC 9110 §10.1.1; PATCH per RFC 5789 §3.1). Pinning the
				// literal locks this HTTP-contract surface against drift —
				// asserting against allowMethods would be tautological.
				if tc.method == "OPTIONS" {
					const wantAllow = "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, CONNECT"
					if allow := resp.Header.Get(headerAllow); allow != wantAllow {
						t.Errorf("OPTIONS MF=0 Allow header = %q, want %q", allow, wantAllow)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// I1/I2 — Connection closed after response
// ---------------------------------------------------------------------------

// TestI1I2_ConnectionClosedAfterResponse verifies that the proxy closes the
// connection after the response for HTTP/1.0 clients (RFC 9112 §9.3) and
// when the client sends Connection: close (RFC 9112 §9.6).
func TestI1I2_ConnectionClosedAfterResponse(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "HTTP/1.0 connection closed (I1)",
			raw: "GET http://example.com/ HTTP/1.0\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
		},
		{
			// RFC 9112 §9.3: "A proxy server MUST NOT maintain a
			// persistent connection with an HTTP/1.0 client." The
			// legacy "Connection: Keep-Alive" token from the
			// HTTP/1.0 era does not override this MUST NOT.
			name: "HTTP/1.0 with Connection: Keep-Alive still closed (I1)",
			raw: "GET http://example.com/ HTTP/1.0\r\n" +
				"Host: example.com\r\n" +
				"Connection: Keep-Alive\r\n" +
				"\r\n",
		},
		{
			name: "Connection: close honored (I2)",
			raw: "GET http://example.com/ HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Connection: close\r\n" +
				"\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := NewMockUpstreamProxy(t, nil)
			t.Cleanup(upstream.Close)

			proxy := NewProxyUnderTest(t, upstream.Addr())
			t.Cleanup(proxy.Close)

			conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })

			if _, err := conn.Write([]byte(tc.raw)); err != nil {
				t.Fatalf("write raw request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			assertStatusCode(t, resp, http.StatusOK)
			_, _ = io.Copy(io.Discard, resp.Body)

			// After the response the proxy must close the connection.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1)
			n, readErr := conn.Read(buf)
			if n > 0 {
				t.Errorf("expected connection closed after response, got %d bytes: %q", n, buf[:n])
			}
			if readErr == nil {
				t.Error("expected error reading from closed connection, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// N2 — RFC 8470 §5.1: Early-Data header not removed
// ---------------------------------------------------------------------------

// TestN2_EarlyData_ForwardedToUpstream verifies that the proxy forwards the
// Early-Data header to the upstream without modification.
//
// RFC 8470 §5.1: intermediaries MUST NOT remove the Early-Data header. The
// proxy's hop-by-hop sanitization does not include Early-Data, so this is
// already satisfied structurally.
func TestN2_EarlyData_ForwardedToUpstream(t *testing.T) {
	upReq := proxyRoundTrip(t, http.Header{
		"Early-Data": {"1"},
	})

	assertHeaderPresent(t, upReq.Header, "Early-Data", "1")
}

// ---------------------------------------------------------------------------
// I1/I2 concurrent safety: verify proxy is safe under concurrent connections
// ---------------------------------------------------------------------------

// TestI1I2_ConcurrentConnectionsClosed verifies that under concurrent load,
// each connection is closed independently after its response, with no
// persistent connections or connection sharing.
func TestI1I2_ConcurrentConnectionsClosed(t *testing.T) {
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	t.Cleanup(proxy.Close)

	const numClients = 10
	var wg sync.WaitGroup
	errs := make(chan error, numClients)

	for i := range numClients {
		wg.Go(func() {
			conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
			if err != nil {
				errs <- fmt.Errorf("client %d: dial: %w", i, err)
				return
			}
			defer func() { _ = conn.Close() }()

			raw := fmt.Sprintf("GET http://example.com/concurrent/%d HTTP/1.0\r\nHost: example.com\r\n\r\n", i)
			if _, writeErr := conn.Write([]byte(raw)); writeErr != nil {
				errs <- fmt.Errorf("client %d: write: %w", i, writeErr)
				return
			}

			resp, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
			if readErr != nil {
				errs <- fmt.Errorf("client %d: read response: %w", i, readErr)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("client %d: want 200 OK, got %d", i, resp.StatusCode)
				return
			}

			// Connection must close after HTTP/1.0 response.
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1)
			n, connErr := conn.Read(buf)
			if n > 0 || connErr == nil {
				errs <- fmt.Errorf("client %d: expected closed connection, got %d bytes, err=%w", i, n, connErr)
			}
		})
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
