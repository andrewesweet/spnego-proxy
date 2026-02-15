package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const defaultMaxRedirects = 10

// isRedirect returns true if the HTTP status code is a redirect that may
// include a Location header worth following.
func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently,  // 301
		http.StatusFound,              // 302
		http.StatusSeeOther,           // 303
		http.StatusTemporaryRedirect,  // 307
		http.StatusPermanentRedirect:  // 308
		return true
	}
	return false
}

// redirectPreservesMethod returns true for redirect codes that require the
// client to replay the original method and body (307, 308).
func redirectPreservesMethod(code int) bool {
	return code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect
}

// resolveRedirectURL resolves a possibly-relative Location header value
// against the URL of the request that produced the redirect.
func resolveRedirectURL(base *url.URL, location string) (*url.URL, error) {
	ref, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("invalid Location header %q: %w", location, err)
	}
	return base.ResolveReference(ref), nil
}

// requestURL reconstructs the full URL from an inbound proxy-style HTTP
// request.  For a request like "GET http://host/path HTTP/1.1" the URL is
// already absolute.  We normalise it so downstream code can always rely on
// Scheme and Host being set.
func requestURL(req *http.Request) *url.URL {
	u := *req.URL
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Host == "" {
		u.Host = req.Host
	}
	return &u
}

// dialUpstreamPlainHTTP connects to the upstream proxy and returns the raw
// TCP connection.  The caller is responsible for writing the full
// proxy-style request (e.g. "GET http://… HTTP/1.1").
func dialUpstreamPlainHTTP(proxy string) (net.Conn, error) {
	return net.Dial("tcp", proxy)
}

// dialUpstreamHTTPS connects to the upstream proxy, issues a CONNECT request
// authenticated with SPNEGO, performs a TLS handshake, and returns the TLS
// connection ready for the caller to send an origin-form HTTP request.
func dialUpstreamHTTPS(proxy string, provider TokenProvider, targetHost string, debug bool) (net.Conn, error) {
	raw, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}

	token, err := provider.GetToken(proxy)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("SPNEGO token for CONNECT: %w", err)
	}

	// Send CONNECT request.
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetHost},
		Host:   targetHost,
		Header: http.Header{
			"Proxy-Authorization": {"Negotiate " + token},
		},
	}
	if err := connectReq.Write(raw); err != nil {
		raw.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw.Close()
		return nil, fmt.Errorf("CONNECT returned %s", resp.Status)
	}

	// TLS handshake over the tunnel.
	host, _, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// hostWithPort ensures the host string has an explicit port.
func hostWithPort(u *url.URL) string {
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		switch u.Scheme {
		case "https":
			host = net.JoinHostPort(host, "443")
		default:
			host = net.JoinHostPort(host, "80")
		}
	}
	return host
}

// sendHTTPRequestViaProxy sends a single HTTP request through the upstream
// proxy and returns the parsed response.  For plain HTTP targets the request
// is written in proxy (absolute-URI) form; for HTTPS targets a CONNECT
// tunnel with TLS is set up first and the request is written in origin form.
//
// The returned net.Conn and *bufio.Reader are provided so the caller can
// stream the response body and close the connection when done.
func sendHTTPRequestViaProxy(
	proxy string,
	provider TokenProvider,
	target *url.URL,
	method string,
	header http.Header,
	body io.Reader,
	protoMajor, protoMinor int,
	debug bool,
) (*http.Response, net.Conn, *bufio.Reader, error) {

	outReq := &http.Request{
		Method:     method,
		Header:     header.Clone(),
		Body:       io.NopCloser(body),
		Proto:      fmt.Sprintf("HTTP/%d.%d", protoMajor, protoMinor),
		ProtoMajor: protoMajor,
		ProtoMinor: protoMinor,
		Host:       target.Host,
	}

	// Remove hop-by-hop headers that should not be forwarded.
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")

	if target.Scheme == "https" {
		targetHostPort := hostWithPort(target)

		tlsConn, err := dialUpstreamHTTPS(proxy, provider, targetHostPort, debug)
		if err != nil {
			return nil, nil, nil, err
		}

		// Origin-form request over TLS.
		outReq.URL = &url.URL{
			Path:     target.Path,
			RawQuery: target.RawQuery,
		}
		if outReq.URL.Path == "" {
			outReq.URL.Path = "/"
		}

		if debug {
			logger.Printf("redirect-follow: HTTPS %s %s", method, target.String())
		}
		if err := outReq.Write(tlsConn); err != nil {
			tlsConn.Close()
			return nil, nil, nil, fmt.Errorf("write HTTPS request: %w", err)
		}
		br := bufio.NewReader(tlsConn)
		resp, err := http.ReadResponse(br, outReq)
		if err != nil {
			tlsConn.Close()
			return nil, nil, nil, fmt.Errorf("read HTTPS response: %w", err)
		}
		return resp, tlsConn, br, nil
	}

	// Plain HTTP — proxy (absolute-URI) form.
	conn, err := dialUpstreamPlainHTTP(proxy)
	if err != nil {
		return nil, nil, nil, err
	}

	token, err := provider.GetToken(proxy)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("SPNEGO token: %w", err)
	}
	outReq.Header.Set("Proxy-Authorization", "Negotiate "+token)
	outReq.URL = target

	if debug {
		logger.Printf("redirect-follow: HTTP %s %s", method, target.String())
	}
	if err := outReq.WriteProxy(conn); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("write HTTP request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("read HTTP response: %w", err)
	}
	return resp, conn, br, nil
}

// handleClientFollowRedirects handles an inbound HTTP proxy request with
// redirect following.  For CONNECT requests it falls back to normal pass-
// through behaviour handled by the caller.
func handleClientFollowRedirects(conn net.Conn, proxy string, provider TokenProvider, maxRedirects int, debug bool) {
	defer conn.Close()
	if debug {
		defer logger.Printf("stop processing request for client: %v", conn.RemoteAddr())
		logger.Printf("new client (follow-redirects): %v", conn.RemoteAddr())
	}

	reqReader := bufio.NewReader(conn)
	if debug {
		reqReader = bufio.NewReader(io.TeeReader(conn, logger.Writer()))
	}

	req, err := http.ReadRequest(reqReader)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Printf("failed to read request: %v", err)
		}
		return
	}

	// CONNECT requests establish opaque tunnels — fall back to the normal
	// pass-through path because we cannot inspect encrypted traffic.
	if req.Method == http.MethodConnect {
		handleCONNECTPassthrough(conn, req, reqReader, proxy, provider, debug)
		return
	}

	target := requestURL(req)
	method := req.Method
	hdr := req.Header.Clone()
	protoMajor := req.ProtoMajor
	protoMinor := req.ProtoMinor

	// Buffer the request body so it can be replayed for 307/308 redirects.
	// For 301/302/303 the body is dropped anyway.
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			logger.Printf("failed to read request body: %v", err)
			return
		}
	}

	var upstreamConn net.Conn
	for i := 0; ; i++ {
		var body io.Reader = http.NoBody
		if len(bodyBytes) > 0 {
			body = strings.NewReader(string(bodyBytes))
		}

		resp, uc, _, err := sendHTTPRequestViaProxy(
			proxy, provider, target, method, hdr, body, protoMajor, protoMinor, debug,
		)
		if err != nil {
			logger.Printf("upstream request failed: %v", err)
			return
		}
		upstreamConn = uc

		if !isRedirect(resp.StatusCode) || i >= maxRedirects {
			if i >= maxRedirects && isRedirect(resp.StatusCode) {
				logger.Printf("max redirects (%d) reached, returning redirect response to client", maxRedirects)
			}
			// Write the final response back to the client.
			if err := resp.Write(conn); err != nil {
				logger.Printf("failed writing response to client: %v", err)
			}
			upstreamConn.Close()
			return
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			// Redirect without Location — return as-is.
			if err := resp.Write(conn); err != nil {
				logger.Printf("failed writing response to client: %v", err)
			}
			upstreamConn.Close()
			return
		}

		// Drain and close redirect response body.
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		upstreamConn.Close()

		newTarget, err := resolveRedirectURL(target, loc)
		if err != nil {
			logger.Printf("bad redirect Location: %v", err)
			return
		}

		if debug {
			logger.Printf("redirect-follow: %d %s -> %s", resp.StatusCode, target.String(), newTarget.String())
		}

		if !redirectPreservesMethod(resp.StatusCode) {
			method = http.MethodGet
			bodyBytes = nil
		}

		target = newTarget
		// Update the Host header for the new target.
		hdr.Set("Host", target.Host)
	}
}

// handleCONNECTPassthrough handles a CONNECT request using the same
// pass-through tunnel logic as the original handleClient, but starting from
// an already-parsed request.
func handleCONNECTPassthrough(conn net.Conn, req *http.Request, reqReader *bufio.Reader, proxy string, provider TokenProvider, debug bool) {
	proxyConn, err := net.Dial("tcp", proxy)
	if err != nil {
		logger.Printf("failed to connect to proxy: %v", err)
		return
	}
	defer proxyConn.Close()

	token, err := provider.GetToken(proxy)
	if err != nil {
		logger.Printf("failed to get SPNEGO token: %v", err)
		return
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)

	if debug {
		req.WriteProxy(io.MultiWriter(proxyConn, logger.Writer()))
	} else {
		req.WriteProxy(proxyConn)
	}

	var wg sync.WaitGroup
	forward := func(from io.Reader, to net.Conn) {
		defer wg.Done()
		defer func() {
			if cw, ok := to.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()
		if debug {
			logger.Printf("forward start -> %v", to.RemoteAddr())
			defer logger.Printf("forward done -> %v", to.RemoteAddr())
		}
		io.Copy(to, from)
	}
	wg.Add(2)
	// Use reqReader (buffered) for client→proxy so any data already buffered
	// from reading the CONNECT request is not lost.
	go forward(reqReader, proxyConn)
	go forward(proxyConn, conn)
	wg.Wait()
}
