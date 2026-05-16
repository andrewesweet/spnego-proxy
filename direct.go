package main

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// stripIPv6Brackets removes one surrounding "[]" pair from a bare bracketed
// IPv6 literal that has no port (e.g. "[::1]" -> "::1"). It is a no-op for any
// other input. Used on host-canonicalisation paths where net.SplitHostPort has
// already failed (no port present).
func stripIPv6Brackets(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// sameHost reports whether two HTTP Host values refer to the same
// target. It canonicalises by lower-casing and applying defaultPort when a
// host has no explicit port. Bracketed IPv6 addresses without a port (e.g.
// "[::1]") are normalised to "[::1]:<defaultPort>" so they match the same
// IPv6 address written with an explicit port.
func sameHost(a, b, defaultPort string) bool {
	canon := func(h string) string {
		h = strings.ToLower(strings.TrimSpace(h))
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			host = h
			port = defaultPort
			// Strip brackets so net.JoinHostPort below re-adds them once.
			host = stripIPv6Brackets(host)
		}
		return net.JoinHostPort(host, port)
	}
	return canon(a) == canon(b)
}

// dialDirect dials a target host directly, defaulting to defaultPort when
// the host has no explicit port. Used by both noproxy bypass paths.
func dialDirect(host, defaultPort string, timeout time.Duration) (net.Conn, string, error) {
	target := host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, defaultPort)
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", target)
	return conn, target, err
}

// handleDialError logs and responds to a failed direct dial attempt.
func handleDialError(conn net.Conn, err error, target, clientAddr, path string) {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		slog.Error("noproxy direct dial timeout", "error", err, "target", target, "client_addr", clientAddr, "path", path)
		writeHTTPError(conn, errConnectionTimeout)
	} else {
		slog.Error("noproxy direct dial failed", "error", err, "target", target, "client_addr", clientAddr, "path", path)
		writeHTTPError(conn, errConnectionRefused)
	}
}

// handleDirectHTTP forwards an HTTP request directly to the target host,
// bypassing the upstream proxy. Used for noproxy bypass of non-CONNECT
// requests. The request is converted from absolute-URI (proxy form) to
// origin form.
//
// The function runs a keep-alive loop bound to the original target host.
// Subsequent pipelined requests are re-parsed and validated; requests for
// a different host are rejected with errMismatchedTarget so a smuggled
// second request cannot ride the existing direct TCP connection to a
// target it was never authorised for.
func handleDirectHTTP(conn net.Conn, req *http.Request, reqReader *bufio.Reader, cfg ProxyConfig, clientAddr string) {
	targetConn, target, err := dialDirect(req.Host, "80", cfg.DialTimeout)
	if err != nil {
		handleDialError(conn, err, target, clientAddr, "HTTP")
		return
	}
	defer func() { _ = targetConn.Close() }()

	if cfg.KeepAlive > 0 {
		enableKeepAlive(conn, cfg.KeepAlive)
		enableKeepAlive(targetConn, cfg.KeepAlive)
	}

	boundHost := req.Host
	upstreamReader := bufio.NewReader(targetConn)

	for iter := 0; ; iter++ {
		if iter > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
			nextReq, rerr := http.ReadRequest(reqReader)
			_ = conn.SetReadDeadline(time.Time{})
			if rerr != nil {
				slog.Debug("noproxy keep-alive loop ended", "error", rerr, "target", target, "iter", iter, "client_addr", clientAddr)
				return
			}
			proceed, pe := prepareForwardRequest(conn, nextReq, cfg, clientAddr)
			if !proceed {
				if pe != nil {
					writeHTTPError(conn, pe)
				}
				return
			}
			// A direct TCP connection is bound to a single target host;
			// reject pipelined requests for any other host.
			if !sameHost(nextReq.Host, boundHost, "80") {
				slog.Warn("noproxy pipelined request targets different host", "bound_host", boundHost, "request_host", nextReq.Host, "client_addr", clientAddr)
				writeHTTPError(conn, errMismatchedTarget)
				return
			}
			// CONNECT on a plain-HTTP direct connection: cannot tunnel
			// on a connection used for HTTP responses.
			if nextReq.Method == http.MethodConnect {
				slog.Warn("noproxy pipelined CONNECT on HTTP connection", "client_addr", clientAddr)
				writeHTTPError(conn, errMismatchedTarget)
				return
			}
			injectVia(nextReq.Header, nextReq.Proto, cfg.Pseudonym)
			req = nextReq
		}

		// Write request in origin form (not proxy form).
		if err := req.Write(targetConn); err != nil {
			if isExpectedCloseError(err) {
				slog.Debug("noproxy write request closed", "error", err, "target", target, "client_addr", clientAddr)
			} else {
				slog.Error("noproxy write request failed", "error", err, "target", target, "client_addr", clientAddr)
			}
			writeHTTPError(conn, errConnectionTerminated)
			return
		}

		slog.Debug("noproxy HTTP response forwarding start", "target", target, "client_addr", clientAddr, "iter", iter)
		resp, rerr := http.ReadResponse(upstreamReader, req)
		if rerr != nil {
			if isExpectedCloseError(rerr) {
				slog.Debug("noproxy read response closed", "error", rerr, "target", target, "client_addr", clientAddr)
			} else {
				slog.Error("noproxy read response failed", "error", rerr, "target", target, "client_addr", clientAddr)
			}
			return
		}
		injectVia(resp.Header, resp.Proto, cfg.Pseudonym)
		writeErr := resp.Write(conn)
		if writeErr != nil {
			_ = resp.Body.Close()
			if isExpectedCloseError(writeErr) {
				slog.Debug("noproxy forward response closed", "error", writeErr, "target", target, "client_addr", clientAddr)
			} else {
				slog.Error("noproxy forward response failed", "error", writeErr, "target", target, "client_addr", clientAddr)
			}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		slog.Debug("noproxy HTTP response forwarding done", "target", target, "client_addr", clientAddr, "iter", iter)

		if connectionWillClose(req, resp) {
			return
		}
	}
}

// handleDirectConnect establishes a direct TCP tunnel to the target host,
// bypassing the upstream proxy. Used for noproxy bypass of CONNECT requests.
// Via is injected on the 200 response (not on req.Header, which is never
// forwarded for CONNECT tunnels).
func handleDirectConnect(conn net.Conn, req *http.Request, reqReader *bufio.Reader, cfg ProxyConfig, clientAddr string) {
	targetConn, target, err := dialDirect(req.Host, "443", cfg.DialTimeout)
	if err != nil {
		handleDialError(conn, err, target, clientAddr, "CONNECT")
		return
	}
	defer func() { _ = targetConn.Close() }()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	injectVia(resp.Header, req.Proto, cfg.Pseudonym)
	if err := writeConnectOK(conn, resp); err != nil {
		if isExpectedCloseError(err) {
			slog.Debug("noproxy CONNECT response write closed", "error", err, "target", target, "client_addr", clientAddr)
		} else {
			slog.Error("noproxy CONNECT response write failed", "error", err, "target", target, "client_addr", clientAddr)
		}
		return
	}

	if cfg.KeepAlive > 0 {
		enableKeepAlive(conn, cfg.KeepAlive)
		enableKeepAlive(targetConn, cfg.KeepAlive)
	}

	slog.Debug("noproxy CONNECT tunnel established", "target", target, "client_addr", clientAddr)
	var wg sync.WaitGroup
	wg.Go(func() {
		forwardHalf(targetConn, reqReader, conn, conn.RemoteAddr(), targetConn.RemoteAddr(), cfg.IdleTimeout)
	})
	wg.Go(func() {
		forwardHalf(conn, bufio.NewReader(targetConn), targetConn, targetConn.RemoteAddr(), conn.RemoteAddr(), cfg.IdleTimeout)
	})
	wg.Wait()
}
