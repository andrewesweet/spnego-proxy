package proxy

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

// handleDialError logs and responds to a failed dial attempt. An empty path
// identifies an upstream dial; direct dials use "HTTP" or "CONNECT".
func (s *ClientSession) handleDialError(err error, target, path string) {
	pe := errConnectionRefused
	message := "noproxy direct dial failed"
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		pe = errConnectionTimeout
		message = "noproxy direct dial timeout"
	}
	if path == "" {
		slog.Error("failed to connect to proxy", "error", err, "error_type", pe.errorType, "client_addr", s.clientAddr, "upstream_addr", target)
	} else {
		slog.Error(message, "error", err, "target", target, "client_addr", s.clientAddr, "path", path)
	}
	writeHTTPError(s.conn, pe)
}

// logDirectError logs a failure on a direct (noproxy) connection: at Debug
// level for an expected connection close, at Error level otherwise. what
// names the failed step; the logged message is what + " closed" or
// what + " failed".
func (s *ClientSession) logDirectError(what string, err error, target string) {
	if isExpectedCloseError(err) {
		slog.Debug(what+" closed", "error", err, "target", target, "client_addr", s.clientAddr)
		return
	}
	slog.Error(what+" failed", "error", err, "target", target, "client_addr", s.clientAddr)
}

// forwardDirect forwards an HTTP request directly to the target host,
// bypassing the upstream proxy. Used for noproxy bypass of non-CONNECT
// requests. The request is converted from absolute-URI (proxy form) to
// origin form.
//
// The function runs a keep-alive loop bound to the original target host.
// Subsequent pipelined requests are re-parsed and validated; requests for
// a different host are rejected with errMismatchedTarget so a smuggled
// second request cannot ride the existing direct TCP connection to a
// target it was never authorised for.
func (s *ClientSession) forwardDirect(req *http.Request) {
	targetConn, target, err := dialDirect(req.Host, "80", s.cfg.DialTimeout)
	if err != nil {
		s.handleDialError(err, target, "HTTP")
		return
	}
	defer func() { _ = targetConn.Close() }()

	if s.cfg.KeepAlive > 0 {
		enableKeepAlive(s.conn, s.cfg.KeepAlive)
		enableKeepAlive(targetConn, s.cfg.KeepAlive)
	}

	boundHost := req.Host
	upstreamReader := bufio.NewReader(targetConn)

	for iter := 0; ; iter++ {
		if iter > 0 {
			if req = s.nextDirectRequest(boundHost, target, iter); req == nil {
				return
			}
		}
		if !s.relayDirect(req, targetConn, upstreamReader, target, iter) {
			return
		}
	}
}

// nextDirectRequest reads and validates the next pipelined request on an
// established direct connection and injects Via. It returns nil when the
// keep-alive loop must stop: the client stopped sending, validation
// rejected the request, the request targets a host this connection is not
// bound to, or it is a CONNECT that cannot tunnel on a connection already
// used for HTTP responses. Any client-facing error response has already
// been written in those cases.
func (s *ClientSession) nextDirectRequest(boundHost, target string, iter int) *http.Request {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	req, rerr := http.ReadRequest(s.reqReader)
	_ = s.conn.SetReadDeadline(time.Time{})
	if rerr != nil {
		slog.Debug("noproxy keep-alive loop ended", "error", rerr, "target", target, "iter", iter, "client_addr", s.clientAddr)
		return nil
	}
	proceed, pe := s.validateRequest(req)
	if !proceed {
		if pe != nil {
			writeHTTPError(s.conn, pe)
		}
		return nil
	}
	// A direct TCP connection is bound to a single target host;
	// reject pipelined requests for any other host.
	if !sameHost(req.Host, boundHost, "80") {
		slog.Warn("noproxy pipelined request targets different host", "bound_host", boundHost, "request_host", req.Host, "client_addr", s.clientAddr)
		writeHTTPError(s.conn, errMismatchedTarget)
		return nil
	}
	// CONNECT on a plain-HTTP direct connection: cannot tunnel
	// on a connection used for HTTP responses.
	if req.Method == http.MethodConnect {
		slog.Warn("noproxy pipelined CONNECT on HTTP connection", "client_addr", s.clientAddr)
		writeHTTPError(s.conn, errMismatchedTarget)
		return nil
	}
	injectVia(req.Header, req.Proto, s.cfg.Pseudonym)
	return req
}

// relayDirect writes one request to the direct target connection in origin
// form and relays the response back to the client with Via injected. It
// reports whether both connections may be reused for a further request;
// false means the connection must be closed, either because of an error or
// because a side signalled close.
func (s *ClientSession) relayDirect(req *http.Request, targetConn net.Conn, upstreamReader *bufio.Reader, target string, iter int) bool {
	// Write request in origin form (not proxy form).
	if err := req.Write(targetConn); err != nil {
		s.logDirectError("noproxy write request", err, target)
		writeHTTPError(s.conn, errConnectionTerminated)
		return false
	}

	slog.Debug("noproxy HTTP response forwarding start", "target", target, "client_addr", s.clientAddr, "iter", iter)
	resp, rerr := http.ReadResponse(upstreamReader, req)
	if rerr != nil {
		s.logDirectError("noproxy read response", rerr, target)
		return false
	}
	injectVia(resp.Header, resp.Proto, s.cfg.Pseudonym)
	if writeErr, derr := writeResponse(s.conn, resp); writeErr != nil {
		s.logDirectError("noproxy forward response", writeErr, target)
		return false
	} else if derr != nil {
		slog.Debug("noproxy upstream body drain failed, closing connection", "error", derr, "target", target, "client_addr", s.clientAddr)
		return false
	}
	slog.Debug("noproxy HTTP response forwarding done", "target", target, "client_addr", s.clientAddr, "iter", iter)
	return !connectionWillClose(req, resp)
}

// tunnelDirect establishes a direct TCP tunnel to the target host,
// bypassing the upstream proxy. Used for noproxy bypass of CONNECT requests.
// Via is injected on the 200 response (not on req.Header, which is never
// forwarded for CONNECT tunnels). targetConn is method-local (the noproxy
// connection is single-target and never reused as s.proxyConn).
func (s *ClientSession) tunnelDirect(req *http.Request) {
	targetConn, target, err := dialDirect(req.Host, "443", s.cfg.DialTimeout)
	if err != nil {
		s.handleDialError(err, target, "CONNECT")
		return
	}
	defer func() { _ = targetConn.Close() }()

	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	injectVia(resp.Header, req.Proto, s.cfg.Pseudonym)
	if err := writeConnectOK(s.conn, resp); err != nil {
		s.logDirectError("noproxy CONNECT response write", err, target)
		return
	}

	if s.cfg.KeepAlive > 0 {
		enableKeepAlive(s.conn, s.cfg.KeepAlive)
		enableKeepAlive(targetConn, s.cfg.KeepAlive)
	}

	slog.Debug("noproxy CONNECT tunnel established", "target", target, "client_addr", s.clientAddr)
	forwardTunnel(s.conn, targetConn, s.reqReader, bufio.NewReader(targetConn), s.cfg.IdleTimeout)
}
