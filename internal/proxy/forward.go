package proxy

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// validateRequest runs the per-request validation pipeline shared by
// every iteration of the client-facing keep-alive loop (issue #215). It
// performs, in order: Via loop detection, CONNECT port allowlist,
// Max-Forwards decrement (with local response for the terminal case), and
// hop-by-hop header sanitisation.
//
// Return values:
//   - proceed=true, pe=nil      → forward the request.
//   - proceed=false, pe=nil     → proxy already wrote a local response
//     (Max-Forwards: 0); caller should stop reading further requests.
//   - proceed=false, pe!=nil    → reject; caller must writeHTTPError(pe)
//     and stop reading further requests.
//
// Noproxy matching and forwarding-header injection are NOT performed here;
// they are caller-side routing decisions that vary by call site.
func (s *ClientSession) validateRequest(req *http.Request) (proceed bool, pe *proxyError) {
	// RFC 9110 §7.6.3: loop detection must run BEFORE sanitizeHopByHop so
	// that a client sending "Connection: Via" cannot strip Via and bypass
	// the check.
	if prior := req.Header.Get(headerVia); prior != "" && strings.Contains(prior, s.cfg.Pseudonym) {
		slog.Warn("proxy loop detected", "via", prior, "pseudonym", s.cfg.Pseudonym, "client_addr", s.clientAddr, "method", req.Method, "host", req.Host)
		return false, errProxyLoopDetected
	}

	// D4 (RFC 9110 §9.3.6): restrict CONNECT to allowed ports.
	if req.Method == http.MethodConnect && len(s.cfg.ConnectPorts) > 0 {
		_, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			slog.Debug("CONNECT host has no explicit port, defaulting to 443", "host", req.Host, "error", err, "client_addr", s.clientAddr)
			port = "443"
		}
		if !connectPortAllowed(port, s.cfg.ConnectPorts) {
			slog.Warn("CONNECT port not allowed", "host", req.Host, "port", port, "client_addr", s.clientAddr)
			return false, errForbiddenPort
		}
	}

	// G1 (RFC 9110 §7.6.2): TRACE/OPTIONS Max-Forwards.
	if !s.applyMaxForwards(req) {
		return false, nil
	}

	// Hop-by-hop sanitisation (RFC 9110 §7.6.1) — runs on every
	// iteration so a smuggled Proxy-Authorization cannot ride an
	// already-authenticated upstream connection.
	sanitizeHopByHop(req)
	return true, nil
}

// applyMaxForwards implements the G1 (RFC 9110 §7.6.2) Max-Forwards rule for
// TRACE and OPTIONS: decrement the header when it carries a positive count,
// leave a non-numeric value untouched, and answer locally when the count has
// reached zero. It reports whether the request should still be forwarded;
// false means a local response has already been written.
func (s *ClientSession) applyMaxForwards(req *http.Request) bool {
	if req.Method != http.MethodTrace && req.Method != http.MethodOptions {
		return true
	}
	mf := req.Header.Get(headerMaxForwards)
	if mf == "" {
		return true
	}
	switch n, err := strconv.Atoi(mf); {
	case err != nil:
		slog.Debug("non-numeric Max-Forwards value, forwarding unmodified", "max_forwards", mf, "client_addr", s.clientAddr)
	case n <= 0:
		slog.Debug("Max-Forwards: 0, responding locally", "method", req.Method, "client_addr", s.clientAddr)
		writeMaxForwardsResponse(s.conn, req)
		return false
	default:
		req.Header.Set(headerMaxForwards, strconv.Itoa(n-1))
	}
	return true
}

// connectionWillClose reports whether either side has signalled that the
// connection should not be reused after the current request/response
// exchange. RFC 9112 §9.3 forbids persistent connections with HTTP/1.0
// clients even when they send "Connection: Keep-Alive"; the stdlib's
// req.Close / resp.Close flags cover the other cases (Connection: close
// on either side, HTTP/1.0 without keep-alive).
func connectionWillClose(req *http.Request, resp *http.Response) bool {
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return true
	}
	return req.Close || resp.Close
}

// dialAndAuthUpstream acquires a SPNEGO token, sets Proxy-Authorization on
// req, dials the upstream proxy, and enables TCP keepalive on both
// sockets when configured. On any failure it writes a proxyError to the
// client conn and returns nil. Returns the open upstream connection on
// success. The connection is RETURNED rather than stored on the session:
// the keep-alive path assigns it to s.proxyConn (reused across iterations)
// while tunnelViaUpstream keeps it method-local (fresh per CONNECT), so
// the two must not alias.
func (s *ClientSession) dialAndAuthUpstream(req *http.Request) net.Conn {
	token, terr := s.cfg.Provider.GetToken()
	if terr != nil {
		pe := tokenErrorToProxyError(terr)
		slog.Error("failed to get SPNEGO token", "error", terr, "error_type", pe.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(s.conn, pe)
		return nil
	}
	req.Header.Set(headerProxyAuthorization, negotiateScheme+token)

	proxyConn, derr := dialUpstream(s.cfg.Upstream, s.cfg.UpstreamTLS)
	if derr != nil {
		var ne net.Error
		if errors.As(derr, &ne) && ne.Timeout() {
			slog.Error("failed to connect to proxy", "error", derr, "error_type", errConnectionTimeout.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream)
			writeHTTPError(s.conn, errConnectionTimeout)
		} else {
			slog.Error("failed to connect to proxy", "error", derr, "error_type", errConnectionRefused.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream)
			writeHTTPError(s.conn, errConnectionRefused)
		}
		return nil
	}
	if s.cfg.KeepAlive > 0 {
		enableKeepAlive(s.conn, s.cfg.KeepAlive)
		enableKeepAlive(proxyConn, s.cfg.KeepAlive)
	}
	return proxyConn
}

// handleClient handles a single client connection. cfg groups all
// non-connection parameters including upstream address, token provider,
// timeouts, CONNECT port restrictions (D4, RFC 9110 §9.3.6), and
// forwarding header injection (RFC 7239 Forwarded, X-Forwarded-For, etc.).
//
// handleClient is the stable seam called by Serve and the test harness;
// its signature is deliberately unchanged. It performs the connection-level
// guards (pseudonym, IP allowlist), owns the conn close / closeWrite and
// proxyConn cleanup defers (issue #75 LIFO ordering), constructs the
// per-connection ClientSession, and delegates the request lifecycle to
// ClientSession.run. All per-connection handlers are methods on
// ClientSession; cfg is no longer threaded through them individually.
func handleClient(conn net.Conn, cfg Config) {
	defer func() { _ = conn.Close() }()
	// Half-close the write half before the full close so the client
	// reads EOF on the response stream rather than receiving a RST that
	// could discard buffered response bytes (issue #75). Deferred AFTER
	// conn.Close so it runs FIRST (LIFO order).
	defer closeWrite(conn)
	if cfg.Pseudonym == "" {
		slog.Error("empty pseudonym in ProxyConfig, refusing connection", "client_addr", conn.RemoteAddr())
		return
	}
	clientAddr := conn.RemoteAddr().String()

	// Check IP allowlist before processing anything.
	if len(cfg.AllowedIPs) > 0 {
		clientHost := extractHost(clientAddr)
		if !ipAllowed(net.ParseIP(clientHost), cfg.AllowedIPs) {
			slog.Warn("client IP not in allowlist", "client_addr", clientAddr)
			writeHTTPError(conn, errClientDenied)
			// Drain any unread client data so the kernel can perform a
			// graceful FIN-based close rather than sending a TCP RST.
			// A RST would discard the server's send buffer, causing the
			// client to receive a truncated error response.
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = io.Copy(io.Discard, conn)
			return
		}
	}

	slog.Debug("new client", "client_addr", clientAddr)
	defer slog.Debug("stop processing request", "client_addr", clientAddr)

	s := &ClientSession{
		conn:       conn,
		cfg:        cfg,
		clientAddr: clientAddr,
		reqReader:  bufio.NewReader(conn),
	}
	defer func() {
		if s.proxyConn != nil {
			_ = s.proxyConn.Close()
		}
	}()

	s.run()
}

// run executes the client-facing keep-alive loop: read a request, run the
// validation pipeline, route it (noproxy bypass, CONNECT-via-upstream, or
// plain HTTP through the upstream proxy), and repeat until either side
// signals close or an error occurs. The session's conn close / closeWrite
// and proxyConn cleanup defers stay in handleClient and fire when run
// returns, preserving the issue #75 LIFO ordering.
func (s *ClientSession) run() {
	for iter := 0; ; iter++ {
		req := s.readNextRequest(iter)
		if req == nil {
			return
		}

		proceed, pe := s.validateRequest(req)
		if !proceed {
			if pe != nil {
				writeHTTPError(s.conn, pe)
			}
			return
		}

		// Noproxy bypass and CONNECT-via-upstream both terminate the
		// keep-alive loop: neither can share the authenticated upstream
		// connection with further HTTP requests.
		if s.routeNoProxy(req) {
			return
		}
		if req.Method == http.MethodConnect {
			s.tunnelViaUpstream(req)
			return
		}

		if !s.relayViaUpstream(req, iter) {
			return
		}
	}
}

// readNextRequest reads the next request from the client connection under
// the read timeout. It returns nil when no further request will arrive:
// iteration 0 distinguishes an expected close from a malformed request (and
// answers the latter with a 400), while a failure on a later iteration just
// ends the keep-alive loop.
func (s *ClientSession) readNextRequest(iter int) *http.Request {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	req, err := http.ReadRequest(s.reqReader)
	_ = s.conn.SetReadDeadline(time.Time{})
	if err == nil {
		return req
	}
	switch {
	case iter > 0:
		slog.Debug("keep-alive loop ended", "error", err, "iter", iter, "client_addr", s.clientAddr)
	case isExpectedCloseError(err):
		slog.Debug("client connection closed before request", "error", err, "client_addr", s.clientAddr)
	default:
		slog.Error("failed to read request", "error", err, "error_type", errHTTPRequestError.errorType, "client_addr", s.clientAddr)
		writeHTTPError(s.conn, errHTTPRequestError)
	}
	return nil
}

// routeNoProxy handles a request whose host matches the noproxy matcher by
// dialling the target directly, bypassing the upstream proxy and SPNEGO. It
// reports whether it took the request; false means the caller must route it
// via the upstream proxy.
func (s *ClientSession) routeNoProxy(req *http.Request) bool {
	if s.cfg.NoProxy == nil {
		return false
	}
	matched, pattern := s.cfg.NoProxy.Match(req.Host)
	if !matched {
		return false
	}
	slog.Debug("noproxy bypass", "host", req.Host, "pattern", pattern, "method", req.Method, "client_addr", s.clientAddr)
	if req.Method == http.MethodConnect {
		s.tunnelDirect(req)
		return true
	}
	injectVia(req.Header, req.Proto, s.cfg.Pseudonym)
	s.forwardDirect(req)
	return true
}

// relayViaUpstream forwards one plain-HTTP request through the upstream
// proxy and relays the response to the client. The upstream connection is
// lazy-dialled on the first such request and the SPNEGO-authenticated
// connection is reused on subsequent ones (RFC 4559 §5). It reports whether
// the client connection may carry a further request; false means it must be
// closed, either because of an error or because a side signalled close.
func (s *ClientSession) relayViaUpstream(req *http.Request, iter int) bool {
	injectForwardingHeaders(req, s.clientAddr, s.cfg.Forwarding)
	if s.proxyConn == nil {
		s.proxyConn = s.dialAndAuthUpstream(req)
		if s.proxyConn == nil {
			return false
		}
		s.upstreamReader = bufio.NewReader(s.proxyConn)
	}
	injectVia(req.Header, req.Proto, s.cfg.Pseudonym)

	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "via", req.Header.Get(headerVia), "iter", iter)
	if err := req.WriteProxy(s.proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(s.conn, errConnectionTerminated)
		return false
	}

	resp, err := readUpstreamResponse(s.upstreamReader, req, s.cfg.Pseudonym)
	if err != nil {
		handleUpstreamResponseError(s.conn, s.proxyConn, err, s.clientAddr)
		return false
	}

	if writeErr := resp.Write(s.conn); writeErr != nil {
		_ = resp.Body.Close()
		logForwardError(writeErr, s.proxyConn.RemoteAddr(), s.conn.RemoteAddr())
		return false
	}
	// Drain any unread body so upstreamReader is aligned for the
	// next iteration; resp.Write already consumed it for well-framed
	// responses. If the drain fails the reader may be mid-body and
	// reusing it for the next request risks response misframing —
	// close the connection instead of continuing the keep-alive loop.
	if _, derr := io.Copy(io.Discard, resp.Body); derr != nil {
		_ = resp.Body.Close()
		slog.Debug("upstream body drain failed, closing connection", "error", derr, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream)
		return false
	}
	_ = resp.Body.Close()

	return !connectionWillClose(req, resp)
}

// tunnelViaUpstream performs the CONNECT-via-upstream-proxy flow:
// inject forwarding headers, acquire a SPNEGO token, dial a FRESH upstream
// connection, send the CONNECT request, and hand off to handleConnectTunnel.
// A fresh connection is required because a CONNECT tunnel co-opts the
// entire upstream connection for opaque bytes; it must not share with
// prior keep-alive HTTP traffic on the same socket. The fresh proxyConn is
// therefore a method-local connection with its own deferred Close and is
// never stored on the session (s.proxyConn is the reused keep-alive conn).
func (s *ClientSession) tunnelViaUpstream(req *http.Request) {
	injectForwardingHeaders(req, s.clientAddr, s.cfg.Forwarding)

	proxyConn := s.dialAndAuthUpstream(req)
	if proxyConn == nil {
		return
	}
	defer func() { _ = proxyConn.Close() }()
	injectVia(req.Header, req.Proto, s.cfg.Pseudonym)

	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "via", req.Header.Get(headerVia))
	if err := req.WriteProxy(proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(s.conn, errConnectionTerminated)
		return
	}

	handleConnectTunnel(s.conn, proxyConn, s.reqReader, req, s.cfg.Pseudonym, s.clientAddr, s.cfg.IdleTimeout)
}
