package proxy

import (
	"bufio"
	"context"
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
		s.handleDialError(derr, s.cfg.Upstream, "")
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
// handleClient is the stable test-harness seam. It delegates to handleClientCtx
// with a background context, so callers retain the same signature without
// participating in Serve's shutdown lifecycle.
func handleClient(conn net.Conn, cfg Config) {
	handleClientCtx(context.Background(), conn, cfg)
}

// handleClientCtx is Serve's session entry point. It performs the connection-level
// guards (pseudonym, IP allowlist), owns the conn close / closeWrite and proxyConn
// cleanup defers (issue #75 LIFO ordering), constructs the per-connection
// ClientSession, and delegates the request lifecycle to ClientSession.run.
// Context cancellation closes an idle connection immediately and ends a busy
// HTTP connection after its response. When endAfterResponse observes cancellation
// before the response is written, it marks that response Connection: close (D8).
func handleClientCtx(ctx context.Context, conn net.Conn, cfg Config) {
	defer func() { _ = conn.Close() }()
	// Half-close the write half before the full close so the client
	// reads EOF on the response stream rather than receiving a RST that
	// could discard buffered response bytes (issue #75). Deferred AFTER
	// conn.Close so it runs FIRST (LIFO order).
	defer func() { _ = closeWrite(conn) }()
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
	// Shutdown closes a connection that is idle between requests at once: the
	// blocked request read would otherwise hold the drain for its whole
	// read-timeout. A busy connection is left alone so the request in flight
	// still gets an answer.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			s.beginShutdown()
		case <-stopWatch:
		}
	}()
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
// signals close or an error occurs. Connection cleanup follows handleClientCtx's
// ownership rules when run returns.
func (s *ClientSession) run() {
	// pending carries a request that arrived on a direct (noproxy) connection
	// which is bound to another host: it has already been read and must now
	// be routed again on a fresh connection instead of being refused (D6).
	var pending *http.Request
	for iter := 0; ; iter++ {
		req := pending
		if req == nil {
			req = s.readNextRequest(iter)
			if req == nil {
				return
			}
		}

		proceed, pe := s.validateRequest(req)
		if !proceed {
			if pe != nil {
				writeHTTPError(s.conn, pe)
			}
			return
		}

		next, cont := s.routeRequest(req, iter)
		if !cont {
			return
		}
		pending = next
	}
}

// routeRequest sends one validated request down the routing decision:
// noproxy bypass, CONNECT-via-upstream, or plain HTTP through the upstream
// proxy. It reports whether the session may continue, and returns a non-nil
// request when the request could not be served on the direct connection it
// arrived on: the caller must route that request again, which is what keeps
// a direct connection bound to the single host it was dialled for.
func (s *ClientSession) routeRequest(req *http.Request, iter int) (*http.Request, bool) {
	if s.cfg.NoProxy != nil {
		if matched, pattern := s.cfg.NoProxy.Match(req.Host); matched {
			slog.Debug("noproxy bypass", "host", req.Host, "pattern", pattern, "method", req.Method, "client_addr", s.clientAddr)
			if req.Method == http.MethodConnect {
				s.tunnelDirect(req)
				return nil, false
			}
			injectVia(req.Header, req.Proto, s.cfg.Pseudonym)
			return s.forwardDirect(req)
		}
	}
	// CONNECT-via-upstream terminates the keep-alive loop: a tunnel cannot
	// share the authenticated upstream connection with further HTTP requests.
	if req.Method == http.MethodConnect {
		s.tunnelViaUpstream(req)
		return nil, false
	}
	if !s.relayViaUpstream(req, iter) {
		return nil, false
	}
	return nil, true
}

// errSessionShutdown reports that the session stopped waiting for the next
// request because shutdown started.
var errSessionShutdown = errors.New("proxy: shutdown")

// readRequest reads the next request from the client under the read timeout.
// The session counts as idle while it waits, which lets shutdown close the
// connection at once instead of waiting for the deadline (D8).
func (s *ClientSession) readRequest() (*http.Request, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
	// Publish the idle wait and check for shutdown in one step: beginShutdown
	// either sees idle and closes the connection, or this sees shutdown and
	// returns without waiting for a request that will never be served.
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil, errSessionShutdown
	}
	s.idle = true
	s.mu.Unlock()
	req, err := http.ReadRequest(s.reqReader)
	s.mu.Lock()
	s.idle = false
	shutdown := s.shutdown
	s.mu.Unlock()
	_ = s.conn.SetReadDeadline(time.Time{})
	if shutdown {
		// A request that finished parsing after beginShutdown ran is dropped:
		// shutdown may already have closed the connection, so routing it would
		// write its response to a dead socket. err can be nil here because the
		// request bytes were already buffered.
		return nil, errSessionShutdown
	}
	return req, err
}

// beginShutdown records that Serve is shutting down and closes the client
// connection when the session is idle between requests. A busy session is
// left open so the request in flight still gets its answer; its response is
// marked Connection: close so the connection ends after it (D8).
func (s *ClientSession) beginShutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdown = true
	if s.idle {
		_ = s.conn.Close()
	}
}

// endAfterResponse and the response write are one step: writeResponse marks
// the response with Connection: close when shutdown has already started, under
// the same lock beginShutdown takes, so the decision cannot race the
// serialization.

// readNextRequest reads the next request from the client connection under
// the read timeout. It returns nil when no further request will arrive:
// iteration 0 distinguishes an expected close from a malformed request (and
// answers the latter with a 400), while a failure on a later iteration just
// ends the keep-alive loop.
func (s *ClientSession) readNextRequest(iter int) *http.Request {
	req, err := s.readRequest()
	if err == nil {
		return req
	}
	switch {
	case errors.Is(err, errSessionShutdown):
		slog.Debug("shutdown, closing idle connection", "iter", iter, "client_addr", s.clientAddr)
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
	resp, requestErr, clientErr, rerr := exchangeRequest(s.conn, s.proxyConn, req, func() error {
		return req.WriteProxy(s.proxyConn)
	}, func() (*http.Response, error) {
		return readUpstreamResponse(s.upstreamReader, req, s.cfg.Pseudonym)
	})
	if requestErr != nil {
		slog.Error("failed to write request to proxy", "error", requestErr, "error_type", errConnectionTerminated.errorType, "client_addr", s.clientAddr, "upstream_addr", s.cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(s.conn, errConnectionTerminated)
		return false
	}
	if clientErr != nil {
		logForwardError(clientErr, s.proxyConn.RemoteAddr(), s.conn.RemoteAddr())
		return false
	}
	if rerr != nil {
		handleUpstreamResponseError(s.conn, s.proxyConn, rerr, s.clientAddr)
		return false
	}

	if err := s.writeResponse(resp); err != nil {
		logForwardError(err, s.proxyConn.RemoteAddr(), s.conn.RemoteAddr())
		return false
	}

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

// writeResponse relays one response to the client. The shutdown decision and
// the write are serialized under the session lock, so beginShutdown either
// runs before the response is serialized — which marks it — or after it has
// been written completely: a response written during shutdown always carries
// Connection: close (D8). Response.Write reads the body to its end and closes
// it, so no separate drain follows: a read or close failure on the body comes
// back from Write as the error, and callers treat it as fatal because a failed
// write leaves the client stream misaligned (D2).
func (s *ClientSession) writeResponse(resp *http.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		resp.Close = true
	}
	err := resp.Write(s.conn)
	// Write has already closed the body when it succeeded; this close only
	// releases it on the error path.
	_ = resp.Body.Close()
	return err
}
