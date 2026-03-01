// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
)

var logLevel = new(slog.LevelVar) // default Info

func init() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
}

// extractHost returns the host portion of addr, stripping any port suffix.
// If addr has no port, it is returned unchanged.
func extractHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// normalizeSPN converts an explicit SPN between GSS-API hostbased format
// (service@host) and Kerberos principal format (service/host) so the user
// need not know which backend is active. targetSep is the separator the
// active backend expects ('@' for GSS-API, '/' for gokrb5); alternateSep
// is the other backend's separator.
func normalizeSPN(spn string, targetSep, alternateSep byte) string {
	if strings.IndexByte(spn, targetSep) >= 0 {
		return spn // already contains the target separator
	}
	if i := strings.IndexByte(spn, alternateSep); i >= 0 {
		return spn[:i] + string(targetSep) + spn[i+1:]
	}
	return spn // no recognized separator; return as-is
}

// ForwardingConfig controls which forwarding headers the proxy injects into
// outbound requests.
//
// Both fields default to false (disabled) to preserve the existing behaviour
// where no forwarding headers are added. Operators opt in via CLI flags.
type ForwardingConfig struct {
	// ForwardedEnabled enables the RFC 7239 Forwarded header (H1).
	// The header uses an obfuscated identifier for the client address.
	ForwardedEnabled bool

	// XForwardedForEnabled enables the de-facto X-Forwarded-For header (H2)
	// and, when the headers are absent, also sets X-Forwarded-Proto (H3) and
	// X-Forwarded-Host (H4).
	XForwardedForEnabled bool
}

// ProxyConfig groups the non-connection parameters for handleClient.
type ProxyConfig struct {
	Upstream     string
	Provider     TokenProvider
	Pseudonym    string
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	KeepAlive    time.Duration
	IdleTimeout  time.Duration
	ConnectPorts []string
	Forwarding   ForwardingConfig
}

// randomHex returns n random bytes encoded as 2*n lowercase hex characters.
// If the OS entropy source is unavailable, the process exits immediately.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		slog.Error("entropy source failure: crypto/rand is unavailable", "error", err)
		os.Exit(1)
	}
	return hex.EncodeToString(b)
}

// generateObfuscatedID returns a random RFC 7239 §6.3 obfuscated identifier
// of the form "_xxxxxxxx" (underscore followed by 8 lowercase hex characters).
// Using 4 random bytes gives 2^32 unique values — sufficient to avoid
// collisions in practice while keeping the identifier short.
func generateObfuscatedID() string {
	return "_" + randomHex(4)
}

// appendHeaderValue appends value to the existing comma-separated header
// identified by key, or sets it when the header is absent.
func appendHeaderValue(header http.Header, key, value string) {
	if existing := header.Get(key); existing != "" {
		header.Set(key, existing+", "+value)
	} else {
		header.Set(key, value)
	}
}

// injectForwardingHeaders adds RFC 7239 Forwarded and/or de-facto
// X-Forwarded-* headers to the request according to fwdCfg. It is called
// after sanitizeHopByHop so that any client-supplied hop-by-hop headers have
// already been stripped before we append our own values.
func injectForwardingHeaders(req *http.Request, clientAddr string, fwdCfg ForwardingConfig) {
	if !fwdCfg.ForwardedEnabled && !fwdCfg.XForwardedForEnabled {
		return
	}

	// H1: RFC 7239 Forwarded header.
	if fwdCfg.ForwardedEnabled {
		obfID := generateObfuscatedID()
		entry := fmt.Sprintf("for=%s;proto=http", obfID)
		appendHeaderValue(req.Header, "Forwarded", entry)
	}

	// H2/H3/H4
	if fwdCfg.XForwardedForEnabled {
		clientIP, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			slog.Debug("could not parse host:port from client address, using raw address", "client_addr", clientAddr, "error", err)
			clientIP = clientAddr // fallback when address has no port component
		}
		// H2
		appendHeaderValue(req.Header, "X-Forwarded-For", clientIP)
		// H3
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
		// H4
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}
}

// generateViaPseudonym returns a unique pseudonym for this proxy instance,
// used in the Via header to identify this specific process. The format is
// "spnego-proxy-<8-hex-chars>", providing 2^32 unique identifiers — sufficient
// for loop detection across chains of spnego-proxy instances.
func generateViaPseudonym() string {
	return "spnego-proxy-" + randomHex(4)
}

// injectVia appends a Via header entry to the given HTTP headers per
// RFC 9110 §7.6.3. The entry identifies this proxy instance using the
// protocol version received and the proxy's pseudonym.
func injectVia(header http.Header, proto, pseudonym string) {
	appendHeaderValue(header, "Via", proto+" "+pseudonym)
}

// sanitizeHopByHop removes hop-by-hop headers from the request before
// forwarding to the upstream proxy per RFC 9110 §7.6.1. It also handles
// the Transfer-Encoding / Content-Length conflict (RFC 9112 §6.1) and
// strips the client's Proxy-Authorization (RFC 9110 §11.7.1).
//
// The function accepts *http.Request (not bare http.Header) because Go's
// ReadRequest moves Transfer-Encoding into req.TransferEncoding and
// Trailer into req.Trailer, removing both from req.Header. We clear
// req.Trailer so WriteProxy does not re-emit it. We intentionally
// preserve req.TransferEncoding so the proxy relays the body framing
// (e.g. chunked) to the upstream — clearing it would break body
// forwarding.
func sanitizeHopByHop(req *http.Request) {
	header := req.Header

	// B1 (RFC 9110 §7.6.1): parse the Connection header for additional
	// field names to remove, then remove Connection itself.
	for _, v := range header["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	header.Del("Connection")

	// Well-known hop-by-hop headers (RFC 9110 §7.6.1, RFC 9113 §8.2.2).
	header.Del("Keep-Alive")
	header.Del("Proxy-Connection") // K3: non-standard hop-by-hop
	header.Del("TE")
	header.Del("Trailer")
	req.Trailer = nil     // ReadRequest moves Trailer into this field
	header.Del("Upgrade") // J2: strip unless proxy supports the protocol

	// B2 (RFC 9110 §11.7.1): consume the client's Proxy-Authorization.
	// The proxy injects its own SPNEGO token after this function returns.
	header.Del("Proxy-Authorization")

	// E1 (RFC 9112 §6.1): when both Transfer-Encoding and Content-Length
	// are present, remove Content-Length to prevent request smuggling.
	// ReadRequest moves Transfer-Encoding into req.TransferEncoding, so
	// we check that field rather than the header map.
	if len(req.TransferEncoding) > 0 && header.Get("Content-Length") != "" {
		slog.Warn("TE/CL conflict resolved",
			"action", "removed Content-Length",
			"transfer_encoding", req.TransferEncoding,
			"content_length", header.Get("Content-Length"),
		)
		header.Del("Content-Length")
	}
}

// validateResponseContentLength checks the upstream response for invalid
// Content-Length values per RFC 9112 §6.1. It returns a non-nil *proxyError
// when the response must be rejected with 502.
func validateResponseContentLength(resp *http.Response) *proxyError {
	clValues := resp.Header["Content-Length"]
	if len(clValues) == 0 {
		return nil
	}

	// Collect all individual values; headers may be comma-separated per
	// RFC 9110 §5.6.1. Compare numerically so that semantically equal
	// values like "042" and "42" are not rejected.
	var first uint64
	var seen bool
	for _, v := range clValues {
		for part := range strings.SplitSeq(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return errInvalidContentLength
			}
			if !seen {
				first = n
				seen = true
			} else if n != first {
				return errInvalidContentLength
			}
		}
	}
	return nil
}

// errContentLengthInvalid is a sentinel error returned by readUpstreamResponse
// when the upstream response has an invalid Content-Length header, either
// detected by Go's ReadResponse or by validateResponseContentLength.
var errContentLengthInvalid = errors.New("invalid Content-Length in upstream response")

// readUpstreamResponse reads and validates an upstream HTTP response. It
// performs: ReadResponse, Content-Length error detection, content-length
// validation, Transfer-Encoding / Content-Length conflict resolution, and
// Via header injection.
//
// On success it returns the parsed response (caller must close Body).
// On Content-Length errors it returns errContentLengthInvalid so the caller
// can send a 502. On other parse failures it returns a different error,
// signalling the caller to fall back to raw relay.
func readUpstreamResponse(upstreamReader *bufio.Reader, req *http.Request, pseudonym string) (*http.Response, error) {
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		// E2 (RFC 9112 §6.1): Go's ReadResponse rejects responses
		// with invalid Content-Length (e.g. non-numeric values,
		// conflicting duplicates). Detect this so callers return 502
		// instead of raw-relaying the malformed response.
		//
		// The match on the error string is deliberate: Go's
		// net/http does not export a typed error for this case.
		// If the wording changes in a future Go release, the
		// worst outcome is falling through to the raw-relay path
		// — not a security issue, since Go already rejected
		// the malformed response.
		if strings.Contains(err.Error(), "Content-Length") {
			return nil, errContentLengthInvalid
		}
		return nil, err
	}

	// E2 (RFC 9112 §6.1): reject responses with invalid Content-Length.
	// Defense-in-depth: Go's ReadResponse currently rejects most
	// invalid Content-Length values before this point, but our
	// validator catches edge cases (e.g. comma-separated differing
	// values) and guards against future Go stdlib changes.
	if pe := validateResponseContentLength(resp); pe != nil {
		_ = resp.Body.Close()
		return nil, errContentLengthInvalid
	}

	// RFC 9112 §6.1: if both Transfer-Encoding and Content-Length
	// are present in the response, remove Content-Length.
	if len(resp.TransferEncoding) > 0 && resp.Header.Get("Content-Length") != "" {
		slog.Warn("TE/CL conflict resolved in upstream response",
			"action", "removed Content-Length",
			"transfer_encoding", resp.TransferEncoding,
			"content_length", resp.Header.Get("Content-Length"),
		)
		resp.Header.Del("Content-Length")
		// Reset to -1 so resp.Write uses chunked framing instead
		// of a fixed-length body derived from the removed header.
		resp.ContentLength = -1
	}

	// B3 (RFC 9110 §11.7.2): Proxy-Authenticate is hop-by-hop — it applies
	// only between the client and the next inbound proxy. Strip it before
	// relaying the response downstream.
	resp.Header.Del("Proxy-Authenticate")

	// RFC 9110 §7.6.3: a forward proxy MUST add Via to responses.
	injectVia(resp.Header, resp.Proto, pseudonym)

	return resp, nil
}

// TokenProvider acquires SPNEGO tokens for proxy authentication.
type TokenProvider interface {
	// GetToken returns a base64-encoded SPNEGO token.
	GetToken() (string, error)
	// Close cleans up any resources.
	Close() error
}

// enableKeepAlive enables TCP keepalive on conn with the given period.
// Non-TCP connections (e.g. net.Pipe in tests) are silently skipped.
func enableKeepAlive(conn net.Conn, period time.Duration) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(period)
	}
}

// proxyError describes a structured error response that the proxy sends to
// clients. Each field maps to part of the human-readable body format:
//
//	spnego-proxy error: <errorType>
//
//	<message>
//
//	Suggested action: <action>
type proxyError struct {
	statusCode int    // HTTP status code (e.g. 502, 504)
	errorType  string // RFC 9209 Proxy-Status token
	message    string // human-readable description
	action     string // suggested remediation
}

// body renders the structured plain-text response body.
func (e *proxyError) body() string {
	if e.action == "" {
		return fmt.Sprintf("spnego-proxy error: %s\n\n%s\n", e.errorType, e.message)
	}
	return fmt.Sprintf("spnego-proxy error: %s\n\n%s\n\nSuggested action: %s\n", e.errorType, e.message, e.action)
}

// RFC 9209 Proxy-Status error type tokens.
const (
	errorTypeConnectionTimeout    = "connection_timeout"
	errorTypeConnectionRefused    = "connection_refused"
	errorTypeConnectionTerminated = "connection_terminated"
	errorTypeProxyInternalError   = "proxy_internal_error"
	errorTypeHTTPRequestError     = "http_request_error"
	errorTypeProxyLoopDetected    = "proxy_loop_detected"
	errorTypeHTTPProtocolError    = "http_protocol_error"
	errorTypeHTTPRequestDenied    = "http_request_denied"
)

// Pre-defined proxy errors for each scenario the proxy can encounter.
var (
	errConnectionTimeout = &proxyError{
		statusCode: http.StatusGatewayTimeout,
		errorType:  errorTypeConnectionTimeout,
		message:    "The proxy timed out connecting to the upstream proxy.",
		action:     "Verify the upstream proxy address and that it is reachable from this host. Check for network connectivity issues or firewall rules.",
	}
	errConnectionRefused = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeConnectionRefused,
		message:    "The upstream proxy refused the connection.",
		action:     "Verify the upstream proxy is running and listening on the configured address. Check firewall rules and network connectivity.",
	}
	errTokenAcquisition = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeProxyInternalError,
		message:    "The proxy failed to acquire a SPNEGO authentication token.",
		action:     "Check Kerberos credentials. Run 'klist' to verify a valid ticket exists, or 'kinit' to obtain a new one.",
	}
	errCredentialFailure = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeProxyInternalError,
		message:    "Kerberos credentials are expired or unavailable.",
		action:     "Run 'kinit' to obtain or refresh Kerberos credentials, then retry. Run 'klist' to check current ticket status.",
	}
	errNegotiationFailure = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeProxyInternalError,
		message:    "SPNEGO negotiation with the KDC failed.",
		action:     "Check the service principal name (-spn flag) and Kerberos realm configuration. Verify the KDC is reachable.",
	}
	errCircuitBreakerOpen = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeProxyInternalError,
		message:    "Token acquisition is temporarily disabled after repeated failures (circuit breaker open).",
		action:     "The proxy will automatically retry after a cooldown period. Check Kerberos credentials and the KDC. Run 'klist' to verify ticket status.",
	}
	errHTTPRequestError = &proxyError{
		statusCode: http.StatusBadRequest,
		errorType:  errorTypeHTTPRequestError,
		message:    "The proxy could not read or parse the HTTP request.",
		action:     "Verify the client is sending a well-formed HTTP request to the proxy.",
	}
	errConnectionTerminated = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeConnectionTerminated,
		message:    "The connection to the upstream proxy was lost while relaying the request.",
		action:     "The upstream proxy may have closed the connection unexpectedly. Retry the request.",
	}
	errProxyLoopDetected = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeProxyLoopDetected,
		message:    "A routing loop was detected: the request has already passed through this proxy instance.",
		action:     "Check the proxy chain configuration for circular routing. The Via header in the request contains this proxy's identity.",
	}
	errInvalidContentLength = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeHTTPProtocolError,
		message:    "The upstream proxy sent a response with an invalid Content-Length header.",
		action:     "This may indicate a misconfigured upstream proxy or an attempt at response splitting. Contact the upstream proxy administrator.",
	}
	errForbiddenPort = &proxyError{
		statusCode: http.StatusForbidden,
		errorType:  errorTypeHTTPRequestDenied,
		message:    "CONNECT to the requested port is not allowed.",
		action:     "The proxy restricts CONNECT tunneling to specific ports. Contact the proxy administrator.",
	}
	errUnparseableResponse = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeHTTPProtocolError,
		message:    "The upstream proxy sent a response that could not be parsed as valid HTTP.",
		action:     "This may indicate a misconfigured upstream proxy. Contact the upstream proxy administrator.",
	}
)

// writeHTTPError sends a structured HTTP error response to the client with an
// RFC 9209 Proxy-Status header indicating the error type. It is best-effort;
// write failures are silently ignored because the connection is about to be
// closed.
func writeHTTPError(conn net.Conn, pe *proxyError) {
	body := pe.body()
	// RFC 9209 Proxy-Status header with RFC 8941 Structured Fields syntax.
	header := http.Header{
		"Content-Type": {"text/plain; charset=utf-8"},
		"Connection":   {"close"},
		"Proxy-Status": {"spnego-proxy; error=" + pe.errorType},
	}

	resp := &http.Response{
		StatusCode:    pe.statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(conn)
}

// writeMaxForwardsResponse sends a local 200 OK response when a TRACE or
// OPTIONS request arrives with Max-Forwards: 0 per RFC 9110 §7.6.2. This
// proxy is the designated final recipient for that request; it MUST NOT
// forward it further.
//
// For TRACE, RFC 9110 §9.3.8 specifies the body should echo the received
// message. For OPTIONS, RFC 9110 §9.3.7 specifies a simple 200 OK with an
// Allow header describing the supported methods. We respond with 200 OK and
// an empty body for both methods — this satisfies the MUST NOT
// forward requirement without implementing full TRACE/OPTIONS semantics that
// are irrelevant to a forwarding proxy.
func writeMaxForwardsResponse(conn net.Conn, req *http.Request) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type": {"text/plain; charset=utf-8"},
			"Connection":   {"close"},
		},
		Body: http.NoBody,
	}
	// OPTIONS: advertise the request methods this proxy accepts.
	if req.Method == http.MethodOptions {
		resp.Header.Set("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, CONNECT")
	}
	_ = resp.Write(conn)
}

// splitCSV splits a comma-separated string into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// connectPortAllowed reports whether port is in the allowed set.
// An empty allowedPorts slice means all ports are permitted.
func connectPortAllowed(port string, allowedPorts []string) bool {
	return len(allowedPorts) == 0 || slices.Contains(allowedPorts, "*") || slices.Contains(allowedPorts, port)
}

// tokenErrorToProxyError maps a GetToken error to the most specific proxyError
// sentinel, falling back to errTokenAcquisition for unrecognised errors.
func tokenErrorToProxyError(err error) *proxyError {
	var cbErr *CircuitBreakerError
	var credErr *CredentialError
	var negErr *NegotiationError
	switch {
	case errors.As(err, &cbErr):
		return errCircuitBreakerOpen
	case errors.As(err, &credErr):
		return errCredentialFailure
	case errors.As(err, &negErr):
		return errNegotiationFailure
	default:
		return errTokenAcquisition
	}
}

// handleUpstreamResponseError handles errors from readUpstreamResponse.
// For invalid Content-Length it sends a 502 error to the client; for all
// other errors it falls back to raw-relaying the upstream bytes.
func handleUpstreamResponseError(conn, proxyConn net.Conn, _ *bufio.Reader, err error, clientAddr string) {
	if errors.Is(err, errContentLengthInvalid) {
		slog.Error("invalid Content-Length in upstream response",
			"error", err, "error_type", errInvalidContentLength.errorType,
			"client_addr", clientAddr,
			"upstream_addr", proxyConn.RemoteAddr())
		writeHTTPError(conn, errInvalidContentLength)
		return
	}
	slog.Warn("unparseable upstream response",
		"error", err, "error_type", errUnparseableResponse.errorType,
		"client_addr", clientAddr,
		"upstream_addr", proxyConn.RemoteAddr())
	writeHTTPError(conn, errUnparseableResponse)
}

// closeWrite calls CloseWrite on conn if the underlying type supports it.
// This signals the remote peer that no more data will be sent on this half
// of the connection, allowing it to read EOF and finish gracefully.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// idleCopy copies from src to dst, resetting the read deadline on srcConn
// after each successful read. If no data arrives within timeout, the read
// fails with a deadline error and the copy returns. A zero timeout disables
// the idle check and falls back to plain io.Copy.
func idleCopy(dst net.Conn, src io.Reader, srcConn net.Conn, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		return io.Copy(dst, src)
	}
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(timeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			nw, writeErr := dst.Write(buf[:n])
			total += int64(nw)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			_ = srcConn.SetReadDeadline(time.Time{}) // clear deadline
			return total, readErr
		}
	}
}

// forwardHalf copies data from src to dst, calling CloseWrite on dst when
// done. It logs the start, completion, and any errors. Callers use
// wg.Go to launch forwardHalf so the WaitGroup is managed automatically.
func forwardHalf(dst net.Conn, src io.Reader, fromAddr, toAddr net.Addr) {
	defer closeWrite(dst)
	slog.Debug("forward start", "from", fromAddr, "to", toAddr)
	defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
	if _, err := io.Copy(dst, src); err != nil {
		slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
	}
}

// handleClient handles a single client connection. cfg groups all
// non-connection parameters including upstream address, token provider,
// timeouts, CONNECT port restrictions (D4, RFC 9110 §9.3.6), and
// forwarding header injection (RFC 7239 Forwarded, X-Forwarded-For, etc.).
func handleClient(conn net.Conn, cfg ProxyConfig) {
	defer func() { _ = conn.Close() }()
	if cfg.Pseudonym == "" {
		slog.Error("empty pseudonym in ProxyConfig, refusing connection", "client_addr", conn.RemoteAddr())
		return
	}
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("new client", "client_addr", clientAddr)
	defer slog.Debug("stop processing request", "client_addr", clientAddr)

	// Read and validate the client request before dialing upstream so that
	// rejected requests (malformed, loop, forbidden port, Max-Forwards: 0,
	// token failure) never open a wasted TCP connection.
	reqReader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	req, err := http.ReadRequest(reqReader)
	_ = conn.SetReadDeadline(time.Time{}) // clear after read
	if err != nil {
		if !errors.Is(err, io.EOF) {
			slog.Error("failed to read request", "error", err, "error_type", errHTTPRequestError.errorType, "client_addr", clientAddr)
			writeHTTPError(conn, errHTTPRequestError)
		}
		return
	}
	// RFC 9110 §7.6.3: detect routing loops by checking whether the
	// incoming Via header already contains this proxy instance's pseudonym.
	// This must precede sanitizeHopByHop: a client sending
	// "Connection: Via" would strip Via before the loop check otherwise.
	if prior := req.Header.Get("Via"); prior != "" && strings.Contains(prior, cfg.Pseudonym) {
		slog.Warn("proxy loop detected", "via", prior, "pseudonym", cfg.Pseudonym, "client_addr", clientAddr, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, errProxyLoopDetected)
		return
	}

	// D4 (RFC 9110 §9.3.6): restrict CONNECT to allowed ports when
	// connectPorts is non-empty. Parse the port from req.Host; default to
	// "443" when no port is present (bare hostname CONNECT).
	if req.Method == http.MethodConnect && len(cfg.ConnectPorts) > 0 {
		_, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			slog.Debug("CONNECT host has no explicit port, defaulting to 443", "host", req.Host, "error", err, "client_addr", clientAddr)
			port = "443"
		}
		if !connectPortAllowed(port, cfg.ConnectPorts) {
			slog.Warn("CONNECT port not allowed", "host", req.Host, "port", port, "client_addr", clientAddr)
			writeHTTPError(conn, errForbiddenPort)
			return
		}
	}

	// G1 (RFC 9110 §7.6.2): for TRACE and OPTIONS, decrement Max-Forwards
	// before forwarding, or respond locally when the value reaches zero.
	if req.Method == http.MethodTrace || req.Method == http.MethodOptions {
		if mf := req.Header.Get("Max-Forwards"); mf != "" {
			n, err := strconv.Atoi(mf)
			if err != nil {
				// Non-numeric value: forward unmodified per the principle of liberal acceptance.
				slog.Debug("non-numeric Max-Forwards value, forwarding unmodified", "max_forwards", mf, "client_addr", clientAddr)
			} else if n <= 0 {
				// This proxy is the final recipient — respond locally.
				slog.Debug("Max-Forwards: 0, responding locally",
					"method", req.Method, "client_addr", clientAddr)
				writeMaxForwardsResponse(conn, req)
				return
			} else {
				req.Header.Set("Max-Forwards", strconv.Itoa(n-1))
			}
		}
	}

	// Remove hop-by-hop headers before forwarding (RFC 9110 §7.6.1).
	sanitizeHopByHop(req)

	// H1–H4: inject optional forwarding headers after hop-by-hop sanitization
	// so that any client-sent hop-by-hop headers are stripped first.
	injectForwardingHeaders(req, clientAddr, cfg.Forwarding)

	token, err := cfg.Provider.GetToken()
	if err != nil {
		pe := tokenErrorToProxyError(err)
		slog.Error("failed to get SPNEGO token", "error", err, "error_type", pe.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, pe)
		return
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)

	// RFC 9110 §7.6.3: intermediaries MUST add a Via entry identifying
	// the protocol version received and the proxy instance.
	injectVia(req.Header, req.Proto, cfg.Pseudonym)

	// Now that the request is validated and prepared, dial upstream.
	proxyConn, err := net.DialTimeout("tcp", cfg.Upstream, cfg.DialTimeout)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			slog.Error("failed to connect to proxy", "error", err, "error_type", errConnectionTimeout.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream)
			writeHTTPError(conn, errConnectionTimeout)
		} else {
			slog.Error("failed to connect to proxy", "error", err, "error_type", errConnectionRefused.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream)
			writeHTTPError(conn, errConnectionRefused)
		}
		return
	}
	defer func() { _ = proxyConn.Close() }()

	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "via", req.Header.Get("Via"))
	if err := req.WriteProxy(proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, errConnectionTerminated)
		return
	}
	if cfg.KeepAlive > 0 {
		enableKeepAlive(conn, cfg.KeepAlive)
		enableKeepAlive(proxyConn, cfg.KeepAlive)
	}

	if req.Method == http.MethodConnect {
		// D6 (RFC 9110 §9.3.6): for CONNECT, read the upstream response
		// BEFORE starting to forward client payload. This ensures client
		// data (e.g. TLS ClientHello) is not sent to the upstream until
		// after the upstream has confirmed tunnel establishment with 2xx.
		handleConnectTunnel(conn, proxyConn, reqReader, req, cfg.Pseudonym, clientAddr, cfg.IdleTimeout)
		return
	}

	var wg sync.WaitGroup
	wg.Go(func() { forwardHalf(proxyConn, reqReader, conn.RemoteAddr(), proxyConn.RemoteAddr()) })
	// Upstream→client: parse response headers to inject Via, then relay body.
	wg.Go(func() {
		defer closeWrite(conn)
		slog.Debug("forward start", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		defer slog.Debug("forward done", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())

		upstreamReader := bufio.NewReader(proxyConn)
		resp, err := readUpstreamResponse(upstreamReader, req, cfg.Pseudonym)
		if err != nil {
			handleUpstreamResponseError(conn, proxyConn, upstreamReader, err, clientAddr)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		if err := resp.Write(conn); err != nil {
			slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			return
		}
	})
	wg.Wait()
}

// handleConnectTunnel manages the CONNECT tunnel lifecycle per RFC 9110 §9.3.6.
// It reads the upstream response before forwarding any client payload (D6),
// relays the response to the client (D7), and then starts bidirectional
// forwarding only after a 2xx is confirmed.
func handleConnectTunnel(conn, proxyConn net.Conn, reqReader *bufio.Reader, req *http.Request, pseudonym, clientAddr string, idleTimeout time.Duration) {
	upstreamReader := bufio.NewReader(proxyConn)
	resp, err := readUpstreamResponse(upstreamReader, req, pseudonym) //nolint:bodyclose // S3: resp.Body is the raw tunnel stream; closing it would shut down the TCP connection we forward below.
	if err != nil {
		handleUpstreamResponseError(conn, proxyConn, upstreamReader, err, clientAddr)
		return
	}

	// For CONNECT responses, the "body" is the raw tunnel data — it must
	// not be written by resp.Write (that would block waiting for the
	// upstream to close the connection). We write only the response
	// headers here; raw tunnel forwarding happens below after 2xx.
	resp.Body = http.NoBody
	resp.ContentLength = 0

	// D7 (RFC 9110 §9.3.6): relay the upstream's actual response to the
	// client. We never synthesise our own 2xx here.
	if err := resp.Write(conn); err != nil {
		slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		return
	}

	// Only start bidirectional tunnel forwarding after confirmed 2xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Upstream rejected the CONNECT — connection will be closed by
		// the deferred conn.Close() in handleClient (D5).
		slog.Debug("upstream rejected CONNECT", "status", resp.StatusCode, "client_addr", clientAddr)
		return
	}

	slog.Debug("CONNECT tunnel established", "client_addr", clientAddr, "upstream_addr", proxyConn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Go(func() {
		defer closeWrite(proxyConn)
		slog.Debug("forward start", "from", conn.RemoteAddr(), "to", proxyConn.RemoteAddr())
		defer slog.Debug("forward done", "from", conn.RemoteAddr(), "to", proxyConn.RemoteAddr())
		if _, err := idleCopy(proxyConn, reqReader, conn, idleTimeout); err != nil {
			slog.Error("forward error", "error", err, "from", conn.RemoteAddr(), "to", proxyConn.RemoteAddr())
		}
	})
	wg.Go(func() {
		defer closeWrite(conn)
		slog.Debug("forward start", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		defer slog.Debug("forward done", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		if _, err := idleCopy(conn, upstreamReader, proxyConn, idleTimeout); err != nil {
			slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		}
	})
	wg.Wait()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	proxy := flag.String("proxy", "", "proxy address")
	spn := flag.String("spn", "", "service principal name; accepts service@host or service/host (default: derived from -proxy)")
	debug := flag.Bool("debug", false, "turn on debugging")

	dialTimeout := flag.Duration("dial-timeout", 30*time.Second, "timeout for connecting to upstream proxy")
	readTimeout := flag.Duration("read-timeout", 30*time.Second, "timeout for reading client HTTP request")
	drainTimeout := flag.Duration("drain-timeout", 30*time.Second, "timeout for draining in-flight connections on shutdown")
	keepAlive := flag.Duration("keepalive", 30*time.Second, "TCP keepalive period for idle connection detection (0 to disable)")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute,
		"idle timeout for CONNECT tunnels; connections with no data flow are closed after this duration (0 to disable)")
	maxConns := flag.Int("max-conns", 512, "maximum number of concurrent connections (0 for unlimited)")
	connectPortsFlag := flag.String("connect-ports", "443", "comma-separated list of ports allowed for CONNECT tunneling (default: 443; use * for all)")
	cbThreshold := flag.Uint("cb-threshold", 3,
		"consecutive failures before circuit breaker opens")
	cbTimeout := flag.Duration("cb-timeout", 30*time.Second,
		"circuit breaker cooldown duration")

	forwardedFlag := flag.Bool("forwarded", false, "inject RFC 7239 Forwarded header with obfuscated client identifier")
	xForwardedForFlag := flag.Bool("x-forwarded-for", false, "inject X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host headers")

	// Flags for gokrb5 password-based auth (optional on macOS, required on other platforms)
	cfgFile := flag.String("config", "", "kerberos config file")
	user := flag.String("user", "", "kerberos user name")
	realm := flag.String("realm", "", "kerberos realm")
	passwordFile := flag.String("password-file", "", "password file path")
	flag.Parse()

	if *debug {
		logLevel.Set(slog.LevelDebug)
	}

	if *addr == "" || *proxy == "" {
		slog.Error("-addr and -proxy are required")
		flag.Usage()
		os.Exit(1)
	}

	var provider TokenProvider
	var err error

	if *user != "" {
		// Explicit user provided — use gokrb5 password-based auth on any platform
		provider, err = NewGokrb5TokenProvider(*user, *realm, *cfgFile, *passwordFile, *proxy, *spn, *debug)
	} else {
		// Try platform-native GSS-API (macOS) or error on other platforms
		provider, err = newNativeTokenProvider(*proxy, *spn)
	}
	if err != nil {
		// codeql[go/clear-text-logging]
		slog.Error("failed to create token provider", "error", err)
		os.Exit(1)
	}
	provider = NewCircuitBreakerTokenProvider(provider, uint32(*cbThreshold), *cbTimeout)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", *addr)
		os.Exit(1)
	}
	pseudonym := generateViaPseudonym()

	connectPorts := splitCSV(*connectPortsFlag)

	cfg := ProxyConfig{
		Upstream:     *proxy,
		Provider:     provider,
		Pseudonym:    pseudonym,
		DialTimeout:  *dialTimeout,
		ReadTimeout:  *readTimeout,
		KeepAlive:    *keepAlive,
		IdleTimeout:  *idleTimeout,
		ConnectPorts: connectPorts,
		Forwarding: ForwardingConfig{
			ForwardedEnabled:     *forwardedFlag,
			XForwardedForEnabled: *xForwardedForFlag,
		},
	}

	if *maxConns > 0 {
		l = netutil.LimitListener(l, *maxConns)
	}
	logArgs := []any{"addr", *addr, "proxy", *proxy, "via_pseudonym", pseudonym}
	if *maxConns > 0 {
		logArgs = append(logArgs, "max_conns", *maxConns)
	}
	slog.Info("listening", logArgs...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				slog.Error("accept error", "error", err)
				continue
			}
			wg.Go(func() {
				handleClient(conn, cfg)
			})
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down, draining connections...")
	_ = l.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all connections drained")
	case <-time.After(*drainTimeout):
		slog.Warn("drain timeout exceeded, forcing exit")
	}
	_ = provider.Close()
}
