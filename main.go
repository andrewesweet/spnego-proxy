// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

// connectPortWildcard is the sentinel value meaning "allow all ports" in the
// -connect-ports flag and connectPortAllowed logic.
const connectPortWildcard = "*"

// copyBufPool pools 32 KiB buffers used by idleCopy to avoid a heap
// allocation on every tunnel connection.
var copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// version and commit are set at build time via ldflags.
var (
	version = ""
	commit  = ""
)

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

// UpstreamTLSConfig holds optional TLS settings for the upstream proxy connection.
type UpstreamTLSConfig struct {
	Enabled            bool
	CAFile             string
	InsecureSkipVerify bool
	// TLSConfig is the pre-built *tls.Config constructed once at startup.
	// dialUpstream clones it and sets ServerName per connection.
	// Call buildTLSConfig to populate it from the other fields.
	TLSConfig *tls.Config
	// Dialer is the pre-allocated net.Dialer constructed once at startup.
	Dialer *net.Dialer
}

// buildTLSConfig constructs a *tls.Config from the fields of UpstreamTLSConfig
// and stores it in TLSConfig. It is called once at startup (and in tests) so
// that dialUpstream can clone the result without re-reading the CA file per connection.
func (c *UpstreamTLSConfig) buildTLSConfig() error {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return fmt.Errorf("failed to read upstream CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse upstream CA certificate from %s", c.CAFile)
		}
		tc.RootCAs = pool
	}
	if c.InsecureSkipVerify {
		tc.InsecureSkipVerify = true //nolint:gosec // user explicitly opted in via -upstream-tls-insecure
	}
	c.TLSConfig = tc
	return nil
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
	AllowedIPs   []*net.IPNet
	NoProxy      *NoProxyMatcher
	Forwarding   ForwardingConfig
	UpstreamTLS  UpstreamTLSConfig
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

// writeConnectOK writes a raw CONNECT 2xx response to conn without using
// http.Response.Write, which would emit Content-Length: 0 and Connection:
// close headers. Per RFC 9110 §9.3.6, a successful CONNECT response consists
// only of a status line and optional headers — there is no message body, so
// Content-Length is semantically meaningless. HTTP clients like Bun and undici
// interpret Content-Length: 0 literally and close the connection before the
// TLS handshake can begin.
func writeConnectOK(conn net.Conn, resp *http.Response) error {
	var buf strings.Builder
	fmt.Fprintf(&buf, "HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor,
		resp.StatusCode, http.StatusText(resp.StatusCode))
	if via := resp.Header.Get("Via"); via != "" {
		fmt.Fprintf(&buf, "Via: %s\r\n", via)
	}
	buf.WriteString("\r\n")
	_, err := io.WriteString(conn, buf.String())
	return err
}

// logTECLConflict logs the Transfer-Encoding / Content-Length conflict
// resolution warning per RFC 9110 §6.2. direction is "request" or "response".
func logTECLConflict(direction string, te []string, cl string) {
	slog.Warn("TE/CL conflict resolved",
		"direction", direction,
		"action", "removed Content-Length per RFC 9110 §6.2",
		"transfer_encoding", te,
		"content_length", cl)
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
	if cl := header.Get("Content-Length"); len(req.TransferEncoding) > 0 && cl != "" {
		logTECLConflict("request", req.TransferEncoding, cl)
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
	if cl := resp.Header.Get("Content-Length"); len(resp.TransferEncoding) > 0 && cl != "" {
		logTECLConflict("response", resp.TransferEncoding, cl)
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
	errClientDenied = &proxyError{
		statusCode: http.StatusForbidden,
		errorType:  errorTypeHTTPRequestDenied,
		message:    "Client IP is not in the allowlist.",
		action:     "Contact the proxy administrator to add your IP to the -allowed-ips list.",
	}
	errMismatchedTarget = &proxyError{
		statusCode: http.StatusBadRequest,
		errorType:  errorTypeHTTPRequestDenied,
		message:    "Pipelined request is incompatible with the existing direct connection.",
		action:     "Open a new connection to the proxy and retry.",
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

// parseAllowList parses a comma-separated string of IPs and CIDR ranges
// into a slice of *net.IPNet entries for use with ipAllowed.
func parseAllowList(s string) ([]*net.IPNet, error) {
	if s == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, entry := range splitCSV(s) {
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %q", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets, nil
}

// ipAllowed returns true if the given IP is in the allow list.
// A nil or empty allow list permits all IPs.
func ipAllowed(ip net.IP, allowList []*net.IPNet) bool {
	if len(allowList) == 0 {
		return true
	}
	for _, n := range allowList {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// connectPortAllowed reports whether port is in the allowed set.
// An empty allowedPorts slice means all ports are permitted.
func connectPortAllowed(port string, allowedPorts []string) bool {
	return len(allowedPorts) == 0 || slices.ContainsFunc(allowedPorts, func(p string) bool { return p == connectPortWildcard || p == port })
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
func handleUpstreamResponseError(conn, proxyConn net.Conn, err error, clientAddr string) {
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

// prepareForwardRequest runs the per-request validation pipeline shared by
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
func prepareForwardRequest(conn net.Conn, req *http.Request, cfg ProxyConfig, clientAddr string) (proceed bool, pe *proxyError) {
	// RFC 9110 §7.6.3: loop detection must run BEFORE sanitizeHopByHop so
	// that a client sending "Connection: Via" cannot strip Via and bypass
	// the check.
	if prior := req.Header.Get("Via"); prior != "" && strings.Contains(prior, cfg.Pseudonym) {
		slog.Warn("proxy loop detected", "via", prior, "pseudonym", cfg.Pseudonym, "client_addr", clientAddr, "method", req.Method, "host", req.Host)
		return false, errProxyLoopDetected
	}

	// D4 (RFC 9110 §9.3.6): restrict CONNECT to allowed ports.
	if req.Method == http.MethodConnect && len(cfg.ConnectPorts) > 0 {
		_, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			slog.Debug("CONNECT host has no explicit port, defaulting to 443", "host", req.Host, "error", err, "client_addr", clientAddr)
			port = "443"
		}
		if !connectPortAllowed(port, cfg.ConnectPorts) {
			slog.Warn("CONNECT port not allowed", "host", req.Host, "port", port, "client_addr", clientAddr)
			return false, errForbiddenPort
		}
	}

	// G1 (RFC 9110 §7.6.2): TRACE/OPTIONS Max-Forwards.
	if req.Method == http.MethodTrace || req.Method == http.MethodOptions {
		if mf := req.Header.Get("Max-Forwards"); mf != "" {
			n, err := strconv.Atoi(mf)
			switch {
			case err != nil:
				slog.Debug("non-numeric Max-Forwards value, forwarding unmodified", "max_forwards", mf, "client_addr", clientAddr)
			case n <= 0:
				slog.Debug("Max-Forwards: 0, responding locally", "method", req.Method, "client_addr", clientAddr)
				writeMaxForwardsResponse(conn, req)
				return false, nil
			default:
				req.Header.Set("Max-Forwards", strconv.Itoa(n-1))
			}
		}
	}

	// Hop-by-hop sanitisation (RFC 9110 §7.6.1) — runs on every
	// iteration so a smuggled Proxy-Authorization cannot ride an
	// already-authenticated upstream connection.
	sanitizeHopByHop(req)
	return true, nil
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
// sockets when configured. On any failure it writes a proxyError to conn
// and returns nil. Returns the open upstream connection on success.
func dialAndAuthUpstream(conn net.Conn, req *http.Request, cfg ProxyConfig, clientAddr string) net.Conn {
	token, terr := cfg.Provider.GetToken()
	if terr != nil {
		pe := tokenErrorToProxyError(terr)
		slog.Error("failed to get SPNEGO token", "error", terr, "error_type", pe.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, pe)
		return nil
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)

	proxyConn, derr := dialUpstream(cfg.Upstream, cfg.UpstreamTLS)
	if derr != nil {
		var ne net.Error
		if errors.As(derr, &ne) && ne.Timeout() {
			slog.Error("failed to connect to proxy", "error", derr, "error_type", errConnectionTimeout.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream)
			writeHTTPError(conn, errConnectionTimeout)
		} else {
			slog.Error("failed to connect to proxy", "error", derr, "error_type", errConnectionRefused.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream)
			writeHTTPError(conn, errConnectionRefused)
		}
		return nil
	}
	if cfg.KeepAlive > 0 {
		enableKeepAlive(conn, cfg.KeepAlive)
		enableKeepAlive(proxyConn, cfg.KeepAlive)
	}
	return proxyConn
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
			// Bare bracketed IPv6 address with no port: strip brackets so
			// net.JoinHostPort below re-adds them exactly once.
			if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
				host = host[1 : len(host)-1]
			}
		}
		return net.JoinHostPort(host, port)
	}
	return canon(a) == canon(b)
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
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
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

// isExpectedCloseError reports whether err is a normal connection-teardown
// error that does not warrant ERROR-level logging. EOF, broken pipe,
// connection reset, and use-of-closed-connection are all routine in proxy
// forwarding — one side simply closed first.
func isExpectedCloseError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return false
}

// forwardHalf copies data from src to dst, calling CloseWrite on dst when
// done. It logs the start, completion, and any errors. Callers use
// wg.Go to launch forwardHalf so the WaitGroup is managed automatically.
// When idleTimeout > 0, idleCopy is used with srcConn to enforce an idle
// deadline; otherwise plain io.Copy is used and srcConn may be nil.
func forwardHalf(dst net.Conn, src io.Reader, srcConn net.Conn, fromAddr, toAddr net.Addr, idleTimeout time.Duration) {
	defer closeWrite(dst)
	slog.Debug("forward start", "from", fromAddr, "to", toAddr)
	defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
	var err error
	if idleTimeout > 0 {
		_, err = idleCopy(dst, src, srcConn, idleTimeout)
	} else {
		_, err = io.Copy(dst, src)
	}
	if err != nil {
		if isExpectedCloseError(err) {
			slog.Debug("forward closed", "error", err, "from", fromAddr, "to", toAddr)
		} else {
			slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
		}
	}
}

// dialUpstream connects to the upstream proxy, optionally using TLS.
// tlsCfg.Dialer must be non-nil; it is pre-allocated at startup by main().
func dialUpstream(addr string, tlsCfg UpstreamTLSConfig) (net.Conn, error) {
	dialer := tlsCfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if !tlsCfg.Enabled {
		return dialer.Dial("tcp", addr)
	}

	var tc *tls.Config
	if tlsCfg.TLSConfig != nil {
		tc = tlsCfg.TLSConfig.Clone()
	} else {
		tc = &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // fallback for tests without pre-built config
	}
	tc.ServerName = extractHost(addr)

	return tls.DialWithDialer(dialer, "tcp", addr, tc)
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

// handleClient handles a single client connection. cfg groups all
// non-connection parameters including upstream address, token provider,
// timeouts, CONNECT port restrictions (D4, RFC 9110 §9.3.6), and
// forwarding header injection (RFC 7239 Forwarded, X-Forwarded-For, etc.).
func handleClient(conn net.Conn, cfg ProxyConfig) {
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

	reqReader := bufio.NewReader(conn)

	var proxyConn net.Conn
	var upstreamReader *bufio.Reader
	defer func() {
		if proxyConn != nil {
			_ = proxyConn.Close()
		}
	}()

	for iter := 0; ; iter++ {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
		req, err := http.ReadRequest(reqReader)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			if iter == 0 {
				if isExpectedCloseError(err) {
					slog.Debug("client connection closed before request", "error", err, "client_addr", clientAddr)
				} else {
					slog.Error("failed to read request", "error", err, "error_type", errHTTPRequestError.errorType, "client_addr", clientAddr)
					writeHTTPError(conn, errHTTPRequestError)
				}
			} else {
				slog.Debug("keep-alive loop ended", "error", err, "iter", iter, "client_addr", clientAddr)
			}
			return
		}

		proceed, pe := prepareForwardRequest(conn, req, cfg, clientAddr)
		if !proceed {
			if pe != nil {
				writeHTTPError(conn, pe)
			}
			return
		}

		// Noproxy bypass — direct dial to the target. Terminates the
		// keep-alive loop because the authenticated upstream connection
		// (if any) cannot serve a direct-dial request.
		matched, pattern := false, ""
		if cfg.NoProxy != nil {
			matched, pattern = cfg.NoProxy.Match(req.Host)
		}
		if matched {
			slog.Debug("noproxy bypass", "host", req.Host, "pattern", pattern, "method", req.Method, "client_addr", clientAddr)
			if req.Method == http.MethodConnect {
				handleDirectConnect(conn, req, reqReader, cfg, clientAddr)
			} else {
				injectVia(req.Header, req.Proto, cfg.Pseudonym)
				handleDirectHTTP(conn, req, reqReader, cfg, clientAddr)
			}
			return
		}

		// CONNECT via upstream proxy — tunnel mode terminates the loop.
		// A CONNECT request always dials a fresh upstream connection
		// because a tunnel co-opts the connection for opaque bytes; it
		// cannot share with prior HTTP responses on the keep-alive
		// connection.
		if req.Method == http.MethodConnect {
			forwardConnectViaUpstream(conn, req, reqReader, cfg, clientAddr)
			return
		}

		// Plain HTTP through upstream proxy. Lazy-dial on the first
		// non-CONNECT, non-noproxy request; reuse the SPNEGO-authenticated
		// connection on subsequent requests (RFC 4559 §5).
		injectForwardingHeaders(req, clientAddr, cfg.Forwarding)
		if proxyConn == nil {
			proxyConn = dialAndAuthUpstream(conn, req, cfg, clientAddr)
			if proxyConn == nil {
				return
			}
			upstreamReader = bufio.NewReader(proxyConn)
		}
		injectVia(req.Header, req.Proto, cfg.Pseudonym)

		slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "via", req.Header.Get("Via"), "iter", iter)
		if err := req.WriteProxy(proxyConn); err != nil {
			slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "method", req.Method, "host", req.Host)
			writeHTTPError(conn, errConnectionTerminated)
			return
		}

		resp, err := readUpstreamResponse(upstreamReader, req, cfg.Pseudonym)
		if err != nil {
			handleUpstreamResponseError(conn, proxyConn, err, clientAddr)
			return
		}

		writeErr := resp.Write(conn)
		if writeErr != nil {
			_ = resp.Body.Close()
			if isExpectedCloseError(writeErr) {
				slog.Debug("forward closed", "error", writeErr, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			} else {
				slog.Error("forward error", "error", writeErr, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			}
			return
		}
		// Drain any unread body so upstreamReader is aligned for the
		// next iteration; resp.Write already consumed it for well-framed
		// responses.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if connectionWillClose(req, resp) {
			return
		}
	}
}

// forwardConnectViaUpstream performs the CONNECT-via-upstream-proxy flow:
// inject forwarding headers, acquire a SPNEGO token, dial a FRESH upstream
// connection, send the CONNECT request, and hand off to handleConnectTunnel.
// A fresh connection is required because a CONNECT tunnel co-opts the
// entire upstream connection for opaque bytes; it must not share with
// prior keep-alive HTTP traffic on the same socket.
func forwardConnectViaUpstream(conn net.Conn, req *http.Request, reqReader *bufio.Reader, cfg ProxyConfig, clientAddr string) {
	injectForwardingHeaders(req, clientAddr, cfg.Forwarding)

	proxyConn := dialAndAuthUpstream(conn, req, cfg, clientAddr)
	if proxyConn == nil {
		return
	}
	defer func() { _ = proxyConn.Close() }()
	injectVia(req.Header, req.Proto, cfg.Pseudonym)

	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "via", req.Header.Get("Via"))
	if err := req.WriteProxy(proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", clientAddr, "upstream_addr", cfg.Upstream, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, errConnectionTerminated)
		return
	}

	handleConnectTunnel(conn, proxyConn, reqReader, req, cfg.Pseudonym, clientAddr, cfg.IdleTimeout)
}

// handleConnectTunnel manages the CONNECT tunnel lifecycle per RFC 9110 §9.3.6.
// It reads the upstream response before forwarding any client payload (D6),
// relays the response to the client (D7), and then starts bidirectional
// forwarding only after a 2xx is confirmed.
func handleConnectTunnel(conn, proxyConn net.Conn, reqReader *bufio.Reader, req *http.Request, pseudonym, clientAddr string, idleTimeout time.Duration) {
	upstreamReader := bufio.NewReader(proxyConn)
	resp, err := readUpstreamResponse(upstreamReader, req, pseudonym) //nolint:bodyclose // S3: resp.Body is the raw tunnel stream; closing it would shut down the TCP connection we forward below.
	if err != nil {
		handleUpstreamResponseError(conn, proxyConn, err, clientAddr)
		return
	}

	// D7 (RFC 9110 §9.3.6): relay the upstream's actual response to the
	// client. We never synthesise our own 2xx here.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Upstream rejected the CONNECT — forward the full response
		// including any rejection body (e.g. HTML error page).
		// Non-2xx is terminal, so Content-Length/Connection are fine.
		// Connection is cleaned up by deferred conn.Close() in
		// handleClient (D5).
		if err := resp.Write(conn); err != nil {
			if isExpectedCloseError(err) {
				slog.Debug("forward closed", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			} else {
				slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			}
		}
		slog.Debug("upstream rejected CONNECT", "status", resp.StatusCode, "client_addr", clientAddr)
		return
	}

	// For 2xx CONNECT responses, write a raw status line instead of using
	// resp.Write, which emits Content-Length: 0 and Connection: close —
	// headers that cause Bun/undici clients to close the connection before
	// the TLS handshake through the tunnel can begin.
	if err := writeConnectOK(conn, resp); err != nil {
		if isExpectedCloseError(err) {
			slog.Debug("forward closed", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		} else {
			slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		}
		return
	}

	slog.Debug("CONNECT tunnel established", "client_addr", clientAddr, "upstream_addr", proxyConn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Go(func() {
		forwardHalf(proxyConn, reqReader, conn, conn.RemoteAddr(), proxyConn.RemoteAddr(), idleTimeout)
	})
	wg.Go(func() {
		forwardHalf(conn, upstreamReader, proxyConn, proxyConn.RemoteAddr(), conn.RemoteAddr(), idleTimeout)
	})
	wg.Wait()
}

func versionString() string {
	if version == "" {
		return "spnego-proxy version (devel)"
	}
	if commit == "" {
		return fmt.Sprintf("spnego-proxy version %s", version)
	}
	short := commit
	if len(short) > 7 {
		short = short[:7]
	}
	return fmt.Sprintf("spnego-proxy version %s (commit %s)", version, short)
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
	connectPortsFlag := flag.String("connect-ports", "443", "comma-separated list of ports allowed for CONNECT tunneling (default: 443; use "+connectPortWildcard+" for all)")
	allowedIPs := flag.String("allowed-ips", "",
		"comma-separated list of allowed client IPs or CIDR ranges (empty = allow all; recommended when binding to non-loopback)")
	noProxyFlag := flag.String("noproxy", "",
		"comma-separated list of hosts/domains/IPs/CIDRs to bypass upstream proxy (supports *.domain, .domain, CIDR, * for all; also reads NO_PROXY/no_proxy env vars)")
	cbThreshold := flag.Uint("cb-threshold", uint(cbConsecutiveFailures),
		"consecutive failures before circuit breaker opens")
	cbTimeoutFlag := flag.Duration("cb-timeout", cbTimeout,
		"circuit breaker cooldown duration")

	forwardedFlag := flag.Bool("forwarded", false, "inject RFC 7239 Forwarded header with obfuscated client identifier")
	xForwardedForFlag := flag.Bool("x-forwarded-for", false, "inject X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host headers")

	upstreamTLS := flag.Bool("upstream-tls", false,
		"use TLS for upstream proxy connection")
	upstreamCA := flag.String("upstream-ca", "",
		"path to CA certificate for upstream TLS verification")
	upstreamTLSInsecure := flag.Bool("upstream-tls-insecure", false,
		"skip TLS certificate verification for upstream (not recommended)")

	// Flags for gokrb5 password-based auth (optional on macOS, required on other platforms)
	cfgFile := flag.String("config", "", "kerberos config file")
	user := flag.String("user", "", "kerberos user name")
	realm := flag.String("realm", "", "kerberos realm")
	passwordFile := flag.String("password-file", "", "password file path")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", versionString())
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", "spnego-proxy")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

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
	provider = NewCircuitBreakerTokenProvider(provider, uint32(*cbThreshold), *cbTimeoutFlag) //nolint:gosec // CLI flag value; overflow not a concern

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", *addr)
		os.Exit(1)
	}
	pseudonym := generateViaPseudonym()

	connectPorts := splitCSV(*connectPortsFlag)

	allowList, err := parseAllowList(*allowedIPs)
	if err != nil {
		slog.Error("invalid -allowed-ips", "error", err)
		os.Exit(1)
	}

	noProxyPatterns := resolveNoProxy(*noProxyFlag)
	var noProxy *NoProxyMatcher
	if noProxyPatterns != "" {
		noProxy = NewNoProxyMatcher(noProxyPatterns)
		source := "flag"
		if *noProxyFlag == "" {
			source = "env"
		}
		slog.Info("noproxy bypass configured", "patterns", noProxyPatterns, "source", source)
	}

	// Build the upstream TLS config once at startup (avoids re-reading CA file per connection).
	upstreamTLSCfg := UpstreamTLSConfig{
		Enabled:            *upstreamTLS,
		CAFile:             *upstreamCA,
		InsecureSkipVerify: *upstreamTLSInsecure,
		Dialer:             &net.Dialer{Timeout: *dialTimeout},
	}
	if err := upstreamTLSCfg.buildTLSConfig(); err != nil {
		slog.Error("failed to build upstream TLS config", "error", err)
		os.Exit(1)
	}
	if *upstreamTLSInsecure {
		slog.Warn("upstream TLS certificate verification is disabled")
	}

	cfg := ProxyConfig{
		Upstream:     *proxy,
		Provider:     provider,
		Pseudonym:    pseudonym,
		DialTimeout:  *dialTimeout,
		ReadTimeout:  *readTimeout,
		KeepAlive:    *keepAlive,
		IdleTimeout:  *idleTimeout,
		ConnectPorts: connectPorts,
		AllowedIPs:   allowList,
		NoProxy:      noProxy,
		Forwarding: ForwardingConfig{
			ForwardedEnabled:     *forwardedFlag,
			XForwardedForEnabled: *xForwardedForFlag,
		},
		UpstreamTLS: upstreamTLSCfg,
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
