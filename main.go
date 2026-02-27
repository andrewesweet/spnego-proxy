// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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

// generateViaPseudonym returns a unique pseudonym for this proxy instance,
// used in the Via header to identify this specific process. The format is
// "spnego-proxy-<8-hex-chars>", providing 2^32 unique identifiers — sufficient
// for loop detection across chains of spnego-proxy instances.
func generateViaPseudonym() string {
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		return fmt.Sprintf("spnego-proxy-%08x", time.Now().UnixNano()&0xffffffff)
	}
	return fmt.Sprintf("spnego-proxy-%x", b)
}

// injectVia appends a Via header entry to the given HTTP headers per
// RFC 9110 §7.6.3. The entry identifies this proxy instance using the
// protocol version received and the proxy's pseudonym.
func injectVia(header http.Header, proto, pseudonym string) {
	viaEntry := proto + " " + pseudonym
	if prior := header.Get("Via"); prior != "" {
		header.Set("Via", prior+", "+viaEntry)
	} else {
		header.Set("Via", viaEntry)
	}
}

// sanitizeHopByHop removes hop-by-hop headers from the request before
// forwarding to the upstream proxy per RFC 9110 §7.6.1. It also handles
// the Transfer-Encoding / Content-Length conflict (RFC 9112 §6.1) and
// strips the client's Proxy-Authorization (RFC 9110 §11.7.1).
//
// The function accepts *http.Request (not bare http.Header) because Go's
// ReadRequest moves Transfer-Encoding into req.TransferEncoding and
// Trailer into req.Trailer, removing both from req.Header. Clearing
// those fields prevents WriteProxy from re-emitting them.
func sanitizeHopByHop(req *http.Request) {
	header := req.Header

	// B1 (RFC 9110 §7.6.1): parse the Connection header for additional
	// field names to remove, then remove Connection itself.
	for _, v := range header["Connection"] {
		for _, name := range strings.Split(v, ",") {
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
		for _, part := range strings.Split(v, ",") {
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
	var buf strings.Builder
	fmt.Fprintf(&buf, "spnego-proxy error: %s\n\n%s\n", e.errorType, e.message)
	if e.action != "" {
		fmt.Fprintf(&buf, "\nSuggested action: %s\n", e.action)
	}
	return buf.String()
}

// Pre-defined proxy errors for each scenario the proxy can encounter.
var (
	errConnectionTimeout = &proxyError{
		statusCode: http.StatusGatewayTimeout,
		errorType:  "connection_timeout",
		message:    "The proxy timed out connecting to the upstream proxy.",
		action:     "Verify the upstream proxy address and that it is reachable from this host. Check for network connectivity issues or firewall rules.",
	}
	errConnectionRefused = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "connection_refused",
		message:    "The upstream proxy refused the connection.",
		action:     "Verify the upstream proxy is running and listening on the configured address. Check firewall rules and network connectivity.",
	}
	errTokenAcquisition = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "proxy_internal_error",
		message:    "The proxy failed to acquire a SPNEGO authentication token.",
		action:     "Check Kerberos credentials. Run 'klist' to verify a valid ticket exists, or 'kinit' to obtain a new one.",
	}
	errCredentialFailure = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "proxy_internal_error",
		message:    "Kerberos credentials are expired or unavailable.",
		action:     "Run 'kinit' to obtain or refresh Kerberos credentials, then retry. Run 'klist' to check current ticket status.",
	}
	errNegotiationFailure = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "proxy_internal_error",
		message:    "SPNEGO negotiation with the KDC failed.",
		action:     "Check the service principal name (-spn flag) and Kerberos realm configuration. Verify the KDC is reachable.",
	}
	errCircuitBreakerOpen = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "proxy_internal_error",
		message:    "Token acquisition is temporarily disabled after repeated failures (circuit breaker open).",
		action:     "The proxy will automatically retry after a cooldown period. Check Kerberos credentials and the KDC. Run 'klist' to verify ticket status.",
	}
	errHTTPRequestError = &proxyError{
		statusCode: http.StatusBadRequest,
		errorType:  "http_request_error",
		message:    "The proxy could not read or parse the HTTP request.",
		action:     "Verify the client is sending a well-formed HTTP request to the proxy.",
	}
	errConnectionTerminated = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "connection_terminated",
		message:    "The connection to the upstream proxy was lost while relaying the request.",
		action:     "The upstream proxy may have closed the connection unexpectedly. Retry the request.",
	}
	errProxyLoopDetected = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "proxy_loop_detected",
		message:    "A routing loop was detected: the request has already passed through this proxy instance.",
		action:     "Check the proxy chain configuration for circular routing. The Via header in the request contains this proxy's identity.",
	}
	errInvalidContentLength = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  "http_protocol_error",
		message:    "The upstream proxy sent a response with an invalid Content-Length header.",
		action:     "This may indicate a misconfigured upstream proxy or an attempt at response splitting. Contact the upstream proxy administrator.",
	}
)

// writeHTTPError sends a structured HTTP error response to the client with an
// RFC 9209 Proxy-Status header indicating the error type. It is best-effort;
// write failures are silently ignored because the connection is about to be
// closed.
func writeHTTPError(conn net.Conn, pe *proxyError) {
	body := pe.body()
	header := http.Header{
		"Content-Type": {"text/plain; charset=utf-8"},
		"Connection":   {"close"},
	}
	// RFC 9209 Proxy-Status header with RFC 8941 Structured Fields syntax.
	header.Set("Proxy-Status", "spnego-proxy; error="+pe.errorType)

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

func handleClient(conn net.Conn, proxy string, provider TokenProvider, pseudonym string, dialTimeout, readTimeout, keepAlive time.Duration) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("new client", "client_addr", clientAddr)
	defer slog.Debug("stop processing request", "client_addr", clientAddr)
	proxyConn, err := net.DialTimeout("tcp", proxy, dialTimeout)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			slog.Error("failed to connect to proxy", "error", err, "error_type", errConnectionTimeout.errorType, "client_addr", clientAddr, "upstream_addr", proxy)
			writeHTTPError(conn, errConnectionTimeout)
		} else {
			slog.Error("failed to connect to proxy", "error", err, "error_type", errConnectionRefused.errorType, "client_addr", clientAddr, "upstream_addr", proxy)
			writeHTTPError(conn, errConnectionRefused)
		}
		return
	}
	defer func() { _ = proxyConn.Close() }()
	reqReader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
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
	if prior := req.Header.Get("Via"); prior != "" && strings.Contains(prior, pseudonym) {
		slog.Warn("proxy loop detected", "via", prior, "pseudonym", pseudonym, "client_addr", clientAddr, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, errProxyLoopDetected)
		return
	}

	// Remove hop-by-hop headers before forwarding (RFC 9110 §7.6.1).
	sanitizeHopByHop(req)

	token, err := provider.GetToken()
	if err != nil {
		pe := errTokenAcquisition
		var cbErr *CircuitBreakerError
		var credErr *CredentialError
		var negErr *NegotiationError
		switch {
		case errors.As(err, &cbErr):
			pe = errCircuitBreakerOpen
		case errors.As(err, &credErr):
			pe = errCredentialFailure
		case errors.As(err, &negErr):
			pe = errNegotiationFailure
		}
		slog.Error("failed to get SPNEGO token", "error", err, "error_type", pe.errorType, "client_addr", clientAddr, "upstream_addr", proxy, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, pe)
		return
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)

	// RFC 9110 §7.6.3: intermediaries MUST add a Via entry identifying
	// the protocol version received and the proxy instance.
	injectVia(req.Header, req.Proto, pseudonym)

	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", clientAddr, "upstream_addr", proxy, "via", req.Header.Get("Via"))
	if err := req.WriteProxy(proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", errConnectionTerminated.errorType, "client_addr", clientAddr, "upstream_addr", proxy, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, errConnectionTerminated)
		return
	}
	if keepAlive > 0 {
		enableKeepAlive(conn, keepAlive)
		enableKeepAlive(proxyConn, keepAlive)
	}
	var wg sync.WaitGroup
	forward := func(from io.Reader, to net.Conn, fromAddr, toAddr net.Addr) {
		defer wg.Done()
		defer func() {
			if cw, ok := to.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		slog.Debug("forward start", "from", fromAddr, "to", toAddr)
		defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
		if _, err := io.Copy(to, from); err != nil {
			slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
		}
	}
	wg.Add(2)
	go forward(reqReader, proxyConn, conn.RemoteAddr(), proxyConn.RemoteAddr())
	// Upstream→client: parse response headers to inject Via, then relay body.
	go func() {
		defer wg.Done()
		defer func() {
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		slog.Debug("forward start", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		defer slog.Debug("forward done", "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())

		upstreamReader := bufio.NewReader(proxyConn)
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			// E2 (RFC 9112 §6.1): Go's ReadResponse rejects responses
			// with invalid Content-Length (e.g. non-numeric values,
			// conflicting duplicates). Detect this so we return 502
			// instead of raw-relaying the malformed response.
			//
			// The match on the error string is deliberate: Go's
			// net/http does not export a typed error for this case.
			// If the wording changes in a future Go release, the
			// worst outcome is falling through to the raw-relay path
			// below — not a security issue, since Go already rejected
			// the malformed response.
			if strings.Contains(err.Error(), "Content-Length") {
				slog.Error("invalid Content-Length in upstream response",
					"error", err, "error_type", errInvalidContentLength.errorType,
					"client_addr", conn.RemoteAddr())
				writeHTTPError(conn, errInvalidContentLength)
				return
			}
			// Deviation from RFC 9110 §7.6.3 (MUST add Via): when the
			// upstream response is unparseable, injecting a Via header is
			// impossible. We relay raw bytes instead of returning an error
			// so the client still receives whatever the upstream sent.
			// The warning log ensures operator visibility. See README.md
			// for the full rationale.
			slog.Warn("failed to parse upstream response, falling back to raw relay",
				"error", err, "client_addr", conn.RemoteAddr())
			if _, err := io.Copy(conn, upstreamReader); err != nil {
				slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			}
			return
		}
		defer func() { _ = resp.Body.Close() }()

		// E2 (RFC 9112 §6.1): reject responses with invalid Content-Length.
		if pe := validateResponseContentLength(resp); pe != nil {
			slog.Error("invalid Content-Length in upstream response",
				"error_type", pe.errorType,
				"content_length", resp.Header["Content-Length"],
				"client_addr", conn.RemoteAddr(),
				"upstream_addr", proxyConn.RemoteAddr())
			writeHTTPError(conn, pe)
			return
		}

		// RFC 9112 §6.1: if both Transfer-Encoding and Content-Length
		// are present in the response, remove Content-Length.
		if resp.Header.Get("Transfer-Encoding") != "" && resp.Header.Get("Content-Length") != "" {
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
		}

		// RFC 9110 §7.6.3: a forward proxy MUST add Via to responses.
		injectVia(resp.Header, resp.Proto, pseudonym)

		if err := resp.Write(conn); err != nil {
			slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			return
		}

		// For CONNECT 200, the tunnel begins after the response headers.
		// resp.Write wrote the (empty-body) response; now relay the
		// encrypted tunnel data as raw bytes.
		if req.Method == http.MethodConnect && resp.StatusCode == http.StatusOK {
			if _, err := io.Copy(conn, upstreamReader); err != nil {
				slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			}
		}
	}()
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
	maxConns := flag.Int("max-conns", 512, "maximum number of concurrent connections (0 for unlimited)")

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
	provider = NewCircuitBreakerTokenProvider(provider)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", *addr)
		os.Exit(1)
	}
	pseudonym := generateViaPseudonym()

	if *maxConns > 0 {
		l = netutil.LimitListener(l, *maxConns)
		slog.Info("listening", "addr", *addr, "proxy", *proxy, "max_conns", *maxConns, "via_pseudonym", pseudonym)
	} else {
		slog.Info("listening", "addr", *addr, "proxy", *proxy, "via_pseudonym", pseudonym)
	}

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
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, *proxy, provider, pseudonym, *dialTimeout, *readTimeout, *keepAlive)
			}()
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
