package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

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
	errMalformedResponseHeader = &proxyError{
		statusCode: http.StatusBadGateway,
		errorType:  errorTypeHTTPProtocolError,
		message:    "The upstream proxy sent a response containing a header field with a malformed name or a forbidden control character in its value.",
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
// For invalid Content-Length or malformed response headers it sends a 502
// error to the client; for all other errors it falls back to raw-relaying
// the upstream bytes.
func handleUpstreamResponseError(conn, proxyConn net.Conn, err error, clientAddr string) {
	if errors.Is(err, errContentLengthInvalid) {
		slog.Error("invalid Content-Length in upstream response",
			"error", err, "error_type", errInvalidContentLength.errorType,
			"client_addr", clientAddr,
			"upstream_addr", proxyConn.RemoteAddr())
		writeHTTPError(conn, errInvalidContentLength)
		return
	}
	if errors.Is(err, errMalformedResponse) {
		slog.Error("malformed upstream response header",
			"error", err, "error_type", errMalformedResponseHeader.errorType,
			"client_addr", clientAddr,
			"upstream_addr", proxyConn.RemoteAddr())
		writeHTTPError(conn, errMalformedResponseHeader)
		return
	}
	slog.Warn("unparseable upstream response",
		"error", err, "error_type", errUnparseableResponse.errorType,
		"client_addr", clientAddr,
		"upstream_addr", proxyConn.RemoteAddr())
	writeHTTPError(conn, errUnparseableResponse)
}
