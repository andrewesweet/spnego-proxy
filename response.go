package main

import (
	"bufio"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// logTECLConflict logs the Transfer-Encoding / Content-Length conflict
// resolution warning per RFC 9110 §6.2. direction is "request" or "response".
func logTECLConflict(direction string, te []string, cl string) {
	slog.Warn("TE/CL conflict resolved",
		"direction", direction,
		"action", "removed Content-Length per RFC 9110 §6.2",
		"transfer_encoding", te,
		"content_length", cl)
}

// validateResponseHeaderBytes scans every upstream-emitted header field name
// and value for octets that RFC 9110 §5.5 / RFC 9112 §11.1 forbid: bare CR,
// bare LF, NUL, and other ASCII control characters (octets 0x00-0x08,
// 0x0A-0x1F, excluding HTAB 0x09). The presence of any such octet inside a
// post-parse value indicates either a malformed upstream emitter or a
// response-splitting attempt; either way the proxy MUST NOT relay it.
// Returns a non-nil *proxyError to reject the response with 502.
//
// Field names are validated against the RFC 9110 §5.1 tchar production so
// that header lines with control characters in the name are also rejected.
//
// These checks duplicate golang.org/x/net/http/httpguts.ValidHeaderField*,
// but that package transitively imports golang.org/x/net/idna →
// golang.org/x/text, which is otherwise not a dependency. The ASCII byte
// scans below are trivial, allocation-free, and keep the dependency
// surface of this security-sensitive proxy minimal.
//
// Note: when an upstream emits a value containing a clean "\r\n" sequence
// followed by another well-formed "Name: value" pair, Go's textproto parser
// splits them into two distinct headers — this is indistinguishable from
// an intentional dual-header response and cannot be detected here.
func validateResponseHeaderBytes(resp *http.Response) *proxyError {
	for name, values := range resp.Header {
		if !isValidFieldName(name) {
			return errMalformedResponseHeader
		}
		if slices.ContainsFunc(values, hasForbiddenFieldValueByte) {
			return errMalformedResponseHeader
		}
	}
	return nil
}

// isValidFieldName reports whether name contains only RFC 9110 §5.1 tchar
// characters. Used to reject upstream response header names containing
// control characters introduced via a response-splitting attempt.
func isValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.',
			'^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

// hasForbiddenFieldValueByte reports whether v contains any octet forbidden
// in an HTTP field-value per RFC 9110 §5.5: NUL, CR, LF, and other ASCII
// control characters (0x00-0x08, 0x0A-0x1F). HTAB (0x09) is permitted.
// obs-text (0x80-0xFF) is also permitted because senders MAY emit it and
// recipients SHOULD pass it through.
func hasForbiddenFieldValueByte(v string) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
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

// errMalformedResponse is a sentinel error returned by readUpstreamResponse
// when the upstream response contains a malformed header field name or
// forbidden control octet in a header value (RFC 9110 §5.5 / RFC 9112 §11.1).
var errMalformedResponse = errors.New("malformed upstream response header")

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

	// RFC 9110 §5.5 / RFC 9112 §11.1: reject responses whose header field
	// names or values contain forbidden control octets (response-splitting
	// defence-in-depth). Go's textproto parser already rejects most such
	// content, but a bare CR mid-value or a NUL byte can survive parsing.
	if pe := validateResponseHeaderBytes(resp); pe != nil {
		_ = resp.Body.Close()
		return nil, errMalformedResponse
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
