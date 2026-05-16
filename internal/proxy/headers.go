package proxy

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

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

// GenerateViaPseudonym returns a unique pseudonym for this proxy instance,
// used in the Via header to identify this specific process. The format is
// "spnego-proxy-<8-hex-chars>", providing 2^32 unique identifiers — sufficient
// for loop detection across chains of spnego-proxy instances.
func GenerateViaPseudonym() string {
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
