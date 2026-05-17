package proxy

// HTTP header field names and protocol value literals used across the proxy.
//
// INVARIANT: every header-name constant MUST be in HTTP canonical form
// (e.g. "Content-Length", not "content-length"). Several call sites read or
// write the http.Header map directly — header[headerConnection],
// resp.Header[headerContentLength], and http.Header{...} composite literals —
// which bypass net/http's automatic canonicalisation. A non-canonical value
// here would silently fail to match at those sites. Do not "normalise" these
// strings.
//
// Every value below is byte-for-byte identical to the literal it replaced;
// this catalogue is a pure refactor with no behaviour change.

// HTTP header field names (RFC 9110 canonical form).
const (
	headerForwarded          = "Forwarded"         // RFC 7239
	headerXForwardedFor      = "X-Forwarded-For"   // de facto
	headerXForwardedProto    = "X-Forwarded-Proto" // de facto
	headerXForwardedHost     = "X-Forwarded-Host"  // de facto
	headerVia                = "Via"               // RFC 9110 §7.6.3
	headerConnection         = "Connection"        // RFC 9110 §7.6.1
	headerKeepAlive          = "Keep-Alive"
	headerProxyConnection    = "Proxy-Connection" // non-standard hop-by-hop
	headerTE                 = "TE"
	headerTrailer            = "Trailer"
	headerUpgrade            = "Upgrade"
	headerProxyAuthorization = "Proxy-Authorization" // RFC 9110 §11.7.1
	headerProxyAuthenticate  = "Proxy-Authenticate"  // RFC 9110 §11.7.2
	headerContentLength      = "Content-Length"      // RFC 9112 §6.1
	headerContentType        = "Content-Type"
	headerAllow              = "Allow"        // RFC 9110 §10.2.1
	headerMaxForwards        = "Max-Forwards" // RFC 9110 §7.6.2
	headerProxyStatus        = "Proxy-Status" // RFC 9209
)

// Protocol value literals. Correctness-sensitive, not merely deduplication:
// negotiateScheme carries a MANDATORY trailing space (RFC 4559 auth-scheme
// followed by SP before the token).
const (
	negotiateScheme     = "Negotiate "                // RFC 4559; trailing SP REQUIRED — do not trim
	connectionClose     = "close"                     // Connection header value
	contentTypeTextUTF8 = "text/plain; charset=utf-8" // exact: single space after ';'
	proxyStatusPrefix   = "spnego-proxy; error="      // RFC 9209 + RFC 8941; trailing '=' intentional
	schemeHTTP          = "http"                      // X-Forwarded-Proto default
	allowMethods        = "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, CONNECT"
)
