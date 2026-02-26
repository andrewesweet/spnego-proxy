# HTTP Proxy Standards Compliance Requirements for spnego-proxy

## 1. Applicable Standards

### De Jure Standards (IETF RFCs)

| RFC | Title | Status | Relevance to spnego-proxy |
| ----- | ------- | -------- | --------------------------- |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) | HTTP Semantics | Internet Standard | Core proxy behavior: Via, Connection, CONNECT, Max-Forwards, Expect, proxy auth |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html) | HTTP/1.1 | Internet Standard | Message framing, Transfer-Encoding/Content-Length handling, CONNECT tunneling |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html) | HTTP/2 | Internet Standard | HTTP/2 proxy semantics, pseudo-headers, connection-specific header removal |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html) | HTTP/3 | Internet Standard | HTTP/3 proxy semantics (QUIC transport) |
| [RFC 9209](https://www.rfc-editor.org/rfc/rfc9209.html) | Proxy-Status Header | Proposed Standard | Structured error reporting from intermediaries |
| [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) | HTTP Caching | Internet Standard | Cache-related headers proxies must not corrupt |
| [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html) | Forwarded HTTP Extension | Proposed Standard | Standardized client identity forwarding |
| [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559.html) | SPNEGO-based HTTP Auth | Informational | Negotiate authentication scheme (already implemented) |
| [RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html) | Using Early Data in HTTP | Standards Track | 0-RTT / Early-Data header handling for intermediaries |

### De Facto Standards

| Header/Convention | Origin | Relevance |
| ------------------- | -------- | ----------- |
| `X-Forwarded-For` | Squid proxy (1990s) | Client IP preservation; widely expected by upstream proxies |
| `X-Forwarded-Proto` | De facto convention | Original protocol scheme preservation |
| `X-Forwarded-Host` | De facto convention | Original Host header preservation |
| `Proxy-Connection` | Netscape Navigator (non-standard) | Legacy hop-by-hop header; must not be forwarded |

---

## 2. Requirements Extracted from Standards

Each requirement is tagged with:

- **Normative level**: MUST, SHOULD, or MAY (per RFC 2119)
- **Source**: Exact RFC and section
- **Applicability**: Whether it applies to the current spnego-proxy architecture (forward proxy, HTTP/1.1, TCP transport)

---

### Group A: Proxy Identification and Traceability

#### A1. Via Header — Append on Every Forwarded Message

> "An intermediary MUST send an appropriate Via header field, as described in Section 7.6.3, in each message that it forwards."
>
> — RFC 9110, §7.6.3

**Level**: MUST
**Details**: Each intermediary MUST append its own Via entry indicating the received protocol version and a `received-by` identifier (hostname, IP, or pseudonym). The protocol name "HTTP" MAY be omitted. Existing Via entries MUST NOT be removed.

**Format**: `Via: <received-protocol> <received-by> [<comment>]`
**Example**: `Via: 1.1 spnego-proxy` or `Via: 1.1 pseudonym`

**Privacy note**: An intermediary used as a portal through a network firewall SHOULD NOT forward the names and ports of hosts within the firewall region unless explicitly enabled to do so. An intermediary MAY replace the received-by with a pseudonym (RFC 9110, §7.6.3).

**Testing strategy**:

- **White-box integration test**: Send a request through spnego-proxy to a test upstream that echoes back received headers. Assert the request arriving at upstream contains a `Via` header with the correct protocol version and identifier.
- **Test chained Via**: Send a request that already has a `Via` header. Assert the proxy appends (not replaces) its entry.
- **Test pseudonym mode**: When configured for privacy, assert the Via entry uses a pseudonym rather than hostname.
- **Traceability**: Each assertion maps to RFC 9110, §7.6.3 ¶2–3.

#### A2. Via Header — Loop Detection

> The Via header field can be used to detect forwarding loops, since each intermediary that processes a message is required to add its own Via entry.
>
> — RFC 9110, §7.6.3

**Level**: SHOULD (implied by MUST append + detection guidance)
**Details**: A proxy SHOULD detect its own identifier in an incoming Via header and return `502 Bad Gateway` (or use `Proxy-Status: proxy_loop_detected` per RFC 9209, §2.3.2.8).

**Testing strategy**:

- **White-box integration test**: Construct a request with a `Via` header already containing the proxy's identifier. Assert the proxy returns 502 or a loop-detection error response.
- **Traceability**: RFC 9110 §7.6.3 + RFC 9209 §2.3.2.8.

#### A3. Proxy-Status Header — Error Reporting

> "When generating a Proxy-Status field, each member of the list identifies the intermediary that inserted the value."
>
> — RFC 9209, §2

**Level**: MAY (proxy decides when to add it)
**Details**: When the proxy generates an error response (e.g., upstream connection failure, auth failure, timeout), it SHOULD include a `Proxy-Status` header with a structured value identifying the proxy and the error type. The intermediary identifier MUST have a type of either String or Token (RFC 9209, §2).

Defined error types relevant to spnego-proxy:

| Error Type | Description | HTTP Status | RFC 9209 Section |
| --- | --- | --- | --- |
| `destination_not_found` | Cannot determine next hop | 502 | §2.3.2.1 |
| `destination_unavailable` | Next hop refuses connection | 502 | §2.3.2.2 |
| `connection_timeout` | Connecting to next hop timed out | 504 | §2.3.2.4 |
| `connection_refused` | Next hop refused TCP connection | 502 | §2.3.2.5 |
| `connection_terminated` | Connection closed prematurely | 502 | §2.3.2.6 |
| `dns_error` | DNS resolution failure | 502 | §2.3.2.9 |
| `dns_timeout` | DNS resolution timed out | 504 | §2.3.2.10 |
| `proxy_internal_error` | Internal proxy error | 500 | §2.3.2.12 |
| `proxy_loop_detected` | Request loop detected | 502 | §2.3.2.8 |
| `proxy_configuration_error` | Proxy misconfigured | 500 | §2.3.2.13 |
| `http_request_error` | Malformed request | 400 | §2.3.2.16 |

**Testing strategy**:

- **White-box integration test**: For each error scenario (upstream unreachable, DNS failure, timeout, auth failure), trigger the condition and assert the error response includes a correctly-formatted `Proxy-Status` header with the appropriate error type.
- **Test structured field format**: Assert the Proxy-Status value parses as a valid Structured Field (RFC 8941).
- **Traceability**: Each error type maps 1:1 to RFC 9209 §2.3.2.x.

---

### Group B: Hop-by-Hop Header Handling

#### B1. Connection Header — Remove Hop-by-Hop Headers

> "A proxy or gateway MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove the corresponding header field(s) from the message and then remove the Connection header field itself (or replace it with the intermediary's own connection options for the forwarded message)."
>
> — RFC 9110, §7.6.1

**Level**: MUST
**Details**: Before forwarding, the proxy MUST:

1. Parse the `Connection` header to find all listed field names
2. Remove each header field named in Connection
3. Remove the Connection header itself
4. Also remove these well-known hop-by-hop headers even if not listed: `Keep-Alive`, `Transfer-Encoding` (when translating versions), `TE`, `Trailer`, `Upgrade`, `Proxy-Connection`

**Testing strategy**:

- **White-box integration test**: Send a request with `Connection: X-Custom-Hop\r\nX-Custom-Hop: value\r\nKeep-Alive: timeout=5`. Assert the upstream receives neither `Connection`, `X-Custom-Hop`, nor `Keep-Alive`.
- **Test Proxy-Connection removal**: Send a request with `Proxy-Connection: keep-alive`. Assert it is not forwarded.
- **Traceability**: RFC 9110 §7.6.1 ¶5–7.

#### B2. Proxy-Authorization — Hop-by-Hop Consumption

> "A proxy that forwards a request MUST NOT forward the Proxy-Authorization field value from a downstream client."
>
> — RFC 9110, §11.7.1

**Level**: MUST NOT
**Details**: The `Proxy-Authorization` header is hop-by-hop. A proxy MUST consume it (for its own authentication) and NOT forward it to the next hop unless the next hop explicitly requires it with its own 407 challenge. spnego-proxy already injects its own `Proxy-Authorization: Negotiate` header; it must ensure it does not also forward any `Proxy-Authorization` sent by the original client.

**Testing strategy**:

- **White-box integration test**: Send a request with `Proxy-Authorization: Basic dXNlcjpwYXNz` from the client. Assert the upstream receives `Proxy-Authorization: Negotiate <token>` (injected by spnego-proxy) and NOT the client's original Basic auth header.
- **Traceability**: RFC 9110 §11.7.1.

#### B3. Do Not Forward Proxy-Authenticate Downstream

> "A proxy MUST NOT forward a Proxy-Authenticate header field to a client unless the proxy is explicitly configured to do so."
>
> — RFC 9110, §11.7.2 (implied by hop-by-hop semantics)

**Level**: MUST NOT (implied)
**Details**: If the upstream proxy returns `407 Proxy Authentication Required` with a `Proxy-Authenticate` header, spnego-proxy must consume this for its own SPNEGO negotiation and NOT forward the 407/Proxy-Authenticate to the downstream client. The client should not see the upstream's authentication challenges.

**Testing strategy**:

- **White-box integration test**: Configure a mock upstream that returns 407 with `Proxy-Authenticate: Negotiate`. Assert spnego-proxy handles this internally and does not forward the 407 to the client.
- **Traceability**: RFC 9110 §11.7.2.

---

### Group C: Request Forwarding Fidelity

#### C1. Preserve Header Field Order

> "A proxy MUST NOT change the order of these field line values when forwarding a message."
>
> — RFC 9110, §5.3

**Level**: MUST NOT
**Details**: When multiple header fields share the same name, their relative order is semantically significant. The proxy must preserve this ordering when forwarding.

**Testing strategy**:

- **White-box integration test**: Send a request with multiple `Cookie` headers (or other repeated headers) in a specific order. Assert the upstream receives them in the same order.
- **Traceability**: RFC 9110 §5.3 ¶1.

#### C2. Forward Unrecognized Header Fields

> "A proxy MUST forward unrecognized header fields unless the field name is listed in the Connection header field (Section 7.6.1) or the proxy is specifically configured to block, or otherwise transform, such fields."
>
> — RFC 9110, §5.1

**Level**: MUST
**Details**: The proxy must be transparent to headers it does not understand. Only hop-by-hop headers (listed in Connection) or explicitly blocked headers may be removed.

**Testing strategy**:

- **White-box integration test**: Send a request with a custom header `X-Exotic-Widget: foo`. Assert it arrives at the upstream unchanged.
- **Traceability**: RFC 9110 §5.1.

#### C3. Host Header Regeneration from Request-Target

> "When a proxy receives a request with an absolute-form of request-target, the proxy MUST ignore the received Host header field (if any) and instead replace it with the host information of the request-target."
>
> — RFC 9112, §3.2.2

**Level**: MUST
**Details**: When a client sends a request to a forward proxy, it uses absolute-form (e.g., `GET http://example.com/path HTTP/1.1`). The proxy MUST regenerate the Host header from the request-target URI, ignoring any Host header the client sent. This is stronger than mere "reconciliation" — the request-target is authoritative.

**Testing strategy**:

- **White-box integration test**: Send `GET http://example.com/path HTTP/1.1` with `Host: other.com`. Assert the upstream receives `Host: example.com`.
- **Test with matching Host**: Send with `Host: example.com`. Assert Host is still correctly set.
- **Traceability**: RFC 9112 §3.2.2.

#### C4. Preserve Request-Target Path and Query

> "A proxy MUST NOT modify the 'absolute-path' and 'query' parts of the received request-target when forwarding it to the next inbound server, except to replace an empty path with '/' or '*'."
>
> — RFC 9112, §3.2.2

**Level**: MUST NOT
**Details**: The proxy must forward the path and query string exactly as received. Only an empty path may be replaced with `/`.

**Testing strategy**:

- **White-box integration test**: Send `GET http://example.com/path?q=1&r=2%20 HTTP/1.1`. Assert the upstream receives the path and query unmodified.
- **Test empty path**: Send `GET http://example.com HTTP/1.1`. Assert the upstream receives `/` as the path.
- **Traceability**: RFC 9112 §3.2.2.

#### C5. Do Not Forward Authorization Header (Pass-Through)

> "A proxy forwarding a request MUST NOT modify any Authorization header fields in that request."
>
> — RFC 9110, §11.7.2

**Level**: MUST NOT modify
**Details**: The `Authorization` header is end-to-end (unlike `Proxy-Authorization`). The proxy must pass it through unaltered to the origin server.

**Testing strategy**:

- **White-box integration test**: Send a request with `Authorization: Bearer token123`. Assert the upstream receives it unchanged.
- **Traceability**: RFC 9110 §11.7.2.

#### C6. Remove Whitespace Between Header Name and Colon

> "A proxy MUST remove any whitespace between a header field name and colon in a response message before forwarding the message downstream."
>
> — RFC 9112, §5.2

**Level**: MUST
**Details**: If the upstream sends a response with `Header : value` (space before colon), the proxy must normalize it to `Header: value` before forwarding to the client.

**Testing strategy**:

- **White-box integration test**: Mock upstream sends a response with `Content-Type : text/plain` (space before colon). Assert the client receives `Content-Type: text/plain` (no space).
- **Traceability**: RFC 9112 §5.2.

#### C7. No-Transform Content Integrity

> "A proxy MUST NOT transform the content of a message that contains a no-transform cache directive."
>
> — RFC 9110, §7.7

**Level**: MUST NOT
**Details**: When `Cache-Control: no-transform` is present, the proxy must not modify the message body in any way (compression, encoding changes, etc.). Since spnego-proxy is transparent by design, this is likely already satisfied, but should be tested.

**Testing strategy**:

- **White-box integration test**: Send a request with `Cache-Control: no-transform`. Assert the response body arrives at the client byte-for-byte identical to what the upstream sent.
- **Traceability**: RFC 9110 §7.7.

---

### Group D: CONNECT Tunnel Handling

#### D1. CONNECT — Tunnel Establishment

> "The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request target and, if successful, thereafter restrict its behavior to blind forwarding of data, in both directions, until the tunnel is closed."
>
> — RFC 9110, §9.3.6

**Level**: MUST (implicit in method definition)
**Details**: spnego-proxy already implements CONNECT tunneling. The request-target MUST be `host:port` only — no path, no query. A 2xx response indicates tunnel mode is active.

**Testing strategy**:

- **Existing tests** already cover basic CONNECT tunneling.
- **Additional test**: Assert that a CONNECT request without a port is rejected (RFC 9110 §9.3.6 ¶2: "There is no default port; a client MUST send the port number").
- **Traceability**: RFC 9110 §9.3.6 ¶1–3.

#### D2. CONNECT — Tunnel Closure and Data Draining

> "A tunnel intermediary MUST attempt to send any outstanding data that came from the closed side to the other side, close both connections, and then discard any remaining data left undelivered."
>
> — RFC 9110, §9.3.6

**Level**: MUST
**Details**: When one side of the tunnel closes, the proxy must drain buffered data to the other side before closing. spnego-proxy already implements half-close support via `CloseWrite()`.

**Testing strategy**:

- **Existing tests** (`TestHandleClientForwardsBufferedData`) partially cover this.
- **Additional test**: Close the upstream side with pending data. Assert all pending bytes are delivered to the client before the client connection is closed.
- **Traceability**: RFC 9110 §9.3.6 ¶8.

#### D3. CONNECT — No Transfer-Encoding in 2xx Response

> "A server MUST NOT send a Transfer-Encoding header field in any 2xx (Successful) response to a CONNECT request."
>
> — RFC 9112, §6.1

**Level**: MUST NOT
**Details**: When generating the 200 response to a CONNECT request, spnego-proxy must not include Transfer-Encoding.

**Testing strategy**:

- **White-box integration test**: Perform a CONNECT request. Assert the 200 response contains no `Transfer-Encoding` header.
- **Traceability**: RFC 9112 §6.1.

#### D4. CONNECT — Restrict to Safe Ports

> "Proxies that support CONNECT SHOULD restrict its use to a set of known ports or a configurable list of safe request targets."
>
> — RFC 9110, §9.3.6

**Level**: SHOULD
**Details**: To prevent abuse, the proxy should allow CONNECT only to commonly expected ports (e.g., 443 for HTTPS, 80). This is a security hardening measure.

**Testing strategy**:

- **White-box integration test**: Attempt CONNECT to a disallowed port (e.g., 25/SMTP). Assert the proxy returns 403 Forbidden.
- **Test allowed ports**: CONNECT to 443. Assert tunnel is established.
- **Traceability**: RFC 9110 §9.3.6 ¶10.

#### D5. CONNECT — Close Connection on Rejection

> "Proxy servers MUST close the underlying connection when rejecting a CONNECT request, without processing any further requests on that connection."
>
> — RFC 9112, §11.2

**Level**: MUST
**Details**: When the proxy rejects a CONNECT request (e.g., forbidden port, auth failure), it must close the TCP connection after sending the error response. It must not attempt to read further requests on the same connection.

**Testing strategy**:

- **White-box integration test**: Send a CONNECT request that the proxy rejects (e.g., bad port). Assert the connection is closed after the error response. Attempt to send another request on the same connection; assert it fails.
- **Traceability**: RFC 9112 §11.2.

#### D6. CONNECT — Wait for 2xx Before Forwarding Payload

> "Proxy clients that send CONNECT requests on behalf of untrusted TCP clients MUST wait for a 2xx (Successful) response before forwarding any TCP payload data."
>
> — RFC 9112, §11.2

**Level**: MUST
**Details**: When spnego-proxy sends a CONNECT request to the upstream proxy, it must not forward any client data until it has received a 2xx response from the upstream. Premature forwarding can lead to request smuggling.

**Testing strategy**:

- **White-box integration test**: Client sends CONNECT followed immediately by payload data. Assert that spnego-proxy holds the payload and only forwards it after receiving 200 from upstream.
- **Traceability**: RFC 9112 §11.2.

#### D7. CONNECT — No 2xx Without Established Connection

> "A proxy MUST NOT respond with any 2xx (Successful) status code unless it has either a direct or tunnel connection established to the authority."
>
> — RFC 9110, §9.3.6

**Level**: MUST NOT
**Details**: The proxy must not send 200 to the client until the upstream TCP connection (or upstream tunnel) is actually established.

**Testing strategy**:

- **White-box integration test**: Mock upstream that delays TCP connection acceptance. Assert the client does not receive 200 until the upstream connection is established.
- **Test upstream refusal**: Mock upstream that refuses connection. Assert the client receives an error (not 200).
- **Traceability**: RFC 9110 §9.3.6 + RFC 2817 §5.2.

---

### Group E: Message Framing and Body Integrity

#### E1. Transfer-Encoding / Content-Length Conflict Resolution

> "If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length. Such a message might indicate an attempt to perform request smuggling (Section 11.2) or response splitting (Section 11.1)."
>
> "An intermediary that chooses to forward the message MUST first remove the received Content-Length field prior to forwarding it downstream."
>
> — RFC 9112, §6.1

**Level**: MUST
**Details**: When both `Transfer-Encoding` and `Content-Length` are present, the proxy MUST remove `Content-Length` before forwarding to prevent request smuggling attacks.

**Testing strategy**:

- **White-box integration test**: Send a request with both `Transfer-Encoding: chunked` and `Content-Length: 100`. Assert the upstream receives `Transfer-Encoding: chunked` but NOT `Content-Length`.
- **Test response direction**: Mock an upstream response with both headers. Assert the client receives only `Transfer-Encoding`.
- **Traceability**: RFC 9112 §6.1, RFC 9112 §11.2 (request smuggling).

#### E2. Invalid Content-Length Without Transfer-Encoding

> "If it is in a response message received by a proxy, the proxy MUST close the connection to the server, discard the received response, and send a 502 (Bad Gateway) response to the client."
>
> — RFC 9112, §6.1

**Level**: MUST
**Details**: If the upstream sends a response with an invalid Content-Length (and no Transfer-Encoding), the proxy must reject it with 502.

**Testing strategy**:

- **White-box integration test**: Mock upstream sends a response with `Content-Length: abc` (non-numeric). Assert the proxy returns 502 to the client.
- **Traceability**: RFC 9112 §6.1.

#### E3. obs-fold Handling

> "A proxy or gateway that receives an obs-fold in a response message that is not within a message/http container MUST either discard the message and replace it with a 502 (Bad Gateway) response, or replace each received obs-fold with one or more SP octets prior to interpreting the field value or forwarding the message downstream."
>
> — RFC 9112, §5.2

**Level**: MUST
**Details**: Obsolete line folding (continuation lines starting with whitespace) in response headers must be either normalized or rejected.

**Testing strategy**:

- **White-box integration test**: Mock upstream sends a response with an obs-fold header (`Header: value\r\n continued`). Assert the proxy either normalizes it to `Header: value continued` or returns 502.
- **Traceability**: RFC 9112 §5.2.

---

### Group F: Expect / 100-Continue Handling

#### F1. Forward Expect: 100-continue

> "A proxy MUST, if it knows the next-hop server complies with HTTP/1.1 or higher, or does not know the HTTP version of the next-hop server, forward the request, including the Expect header field."
>
> — RFC 9110, §10.1.1

**Level**: MUST
**Details**: If a client sends `Expect: 100-continue`, the proxy must forward the Expect header to the upstream (unless the upstream is known to be HTTP/1.0).

**Testing strategy**:

- **White-box integration test**: Client sends `Expect: 100-continue`. Assert the upstream receives the `Expect` header.
- **Test 100 response forwarding**: Upstream sends `100 Continue`. Assert the client receives it.
- **Traceability**: RFC 9110 §10.1.1 ¶4.

#### F2. Do Not Forward 100 to HTTP/1.0 Clients

> "A proxy MUST NOT forward a 100 (Continue) response if the request message was received from an HTTP/1.0 (or earlier) client and did not include an Expect request-header field with the '100-continue' expectation."
>
> — RFC 9110, §10.1.1

**Level**: MUST NOT
**Details**: If the downstream client is HTTP/1.0, the proxy must suppress 100 Continue interim responses from the upstream.

**Testing strategy**:

- **White-box integration test**: Client sends an HTTP/1.0 request without `Expect`. Mock upstream sends `100 Continue`. Assert the client does NOT receive the 100 response.
- **Traceability**: RFC 9110 §10.1.1 ¶5.

---

### Group G: Max-Forwards Handling

#### G1. Max-Forwards for TRACE and OPTIONS

> "A proxy MUST, before forwarding a TRACE or OPTIONS request with a Max-Forwards value, decrement the value by 1. If the decremented value is zero (0), the proxy MUST NOT forward the request; instead, the proxy SHOULD generate a 200 (OK) response."
>
> — RFC 9110, §7.6.2

**Level**: MUST / SHOULD
**Details**: For TRACE and OPTIONS requests that include `Max-Forwards`, the proxy must decrement and stop forwarding at zero.

**Testing strategy**:

- **White-box integration test**: Send `OPTIONS * HTTP/1.1` with `Max-Forwards: 1`. Assert the proxy decrements to 0 and generates a 200 response itself (not forwarded).
- **Send with Max-Forwards: 2**: Assert the upstream receives `Max-Forwards: 1`.
- **Traceability**: RFC 9110 §7.6.2.

---

### Group H: Forwarded / X-Forwarded-* Headers

#### H1. Forwarded Header (RFC 7239)

> "The Forwarded HTTP header field is an OPTIONAL header field that, when used, contains a list of parameter-identifier pairs that disclose information that is altered or lost when a proxy is involved in the path of the request."
>
> — RFC 7239, §4

**Level**: MAY (optional but standardized)
**Details**: If configured, the proxy SHOULD add a `Forwarded` header with these parameters:

- `for=<client-ip>` — the client's IP address (SHOULD be obfuscated by default, §6.3)
- `by=<proxy-ip>` — the proxy's receiving interface (SHOULD be obfuscated by default, §5.1)
- `host=<original-host>` — the Host header value from the client
- `proto=<scheme>` — the protocol used (http or https)

Syntax constraints:

- IPv6 addresses and `node:port` MUST be quoted (RFC 7239, §4)
- Obfuscated identifiers MUST have a leading underscore `_` (RFC 7239, §6.3)
- Obfuscated identifiers SHOULD be randomly generated per request (RFC 7239, §6.3)

**Testing strategy**:

- **White-box integration test**: Enable Forwarded header support. Assert the upstream receives `Forwarded: for="<client-ip>";by=_obfuscated;proto=http`.
- **Test IPv6 quoting**: Connect from an IPv6 address. Assert the `for` parameter is properly quoted.
- **Test obfuscation**: Assert that by default, identifiers are obfuscated (not raw IPs).
- **Test chaining**: Send a request that already has a `Forwarded` header. Assert the proxy appends rather than replaces.
- **Traceability**: RFC 7239 §§4–6.

#### H2. X-Forwarded-For (De Facto)

**Level**: MAY (no RFC; de facto convention)
**Details**: Widely expected by upstream servers and proxies. Contains the client's IP address. Multiple proxies append to a comma-separated list.

**Testing strategy**:

- **White-box integration test**: Enable X-Forwarded-For. Assert the upstream receives `X-Forwarded-For: <client-ip>`.
- **Test chaining**: Send with existing `X-Forwarded-For: 1.2.3.4`. Assert upstream gets `X-Forwarded-For: 1.2.3.4, <client-ip>`.
- **Traceability**: De facto convention; documented in MDN, Apache, nginx docs.

#### H3. X-Forwarded-Proto (De Facto)

**Level**: MAY
**Details**: Records the protocol used between the client and proxy.

**Testing strategy**:

- **White-box integration test**: Enable X-Forwarded-Proto. Assert upstream receives `X-Forwarded-Proto: http` (or `https` if TLS is used on the client-facing side).
- **Traceability**: De facto convention.

#### H4. X-Forwarded-Host (De Facto)

**Level**: MAY
**Details**: Records the original Host header from the client.

**Testing strategy**:

- **White-box integration test**: Enable X-Forwarded-Host. Client sends `Host: example.com`. Assert upstream receives `X-Forwarded-Host: example.com`.
- **Traceability**: De facto convention.

---

### Group I: Connection Management

#### I1. No Persistent Connection with HTTP/1.0 Clients

> "A proxy server MUST NOT maintain a persistent connection with an HTTP/1.0 client."
>
> — RFC 9112, §9.3

**Level**: MUST NOT
**Details**: If a client identifies as HTTP/1.0, the proxy must close the connection after the response. HTTP/1.0 does not support persistent connections by default (the `Connection: keep-alive` extension is non-standard and unreliable through proxies).

**Testing strategy**:

- **White-box integration test**: Send an HTTP/1.0 request. Assert the proxy closes the connection after the response.
- **Test HTTP/1.0 with Connection: keep-alive**: Assert the proxy still closes the connection (keep-alive is not reliable for HTTP/1.0 through proxies).
- **Traceability**: RFC 9112 §9.3.

#### I2. Honor Connection: close

> "A server that receives a 'close' connection option MUST initiate closure of the connection after it sends the final response to the request that contained the 'close'. The server MUST NOT process any further requests on that connection."
>
> — RFC 9112, §9.6

**Level**: MUST
**Details**: When a client sends `Connection: close`, the proxy must close the connection after sending the response.

**Testing strategy**:

- **White-box integration test**: Client sends a request with `Connection: close`. Assert the proxy closes the connection after the response.
- **Traceability**: RFC 9112 §9.6.

---

### Group J: Protocol Version and Upgrade

#### J1. Advertise HTTP/1.1

> "An HTTP intermediary that advertises conformance to HTTP/1.1 MUST advertise HTTP/1.1 in the responses it generates."
>
> — RFC 9112, §2.1 (paraphrased from version negotiation rules)

**Level**: MUST
**Details**: The proxy should use `HTTP/1.1` in its response status line, even when communicating with HTTP/1.0 clients, as long as it implements HTTP/1.1 correctly (especially chunked encoding).

**Testing strategy**:

- **White-box integration test**: Send an HTTP/1.0 request. Assert the proxy's own error responses (e.g., 502) use `HTTP/1.1` in the status line.
- **Traceability**: RFC 9112 §2.1.

#### J2. Upgrade Header Handling

> "A proxy or gateway MUST NOT forward the Upgrade header field to the next inbound server unless the proxy or gateway supports the protocol indicated by the Upgrade header field."
>
> — RFC 9110, §7.8

**Level**: MUST NOT (unless supported)
**Details**: The proxy should strip the `Upgrade` header unless it can actually negotiate the protocol upgrade.

**Testing strategy**:

- **White-box integration test**: Client sends `Upgrade: websocket`. Assert the proxy strips it unless WebSocket tunneling is supported.
- **Traceability**: RFC 9110 §7.8.

---

### Group K: Security and Access Control

#### K1. Request Smuggling Prevention

> See Group E (E1, E2) for Transfer-Encoding/Content-Length handling.
>
> — RFC 9112, §11.2

**Level**: MUST
**Details**: Covered by E1 and E2. This is cross-referenced here for completeness. The proxy must rigorously handle message framing to prevent request smuggling.

#### K2. CONNECT Port Restriction

> See D4 above.
>
> — RFC 9110, §9.3.6

#### K3. Proxy-Connection Stripping

**Level**: MUST (de facto requirement; never forward non-standard hop-by-hop headers)
**Details**: The non-standard `Proxy-Connection` header was introduced by Netscape and is sometimes sent by older clients. It must not be forwarded as it can confuse upstream servers and other intermediaries.

Per RFC 9113, §8.2.2: "intermediaries SHOULD also remove other connection-specific header fields, such as Keep-Alive, Proxy-Connection, Transfer-Encoding, and Upgrade."

**Testing strategy**:

- **White-box integration test**: Client sends `Proxy-Connection: keep-alive`. Assert it does not appear in the request forwarded to upstream.
- **Traceability**: RFC 9113 §8.2.2, de facto best practice.

---

### Group L: Error Response Generation

#### L1. 502 Bad Gateway for Upstream Failures

> "If the response received by a proxy is invalid or cannot be forwarded, the proxy MUST close the connection to the server, discard the received response, and send a 502 (Bad Gateway) response to the client."
>
> — RFC 9112, §6.1

**Level**: MUST
**Details**: When the upstream proxy is unreachable, returns malformed responses, or the connection fails, spnego-proxy must return 502. Currently, spnego-proxy generates plain-text error responses but doesn't consistently use 502.

**Testing strategy**:

- **White-box integration test**: Mock upstream that closes the connection immediately. Assert the proxy returns 502.
- **Test with malformed response**: Mock upstream sends invalid HTTP. Assert 502.
- **Traceability**: RFC 9112 §6.1.

#### L2. 504 Gateway Timeout for Upstream Timeouts

**Level**: SHOULD (implied by HTTP status code semantics)
**Details**: When the upstream connection times out, the proxy should return 504 rather than a generic error. RFC 9110, §15.6.5 defines 504.

**Testing strategy**:

- **White-box integration test**: Set a very short dial timeout. Mock upstream that delays beyond it. Assert the proxy returns 504.
- **Traceability**: RFC 9110 §15.6.5.

---

### Group M: HTTP/2 and HTTP/3 Considerations

#### M1. HTTP/2 Connection-Specific Header Removal

> "An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/3 endpoints as malformed."
>
> — RFC 9113, §8.2.2

**Level**: MUST (when doing HTTP/1.x to HTTP/2 translation)
**Details**: Not currently applicable since spnego-proxy operates at TCP level with HTTP/1.x only. Becomes relevant if HTTP/2 support is added.

#### M2. HTTP/2 CONNECT Pseudo-Header Requirements

> "In HTTP/2, the CONNECT method: the :method pseudo-header field is set to CONNECT; the :scheme and :path pseudo-header fields MUST be omitted; the :authority pseudo-header field contains the host and port to connect to."
>
> — RFC 9113, §8.5

**Level**: MUST (when implementing HTTP/2)
**Details**: Not currently applicable. Relevant if HTTP/2 client-facing or upstream support is added.

#### M3. HTTP/3 Support

**Level**: N/A currently
**Details**: HTTP/3 uses QUIC (UDP) transport. spnego-proxy uses TCP. HTTP/3 support would require a fundamentally different transport layer. This is included for completeness.

---

### Group N: Early Data (0-RTT)

#### N1. Early-Data Header for Intermediaries

> "An intermediary that forwards a request prior to the completion of the TLS handshake with its client MUST send it with the Early-Data header field set to '1'."
>
> — RFC 8470, §5.1

**Level**: MUST (when forwarding early data)
**Details**: If spnego-proxy accepts TLS connections and forwards requests received during 0-RTT, it must add `Early-Data: 1`. Not currently applicable (spnego-proxy listens on plain TCP).

#### N2. Must Not Remove Early-Data Header

> "An intermediary MUST NOT remove this header field if it is present in a request."
>
> — RFC 8470, §5.1

**Level**: MUST NOT
**Details**: Even without TLS support, the proxy must pass through an `Early-Data` header if present.

**Testing strategy**:

- **White-box integration test**: Client sends `Early-Data: 1`. Assert the upstream receives it unchanged.
- **Traceability**: RFC 8470 §5.1.

---

## 3. Requirements Grouped by Current Applicability

### Tier 1: Immediately Applicable (HTTP/1.1, forward proxy, current architecture)

| ID | Requirement | Level |
| ---- | ------------- | ------- |
| A1 | Via header — append on forwarded messages | MUST |
| A2 | Via header — loop detection | SHOULD |
| B1 | Connection header — remove hop-by-hop headers | MUST |
| B2 | Proxy-Authorization — consume, don't forward client's | MUST NOT forward |
| B3 | Proxy-Authenticate — don't forward upstream's challenges | MUST NOT forward |
| C1 | Preserve header field order | MUST NOT reorder |
| C2 | Forward unrecognized headers | MUST |
| C3 | Host header regeneration from request-target | MUST |
| C4 | Preserve request-target path and query | MUST NOT modify |
| C5 | Pass through Authorization header unmodified | MUST NOT modify |
| C6 | Remove whitespace between header name and colon | MUST |
| C7 | No-transform content integrity | MUST NOT transform |
| D1 | CONNECT tunnel establishment | Already implemented |
| D2 | CONNECT tunnel closure / data draining | Partially implemented |
| D3 | No Transfer-Encoding in CONNECT 2xx | MUST NOT |
| D4 | CONNECT port restriction | SHOULD |
| D5 | Close connection on CONNECT rejection | MUST |
| D6 | Wait for 2xx before forwarding CONNECT payload | MUST |
| D7 | No 2xx without established upstream connection | MUST NOT |
| E1 | TE/CL conflict resolution | MUST |
| E2 | Invalid Content-Length → 502 | MUST |
| E3 | obs-fold handling | MUST |
| F1 | Forward Expect: 100-continue | MUST |
| F2 | Don't forward 100 to HTTP/1.0 clients | MUST NOT |
| G1 | Max-Forwards for TRACE/OPTIONS | MUST |
| I1 | No persistent connection with HTTP/1.0 clients | MUST NOT |
| I2 | Honor Connection: close | MUST |
| J1 | Advertise HTTP/1.1 | MUST |
| J2 | Strip Upgrade unless supported | MUST NOT forward |
| K3 | Strip Proxy-Connection | SHOULD |
| L1 | 502 for upstream failures | MUST |
| L2 | 504 for upstream timeouts | SHOULD |
| N2 | Preserve Early-Data header | MUST NOT remove |

### Tier 2: Valuable Additions (optional but high value)

| ID | Requirement | Level |
| ---- | ------------- | ------- |
| A3 | Proxy-Status error reporting | MAY |
| H1 | Forwarded header (RFC 7239) | MAY |
| H2 | X-Forwarded-For | MAY |
| H3 | X-Forwarded-Proto | MAY |
| H4 | X-Forwarded-Host | MAY |

### Tier 3: Future / Not Applicable Yet

| ID | Requirement | Level |
| ---- | ------------- | ------- |
| M1 | HTTP/2 connection-specific header removal | MUST (when HTTP/2) |
| M2 | HTTP/2 CONNECT pseudo-headers | MUST (when HTTP/2) |
| M3 | HTTP/3 support | N/A |
| N1 | Early-Data header injection | MUST (when TLS) |

---

## 4. Recommended Implementation Order

Ordered by value: correctness/security requirements first, then observability, then optional features.

### Phase 1: Test Infrastructure Foundation

**Prerequisite**: Create a shared white-box integration test harness that can:

- Start spnego-proxy with a mock `TokenProvider`
- Start a programmable mock upstream proxy that can echo headers, delay, return errors, etc.
- Capture requests arriving at the upstream
- Assert on both client-received responses and upstream-received requests

This harness will be reused by all subsequent requirement implementations and iteratively improved.

### Phase 2: Correctness — Hop-by-Hop Header Hygiene (Security-Critical)

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 1 | B1 | Connection header / hop-by-hop removal | **Security**: prevents request smuggling, hop-by-hop header leakage; most fundamental proxy requirement |
| 2 | B2 | Consume client Proxy-Authorization | **Security**: prevents credential leakage to upstream |
| 3 | K3 | Strip Proxy-Connection | **Security**: prevents confusion with non-standard hop-by-hop header |
| 4 | J2 | Strip Upgrade unless supported | **Security**: prevents protocol confusion |
| 5 | E1 | TE/CL conflict → remove CL | **Security**: prevents request smuggling |
| 6 | E2 | Invalid CL → 502 | **Security**: prevents message framing attacks |

### Phase 3: Correctness — Proxy Identity and Error Handling

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 7 | A1 | Via header | **Compliance**: MUST-level RFC 9110 requirement; enables loop detection |
| 8 | A2 | Via loop detection | **Reliability**: prevents infinite proxy loops |
| 9 | L1 | 502 for upstream failures | **Compliance**: proper error status codes |
| 10 | L2 | 504 for timeouts | **Compliance**: distinguishes timeout from failure |
| 11 | D3 | No TE in CONNECT 2xx | **Compliance**: MUST NOT violation is easy to fix |
| 12 | J1 | Advertise HTTP/1.1 | **Compliance**: version advertisement |

### Phase 4: Correctness — Request Forwarding Fidelity

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 13 | C1 | Preserve header order | **Correctness**: MUST NOT reorder |
| 14 | C2 | Forward unrecognized headers | **Correctness**: MUST forward (likely already works, needs test) |
| 15 | C3 | Host header regeneration from request-target | **Correctness**: MUST regenerate from URI |
| 16 | C4 | Preserve request-target path and query | **Correctness**: MUST NOT modify |
| 17 | C5 | Pass through Authorization header | **Correctness**: MUST NOT modify end-to-end auth |
| 18 | C6 | Remove whitespace before colon in responses | **Correctness**: MUST normalize |
| 19 | C7 | No-transform content integrity | **Correctness**: MUST NOT transform with no-transform |
| 20 | B3 | Don't forward Proxy-Authenticate | **Correctness**: consume upstream auth challenges |
| 21 | E3 | obs-fold handling | **Correctness**: MUST handle legacy headers |

### Phase 5: Correctness — CONNECT Hardening

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 22 | D5 | Close connection on CONNECT rejection | **Security**: MUST close to prevent smuggling |
| 23 | D6 | Wait for 2xx before forwarding CONNECT payload | **Security**: MUST prevent premature forwarding |
| 24 | D7 | No 2xx without established upstream connection | **Correctness**: MUST NOT send premature 200 |
| 25 | D2 | CONNECT data draining on close | **Correctness**: partially implemented, needs hardening |
| 26 | D4 | CONNECT port restriction | **Security**: SHOULD restrict |

### Phase 6: Correctness — Protocol Edge Cases

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 27 | F1 | Forward Expect: 100-continue | **Correctness**: prevents client hangs |
| 28 | F2 | Suppress 100 for HTTP/1.0 | **Correctness**: version-dependent behavior |
| 29 | G1 | Max-Forwards for TRACE/OPTIONS | **Correctness**: MUST decrement |
| 30 | I1 | No persistent connection with HTTP/1.0 | **Correctness**: MUST NOT maintain |
| 31 | I2 | Honor Connection: close | **Correctness**: MUST close when requested |
| 32 | N2 | Preserve Early-Data header | **Correctness**: MUST NOT remove |

### Phase 7: Observability — Proxy-Status

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 33 | A3 | Proxy-Status header | **Observability**: structured error reporting aids debugging |

### Phase 8: Client Identity Forwarding

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 34 | H1 | Forwarded header (RFC 7239) | **Observability**: standardized client identity |
| 35 | H2 | X-Forwarded-For | **Compatibility**: widely expected de facto header |
| 36 | H3 | X-Forwarded-Proto | **Compatibility**: scheme preservation |
| 37 | H4 | X-Forwarded-Host | **Compatibility**: host preservation |

### Phase 9: Future — HTTP/2 and HTTP/3

| Priority | ID | Requirement | Rationale |
| ---------- | ----- | ------------- | ----------- |
| 38 | M1 | HTTP/2 header cleanup | **Future**: when HTTP/2 support is added |
| 39 | M2 | HTTP/2 CONNECT | **Future**: when HTTP/2 support is added |
| 40 | M3 | HTTP/3 support | **Future**: requires QUIC transport |
| 41 | N1 | Early-Data injection | **Future**: when TLS listener is added |

---

## 5. Testing Strategy Overview

### Shared Test Harness Design

The test harness should support:

```text
Client <--TCP--> spnego-proxy <--TCP--> Mock Upstream Proxy
```

**Components**:

1. **MockUpstreamProxy**: A programmable HTTP server that:
   - Records all received requests (headers, body, method, URI)
   - Returns configurable responses (status, headers, body, delays)
   - Can simulate errors (close connection, send malformed responses, delay indefinitely)
   - Can require Negotiate auth (return 407 then accept)

2. **ProxyUnderTest**: spnego-proxy started with:
   - A mock `TokenProvider` (returns a fixed token)
   - Configurable flags (debug, timeouts, etc.)
   - Listening on a dynamic port

3. **TestClient**: Makes HTTP requests through the proxy and captures responses.

4. **Assertions**: Helper functions to:
   - Assert a header is present/absent in upstream-received requests
   - Assert header order
   - Assert response status codes
   - Assert `Via`, `Forwarded`, `Proxy-Status` field syntax

### Test Naming Convention

Tests should be named to trace back to the standard:

```text
TestRFC9110_7_6_3_ViaHeaderAppended
TestRFC9110_7_6_1_HopByHopHeadersRemoved
TestRFC9112_6_1_TECLConflictRemovesCL
TestRFC9209_ProxyStatusOnUpstreamTimeout
TestRFC7239_ForwardedHeaderObfuscation
```

### Iterative Test Infrastructure

The test harness itself can be built incrementally:

- **Phase 1**: Basic request echo + header capture (sufficient for Groups B, C)
- **Phase 2**: Error simulation (sufficient for Groups E, K)
- **Phase 3**: Configurable response generation (sufficient for Groups D, F)
- **Phase 4**: Protocol version handling (sufficient for Groups G, I)

---

## 6. Version Differences Summary

| Requirement | HTTP/1.0 | HTTP/1.1 | HTTP/2 | HTTP/3 |
| --- | --- | --- | --- | --- |
| Via header | MUST | MUST | MUST | MUST |
| Connection header removal | MUST | MUST | N/A (no Connection in H2/H3) | N/A |
| Proxy-Connection removal | SHOULD | SHOULD | MUST (malformed if present) | MUST |
| Transfer-Encoding handling | N/A (no chunked) | MUST | N/A (frames handle framing) | N/A |
| CONNECT method | Supported | Supported | Extended CONNECT (§8.5) | Extended CONNECT |
| Forwarded header | MAY | MAY | MAY | MAY |
| Proxy-Status | MAY | MAY | MAY | MAY |
| Expect: 100-continue | Ignore | MUST forward | N/A (H2 flow control) | N/A |
| Max-Forwards | MUST | MUST | MUST | MUST |
| Upgrade header | Strip | Strip unless supported | N/A (no Upgrade in H2) | N/A |

---

## References

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html)
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 9209 — Proxy-Status Header](https://www.rfc-editor.org/rfc/rfc9209.html)
- [RFC 9111 — HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111.html)
- [RFC 7239 — Forwarded HTTP Extension](https://www.rfc-editor.org/rfc/rfc7239.html)
- [RFC 4559 — SPNEGO-based HTTP Authentication](https://www.rfc-editor.org/rfc/rfc4559.html)
- [RFC 8470 — Using Early Data in HTTP](https://www.rfc-editor.org/rfc/rfc8470.html)
- [Mark Nottingham — "What Proxies Must Do"](https://www.mnot.net/blog/2011/07/11/what_proxies_must_do)
