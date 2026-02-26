<!-- markdownlint-disable MD036 -->
# Proposed GitHub Issues for HTTP Proxy Standards Compliance

## Recommendation: One Issue per Phase

**Per phase** (not per requirement) is the right granularity because:

1. **Requirements within a phase share implementation surface area.** For example,
   Phase 2 items (B1, B2, K3, J2, E1, E2) all modify the same header-processing
   code path in `handleClient()`. Splitting them would create merge conflicts and
   duplicated test infrastructure.

2. **Each phase is a coherent, reviewable unit.** A PR that implements "all
   hop-by-hop header hygiene" is easier to review than six PRs that each touch
   overlapping lines in `main.go`.

3. **Per-requirement issues would create 41 issues**, most of which are 10–30 line
   changes. The overhead of issue triage, branch management, and PR review would
   dwarf the implementation effort.

**Exception**: Phase 3 is split into two issues because Via header injection (A1,
A2) and error response codes (L1, L2, D3, J1) are architecturally independent —
they touch different code paths and can be reviewed separately.

## Dependency Graph

```text
Issue 1: Test Infrastructure Foundation
├──→ Issue 2: Hop-by-Hop Header Hygiene (B1, B2, K3, J2, E1, E2)
├──→ Issue 3: Via Header and Loop Detection (A1, A2)
│    └──→ Issue 8: Proxy-Status Error Reporting (A3) [uses Via identifier]
├──→ Issue 4: Error Response Codes (L1, L2, D3, J1)
├──→ Issue 5: Request Forwarding Fidelity (C1–C7, B3, E3)
├──→ Issue 6: CONNECT Tunnel Hardening (D2, D4, D5, D6, D7)
├──→ Issue 7: Protocol Edge Cases (F1, F2, G1, I1, I2, N2)
└──→ Issue 9: Client Identity Forwarding (H1–H4)
```

**What can be parallelized**: After Issue 1 merges, Issues 2–7 and 9 can all be
worked on **in parallel** by different contributors. They touch different aspects
of the proxy pipeline:

- Issue 2 modifies request header processing (before `WriteProxy`)
- Issue 3 adds Via header injection (before `WriteProxy`)
- Issue 4 modifies error response generation (`writeHTTPError`)
- Issue 5 modifies request URI and header forwarding logic
- Issue 6 modifies CONNECT-specific tunnel establishment
- Issue 7 adds protocol version and Expect/Max-Forwards handling
- Issue 9 adds new forwarding headers (before `WriteProxy`)

**Sequential dependencies**:

- Issue 8 (Proxy-Status) depends on Issues 3 and 4 because it uses the Via
  identifier and error response infrastructure.
- All issues depend on Issue 1 (test harness).

## Proposed Issues

---

### Issue 1: Build white-box integration test harness for HTTP standards compliance

**Labels**: `testing`, `infrastructure`

**Context**

spnego-proxy needs a reusable test harness to verify compliance with HTTP proxy
standards (RFC 9110, RFC 9112, RFC 9209, and others). The existing tests in
`main_test.go` use ad-hoc mock upstreams that echo minimal responses, but the
upcoming standards compliance work requires a **programmable mock upstream** that
can:

- Record all received request headers, method, URI, and body
- Return configurable responses (status, headers, body, delays, errors)
- Simulate failure modes (close connection, send malformed responses, delay
  indefinitely)
- Support both regular HTTP and CONNECT tunnel handshakes

The current test helpers (`stubTokenProvider` in `testutil_test.go`,
`closeWriteConn` in `main_test.go`) will continue to be used. This issue adds a
complementary `MockUpstreamProxy` and a `ProxyUnderTest` helper that reduce
boilerplate across all subsequent compliance tests.

**Requirements reference**

See [docs/http-proxy-standards-requirements.md, §5 "Testing Strategy Overview"](docs/http-proxy-standards-requirements.md)
for the full test harness design.

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached: a
> reusable test harness that subsequent standards compliance issues can build on.

Create a new file `compliance_test.go` (or `test_harness_test.go`) with:

1. **`MockUpstreamProxy`** — a `net.Listener`-based test server that:
   - Accepts connections and reads HTTP requests using `http.ReadRequest`
   - Stores received requests in a thread-safe slice for later assertion
   - Responds according to a configurable `ResponseFunc func(*http.Request) *http.Response`
   - Has a `Close()` that shuts down the listener
   - Can be configured to simulate errors (e.g., close connection before
     responding, send malformed data, delay response)

2. **`ProxyUnderTest`** — a helper that:
   - Starts `handleClient` goroutines against a `net.Listener` on a dynamic port
   - Uses `stubTokenProvider` with a fixed token
   - Exposes `Addr()` for the test client to connect to
   - Has a `Close()` that stops accepting and drains connections

3. **Assertion helpers**:
   - `assertHeaderPresent(t, req, key, expectedValue)`
   - `assertHeaderAbsent(t, req, key)`
   - `assertStatusCode(t, resp, expectedCode)`

4. **One smoke test** that proves the harness works: send a GET request through
   the proxy to the mock upstream, assert it arrives with the injected
   `Proxy-Authorization` header, and assert the client receives the mock
   response.

**Key code locations**

- `main.go:82-145` — `handleClient()`, the function under test
- `main_test.go:253-347` — `TestShutdownDrainsInFlightConnections`, an example
  of the current test pattern with ad-hoc mock upstream
- `testutil_test.go:1-33` — `stubTokenProvider`, which this harness will reuse

**Acceptance criteria**

- [ ] A `MockUpstreamProxy` type exists that records requests and returns
      configurable responses
- [ ] A `ProxyUnderTest` helper exists that starts the proxy on a dynamic port
- [ ] At least one smoke test demonstrates the harness end-to-end
- [ ] The harness is in a `_test.go` file (not shipped in the binary)
- [ ] Existing tests continue to pass (`go test ./...`)

---

### Issue 2: Implement hop-by-hop header hygiene (Connection, Proxy-Authorization, Proxy-Connection, Upgrade, TE/CL)

**Labels**: `security`, `standards-compliance`, `proxy-behavior`

**Context**

spnego-proxy currently forwards all headers transparently via `req.WriteProxy()`
(`main.go:116`), only adding `Proxy-Authorization: Negotiate <token>`
(`main.go:115`). It does not strip hop-by-hop headers, which is a
**security-critical** gap — failure to remove these headers enables request
smuggling, credential leakage, and protocol confusion attacks.

This issue implements the most fundamental proxy obligations from RFC 9110 and
RFC 9112.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| B1 | Remove Connection header and all headers it names | MUST | RFC 9110 §7.6.1 |
| B2 | Consume client's Proxy-Authorization; don't forward it | MUST NOT | RFC 9110 §11.7.1 |
| K3 | Strip Proxy-Connection (non-standard hop-by-hop) | SHOULD | RFC 9113 §8.2.2 |
| J2 | Strip Upgrade unless proxy supports the protocol | MUST NOT | RFC 9110 §7.8 |
| E1 | When both TE and CL present, remove CL before forwarding | MUST | RFC 9112 §6.1 |
| E2 | Invalid Content-Length in upstream response → 502 | MUST | RFC 9112 §6.1 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

The core change is in `handleClient()` (`main.go:82-145`). After
`http.ReadRequest` (line 97) and before `req.WriteProxy` (line 116), add a
header sanitization step:

```go
// Remove hop-by-hop headers before forwarding.
// 1. Parse Connection header for additional field names to remove.
connectionHeaders := parseConnectionHeader(req.Header)
for _, h := range connectionHeaders {
    req.Header.Del(h)
}
req.Header.Del("Connection")

// 2. Remove well-known hop-by-hop headers.
req.Header.Del("Keep-Alive")
req.Header.Del("Proxy-Connection")
req.Header.Del("TE")
req.Header.Del("Trailer")
req.Header.Del("Upgrade")

// 3. Remove client's Proxy-Authorization (we inject our own).
// Note: req.Header.Set("Proxy-Authorization", ...) on line 115
// already overwrites it, but Del first is more explicit.

// 4. Handle TE/CL conflict (request smuggling prevention).
if req.Header.Get("Transfer-Encoding") != "" && req.Header.Get("Content-Length") != "" {
    req.Header.Del("Content-Length")
}
```

For E2 (invalid Content-Length in responses), the response path is currently raw
`io.Copy` (`main.go:137-143`). Detecting invalid Content-Length in the response
stream would require parsing the response headers. This may be deferred or
handled by reading the response via `http.ReadResponse` before forwarding — this
is an architectural decision for the implementer.

**Key code locations**

- `main.go:82-145` — `handleClient()`, where header processing must be added
- `main.go:97` — `http.ReadRequest(reqReader)`, where the request is parsed
- `main.go:115` — `req.Header.Set("Proxy-Authorization", ...)`, current header
  modification
- `main.go:116` — `req.WriteProxy(proxyConn)`, where the request is forwarded

**Testing strategy**

Using the test harness from Issue 1:

- Send a request with `Connection: X-Custom-Hop\r\nX-Custom-Hop: secret`. Assert
  upstream receives neither `Connection` nor `X-Custom-Hop` nor `Keep-Alive`.
- Send a request with the client's own `Proxy-Authorization: Basic abc`. Assert
  upstream receives `Proxy-Authorization: Negotiate <token>` (injected), not the
  client's Basic header.
- Send `Proxy-Connection: keep-alive`. Assert upstream does not receive it.
- Send `Upgrade: websocket`. Assert upstream does not receive it.
- Send both `Transfer-Encoding: chunked` and `Content-Length: 100`. Assert
  upstream receives `Transfer-Encoding` but not `Content-Length`.

**Acceptance criteria**

- [ ] Connection header and all headers it names are removed before forwarding
- [ ] Client's Proxy-Authorization is not forwarded (proxy's own is injected)
- [ ] Proxy-Connection, Keep-Alive, TE, Trailer, Upgrade are stripped
- [ ] TE + CL conflict resolved by removing CL
- [ ] All new behavior has test coverage with RFC traceability in test names
- [ ] Existing tests continue to pass

---

### Issue 3: Add Via header injection and loop detection

**Labels**: `standards-compliance`, `proxy-behavior`

**Context**

RFC 9110 §7.6.3 requires every intermediary to append a `Via` header field to
each message it forwards. spnego-proxy does not currently add a Via header. This
header serves two purposes: traceability (knowing which proxies handled a
request) and loop detection (a proxy can detect its own identifier in an incoming
Via header).

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| A1 | Append Via entry on every forwarded message | MUST | RFC 9110 §7.6.3 |
| A2 | Detect own identifier in Via header (loop detection) | SHOULD | RFC 9110 §7.6.3 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

1. **Choose a Via identifier**: Use a configurable pseudonym (e.g., `spnego-proxy`)
   rather than the hostname, for privacy per RFC 9110 §7.6.3. Could be derived
   from a new CLI flag or hardcoded.

2. **Append Via header** in `handleClient()` after `http.ReadRequest` (line 97)
   and before `req.WriteProxy` (line 116):

   ```go
   // Via: 1.1 spnego-proxy
   req.Header.Add("Via", fmt.Sprintf("%d.%d %s", req.ProtoMajor, req.ProtoMinor, viaIdentifier))
   ```

   Use `Add` (not `Set`) to preserve any existing Via entries from upstream
   proxies.

3. **Loop detection**: Before appending, check if the Via header already contains
   the proxy's identifier. If so, return 502 (Bad Gateway) to break the loop:

   ```go
   for _, v := range req.Header.Values("Via") {
       if strings.Contains(v, viaIdentifier) {
           writeHTTPError(conn, http.StatusBadGateway, "proxy loop detected\n")
           return
       }
   }
   ```

**Key code locations**

- `main.go:82-145` — `handleClient()`, where Via must be injected
- `main.go:70-80` — `writeHTTPError()`, used for loop detection error response
- `main.go:148-164` — Flag definitions, where a Via identifier flag could be
  added

**Testing strategy**

Using the test harness from Issue 1:

- Send a request with no Via header. Assert upstream receives `Via: 1.1 spnego-proxy`
  (or configured identifier).
- Send a request with existing `Via: 1.1 other-proxy`. Assert upstream receives
  both the existing entry and the new one.
- Send a request with `Via: 1.1 spnego-proxy` (matching the proxy's identifier).
  Assert the proxy returns 502 and does not forward the request.

**Acceptance criteria**

- [ ] Every forwarded request includes a Via header with protocol version and
      proxy identifier
- [ ] Existing Via entries are preserved (appended, not replaced)
- [ ] Loop detection returns 502 when the proxy's own identifier is found
- [ ] Test coverage with RFC traceability in test names
- [ ] Existing tests continue to pass

---

### Issue 4: Use correct HTTP status codes for error responses (502 vs 504, version advertisement)

**Labels**: `standards-compliance`, `proxy-behavior`

**Context**

spnego-proxy already returns 502 for some errors, but doesn't distinguish between
upstream failures (502) and timeouts (504). Additionally, RFC 9112 §6.1 requires
that CONNECT 2xx responses must not contain `Transfer-Encoding`, and RFC 9112
§2.1 requires proxies to advertise HTTP/1.1 in their own responses.

The `writeHTTPError` function (`main.go:70-80`) already generates HTTP/1.1
responses, so J1 may already be satisfied. This issue ensures all error paths use
the correct status codes.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| L1 | 502 Bad Gateway for upstream connection/response failures | MUST | RFC 9112 §6.1 |
| L2 | 504 Gateway Timeout for upstream timeouts | SHOULD | RFC 9110 §15.6.5 |
| D3 | No Transfer-Encoding in CONNECT 2xx response | MUST NOT | RFC 9112 §6.1 |
| J1 | Advertise HTTP/1.1 in proxy-generated responses | MUST | RFC 9112 §2.1 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

1. **Distinguish timeout from failure** in `handleClient()` at line 88-92:

   ```go
   proxyConn, err := net.DialTimeout("tcp", proxy, dialTimeout)
   if err != nil {
       if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
           writeHTTPError(conn, http.StatusGatewayTimeout, "upstream proxy connection timed out\n")
       } else {
           writeHTTPError(conn, http.StatusBadGateway, "failed to connect to upstream proxy\n")
       }
       return
   }
   ```

2. **Verify D3**: Since spnego-proxy does not generate its own CONNECT 2xx
   responses (it forwards the upstream's response via `io.Copy`), this may
   already be satisfied. But verify that the upstream's response is not modified
   to add Transfer-Encoding. If the proxy ever generates its own 200 for CONNECT,
   ensure no TE header.

3. **Verify J1**: `writeHTTPError` (`main.go:70-80`) already sets `ProtoMajor: 1,
   ProtoMinor: 1`. Confirm via test.

**Key code locations**

- `main.go:70-80` — `writeHTTPError()`, the error response generator
- `main.go:88-92` — Dial failure path (currently always returns 502)
- `main.go:99-104` — Read failure path (returns 400)
- `main.go:107-110` — Token failure path (returns 502)
- `main.go:116-119` — Write failure path (returns 502)

**Testing strategy**

Using the test harness from Issue 1:

- Configure a dial timeout of 50ms with an unreachable upstream (192.0.2.1:1).
  Assert the proxy returns **504** (not 502).
- Configure a reachable upstream that immediately closes the connection. Assert
  the proxy returns **502**.
- Send a CONNECT request. Inspect the 200 response. Assert no
  `Transfer-Encoding` header.
- Trigger any proxy-generated error. Assert the response uses `HTTP/1.1` in the
  status line.

**Acceptance criteria**

- [ ] Upstream connection timeout returns 504
- [ ] Upstream connection refusal/failure returns 502
- [ ] CONNECT 2xx responses do not contain Transfer-Encoding
- [ ] All proxy-generated responses advertise HTTP/1.1
- [ ] Existing `TestHandleClientDialTimeout` updated (now expects 504 for
      timeout, or a new test added for the distinction)
- [ ] Existing tests continue to pass

---

### Issue 5: Ensure request forwarding fidelity (Host regeneration, header preservation, obs-fold, no-transform, Authorization pass-through)

**Labels**: `standards-compliance`, `proxy-behavior`

**Context**

RFC 9112 and RFC 9110 impose several requirements on how a proxy forwards
requests and responses. spnego-proxy currently uses Go's `http.ReadRequest` +
`req.WriteProxy`, which handles some of these automatically (e.g., Host header
from request-target). This issue verifies existing behavior and fills any gaps.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| C1 | Preserve header field order for same-name headers | MUST NOT reorder | RFC 9110 §5.3 |
| C2 | Forward unrecognized headers | MUST | RFC 9110 §5.1 |
| C3 | Regenerate Host from request-target URI | MUST | RFC 9112 §3.2.2 |
| C4 | Do not modify path and query of request-target | MUST NOT | RFC 9112 §3.2.2 |
| C5 | Pass through Authorization header unmodified | MUST NOT modify | RFC 9110 §11.7.2 |
| C6 | Remove whitespace between header name and colon in responses | MUST | RFC 9112 §5.2 |
| C7 | Do not transform content when no-transform is present | MUST NOT | RFC 9110 §7.7 |
| B3 | Do not forward upstream's Proxy-Authenticate to client | MUST NOT | RFC 9110 §11.7.2 |
| E3 | Handle obs-fold in response headers | MUST | RFC 9112 §5.2 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

Many of these may already be satisfied by Go's `http.ReadRequest` +
`req.WriteProxy` pipeline. The primary task is to **verify via tests** and fill
gaps:

1. **C1, C2, C4, C5, C7**: Likely already work correctly because `WriteProxy`
   forwards headers and URI as-is. Write tests to verify.

2. **C3 (Host regeneration)**: Go's `http.ReadRequest` populates `req.Host` from
   the request-target when the client uses absolute-form. `WriteProxy` uses
   `req.Host` for the Host header. Verify with a test where the client sends a
   mismatched Host header.

3. **C6 (whitespace before colon in responses)**: This affects the response path.
   Since responses are currently forwarded via raw `io.Copy` (`main.go:143`), the
   proxy does not parse or normalize response headers. Implementing this would
   require parsing the response. This could be a known gap documented as a
   follow-up, or the response path could be changed to use `http.ReadResponse` +
   `resp.Write`.

4. **B3 (Proxy-Authenticate)**: spnego-proxy handles 407 responses internally in
   its auth flow. Currently responses are forwarded via `io.Copy`, so if the
   upstream sends a 407, it would be forwarded to the client. Verify whether this
   is already handled. If not, consider whether the response needs to be
   inspected.

5. **E3 (obs-fold)**: Go's `http.ReadResponse` handles obs-fold by normalizing it
   (replacing with spaces). If the response path is changed to use
   `http.ReadResponse`, this comes for free. Otherwise document as a known gap.

**Key code locations**

- `main.go:95-98` — Request reading via `http.ReadRequest` / `bufio.NewReader`
- `main.go:116` — `req.WriteProxy(proxyConn)`, where the request is forwarded
- `main.go:142-143` — Bidirectional `io.Copy` for response forwarding
- `main.go:70-80` — `writeHTTPError`, where proxy-generated responses originate

**Testing strategy**

Using the test harness from Issue 1:

- **C1**: Send multiple `X-Custom: a` and `X-Custom: b` headers in order. Assert
  upstream receives them in the same order.
- **C2**: Send `X-Exotic-Widget: foo`. Assert upstream receives it unchanged.
- **C3**: Send `GET http://example.com/path HTTP/1.1` with `Host: other.com`.
  Assert upstream receives `Host: example.com`.
- **C4**: Send `GET http://example.com/path?q=1&r=2%20 HTTP/1.1`. Assert upstream
  receives the path and query unmodified.
- **C5**: Send `Authorization: Bearer token123`. Assert upstream receives it
  unchanged.
- **C7**: This is inherently satisfied if the proxy does not modify response
  bodies. Write a test that sends a response with `Cache-Control: no-transform`
  and verifies byte-for-byte body integrity.
- **B3**: Mock upstream returns 407 with `Proxy-Authenticate: Negotiate`. Assert
  the client does not receive the 407 (spnego-proxy should handle it internally).

**Acceptance criteria**

- [ ] Tests verify header order preservation for same-name headers
- [ ] Tests verify unrecognized headers are forwarded
- [ ] Tests verify Host header is regenerated from request-target
- [ ] Tests verify path and query are not modified
- [ ] Tests verify Authorization header passes through unmodified
- [ ] No-transform content integrity verified via test
- [ ] Known gaps (C6, E3, B3) are either fixed or documented as follow-up issues
      with clear rationale
- [ ] Existing tests continue to pass

---

### Issue 6: Harden CONNECT tunnel handling (connection close on rejection, payload gating, port restriction)

**Labels**: `security`, `standards-compliance`, `proxy-behavior`

**Context**

spnego-proxy supports CONNECT tunneling (`main.go:82-145`) via bidirectional
`io.Copy`. Several CONNECT-specific security requirements from RFC 9110 §9.3.6
and RFC 9112 §11.2 are not yet explicitly implemented or tested.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| D5 | Close connection when rejecting a CONNECT request | MUST | RFC 9112 §11.2 |
| D6 | Wait for upstream 2xx before forwarding client payload | MUST | RFC 9112 §11.2 |
| D7 | Do not send 2xx to client without established upstream connection | MUST NOT | RFC 9110 §9.3.6 |
| D2 | Drain buffered data on tunnel close | MUST | RFC 9110 §9.3.6 |
| D4 | Restrict CONNECT to safe ports | SHOULD | RFC 9110 §9.3.6 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

1. **D5 (Close on rejection)**: Currently, `handleClient` already closes the
   connection via `defer conn.Close()` at line 83. But the RFC specifically says
   no further requests should be processed on the connection. Since the proxy
   handles one request per connection (no persistent connection support yet), this
   may already be satisfied. Verify with a test.

2. **D6 (Wait for 2xx before forwarding)**: The current flow is:
   - Read client request (line 97)
   - Forward to upstream via `WriteProxy` (line 116)
   - Start bidirectional `io.Copy` (lines 142-143)

   The problem: `io.Copy` from `reqReader` to `proxyConn` (line 142) starts
   immediately, potentially forwarding client payload before the upstream has
   responded with 2xx. For CONNECT requests, the client may send TLS ClientHello
   immediately after the CONNECT request. The fix: for CONNECT requests, read the
   upstream's response first, verify it's 2xx, forward it to the client, then
   start bidirectional `io.Copy`.

3. **D7 (No premature 2xx)**: This is the server-side of D6. Since spnego-proxy
   forwards the upstream's response (not generating its own), this is satisfied
   as long as D6 is implemented correctly.

4. **D2 (Drain on close)**: Already partially implemented via `CloseWrite()`
   (lines 128-131). Verify that buffered data is flushed before close.

5. **D4 (Port restriction)**: Add a configurable allowlist of CONNECT ports.
   Default: `443`. Reject CONNECT to other ports with 403 Forbidden. This could
   be a new CLI flag like `-connect-ports 443,8443`.

**Key code locations**

- `main.go:82-145` — `handleClient()`, the entire request pipeline
- `main.go:97` — `http.ReadRequest`, where CONNECT is parsed
- `main.go:116` — `req.WriteProxy`, where CONNECT is forwarded to upstream
- `main.go:125-143` — Bidirectional forwarding (needs CONNECT-specific gating)
- `main.go:128-131` — `CloseWrite()` half-close support
- `main_test.go:583-685` — `TestHandleClientForwardsBufferedData`, existing
  CONNECT test

**Testing strategy**

Using the test harness from Issue 1:

- **D5**: Send a CONNECT to a forbidden port. Assert the proxy returns an error
  and closes the connection. Attempt to send another request on the same
  connection; assert it fails (connection closed).
- **D6**: Client sends `CONNECT example.com:443` followed immediately by
  `ClientHello` bytes. Mock upstream delays its 200 response by 100ms. Assert the
  upstream does not receive the ClientHello bytes until after it has sent 200.
- **D7**: Mock upstream that refuses the CONNECT (returns 403). Assert the client
  receives 403 (or 502) — not 200.
- **D2**: Already covered by `TestHandleClientForwardsBufferedData`. Add a test
  for the reverse direction: upstream closes with pending data, assert client
  receives all bytes.
- **D4**: Send `CONNECT example.com:443` → success. Send
  `CONNECT mail.example.com:25` → 403 Forbidden.

**Acceptance criteria**

- [ ] Connection is closed after rejecting a CONNECT request (no further request
      processing)
- [ ] Client payload is not forwarded until upstream returns 2xx for CONNECT
- [ ] CONNECT to non-allowed ports is rejected with an appropriate error
- [ ] Buffered data is drained in both directions on tunnel close
- [ ] Tests cover all scenarios with RFC traceability
- [ ] Existing tests continue to pass

---

### Issue 7: Handle protocol edge cases (Expect, Max-Forwards, HTTP/1.0 connections, Connection: close, Early-Data)

**Labels**: `standards-compliance`, `proxy-behavior`

**Context**

Several RFC requirements cover protocol-level edge cases that spnego-proxy does
not currently handle. These are lower priority than header hygiene and CONNECT
hardening, but they are MUST-level requirements that affect correctness.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| F1 | Forward Expect: 100-continue to upstream | MUST | RFC 9110 §10.1.1 |
| F2 | Do not forward 100 Continue to HTTP/1.0 clients | MUST NOT | RFC 9110 §10.1.1 |
| G1 | Decrement Max-Forwards for TRACE/OPTIONS; stop at zero | MUST | RFC 9110 §7.6.2 |
| I1 | Do not maintain persistent connection with HTTP/1.0 client | MUST NOT | RFC 9112 §9.3 |
| I2 | Honor Connection: close from client | MUST | RFC 9112 §9.6 |
| N2 | Do not remove Early-Data header | MUST NOT | RFC 8470 §5.1 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

1. **F1 (Expect: 100-continue)**: Go's `http.ReadRequest` strips the Expect
   header by default for body handling. Verify whether `WriteProxy` re-includes
   it. If not, preserve it manually before forwarding. This may require saving the
   Expect value before ReadRequest processes it.

2. **F2 (100 to HTTP/1.0)**: Since responses are forwarded via raw `io.Copy`,
   interim 100 responses are passed through blindly. Implementing this properly
   would require parsing the response stream. Document as a known gap if the
   response path isn't refactored to use `http.ReadResponse`.

3. **G1 (Max-Forwards)**: Before forwarding TRACE or OPTIONS requests, check for
   a `Max-Forwards` header. If present and the value is 0, generate a 200 response
   locally. If > 0, decrement by 1 and forward.

4. **I1, I2 (Connection management)**: Currently spnego-proxy handles one request
   per connection and always closes afterward (`defer conn.Close()` at line 83).
   This means I1 and I2 are already effectively satisfied. Verify with tests.

5. **N2 (Early-Data)**: Since the proxy forwards all unrecognized headers (C2),
   Early-Data should already pass through. Verify with a test.

**Key code locations**

- `main.go:82-145` — `handleClient()`, where all request processing occurs
- `main.go:95-98` — Request reading, where Expect header may be consumed
- `main.go:83` — `defer conn.Close()`, which already ensures connection closure
- `main.go:112-113` — Debug logging of request method, where TRACE/OPTIONS could
  be detected

**Testing strategy**

Using the test harness from Issue 1:

- **F1**: Client sends `Expect: 100-continue`. Assert upstream receives the
  `Expect` header.
- **G1**: Send `OPTIONS * HTTP/1.1` with `Max-Forwards: 0`. Assert proxy returns
  200 without forwarding.
- **G1**: Send `OPTIONS http://example.com/ HTTP/1.1` with `Max-Forwards: 2`.
  Assert upstream receives `Max-Forwards: 1`.
- **I1**: Send an HTTP/1.0 request. Assert the connection closes after the
  response.
- **I2**: Send a request with `Connection: close`. Assert the connection closes
  after the response.
- **N2**: Send `Early-Data: 1`. Assert upstream receives it unchanged.

**Acceptance criteria**

- [ ] Expect: 100-continue is forwarded to upstream (or gap documented)
- [ ] Max-Forwards is decremented for TRACE/OPTIONS; 0 triggers local response
- [ ] HTTP/1.0 connections are closed after response
- [ ] Connection: close is honored
- [ ] Early-Data header passes through unchanged
- [ ] Known gaps (F2 if response parsing not implemented) documented as follow-up
- [ ] Tests cover all scenarios with RFC traceability
- [ ] Existing tests continue to pass

---

### Issue 8: Add Proxy-Status error reporting header (RFC 9209)

**Labels**: `standards-compliance`, `observability`

**Depends on**: Issue 3 (Via header — uses the same proxy identifier), Issue 4
(error response codes — Proxy-Status augments error responses)

**Context**

RFC 9209 defines the `Proxy-Status` response header, which allows intermediaries
to communicate structured error information to clients. This is a MAY-level
feature, but it significantly improves debuggability for users who encounter
proxy errors.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| A3 | Include Proxy-Status in error responses | MAY | RFC 9209 §2 |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

Modify `writeHTTPError` (`main.go:70-80`) to accept an optional error type
parameter and include a `Proxy-Status` header:

```go
// Example Proxy-Status values:
// Proxy-Status: spnego-proxy; error=connection_timeout
// Proxy-Status: spnego-proxy; error=connection_refused
// Proxy-Status: spnego-proxy; error=proxy_internal_error; details="SPNEGO token acquisition failed"
```

The proxy identifier should match the Via header identifier (from Issue 3).

Error type mapping (from RFC 9209 §2.3):

| Proxy condition | RFC 9209 error type | HTTP status |
| --- | --- | --- |
| Upstream dial timeout | `connection_timeout` | 504 |
| Upstream connection refused | `connection_refused` | 502 |
| Upstream connection closed | `connection_terminated` | 502 |
| SPNEGO token failure | `proxy_internal_error` | 502 |
| Request read failure | `http_request_error` | 400 |
| Loop detected | `proxy_loop_detected` | 502 |

**Key code locations**

- `main.go:70-80` — `writeHTTPError()`, where Proxy-Status should be added
- `main.go:88-92` — Dial failure (connection_timeout or connection_refused)
- `main.go:107-110` — Token failure (proxy_internal_error)
- `main.go:99-104` — Read failure (http_request_error)

**Testing strategy**

Using the test harness from Issue 1:

- Trigger each error condition. Assert the response includes a `Proxy-Status`
  header with the correct error type.
- Verify the Proxy-Status value parses as valid Structured Fields (RFC 8941).
- Verify the proxy identifier matches the Via header identifier.

**Acceptance criteria**

- [ ] Error responses include `Proxy-Status` header with appropriate error type
- [ ] Proxy identifier in Proxy-Status matches Via identifier
- [ ] Error types follow RFC 9209 §2.3 taxonomy
- [ ] Tests verify Proxy-Status for each error scenario
- [ ] Existing tests updated to accept the new header (or ignore it)

---

### Issue 9: Add client identity forwarding headers (Forwarded, X-Forwarded-*)

**Labels**: `standards-compliance`, `feature`

**Context**

RFC 7239 defines the `Forwarded` header for standardized client identity
forwarding. The `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host`
headers are widely-used de facto equivalents. These are all MAY-level features
but are valuable for upstream servers that need to know the original client
identity.

**Requirements** (from [docs/http-proxy-standards-requirements.md](docs/http-proxy-standards-requirements.md))

| ID | Requirement | Level | RFC |
| --- | --- | --- | --- |
| H1 | Forwarded header (RFC 7239) | MAY | RFC 7239 §4 |
| H2 | X-Forwarded-For | MAY | De facto |
| H3 | X-Forwarded-Proto | MAY | De facto |
| H4 | X-Forwarded-Host | MAY | De facto |

**Suggested implementation approach**

> **Note**: The implementation and testing details below are suggestions. The
> assignee is free to vary the approach as long as the same goal is reached.

These headers should be **opt-in** via CLI flags since they expose client IP
addresses and may not be desired in all environments.

Suggested new flags:

- `-forwarded` (bool): Enable RFC 7239 `Forwarded` header
- `-x-forwarded-for` (bool): Enable `X-Forwarded-For` header

When enabled, add headers in `handleClient()` before `WriteProxy`:

```go
if forwardedEnabled {
    clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
    // RFC 7239 §6.3: SHOULD obfuscate by default
    fwd := fmt.Sprintf("for=%s;proto=http", quoteIfNeeded(clientIP))
    req.Header.Add("Forwarded", fwd)
}

if xForwardedForEnabled {
    clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
    existing := req.Header.Get("X-Forwarded-For")
    if existing != "" {
        req.Header.Set("X-Forwarded-For", existing+", "+clientIP)
    } else {
        req.Header.Set("X-Forwarded-For", clientIP)
    }
}
```

Privacy considerations (RFC 7239 §6.3):

- By default, the `for` parameter SHOULD use an obfuscated identifier (random
  `_` prefixed token) rather than the raw IP address
- A flag like `-forwarded-obfuscate=true` (default) could control this
- IPv6 addresses and `node:port` values MUST be quoted per RFC 7239 §4

**Key code locations**

- `main.go:82-145` — `handleClient()`, where headers are injected
- `main.go:148-164` — Flag definitions, where new flags would be added
- `main.go:216-218` — `handleClient` call site, where new flags would be passed

**Testing strategy**

Using the test harness from Issue 1:

- Enable Forwarded header. Assert upstream receives
  `Forwarded: for=_<obfuscated>;proto=http`.
- Enable X-Forwarded-For. Assert upstream receives
  `X-Forwarded-For: <client-ip>`.
- Send a request with existing `X-Forwarded-For: 1.2.3.4`. Assert upstream
  receives `X-Forwarded-For: 1.2.3.4, <client-ip>` (appended).
- Connect from an IPv6 address with Forwarded enabled. Assert the `for` parameter
  is properly quoted.
- Disable both flags (default). Assert neither header is added.

**Acceptance criteria**

- [ ] Forwarded header added when `-forwarded` flag is set
- [ ] X-Forwarded-For added when `-x-forwarded-for` flag is set
- [ ] Both are disabled by default
- [ ] Forwarded header uses obfuscated identifiers by default
- [ ] IPv6 addresses are properly quoted in Forwarded header
- [ ] Chaining works (existing values preserved and appended)
- [ ] Tests cover all scenarios
- [ ] Existing tests continue to pass
