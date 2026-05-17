# CONTEXT — spnego-proxy domain glossary

The vocabulary engineering work should use when naming concepts in this
repo (issue titles, refactor proposals, hypotheses, test names). One
context (the proxy core in `internal/proxy`). Keep terms here in sync as
decisions crystallise; record decisions as ADRs under `docs/adr/`.

## Glossary

- **Client Session** — the per-connection unit of work: one accepted
  client TCP connection plus the state that lives for its duration
  (config snapshot, the buffered request reader, the lazily-dialled
  upstream connection and its reader). Represented by the `ClientSession`
  type (`internal/proxy/session.go`); see [ADR-0001](docs/adr/0001-introduce-client-session-handling-layer.md).

- **Keep-Alive Loop** — the loop in `ClientSession.run` that reads,
  validates, and relays successive HTTP requests over one persistent
  client connection until either side signals close (see *Connection
  Close Signal*) or an error occurs.

- **Forward** — relaying an HTTP request and its response with
  request/response framing preserved (as opposed to *Tunnel*). The
  via-upstream HTTP relay lives in `ClientSession.run`; the noproxy
  variant is `ClientSession.forwardDirect`.

- **Tunnel** — opaque bidirectional byte relay established after a
  CONNECT, with no HTTP framing. Methods: `ClientSession.tunnelViaUpstream`
  (through the upstream proxy) and `ClientSession.tunnelDirect` (noproxy);
  the byte-pump primitive is `handleConnectTunnel` / `forwardHalf`.

- **Via-Upstream** — traffic routed through the SPNEGO/Kerberos-
  authenticated upstream proxy, carrying `Proxy-Authorization: Negotiate
  <token>`.

- **Direct (noproxy bypass)** — traffic for a host matching the `NoProxy`
  matcher that the proxy dials itself, bypassing the upstream proxy and
  SPNEGO entirely.

- **Validation Pipeline** — the per-request pre-forward checks run on
  every keep-alive iteration: Via loop detection, CONNECT port allowlist,
  Max-Forwards decrement, and hop-by-hop sanitisation
  (`ClientSession.validateRequest`).

- **Hop-by-Hop Sanitisation** — stripping connection-scoped headers
  (notably a smuggled `Proxy-Authorization`) on every iteration so a
  later request cannot ride a prior authenticated upstream connection.

- **Lazy Upstream Dial / Connection Reuse** — the upstream proxy
  connection is dialled on the first via-upstream plain-HTTP request and
  reused for subsequent ones (RFC 4559 §5); a CONNECT always dials a
  fresh connection because a tunnel co-opts the socket for opaque bytes.

- **Connection Close Signal** — the condition, computed by
  `connectionWillClose`, under which the keep-alive loop must stop:
  HTTP/1.0 client (RFC 9112 §9.3), or `Connection: close` on either side.

- **Frozen Seam** — `handleClient(conn, cfg)`: the stable entry point
  called by `Serve` and the test harness. Its signature is deliberately
  held constant so internal refactors do not ripple into callers or
  tests; see [ADR-0001](docs/adr/0001-introduce-client-session-handling-layer.md).

- **CLI Contract Surface** — the SemVer-relevant public API: CLI flags
  (names, types, defaults), exit codes, stdout/stderr behaviour, HTTP
  response headers and error format, and CONNECT tunnelling behaviour.
  Internal restructuring that leaves this surface untouched is not a
  breaking change.
