# ADR 0001 — Introduce a per-connection handling layer (`ClientSession`)

- Status: Accepted
- Date: 2026-05-17
- Issue: [#236](https://github.com/andrewesweet/spnego-proxy/issues/236)

## Context

`internal/proxy` had no request-handling layer object. Per-connection
orchestration was a set of free functions sharing the
`(conn, req, cfg, clientAddr)` tuple by convention. `forward.go` was a
god-file mixing four jobs: the validation pipeline
(`prepareForwardRequest`), dial+auth (`dialAndAuthUpstream`), the 145-line
keep-alive loop (`handleClient`), and CONNECT-via-upstream
(`forwardConnectViaUpstream`). `Config` (13 fields) was threaded whole
through 7 functions — 22 parameter sites, 42 field-read sites — so the
data dependency of each handler was invisible at its call boundary. The
implicit per-connection contract (e.g. "create the buffered request
reader exactly once, or pipelining silently breaks") was undocumented and
easy to violate.

Surfaced by a whole-codebase architecture review (findings F1 god-file,
F4 fat `Config`, F8 generic `handle*` names, F13 no handling layer). The
deletion test confirmed depth rather than a pass-through: removing a
hypothetical session reintroduces the same tuple across all 7 functions.

A material constraint shaped the decision: `handleClient(conn, cfg)` is
called directly by ~7 test files and by `Serve`. Constructing the session
"in `Serve`'s goroutine" (the original proposal wording) would have
forced edits to `server.go` and every test seam and risked reordering the
issue-#75 LIFO close defers.

## Decision

Introduce `ClientSession{conn, cfg, clientAddr, reqReader, proxyConn,
upstreamReader}`, constructed **inside `handleClient`** — not in `Serve`'s
goroutine — so `handleClient(conn net.Conn, cfg Config)` remains a
**Frozen Seam** for `Serve` and the test harness. The connection-level
cleanup defers (conn close / closeWrite / proxyConn close) stay in
`handleClient`, preserving the issue-#75 LIFO ordering exactly.

Convert the four sub-flows and the keep-alive loop to methods named for
the domain: `run`, `validateRequest`, `dialAndAuthUpstream` (kept its
`net.Conn` return so the reused keep-alive `s.proxyConn` and the fresh
per-CONNECT method-local conn cannot alias), `tunnelViaUpstream`,
`tunnelDirect`, `forwardDirect`. Replace wide `Config` threading with
`s.cfg`.

Keep `handleConnectTunnel` a free function with its narrow scalar
signature (the session destructures itself at the call site), and keep
the pure helpers (`connectionWillClose`, `dialDirect`, `sameHost`,
`handleDialError`, `stripIPv6Brackets`) free — methodising them would add
no locality.

Migration executed as nine substitution-only `refactor:` commits with the
full test suite green at each step.

## Consequences

- (+) Per-connection state, its lifetime, and ownership rules (single
  `reqReader`; lazily-dialled, reused `proxyConn`) are explicit in one
  type and enforced by structure rather than convention.
- (+) Handler signatures shrink to the per-request `*http.Request`;
  `Config` plumbing collapses to `s.cfg`. Handler names now reveal the
  domain (forward vs tunnel, via-upstream vs direct).
- (+) `handleClient` stays a one-screen constructor + dispatch shim; its
  call seam for `Serve` and tests is unchanged, which is what made the
  incremental green migration possible (the test/`server.go` diff against
  the pre-refactor commit is empty).
- (−) One more type and an `s.` indirection on the hot path; negligible
  (one struct allocation per connection, equivalent to the previous
  pass-by-value `Config`).
- (−) `handleConnectTunnel`'s deliberate decoupling means the session
  must destructure itself at that one call site (accepted: keeps the
  tunnel primitive minimal and independently testable).
- Zero behaviour change. Not SemVer-relevant — the CLI Contract Surface
  is untouched; `refactor:`/`docs:` commits only, no release triggered.

## Fuzz-target gate (issue #236 subtask)

No new fuzz target is mandated by this refactor: it introduces no new
parseable-input surface (same `http.ReadRequest`, same validation
pipeline, same `resp.Write`, relocated onto methods). The 7 existing
leaf-function `Fuzz*` targets are unaffected. A pre-existing coverage gap
— no target exercises the per-connection keep-alive request-reading loop
(bufio state across pipelined requests + drain + framing) — predates this
work and is tracked separately, not as a blocker for #236.
