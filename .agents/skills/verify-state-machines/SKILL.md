---
name: verify-state-machines
description: "Re-run the TLA+ model checks that formal/ holds for spnego-proxy's concurrent state machines: the keep-alive relay, the token circuit breaker, the CONNECT tunnel idle timeout, the accept loop and shutdown, the -noproxy direct loop, and the gokrb5 TGT renewal goroutine. Use after changing internal/proxy/forward.go, response.go, connect.go, server.go, direct.go, circuit_breaker.go or auth_gokrb5.go, after changing a -cb-* / -idle-timeout / -noproxy / -timeout flag those machines read, or when you need the shortest path through a state machine that breaks one of its promises."
---

# Verify the state machines

`formal/` holds six TLA+ models of spnego-proxy's concurrent state machines. Each
model states the promises its machine makes, and TLC checks every order of steps
the model allows, so a broken promise comes back as the shortest sequence of
steps that breaks it. The checks are a **manual step**: CI does not run them.

The models are hand-written descriptions of the Go code. Nothing executes the Go
code, so a model can only be as right as the last person who read both. That is
why this file records which code each model describes and the commit at which
that was last confirmed.

## Prerequisites

The checks need Node, Java and TLC. Install them once:

- **Node** 22.18 to 22.x, or 23.6 or later — runs the checker.
- **Java** 25 (`temurin-25`) and **TLC** 1.7.4 — pinned by the checker, which
  installs both with [mise](https://mise.jdx.dev/) on its first run. The first
  run therefore needs the network; later runs do not.
- **The pstack `/statechart` command.** `formal/run-model.sh` looks for it on
  `PATH`, then at the pstack checkout path
  `~/ghq/github.com/cursor/plugins/pstack/skills/statechart/scripts/statechart`.
  If yours is elsewhere, set `STATECHART` to it.

Check the toolchain with `node --version` and `mise ls java http:tla2tools`.

## Run

From the repository root:

```bash
formal/run-model.sh                  # every model, about two minutes
formal/run-model.sh m4-serve-shutdown
formal/run-model.sh m5-direct-loop /tmp/my-run
```

The runner writes each config's `report.md`, `chart.mmd` and log under
`OUT_ROOT/<config>/`, where `OUT_ROOT` defaults to
`${TMPDIR:-/tmp}/spnego-formal-runs/<UTC time>`. It never writes inside the
repository. It then compares each config's verdict with `formal/expected.txt`
and prints one line per config:

- `ok` — the verdict is the one recorded.
- `MISMATCH` — the verdict changed. Read the next section before touching
  anything.
- `no line in expected.txt` — a config was added without recording its verdict.
- `statechart error` — the checker itself failed; read the named log.

Exit status: `0` all matched, `1` a verdict differs, `2` the checker errored.

## Read a result

Read every result with the pstack `/statechart` skill. `report.md` gives each
rule that breaks as a numbered path in plain words, `chart.mmd` is a Mermaid
statechart, and a state that breaks a rule is marked `breaks` (or `mayBreak`
when only some model states behind it break it). `/statechart` owns its own
commands, options and file layout, and they change between releases, so read
that skill rather than re-deriving them here.

Three things in a report are easy to misread:

- **`Rules not checked`** — TLC stopped before it checked that rule everywhere
  (the model outgrew the state cap, or an earlier break ended the run). A rule
  in that list neither holds nor breaks. `formal/expected.txt` records the
  configs where this is expected; anywhere else it means the run did not
  finish its job.
- **`NoDeadlock`** — a rule TLC adds, so a state with no step out shows up.
  Only m3 treats it as a promise. Everywhere else it is a sanity rule that says
  the model has no accidental dead end.
- **`TypeOK`** — a type sanity rule, never a promise about the product.

## The models

Rule names are the TLA+ names; each sentence is the promise in plain words and
the harm when it breaks. `breaks` marks a rule the config named after today's
code is expected to break; those breaks are the known defects, each tracked as
a GitHub issue. Do not weaken a rule, a bound or a config to clear one.

### m1-relay-keepalive — `Relay.tla`

Keep-alive relay of plain-HTTP requests through the upstream proxy. One action
is one blocking I/O call of the session goroutine, or one message from the
client or the upstream; dialling, the SPNEGO token and header rewriting are
folded into the forwarding step because they do not change which response is
paired with which request.

Covers `internal/proxy/forward.go` (`run`, `readNextRequest`,
`relayViaUpstream`, `writeResponse`), `internal/proxy/response.go`
(`readUpstreamResponse`, which calls `http.ReadResponse` once), and `net/http`'s
`Response.Write` closing the body it sent.

- `EveryRequestAnswered` — the proxy closes a client connection only after every
  request it read has a final answer. Break: the client's request fails after
  the read timeout instead of being answered. **breaks**
- `ProxyReadsOwnResponse` — the proxy relays the final response belonging to the
  request it just forwarded, never an interim (1xx) message. Break: a 1xx is
  relayed as the answer and a later message is framed against the wrong request.
  **breaks**
- `KeepAliveKept` — the connection survives a response that both sides keep
  alive. Break: every response with a body costs the client a new connection and
  the proxy a new upstream connection and token. **breaks**

Configs: `Relay.cfg` (today's code, `N=2`), `RelayDrainFixed.cfg` and
`RelayInterimFixed.cfg` (today's code with one of the two defects fixed, which
isolates the other), `RelayFixed.cfg` (the fix direction for both, `N=3`; all
rules hold).

### m2-token-breaker — `Breaker.tla`

The circuit breaker around SPNEGO token acquisition, with concurrent callers,
while the configured password no longer works. `beforeRequest` and
`afterRequest` are separate atomic steps as in gobreaker, the inner `GetToken`
calls are serialised as in the gokrb5 provider, and the open-to-half-open expiry
is one abstract step.

Covers `internal/proxy/circuit_breaker.go` (`NewCircuitBreakerTokenProvider`,
`GetToken`), gobreaker's `Execute`, `beforeRequest`, `afterRequest`,
`onFailure` and `currentState`, `internal/proxy/auth_gokrb5.go` (`GetToken`,
which holds its mutex across `AcquireCred` and `InitSecContext`), and
`internal/proxy/forward.go` (`dialAndAuthUpstream`, one `GetToken` per upstream
connection, so each client connection is a caller).

- `KDCFailuresBounded` — the KDC sees at most `-cb-threshold` rejected logins
  plus one per half-open probe. Break: a burst of client connections makes more
  failed logins than the breaker allows, and those count towards account
  lockout. **breaks**
- `NoLoginWhileOpen` — no login reaches the KDC while the breaker is open.
  **breaks**
- `SingleProbe` — while half-open, one probe is in flight. Holds today.

Configs: `Breaker.cfg` (today's code, four callers), `BreakerFixed.cfg` (a mutex
held across the whole `Execute`, two calls per caller, which also crosses
open → half-open → open), `BreakerSabotageMaxRequests.cfg` (deliberately broken:
`MaxRequests` 2, where `SingleProbe` must break).

### m3-connect-tunnel — `Tunnel.tla`

An established CONNECT tunnel with `-idle-timeout` enabled. Time is abstract: a
direction's read deadline may pass whenever its source is quiet, and
`otherActive` records whether the other direction moved data since that deadline
was set.

Covers `internal/proxy/connect.go` (`idleCopy`, `forwardHalf`,
`forwardTunnel`), `internal/proxy/forward.go` (`handleClient`, which closes both
connections after the tunnel returns), and the `-idle-timeout` help text in
`cli.go`.

- `IdleCutOnlyWhenIdle` — the idle timeout fires only when no data moved in
  either direction. Break: a long one-way transfer (a download where the client
  sends nothing) loses its other direction at the timeout. **breaks**
- `NoDataDroppedWhileOpen` — while the tunnel is open, data either side sends is
  forwarded. **breaks**
- `NoDeadlock` — the tunnel always ends. Break: a tunnel whose reader stops
  reading is never closed. **breaks**

Configs: `Tunnel.cfg` (today's code: one read deadline per direction, no write
deadline), `TunnelFixed.cfg` (a deadline that sees both directions, plus a write
deadline; all rules hold).

### m4-serve-shutdown — `Serve.tla`

Shutdown of the accept loop and of the keep-alive connections it started. Time
is abstract, except that the fix's urgent close of idle connections happens
before any deadline passes.

Covers `internal/proxy/server.go` (`Serve`: the accept goroutine, the
`<-acceptDone` wait before `wg.Wait`, the drain timeout), `internal/proxy/forward.go`
(`run`, `readNextRequest`, which never looks at the shutdown context), and
`main.go`'s signal handling.

- `NoAddAfterWait` — no connection handler starts after shutdown has begun
  waiting. Holds today.
- `DrainSkipsIdle` — shutdown waits only for requests in flight, never for a
  read deadline on a connection sitting idle between requests. **breaks**

Configs: `Serve.cfg` (today's code), `ServeFixed.cfg` (shutdown closes idle
connections and ends each busy connection after its current response; all rules
hold), `ServeSabotageNoAcceptDone.cfg` (deliberately broken: the `<-acceptDone`
wait removed, where `NoAddAfterWait` must break).

### m5-direct-loop — `DirectLoop.tla`

One client connection's keep-alive loop, through the upstream proxy and after a
request matched `-noproxy`. Hosts are compared in `sameHost`'s canonical form;
host parsing itself is out of scope (the fuzz targets cover it).

Covers `internal/proxy/forward.go` (`run`, `routeNoProxy`),
`internal/proxy/direct.go` (`forwardDirect`, `nextDirectRequest`, `relayDirect`,
`sameHost`).

- `BoundHostOnly` — a request written on a direct connection is for that
  connection's host. Holds today.
- `PolicyRouting` — matching hosts go direct and the rest go upstream, as
  `-noproxy` says. Holds today.
- `MixedHostsServed` — a request is never refused only because an earlier
  request on the same client connection went to another host. **breaks**

Configs: `DirectLoop.cfg` (today's code: the request is answered with 400 and
the loop ends), `DirectLoopReroute.cfg` (alternative: the loop ends and the
request is routed again; all rules hold), `DirectLoopSabotageNoCheck.cfg`
(deliberately broken: the `sameHost` check removed, where `BoundHostOnly` and
`PolicyRouting` must break).

### m6-tgt-renewal — `Renewal.tla`

The gokrb5 TGT session behind the circuit breaker, after the configured password
stops working. Time is abstract: the TGT moves fresh → last sixth → expired, and
`R` stands for the renewal goroutine's retries before expiry. One caller makes
its `GetToken` calls one at a time, so m2's burst plays no part here.

Covers `internal/proxy/circuit_breaker.go` (`GetToken`), `internal/proxy/auth_gokrb5.go`
(`GetToken`), gokrb5's `client/client.go` (`Login`, `AffirmLogin`,
`realmLogin`), `client/session.go` (`enableAutoSessionRenewal`,
`refreshSession`, `ensureValidSession`), and `client/TGSExchange.go`
(`GetServiceTicket`).

- `BreakerSeesEveryRejectedLogin` — every password login the KDC rejects is a
  failure the breaker counts. Break: the renewal goroutine retries logins the
  breaker never sees, so the lockout count climbs past `-cb-threshold`.
  **breaks** with a non-renewable TGT
- `RejectedLoginsBounded` — the KDC sees at most `-cb-threshold` rejected
  logins plus one per half-open probe. **breaks** with a non-renewable TGT

Configs: `RenewalNonRenewable.cfg` and `RenewalRenewable.cfg` (today's code with
each kind of TGT; a renewable TGT holds both rules), `RenewalFixed.cfg` (every
password login runs inside `GetToken`; all rules hold).

## When to run the checks

Run them when a change touches a machine above:

- a file or function listed under a model — especially if the function moved or
  was renamed, which is the strongest signal that the model needs a look;
- a constant, default or semantic of `-cb-threshold`, `-cb-timeout`,
  `-idle-timeout`, `-timeout` or `-noproxy`;
- a model or config under `formal/` itself.

A change that only touches tests, docs, CI or the fuzz targets does not need
them.

## When a verdict differs

`MISMATCH` means the model and the code disagree. Decide which one moved:

1. Read the config's `report.md` path and ask whether the code can do that. The
   models describe behaviour, so replay the path against the real code as a Go
   test or a live repro, one step per action.
2. **The code does it** — that is a finding, not a model bug. File an issue with
   the path as the counterexample. Leave the rule and the config alone, and
   record the new verdict in `formal/expected.txt` only when the issue is filed.
3. **The code cannot do it** — the model is stale. Fix the model so it describes
   the code, and say in the commit which code change made it stale.
4. **The code changed on purpose** — see the next section.

Never make a run pass by deleting a rule, widening a bound to hide a path, or
editing `expected.txt` alone.

## When a change is intended

When a machine changes on purpose, bring the model with it in the same commit:

1. Update the `.tla` so each action is still one indivisible step of the code,
   and update the line numbers and function names in its header comment.
2. Add a config for the new behaviour rather than editing the one named after
   the old code, so the old and new shapes stay comparable. Once a defect is
   fixed, the fixed shape becomes the code: move the `Fixed` constants into the
   plain config, keep the fixed config only if it still tests something else,
   and delete the config that no longer describes anything.
3. Run `formal/run-model.sh`, then update `formal/expected.txt` from the run.
4. Move the sync commit below forward — but only after you have read the model
   against the code at the new commit, not merely after the run passed.

## Coverage record

Each model was last confirmed against the code at **commit `ecd1990`**. The line
numbers in the models' header comments refer to that commit; when a listed
function has moved, treat the model as unconfirmed until you have re-read it.

| Model | Code at `ecd1990` |
| --- | --- |
| m1 | `internal/proxy/forward.go`, `internal/proxy/response.go` |
| m2 | `internal/proxy/circuit_breaker.go`, `internal/proxy/auth_gokrb5.go`, `internal/proxy/forward.go`, gobreaker v2.4.0 |
| m3 | `internal/proxy/connect.go`, `internal/proxy/forward.go`, `cli.go` (`-idle-timeout`) |
| m4 | `internal/proxy/server.go`, `internal/proxy/forward.go`, `main.go` |
| m5 | `internal/proxy/direct.go`, `internal/proxy/forward.go` |
| m6 | `internal/proxy/circuit_breaker.go`, `internal/proxy/auth_gokrb5.go`, gokrb5 v8.4.4 |

## What the checks do not cover

- **Bounds.** TLC explores every interleaving inside the constants each config
  sets — 2 to 4 concurrent actors and 2 to 3 requests or calls. A defect that
  needs more actors would not show.
- **Time.** Deadlines, timeouts and renewal intervals are abstract steps, so the
  models say what happens when a deadline passes, never how long it takes.
- **The Go code.** No model runs the code; the replay tests that check a path
  against the real proxy are not committed here.
- **Parsing.** Request, response, host and `-noproxy` parsing is left to the
  fuzz targets (see `CONTRIBUTING.md`).
- **The macOS GSS provider**, upstream TLS, the dial paths, `netutil.LimitListener`
  and the Windows build.
- **The accept-error spin**, which is outside m4's rules.

## Keeping this file in line

When the models are re-baselined wholesale — a big refactor, or a new machine —
follow the pstack `/maintain-formal-verification-skill` skill rather than editing
this file piecemeal.
