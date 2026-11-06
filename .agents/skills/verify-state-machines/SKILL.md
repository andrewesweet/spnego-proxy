---
name: verify-state-machines
description: "Re-run the TLA+ model checks that formal/ holds for spnego-proxy's concurrent state machines: the keep-alive relay, the token circuit breaker, the CONNECT tunnel idle timeout, the accept loop and shutdown, the -noproxy direct loop, and the gokrb5 TGT session behind the breaker. Use after changing internal/proxy/forward.go, response.go, connect.go, tunnel_write.go, server.go, direct.go, circuit_breaker.go or auth_gokrb5.go, after changing a flag listed under 'When to run the checks', or when you need the shortest path through a state machine that breaks one of its promises."
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
- **The pstack `/statechart` command.** Set `STATECHART` to its executable
  path, or put `statechart` on `PATH`. The runner uses `STATECHART` when set;
  otherwise it looks for `statechart` on `PATH`.

Check the toolchain with `node --version` and `mise ls java http:tla2tools`.

When Java and TLC are installed but not on `PATH`, the checker still finds them
if `TLA2TOOLS` and `JAVA` name them, so a machine that has run the checker once
can run it again without a shell that has mise activated:

```bash
STATECHART=/path/to/statechart \
TLA2TOOLS="$HOME/.local/share/mise/installs/http-tla2tools/1.7.4/tla2tools.jar" \
JAVA="$(mise which java --tool java@temurin-25)" \
formal/run-model.sh all
```

Do not install a tool to get past a missing one; find the installed copy with
`mise where http:tla2tools` and `mise which java --tool java@temurin-25`.

## Run

From the repository root:

```bash
formal/run-model.sh                  # every model, about two minutes
formal/run-model.sh m4-serve-shutdown
formal/run-model.sh m5-direct-loop /tmp/my-run
```

The first argument accepts only `all` or an exact model folder name under
`formal/`. Omitting it runs every model. Paths to model folders are not accepted.

The runner writes each config's `report.md` and `chart.mmd` under
`OUT_ROOT/<config>/`, and its log to `OUT_ROOT/<config>.log`. `OUT_ROOT` defaults
to `${TMPDIR:-/tmp}/spnego-formal-runs/<UTC time>`; the second argument selects
another directory. Existing output paths are reused and logs are overwritten,
so choose a fresh directory to preserve earlier runs.
The runner then compares each config's verdict with `formal/expected.txt` and
prints one line per config:

- `ok` — the verdict is the one recorded.
- `MISMATCH` — the verdict changed. Read the next section before touching
  anything.
- `no line in expected.txt` — a config was added without recording its verdict.
- `no verdict` — the checker exited without writing a report or a verdict
  section, so it checked nothing; the run counts as a checker error.
- `statechart error` — the checker itself failed; read the named log.

`expected.txt` and the configs must match one to one. The runner refuses to
start when a config is recorded twice, and fails when a record for a selected
model names a config this run did not produce. Run all models to detect stale
expectations anywhere in the file.

Exit status: `0` all matched, `1` a verdict differs or is missing from
`expected.txt`, or the records and configs do not match one to one; `2` the
checker is unavailable, the output directory cannot be created, a model name is
invalid, or a checker run errored or reported no verdict.

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

The summaries, function names, and verdicts below describe the state in the
[coverage record](#coverage-record). Rule names are the TLA+ names; each sentence
is the promise in plain words and the harm when it breaks. Each model has a
plain `<Model>.cfg` for the code as it is — every rule must hold there — and
`<Model>Sabotage*.cfg` configs that deliberately break the code in one recorded
way and must break exactly the rules listed for them. Do not weaken a rule, a
bound or a config to clear one.

### m1-relay-keepalive — `Relay.tla`

Keep-alive relay of plain-HTTP requests through the upstream proxy. One action
is one blocking I/O call of the session goroutine, or one message from the
client or the upstream; dialling, the SPNEGO token and header rewriting are
folded into the forwarding step because they do not change which response is
paired with which request. A request may receive up to two 1xx messages before
its final response, and `readThroughInterim` relays each non-101 1xx and keeps
reading until the final response.

Covers `internal/proxy/forward.go` (`run`, `readNextRequest`,
`relayViaUpstream`, `writeResponse`), `internal/proxy/response.go`
(`readUpstreamResponse`, which calls `http.ReadResponse` once per call, and
`readThroughInterim`), and `net/http`'s `Response.Write` closing the body it
sent, which is why `writeResponse` runs no drain.

- `EveryRequestAnswered` — the proxy closes a client connection only after every
  request the client sent has a final answer. Break: the client's request fails
  after the read timeout instead of being answered.
- `ProxyReadsOwnResponse` — the proxy relays the final response belonging to the
  request it just forwarded, never an interim (1xx) message. Break: a 1xx is
  relayed as the answer and a later message is framed against the wrong request.
- `KeepAliveKept` — the connection survives a response that both sides keep
  alive. Break: every response with a body costs the client a new connection and
  the proxy a new upstream connection and token.

Configs: `Relay.cfg` (the code; all rules hold), `RelaySabotageSingleRead.cfg`
(deliberately broken: the 1xx loop removed, the ecd1990 shape, where
`EveryRequestAnswered` and `ProxyReadsOwnResponse` must break),
`RelaySabotageBodyDrain.cfg` (deliberately broken: the ecd1990 body drain
restored, where `EveryRequestAnswered` and `KeepAliveKept` must break).

### m2-token-breaker — `Breaker.tla`

The circuit breaker around SPNEGO token acquisition, with concurrent callers,
while the configured password no longer works. The backend abstraction has
neither a cached TGT nor a password-rejection latch: every admitted inner call
attempts one rejected login. This conservatively checks the breaker's bounds;
current gokrb5 rejects repeat calls for the same rejected fingerprint without
KDC contact, as m6 models. `beforeRequest` and `afterRequest` are separate atomic
steps as in gobreaker. Inner calls are serialised by the backend mutex and by
the mutex held across the whole `Execute`; open-to-half-open expiry is one
abstract step.

Covers `internal/proxy/circuit_breaker.go` (`NewCircuitBreakerTokenProvider`,
`GetToken`), gobreaker's `Execute`, `beforeRequest`, `afterRequest`,
`onFailure` and `currentState`, the mutex in `internal/proxy/auth_gokrb5.go`
(`GetToken`, held across `ticketGrantingClient` and `InitSecContext`, with the
password-rejection latch omitted), and
`internal/proxy/forward.go` (`dialAndAuthUpstream`, one `GetToken` per upstream
connection, so each client connection is a caller).

- `KDCFailuresBounded` — the KDC sees at most `-cb-threshold` rejected logins
  plus one per half-open probe. Break: a burst of client connections makes more
  failed logins than the breaker allows, and those count towards account
  lockout.
- `NoLoginWhileOpen` — no login reaches the KDC while the breaker is open.
- `SingleProbe` — while half-open, one probe is in flight. Holds in the code
  config and breaks only in `BreakerSabotageMaxRequests.cfg`.

Configs use this latch-free backend abstraction: `Breaker.cfg` (current
breaker settings, four callers and two calls each, crossing open → half-open →
open; all rules hold), `BreakerSabotageUnserialised.cfg` (the `Execute` mutex
removed, the ecd1990 shape, where `KDCFailuresBounded` and `NoLoginWhileOpen`
must break), and `BreakerSabotageMaxRequests.cfg` (the mutex removed and
`MaxRequests` 2, where `SingleProbe` must break). The first sabotage's KDC
failures do not reproduce current gokrb5 with only the outer mutex removed:
its inner mutex and fingerprint latch allow only one rejected login for an
unchanged password.

### m3-connect-tunnel — `Tunnel.tla`

An established CONNECT tunnel with `-idle-timeout` enabled. Time is abstract: a
direction's read deadline may pass whenever its source is quiet, and
`otherActive` records whether the tunnel moved data since that deadline was
armed — in the code that is the shared tunnelClock, whose last touch can come
from either half. `timeoutReArms` counts the deadlines that passed while the
tunnel was not idle and were re-armed; `cutWhileFlowing` counts every cut.

Covers `internal/proxy/connect.go` (`idleCopy`, `forwardHalf`,
`forwardTunnel`, the `tunnelClock`), `internal/proxy/tunnel_write.go`
(`tunnelConn`, which re-arms the read deadline and arms a write deadline),
`internal/proxy/forward.go` (`handleClientCtx`, which closes both connections
after the tunnel returns), and the `-idle-timeout` help text in `cli.go`.

- `IdleCutOnlyWhenIdle` — a read deadline never cuts a direction, and never
  closes the tunnel, while the other direction moved data in that read window.
  Break: a long one-way transfer (a download where the client sends nothing)
  loses its other direction at the timeout.
- `NoDataDroppedWhileOpen` — see the invariant comment in
  [`Tunnel.tla`](../../../formal/m3-connect-tunnel/Tunnel.tla) for its precise
  safety guarantee and delivery limits.
- `NoDeadlock` — an open tunnel never reaches a state with no enabled step.
  Break: a tunnel whose reader stops reading can become stuck without closing.
  This checks for dead ends, not eventual termination.

Configs: `Tunnel.cfg` (the code: one deadline that sees both directions, plus
a write deadline; all rules hold), `TunnelSabotagePerDirection.cfg`
(deliberately broken: one read deadline per direction and no write deadline,
the ecd1990 shape, where all three rules must break).

### m4-serve-shutdown — `Serve.tla`

Shutdown of the accept loop and of the keep-alive connections it started. Time
is abstract, except that the code's urgent close of idle connections happens
before any deadline passes.

Covers `internal/proxy/server.go` (`Serve`: the accept goroutine with its
backoff, the `<-acceptDone` wait before `wg.Wait`, the drain timeout),
`internal/proxy/forward.go` (`handleClientCtx`, `readRequest`, which discards a
request read after shutdown began, and `writeResponse`, which ends a busy
connection after its response), and `main.go`'s signal handling.

- `NoAddAfterWait` — no connection handler starts after shutdown has begun
  waiting. Holds in the code config.
- `DrainSkipsIdle` — shutdown waits only for requests in flight, never for a
  read deadline on a connection sitting idle between requests.

Configs: `Serve.cfg` (the code; all rules hold), `ServeSabotageNoIdleClose.cfg`
(deliberately broken: the idle-connection close removed, the ecd1990 shape,
where `DrainSkipsIdle` must break), `ServeSabotageNoAcceptDone.cfg`
(deliberately broken: the `<-acceptDone` wait removed, where `NoAddAfterWait`
must break).

### m5-direct-loop — `DirectLoop.tla`

One client connection's keep-alive loop, through the upstream proxy and after a
request matched `-noproxy`. Hosts are compared in `sameHost`'s canonical form;
host parsing itself is out of scope (the fuzz targets cover it). The model
covers plain-HTTP requests only: the 400 that `nextDirectRequest` answers for a
CONNECT on a bound direct connection is not modelled, so a regression there
would not show.

Covers `internal/proxy/forward.go` (`run`, `routeRequest`),
`internal/proxy/direct.go` (`forwardDirect`, `nextDirectRequest`,
`relayDirect`, `sameHost`).

- `BoundHostOnly` — a request written on a direct connection is for that
  connection's host. Holds in the code config.
- `PolicyRouting` — matching hosts go direct and the rest go upstream, as
  `-noproxy` says. Holds in the code config.
- `MixedHostsServed` — a request is never refused only because an earlier
  request on the same client connection went to another host.

Configs: `DirectLoop.cfg` (the code: the loop ends and the request is routed
again; all rules hold), `DirectLoopSabotageRefuse.cfg` (deliberately broken:
the ecd1990 refusal, where the request is answered with 400 and the loop ends,
and `MixedHostsServed` must break), `DirectLoopSabotageNoCheck.cfg`
(deliberately broken: the `sameHost` check removed, where `BoundHostOnly` and
`PolicyRouting` must break).

### m6-tgt-renewal — `Renewal.tla`

The gokrb5 TGT session behind the circuit breaker, after the configured password
stops working. Time is abstract: the TGT moves fresh → past its refresh point
(5/6 of the lifetime) → expired, and every state past the refresh point makes
the next `GetToken` replace the TGT with one password AS exchange. The only
password login is that replacement, inside `GetToken`; `checkPasswordRejected`
refuses every login without KDC contact until the password file's content
changes. One caller makes its `GetToken` calls one at a time, so m2's burst
plays no part here.

Covers `internal/proxy/circuit_breaker.go` (`GetToken`, the mutex held across
`Execute`), `internal/proxy/auth_gokrb5.go` (`GetToken`,
`ticketGrantingClient`, `acquireCredential`, `checkPasswordRejected`,
`tgtRefreshDeadline`), and the absence of a session renewal goroutine:
gokrb5's auto-renewal and its password-login fallback are outside the provider.

- `BreakerSeesEveryRejectedLogin` — every password login the KDC rejects is a
  failure the breaker counts. Break: the renewal goroutine retries logins the
  breaker never sees, so the lockout count climbs past `-cb-threshold`.
- `RejectedLoginsBounded` — the KDC sees at most `-cb-threshold` rejected
  logins plus one per half-open probe.

Configs: `Renewal.cfg` (the code; all rules hold),
`RenewalSabotageGoroutineRefresh.cfg` (deliberately broken: the ecd1990 shape,
a renewal goroutine that logs in outside `GetToken` and the breaker, where both
rules must break).

## When to run the checks

Run them when a change touches a machine above:

- a file or function listed under a model — especially if the function moved or
  was renamed, which is the strongest signal that the model needs a look;
- a constant, default or semantic of a flag the models read: `-read-timeout`,
  `-dial-timeout`, `-keepalive`, `-drain-timeout`, `-idle-timeout`,
  `-cb-threshold`, `-cb-timeout`, `-noproxy` or `-connect-ports`;
- a model or config under `formal/` itself.

A change that only touches tests, docs, CI or the fuzz targets does not need
them.

## When a verdict differs

`MISMATCH` means the checked verdict differs from `formal/expected.txt`.
Compare the model with the code to decide which one moved:

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

Each model was last confirmed against the code at **commit `52034ab`**. The line
numbers in the models' header comments refer to that commit; when a listed
function has moved, treat the model as unconfirmed until you have re-read it.

For the current user-facing contract, see
[HTTP connection reuse and shutdown](../../../README.md#http-connection-reuse-and-shutdown).

| Model | Code at `52034ab` |
| --- | --- |
| m1 | `internal/proxy/forward.go`, `internal/proxy/response.go` |
| m2 | `internal/proxy/circuit_breaker.go`, `internal/proxy/auth_gokrb5.go` (mutex only; cached TGT and password-rejection latch omitted), `internal/proxy/forward.go`, gobreaker v2.4.0 |
| m3 | `internal/proxy/connect.go`, `internal/proxy/tunnel_write.go`, `internal/proxy/forward.go`, `cli.go` (`-idle-timeout`) |
| m4 | `internal/proxy/server.go`, `internal/proxy/forward.go`, `main.go` |
| m5 | `internal/proxy/direct.go`, `internal/proxy/forward.go` |
| m6 | `internal/proxy/circuit_breaker.go`, `internal/proxy/auth_gokrb5.go` (gokrb5 internals no longer covered) |

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
- **The accept-error backoff**: the accept loop waits out an exponential
  backoff between failed accepts (server.go); m4 treats the loop's retry as
  one step and does not model the backoff timing.

## Keeping this file in line

When the models are re-baselined wholesale — a big refactor, or a new machine —
follow the pstack `/maintain-formal-verification-skill` skill rather than editing
this file piecemeal.
