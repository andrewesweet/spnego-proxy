# Adversarial Review: MITM Credential Injection — Revised Plan (v2)

**Date:** 2026-04-05
**Reviewer:** Senior Engineering (adversarial review, second pass)
**Subject:** Revised plan incorporating pivots 1–14 above
**Scope:** NEW weaknesses not caught by prior reviewers + unresolved prior critiques

---

## Part I — Unresolved Prior Critiques

### U1. Host-header vs. SNI authority (Security review M8) — still unresolved [HIGH]

The v2 plan adopts `CredentialMutator` and per-container identity but does not
state which authority the proxy uses when deciding which credential to inject:
the CONNECT hostname, the TLS SNI value, or the decrypted `Host` header. These
can disagree. A container can CONNECT to `api.github.com:443` (allowlisted),
send SNI `api.github.com`, but write `Host: internal.corp.example.com` after
TLS termination. The revised plan's policy+identity slice (Phase 3d) does not
name this decision point. The injection credential is then chosen by the wrong
key, and the wrong secret goes outbound.

### U2. `refresh-and-respond` still leaks the access token to the container [HIGH]

The security review flagged that the gcloud OAuth shim returns the real access
token in the response body. The v2 plan introduces the sentinel mechanism
(`Authorization: Bearer sentinel-<id>`) for outbound injection, but Phase 3c
still describes an `OAuthRefreshProvider` that can return a token to satisfy
a `gcloud auth print-access-token` call. If the container can invoke that
command and the proxy faithfully returns a real token, the credential is in
the container. The revised plan does not close this gap for token-print
commands; it only addresses header injection for normal API calls.

### U3. Wildcard rule scope creep (Security review finding 5.3) — not addressed [MEDIUM]

`*.googleapis.com` matching is carried forward in the v2 design. The revised
plan adds per-container identity binding but does not constrain wildcard host
rules. A compromised container still triggers credential injection for any
subdomain that matches a wildcard, including attacker-controlled subdomains
reachable via DNS poisoning or subdomain takeover.

---

## Part II — New Weaknesses

### N1. Sentinel token fails for tools with local JWT validation [CRITICAL]

The sentinel design (`Authorization: Bearer sentinel-<id>`) assumes the tool
forwards the header to the network without inspecting it first. Several tools
break this assumption:

- **gcloud SDK** validates the ADC access token offline using the token's `exp`
  claim before making any network call. A sentinel string is not a JWT and will
  fail `jwt.Parse` immediately, producing "invalid token format" — not a network
  error the proxy can intercept.
- **Google Cloud client libraries** (Python, Java, Go) call
  `credentials.token_state()` before the first RPC; if the token is not a
  parseable JWT with a non-expired `exp`, they attempt a full re-auth flow that
  the proxy cannot intercept because it originates from the credential library's
  internal HTTP client, which may bypass `HTTP_PROXY` entirely.
- **npm v9+** validates the format of registry tokens (base64url, specific
  length constraints) before the first registry call.

The plan acknowledges local validation as a risk for Phase 2 but treats it as
a matter of "dummy credentials with correct format." For JWT-based credentials
this means the container must receive a structurally valid, non-expired JWT —
which is a real credential, not a sentinel. The sentinel approach does not
compose with local JWT validation. Phase 3c needs a concrete answer for this
case before the OAuth sentinel slice is scheduled.

### N2. SO_PEERCRED and Unix socket identity are weaker than the plan implies [HIGH]

The plan proposes Unix socket + `SO_PEERCRED` as the per-container identity
mechanism. `SO_PEERCRED` returns the UID/PID of the connecting process. Three
concrete weaknesses:

1. **PID reuse.** The PID the proxy reads from `SO_PEERCRED` is the PID at
   connection time. On a busy host, the container process may have exited and a
   new unrelated process may have the same PID before the proxy finishes
   evaluating policy. The window is small but non-zero under high fork/exit
   churn.

2. **Network namespace sharing.** If two containers share a network namespace
   (e.g., Kubernetes pod sidecar pattern, or `--network container:X`), they
   share the same Unix socket view and present the same identity to the proxy.
   A compromised sidecar can make requests on behalf of the main container
   identity. The plan does not address namespace co-location.

3. **UID 0 mapping.** In user-namespace containers, UID 0 inside the container
   maps to an unprivileged UID on the host. `SO_PEERCRED` returns the *host*
   UID. If two containers run as the same host UID (common with rootless
   Podman's default UID mapping), `SO_PEERCRED` cannot distinguish them. The
   plan's identity model silently collapses to a single identity for all
   containers sharing a host UID.

### N3. The hybrid approach creates two credential systems, not one [HIGH]

The v2 plan routes SSH/GPG/Kerberos through existing agent forwarding and
bearer-token APIs through the MITM proxy. This means operators must configure,
monitor, and rotate credentials in two separate systems with different failure
modes. The security boundary between them is also unclear: if an attacker
compromises the MITM proxy credential store, they do not get Kerberos TGTs;
if they compromise the SSH agent socket, they do not get bearer tokens. That
is the benefit. The cost not acknowledged in the plan:

- Two distinct identity propagation paths means two audit log sources that
  must be correlated to reconstruct a single agent session's full credential
  usage.
- If a tool uses both Kerberos (for an internal API) and a bearer token (for
  an external API) in the same session, debugging auth failures requires
  understanding which path is active — a significant DX increase over either
  approach alone.
- The plan's Phase 0 DX spike evaluates "time to first success" but this
  metric does not capture the ongoing maintenance cost of two systems. A tool
  that migrates from Kerberos to OAuth (common in enterprise cloud migrations)
  requires re-routing in the hybrid model; a single-path model just adds a
  provider.

### N4. Phase 0 "time to first success" is the wrong metric [MEDIUM]

The DX spike uses time-to-first-success to compare pure MITM vs. hybrid vs.
helper-socket approaches. This metric favors whichever approach has the
simplest happy path. The failure modes differ dramatically:

- Helper-socket fails: the tool gets a clear "credential helper exited with
  code 1" message with a stack trace pointing to the helper binary.
- MITM proxy fails: the tool gets `SSL: CERTIFICATE_VERIFY_FAILED` or a silent
  `401`, with no indication that a proxy is in the middle.

Time-to-first-success cannot detect this asymmetry. The spike should also
measure time-to-diagnosis of a deliberately injected failure (expired
credential, missing shim, proxy not running). Without this, Phase 0 may
select the MITM path because setup is fast while hiding that debugging is
five times harder.

### N5. gRPC and HTTP/2 trailers are not covered by "mandatory H2" [HIGH]

The plan mandates HTTP/2 end-to-end using `golang.org/x/net/http2`. This
addresses basic H2 multiplexing, but GCP SDKs use gRPC, which has additional
requirements the plan does not address:

- **gRPC trailers.** gRPC uses HTTP/2 trailing headers (`HEADERS` frame with
  `END_STREAM`) to carry status codes and metadata. Go's `net/http` does not
  expose trailing headers on the response writer; an H2 proxy built on
  `net/http` will silently drop them. gRPC calls will appear to succeed but
  lose status codes, causing the client-side gRPC library to report
  `UNKNOWN` errors.
- **gRPC-Web.** Some GCP browser and CLI clients use gRPC-Web (HTTP/1.1 with
  `Content-Type: application/grpc-web`), which encodes trailers in the
  response body. The proxy must not re-encode these.
- **H2 flow control.** A streaming gRPC call (e.g., `gcloud run services logs
  --follow`) will stall if the proxy does not propagate `WINDOW_UPDATE` frames
  correctly between client and upstream streams. `golang.org/x/net/http2` does
  manage flow control internally, but only if the proxy correctly bridges two
  independent H2 connections — this requires the proxy to act as an H2
  reverse proxy, not just forward requests, and the plan does not specify this
  architecture.

### N6. Ephemeral per-session CA creates a long-lived trust anchor problem [MEDIUM]

The plan proposes that `agent-run` creates an ephemeral CA per session and
injects it into the container at startup. Two problems:

1. **Long-lived agent sessions.** An AI coding agent may run for hours or
   across multiple `agent-run` invocations (e.g., resumed sessions, tmux
   detach). If each invocation generates a new CA, the container's trust store
   accumulates stale CA entries. If the container is long-lived (days), the
   accumulation becomes a trust-store audit problem. The plan does not specify
   CA TTL or cleanup.

2. **Startup latency is unquantified.** Generating a CA key pair (ECDSA P-256)
   and signing it takes ~1–2 ms, but injecting it into a container trust store
   requires either a volume mount resolution at container start or an `exec`
   into the running container. If the trust store injection uses `update-ca-
   certificates` inside the container, that adds 500ms–2s depending on the
   image. The plan calls this the "primary UX" but does not acknowledge the
   startup cost.

### N7. `agent-run` cannot prevent HTTP_PROXY bypass by the container [HIGH]

The plan asks whether `agent-run` defends against a container that overrides
`HTTP_PROXY`. It does not. A container process that sets `HTTP_PROXY=` (empty)
or `HTTP_PROXY=http://attacker.example.com/` after startup bypasses the proxy
entirely. Mitigations available but absent from the plan:

- **`iptables` REDIRECT rules in the container's network namespace** — all
  TCP port 443 traffic redirected to the proxy regardless of env vars. This
  requires host-side `CAP_NET_ADMIN` or a network namespace wrapper. The plan
  mentions transparent proxy as prior art but does not adopt it.
- **Seccomp/AppArmor policy** blocking `setenv` for `HTTP_PROXY` — fragile
  and not mentioned.
- Without one of these, a sufficiently motivated container workload can
  trivially exfiltrate credentials by bypassing the proxy. The plan's security
  model assumes env var enforcement, which is not enforced.

### N8. The "separate binary" boundary does not reduce combined attack surface when co-deployed [MEDIUM]

The plan states that `agent-proxy` ships as a separate binary from
`spnego-proxy`. Users who run both on the same host (the target deployment
model) have both attack surfaces simultaneously. The CA key, the credential
store, and the SPNEGO keytab all live in the same OS user's filesystem. A
local privilege escalation or a supply chain compromise of either binary
reaches all of them. The separation is an architectural boundary, not a
security boundary unless enforced by OS primitives (separate UIDs, separate
`systemd` service units with restricted filesystem access, separate cgroups).
The plan does not specify the OS-level isolation model between the two
binaries, so the "separate binary" statement provides a false sense of
isolation.

### N9. Phase 2 tool-behavior mapping is a permanent maintenance liability [MEDIUM]

The plan correctly defers shim development until Phase 2 empirically maps each
tool's validation behavior. However, the plan underestimates the ongoing cost:

- Tool versions are not pinned in Phase 2. The matrix is valid at the time of
  measurement and may be wrong one minor release later (`gcloud` components
  auto-update by default; npm has auto-updated since v7).
- The plan has no mechanism for detecting when a tool update invalidates a
  shim. The proxy will silently return a shim response that no longer matches
  the tool's expected schema, producing mysterious failures in production.
- A correct implementation requires a CI matrix that runs the tool behavior
  tests against each new tool release — an ongoing engineering investment the
  plan does not budget for.

### N10. Phase 3c OAuth sentinel: token inspection by the container [MEDIUM]

If a container legitimately needs to inspect the access token — for example,
to extract the `sub` claim for audit logging, or because the application code
calls `credentials.id_token` to generate a signed assertion for a downstream
service — a sentinel string fails silently. The application gets a
non-decodable token, logs a garbage subject, or generates an invalid
downstream assertion. The plan does not define what the proxy should return
when the container requests a token for purposes other than direct API
authorization. This is not an edge case: audit logging of the calling identity
is standard in any compliance-relevant workload.

---

## Summary Table

| ID | Finding | Severity | Prior reviewers |
|----|---------|----------|----------------|
| U1 | Host vs. SNI authority unresolved | High | Carried from security review M8 |
| U2 | Token-print commands still expose real tokens | High | Carried from security review §4 |
| U3 | Wildcard rule scope not constrained | Medium | Carried from security review 5.3 |
| N1 | Sentinel breaks for locally-validating JWT tools | Critical | New |
| N2 | SO_PEERCRED identity weaker than stated | High | New |
| N3 | Hybrid approach doubles operational surface | High | New |
| N4 | Phase 0 "time to first success" metric misleads | Medium | New |
| N5 | gRPC trailers and H2 flow control not covered | High | New |
| N6 | Ephemeral CA accumulates; startup latency unquantified | Medium | New |
| N7 | HTTP_PROXY bypass not defended | High | New |
| N8 | Separate binary is not a security boundary | Medium | New |
| N9 | Tool-behavior matrix is a permanent maintenance liability | Medium | New |
| N10 | Container token inspection breaks sentinel model | Medium | New |

**Critical issues requiring resolution before Phase 3c is scheduled:** N1.

**Issues requiring resolution before Phase 3d (policy+identity):** U1, N2, N7.

**Issues requiring architectural decision before Phase 0 completes:** N3, N4.
