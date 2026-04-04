# Adversarial Architecture Review: MITM Credential Injection Research Plan

**Date:** 2026-04-04  
**Reviewer:** Architecture & Design (adversarial)  
**Subject:** `docs/plans/2026-04-04-mitm-credential-injection-research.md`

---

## 1. Architectural Fit — Scope Creep Risk Is Real

spnego-proxy is a **single-purpose SPNEGO token injector** that operates as a
forward proxy to an upstream proxy. Its core loop reads a CONNECT tunnel, adds
one Kerberos header, and passes bytes through. The proposed system requires:

- A CA and certificate issuance engine
- A process-lifetime credential store with OAuth refresh logic
- A YAML policy engine with wildcard matching
- Per-tool response shim templates
- A TLS termination and re-origination stack

This is not an extension — it is a different product that happens to share a
binary. If this ships in spnego-proxy, every existing user inherits the attack
surface (CA key on disk, credential store) even when they never configure a
single injection rule. The honest architectural answer is to build a separate
binary, or at minimum a separate `cmd/` entry point, and share library code.
The plan does not address this split at all.

## 2. CredentialProvider Interface — Too Narrow

```go
GetCredential(ctx context.Context, host string) (headerName, headerValue string, err error)
```

This interface has four concrete problems:

**a. Single-header assumption.** AWS Signature V4 requires `Authorization`,
`x-amz-date`, and `x-amz-security-token` in every request. The interface
cannot return multiple headers without a breaking redesign.

**b. Host-only routing.** Many auth decisions depend on request path or method.
GitHub's fine-grained PATs are scoped to repository paths. An npm token for
`registry.npmjs.org/mypackage` may differ from one for a private scoped
registry at the same host. `host string` is insufficient; the argument should
be `*http.Request`.

**c. Cookie-based and body-based auth not handled.** The plan explicitly lists
OAuth via browser (gcloud) but the interface only returns a header. OAuth PKCE
flows require injecting into the request body (`grant_type`, `code_verifier`).
Cookie injection is entirely absent. There is no extensibility hook.

**d. No cache invalidation signal.** The provider has no `Invalidate` or
`OnUnauthorized` method. When the upstream returns 401, the caller has no way
to tell the provider that the cached token is stale and trigger a refresh.
This will cause retry storms on token expiry.

**Recommendation:** Return `func(*http.Request) error` — a mutator — instead
of a `(headerName, headerValue)` pair. Add `Invalidate(ctx, host)` to the
interface.

## 3. TLS Interception Architecture — Critical Gaps

**HTTP/2 is unaddressed.** The plan discusses intercepting HTTP/1.1 requests.
But `api.github.com` and all googleapis endpoints negotiate HTTP/2 via ALPN.
A naive TLS terminator that does not speak h2 will cause the upstream to
downgrade or reject the connection, breaking tools that rely on HTTP/2
multiplexing (gRPC especially). The proxy must either: (a) negotiate h2 with
the client, translate to h2 upstream — requiring a full h2 reverse proxy; or
(b) force h1 via ALPN on both sides, which is detectable and may break some
endpoints.

**WebSocket upgrades.** A WebSocket `Upgrade` over TLS through the proxy
requires the terminator to become a transparent byte pipe after the handshake.
The plan has no concept of "inspect headers then stop inspecting."

**CONNECT-in-CONNECT (nested tunnels).** Some tools (Terraform providers,
Docker CLI) tunnel another CONNECT inside the first. The inspection engine
must detect this and not attempt to parse the inner stream as HTTP.

**Certificate generation latency.** Per-destination leaf certificate issuance
must happen on the hot path of the first connection to each host. Under
concurrent load (npm install, pip install with hundreds of packages), the CA
signing operation adds latency to every unique host. The plan notes latency
risk but does not propose certificate caching keyed by SNI, which is the
standard mitigation.

## 4. Policy Engine — Dynamic Credential Rotation Not Modeled

The YAML config is static. The plan acknowledges OAuth token refresh but the
policy layer has no concept of:

- **Hot-reload** without restart (credentials rotate, container keeps running)
- **Credential revocation** — if a PAT is compromised, how does the operator
  push a replacement without restarting the proxy and breaking active tunnels?
- **Per-container identity** — if multiple containers share one proxy host,
  the YAML gives every container the same credentials, defeating per-agent
  isolation

The plan also lacks a credential reference scheme. `credential: github-pat` is
a name, but the YAML does not show where the value comes from: env var? file?
Secret store? This is a significant operational gap; hardcoding secrets in YAML
is the anti-pattern the proposal is meant to avoid.

## 5. Credential Shim Layer — Architecturally Brittle

The shim design returns synthetic responses keyed on `(host, path, method)`.
This is fragile in several concrete ways:

- **API versioning.** GitHub deprecated `/user` in favor of `/user` with a
  specific `Accept: application/vnd.github+json` header. The response schema
  changes across API versions. A static JSON body will break the moment the
  tool pins to a newer API version header.
- **Pagination and rate-limit headers.** `gh` reads `X-RateLimit-Remaining`
  from `/user` responses. A synthetic response without these headers may cause
  unexpected tool behavior.
- **POST body matching.** The OAuth token shim matches `POST /token` but does
  not inspect the request body. If the tool sends a `client_id` that the proxy
  does not recognize, the shim returns a token anyway, which the upstream may
  reject.
- **No fallback behavior on mismatch.** If the shim fails to match (e.g., the
  tool hits a new endpoint), the request either leaks unauthenticated to the
  upstream or is dropped. Neither is logged with enough context in the proposed
  design to debug.

## 6. State Management — Token Refresh Under Concurrency

The plan has `OAuthRefreshProvider` but does not describe the refresh
synchronization strategy. Concurrent requests with an expired token will all
race to refresh simultaneously (thundering herd against `oauth2.googleapis.com`).
Standard mitigation is a singleflight group keyed by credential name, but this
is absent from the design. The interaction with the circuit breaker (which
already exists in spnego-proxy for SPNEGO token acquisition) is not discussed —
do they share the same breaker? Separate ones?

## 7. Modularity and MVP

The plan's Phase 3 bundles TLS interception, the provider abstraction, the
policy engine, and the shim layer into a single prototype sprint. These are
four independent subsystems with different risk profiles. A brittle shim engine
should not block validating the TLS interception approach.

A realistic MVP is: static PAT injection for one host (api.github.com)
without any shim, with a manually injected CA. This validates the core TLS
termination loop in isolation. The plan does not identify this minimal slice.

## 8. Missing Research Areas

- **mTLS destinations.** Some corporate APIs require client certificates. The
  inspection engine sits in the middle and must either present the real client
  cert upstream or forge one — both are complex.
- **Certificate transparency logs.** Leaf certs issued by the local CA will not
  appear in CT logs. Some tools (rare) check CT. Not a blocker, but unmentioned.
- **Audit log.** A proxy that injects credentials and returns synthetic
  responses with no immutable audit trail is a compliance problem. No logging
  design is proposed.
- **Process isolation of the CA key.** The CA private key should not live in
  the same process as the credential store. A compromise of the injection logic
  should not automatically yield the CA key. The plan treats the whole system as
  one process.
- **Container escape scenarios.** If the container can reach the proxy
  management interface (health check port, config reload endpoint), it may be
  able to influence its own credential injection rules. Network namespacing
  between the container and the proxy management plane is not discussed.

## Summary

The research plan is well-motivated and the problem is real. The prior-art
survey (Phase 1) and tool behavior matrix (Phase 2) are sound research steps.
The architectural weaknesses are concentrated in Phases 3–4:

| Area | Risk | Severity |
|---|---|---|
| CredentialProvider interface | Too narrow; will require breaking redesign | High |
| HTTP/2 / ALPN handling | Not addressed; breaks majority of targets | High |
| Shim layer brittleness | Fragile to API changes; no versioning strategy | High |
| Scope creep into spnego-proxy | Inflates attack surface for all users | Medium |
| Token refresh concurrency | Thundering herd on expiry | Medium |
| CA key process isolation | Single-process compromise yields everything | Medium |
| Dynamic credential rotation | Static YAML insufficient for production | Medium |
| Audit logging | Absent; compliance gap | Low-Medium |

The plan should be revised to (a) separate the binary concern up front,
(b) redesign the CredentialProvider interface before any prototype code is
written, and (c) split Phase 3 into sequential slices so TLS interception
is validated before the shim layer is built.
