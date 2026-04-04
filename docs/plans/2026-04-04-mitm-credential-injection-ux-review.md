# Adversarial UX Review: MITM Credential Injection Research Plan

**Date:** 2026-04-04  
**Reviewer role:** Senior DX / UX engineer  
**Document reviewed:** `2026-04-04-mitm-credential-injection-research.md`

---

## Executive Summary

The proposal is technically coherent but ships a UX iceberg: the diagram fits on one slide; the real setup burden is eight distinct manual steps with failure modes at each. As written, this is a platform team offering, not a developer tool. Individual developers will abandon it at step three.

---

## 1. Setup Complexity — Eight Steps, Every One a Trap

The plan requires, in order:

1. Generate a local CA (`openssl` or `mkcert`)
2. Inject the CA into **each container image** — differently per runtime (system `update-ca-certificates`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, Java `keytool`)
3. Set `HTTP_PROXY` / `HTTPS_PROXY` in the container environment
4. Author a YAML policy file (hosts, actions, credential references)
5. Author a shim YAML file (per-tool synthetic response templates)
6. Populate a credential store on the host (PATs, OAuth refresh tokens, client secrets)
7. Create plausible dummy credential files inside the container (for tools with local schema validation)
8. Start and validate the proxy is running before any container launch

The existing spnego-proxy has a flat CLI surface: one `-proxy`, one `-spn`, a handful of timeout flags. This proposal multiplies that surface by an order of magnitude before a user sees a working request. A developer who just wants `gh pr list` to work will encounter this as "fill in five config files and rebuild your Docker image."

**Verdict:** Not viable as self-service. Requires a platform team to vend pre-baked images and a credential-store operator.

---

## 2. Debugging Experience — TLS Errors Are a Black Box

When TLS interception fails silently the tool reports only what it sees: `curl: (60) SSL certificate problem: unable to get local issuer certificate`. There is no hint that a proxy is in the middle. The user must know to check `HTTP_PROXY`, verify the CA bundle, confirm the proxy is running, and cross-reference the proxy's JSON log — none of which is obvious.

The plan mentions a JSON log (spnego-proxy already uses `slog` JSON), but does not define what events are emitted during TLS interception. Without structured events like `tls_inspection_started`, `cert_issued_for`, `credential_injected`, `shim_matched`, debugging becomes `tcpdump` territory.

Specific debugging nightmares:
- `gcloud` JWT expiry is checked **locally** before any network call. The proxy never sees it. The error looks like a missing ADC file, not a proxy issue.
- A shim that returns `{"login":"container-agent","id":0}` will pass `gh auth status` but fail `gh pr list` if `gh` checks `id != 0` or validates the token scopes embedded in the PAT itself.
- If the proxy is restarted and the ephemeral CA keypair regenerated, all containers with the old CA baked in silently break.

---

## 3. Error Attribution — Three Failure Classes, Zero Distinction

The proxy creates a new failure category that looks identical to existing categories:

| Actual cause | What the user sees |
|---|---|
| Proxy misconfigured (missing shim) | `401 Unauthorized` from tool |
| Credential expired on host | `401 Unauthorized` from tool |
| Shim response out of date (tool updated API shape) | `401 Unauthorized` or tool crash |
| Proxy not running | `Connection refused` or hang |

Without a proxy-side request/response log with correlation IDs threaded back to the tool, the user cannot distinguish these. The plan does not address error attribution tooling at all.

---

## 4. Configuration Surface — Four New Concepts, One New Format

Current spnego-proxy config: CLI flags only, no files required.

This proposal adds:
- Policy YAML (rules, hosts, actions, credential references)
- Shim YAML (match patterns, response bodies per tool per endpoint)
- Credential store (format unspecified — env file? vault? JSON?)
- CA lifecycle management (generation, rotation, container re-injection)

That is four new sub-systems with no defined schema, no validation tooling, and no error messages for misconfiguration. A typo in a host glob silently passes all traffic or silently denies it depending on the catch-all rule.

**Simpler alternative:** A single structured config file with `go-jsonschema`-generated validation and a `spnego-proxy validate` subcommand would cut debugging time by half.

---

## 5. Shim Maintenance — An Unbounded Ongoing Burden

Each supported tool is a maintenance contract:

- `gh` v2 → v3 may change the `/user` response schema or add scope checks
- `gcloud` changes its ADC token endpoint shape with SDK updates
- `npm` added token format validation in v9

The plan has no answer for who maintains shims, how versions are pinned, or how users learn that a tool update broke their container. There is no mention of a community registry, no versioned shim definitions, no compatibility matrix. Every user is on their own.

---

## 6. Container Image Requirements — Dockerfile Pollution

Every container image must be modified to trust the MITM CA. For a team using five base images (alpine, debian-slim, python, node, openjdk), that is five different CA injection patterns, each requiring a layer rebuild on CA rotation.

This conflicts with the container isolation goal: if the CA is baked in, rotating it requires rebuilding and redeploying images — the same operational overhead the proposal is trying to avoid.

The plan identifies trust store fragmentation as a risk but offers no mitigation. The least-friction approach (a mounted CA bundle via `--volume`) is not discussed.

---

## 7. Failure Modes — Silent and Confusing

| Scenario | Observed behavior |
|---|---|
| Proxy down, container starts | `HTTP_PROXY` set but unreachable — tools hang for `dial-timeout` (default 30s), then exit with a generic network error |
| Proxy up, credential expired | Tool gets a real `401` from the upstream API; looks identical to wrong credentials |
| Proxy up, shim missing for new tool version | Tool gets a `200` from shim but misreads the response shape; fails with a parsing error unrelated to auth |
| CA rotated, container not rebuilt | `SSL_ERROR_RX_RECORD_TOO_LONG` or trust failure; no indication the CA changed |

None of these failure modes produce an actionable error message pointing to the proxy.

---

## 8. Alternative UX Models Worth Evaluating

The plan's comparison table lists alternatives but dismisses them without comparing DX cost:

- **Credential-helper socket mounted into container**: tools like `gh`, `git`, and `gcloud` already support external credential helpers via config. A Unix socket mounted into the container (not exposed to the network) can vend short-lived tokens on demand with zero TLS interception. No CA management, no shim layer, no Dockerfile changes.
- **`docker run` wrapper / CLI shim**: a thin wrapper that injects `HTTP_PROXY`, a temp CA, and a dummy credential file at container start time — all ephemeral, no YAML authoring required. Developer UX: `agent-run gh pr list`.
- **Transparent proxy via `iptables` redirect**: no `HTTP_PROXY` env var needed, no container-side configuration. The interception is invisible to the tool. Eliminates one entire configuration surface.

The MITM approach should be compared against the socket model on DX metrics, not just on "credential in container?" isolation.

---

## 9. Documentation Burden

Each supported tool requires:
- A shim YAML snippet
- A dummy credential file format description
- A per-runtime CA injection snippet
- Troubleshooting steps for that tool's specific local validation behavior

For five tools across four runtimes that is 20+ distinct documentation sections before the first user successfully completes a request. This is not sustainable without a dedicated DX writer and automated example testing.

---

## Summary Scorecard

| Dimension | Score | Key issue |
|---|---|---|
| Setup complexity | 2/10 | 8-step manual process; four new config formats |
| Debugging | 3/10 | TLS errors opaque; no shim trace logging defined |
| Error attribution | 2/10 | Proxy/credential/tool failures indistinguishable |
| Config surface | 3/10 | No schema, no validation, no CLI to check config |
| Shim maintenance | 2/10 | No ownership model, no versioning, no registry |
| Container requirements | 4/10 | Dockerfile changes required; CA rotation is painful |
| Failure modes | 3/10 | Most failures are silent or misleading |
| Documentation | 2/10 | Unsustainable per-tool burden |

**Overall:** The security model is sound. The UX is not ready for developer self-service. The research plan should add Phase 0: a DX spike comparing the socket-based credential helper model against the MITM approach on setup step count and time-to-first-success before investing five weeks in the MITM prototype.
