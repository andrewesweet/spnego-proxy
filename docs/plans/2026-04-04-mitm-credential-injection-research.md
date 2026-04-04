# MITM Credential Injection for Containerized AI Agents

**Date:** 2026-04-04
**Status:** Research Plan (Draft)
**Author:** Research spike

## Problem Statement

AI coding assistants increasingly run in isolated containers or microVMs to limit
blast radius. Yet these agents still need credentials to do useful work:

- A fine-grained PAT for `gh` CLI (GitHub API)
- An interactive OAuth login via coding assistants to the GitHub Copilot API
- A PAT for `jira-cli` against JIRA Data Center
- OAuth via `gcloud auth login --update-adc` for GCP operations and Vertex AI

Today, credentials are typically mounted or injected directly into the container,
which undermines the isolation guarantee — a compromised agent has the raw credential
and can exfiltrate or misuse it.

## Proposed Solution

Run a **MITM forward proxy with TLS inspection** on the host that:

1. **Allowlists destinations** — the container can only reach approved hosts
2. **Injects authentication headers** — credentials never enter the container
3. **Intercepts credential verification calls** — tools like `gh`, `gcloud`, etc.
   verify credentials on startup; the proxy returns synthetic success responses so
   tools believe they have valid credentials when they actually have dummy/benign ones

This extends spnego-proxy's existing architecture (SPNEGO token injection into
proxied traffic) to a general-purpose credential injection proxy.

## Architecture Overview

```
┌─────────────────────────────────┐
│         Container / microVM     │
│                                 │
│  ┌─────┐  ┌────────┐  ┌─────┐  │
│  │ gh  │  │ gcloud │  │ npm │  │
│  └──┬──┘  └───┬────┘  └──┬──┘  │
│     │         │          │      │
│     ▼         ▼          ▼      │
│  HTTP_PROXY / HTTPS_PROXY       │
│  (points to host proxy)        │
└────────────┬────────────────────┘
             │
             ▼
┌────────────────────────────────────────┐
│  Host: MITM Credential Injection Proxy │
│                                        │
│  ┌──────────┐  ┌───────────────────┐   │
│  │ Allowlist │  │ Credential Store  │   │
│  │ Policy    │  │ (PATs, OAuth, etc)│   │
│  └────┬─────┘  └────────┬──────────┘   │
│       │                 │              │
│  ┌────▼─────────────────▼──────────┐   │
│  │  TLS Inspection Engine          │   │
│  │  - Terminate client TLS         │   │
│  │  - Inspect/modify HTTP request  │   │
│  │  - Inject Authorization headers │   │
│  │  - Re-encrypt to destination    │   │
│  └────┬────────────────────────────┘   │
│       │                                │
│  ┌────▼────────────────────────────┐   │
│  │  Credential Shim Layer          │   │
│  │  - Intercept auth verification  │   │
│  │  - Return synthetic responses   │   │
│  │  - Per-tool response templates  │   │
│  └─────────────────────────────────┘   │
└────────────┬───────────────────────────┘
             │
             ▼
        Internet / Corporate Network
```

## Research Plan

### Phase 1: Literature Review & Prior Art

| # | Topic | Questions to Answer |
|---|-------|-------------------|
| 1a | **Existing MITM proxy credential injection** | Do mitmproxy, Squid ssl-bump, or AITM frameworks support header injection post-TLS-termination? What configuration is needed? What are the operational costs? |
| 1b | **Container credential isolation patterns** | How do Devcontainers, GitHub Codespaces, Gitpod, Coder handle credential forwarding? (SSH agent forwarding, VS Code credential provider API, socket mounting, etc.) What are the trade-offs? |
| 1c | **Tool-specific auth flows** | For each target tool: credential format, storage location, online vs. offline verification, token refresh mechanics. Targets: `gh`, `gcloud`, `jira-cli`, `npm`, `pip` |
| 1d | **Dynamic CA injection in containers** | Patterns for injecting a MITM CA into container trust stores. Go, Node, Python, Java, and system stores all differ. What's the least-friction approach? |
| 1e | **Security model analysis** | Threat model implications: the host proxy becomes a high-value target. Compare to credential-helper sockets, VS Code credential provider, short-lived tokens, etc. |

### Phase 2: Spike — Tool Credential Verification Behavior

Empirically determine, for each tool, what happens when credentials are dummy/missing
and a proxy intercepts all traffic:

| Tool | Key Questions |
|------|-------------|
| `gh` | Does it validate PAT before use? What endpoint? (`api.github.com/user`?) Can we fake the response? Does it check token format locally? |
| `gcloud` | Does it verify ADC locally (JWT expiry) or via network (tokeninfo endpoint)? What about `gcloud auth print-access-token`? Can we intercept the OAuth2 token refresh at `oauth2.googleapis.com/token`? |
| `jira-cli` | PAT-based — lazy or eager verification? What endpoint? |
| `npm` | Registry auth tokens — verified before `install` or sent inline? |
| `pip` | Same as npm — does it pre-verify credentials? |

**Method:** Source code review of each tool's auth module, plus empirical testing with
mitmproxy capturing all traffic from a container with dummy credentials.

### Phase 3: Spike — Prototype Implementation

Build a minimal extension to spnego-proxy:

#### 3a. TLS Interception for Selected Destinations

For allowlisted hosts, the proxy:
- Terminates client TLS using a generated certificate signed by a local CA
- Reads the plaintext HTTP request
- Injects/replaces `Authorization` headers per destination rules
- Opens a new TLS connection to the real destination
- Forwards the modified request

For non-allowlisted hosts: passthrough (CONNECT tunnel) or deny.

#### 3b. Credential Provider Abstraction

Generalize beyond SPNEGO:

```go
// CredentialProvider returns credentials for a given destination.
type CredentialProvider interface {
    // GetCredential returns the header name and value for the destination.
    // Returns empty strings if no credential is configured.
    GetCredential(ctx context.Context, host string) (headerName, headerValue string, err error)
}
```

Implementations:
- `StaticTokenProvider` — PAT, API key (gh, jira-cli, npm)
- `OAuthRefreshProvider` — refreshes OAuth tokens on demand (gcloud ADC)
- `SPNEGOProvider` — existing Kerberos authentication (refactored)

#### 3c. Policy Engine

Per-destination rules controlling proxy behavior:

```yaml
rules:
  - hosts: ["api.github.com"]
    action: inspect-and-inject
    credential: github-pat
    
  - hosts: ["*.googleapis.com", "oauth2.googleapis.com"]
    action: inspect-and-inject
    credential: gcloud-oauth
    
  - hosts: ["jira.corp.example.com"]
    action: inspect-and-inject
    credential: jira-pat
    
  - hosts: ["registry.npmjs.org"]
    action: inspect-and-inject
    credential: npm-token
    
  - hosts: ["*"]
    action: deny  # or passthrough
```

#### 3d. Credential Shim Layer

For tools that verify credentials via network calls, intercept specific
request patterns and return synthetic success responses:

```yaml
shims:
  - match:
      host: "api.github.com"
      path: "/user"
      method: GET
    response:
      status: 200
      body: '{"login":"container-agent","id":0}'
      
  - match:
      host: "oauth2.googleapis.com"
      path: "/token"
      method: POST
    action: refresh-and-respond  # proxy refreshes token on host, returns it
```

### Phase 4: Integration Testing

- Run `gh pr list`, `gcloud projects list`, `jira issue list`, `npm install`
  through the proxy from a container with no real credentials
- Measure: what works, what breaks, what additional shims are needed
- Performance: latency overhead of TLS interception
- Security: verify credentials never appear in container filesystem or env

## Feasibility Assessment (Preliminary)

| Category | Confidence | Notes |
|----------|-----------|-------|
| PAT-based tools (gh, jira-cli, npm) | **High** | Static `Authorization: Bearer/token <PAT>` header injection. Well-understood. |
| OAuth-based tools (gcloud) | **Medium** | Token refresh is more complex. Proxy must intercept refresh calls and return valid tokens obtained by the host. |
| TLS interception | **High** | Well-understood technology (mitmproxy, Squid ssl-bump). Challenge is CA trust store injection per runtime. |
| Credential shims | **Medium** | Each tool has idiosyncratic startup checks. Must be empirically mapped. |
| Certificate pinning | **Low risk** | Most CLI tools use system trust stores. Some SDKs pin (rare for dev tools). |

## Key Risks

1. **Tool-specific complexity.** Each tool may need custom shim responses. This is
   a maintenance burden that grows with each supported tool.

2. **OAuth token lifecycle.** Short-lived tokens need refresh. The proxy must manage
   token lifecycle on behalf of the container without exposing refresh tokens.

3. **Local-only validation.** If a tool checks credential format locally (e.g., JWT
   expiry, file schema validation) without a network call, we can't intercept it.
   We'd need to provide a convincing dummy credential file.

4. **Security of the proxy itself.** The proxy holds all credentials and has TLS
   interception capability. It becomes the highest-value target on the host. Must
   be hardened accordingly.

5. **Performance.** TLS termination + re-encryption adds latency. For bulk
   operations (npm install with many packages), this could be noticeable.

6. **Certificate trust store fragmentation.** Go uses system certs, Node can use
   `NODE_EXTRA_CA_CERTS`, Python uses `certifi` or `REQUESTS_CA_BUNDLE`, Java has
   its own keystore. Each container image may need different CA injection.

## Deliverables

| Phase | Output | Timeline |
|-------|--------|----------|
| 1 | Research document: prior art, per-tool auth flows, threat model | Week 1-2 |
| 2 | Tool behavior matrix: what needs faking, what's interceptable | Week 2-3 |
| 3 | Working prototype on spnego-proxy branch | Week 3-5 |
| 4 | Integration test results, go/no-go recommendation | Week 5-6 |

## Comparison with Alternatives

| Approach | Credential in container? | Tool compatibility | Complexity |
|----------|------------------------|-------------------|-----------|
| **Mount credentials directly** | Yes (full exposure) | Perfect | Low |
| **SSH agent forwarding** | No (socket only) | SSH/Git only | Low |
| **VS Code credential provider** | Partial (token in memory) | VS Code extensions only | Medium |
| **Short-lived tokens via sidecar** | Yes (time-limited) | Good | Medium |
| **MITM proxy injection (this proposal)** | No | Broad (any HTTP tool) | High |
| **Credential helper socket** | No (socket only) | Tool-specific | Medium |

The MITM approach offers the broadest tool compatibility with the strongest
isolation guarantee, at the cost of higher implementation complexity and the
need for per-tool credential shims.
