# Adversarial Security Review: MITM Credential Injection Proxy

**Date:** 2026-04-04  
**Reviewer:** Security Engineering (adversarial review)  
**Subject:** `docs/plans/2026-04-04-mitm-credential-injection-research.md`  
**Verdict:** Do Not Proceed Without Addressing Sections 1, 3, 5, and 6

---

## 1. The Proxy Becomes a Tier-0 Asset — The Plan Underweights This

The existing threat model (P1, P3, P4, P5) was written for a narrow SPNEGO injector. The proposed design consolidates *every* credential the host owns — GitHub PAT, GCP OAuth refresh token, JIRA PAT, npm token — into a single process and its on-disk config. This is not a modest expansion of attack surface; it is a qualitative step change.

**What the plan says:** "The proxy holds all credentials and has TLS interception capability. It becomes the highest-value target on the host. Must be hardened accordingly." (Risk #4)

**What the plan does not say:** How. There is no hardening specification, no secrets management design, and no isolation model. "Harden accordingly" is not a control.

---

## 2. Credential Storage: The Plan Has No Answer

The YAML policy file contains credentials inline (`credential: github-pat` referencing a store never specified). Questions the plan does not answer:

- **At rest:** Are credentials stored in a file? What permissions? The existing proxy already has GAP-003 (password in memory, Go string immutability prevents zeroing). Adding five more credential types without addressing this compounds a known gap.
- **In memory:** Go's GC means tokens sit on the heap indefinitely until collected. A container escape or local privilege escalation that enables `/proc/<pid>/mem` reads recovers every token. This is not hypothetical on Linux hosts running containers.
- **Credential store:** No KMS, HSM, or OS keychain integration is mentioned. `StaticTokenProvider` holding a raw PAT in a config file parsed at startup means the credential is in the process heap for its entire lifetime.

**Attack scenario:** An AI agent achieves local code execution on the host (e.g., via a compromised build step). It reads `/proc/<proxy_pid>/mem` or triggers a core dump. All tokens for all services are recovered in a single operation with no audit trail.

---

## 3. TLS Interception: CA Key Is the Crown Jewel

The plan assumes the proxy generates a local CA and issues per-connection certificates. This is standard MITM proxy design, but the plan does not address:

- **CA key storage:** Where does the private key live? On-disk in plaintext? The blast radius of compromising this key is total: any process on the host can present a certificate the container trusts. Credential extraction no longer requires proxy access.
- **CA key rotation:** Never mentioned. A static CA key means a one-time compromise has permanent effect until the container image is rebuilt.
- **CA injection into containers:** The plan acknowledges trust store fragmentation (Go, Node, Python, Java). Injecting a CA into a container trust store at startup requires the container to accept the CA unconditionally, defeating certificate transparency and any future pinning.

**Attack scenario:** The CA private key is stored at a predictable path (e.g., `~/.config/spnego-proxy/ca.key`). A malicious package in a build step reads and exfiltrates it. The attacker can now perform real MITM attacks on the container from *outside the host* by ARP-spoofing at the network layer, since the container trusts their CA.

---

## 4. Credential Shim: The Proxy Lies — This Is Exploitable

The shim layer returns synthetic responses to fool tools into believing they have valid credentials. This inverts the security model: the proxy is no longer a transparent conduit but an active participant in deceiving clients.

**Crafted request leakage:** If the shim matches on `path: "/user"` and returns a synthetic 200, what happens for `path: "/user/emails"` or `path: "/user/keys"`? If those fall through to real injection and the container controls the path, the container can probe the proxy's shim coverage to discover which endpoints are intercepted and which return real data. This is an oracle for understanding the credential's actual privilege scope.

**Error message leakage:** If the credential provider fails (token expired, KMS unreachable), what does the proxy return? If it proxies through an upstream 401 response that includes `WWW-Authenticate` headers or error details, those headers may contain service-specific information about the credential type or realm — leaking the real auth scheme to the container even when injection fails.

**Refresh token exposure:** The `refresh-and-respond` shim action (gcloud OAuth) means the proxy sends the *real* access token back to the container in the response body. This is exactly the credential exposure the design is supposed to prevent. The plan treats this as acceptable but does not bound the token lifetime, scope, or whether the container can cache and reuse it.

---

## 5. Allowlist Bypass: Four Vectors Not Addressed

The plan's allowlist is the primary security control. It has the following bypass paths:

1. **DNS rebinding:** The container resolves `api.github.com` to an attacker-controlled IP before the request. The proxy allowlists the hostname; if it resolves DNS at policy check time rather than enforcing the allowlist at TCP connection time, DNS rebinding defeats it entirely. The plan does not specify when DNS resolution occurs.

2. **Host header vs. SNI mismatch:** For TLS inspection, the proxy must choose between trusting the CONNECT hostname or the inner `Host` header. A container can CONNECT to `api.github.com:443` (allowlisted) but send `Host: internal.corp.example.com` in the decrypted request. If the proxy injects credentials based on the CONNECT hostname rather than the inner Host, it may inject GitHub credentials into a request destined for an internal service.

3. **Wildcard rule scope creep:** The rule `*.googleapis.com` matches `evil.googleapis.com` if an attacker can register a subdomain or if a typosquatted domain resolves to a controlled server. Wildcard host matching in credential injection rules is high-risk.

4. **CONNECT to IP addresses:** The existing spnego-proxy already has GAP-005 (open CONNECT ports by default). If the allowlist checks hostnames only, a container can CONNECT to `142.250.80.46:443` (a Google IP) and bypass hostname-based rules entirely, or reach unintended destinations.

---

## 6. Credential Isolation: None Between Containers

The plan assumes a single proxy instance serving multiple containers. There is no credential isolation model described. All containers that can reach the proxy get all credentials injected based solely on destination host.

**Lateral movement scenario:** Container A is a documentation tool that needs read access to GitHub. Container B is a code execution agent with higher risk. Both reach the same proxy. Both get the same GitHub PAT injected when they hit `api.github.com`. If container B is compromised, the attacker pivots through it to make arbitrary GitHub API calls at the PAT's full privilege level — indistinguishable from container A's legitimate traffic.

The existing threat model (T-E-P-005-001, T-S-EI-001-001) already flags "any localhost process gets authenticated proxy access" as P1. This proposal expands that to five credential types with no per-container scoping.

---

## 7. Audit Gap: Attribution Is Impossible

The plan has no attribution model. When the proxy injects a credential and makes a request to `api.github.com`, the audit log shows a proxy request — it does not show *which container* initiated it. GitHub's audit log shows the PAT being used; the proxy log shows a connection from a local socket. Neither is sufficient to reconstruct "container X made call Y at time Z."

This matters for incident response: if the PAT appears in GitHub's abuse detection, there is no forensic path from that event back to the specific container or agent invocation that caused it.

---

## 8. Comparison to Alternatives: The Plan Oversells MITM

The plan's comparison table marks "MITM proxy injection" as "No" for credential-in-container and "Broad" for tool compatibility. Both are partially misleading:

- **Credential-in-container:** The `refresh-and-respond` shim returns access tokens *to* the container. The container has the token in memory. This is not "No."
- **Short-lived tokens via sidecar:** Marked "Yes (time-limited)" for credential-in-container, but a 60-second token with a narrow scope is dramatically lower risk than a long-lived PAT injected invisibly. The plan does not compare worst-case blast radius.
- **Credential helper socket:** The plan rates this "Medium" complexity and "No" for credential-in-container. For tools that support credential helpers natively (`gh`, `gcloud`, `git`), this approach is strictly safer: the credential never leaves the helper process, there is no TLS interception CA to compromise, and the attack surface is a Unix socket rather than a TCP listener handling arbitrary HTTPS traffic. The plan should justify why credential helpers are insufficient before proposing MITM.

---

## 9. Supply Chain and Implementation Risk

`crypto/tls` certificate generation is mature, but the proposed on-the-fly CA signing introduces implementation complexity: key generation, certificate templating, serial number management, and validity period selection. Each is a potential source of implementation bugs (weak key size, serial collision, overly broad Subject Alternative Names). The existing codebase has no TLS certificate generation code; this is net-new cryptographic implementation.

The existing supply chain posture (GAP supply chain: compliant, minimal deps) would be degraded by adding a MITM TLS library or implementing custom cert generation.

---

## Summary of Required Mitigations Before Proceeding

| # | Gap | Severity |
|---|-----|----------|
| M1 | Define credential storage with KMS/keychain integration or at minimum encrypted-at-rest store | Critical |
| M2 | Specify CA key protection (HSM or OS keychain), rotation policy, and blast radius analysis | Critical |
| M3 | Add per-container credential scoping or separate proxy instances per trust level | High |
| M4 | Specify DNS resolution timing in allowlist enforcement; prohibit CONNECT-to-IP for allowlisted credential injection | High |
| M5 | Bound token lifetime for `refresh-and-respond` shims; treat returned tokens as credential exposure | High |
| M6 | Add request attribution (container ID → proxy log → upstream request correlation) | Medium |
| M7 | Evaluate credential helper socket for natively-supported tools before expanding MITM scope | Medium |
| M8 | Define Host header vs. SNI authority for credential injection decisions | Medium |
