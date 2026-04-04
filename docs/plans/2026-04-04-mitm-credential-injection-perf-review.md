# Adversarial Performance Review: MITM Credential Injection Plan

**Date:** 2026-04-04
**Reviewer role:** Senior performance engineer
**Target document:** `2026-04-04-mitm-credential-injection-research.md`

---

## Summary Verdict

The plan mentions performance in one bullet point under Key Risks (#5) and one row of Phase 4 integration testing. This is insufficient. TLS termination on every inspected connection is architecturally expensive. The costs compound across every layer and are likely to be **unacceptable for bulk workloads without a mitigation strategy designed upfront, not discovered in Phase 4**.

---

## 1. TLS Termination Overhead — Per-Connection Cost

**Baseline (current spnego-proxy):** CONNECT tunnel. The proxy does a TCP handshake to the upstream proxy, sends the CONNECT request, injects a SPNEGO header, then switches to raw `io.Copy` using a pooled 32 KiB buffer. After tunnel establishment the proxy is transparent — TLS occurs end-to-end between client and destination. Zero crypto work per request after the first.

**MITM mode:** Every inspected connection requires:

1. Client TLS handshake termination (~1–3 ms, ECDSA P-256)
2. Dynamic certificate generation and signing (see §2)
3. HTTP request parsing into memory (`bufio.Reader`, full header scan)
4. Header mutation and credential injection
5. New outbound TLS handshake to the real destination (~5–15 ms depending on RTT and cipher)

**Estimated per-request overhead (same host, no caching):** 6–20 ms added latency on top of network RTT. For interactive tools like `gh pr list` (typically 1–3 API calls), this is perceptible. For `gcloud builds log --stream` the initial latency spike delays the first byte of output.

**Connection reuse:** The existing proxy does not maintain outbound persistent connections — each CONNECT tunnel is a new TCP+TLS connection to the upstream proxy. The MITM design inherits this unless a connection pool is added. Without pooling, every HTTPS request to `api.github.com` pays the full outbound TLS handshake cost. This is the **largest single performance risk**.

---

## 2. Certificate Generation and Caching — Unquantified and Unaddressed

The plan does not mention a certificate cache. Generating an RSA-2048 key takes ~5–15 ms on modern hardware; ECDSA P-256 is ~0.5–1 ms. Without caching, every new connection to a distinct destination host requires signing a fresh leaf certificate.

**A workload like `npm install` with 200 packages from `registry.npmjs.org` will:**
- Potentially open 6–20 parallel connections (npm's default concurrency)
- Without caching: 6–20 concurrent certificate generations, each ~1 ms (ECDSA)
- With caching keyed on hostname: only 1 generation, then 19 cache hits

**Recommended design (missing from the plan):**

- `sync.Map` or LRU cache keyed on `hostname` → `*tls.Certificate`
- TTL matching the CA certificate validity (e.g., 24 h)
- Estimated memory per cached cert: ~4–8 KB (public key + chain + private key)
- 500 distinct destinations × 8 KB = ~4 MB — acceptable
- **The plan must specify this cache; without it the prototype will appear to work but degrade under any realistic workload.**

---

## 3. HTTP/2 Multiplexing — Complexity Drastically Underestimated

The plan's TLS inspection engine is described as if HTTP/1.1 is the only concern. Modern `gh`, `gcloud`, and `npm` clients negotiate HTTP/2 over TLS (via ALPN). If the proxy terminates TLS and presents a generated certificate, the client will attempt HTTP/2 ALPN negotiation. The proxy must either:

- **Speak HTTP/2 to the client and HTTP/2 to the destination** (full H2 proxy): implement flow control, stream multiplexing, HPACK header compression, SETTINGS frames. Estimated implementation effort: weeks; existing Go `golang.org/x/net/http2` helps but requires a net.Listener wrapper. Memory cost: per-stream buffers (~64 KB initial window) × number of concurrent streams.
- **Downgrade to HTTP/1.1 on both sides** (force `h1` in ALPN): breaks HTTP/2 semantics, loses multiplexing, and may break tools that require H2 (rare but possible with gRPC-based GCP SDKs).
- **Selective downgrade for inspected hosts only**: inconsistent behavior that will cause hard-to-diagnose failures.

The plan has no discussion of ALPN negotiation. This is a **critical gap**.

---

## 4. Bulk Workload Throughput Impact

| Workload | Requests | Current proxy overhead | MITM overhead (est.) |
|---|---|---|---|
| `npm install` (medium project) | 50–200 parallel HTTPS | ~0 ms/req (tunnel) | 2–5 ms/req + 1 cert gen |
| `pip install` (single package) | 3–10 HTTPS | ~0 ms/req | 5–15 ms/req |
| `gcloud storage cp` (large file) | 1 resumable upload HTTPS | ~0 ms/req | 1 TLS round-trip overhead; sustained throughput unchanged |
| `gh pr list` | 1–3 HTTPS | ~0 ms/req | 6–20 ms total |

For `npm install` with HTTP/2, the client may multiplex 6 requests per connection. If the proxy forces HTTP/1.1, npm opens more connections, increasing certificate signing and TLS handshake work proportionally. A 200-package install that takes 30 s today could take 40–50 s.

---

## 5. Memory Pressure Per Connection

The current proxy uses a pooled 32 KiB copy buffer per tunneled connection (see `copyBufPool` in `main.go`). In MITM mode each inspected connection requires:

- Two `bufio.Reader` instances (client-side and server-side): 4 KB each = 8 KB
- TLS record buffers (client TLS): ~32 KB read buffer + ~16 KB write buffer
- TLS record buffers (outbound TLS): same
- HTTP request/response headers in memory: up to 8 KB (Go's default limit)
- Total per inspected connection: ~80–100 KB

At 500 concurrent connections (plausible in a container farm running parallel CI jobs): **40–50 MB additional RSS** beyond the current proxy's footprint. This is manageable but should be capacity-planned. It is not mentioned in the plan.

---

## 6. OAuth Token Refresh — Thundering Herd Not Addressed

The `OAuthRefreshProvider` in the plan has no mention of deduplication. When 20 requests to `*.googleapis.com` arrive simultaneously with an expired token, each goroutine independently calls the OAuth2 token endpoint. This:

- Issues 20 refresh requests to `oauth2.googleapis.com`
- May trigger rate limiting (Google's token endpoint has per-client quotas)
- Causes 20 concurrent outbound TLS handshakes to the token endpoint

**Required mitigation (not in plan):** `singleflight.Group` per credential key, so concurrent refreshes collapse to one network call. The remaining 19 goroutines block and receive the same token. This is standard practice but the plan does not prescribe it.

---

## 7. Latency for Interactive Tools

`gh` CLI users expect sub-second responses for `gh pr list` or `gh issue view`. Current spnego-proxy adds ~1–2 ms (TCP to upstream + header injection). MITM adds 6–20 ms. On a corporate network with a proxy chain (client → MITM proxy → upstream SPNEGO proxy → destination), the TLS handshake RTT doubles.

**Streaming responses** (`gcloud builds log --stream`, `gcloud run services logs --follow`) use chunked HTTP. The MITM proxy must buffer-and-forward each chunk. If the proxy uses `http.ResponseWriter` with flushing, this works but adds per-chunk syscall overhead. The plan does not address streaming semantics.

---

## 8. Baseline vs. MITM Performance Delta

| Metric | Current spnego-proxy | MITM mode (estimated) |
|---|---|---|
| Added latency (first request) | 1–2 ms | 8–25 ms |
| Added latency (reused connection) | ~0 ms | 2–5 ms (TLS resumption) |
| Memory per connection | ~32 KB | ~80–100 KB |
| CPU per connection | Near zero (copy loop) | TLS crypto + HTTP parse |
| `npm install` 200 pkgs | baseline | +15–40 s (worst case, no H2) |
| Streaming | Transparent | Requires explicit flush loop |

---

## Required Additions to the Plan Before Phase 3

1. **Certificate cache specification** — LRU, TTL, max size, eviction policy.
2. **HTTP/2 strategy decision** — speak H2 or force H1; document the trade-off.
3. **Connection pooling to destinations** — without it every request pays full TLS handshake cost.
4. **singleflight for token refresh** — required before any load test.
5. **Phase 4 must include throughput benchmarks**, not just "latency overhead": measure `npm install` wall time and `gcloud storage cp` throughput with and without the proxy.
6. **Memory budget** — state the target RSS ceiling and the concurrent connection assumption.
