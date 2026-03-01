# Competitor Analysis: spnego-proxy vs. cntlm vs. px-proxy

**Date:** 2026-03-01

## Executive Summary

spnego-proxy, cntlm, and px-proxy occupy the same niche: localhost HTTP proxies
that inject corporate authentication credentials on behalf of CLI tools and
applications that cannot perform NTLM or Kerberos authentication themselves.
They differ significantly in protocol focus, platform strengths, configuration
philosophy, and maintenance status.

| Dimension | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| **Language** | Go 1.25 | C | Python 3 (+ libcurl) |
| **Primary auth** | SPNEGO/Kerberos | NTLM family | NTLM + Kerberos (via libcurl) |
| **macOS native SSO** | Yes (GSS-API/Heimdal) | No | No (requires username + password) |
| **Windows native SSO** | No | SSPI (versat fork) | Yes (SSPI, flagship) |
| **SOCKS5** | No | Yes | No |
| **PAC/WPAD** | No | Partial (versat fork) | Yes (QuickJS engine) |
| **Config file** | CLI-only | INI-like (`cntlm.conf`) | INI + env + dotenv + CLI |
| **Structured logging** | JSON (slog) | Syslog (unstructured) | Custom text format |
| **RFC compliance** | Extensive (9110, 9112, 9209, 7239) | Minimal | Minimal |
| **Maintenance** | Active (2026) | Dormant (last release 2018) | Active (2025) |
| **Binary size / deps** | Single static binary | Single static binary | Python + libcurl + many deps |
| **Connection limits** | Configurable (default 512) | Unlimited | Workers × threads (default 64) |
| **Circuit breaker** | Yes | No | No |

---

## Detailed Feature Comparison

### Authentication

| Feature | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| SPNEGO/Negotiate | **Primary** | Partial (versat fork) | Via libcurl |
| Kerberos (native GSS-API) | macOS only | versat fork only | Via libcurl |
| NTLM / NTLMv2 | No | **Primary** | Via libcurl |
| Basic | No | NTLM-to-Basic translation | Via libcurl |
| Digest | No | No | Via libcurl |
| SSPI (Windows) | No | versat fork | **Yes (flagship)** |
| Password-based Kerberos | All platforms (gokrb5) | No | Via keyring/env |
| Keytab support | Yes (gokrb5) | No | No |
| Client-side auth | No | No | Yes (since v0.9.0) |
| Auth auto-detection | No | **Yes (`-M` flag)** | Via libcurl |
| Circuit breaker (lockout protection) | **Yes** | No | No |

### Proxy Capabilities

| Feature | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| HTTP forward proxy | Yes | Yes | Yes |
| HTTPS CONNECT tunneling | Yes | Yes | Yes |
| CONNECT port restriction | **Yes (default: 443 only)** | No | No |
| SOCKS5 | No | **Yes** | No |
| TCP port forwarding | No | **Yes (SSH `-L` style)** | No |
| Standalone/direct mode | No | **Yes** | Yes (noproxy) |
| PAC file support | No | Partial (versat fork) | **Yes (QuickJS)** |
| WPAD auto-discovery | No | No | **Yes (Windows)** |
| Noproxy bypass list | No | **Yes (wildcards)** | **Yes (IP/CIDR/domain)** |
| Multiple upstream proxies | No | **Yes (failover)** | **Yes (failover + PAC)** |
| NTLM-to-Basic multi-user | No | **Yes (unique)** | No |

### Standards Compliance & Headers

| Feature | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| Via header (RFC 9110 §7.6.3) | **Yes** | Manual only (`-r`) | No |
| Loop detection | **Yes (Via pseudonym)** | No | No |
| Max-Forwards (TRACE/OPTIONS) | **Yes** | No | No |
| Hop-by-hop header sanitization | **Yes** | No | No |
| Proxy-Status (RFC 9209) | **Yes** | No | No |
| Forwarded header (RFC 7239) | **Yes (optional)** | No | No |
| TE/CL conflict resolution (RFC 9112) | **Yes** | No | No |
| Content-Length validation | **Yes** | No | No |

### Operations & Security

| Feature | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| Structured JSON logging | **Yes (slog)** | No (syslog) | No (custom text) |
| IP allowlist | Yes (CIDR) | Yes (CIDR ACL) | Yes (IP/wildcard/range/CIDR) |
| Graceful shutdown + drain | **Yes** | No | No |
| Connection limit | **Yes (configurable)** | No | Workers × threads |
| Credential memory scrubbing | **Yes (CWE-316)** | Yes (after hashing) | Delegated to keyring |
| Config file | No (CLI-only) | Yes (INI-like) | Yes (INI + env + dotenv) |
| Daemon/service mode | No | Yes (Unix daemon + Windows service) | Yes (Windows registry + WinSW) |
| Connectivity test flag | No | `-M` (auth detection) | `--test=URL` |
| Password hash generation | No | **Yes (`-H` flag)** | N/A |
| Upstream TLS | **Yes (configurable)** | No | Via libcurl |
| Docker image | No | Community images | **Official image** |

### Platform & Distribution

| Feature | spnego-proxy | cntlm | px-proxy |
|---|---|---|---|
| macOS (native Kerberos) | **Yes (GSS-API)** | No | No |
| macOS (password-based) | Yes (gokrb5) | Yes | Yes |
| Linux | Yes (gokrb5) | Yes | Yes |
| Windows (native SSO) | No | SSPI (versat fork) | **Yes (SSPI)** |
| Windows (password-based) | Yes (gokrb5) | Yes | Yes |
| Homebrew | No | Yes | No |
| pip / conda | N/A | N/A | **Yes** |
| Docker | No | Community | **Official** |
| Single binary | **Yes** | Yes | No (Python + deps) |
| Resource footprint | Low (~10 MB) | **Very low (~3 MB)** | Higher (Python runtime) |

---

## Recommended Features and UX Enhancements

Ordered by priority. Each item includes a justification grounded in the
competitive analysis.

### 1. Configuration file support

**What:** Load settings from a TOML or INI file in addition to CLI flags,
with CLI flags taking precedence.

**Justification:** Both cntlm (`cntlm.conf`) and px-proxy (`px.ini` + env
vars + dotenv) offer configuration file support. spnego-proxy currently requires
all settings via CLI flags, which makes invocations verbose and forces users to
manage wrapper scripts or shell aliases to avoid retyping 5-10 flags. A config
file reduces day-to-day friction and aligns with user expectations set by both
competitors. This is the single most impactful UX improvement available because
it touches every user session.

### 2. Noproxy bypass list

**What:** A flag (e.g., `-noproxy`) accepting a comma-separated list of
host patterns, IP ranges, or CIDR blocks for which spnego-proxy connects
directly to the destination rather than through the upstream proxy.

**Justification:** Both competitors offer this (cntlm's `NoProxy`, px-proxy's
`--noproxy`). Corporate environments commonly have intranet hosts, internal
registries, and `localhost` services that must not traverse the upstream proxy.
Without noproxy support, users must configure per-application bypass rules or
run a second proxy, both of which are error-prone. This is table-stakes
functionality for a corporate proxy tool.

### 3. Multiple upstream proxy support with failover

**What:** Accept multiple `-proxy host:port` values. On connection failure,
try the next upstream in round-robin order. Optionally mark failed upstreams as
unhealthy for a configurable cooldown period.

**Justification:** Both cntlm (repeatable `Proxy` directive with circular
failover) and px-proxy (comma-separated `--proxy` with PAC-based selection)
support multiple upstream proxies. Corporate environments frequently have
redundant proxy clusters, and single-proxy configurations create a single point
of failure. The existing circuit breaker infrastructure provides a natural
foundation for per-upstream health tracking.

### 4. SOCKS5 proxy listener

**What:** Add a SOCKS5 listener (e.g., `-socks5 [addr:]port`) that accepts
SOCKS5 CONNECT requests and forwards them through the authenticated upstream
HTTP proxy.

**Justification:** cntlm offers built-in SOCKS5 (`-O` flag) and it is one of
its most cited features. Many tools (SSH, Git over SSH, database clients,
`tsocks`/`proxychains`) speak SOCKS5 but not HTTP CONNECT. Without SOCKS5,
users need a separate SOCKS-to-HTTP adapter, adding operational complexity.
Go's `net` package makes SOCKS5 protocol handling straightforward to implement.

### 5. `--test` / `--check` connectivity verification flag

**What:** A `--test URL` flag that performs a single proxied request through
the full authentication path and reports success or failure with diagnostics,
then exits.

**Justification:** px-proxy's `--test=URL` and cntlm's `-M` (auth
auto-detection) both provide quick validation that the proxy chain works.
spnego-proxy currently requires users to start the proxy, configure a client,
make a request, and interpret logs to verify connectivity. A dedicated test mode
collapses this to a single command, dramatically improving first-run experience
and troubleshooting. This is especially valuable because Kerberos environments
have many failure modes (expired tickets, wrong SPN, clock skew, missing
keytab).

### 6. Daemon / background mode with PID file

**What:** A `-daemon` flag that forks to background and writes a PID file
(configurable via `-pidfile`). Complement with `-quit` and `-restart` management
commands.

**Justification:** cntlm daemonizes by default (with `-f` for foreground).
px-proxy offers `--install`/`--uninstall` (Windows), `--quit`, and `--restart`.
spnego-proxy currently runs only in the foreground, requiring users to manage
backgrounding via shell `&`, `nohup`, `tmux`, `launchd`, or `systemd` manually.
While advanced users prefer systemd unit files, a built-in daemon mode with PID
management reduces friction for casual users and scripted deployments.

### 7. Noproxy environment variable integration

**What:** Respect `NO_PROXY` / `no_proxy` and `HTTP_PROXY` / `HTTPS_PROXY`
environment variables as defaults (overridable by CLI flags).

**Justification:** px-proxy reads standard proxy environment variables
automatically. These variables are a de facto standard across curl, wget, Go's
`net/http`, Python's `requests`, and most CLI tools. Honoring them makes
spnego-proxy a better citizen in scripted environments, CI pipelines, and
container deployments where these variables are already set.

### 8. Upstream proxy auto-discovery via PAC/WPAD

**What:** A `-pac` flag accepting a PAC file URL or local path. Evaluate the
PAC file's `FindProxyForURL()` function per-request to select the correct
upstream proxy or go direct.

**Justification:** px-proxy has comprehensive PAC support (including QuickJS
for evaluation and periodic reloading). cntlm's versat fork added basic PAC
support. In large enterprises, PAC files are the standard mechanism for proxy
selection, and the upstream proxy address changes per-destination or
per-network-segment. Without PAC support, users in these environments must
manually determine and configure the correct upstream proxy. This is complex to
implement (requires a JavaScript evaluator), so it ranks lower despite high
user value.

### 9. Hot-reload of configuration on SIGHUP

**What:** On receiving `SIGHUP`, re-read the configuration file and apply
changes without dropping in-flight connections.

**Justification:** Neither competitor does this well (cntlm requires restart,
px-proxy only reloads PAC periodically). This is an opportunity to leapfrog
both. Credential rotation is a major pain point for cntlm users — when domain
passwords change, the proxy must be fully restarted. Hot-reload of the config
file (especially credential-related settings) would allow seamless password
rotation and upstream proxy changes in long-running deployments.

### 10. Prometheus / OpenTelemetry metrics endpoint

**What:** An optional `-metrics [addr:]port` flag exposing request counts,
error rates, latency histograms, circuit breaker state, active connections, and
authentication success/failure rates.

**Justification:** No competitor offers metrics. Corporate proxy environments
often lack visibility into why tools are slow or failing. An observability
endpoint enables integration with existing monitoring stacks (Prometheus,
Grafana, Datadog) and gives operations teams data for capacity planning and
incident response. This is a clear differentiation opportunity. The slog-based
structured logging already captures the relevant events; metrics would be a
natural complement.

### 11. TCP port forwarding (SSH `-L` style tunnels)

**What:** A `-tunnel [laddr:]lport:rhost:rport` flag (repeatable) that opens a
local listening socket and forwards connections through the authenticated
upstream proxy via CONNECT.

**Justification:** cntlm's `-L` / `Tunnel` feature is well-regarded for
enabling SSH, database, and other non-HTTP tools to traverse corporate proxies.
While SOCKS5 (item 4) covers the general case, explicit port forwarding is
simpler to configure for known fixed endpoints and does not require SOCKS-aware
clients. The two features are complementary.

### 12. Homebrew formula and broader package distribution

**What:** Publish a Homebrew tap/formula, an AUR package, and a Docker image.

**Justification:** cntlm is in Homebrew and most Linux distros' package
managers. px-proxy is on PyPI, conda-forge, and Docker Hub. spnego-proxy
currently distributes only via GitHub release tarballs. Package manager
availability is a major factor in tool adoption — users overwhelmingly prefer
`brew install` over downloading tarballs, verifying checksums, and managing
PATH entries. A Homebrew formula in particular would serve the macOS audience
that is spnego-proxy's strongest platform.

### 13. Credential keyring integration (macOS Keychain, Linux secret service)

**What:** For password-based (gokrb5) mode, read credentials from the OS
keyring (macOS Keychain, GNOME Keyring, KWallet) instead of requiring a
password file or interactive prompt.

**Justification:** px-proxy integrates with platform keyrings on all three
OSes and offers a `--password` setup command. spnego-proxy's current options
are a 0600-permission password file or an interactive stdin prompt. Keyring
integration eliminates plaintext password files from disk entirely, improving
security posture and reducing the credential rotation workflow to updating the
keyring entry.

### 14. User-Agent and custom header injection

**What:** A repeatable `-header "Name: value"` flag that adds or replaces
headers on every forwarded request.

**Justification:** cntlm's `-r` / `Header` directive enables custom header
injection, commonly used for User-Agent overrides or adding corporate tracking
headers. While spnego-proxy's RFC 7239 Forwarded header support covers one use
case, generic header injection would serve the long tail of corporate
environments with bespoke header requirements. This is low-effort to implement
(~20 lines of code) with outsized utility for edge cases.

---

## Addendum: Rejected Ideas

### A. NTLM authentication support

**Why rejected:** NTLM is a legacy Microsoft protocol with known
cryptographic weaknesses (pass-the-hash, relay attacks). spnego-proxy's name
and identity center on SPNEGO/Kerberos, which is the modern replacement.
Adding NTLM would expand the attack surface, require substantial
implementation effort (or a C dependency), and dilute the project's focus.
Users needing NTLM already have cntlm and px-proxy. Kerberos-only is a
defensible, security-forward position.

### B. HTTP response caching

**Why rejected:** An authenticating proxy and an HTTP cache are different
concerns with different complexity profiles. Caching introduces cache
invalidation logic, storage management, `Cache-Control` / `ETag` / `Vary`
header interpretation, and significant memory or disk usage. Neither cntlm
nor px-proxy implements caching. Users who need caching should compose
spnego-proxy with a dedicated caching proxy (Squid, Varnish).

### C. TLS termination on the client-facing listener

**Why rejected:** spnego-proxy listens on localhost by default, where TLS
adds overhead without security benefit (loopback traffic is not
network-exposed). Neither cntlm nor px-proxy offers a TLS listener.
Adding one would require certificate management (generation, rotation,
trust configuration), which creates more UX friction than it solves.
The `-allowed-ips` flag and loopback binding are sufficient access controls.

### D. Web-based management UI

**Why rejected:** All three tools in this category are CLI utilities designed
for developers and system administrators. A web UI would add a web framework
dependency, a significant attack surface (authentication, CSRF, XSS), and
ongoing maintenance burden. The target audience is comfortable with CLI
configuration. Neither competitor offers a web UI (px-proxy's `pxw.exe` is
just a console-less wrapper, not a UI).

### E. HTTP/2 or HTTP/3 support

**Why rejected:** The proxy communicates with the upstream corporate proxy,
which is almost universally HTTP/1.1 (ISA, Squid, BlueCoat, Zscaler legacy).
HTTP/2 between the local client and localhost proxy provides negligible
benefit (no latency to overcome, no multiplexing advantage on loopback).
Neither cntlm nor px-proxy supports HTTP/2. The implementation cost
(HTTP/2 frame handling, HPACK, flow control) far exceeds the practical
benefit.

### F. Plugin / middleware extension system

**Why rejected:** An extension API increases API surface, creates backward
compatibility obligations, and attracts complexity disproportionate to the
tool's scope. spnego-proxy is a focused, single-purpose proxy. Composability
(piping through other tools, chaining proxies) is the Unix-philosophy
alternative to plugins. Neither competitor has an extension system, confirming
that the user base does not demand one.

### G. GUI application

**Why rejected:** The target audience (developers, DevOps engineers, CI
systems) operates in terminal and headless environments. A GUI would require
a UI framework dependency (platform-specific or Electron-heavy), dramatically
increase binary size, and serve only a subset of users. px-proxy's `pxw.exe`
exists solely to hide the console window on Windows, not to provide a GUI.

### H. Built-in auto-update mechanism

**Why rejected:** Auto-update in a security-sensitive tool that handles
authentication credentials is a supply-chain risk. Corporate environments
typically manage software versions through MDM, package managers, or
configuration management (Ansible, Chef, Puppet). An auto-updater would
conflict with these workflows and introduce a network call to an external
server from a tool specifically designed to mediate network access.

### I. Basic / Digest upstream proxy authentication

**Why rejected:** Same rationale as NTLM (item A). spnego-proxy's scope is
SPNEGO/Kerberos. Basic and Digest are less secure authentication methods
that would dilute the project's focus. px-proxy covers these via libcurl
for users who need them.

### J. NTLM-to-Basic multi-user translation (cntlm's `-B` mode)

**Why rejected:** This feature exists in cntlm specifically because NTLM
authentication requires the proxy to know the user's password hash. In
Kerberos, each user has their own ticket, and credential delegation does not
work through a shared proxy instance the same way. The architectural model
does not transfer to SPNEGO. Users needing multi-user support should run
per-user proxy instances (which is already lightweight with a single Go
binary).
