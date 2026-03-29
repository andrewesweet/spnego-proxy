# spnego-proxy

An HTTP proxy that handles SPNEGO (Kerberos) authentication on behalf of
clients that don't support it. It sits between the application and the
real proxy, forwarding requests with a `Proxy-Authorization: Negotiate`
header. It does not alter nor inspect traffic between the client and the
real proxy.

This fork adds **native macOS GSS-API support**, allowing passwordless
operation using Kerberos tickets from the macOS credential cache
(including the Keychain-based `API:` cache type). The existing
password-based authentication via `gokrb5` is preserved as a fallback
for Linux/Windows or when explicitly requested on macOS.

## Installation

### Homebrew (macOS)

```bash
brew tap andrewesweet/spnego-proxy
brew install spnego-proxy
```

The formula builds with `CGO_ENABLED=1` to link against the native GSS.framework
for SPNEGO authentication.

### Docker

```bash
docker run --rm ghcr.io/andrewesweet/spnego-proxy -version
```

For typical usage, pass proxy flags and expose the listening port:

```bash
docker run --rm -p 127.0.0.1:3128:3128 ghcr.io/andrewesweet/spnego-proxy \
  -proxy proxy.corp.example.com:8080 \
  -addr :3128
```

Multi-arch images are available for `linux/amd64` and `linux/arm64`.

### From source (requires Go 1.25+)

```bash
go install github.com/andrewesweet/spnego-proxy@latest
```

### Build from this repository

```bash
git clone https://github.com/andrewesweet/spnego-proxy.git
cd spnego-proxy

# macOS (with CGO for GSS-API support)
CGO_ENABLED=1 go build -o spnego-proxy .

# Linux (pure Go, gokrb5 fallback)
CGO_ENABLED=0 go build -o spnego-proxy .
```

For development setup including formatting, linting, and testing, see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

### macOS (GSS-API mode — passwordless)

On macOS, `spnego-proxy` uses the native GSS-API framework (Heimdal) to
acquire SPNEGO tokens from the default Kerberos credential cache. This
works with tickets obtained via `kinit` or the macOS Kerberos SSO
extension automatically.

Only two flags are required:

```bash
# Ensure you have a valid Kerberos ticket
kinit user@REALM.COM
klist

# Run the proxy
./spnego-proxy \
    -addr 127.0.0.1:3128 \
    -proxy upstream-proxy.example.com:8080

# Test
curl -x http://127.0.0.1:3128 https://example.com
```

Optional flags for macOS GSS-API mode:

- `-spn` — Override the service principal name (default: `HTTP@<proxy-hostname>`)
- `-file-cache` — Enable the SSO Extension file-cache workaround (see below)
- `-debug` — Enable debug logging

### Linux/Windows (password-based mode)

On non-macOS platforms, or when `-user` is specified on macOS, the proxy
uses the pure-Go `gokrb5` library with password-based authentication.

Required flags:

```bash
./spnego-proxy \
    -addr 127.0.0.1:3128 \
    -proxy upstream-proxy.example.com:8080 \
    -config /etc/krb5.conf \
    -user myuser \
    -realm EXAMPLE.COM \
    -password-file /path/to/password
```

All flags:

| Flag | Description | Required |
| ---- | ----------- | -------- |
| `-addr` | Listen address (default: `127.0.0.1:8080`) | No |
| `-proxy` | Upstream proxy address | Yes |
| `-spn` | Service principal name (default: `HTTP@<proxy-host>` on macOS, `HTTP/<proxy-host>` on Linux) | No |
| `-debug` | Enable debug logging | No |
| `-config` | Kerberos config file path | Password mode only |
| `-user` | Kerberos username (triggers password-based auth on macOS) | Password mode only |
| `-realm` | Kerberos realm | Password mode only |
| `-file-cache` | Copy credentials from macOS SSO Extension `API:` cache to `FILE:` cache (macOS only) | No |
| `-password-file` | Path to password file (prompts if omitted) | No |

### macOS with explicit password

If you provide `-user` on macOS, the proxy will use the `gokrb5`
password-based path instead of the native GSS-API:

```bash
./spnego-proxy \
    -addr 127.0.0.1:3128 \
    -proxy upstream-proxy.example.com:8080 \
    -config /etc/krb5.conf \
    -user myuser \
    -realm EXAMPLE.COM \
    -password-file /path/to/password
```

## macOS SSO Extension file-cache workaround

### Background

On macOS devices managed by Microsoft Intune, the Apple Kerberos SSO
Extension stores Kerberos credentials in an `API:` credential cache type.
While this works transparently for apps using higher-level Apple
frameworks (Safari, `curl`), the GSS-API function `gss_init_sec_context`
cannot read from `API:` caches directly. This means `spnego-proxy` —
which uses GSS.framework's C API — fails to acquire SPNEGO tokens on
these managed devices.

### How it works

The `-file-cache` flag enables a workaround that:

1. Enumerates all Kerberos credentials using `gss_iter_creds_f`
   (GSS.framework API)
2. Copies the credential with the longest remaining lifetime to a
   temporary `FILE:` cache using `gss_krb5_copy_ccache`
3. Redirects GSS-API to use the `FILE:` cache via `gss_krb5_ccache_name`
4. Acquires SPNEGO tokens from the `FILE:` cache
5. Automatically refreshes the copy when the credential approaches expiry
6. Securely cleans up (zeroes and deletes) the file cache on exit

### Usage

```bash
./spnego-proxy \
    -addr 127.0.0.1:3128 \
    -proxy upstream-proxy.example.com:8080 \
    -file-cache
```

The flag is only available on macOS and cannot be combined with `-user`
(password-based authentication).

### Security trade-offs

Enabling `-file-cache` writes Kerberos credential data to a temporary
file on disk. The proxy mitigates this risk:

- The file is created in a unique temporary directory with `0700`
  permissions (owner-only access)
- The file path is not predictable (random directory name)
- On exit, the file contents are overwritten with zeros before deletion
  (defense-in-depth against forensic recovery, though APFS
  copy-on-write means this is best-effort)
- The `gss_krb5_ccache_name` API is used instead of setting
  `KRB5CCNAME` to avoid environment variable race conditions

If your security policy prohibits writing credential material to disk,
do not use this flag. On unaffected devices (those without the SSO
Extension or using `kinit`-obtained tickets), `-file-cache` is
unnecessary — the default GSS-API path works without any temporary files.

## Standards compliance

`spnego-proxy` implements RFC 9110 (HTTP Semantics) and RFC 9209
(Proxy-Status) throughout its request and response handling:

- **Via header (RFC 9110 §7.6.3):** The proxy appends a `Via` entry to
  both forwarded requests and responses, using a randomly generated
  pseudonym to identify each proxy instance. Incoming requests whose
  `Via` header already contains the proxy's own pseudonym are rejected
  with `502 proxy_loop_detected` to prevent routing loops.

- **Proxy-Status header (RFC 9209):** All error responses include a
  structured `Proxy-Status` header (e.g.,
  `spnego-proxy; error=connection_timeout`) for machine-readable
  diagnostics.

### Known deviation: response Via fallback

RFC 9110 §7.6.3 states that a proxy **MUST** add a `Via` header to each
message it forwards. `spnego-proxy` complies with this requirement for
all parseable HTTP responses. However, if the upstream proxy sends a
response that cannot be parsed as valid HTTP (e.g., a severely malformed
status line or truncated headers), injecting a `Via` header is
impossible because there are no structured headers to modify.

In this edge case the proxy falls back to raw byte relay — forwarding
the unparseable data to the client without a `Via` header. This
trade-off was chosen deliberately:

1. **Client impact:** Returning a `502` error would discard whatever
   data the upstream sent. Raw relay preserves the original bytes, which
   may still be useful to the client or to downstream debugging tools.
2. **Impossibility of injection:** Without parseable headers there is no
   safe byte offset at which to insert a header line. Attempting to
   splice bytes could corrupt the stream.
3. **Operator visibility:** The proxy emits a `slog.Warn`-level log
   entry whenever the fallback triggers, including the parse error and
   client address, so the condition is always visible in operational
   monitoring.

In practice, this fallback should rarely (if ever) fire because
conforming HTTP proxies always send well-formed responses. If it does
fire, the log entry provides the information needed to investigate the
upstream proxy.

## Architecture

The project uses Go build tags to separate platform-specific authentication:

- `main.go` — Shared proxy logic, `TokenProvider` interface, CLI flags
- `auth_gss_darwin.go` — macOS: CGO-based GSS-API token acquisition
- `gss_darwin.c` / `gss_darwin.h` — C helpers for GSS-API calls
- `filecache_darwin.go` — macOS: SSO Extension file-cache workaround (Go)
- `filecache_darwin.c` / `filecache_darwin.h` — C helpers for credential cache copying
- `auth_gokrb5.go` — Pure-Go gokrb5 password-based auth (all platforms)
- `auth_notdarwin.go` — Non-macOS: returns error when native GSS is unavailable

## Security considerations

### Deployment model

This proxy is designed to run as a per-user localhost tool, similar to
[cntlm](https://cntlm.sourceforge.net/) and
[px-proxy](https://github.com/genotrance/px). It accepts connections
from any process that can reach its listener (default `127.0.0.1:8080`).
When binding to a non-loopback address, use `-allowed-ips` to restrict
access.

### CONNECT tunneling

CONNECT tunnels are restricted to port 443 by default. Use
`-connect-ports` with a comma-separated list to allow additional ports,
or `-connect-ports '*'` to allow all ports.

### Idle tunnel timeout

CONNECT tunnels are closed after 5 minutes of inactivity by default.
Use `-idle-timeout` to adjust or `-idle-timeout 0` to disable.

### Upstream TLS

By default, proxy-to-upstream connections use plain TCP (matching cntlm
and px-proxy behavior). Use `-upstream-tls` to encrypt the upstream
link. A custom CA can be provided with `-upstream-ca`.

### Kerberos configuration

- Ensure `krb5.conf` is read-only and owned by root or the service
  account.
- Be aware that `KRB5_CONFIG` and `KRB5CCNAME` environment variables
  affect authentication behavior.
- Run the proxy in an environment where unauthorized modification of
  these files and variables is not possible.

### Password handling

When using password-based authentication (`-user` flag), the password
bytes are zeroed in memory immediately after being passed to the
Kerberos client. The Kerberos library retains its own copy for TGT
re-authentication; use a keytab in environments where this is a concern.

### CGo boundary (macOS)

The macOS GSS-API integration uses C code that has been reviewed for
buffer safety. All buffers are bounds-checked (`snprintf`, explicit
length limits) and resource cleanup is handled in all code paths.

### Logging

The proxy logs structured JSON via `slog`. Security-relevant events
(authentication failures, CONNECT attempts, circuit breaker state
changes, TE/CL conflicts) are logged but not classified separately from
operational events.

## License

MIT — see [LICENSE](LICENSE).

Based on [montag451/spnego-proxy](https://github.com/montag451/spnego-proxy).
