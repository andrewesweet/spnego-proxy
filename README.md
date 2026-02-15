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

### From source (requires Go 1.22+)

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
| `-addr` | Listen address (default: `127.0.0.1:8080`) | Yes |
| `-proxy` | Upstream proxy address | Yes |
| `-spn` | Service principal name (default: `HTTP/<proxy-host>`) | No |
| `-debug` | Enable debug logging | No |
| `-follow-redirects` | Follow HTTP redirects on behalf of the client | No |
| `-max-redirects` | Maximum number of redirects to follow (default: 10) | No |
| `-config` | Kerberos config file path | Password mode only |
| `-user` | Kerberos username (triggers password-based auth on macOS) | Password mode only |
| `-realm` | Kerberos realm | Password mode only |
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

## Redirect following

Some HTTP clients do not handle redirects themselves. When
`-follow-redirects` is enabled, the proxy follows 3xx redirects
(301, 302, 303, 307, 308) on the client's behalf and returns only the
final response.

```bash
./spnego-proxy \
    -addr 127.0.0.1:3128 \
    -proxy upstream-proxy.example.com:8080 \
    -follow-redirects
```

Behaviour details:

- **Method and body preservation** — 307 and 308 redirects replay the
  original method and request body. 301, 302, and 303 redirects switch
  to GET and drop the body, per the HTTP specification.
- **Redirect limit** — The proxy follows at most 10 redirects by
  default. Use `-max-redirects` to change this. When the limit is
  reached the last redirect response is returned to the client as-is.
- **HTTPS targets** — Redirects that cross from HTTP to HTTPS (or vice
  versa) are followed transparently. For HTTPS targets the proxy opens
  a CONNECT tunnel to the upstream proxy, performs a TLS handshake, and
  issues the request in origin form.
- **CONNECT requests** — CONNECT tunnels are passed through unchanged.
  Redirect following only applies to plain HTTP method requests
  (GET, POST, etc.) because CONNECT establishes an opaque tunnel whose
  traffic the proxy does not interpret at the HTTP level.

## Architecture

The project uses Go build tags to separate platform-specific authentication:

- `main.go` — Shared proxy logic, `TokenProvider` interface, CLI flags
- `redirect.go` — Redirect-following proxy handler and HTTPS tunnel dialling
- `auth_gss_darwin.go` — macOS: CGO-based GSS-API token acquisition
- `gss_darwin.c` / `gss_darwin.h` — C helpers for GSS-API calls
- `auth_gokrb5.go` — Pure-Go gokrb5 password-based auth (all platforms)
- `auth_notdarwin.go` — Non-macOS: returns error when native GSS is unavailable

## License

MIT — see [LICENSE](LICENSE).

Based on [montag451/spnego-proxy](https://github.com/montag451/spnego-proxy).
