# Kerberos Testing Infrastructure Research

## Context

Testing spnego-proxy currently requires:
- Linux x64, macOS Intel x64, and macOS aarch64 hosts
- That sit behind a proxy requiring Kerberos authentication
- Have valid Kerberos tickets or username/password credentials
- Have a Kerberos domain controller to facilitate all Kerberos interactions

This document explores options for automating this testing for (1) local
development and (2) CI, without requiring corporate-style Kerberos DC setups.

## Current Test Coverage

The existing test suite (~1,395 lines across 5 files) covers:

| Area | What's Tested | What's NOT Tested |
|------|---------------|-------------------|
| Proxy mechanics | Dial timeout, read timeout, token injection, bidirectional forwarding, half-close, keepalive, connection limiting, graceful shutdown | Full end-to-end proxy chain with real Kerberos auth |
| gokrb5 path | Password file handling (perms, size, CRLF), provider construction, SPN inference/normalization, error handling | Actual TGT acquisition, SPNEGO token generation against a real KDC |
| macOS GSS-API | SPN derivation, SPN normalization, graceful error without credentials | Actual token acquisition via Heimdal GSS-API |
| Circuit breaker | Open/closed/half-open state transitions | Circuit breaker with real token provider |

**The gap**: No tests exercise the actual Kerberos protocol — acquiring a TGT
from a KDC, generating a real SPNEGO token, and using it to authenticate to an
upstream proxy. This is where all manual testing effort is concentrated.

---

## Option 1: Pure Go Mock KDC (`jcmturner/krb5test`)

### How it works

[jcmturner/krb5test](https://github.com/jcmturner/krb5test) is a pure Go mock
KDC written by the same author as gokrb5 (the library this project uses). It
implements:

- **AS Exchange**: Responds to initial login to obtain a TGT
- **TGS Exchange**: Grants service tickets

Usage:
```go
principals := map[string][]string{
    "testuser1": {"testgroup1"},
    "HTTP/proxy.example.com": {},
}
kdc := krb5test.NewKDC(principals, logger)
kdc.Start()
defer kdc.Close()

// kdc.KRB5Conf — auto-generated krb5.conf pointing to ephemeral localhost port
// kdc.Keytab   — generated keytab for all principals
// kdc.Realm    — realm name
```

### What it enables

- **Test gokrb5 token acquisition end-to-end**: Create a
  `Gokrb5TokenProvider` with the mock KDC's `krb5.conf` and verify that
  `GetToken()` returns a valid base64-encoded SPNEGO token.
- **Test the full proxy chain (gokrb5 path)**: Start the mock KDC, start a
  fake upstream "proxy" that validates the `Proxy-Authorization: Negotiate`
  header, start spnego-proxy pointed at both, and send HTTP requests through.
- **No Docker, no system packages, no network**: Runs entirely in-process on
  ephemeral localhost ports. Works in any CI environment.
- **Parallel test safety**: Each test gets its own KDC on a unique port.

### Limitations

- Only tests the gokrb5 code path (Linux/password-based auth). Does **not**
  test the macOS native GSS-API path.
- The mock KDC does not implement the full Kerberos protocol (e.g., no
  pre-authentication negotiation, no PA-FX-FAST, no ticket renewal).
- Does not validate that generated SPNEGO tokens would be accepted by a real
  corporate proxy.

### Effort: Low

Add `github.com/jcmturner/krb5test` as a test dependency. Write integration
tests using it. No infrastructure changes needed.

### Recommendation: **Do this first.**

This is the highest-value, lowest-effort option. It closes the biggest testing
gap (gokrb5 token acquisition) with zero infrastructure overhead.

---

## Option 2: Docker-Based MIT KDC for Integration Tests

### How it works

Run a real MIT Kerberos KDC inside a Docker container. Several mature options
exist:

| Image | Description | Notes |
|-------|-------------|-------|
| [godatadriven/krb5-kdc-server](https://hub.docker.com/r/godatadriven/krb5-kdc-server) | Purpose-built test KDC | Simple, widely used |
| [gcavalcante8808/krb5-server](https://hub.docker.com/r/gcavalcante8808/krb5-server) | Alpine-based MIT krb5 | Env var config (`KRB5_REALM`, `KRB5_KDC`, `KRB5_PASS`), amd64+arm64 |
| [NORDUnet/krb5-docker](https://github.com/NORDUnet/krb5-docker) | **MIT and Heimdal** | Separate Dockerfiles; principals via `PRINCIPALS` env var (`name:password` pairs) |
| [criteo/kerberos-docker](https://github.com/criteo/kerberos-docker) | Full Kerberos environment | Multi-container, CI-tested with GitHub Actions |
| gokrb5's own images (`jcmturner/gokrb5:kdc-centos-default`, etc.) | Used by gokrb5 CI | Battle-tested, multiple KDC configurations |

A typical docker-compose setup:

```yaml
services:
  kdc:
    image: godatadriven/krb5-kdc-server
    environment:
      KRB5_REALM: TEST.LOCAL
      KRB5_KDC: kdc.test.local
    ports:
      - "88:88/tcp"
      - "88:88/udp"
      - "749:749/tcp"
    volumes:
      - ./test/krb5.conf:/etc/krb5.conf
      - keytabs:/etc/security/keytabs

  upstream-proxy:
    image: <nginx or custom image with SPNEGO auth>
    depends_on: [kdc]
    # ... configured to require Kerberos auth

  spnego-proxy:
    build: .
    depends_on: [upstream-proxy]
    command: >
      ./spnego-proxy
        -proxy upstream-proxy:3128
        -config /etc/krb5.conf
        -user testuser
        -realm TEST.LOCAL
        -password-file /run/secrets/password
```

### What it enables

- **Real Kerberos protocol testing**: TGT acquisition, service ticket
  requests, and SPNEGO token generation against a genuine MIT KDC.
- **Full end-to-end proxy chain**: Client → spnego-proxy → authenticated
  upstream proxy → backend, with real Kerberos authentication at every step.
- **Token validation**: Verify that tokens generated by gokrb5 are actually
  accepted by a standards-compliant KDC/service.
- **Regression testing**: Catch protocol-level bugs that a mock KDC would miss.

### Gotcha: Docker Entropy

Docker containers often have very low entropy, which can cause the KDC to hang
during database initialization. The standard workaround is mapping
`/dev/urandom` to `/dev/random`:

```bash
docker run -v /dev/urandom:/dev/random ...
```

### Limitations

- **Hostname sensitivity**: Kerberos is very sensitive to hostnames and DNS.
  All containers must be on a shared Docker network with correct DNS
  resolution, or `/etc/hosts` must be carefully configured. This is the #1
  source of friction in Docker-based Kerberos testing.
- **Does NOT test macOS GSS-API path**: Docker containers run Linux. The
  macOS native Heimdal GSS-API code path cannot be tested this way.
- **Slower**: Container startup adds seconds to test runs.
- **Requires Docker**: Not available in all CI environments (though GitHub
  Actions Ubuntu runners have Docker).

### Effort: Medium

Write a `docker-compose.yml` for the test environment, create initialization
scripts for the KDC (create realm, add principals, export keytabs), write a
Go test file with `-tags=integration` that expects the Docker environment to
be running.

### Reference: gokrb5's CI workflow

The gokrb5 library itself runs integration tests in GitHub Actions using 7
Docker containers (DNS server, 5 KDC variants, HTTP service). See
[testing.yml](https://github.com/jcmturner/gokrb5/blob/master/.github/workflows/testing.yml).
This is the gold standard for Go Kerberos CI testing and the most natural
pattern to adapt since spnego-proxy already depends on gokrb5.

### Recommendation: **Do this second, for CI.**

This provides the most realistic testing of the gokrb5 path. Run it in GitHub
Actions as a separate integration test job alongside the existing unit tests.

---

## Option 3: Ephemeral MIT KDC Process (k5test-style)

### How it works

Instead of Docker, spawn a real `krb5kdc` process directly on the test host,
following the pattern established by MIT krb5's own test framework
([k5test.py](https://github.com/krb5/krb5/blob/master/src/util/k5test.py)) and
the Python [k5test](https://github.com/pythongssapi/k5test) library:

1. Create a temp directory
2. Write `krb5.conf` and `kdc.conf` pointing to that directory
3. Run `kdb5_util create -s -P <password> -r TESTREALM -d <tmpdir>/principal`
4. Add principals with `kadmin.local`
5. Export keytabs with `kadmin.local ktadd`
6. Start `krb5kdc -n -p <ephemeral-port>` as a subprocess
7. Set `KRB5_CONFIG=<tmpdir>/krb5.conf`
8. Run tests
9. Kill `krb5kdc` and clean up temp directory

### What it enables

- **Real KDC, no Docker**: Useful if Docker is unavailable or undesirable.
- **macOS testing potential**: On macOS, if MIT krb5 is installed via Homebrew
  (`brew install krb5`), this approach can test the gokrb5 path. More
  importantly, by setting `KRB5_CONFIG` and `KRB5CCNAME=FILE:<tmpfile>`, it
  may be possible to test the native Heimdal GSS-API path against this
  ephemeral KDC — **if** macOS's Heimdal respects `KRB5_CONFIG` for the
  realm configuration. (This needs verification.)
- **Fast startup**: No container overhead.

### Limitations

- **Requires MIT krb5 packages installed**: `krb5-kdc`, `krb5-admin-server`
  on Ubuntu, or `krb5` via Homebrew on macOS.
- **More complex setup code**: Need to write Go test helpers that shell out to
  `kdb5_util`, `kadmin.local`, and manage the `krb5kdc` subprocess lifecycle.
- **Fragile across OS versions**: Different OSes ship different krb5 versions
  with slightly different behaviors.
- **macOS Heimdal interop is uncertain**: macOS ships Heimdal, not MIT krb5.
  Whether the system Heimdal GSS-API will correctly talk to a locally-running
  MIT KDC via `KRB5_CONFIG` override is not guaranteed and needs testing.

### Effort: Medium-High

Write Go test helpers to manage the KDC lifecycle. Handle platform differences.
May require installing packages in CI.

### Recommendation: **Consider as an alternative to Option 2 if Docker is problematic.**

The main advantage over Docker is potential macOS GSS-API testing, but that
benefit is uncertain. Docker is generally more reproducible.

---

## Option 4: Testing the macOS Native GSS-API Path

This is the hardest gap to close. The macOS GSS-API code (`auth_gss_darwin.go`,
`gss_darwin.c`) uses Apple's Heimdal framework via CGO. Testing this requires:

### Sub-option 4a: Ephemeral KDC on macOS CI Runner

- Use GitHub Actions `macos-latest` runner
- Install MIT krb5 via Homebrew: `brew install krb5`
- Spawn an ephemeral KDC (Option 3)
- Run `kinit` to populate a `FILE:`-type credential cache
- Set `KRB5CCNAME=FILE:/tmp/test_ccache` to bypass the macOS KCM daemon
- Set `KRB5_CONFIG` to point to the test `krb5.conf`
- Call `GetToken()` on the `GSSTokenProvider`

**Key uncertainty**: Apple's Heimdal GSS-API may not respect `KRB5_CONFIG` for
all operations. The KCM cache bypass via `KRB5CCNAME=FILE:...` is documented
in [Apple's own Heimdal tests](https://github.com/aosm/Heimdal/blob/master/tests/apple/check-apple-lkdc.in).

**Effort**: High. Requires macOS-specific CI configuration and may hit
unexpected issues with SIP, Heimdal version differences, etc.

### Sub-option 4b: Structural Testing Without a Real KDC

Instead of testing actual GSS-API calls, verify the code structure:

- The existing tests already cover SPN derivation and normalization
- Add tests that verify error messages and error handling paths (e.g.,
  expired credentials, wrong SPN format, missing credential cache)
- Use `klist` and `kdestroy` in CI to ensure a known-empty credential
  state, then verify `GSSTokenProvider.GetToken()` fails gracefully

**Effort**: Low. Limited value but better than nothing.

### Sub-option 4c: Accept macOS GSS-API as a Manual Testing Surface

The macOS GSS-API path is a thin wrapper (~88 lines Go + ~144 lines C) around
Apple's framework. The critical bugs are more likely in the surrounding logic
(SPN handling, error reporting, credential cache detection) than in the GSS-API
calls themselves. The unit tests already cover the surrounding logic.

**Effort**: None. Accept the risk.

### Recommendation: **Start with 4b, attempt 4a as a stretch goal.**

---

## Option 5: Full End-to-End Integration Test in CI

### Architecture

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐     ┌─────────┐
│  Client   │────▶│ spnego-proxy │────▶│ Upstream Proxy   │────▶│ Backend │
│  (curl)   │     │ (under test) │     │ (SPNEGO-authed) │     │ (httpbin)│
└──────────┘     └──────────────┘     └─────────────────┘     └─────────┘
                        │                      │
                        ▼                      ▼
                   ┌─────────┐           ┌─────────┐
                   │   KDC   │◀──────────│   KDC   │
                   └─────────┘           └─────────┘
```

The upstream proxy would be an nginx or Apache server configured with
`mod_auth_gssapi` / `mod_auth_kerb` to require SPNEGO authentication. This
tests the full chain: spnego-proxy acquires a real SPNEGO token from the KDC
and the upstream proxy validates it against the same KDC.

### Implementation sketch (Docker Compose)

```yaml
services:
  kdc:
    image: godatadriven/krb5-kdc-server
    environment:
      KRB5_REALM: TEST.LOCAL
      KRB5_KDC: kdc
    hostname: kdc
    networks:
      krb5net:
        ipv4_address: 10.5.0.2

  upstream-proxy:
    build: ./test/upstream-proxy  # nginx + mod_auth_gssapi
    hostname: proxy.test.local
    depends_on: [kdc]
    networks:
      krb5net:
        ipv4_address: 10.5.0.3

  backend:
    image: kennethreitz/httpbin
    hostname: backend
    networks:
      krb5net:
        ipv4_address: 10.5.0.4

networks:
  krb5net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.5.0.0/24
```

### What it enables

- **True end-to-end validation**: The generated SPNEGO token is validated by
  a real service, not just a mock.
- **Catches interoperability bugs**: Protocol-level issues between gokrb5's
  SPNEGO implementation and standard Kerberos services.

### Limitations

- **Linux/gokrb5 path only**: Same Docker limitation as Option 2.
- **Complex setup**: Need to build and maintain the upstream proxy container
  with SPNEGO auth configuration.
- **Slow**: Multiple containers, KDC initialization, principal creation.
- **Hostname/DNS complexity**: Everything must agree on hostnames.

### Effort: High

### Recommendation: **Do this as a third phase, after Options 1 and 2 prove their value.**

---

## Comparison Matrix

| Criterion | Option 1: Mock KDC | Option 2: Docker KDC | Option 3: Ephemeral KDC | Option 4: macOS GSS | Option 5: Full E2E |
|-----------|--------------------|-----------------------|-------------------------|---------------------|---------------------|
| **Effort** | Low | Medium | Medium-High | High | High |
| **Tests gokrb5 token gen** | Yes (mock) | Yes (real) | Yes (real) | No | Yes (real) |
| **Tests macOS GSS-API** | No | No | Maybe | Yes | No |
| **Tests full proxy chain** | Possible | Possible | Possible | No | Yes |
| **Token validated by real service** | No | Possible | Possible | No | Yes |
| **Docker required** | No | Yes | No | No | Yes |
| **System packages required** | No | No | Yes (krb5) | No | No |
| **Works in GitHub Actions** | Yes (all runners) | Yes (Ubuntu) | Yes (with setup) | Yes (macOS, uncertain) | Yes (Ubuntu) |
| **Parallel test safe** | Yes | With care | With care | With care | No |
| **Startup time** | Milliseconds | Seconds | Sub-second | Sub-second | Many seconds |

---

## Recommended Phased Approach

### Phase 1: Pure Go Mock KDC (Days)

1. Add `github.com/jcmturner/krb5test` as a test dependency
2. Write integration tests that:
   - Start a mock KDC with test principals
   - Create a `Gokrb5TokenProvider` using the mock's `krb5.conf`
   - Verify `GetToken()` returns a valid base64-encoded SPNEGO token
   - Start spnego-proxy with a fake upstream, verify the `Proxy-Authorization`
     header is injected correctly with a real token
3. Run these tests in the existing CI pipeline (no infrastructure changes)

**Eliminates**: Most manual testing of the gokrb5 code path.

### Phase 2: Docker-Based Integration Tests (Weeks)

1. Create `test/docker-compose.yml` with a real MIT KDC container
2. Write integration tests (behind `-tags=integration`) that:
   - Acquire real TGTs and service tickets
   - Generate SPNEGO tokens validated against the real KDC
   - Exercise the full proxy chain with a SPNEGO-authenticated upstream
3. Add a GitHub Actions job that starts the Docker environment and runs
   integration tests

**Eliminates**: Manual testing of real Kerberos protocol compliance.

### Phase 3: macOS GSS-API Testing (Stretch Goal)

1. Experiment with ephemeral KDC on macOS CI runners
2. Determine if `KRB5_CONFIG` + `KRB5CCNAME=FILE:` overrides work with
   Apple's Heimdal
3. If viable, add macOS integration tests

**Reduces**: Manual testing on macOS, but may not fully eliminate it.

---

## What Cannot Be Automated

Even with all the above, some scenarios will still require manual testing:

- **Corporate proxy interop**: Real corporate proxies may have
  vendor-specific SPNEGO quirks (e.g., Microsoft ISA/TMG, Blue Coat,
  Zscaler) that a test KDC won't reproduce.
- **Credential cache varieties**: macOS Keychain-based `API:` cache, KCM
  daemon, KEYRING on Linux — these system-level integrations are hard to
  replicate in CI.
- **Network edge cases**: Behavior behind real corporate firewalls, proxy
  chains, PAC files, etc.
- **Long-lived operation**: Ticket renewal, credential expiry, cache
  rotation over hours/days.

However, these are relatively narrow scenarios compared to the broad "does
Kerberos auth work at all" testing that currently requires a full corporate
setup.

---

## References

- [jcmturner/krb5test](https://github.com/jcmturner/krb5test) — Pure Go mock KDC
- [jcmturner/gokrb5 CI workflow](https://github.com/jcmturner/gokrb5/blob/master/.github/workflows/testing.yml) — GitHub Actions reference
- [godatadriven/krb5-kdc-server](https://github.com/godatadriven-dockerhub/krb5-kdc-server) — Docker test KDC
- [gcavalcante8808/krb5-server](https://hub.docker.com/r/gcavalcante8808/krb5-server) — Alpine-based Docker KDC
- [NORDUnet/krb5-docker](https://github.com/NORDUnet/krb5-docker) — MIT + Heimdal Docker KDC
- [criteo/kerberos-docker](https://github.com/criteo/kerberos-docker) — Full Docker Kerberos environment
- [tillt/docker-kdc](https://github.com/tillt/docker-kdc) — Heimdal Docker KDC (macOS-friendly)
- [pythongssapi/k5test](https://github.com/pythongssapi/k5test) — Python self-contained KDC (design reference)
- [krb5/k5test.py](https://github.com/krb5/krb5/blob/master/src/util/k5test.py) — MIT krb5 test framework
- [Apple Heimdal LKDC tests](https://github.com/aosm/Heimdal/blob/master/tests/apple/check-apple-lkdc.in) — macOS KRB5CCNAME override pattern
- [Confluent: Containerized Kerberos Testing](https://www.confluent.io/blog/containerized-testing-with-kerberos-and-ssh/)
- [adelton/webauthinfra](https://github.com/adelton/webauthinfra) — Full SPNEGO E2E with Apache + mod_auth_gssapi
- [stnoonan/spnego-http-auth-nginx-module](https://github.com/stnoonan/spnego-http-auth-nginx-module) — Nginx SPNEGO module
