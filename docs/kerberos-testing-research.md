# Kerberos Testing Infrastructure Research

## Context

Manual end-to-end testing against a corporate proxy requires:

- Linux x64, macOS Intel x64, and macOS aarch64 hosts
- That sit behind a proxy requiring Kerberos authentication
- Have valid Kerberos tickets or username/password credentials
- Have a Kerberos domain controller to facilitate all Kerberos interactions

This document explores options for automating this testing for (1) local
development and (2) CI, without requiring corporate-style Kerberos DC setups.

## Current Test Coverage

The existing test suite covers:

| Area | What's Tested | What's NOT Tested |
| ------ | --------------- | ------------------- |
| Proxy mechanics | Dial timeout, read timeout, token injection, bidirectional forwarding, half-close, keepalive, connection limiting, graceful shutdown; full proxy chain with mock-KDC tokens in [TestProxyChainWithRealToken](../internal/proxy/gokrb5_integration_test.go) | Corporate upstream-proxy interoperability |
| gokrb5 path | Password file handling (perms, size, CRLF), provider construction, SPN inference/normalization, error handling; mock-KDC lockout regressions linked below | SPNEGO token acceptance by a corporate upstream proxy |
| macOS GSS-API | SPN derivation, SPN normalization, graceful error without credentials; [native GSS-API integration suite](../CONTRIBUTING.md#macos-gss-api-integration-tests) | Corporate upstream-proxy interoperability |
| Circuit breaker | Open/closed/half-open state transitions, concurrent admission, real token provider with a mock KDC | Directory lockout policy interoperability |

The [lockout regression tests](../internal/proxy/auth_gokrb5_lockout_test.go)
exercise TGT acquisition and SPNEGO token generation against a mock KDC.
They cover delayed exchanges, password changes, rejection warnings, and recovery
from clock skew. Acceptance by a corporate upstream proxy still needs manual
verification.

---

## Option 1: Pure Go Mock KDC (`jcmturner/krb5test`)

### Overview

[jcmturner/krb5test](https://github.com/jcmturner/krb5test) is a pure Go mock
KDC written by the same author as gokrb5 (the library this project uses). It
implements:

- **AS Exchange**: Responds to initial login to obtain a TGT
- **TGS Exchange**: Grants service tickets

For a working setup, see `startLockoutKDC` and `newLockoutProvider` in the tests
linked in [Current Test Coverage](#current-test-coverage).

### What it enables

- **Test gokrb5 token acquisition end-to-end**: Create a
  `Gokrb5TokenProvider` with the mock KDC's `krb5.conf` and verify that
  `GetToken()` returns a valid base64-encoded SPNEGO token.
- **Test the full proxy chain (gokrb5 path)**: Start the mock KDC, start a
  fake upstream "proxy" that validates the `Proxy-Authorization: Negotiate`
  header, start spnego-proxy pointed at both, and send HTTP requests through.
- **No Docker, no system packages, no external network**: Runs in-process on
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

`github.com/jcmturner/krb5test` is already a test dependency, used by the
lockout regression tests linked in [Current Test Coverage](#current-test-coverage).
Extending these tests needs no external KDC infrastructure.

### Recommendation: Extend mock-KDC coverage

Use the existing mock-KDC tests as the starting point for broader proxy-chain
coverage. Keep corporate-proxy interoperability checks separate.

---

## Option 2: Docker-Based MIT KDC for Integration Tests

### Docker KDC images

Run a real MIT Kerberos KDC inside a Docker container. Several mature options
exist:

| Image | Description | Notes |
| ------- | ------------- | ------- |
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

### What Docker testing enables

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

### Docker testing limitations

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

### Ephemeral KDC approach

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

### What an ephemeral KDC enables

- **Real KDC, no Docker**: Useful if Docker is unavailable or undesirable.
- **Native macOS coverage**: See the implemented
  [GSS-API integration suite](../CONTRIBUTING.md#macos-gss-api-integration-tests).
- **Fast startup**: No container overhead.

### Ephemeral KDC limitations

- **Requires MIT krb5 packages installed**: `krb5-kdc`, `krb5-admin-server`
  on Ubuntu, or `krb5` via Homebrew on macOS.
- **More complex setup code**: Helpers must invoke `kdb5_util` and
  `kadmin.local` and manage the `krb5kdc` subprocess lifecycle.
- **Fragile across OS versions**: Different OSes ship different krb5 versions
  with slightly different behaviors.

### Effort: Medium-High

The implemented helper is
[`NewEphemeralKDC`](../internal/proxy/ephemeral_kdc_darwin_test.go).

### Recommendation: **Consider as an alternative to Option 2 if Docker is problematic.**

For the native macOS setup, see the
[integration test guide](../CONTRIBUTING.md#macos-gss-api-integration-tests).
Docker is generally more reproducible.

---

## Option 4: Testing the macOS Native GSS-API Path

For the implemented suite, prerequisites, and commands, see
[macOS GSS-API integration tests](../CONTRIBUTING.md#macos-gss-api-integration-tests).
The fixture's configuration and credential-cache constraints are documented in
[`NewEphemeralKDC`](../internal/proxy/ephemeral_kdc_darwin_test.go).
The FILE: credential cache bypasses the macOS KCM daemon, following
[Apple's Heimdal tests](https://github.com/aosm/Heimdal/blob/master/tests/apple/check-apple-lkdc.in).

---

## Option 5: Full End-to-End Integration Test in CI

### Architecture

```text
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

### What full E2E enables

- **True end-to-end validation**: The generated SPNEGO token is validated by
  a real service, not just a mock.
- **Catches interoperability bugs**: Protocol-level issues between gokrb5's
  SPNEGO implementation and standard Kerberos services.

### Full E2E limitations

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
| ----------- | -------------------- | ----------------------- | ------------------------- | --------------------- | --------------------- |
| **Effort** | Low | Medium | Medium-High | High | High |
| **Tests gokrb5 token gen** | Yes (mock) | Yes (real) | Yes (real) | No | Yes (real) |
| **Tests macOS GSS-API** | No | No | See [Option 4](#option-4-testing-the-macos-native-gss-api-path) | Yes | No |
| **Tests full proxy chain** | Possible | Possible | Possible | See [GSS proxy-chain test](../internal/proxy/integration_gss_darwin_test.go) | Yes |
| **Token validated by real service** | No | Possible | Possible | No | Yes |
| **Docker required** | No | Yes | No | No | Yes |
| **System packages required** | No | No | Yes (krb5) | See [Option 4](#option-4-testing-the-macos-native-gss-api-path) | No |
| **Works in GitHub Actions** | Yes (all runners) | Yes (Ubuntu) | Yes (with setup) | See [Build and Test](../.github/workflows/build-and-test.yml) | Yes (Ubuntu) |
| **Parallel test safe** | Yes | With care | With care | With care | No |
| **Startup time** | Milliseconds | Seconds | Sub-second | Sub-second | Many seconds |

---

## Recommended Phased Approach

### Phase 1: Extend Pure Go Mock KDC Coverage

For implemented coverage, see [Current Test Coverage](#current-test-coverage).
The remaining gap is coverage the mock KDC cannot give: enctypes, pre-auth
policy, and ticket lifetimes that a real KDC negotiates. Extend the existing
mock-KDC tests only for scenarios they do not already assert; the protocol
fidelity gap is what Phase 2 closes.

### Phase 2: Docker-Based Integration Tests (Weeks)

1. Create `test/docker-compose.yml` with a real MIT KDC container
2. Write integration tests (behind `-tags=integration`) that:
   - Acquire real TGTs and service tickets
   - Generate SPNEGO tokens validated against the real KDC
   - Exercise the full proxy chain with a SPNEGO-authenticated upstream
3. Add a GitHub Actions job that starts the Docker environment and runs
   integration tests

**Eliminates**: Manual testing of real Kerberos protocol compliance.

### Phase 3: macOS GSS-API Testing

See [Option 4](#option-4-testing-the-macos-native-gss-api-path) for the
implemented approach. Corporate interoperability remains a manual testing
surface, as described below.

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
