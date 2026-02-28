# P2: Data Flow Diagram Analysis - SPNEGO-PROXY

## DFD Summary

| Element Type | Count |
|-------------|-------|
| External Interactors | 5 |
| Processes | 10 |
| Data Stores | 4 |
| Data Flows | 18 |
| **Total** | **37** |

## External Interactors

| ID | Name | Trust Level |
|----|------|-------------|
| EI-001 | Client Application | UNTRUSTED |
| EI-002 | Upstream Proxy | SEMI-TRUSTED |
| EI-003 | Kerberos KDC | TRUSTED |
| EI-004 | macOS Credential Cache | OS-TRUSTED |
| EI-005 | Operator (CLI) | OPERATOR |

## Processes

| ID | Name | Module | Security Controls |
|----|------|--------|-------------------|
| P-001 | TCP Listener | M-001 | LimitListener, loopback-default |
| P-002 | HTTP Request Parser | M-001 | read-timeout, http-parser-validation |
| P-003 | Hop-by-Hop Sanitizer | M-001 | rfc9110-compliance, te-cl-conflict-resolution |
| P-004 | Loop Detector | M-001 | random-pseudonym, via-check-before-sanitize |
| P-005 | SPNEGO Token Injector | M-001 | circuit-breaker, error-classification |
| P-006 | CONNECT Tunnel Handler | M-001 | port-whitelist, 2xx-gate |
| P-007 | Response Validator | M-001 | content-length-validation, te-cl-conflict |
| P-008 | gokrb5 Auth Provider | M-003 | mutex, password-file-permission-check |
| P-009 | GSS-API Auth Provider | M-004 | mutex, startup-credential-probe |
| P-010 | Circuit Breaker | M-006 | failure-threshold, cooldown-timeout |

## Data Stores

| ID | Name | Sensitivity | Controls |
|----|------|-------------|----------|
| DS-001 | Password File | HIGH | Permission check (0077), 4KB limit |
| DS-002 | krb5.conf | MEDIUM | Operator-supplied path |
| DS-003 | Process Memory (Password) | HIGH | None (Go string immutability limitation) |
| DS-004 | Circuit Breaker State | LOW | In-memory only |

## Data Flow Diagram (ASCII)

```
                                 ┌─────────────────────────────────────────────────────┐
                                 │              TRUST BOUNDARY: Network                 │
   ┌──────────┐  DF-001 (HTTP)   │  ┌─────────┐  DF-002  ┌─────────┐  DF-003          │
   │ EI-001   │─────────────────────│ P-002   │─────────│ P-003   │─────────┐         │
   │ Client   │                  │  │ Parser  │         │Sanitizer│         │         │
   └──────────┘◄─────────────────── └─────────┘         └─────────┘         │         │
     ▲         DF-006 (Response) │      │                                    ▼         │
     │                           │  ┌───┴─────┐                        ┌─────────┐    │
     │                           │  │ P-004   │                        │ P-005   │    │
     │                           │  │ Loop    │                        │ Token   │    │
     │                           │  │Detector │                        │Injector │    │
     │                           │  └─────────┘                        └────┬────┘    │
     │                           │                                          │         │
     │  DF-013/014 (Tunnel)      │  ┌─────────┐     DF-004 (Auth'd)       │         │
     │◄ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ P-006   │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ▼ ─ ─ ─ ─│─ ─ ─►┌──────────┐
     │                           │  │CONNECT  │                                     │      │ EI-002   │
     │                           │  │ Tunnel  │◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ │ Upstream │
     │                           │  └─────────┘     DF-005 (Response)               │      └──────────┘
     │                           │                       │                           │
     │                           │                  ┌────┴────┐                      │
     │◄──────────────────────────── DF-006          │ P-007   │                      │
     │                           │                  │Response │                      │
     │                           │                  │Validator│                      │
     │                           │                  └─────────┘                      │
     │                           └───────────────────────────────────────────────────┘
     │
     │                           ┌─────────────────────────────────────────────────────┐
     │                           │           TRUST BOUNDARY: Kerberos/OS               │
     │                           │                                                     │
     │                           │  ┌─────────┐  DF-009    ┌──────────┐               │
     │                           │  │ P-008   │───────────│ EI-003   │               │
     │                           │  │ gokrb5  │           │   KDC    │               │
     │                           │  └────┬────┘           └──────────┘               │
     │                           │       │ DF-007                                     │
     │                           │  ┌────┴────┐                                       │
     │                           │  │ DS-001  │  Password File                        │
     │                           │  └─────────┘                                       │
     │                           │                                                     │
     │                           │  ┌─────────┐  DF-010    ┌──────────┐               │
     │                           │  │ P-009   │───────────│ EI-004   │               │
     │                           │  │ GSS-API │           │ macOS CC │               │
     │                           │  └─────────┘           └──────────┘               │
     │                           └─────────────────────────────────────────────────────┘
```

## Data Flow Findings

### F-P2-001: Raw relay bypasses response validation (MEDIUM)
When upstream sends an unparseable HTTP response, the proxy falls back to raw `io.Copy` (main.go:540), bypassing Content-Length validation and Via header injection.

### F-P2-002: SPNEGO token sent in cleartext to upstream (MEDIUM)
The `Proxy-Authorization: Negotiate` header containing the SPNEGO token is sent over plain TCP to the upstream proxy (main.go:656). A network observer can intercept tokens.

### F-P2-003: Client-facing listener has no TLS (LOW)
Client connections are plain HTTP. Mitigated by default loopback binding (127.0.0.1:8080).
