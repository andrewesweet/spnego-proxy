# P6: Risk Validation - SPNEGO-PROXY

## Executive Summary

| Metric | Count |
|--------|-------|
| P5 Threats Input | 109 |
| Verified Risks | 5 |
| Theoretical Risks | 33 |
| Pending Risks | 0 |
| Excluded | 71 |
| **Validated Risks (VR)** | **13** |

### Count Conservation

```
P5 Total = Verified + Theoretical + Pending + Excluded
109 = 5 + 33 + 0 + 71  [VERIFIED]
```

## Risk Severity Distribution

| Severity | Count | Validated Risks |
|----------|-------|-----------------|
| Critical | 0 | - |
| High | 5 | VR-001, VR-002 |
| Medium | 8 | VR-003 through VR-013 |
| Low | 0 | - |

## Validated Risks

### VR-001: No Client Authentication (HIGH)

- **Priority**: P1
- **CVSS**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Status**: Verified
- **Source Threats**: T-S-P-001-001, T-S-EI-001-001, T-E-P-005-001
- **Source Gaps**: GAP-001
- **CWE**: CWE-287 (Improper Authentication)

Any process that can reach the TCP listener (default 127.0.0.1:8080) obtains authenticated proxy access using the operator's Kerberos identity. No client authentication or access control mechanism restricts proxy usage.

**POC-001**: Connect to proxy and issue HTTP request; upstream receives request with operator's SPNEGO token regardless of client identity.

### VR-002: SPNEGO Token Exposure on Plaintext Network (HIGH)

- **Priority**: P1
- **CVSS**: 7.1 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **Status**: Verified
- **Source Threats**: T-I-P-005-001, T-I-DF-004-001, T-E-P-008-001
- **Source Gaps**: GAP-002
- **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)

All connections (client-to-proxy and proxy-to-upstream) use plain TCP. SPNEGO tokens in Proxy-Authorization headers are visible to network observers. If password-based auth is used, a compromised password grants full Kerberos identity.

**POC-002**: Network capture on proxy-upstream link reveals Proxy-Authorization header containing Base64-encoded SPNEGO token.

### VR-003: Password Retained in Process Memory (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **Status**: Verified
- **Source Threats**: T-I-DS-003-001, T-I-DS-003-002
- **Source Gaps**: GAP-003
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)

The Kerberos password is stored as an immutable Go string and cannot be zeroed after use. Memory dumps or core files could expose the password.

**POC-003**: Attach debugger or trigger core dump; scan process memory for password string.

### VR-004: Raw Relay Bypasses Response Validation (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Status**: Verified
- **Source Threats**: T-T-P-007-002, T-I-P-007-001
- **Source Gaps**: GAP-004
- **CWE**: CWE-20 (Improper Input Validation)

When upstream responses cannot be parsed by `http.ReadResponse`, the proxy falls back to raw `io.Copy` relay, bypassing Content-Length validation, Via header injection, and Proxy-Auth stripping.

**POC-004**: Upstream returns malformed HTTP response; proxy relays raw bytes without security header processing.

### VR-005: CONNECT Tunnel to Arbitrary Ports (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.3 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N)
- **Status**: Verified
- **Source Threats**: T-E-P-006-001, T-T-P-006-001
- **Source Gaps**: GAP-005
- **CWE**: CWE-284 (Improper Access Control)

When `-connect-ports` is empty (default), the proxy allows CONNECT tunnels to any port on any host through the upstream proxy, enabling potential lateral movement.

**POC-005**: Issue CONNECT request to internal host:port; proxy tunnels without restriction.

### VR-006: No Idle Timeout on Bidirectional Forwarding (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)
- **Status**: Theoretical
- **Source Threats**: T-D-P-006-002, T-D-P-001-002
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)

CONNECT tunnels and bidirectional forwarding have no idle timeout. Established tunnels persist until one side closes, consuming connection slots from the 512 LimitListener pool.

### VR-007: Entropy Fallback Weakens Loop Detection (LOW)

- **Priority**: P3
- **CVSS**: 3.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N)
- **Status**: Theoretical
- **Source Threats**: T-T-P-004-001, T-S-P-004-001
- **Source Gaps**: GAP-007
- **CWE**: CWE-330 (Use of Insufficiently Random Values)

If `crypto/rand` fails, `randomHex` falls back to `time.Now().UnixNano()&0xffffffff`, producing a predictable 32-bit Via pseudonym that could be guessed to bypass loop detection.

### VR-008: Request Smuggling via TE/CL Conflict (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Status**: Theoretical (Mitigated)
- **Source Threats**: T-T-P-002-001
- **CWE**: CWE-444 (HTTP Request/Response Smuggling)

The `sanitizeHopByHop` function resolves TE/CL conflicts per RFC 9112 by removing Content-Length when Transfer-Encoding is present. This is effectively mitigated but remains a theoretical risk if the sanitization logic is bypassed or modified.

### VR-009: Kerberos Configuration Tampering (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.3 (AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N)
- **Status**: Theoretical
- **Source Threats**: T-T-DS-002-001, T-I-DS-002-001
- **CWE**: CWE-15 (External Control of System or Configuration Setting)

The `krb5.conf` file and `KRB5_CONFIG` environment variable are trusted without integrity verification. A local attacker could redirect Kerberos authentication to a rogue KDC.

### VR-010: Circuit Breaker Weaponization (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H)
- **Status**: Theoretical
- **Source Threats**: T-D-P-010-001, T-D-P-010-002
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)

The circuit breaker (3 consecutive failures, 30s cooldown) can be deliberately triggered by a malicious client sending requests that cause authentication failures, denying proxy service to all clients.

### VR-011: CGo Boundary Memory Safety (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.0 (AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H)
- **Status**: Theoretical
- **Source Threats**: T-T-P-009-001, T-D-P-009-001
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)

The CGo boundary in `gss_darwin.c` uses fixed 256-byte error buffers. While bounds-checked with `snprintf`, a logic error could cause buffer overflow. The `malloc`/`free` pattern for token data requires correct lifecycle management.

### VR-012: Insufficient Security Event Logging (LOW)

- **Priority**: P3
- **CVSS**: 3.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N)
- **Status**: Theoretical
- **Source Threats**: T-R-P-001-001, T-R-P-005-001, T-R-P-006-001
- **Source Gaps**: GAP-006
- **CWE**: CWE-778 (Insufficient Logging)

The proxy uses structured JSON logging via `slog` but lacks security event classification, audit trails, and log integrity protection. Security-relevant events (auth failures, CONNECT attempts, circuit breaker trips) are not distinguished from operational logs.

### VR-013: KRB5CCNAME Environment Variable Manipulation (MEDIUM)

- **Priority**: P2
- **CVSS**: 5.0 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **Status**: Theoretical
- **Source Threats**: T-S-P-009-002, T-T-DS-004-001
- **CWE**: CWE-426 (Untrusted Search Path)

On macOS (GSS-API path), the `KRB5CCNAME` environment variable controls the credential cache location. A local attacker with the ability to set environment variables could redirect credential lookups.

## Attack Chains

### AC-001: Credential Harvesting Chain

```
Local Process Access (VR-001)
  --> Send HTTP request through proxy
  --> Proxy adds SPNEGO token (VR-002)
  --> Network observer captures token
  --> Token replay or offline analysis
```

- **Entry**: Any localhost process
- **Impact**: Kerberos credential exposure
- **Combined CVSS**: 8.1

### AC-002: Lateral Movement via CONNECT

```
Local Process Access (VR-001)
  --> CONNECT to internal:port (VR-005)
  --> Authenticated tunnel via upstream proxy
  --> Access internal services with operator identity
```

- **Entry**: Any localhost process
- **Impact**: Authenticated access to internal infrastructure
- **Combined CVSS**: 7.7

## POC Summary

| POC ID | Risk | Method | Feasibility |
|--------|------|--------|-------------|
| POC-001 | VR-001 | Direct TCP connection | High |
| POC-002 | VR-002 | Network packet capture | High |
| POC-003 | VR-003 | Memory dump analysis | Medium |
| POC-004 | VR-004 | Malformed HTTP response | Medium |
| POC-005 | VR-005 | CONNECT to arbitrary port | High |

## Exclusion Summary

71 threats were excluded from validation for the following reasons:

| Reason | Count |
|--------|-------|
| In-process data flow (no network exposure) | 28 |
| Mitigated by existing code controls | 15 |
| Theoretical repudiation (logging adequate for use case) | 12 |
| Low-impact information disclosure (public data) | 9 |
| Duplicate of higher-priority threat | 7 |

## Key Observations

1. **No Critical risks**: Strong existing security controls prevent the most severe scenarios
2. **Architectural decisions dominate**: The two HIGH risks (no client auth, no TLS) are design choices, not implementation bugs
3. **Effective mitigations exist**: Request/response smuggling are well-defended by existing code
4. **Attack chains amplify risk**: VR-001 (no client auth) is the entry point for both identified attack chains
5. **Theoretical risks are defensive in depth**: Most medium risks require local access or specific conditions
