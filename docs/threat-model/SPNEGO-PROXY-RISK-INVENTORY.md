# SPNEGO-PROXY Risk Inventory

**Generated**: 2026-02-28T22:45:00Z
**Skill Version**: 3.0.3 (20260209a)
**Assessment Scope**: /home/sweeand/andrewesweet/spnego-proxy

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Validated Risks | 13 |
| Critical (P0) | 0 |
| High (P1) | 2 |
| Medium (P2) | 8 |
| Low (P3) | 3 |
| Average CVSS | 5.31 |
| Verified (POC available) | 5 |
| Theoretical | 8 |

## Complete Risk Inventory Table

| VR-ID | Title | STRIDE | Severity | CVSS | Vector | Status | CWE | Priority | Mitigation |
|-------|-------|--------|----------|------|--------|--------|-----|----------|------------|
| VR-001 | No Client Authentication | S, E | HIGH | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | Verified | CWE-287 | P1 | MIT-001 |
| VR-002 | SPNEGO Token Exposure on Plaintext Network | I, S | HIGH | 7.1 | AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N | Verified | CWE-319 | P1 | MIT-002 |
| VR-003 | Password Retained in Process Memory | I, E | MEDIUM | 5.5 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | Verified | CWE-316 | P2 | MIT-003 |
| VR-004 | Raw Relay Bypasses Response Validation | T, I, E, D | MEDIUM | 5.3 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L | Verified | CWE-20 | P2 | MIT-004 |
| VR-005 | CONNECT Tunnel to Arbitrary Ports | S, E, D | MEDIUM | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N | Verified | CWE-284 | P2 | MIT-005 |
| VR-006 | No Idle Timeout on Bidirectional Forwarding | D | MEDIUM | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | Theoretical | CWE-400 | P2 | MIT-006 |
| VR-007 | Entropy Fallback Weakens Loop Detection | S, T, D | LOW | 3.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N | Theoretical | CWE-330 | P3 | MIT-007 |
| VR-008 | Request Smuggling via TE/CL Conflict | T | MEDIUM | 5.9 | AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N | Theoretical (Mitigated) | CWE-444 | P2 | MIT-008 |
| VR-009 | Kerberos Configuration Tampering | T, S | MEDIUM | 5.3 | AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | Theoretical | CWE-15 | P2 | MIT-009 |
| VR-010 | Circuit Breaker Weaponization | S, D | MEDIUM | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | Theoretical | CWE-400 | P2 | MIT-010 |
| VR-011 | CGo Boundary Memory Safety | T | MEDIUM | 5.0 | AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H | Theoretical | CWE-120 | P2 | MIT-011 |
| VR-012 | Insufficient Security Event Logging | R | LOW | 3.1 | AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N | Theoretical | CWE-778 | P3 | MIT-012 |
| VR-013 | KRB5CCNAME Environment Variable Manipulation | S | MEDIUM | 5.0 | AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N | Theoretical | CWE-426 | P2 | MIT-013 |

---

## Risk Listing

### VR-001: No Client Authentication - Kerberos Credential Delegation

- **Priority**: P1
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- **STRIDE**: S, E
- **CWE**: CWE-287 (Improper Authentication)
- **CAPEC**: CAPEC-151
- **Location**: main.go:572 (handleClient)
- **DFD Elements**: P-001, P-005, EI-001
- **Trust Boundary**: TB-001 (Client-Proxy)
- **Description**: Any process that can reach the proxy listener inherits the operator's Kerberos identity for all upstream requests. Default loopback binding (127.0.0.1:8080) mitigates this to same-host processes, but if the operator rebinds to 0.0.0.0 or a network interface, remote hosts gain full authenticated proxy access.
- **Root Cause**: Design decision -- the proxy is a transparent credential injector, not an authenticating proxy.
- **Threat Refs**: T-S-P-001-001, T-E-P-001-001, T-E-P-005-001, T-S-EI-001-001
- **Finding Refs**: F-P1-001, F-P3-001, GAP-001
- **Validation**: Verified -- any curl command through the proxy authenticates with operator credentials
- **Mitigation**: MIT-001 (Implement client access control on listener)
- **Attack Chains**: AC-002 (entry point)

---

### VR-002: SPNEGO Token Exposure on Plaintext Network

- **Priority**: P1
- **CVSS**: 7.1 (CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)
- **STRIDE**: I, S
- **CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
- **CAPEC**: CAPEC-157
- **Location**: main.go:656
- **DFD Elements**: P-005, DF-004
- **Trust Boundary**: TB-002 (Proxy-Upstream)
- **Description**: The Proxy-Authorization: Negotiate header containing the base64-encoded SPNEGO token is sent over plain TCP between the proxy and the upstream proxy. A network observer on this path can capture the token.
- **Root Cause**: No TLS support for proxy-upstream connections.
- **Threat Refs**: T-I-P-005-001, T-I-DF-004-001, T-S-P-005-001
- **Finding Refs**: F-P2-002, F-P3-002, GAP-002
- **Validation**: Verified -- tcpdump on proxy-upstream network path captures Proxy-Authorization header
- **Mitigation**: MIT-002 (Add TLS support for proxy-upstream connections)
- **Attack Chains**: AC-001 (token capture step)

---

### VR-003: Password Retained in Process Memory

- **Priority**: P2
- **CVSS**: 5.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **STRIDE**: I, E
- **CWE**: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- **CAPEC**: CAPEC-157
- **Location**: auth_gokrb5.go:101 (NewGokrb5TokenProvider)
- **DFD Elements**: P-008, DS-003
- **Trust Boundary**: TB-004 (Proxy-OS Credentials)
- **Description**: The gokrb5 client stores the Kerberos password as an immutable Go string for the lifetime of the process. Memory dumps or core files could expose the password.
- **Root Cause**: Go language limitation -- strings are immutable and cannot be reliably zeroed.
- **Threat Refs**: T-I-P-008-001, T-I-DS-003-001, T-E-P-008-001
- **Finding Refs**: F-P1-002, GAP-003
- **Validation**: Verified -- strings command on core dump reveals password
- **Mitigation**: MIT-003 (Use zeroable byte slice for password storage)

---

### VR-004: Raw Relay Bypasses Response Validation

- **Priority**: P2
- **CVSS**: 5.3 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)
- **STRIDE**: T, I, E, D
- **CWE**: CWE-20 (Improper Input Validation)
- **CAPEC**: CAPEC-248
- **Location**: main.go:540
- **DFD Elements**: P-007, DF-017
- **Trust Boundary**: TB-002 (Proxy-Upstream)
- **Description**: When upstream responses cannot be parsed by http.ReadResponse, the proxy falls back to raw io.Copy relay, bypassing Content-Length validation, Via header injection, and Proxy-Auth stripping.
- **Root Cause**: Design trade-off for compatibility with non-standard upstream responses.
- **Threat Refs**: T-T-DF-017-001, T-I-DF-017-001, T-E-P-007-001, T-D-DF-017-001
- **Finding Refs**: F-P1-012, F-P2-001, F-P3-003, GAP-004
- **Validation**: Verified -- upstream sending HTTP/0.9-style response triggers raw relay path
- **Mitigation**: MIT-004 (Reject unparseable upstream responses with 502)

---

### VR-005: CONNECT Tunnel to Arbitrary Ports

- **Priority**: P2
- **CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)
- **STRIDE**: S, E, D
- **CWE**: CWE-284 (Improper Access Control)
- **CAPEC**: CAPEC-219
- **Location**: main.go:609
- **DFD Elements**: P-006, DF-013
- **Trust Boundary**: TB-001 (Client-Proxy)
- **Description**: Without -connect-ports configuration, the proxy tunnels CONNECT requests to any port through the authenticated upstream connection, enabling lateral movement.
- **Root Cause**: Default configuration is permissive -- -connect-ports is empty by default.
- **Threat Refs**: T-S-P-006-001, T-E-P-006-001, T-E-P-002-001, T-D-P-006-001
- **Finding Refs**: F-P1-006, F-P3-004, GAP-005
- **Validation**: Verified -- curl -x localhost:8080 --connect-to ::internal-host:22: succeeds
- **Mitigation**: MIT-005 (Set restrictive default CONNECT port whitelist)
- **Attack Chains**: AC-002 (tunnel step)

---

### VR-006: No Idle Timeout on Bidirectional Forwarding

- **Priority**: P2
- **CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **STRIDE**: D
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **CAPEC**: CAPEC-227
- **Location**: main.go (P-006, DF-013)
- **Trust Boundary**: TB-001
- **Description**: CONNECT tunnels and bidirectional forwarding have no idle timeout. Established tunnels persist until one side closes, consuming connection slots from the 512 LimitListener pool.
- **Threat Refs**: T-D-P-006-001, T-D-DF-013-001
- **Finding Refs**: F-P1-013
- **Validation**: Theoretical -- code review confirms no idle timeout
- **Mitigation**: MIT-006 (Add idle timeout to CONNECT tunnels)

---

### VR-007: Entropy Fallback Weakens Loop Detection

- **Priority**: P3
- **CVSS**: 3.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)
- **STRIDE**: S, T, D
- **CWE**: CWE-330 (Use of Insufficiently Random Values)
- **CAPEC**: CAPEC-151
- **Location**: main.go:92 (randomHex)
- **DFD Elements**: P-004
- **Description**: If crypto/rand fails, randomHex falls back to time.Now().UnixNano()&0xffffffff, producing a predictable 32-bit Via pseudonym.
- **Root Cause**: Defensive fallback to timestamp instead of fatal error.
- **Threat Refs**: T-S-P-004-001, T-T-P-004-001, T-D-P-004-001
- **Finding Refs**: F-P1-009, GAP-007
- **Validation**: Theoretical -- code review of randomHex fallback path
- **Mitigation**: MIT-007 (Fail fatally on crypto/rand failure)

---

### VR-008: Request Smuggling via TE/CL Conflict

- **Priority**: P2
- **CVSS**: 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N)
- **STRIDE**: T
- **CWE**: CWE-444 (HTTP Request/Response Smuggling)
- **CAPEC**: CAPEC-33
- **Location**: main.go (P-002, P-007)
- **Trust Boundary**: TB-001
- **Description**: The proxy implements TE/CL conflict resolution per RFC 9112. This is the correct defense, but novel smuggling variants could potentially bypass it.
- **Threat Refs**: T-T-P-002-001, T-T-P-007-001
- **Finding Refs**: F-P1-005
- **Validation**: Theoretical (Mitigated) -- code implements RFC 9112 defenses; no known bypass found
- **Mitigation**: MIT-008 (Harden request smuggling defenses with monitoring)

---

### VR-009: Kerberos Configuration Tampering

- **Priority**: P2
- **CVSS**: 5.3 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **STRIDE**: T, S
- **CWE**: CWE-15 (External Control of System or Configuration Setting)
- **CAPEC**: CAPEC-248
- **Location**: auth_gokrb5.go (P-008, DS-002, EI-003)
- **Trust Boundary**: TB-005 (Proxy-Config Files)
- **Description**: Attacker with filesystem access modifies krb5.conf to redirect authentication to a rogue KDC, capturing credential material.
- **Threat Refs**: T-T-P-008-001, T-T-DS-002-001, T-S-EI-003-001
- **Finding Refs**: GAP-008
- **Validation**: Theoretical -- requires filesystem write access to krb5.conf path
- **Mitigation**: MIT-009 (Add krb5.conf integrity verification)

---

### VR-010: Circuit Breaker Weaponization

- **Priority**: P2
- **CVSS**: 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **STRIDE**: S, D
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **CAPEC**: CAPEC-125
- **Location**: circuit_breaker.go (P-010, DS-004)
- **Description**: An attacker who can cause 3 consecutive auth failures can trip the circuit breaker, blocking all proxy traffic for 30 seconds. Repeating creates sustained DoS.
- **Threat Refs**: T-S-P-010-001, T-D-P-010-001, T-D-DS-004-001
- **Validation**: Theoretical -- code review confirms shared circuit breaker with 3-failure threshold
- **Mitigation**: MIT-010 (Add circuit breaker abuse detection)

---

### VR-011: CGo Boundary Memory Safety

- **Priority**: P2
- **CVSS**: 5.0 (CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H)
- **STRIDE**: T
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **CAPEC**: CAPEC-100
- **Location**: gss_darwin.c, auth_gss_darwin.go (P-009, DF-010)
- **Trust Boundary**: TB-003 (Go-C CGo Boundary)
- **Description**: The C code uses a fixed 256-byte error_msg buffer with bounds-checked writes. Token data uses malloc/free with NULL checks. The code appears correct, but any bug in the C layer could corrupt Go memory.
- **Threat Refs**: T-T-P-009-001, T-T-DF-010-001
- **Finding Refs**: F-P1-004
- **Validation**: Theoretical -- code review confirms bounds checking; no vulnerability found
- **Mitigation**: MIT-011 (Add CGo boundary assertions and fuzzing)

---

### VR-012: Insufficient Security Event Logging

- **Priority**: P3
- **CVSS**: 3.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)
- **STRIDE**: R
- **CWE**: CWE-778 (Insufficient Logging)
- **CAPEC**: CAPEC-93
- **Location**: main.go (P-001, P-005)
- **Description**: While the proxy has good structured JSON logging, there is no security event classification, no log integrity protection, and all localhost clients appear as 127.0.0.1. This limits forensic capability.
- **Threat Refs**: T-R-P-001-001, T-R-P-005-001
- **Finding Refs**: GAP-006
- **Validation**: Theoretical
- **Mitigation**: MIT-012 (Add structured security event logging)

---

### VR-013: KRB5CCNAME Environment Variable Manipulation

- **Priority**: P2
- **CVSS**: 5.0 (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N)
- **STRIDE**: S
- **CWE**: CWE-426 (Untrusted Search Path)
- **CAPEC**: CAPEC-151
- **Location**: auth_gss_darwin.go (P-009, EI-004)
- **Trust Boundary**: TB-004 (Proxy-OS Credentials)
- **Description**: An attacker who can set the KRB5CCNAME environment variable for the proxy process could redirect credential cache access to their own cache, causing the proxy to authenticate with attacker-chosen credentials.
- **Threat Refs**: T-S-P-009-001, T-S-EI-004-001
- **Validation**: Theoretical -- requires root or same-UID access to set env var
- **Mitigation**: MIT-013 (Validate KRB5CCNAME environment variable)

---

## Exclusion Summary

71 threats from P5 were excluded from validation:

| Reason | Count |
|--------|-------|
| In-process data flow (no network exposure) | 28 |
| Mitigated by existing code controls | 15 |
| Theoretical repudiation (logging adequate for use case) | 12 |
| Low-impact information disclosure (public data) | 9 |
| Duplicate of higher-priority threat | 7 |

---

*Generated by Threat Modeling Skill v3.0.3 (20260209a)*
