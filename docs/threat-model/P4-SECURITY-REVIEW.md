# P4: Security Design Review - SPNEGO-PROXY

## Executive Summary

- **Domains Assessed**: 11 (10 core + 1 extended)
- **Fully Compliant**: 3 (OUTPUT, ERROR, SUPPLY)
- **Partially Compliant**: 5 (AUTHN, AUTHZ, INPUT, CRYPTO, LOG, DATA)
- **Not Applicable**: 8 (CLIENT, API, INFRA, AI, MOBILE, CLOUD, AGENT)
- **Total Gaps**: 8
- **High Gaps**: 2
- **Medium Gaps**: 4
- **Low Gaps**: 2

## Security Design Assessment Matrix

| Domain | Code | Implementation | Rating | Gaps | Risk | Reference |
|--------|------|----------------|--------|------|------|-----------|
| Authentication | AUTHN | SPNEGO to upstream; no client auth | Partial | 1 | HIGH | control-set-01 |
| Authorization | AUTHZ | CONNECT port whitelist (off by default) | Partial | 1 | MEDIUM | control-set-02 |
| Input Validation | INPUT | HTTP parser, hop-by-hop sanitize, TE/CL | Partial | 1 | MEDIUM | control-set-03 |
| Output Encoding | OUTPUT | CL validation, Via inject, Proxy-Auth strip | Yes | 0 | LOW | control-set-04 |
| Client-Side | CLIENT | N/A (not a web app) | N/A | 0 | N/A | - |
| Cryptography | CRYPTO | Kerberos encryption; no TLS transport | Partial | 3 | HIGH | control-set-06 |
| Logging | LOG | JSON slog; no security event classification | Partial | 1 | MEDIUM | control-set-07 |
| Error Handling | ERROR | RFC 9209 Proxy-Status; no stack leaks | Yes | 0 | LOW | control-set-08 |
| API Security | API | N/A (TCP proxy) | N/A | 0 | N/A | - |
| Data Protection | DATA | File perms 0600; password in memory | Partial | 1 | MEDIUM | control-set-10 |
| Infrastructure | INFRA | N/A | N/A | 0 | N/A | - |
| Supply Chain | SUPPLY | go.mod/go.sum; minimal deps | Yes | 0 | LOW | - |
| AI/LLM | AI | N/A | N/A | 0 | N/A | - |
| Mobile | MOBILE | N/A | N/A | 0 | N/A | - |
| Cloud | CLOUD | N/A | N/A | 0 | N/A | - |
| Agentic | AGENT | N/A | N/A | 0 | N/A | - |

## Gap Analysis

### GAP-001: No Client Authentication (HIGH)
- **Domain**: AUTHN
- **Current**: Any TCP connection to the listener gets authenticated proxy access
- **Expected**: Client authentication or IP-based access control
- **Impact**: Unauthorized use of operator's Kerberos identity
- **Mitigation**: Default loopback binding; document as deployment requirement

### GAP-002: No TLS Transport (HIGH)
- **Domain**: CRYPTO
- **Current**: Plain TCP for all connections
- **Expected**: TLS for proxy-upstream at minimum
- **Impact**: SPNEGO token interception on network

### GAP-003: Password in Memory (MEDIUM)
- **Domain**: DATA
- **Current**: Go string immutability prevents password zeroing
- **Expected**: Keytab-based auth or zeroable storage

### GAP-004: Raw Relay Bypasses Validation (MEDIUM)
- **Domain**: INPUT
- **Current**: Unparseable responses relayed raw
- **Expected**: Reject with 502 or basic validation

### GAP-005: Open CONNECT Ports (MEDIUM)
- **Domain**: AUTHZ
- **Current**: All ports allowed by default
- **Expected**: Restrictive default port whitelist

### GAP-006: No Security Event Classification (MEDIUM)
- **Domain**: LOG
- **Current**: General structured logging
- **Expected**: Security event taxonomy and integrity

### GAP-007: Entropy Fallback (LOW)
- **Domain**: CRYPTO
- **Current**: Timestamp fallback on crypto/rand failure
- **Expected**: Fatal error on entropy source failure

### GAP-008: PAFXFAST Disabled (LOW)
- **Domain**: CRYPTO
- **Current**: Compatibility override
- **Expected**: Enable when KDC supports it

## Positive Security Controls

The codebase demonstrates strong security awareness:
1. **Request smuggling defenses**: TE/CL conflict resolution per RFC 9112 §6.1, plus per-request re-validation of pipelined HTTP requests on persistent connections (v1.2.5) closing the buffered-bytes vector on the SPNEGO-authenticated upstream socket
2. **Hop-by-hop sanitization**: Full RFC 9110 compliance
3. **Loop detection**: Random pseudonym checked before hop-by-hop stripping
4. **Circuit breaker**: Prevents account lockout cascading
5. **Password file permissions**: Strict 0600 enforcement
6. **Connection limits**: LimitListener prevents resource exhaustion
7. **Structured errors**: RFC 9209 Proxy-Status with no information leakage
8. **CGo safety**: Bounds-checked buffers, NULL checks, proper cleanup
