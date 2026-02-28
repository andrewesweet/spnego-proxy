# P3: Trust Boundary Evaluation - SPNEGO-PROXY

## Boundary Summary

| Boundary | Type | Description | Crossing Flows | Risk |
|----------|------|-------------|----------------|------|
| TB-001 | Network | Client-Proxy | DF-001, DF-006, DF-013, DF-014, DF-017 | HIGH |
| TB-002 | Network | Proxy-Upstream | DF-004, DF-005, DF-013, DF-014, DF-017 | MEDIUM |
| TB-003 | Process | Go-C (CGo) | DF-010 | LOW |
| TB-004 | Data | Proxy-OS Credentials | DF-007, DF-008, DF-010, DF-018 | MEDIUM |
| TB-005 | Network | Proxy-KDC | DF-009 | LOW |

## Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Trust Boundary Diagram: SPNEGO-PROXY                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ╔═══════════════════════════════════════════════════════════════════════╗  │
│  ║ TB-001: Client-Proxy Network Boundary                   [HIGH RISK]  ║  │
│  ╠═══════════════════════════════════════════════════════════════════════╣  │
│  ║                                                                       ║  │
│  ║  ┌──────────┐   DF-001        ┌─────────────────────────────────┐   ║  │
│  ║  │ EI-001   │───[No Auth]───►│ P-001 TCP Listener              │   ║  │
│  ║  │ Client   │◄──[No TLS]────│ P-002 Parser → P-003 Sanitizer  │   ║  │
│  ║  │(Untrusted)│   DF-006       │ P-004 Loop → P-005 Token Inject│   ║  │
│  ║  └──────────┘   DF-013/014   │ P-006 CONNECT → P-007 Response │   ║  │
│  ║                 [Tunnel]      │ P-010 Circuit Breaker           │   ║  │
│  ║                               └──────────┬──────────────────────┘   ║  │
│  ╚══════════════════════════════════════════╪════════════════════════════╝  │
│                                              │                              │
│  ╔══════════════════════════════════════════╪════════════════════════════╗  │
│  ║ TB-002: Proxy-Upstream Network Boundary  │              [MEDIUM RISK] ║  │
│  ╠══════════════════════════════════════════╪════════════════════════════╣  │
│  ║                                          │ DF-004 [SPNEGO+Sanitized]  ║  │
│  ║                                          ▼                            ║  │
│  ║                                    ┌──────────┐                       ║  │
│  ║                                    │ EI-002   │                       ║  │
│  ║                                    │ Upstream │                       ║  │
│  ║                                    │  Proxy   │                       ║  │
│  ║                                    └──────────┘                       ║  │
│  ╚═══════════════════════════════════════════════════════════════════════╝  │
│                                                                             │
│  ╔═══════════════════════════════════════════════════════════════════════╗  │
│  ║ TB-004: Proxy-OS Credential Boundary                    [MEDIUM]     ║  │
│  ╠═══════════════════════════════════════════════════════════════════════╣  │
│  ║                                                                       ║  │
│  ║  ┌─────────┐  DF-007    ┌─────────┐  DF-009    ┌──────────┐        ║  │
│  ║  │ DS-001  │──[0600]──►│ P-008   │──[Kerb]──►│ EI-003   │        ║  │
│  ║  │Password │           │ gokrb5  │           │   KDC    │        ║  │
│  ║  │  File   │           └─────────┘           └──────────┘        ║  │
│  ║  └─────────┘                                   TB-005 ▲           ║  │
│  ║                                                                       ║  │
│  ║  ┌─────────┐  DF-010    ┌──────────┐                                ║  │
│  ║  │ P-009   │──[CGo]───►│ EI-004   │                                ║  │
│  ║  │ GSS-API │           │ macOS CC │                                ║  │
│  ║  └─────────┘  TB-003   └──────────┘                                ║  │
│  ╚═══════════════════════════════════════════════════════════════════════╝  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Assessment Matrix

| Boundary | Crossing Flows | Auth | Encryption | Validation | Risk |
|----------|----------------|------|------------|------------|------|
| TB-001 | DF-001, DF-006, DF-013/014, DF-017 | None | None (loopback) | HTTP parser, timeout | HIGH |
| TB-002 | DF-004, DF-005, DF-013/014, DF-017 | SPNEGO | None (plain TCP) | CL validation, sanitize | MEDIUM |
| TB-003 | DF-010 | N/A | N/A | NULL checks, bounds | LOW |
| TB-004 | DF-007, DF-008, DF-010, DF-018 | OS perms | None | 0600 check, 4KB limit | MEDIUM |
| TB-005 | DF-009 | Kerberos pre-auth | Kerberos encryption | Protocol validation | LOW |

## Boundary Findings

### F-P3-001: No client authentication at TB-001 (HIGH)
Any process reaching the listener port receives authenticated upstream access. Default loopback binding mitigates, but risk is HIGH if rebound to a network interface.

### F-P3-002: No encryption at TB-001 or TB-002 (MEDIUM)
SPNEGO tokens and request data travel in cleartext. Acceptable for loopback; concern for proxy-upstream on untrusted networks.

### F-P3-003: Raw relay bypasses TB-002 response validation (MEDIUM)
Unparseable upstream responses bypass Content-Length validation and Via injection through raw io.Copy fallback.

### F-P3-004: CONNECT tunnel default allows all ports (MEDIUM)
Without `-connect-ports`, any port can be tunneled through the authenticated upstream connection.

## Recommendations

1. Document loopback-only deployment as a security requirement
2. Recommend `-connect-ports 443` as a secure default configuration
3. Consider adding TLS support for proxy-upstream connections in future
4. The CGo boundary (TB-003) is well-defended with bounds-checked buffers
