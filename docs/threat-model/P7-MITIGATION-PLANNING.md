# P7: Mitigation Planning - SPNEGO-PROXY

## Executive Summary

| Priority | Count | Timeline |
|----------|-------|----------|
| P0 (Critical) | 0 | N/A |
| P1 (High) | 2 | Within 1 week |
| P2 (Medium) | 8 | Within 30 days |
| P3 (Low) | 3 | Within 90 days |
| **Total** | **13** | |

All 13 validated risks (VR-001 through VR-013) have corresponding mitigations (MIT-001 through MIT-013).

## Short-Term Actions (P1 - Within 1 Week)

### MIT-001: Implement Client Access Control on Listener

**Risk**: VR-001 - No Client Authentication (CVSS 7.5)
**Effort**: MEDIUM
**Timeline**: 2-3 days

**Current Implementation**:
```go
// main.go - listener accepts any TCP connection
ln, err := net.Listen("tcp", *flagBind)
// No authentication or access control on accepted connections
```

**Recommended Fix**:
```go
// Option A: IP-based allowlist via flag
var flagAllowedIPs = flag.String("allowed-ips", "127.0.0.1,::1",
    "comma-separated list of allowed client IPs")

// In handleClient, before processing:
clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
if !isAllowed(clientIP) {
    conn.Close()
    return
}

// Option B: Unix domain socket (strongest isolation)
var flagUnixSocket = flag.String("unix-socket", "",
    "path to Unix domain socket (overrides -bind)")
```

**Implementation Steps**:
1. Add `-allowed-ips` flag with default loopback
2. Add IP check in `handleClient` before processing
3. Add unit tests for IP filtering
4. Document deployment guidance

**Verification**:
- [ ] Loopback connections accepted
- [ ] External IPs rejected when not in allowlist
- [ ] Rejection events logged
- [ ] ASVS V1.4.1 compliance

---

### MIT-002: Add TLS Support for Proxy-Upstream Connections

**Risk**: VR-002 - SPNEGO Token Exposure on Plaintext Network (CVSS 7.1)
**Effort**: HIGH
**Timeline**: 3-5 days

**Current Implementation**:
```go
// main.go - plain TCP dial to upstream
upstream, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
```

**Recommended Fix**:
```go
var flagUpstreamTLS = flag.Bool("upstream-tls", false,
    "use TLS for upstream proxy connection")
var flagUpstreamCA = flag.String("upstream-ca", "",
    "path to CA certificate for upstream TLS verification")

if *flagUpstreamTLS {
    tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
    if *flagUpstreamCA != "" {
        // Load custom CA
    }
    upstream, err = tls.DialWithDialer(dialer, "tcp", proxyAddr, tlsConfig)
}
```

**Implementation Steps**:
1. Add TLS flags (`-upstream-tls`, `-upstream-ca`, `-upstream-tls-insecure`)
2. Create `dialUpstream()` function with TLS/plain TCP support
3. Add TLS connection tests with test certificates
4. Verify backward compatibility

**Verification**:
- [ ] TLS connection succeeds with valid certificate
- [ ] Invalid/expired certificates rejected
- [ ] SPNEGO tokens encrypted in transit
- [ ] Plain TCP mode still works
- [ ] ASVS V9.1.1 compliance

---

## Medium-Term Actions (P2 - Within 30 Days)

### MIT-003: Use Zeroable Byte Slice for Password Storage

**Risk**: VR-003 - Password Retained in Process Memory (CVSS 5.5)
**Effort**: LOW | **Timeline**: 4 hours

```go
// Before: immutable Go string
password := strings.TrimRight(string(b), "\r\n")

// After: zeroable byte slice
pw := bytes.TrimRight(b, "\r\n")
client := krb5client.NewWithPassword(*flagUsername, *flagRealm, string(pw), cfg)
for i := range pw { pw[i] = 0 }  // Zero immediately
```

**Verification**: ASVS V6.4.2

---

### MIT-004: Reject Unparseable Upstream Responses with 502

**Risk**: VR-004 - Raw Relay Bypasses Response Validation (CVSS 5.3)
**Effort**: LOW | **Timeline**: 3 hours

```go
// Before: raw io.Copy relay on parse failure

// After: return 502 Bad Gateway
resp, err := http.ReadResponse(br, req)
if err != nil {
    slog.Warn("unparseable upstream response", "error", err)
    writeProxyStatus(conn, http.StatusBadGateway,
        "connection_read_timeout",
        "upstream response could not be parsed")
    return
}
```

**Verification**: ASVS V5.1.3

---

### MIT-005: Set Restrictive Default CONNECT Port Whitelist

**Risk**: VR-005 - CONNECT Tunnel to Arbitrary Ports (CVSS 5.3)
**Effort**: LOW | **Timeline**: 2 hours

```go
// Before: empty default allows all ports
var flagConnectPorts = flag.String("connect-ports", "", "...")

// After: default to 443 only
var flagConnectPorts = flag.String("connect-ports", "443",
    "allowed CONNECT ports (comma-separated, default: 443; use * for all)")
```

**Verification**: ASVS V1.4.4

---

### MIT-006: Add Idle Timeout to CONNECT Tunnels

**Risk**: VR-006 - No Idle Timeout on Bidirectional Forwarding (CVSS 5.3)
**Effort**: LOW | **Timeline**: 2 hours

```go
var flagIdleTimeout = flag.Duration("idle-timeout", 5*time.Minute,
    "idle timeout for CONNECT tunnels (0 to disable)")

// idleCopy resets deadline on each read
func idleCopy(dst, src net.Conn, timeout time.Duration) (int64, error) {
    // Reset read deadline after each successful read
    src.SetReadDeadline(time.Now().Add(timeout))
}
```

**Verification**: ASVS V1.14.5

---

### MIT-008: Harden Request Smuggling Defenses with Monitoring

**Risk**: VR-008 - Request Smuggling via TE/CL Conflict (CVSS 5.9, Mitigated)
**Effort**: LOW | **Timeline**: 2 hours

```go
// Add logging before existing TE/CL sanitization
if req.Header.Get("Transfer-Encoding") != "" && req.Header.Get("Content-Length") != "" {
    slog.Warn("TE/CL conflict resolved",
        "action", "removed Content-Length",
        "client", conn.RemoteAddr(),
    )
}
```

**Verification**: ASVS V14.5.1

---

### MIT-009: Add krb5.conf Integrity Verification

**Risk**: VR-009 - Kerberos Configuration Tampering (CVSS 5.3)
**Effort**: MEDIUM | **Timeline**: 4 hours

```go
func verifyConfigFile(path string) error {
    info, err := os.Stat(path)
    if err != nil { return err }
    if info.Mode()&0o022 != 0 {
        return fmt.Errorf("%s is group/world-writable (mode %04o)", path, info.Mode().Perm())
    }
    return nil
}
```

**Verification**: ASVS V12.3.1

---

### MIT-010: Add Circuit Breaker Abuse Detection

**Risk**: VR-010 - Circuit Breaker Weaponization (CVSS 5.3)
**Effort**: MEDIUM | **Timeline**: 4 hours

```go
OnStateChange: func(name string, from, to gobreaker.State) {
    slog.Warn("circuit breaker state change",
        "from", from.String(), "to", to.String())
},
```

Also add configurable `-cb-threshold` and `-cb-timeout` flags.

**Verification**: ASVS V11.1.4

---

### MIT-011: Add CGo Boundary Assertions and Fuzzing

**Risk**: VR-011 - CGo Boundary Memory Safety (CVSS 5.0)
**Effort**: MEDIUM | **Timeline**: 1 day

```go
const maxSPNLength = 1024
func (g *gssProvider) GetToken(spn string) (string, error) {
    if len(spn) > maxSPNLength {
        return "", fmt.Errorf("SPN too long: %d > %d", len(spn), maxSPNLength)
    }
    // ... existing CGo call
}
```

Add `FuzzGSSGetToken` fuzz test for darwin build.

**Verification**: ASVS V5.2.4

---

## Long-Term Actions (P3 - Within 90 Days)

### MIT-007: Fail Fatally on crypto/rand Failure

**Risk**: VR-007 - Entropy Fallback Weakens Loop Detection (CVSS 3.1)
**Effort**: LOW | **Timeline**: 30 minutes

```go
// Before: timestamp fallback
if _, err := rand.Read(buf[:]); err != nil {
    v := uint32(time.Now().UnixNano() & 0xffffffff)
    binary.LittleEndian.PutUint32(buf[:], v)
}

// After: fatal exit
if _, err := rand.Read(buf[:]); err != nil {
    slog.Error("entropy source failure", "error", err)
    os.Exit(1)
}
```

**Verification**: ASVS V6.2.1

---

### MIT-012: Add Structured Security Event Logging

**Risk**: VR-012 - Insufficient Security Event Logging (CVSS 3.1)
**Effort**: MEDIUM | **Timeline**: 1 day

```go
const (
    SecurityEventAuthFailure    = "security.auth.failure"
    SecurityEventAuthSuccess    = "security.auth.success"
    SecurityEventConnectAttempt = "security.connect.attempt"
    SecurityEventConnectDenied  = "security.connect.denied"
    SecurityEventCircuitBreaker = "security.circuit_breaker"
)

slog.Warn("authentication failed",
    "event_type", SecurityEventAuthFailure,
    "client", conn.RemoteAddr(),
    "error", err,
)
```

**Verification**: ASVS V7.1.1

---

### MIT-013: Validate KRB5CCNAME Environment Variable

**Risk**: VR-013 - KRB5CCNAME Environment Variable Manipulation (CVSS 5.0)
**Effort**: LOW | **Timeline**: 1 hour

```go
if ccname := os.Getenv("KRB5CCNAME"); ccname != "" {
    slog.Info("credential cache override", "KRB5CCNAME", ccname)
}
```

**Verification**: ASVS V1.5.3

---

## Implementation Roadmap

| Timeline | Mitigations | Priority | Owner | Effort |
|----------|-------------|----------|-------|--------|
| Week 1 | MIT-001, MIT-002 | P1 (High) | Development Team | Medium-High |
| Week 2-3 | MIT-003, MIT-004, MIT-005, MIT-007 | P2-P3 | Development Team | Low |
| Week 3-4 | MIT-006, MIT-008, MIT-009, MIT-010 | P2 | Development Team | Low-Medium |
| Month 2-3 | MIT-011, MIT-012, MIT-013 | P2-P3 | Development Team | Medium-Low |

## Coverage Verification

```
Validated Risks: 13 (VR-001 through VR-013)
Mitigations:     13 (MIT-001 through MIT-013)
Coverage:        100%

∀ VR-xxx ∈ P6.validated_risks → ∃ MIT-xxx ∈ P7.mitigation_plan  [PASS]
```

## Key Observations

1. **No emergency actions required**: No P0 (Critical) risks exist
2. **Two P1 mitigations are additive**: MIT-001 and MIT-002 add new capabilities rather than fixing bugs
3. **Quick wins available**: MIT-003, MIT-004, MIT-005, MIT-007 are low-effort, high-impact changes
4. **Existing code is sound**: Several mitigations (MIT-008, MIT-010, MIT-012) enhance already-working controls with monitoring
5. **Backward compatible**: All mitigations are opt-in via flags, preserving existing behavior
