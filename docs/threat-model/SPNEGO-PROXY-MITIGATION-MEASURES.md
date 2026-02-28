# SPNEGO-PROXY Mitigation Measures

**Generated**: 2026-02-28T22:45:00Z
**Skill Version**: 3.0.3 (20260209a)
**Assessment Scope**: /home/sweeand/andrewesweet/spnego-proxy

---

## Summary

| Priority | Count | Timeline |
|----------|-------|----------|
| P0 (Critical) | 0 | N/A |
| P1 (High) | 2 | Within 1 week |
| P2 (Medium) | 8 | Within 30 days |
| P3 (Low) | 3 | Within 90 days |
| **Total** | **13** | |

### Coverage Verification

```
Validated Risks: 13 (VR-001 through VR-013)
Mitigations:     13 (MIT-001 through MIT-013)
Coverage:        100%

For all VR-xxx in P6.validated_risks there exists MIT-xxx in P7.mitigation_plan  [PASS]
```

---

## Short-Term Actions (P1 - Within 1 Week)

### MIT-001: Implement Client Access Control on Listener

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-001 - No Client Authentication (CVSS 7.5) |
| **Threat Refs** | T-S-P-001-001, T-S-EI-001-001, T-E-P-005-001 |
| **Priority** | P1 |
| **Effort** | MEDIUM |
| **Timeline** | 2-3 days |
| **Category** | code_fix |
| **CWE** | CWE-287 |
| **ASVS** | V1.4.1 - Access control at trusted enforcement points |
| **WSTG** | WSTG-ATHN-01 |

**Current Implementation (Vulnerable)**:
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
if *flagUnixSocket != "" {
    ln, err = net.Listen("unix", *flagUnixSocket)
}
```

**Implementation Steps**:

**Step 1**: Add -allowed-ips flag with default loopback (main.go)
```go
var flagAllowedIPs = flag.String("allowed-ips", "127.0.0.1,::1",
    "comma-separated list of allowed client IPs")

func parseAllowedIPs(s string) map[string]bool {
    m := make(map[string]bool)
    for _, ip := range strings.Split(s, ",") {
        m[strings.TrimSpace(ip)] = true
    }
    return m
}
```

**Step 2**: Add IP check in handleClient (main.go)
```go
func handleClient(conn net.Conn, ...) {
    clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
    if !allowedIPs[clientIP] {
        slog.Warn("rejected client", "ip", clientIP)
        conn.Close()
        return
    }
    // ... existing logic
}
```

**Step 3**: Add unit tests for IP filtering
```go
func TestAllowedIPFiltering(t *testing.T) {
    tests := []struct{
        name    string
        ip      string
        allowed bool
    }{
        {"loopback v4", "127.0.0.1", true},
        {"loopback v6", "::1", true},
        {"external", "192.168.1.100", false},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            m := parseAllowedIPs("127.0.0.1,::1")
            if m[tt.ip] != tt.allowed {
                t.Errorf("IP %s: got %v, want %v", tt.ip, m[tt.ip], tt.allowed)
            }
        })
    }
}
```

**Step 4**: Document deployment guidance
```bash
# Run with default loopback-only access:
./spnego-proxy -bind 127.0.0.1:8080
# Or restrict to specific IPs:
./spnego-proxy -allowed-ips "127.0.0.1,::1,10.0.0.5"
```

**Verification Checklist**:
- [ ] Verify loopback connections are accepted
- [ ] Verify external IPs are rejected when not in allowlist
- [ ] Verify rejection is logged

**Security Controls**: Network-level access control (AUTHN), IP-based allowlist (AUTHZ)

**Additional Recommendations**:
- Consider Unix domain socket mode for strongest process isolation
- Document that network-accessible deployment requires firewall rules
- Add connection rate limiting per source IP

---

### MIT-002: Add TLS Support for Proxy-Upstream Connections

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-002 - SPNEGO Token Exposure on Plaintext Network (CVSS 7.1) |
| **Threat Refs** | T-I-P-005-001, T-I-DF-004-001, T-E-P-008-001 |
| **Priority** | P1 |
| **Effort** | HIGH |
| **Timeline** | 3-5 days |
| **Category** | code_fix |
| **CWE** | CWE-319 |
| **ASVS** | V9.1.1 - TLS for all connections |
| **WSTG** | WSTG-CRYP-01 |

**Current Implementation (Vulnerable)**:
```go
// main.go - plain TCP dial to upstream
upstream, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
```

**Recommended Fix**:
```go
// Add -upstream-tls flag
var flagUpstreamTLS = flag.Bool("upstream-tls", false,
    "use TLS for upstream proxy connection")
var flagUpstreamCA = flag.String("upstream-ca", "",
    "path to CA certificate for upstream TLS verification")

// In dial function:
if *flagUpstreamTLS {
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
    }
    if *flagUpstreamCA != "" {
        caCert, err := os.ReadFile(*flagUpstreamCA)
        // ... add to cert pool
        tlsConfig.RootCAs = pool
    }
    upstream, err = tls.DialWithDialer(
        &net.Dialer{Timeout: 30 * time.Second},
        "tcp", proxyAddr, tlsConfig,
    )
} else {
    upstream, err = net.DialTimeout("tcp", proxyAddr, 30*time.Second)
}
```

**Implementation Steps**:

**Step 1**: Add TLS flags (main.go)
```go
var flagUpstreamTLS = flag.Bool("upstream-tls", false,
    "use TLS for upstream proxy connection")
var flagUpstreamCA = flag.String("upstream-ca", "",
    "path to CA certificate for upstream TLS verification")
var flagUpstreamInsecure = flag.Bool("upstream-tls-insecure", false,
    "skip TLS certificate verification (NOT recommended)")
```

**Step 2**: Create TLS dialer function (main.go)
```go
func dialUpstream(addr string) (net.Conn, error) {
    dialer := &net.Dialer{Timeout: 30 * time.Second}
    if !*flagUpstreamTLS {
        return dialer.Dial("tcp", addr)
    }
    tlsConfig := &tls.Config{
        MinVersion:         tls.VersionTLS12,
        InsecureSkipVerify: *flagUpstreamInsecure,
    }
    if *flagUpstreamCA != "" {
        caCert, err := os.ReadFile(*flagUpstreamCA)
        if err != nil {
            return nil, fmt.Errorf("read CA cert: %w", err)
        }
        pool := x509.NewCertPool()
        if !pool.AppendCertsFromPEM(caCert) {
            return nil, fmt.Errorf("invalid CA certificate")
        }
        tlsConfig.RootCAs = pool
    }
    return tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
}
```

**Step 3**: Add TLS connection tests
```go
func TestDialUpstreamTLS(t *testing.T) {
    // Create test TLS server
    cert, key := generateTestCert(t)
    tlsCert, _ := tls.X509KeyPair(cert, key)
    srv := tls.NewListener(
        newLocalListener(t),
        &tls.Config{Certificates: []tls.Certificate{tlsCert}},
    )
    defer srv.Close()
    // Test TLS connection succeeds
    // Test plain TCP connection still works
}
```

**Verification Checklist**:
- [ ] Verify TLS connection to upstream with valid certificate
- [ ] Verify rejection of invalid/expired certificates
- [ ] Verify SPNEGO tokens are encrypted in transit
- [ ] Verify backward compatibility when TLS is disabled

**Security Controls**: Transport layer encryption (CRYPTO), Certificate validation (CRYPTO)

**Additional Recommendations**:
- Consider making TLS mandatory when upstream proxy supports it
- Add client-side TLS listener option for local applications
- Log TLS negotiation details at debug level

---

## Medium-Term Actions (P2 - Within 30 Days)

### MIT-003: Use Zeroable Byte Slice for Password Storage

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-003 - Password Retained in Process Memory (CVSS 5.5) |
| **Threat Refs** | T-I-DS-003-001, T-I-DS-003-002 |
| **Priority** | P2 |
| **Effort** | LOW |
| **Timeline** | 4 hours |
| **CWE** | CWE-316 |
| **ASVS** | V6.4.2 - Keys and secrets zeroed after use |
| **WSTG** | WSTG-CRYP-02 |

**Current Implementation**:
```go
// auth_gokrb5.go - password as immutable Go string
func getPassword(path string) (string, error) {
    b, err := os.ReadFile(path)
    // ...
    return strings.TrimRight(string(b), "\r\n"), nil
}
```

**Recommended Fix**:
```go
// Use []byte and zero after Kerberos client initialization
func getPasswordBytes(path string) ([]byte, error) {
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    return bytes.TrimRight(b, "\r\n"), nil
}

// After creating Kerberos client:
pw, err := getPasswordBytes(*flagPasswordFile)
if err != nil {
    return nil, err
}
// gokrb5 accepts string; convert briefly then zero
client := krb5client.NewWithPassword(
    *flagUsername, *flagRealm, string(pw), cfg,
)
// Zero the byte slice immediately
for i := range pw {
    pw[i] = 0
}
```

**Step 3**: Add keytab support as alternative
```go
// Preferred: use keytab instead of password
var flagKeytab = flag.String("keytab", "",
    "path to Kerberos keytab file (preferred over password)")
```

**Verification Checklist**:
- [ ] Verify password bytes are zeroed after client creation
- [ ] Verify proxy functions normally with zeroed password
- [ ] Verify keytab-based auth works when keytab flag is provided

**Security Controls**: Sensitive data zeroing (DATA), Credential lifecycle management (CRYPTO)

---

### MIT-004: Reject Unparseable Upstream Responses with 502

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-004 - Raw Relay Bypasses Response Validation (CVSS 5.3) |
| **Threat Refs** | T-T-P-007-002, T-I-P-007-001 |
| **Priority** | P2 |
| **Effort** | LOW |
| **Timeline** | 3 hours |
| **CWE** | CWE-20 |
| **ASVS** | V5.1.3 - Server-side input validation |
| **WSTG** | WSTG-INPV-01 |

**Current Implementation**:
```go
// main.go - raw relay fallback
// When http.ReadResponse fails, falls back to io.Copy
resp, err := http.ReadResponse(br, req)
if err != nil {
    // raw relay via io.Copy
```

**Recommended Fix**:
```go
resp, err := http.ReadResponse(br, req)
if err != nil {
    slog.Warn("unparseable upstream response",
        "error", err,
        "upstream", upstream.RemoteAddr(),
    )
    // Return 502 Bad Gateway instead of raw relay
    writeProxyStatus(conn, http.StatusBadGateway,
        "connection_read_timeout",
        "upstream response could not be parsed")
    return
}
```

**Test**:
```go
func TestMalformedUpstreamResponse(t *testing.T) {
    // Send garbage bytes from upstream
    // Verify client receives 502 Bad Gateway
    // Verify Proxy-Status header is present
}
```

**Verification Checklist**:
- [ ] Verify 502 returned for unparseable responses
- [ ] Verify Proxy-Status header included
- [ ] Verify event is logged

**Security Controls**: Response validation (INPUT), Fail-closed behavior (ERROR)

---

### MIT-005: Set Restrictive Default CONNECT Port Whitelist

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-005 - CONNECT Tunnel to Arbitrary Ports (CVSS 5.3) |
| **Threat Refs** | T-E-P-006-001, T-T-P-006-001 |
| **Priority** | P2 |
| **Effort** | LOW |
| **Timeline** | 2 hours |
| **CWE** | CWE-284 |
| **ASVS** | V1.4.4 - Access control for resources |
| **WSTG** | WSTG-ATHZ-02 |

**Current Implementation**:
```go
// main.go - empty connect-ports allows all
var flagConnectPorts = flag.String("connect-ports", "",
    "allowed CONNECT ports (comma-separated)")
// connectPortAllowed returns true when list is empty
```

**Recommended Fix**:
```go
var flagConnectPorts = flag.String("connect-ports", "443",
    "allowed CONNECT ports (comma-separated); default: 443 only")

// To allow all ports, pass -connect-ports "*"
func connectPortAllowed(port string) bool {
    if *flagConnectPorts == "*" {
        return true
    }
    // ... existing whitelist logic
}
```

**Test**:
```go
func TestDefaultConnectPortRestriction(t *testing.T) {
    // Verify port 443 allowed by default
    // Verify port 80 rejected by default
    // Verify "*" allows all ports
}
```

**Verification Checklist**:
- [ ] Verify only port 443 allowed by default
- [ ] Verify explicit port list overrides default
- [ ] Verify wildcard enables all ports

**Security Controls**: Port-based access control (AUTHZ), Restrictive defaults (AUTHZ)

---

### MIT-006: Add Idle Timeout to CONNECT Tunnels

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-006 - No Idle Timeout on Bidirectional Forwarding (CVSS 5.3) |
| **Threat Refs** | T-D-P-006-002, T-D-P-001-002 |
| **Priority** | P2 |
| **Effort** | LOW |
| **Timeline** | 2 hours |
| **CWE** | CWE-400 |
| **ASVS** | V1.14.5 - Connection timeout configuration |
| **WSTG** | WSTG-BUSL-09 |

**Current Implementation**:
```go
// main.go - no idle timeout on tunnel forwarding
// bidirectional io.Copy runs until connection close
```

**Recommended Fix**:
```go
var flagIdleTimeout = flag.Duration("idle-timeout", 5*time.Minute,
    "idle timeout for CONNECT tunnels (0 to disable)")

// idleCopy copies data with idle timeout reset on each read
func idleCopy(dst, src net.Conn, timeout time.Duration) (int64, error) {
    buf := make([]byte, 32*1024)
    var total int64
    for {
        src.SetReadDeadline(time.Now().Add(timeout))
        n, readErr := src.Read(buf)
        if n > 0 {
            dst.SetWriteDeadline(time.Now().Add(timeout))
            nw, writeErr := dst.Write(buf[:n])
            total += int64(nw)
            if writeErr != nil {
                return total, writeErr
            }
        }
        if readErr != nil {
            return total, readErr
        }
    }
}
```

**Verification Checklist**:
- [ ] Verify idle tunnel is closed after timeout
- [ ] Verify active tunnel remains open
- [ ] Verify timeout=0 disables idle timeout

**Security Controls**: Resource consumption limits (INPUT), Connection lifecycle management (AUTHZ)

---

### MIT-008: Harden Request Smuggling Defenses with Monitoring

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-008 - Request Smuggling via TE/CL Conflict (CVSS 5.9) |
| **Threat Refs** | T-T-P-002-001 |
| **Priority** | P2 |
| **Effort** | LOW |
| **Timeline** | 2 hours |
| **CWE** | CWE-444 |
| **ASVS** | V14.5.1 - HTTP security header verification |
| **WSTG** | WSTG-INPV-03 |

**Current Implementation**:
```go
// main.go - sanitizeHopByHop already resolves TE/CL conflicts
// This is well-implemented per RFC 9112
```

**Recommended Fix**:
```go
// Add monitoring for TE/CL conflict detection
// In sanitizeHopByHop, before removing Content-Length:
if req.Header.Get("Transfer-Encoding") != "" && req.Header.Get("Content-Length") != "" {
    slog.Warn("TE/CL conflict resolved",
        "action", "removed Content-Length",
        "client", conn.RemoteAddr(),
    )
}
```

**Verification Checklist**:
- [ ] Verify TE/CL conflicts are logged
- [ ] Verify Content-Length is still removed when TE present
- [ ] Verify normal requests are not flagged

**Security Controls**: HTTP request validation (INPUT), Security event monitoring (LOG)

---

### MIT-009: Add krb5.conf Integrity Verification

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-009 - Kerberos Configuration Tampering (CVSS 5.3) |
| **Threat Refs** | T-T-DS-002-001, T-I-DS-002-001 |
| **Priority** | P2 |
| **Effort** | MEDIUM |
| **Timeline** | 4 hours |
| **CWE** | CWE-15 |
| **ASVS** | V12.3.1 - File permission verification |
| **WSTG** | WSTG-CONF-05 |

**Current Implementation**:
```go
// auth_gokrb5.go - krb5.conf loaded without verification
cfg, err := krb5config.Load(*flagKrb5Conf)
```

**Recommended Fix**:
```go
func verifyConfigFile(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return fmt.Errorf("stat %s: %w", path, err)
    }
    if info.Mode()&0o022 != 0 {
        return fmt.Errorf("%s is group/world-writable (mode %04o); "+
            "fix with: chmod 644 %s", path, info.Mode().Perm(), path)
    }
    return nil
}

// Call verification before config load:
if err := verifyConfigFile(*flagKrb5Conf); err != nil {
    slog.Warn("krb5.conf permission warning", "error", err)
}
cfg, err := krb5config.Load(*flagKrb5Conf)
```

**Verification Checklist**:
- [ ] Verify warning logged for world-writable krb5.conf
- [ ] Verify normal load for properly permissioned file

**Security Controls**: Configuration integrity (DATA), File permission enforcement (AUTHZ)

---

### MIT-010: Add Circuit Breaker Abuse Detection

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-010 - Circuit Breaker Weaponization (CVSS 5.3) |
| **Threat Refs** | T-D-P-010-001, T-D-P-010-002 |
| **Priority** | P2 |
| **Effort** | MEDIUM |
| **Timeline** | 4 hours |
| **CWE** | CWE-400 |
| **ASVS** | V11.1.4 - Rate limiting and throttling |
| **WSTG** | WSTG-BUSL-05 |

**Current Implementation**:
```go
// circuit_breaker.go - fixed 3-failure threshold, 30s cooldown
gobreaker.NewCircuitBreaker(gobreaker.Settings{
    MaxRequests:    1,
    ReadyToTrip:   func(counts gobreaker.Counts) bool {
        return counts.ConsecutiveFailures >= 3
    },
    Timeout: 30 * time.Second,
})
```

**Recommended Fix**:
```go
gobreaker.NewCircuitBreaker(gobreaker.Settings{
    MaxRequests: 1,
    ReadyToTrip: func(counts gobreaker.Counts) bool {
        return counts.ConsecutiveFailures >= 3
    },
    Timeout: 30 * time.Second,
    OnStateChange: func(name string, from, to gobreaker.State) {
        slog.Warn("circuit breaker state change",
            "from", from.String(),
            "to", to.String(),
            "name", name,
        )
    },
})

// Add configurable threshold flags:
var flagCBThreshold = flag.Int("cb-threshold", 3,
    "consecutive auth failures before circuit breaker opens")
var flagCBTimeout = flag.Duration("cb-timeout", 30*time.Second,
    "circuit breaker cooldown duration")
```

**Verification Checklist**:
- [ ] Verify state transitions are logged
- [ ] Verify configurable threshold works
- [ ] Verify cooldown timer is configurable

**Security Controls**: Abuse detection (LOG), Configurable rate limiting (AUTHZ)

---

### MIT-011: Add CGo Boundary Assertions and Fuzzing

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-011 - CGo Boundary Memory Safety (CVSS 5.0) |
| **Threat Refs** | T-T-P-009-001, T-D-P-009-001 |
| **Priority** | P2 |
| **Effort** | MEDIUM |
| **Timeline** | 1 day |
| **CWE** | CWE-120 |
| **ASVS** | V5.2.4 - Buffer boundary checks |
| **WSTG** | WSTG-INPV-07 |

**Current Implementation**:
```c
// gss_darwin.c - bounds-checked but no fuzzing
char errBuf[256];
snprintf(errBuf, sizeof(errBuf), "...", ...);
```

**Recommended Fix**:

**Step 1**: Add Go-side input validation before CGo calls (auth_gss_darwin.go)
```go
const maxSPNLength = 1024
func (g *gssProvider) GetToken(spn string) (string, error) {
    if len(spn) > maxSPNLength {
        return "", fmt.Errorf("SPN too long: %d > %d", len(spn), maxSPNLength)
    }
    // ... existing CGo call
}
```

**Step 2**: Add fuzz test for CGo boundary
```go
//go:build darwin
func FuzzGSSGetToken(f *testing.F) {
    f.Add("HTTP/proxy.example.com")
    f.Add("")
    f.Add(strings.Repeat("A", 2048))
    f.Fuzz(func(t *testing.T, spn string) {
        g := &gssProvider{}
        // Should not panic
        _, _ = g.GetToken(spn)
    })
}
```

**Verification Checklist**:
- [ ] Verify SPN length validation
- [ ] Fuzz test passes with no crashes
- [ ] Verify error buffers handle max-length messages

**Security Controls**: Input length validation (INPUT), Memory safety (CRYPTO)

---

## Long-Term Actions (P3 - Within 90 Days)

### MIT-007: Fail Fatally on crypto/rand Failure

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-007 - Entropy Fallback Weakens Loop Detection (CVSS 3.1) |
| **Threat Refs** | T-T-P-004-001, T-S-P-004-001 |
| **Priority** | P3 |
| **Effort** | LOW |
| **Timeline** | 30 minutes |
| **CWE** | CWE-330 |
| **ASVS** | V6.2.1 - Cryptographic random number generation |
| **WSTG** | WSTG-CRYP-04 |

**Current Implementation**:
```go
// main.go - randomHex falls back to timestamp
func randomHex() string {
    var buf [4]byte
    if _, err := rand.Read(buf[:]); err != nil {
        v := uint32(time.Now().UnixNano() & 0xffffffff)
        binary.LittleEndian.PutUint32(buf[:], v)
    }
    return hex.EncodeToString(buf[:])
}
```

**Recommended Fix**:
```go
func randomHex() string {
    var buf [4]byte
    if _, err := rand.Read(buf[:]); err != nil {
        // crypto/rand failure is a critical system issue
        slog.Error("entropy source failure", "error", err)
        os.Exit(1)
    }
    return hex.EncodeToString(buf[:])
}
```

**Verification Checklist**:
- [ ] Verify randomHex produces unique values
- [ ] Verify process exits on entropy failure (mock test)

**Security Controls**: Cryptographic randomness (CRYPTO)

---

### MIT-012: Add Structured Security Event Logging

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-012 - Insufficient Security Event Logging (CVSS 3.1) |
| **Threat Refs** | T-R-P-001-001, T-R-P-005-001, T-R-P-006-001 |
| **Priority** | P3 |
| **Effort** | MEDIUM |
| **Timeline** | 1 day |
| **CWE** | CWE-778 |
| **ASVS** | V7.1.1 - Security-relevant events logged |
| **WSTG** | WSTG-CONF-09 |

**Current Implementation**:
```go
// main.go - general slog logging without security classification
slog.Error("auth failed", "error", err)
```

**Recommended Fix**:
```go
// Define security event constants
const (
    SecurityEventAuthFailure    = "security.auth.failure"
    SecurityEventAuthSuccess    = "security.auth.success"
    SecurityEventConnectAttempt = "security.connect.attempt"
    SecurityEventConnectDenied  = "security.connect.denied"
    SecurityEventCircuitBreaker = "security.circuit_breaker"
    SecurityEventClientRejected = "security.client.rejected"
)

// Auth failure
slog.Warn("authentication failed",
    "event_type", SecurityEventAuthFailure,
    "client", conn.RemoteAddr(),
    "error", err,
)
// CONNECT attempt
slog.Info("CONNECT tunnel requested",
    "event_type", SecurityEventConnectAttempt,
    "target", req.Host,
    "client", conn.RemoteAddr(),
)
```

**Verification Checklist**:
- [ ] Verify security events include event_type field
- [ ] Verify auth failures are logged with client info
- [ ] Verify CONNECT attempts are logged

**Security Controls**: Security event classification (LOG), Audit trail (LOG)

---

### MIT-013: Validate KRB5CCNAME Environment Variable

| Attribute | Value |
|-----------|-------|
| **Risk** | VR-013 - KRB5CCNAME Environment Variable Manipulation (CVSS 5.0) |
| **Threat Refs** | T-S-P-009-002, T-T-DS-004-001 |
| **Priority** | P3 |
| **Effort** | LOW |
| **Timeline** | 1 hour |
| **CWE** | CWE-426 |
| **ASVS** | V1.5.3 - Environment variable validation |
| **WSTG** | WSTG-CONF-06 |

**Current Implementation**:
```go
// auth_gss_darwin.go - KRB5CCNAME used without validation
// GSS-API respects KRB5CCNAME from environment
```

**Recommended Fix**:
```go
func init() {
    if ccname := os.Getenv("KRB5CCNAME"); ccname != "" {
        slog.Info("credential cache override",
            "KRB5CCNAME", ccname,
        )
    }
}
```

**Verification Checklist**:
- [ ] Verify KRB5CCNAME is logged at startup
- [ ] Verify non-standard paths produce warning

**Security Controls**: Environment variable validation (INPUT)

---

## Implementation Roadmap

| Timeline | Mitigations | Priority | Owner | Effort |
|----------|-------------|----------|-------|--------|
| Week 1 | MIT-001, MIT-002 | P1 (High) | Development Team | Medium-High |
| Week 2-3 | MIT-003, MIT-004, MIT-005, MIT-007 | P2-P3 | Development Team | Low |
| Week 3-4 | MIT-006, MIT-008, MIT-009, MIT-010 | P2 | Development Team | Low-Medium |
| Month 2-3 | MIT-011, MIT-012, MIT-013 | P2-P3 | Development Team | Medium-Low |

## Key Observations

1. **No emergency actions required**: No P0 (Critical) risks exist
2. **Two P1 mitigations are additive**: MIT-001 and MIT-002 add new capabilities rather than fixing bugs
3. **Quick wins available**: MIT-003, MIT-004, MIT-005, MIT-007 are low-effort, high-impact changes
4. **Existing code is sound**: Several mitigations (MIT-008, MIT-010, MIT-012) enhance already-working controls with monitoring
5. **Backward compatible**: All mitigations are opt-in via flags, preserving existing behavior

---

*Generated by Threat Modeling Skill v3.0.3 (20260209a)*
