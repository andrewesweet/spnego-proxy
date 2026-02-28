# P1: Project Understanding

## Sub-Phase Progress Tracker

| Sub-Phase | Status | Output | Notes |
|-----------|--------|--------|-------|
| P1.0 Three-Layer Discovery | Done | P1_static_discovery.yaml | 114 files, 21 dirs |
| P1.1 Doc Analysis | Skipped | N/A | Focused on code-first analysis for this small codebase |
| P1.2 Code Analysis | Done | 7 modules, 27 entry points, 13 findings | Full source review |
| P1.3 Dynamic Indicators | Done | 0 dynamic indicators | No dynamic routes |
| P1.4 Source Alignment | Done | alignment_score: 0.95 | Script + LLM agree |
| P1.5 Validation | Done | PASSED | coverage_confidence: 0.95 |

## Project Overview

**SPNEGO-PROXY** is a forward HTTP proxy written in Go (~1,400 LOC) that transparently injects SPNEGO/Kerberos authentication tokens into requests destined for an upstream proxy. It sits between local applications (that don't support SPNEGO) and a corporate proxy server that requires Kerberos authentication.

### Architecture

```
┌─────────────┐     HTTP      ┌──────────────┐  HTTP + SPNEGO   ┌──────────────┐
│  Local App   │ ──────────>  │ spnego-proxy  │ ──────────────>  │  Upstream    │
│  (Client)    │  port 8080   │  (this tool)  │  Negotiate token │  Proxy       │
└─────────────┘               └──────────────┘                   └──────────────┘
                                     │
                              ┌──────┴──────┐
                              │   Kerberos   │
                              │   KDC/Cache  │
                              └─────────────┘
```

### Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.24 |
| Kerberos (Linux) | gokrb5 v8.4.4 (pure Go) |
| Kerberos (macOS) | GSS.framework via CGo |
| Circuit Breaker | sony/gobreaker v2.4.0 |
| Connection Limiting | golang.org/x/net/netutil |

## Module Inventory

| ID | Name | Security Level | LOC | Key Role |
|----|------|---------------|-----|----------|
| M-001 | Proxy Core | HIGH | 885 | TCP listener, HTTP parsing, SPNEGO injection, tunneling |
| M-002 | Error Types | MEDIUM | 25 | Typed auth errors for errors.As matching |
| M-003 | gokrb5 Auth Provider | HIGH | 135 | Password-based Kerberos via pure Go |
| M-004 | macOS GSS-API (Go) | HIGH | 88 | CGo bridge to macOS GSS framework |
| M-005 | macOS GSS-API (C) | HIGH | 170 | Native GSS-API calls, memory management |
| M-006 | Circuit Breaker | MEDIUM | 93 | Auth failure rate limiting |
| M-007 | Platform Stubs | LOW | 20 | Error stubs for non-macOS builds |

## Entry Point Inventory

### Network Entry Points (7)

| ID | Description | Trust Level |
|----|-------------|-------------|
| EP-NET-001 | TCP listener (default 127.0.0.1:8080) | UNTRUSTED |
| EP-NET-002 | Client HTTP request parsing | UNTRUSTED |
| EP-NET-003 | Upstream TCP dial | SEMI-TRUSTED |
| EP-NET-004 | Upstream HTTP response parsing | SEMI-TRUSTED |
| EP-NET-005 | Bidirectional CONNECT tunnel | UNTRUSTED |
| EP-NET-006 | Raw relay fallback | SEMI-TRUSTED |
| EP-NET-007 | Connection accept loop | UNTRUSTED |

### CLI Entry Points (12)

All operator-controlled flags including bind address, upstream proxy, SPN, Kerberos credentials, timeouts, CONNECT port whitelist, and forwarding header configuration.

### System Entry Points (8)

Signal handlers, password file I/O, Kerberos config file, terminal password prompt, CGo boundary crossing, macOS credential cache, environment variables, and entropy source.

## Architecture Findings

| ID | Title | Severity | Category |
|----|-------|----------|----------|
| F-P1-001 | Transparent SPNEGO injection (no client auth) | HIGH | entry_point |
| F-P1-002 | Password retained in process memory | MEDIUM | configuration |
| F-P1-003 | Four distinct trust boundaries | HIGH | module_structure |
| F-P1-004 | CGo boundary with fixed-size buffers | MEDIUM | module_structure |
| F-P1-005 | Request smuggling defenses implemented | HIGH | entry_point |
| F-P1-006 | CONNECT tunnel port restriction off by default | MEDIUM | configuration |
| F-P1-007 | Loop detection via Via pseudonym | MEDIUM | entry_point |
| F-P1-008 | No TLS on client-facing listener | MEDIUM | configuration |
| F-P1-009 | Entropy fallback to timestamp | LOW | configuration |
| F-P1-010 | Password file permission validation | LOW | configuration |
| F-P1-011 | PAFXFAST disabled for compatibility | LOW | configuration |
| F-P1-012 | Raw relay fallback for unparseable responses | MEDIUM | entry_point |
| F-P1-013 | No idle timeout on forwarding phase | MEDIUM | configuration |

## Coverage Confidence

| Metric | Value |
|--------|-------|
| overall_confidence | 0.95 |
| recommendation | HIGH_CONFIDENCE |
| uncertainty_sources | None |
| notes | Small codebase (~1400 LOC) fully analyzed |
