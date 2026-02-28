# Threat Model

STRIDE-based threat model of the spnego-proxy codebase, generated on
2026-02-28.

## How this was generated

The assessment was performed using the
[threat-modeling](https://github.com/fr33d3m0n/threat-modeling) skill (v3.0.3)
for Claude Code. The skill executes an 8-phase sequential workflow:

1. **Project Understanding** — module discovery, entry points, dependencies
2. **DFD Analysis** — data flow diagrams, external interactors, data stores
3. **Trust Boundaries** — boundary identification and crossing analysis
4. **Security Design Review** — gap analysis against 16 security domains
5. **STRIDE Threat Analysis** — systematic threat enumeration (109 threats)
6. **Risk Validation** — verification, CVSS scoring, attack chain mapping
7. **Mitigation Planning** — prioritised remediation recommendations
8. **Report Generation** — final deliverables

Each phase consumes the structured YAML output of the previous phase. The
analysis was driven by Claude Opus 4.6 subagents reading the actual source code;
no mock data was used.

## Results summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 2 |
| Medium | 8 |
| Low | 3 |
| **Total** | **13** |

GitHub issues for all 13 findings:
[issues labelled `threat-model`](https://github.com/andrewesweet/spnego-proxy/labels/threat-model).

## Reports

### Deliverables

| Report | Description |
| --- | --- |
| [Risk Assessment Report](SPNEGO-PROXY-RISK-ASSESSMENT-REPORT.md) | Executive summary and full analysis |
| [Risk Inventory](SPNEGO-PROXY-RISK-INVENTORY.md) | All 13 validated risks with CVSS scores and CWE references |
| [Mitigation Measures](SPNEGO-PROXY-MITIGATION-MEASURES.md) | Remediation recommendations with code examples |
| [Penetration Test Plan](SPNEGO-PROXY-PENETRATION-TEST-PLAN.md) | Test cases for each validated risk |

### Phase reports (audit trail)

These document the intermediate analysis at each phase:

- [P1 — Project Understanding](P1-PROJECT-UNDERSTANDING.md)
- [P2 — DFD Analysis](P2-DFD-ANALYSIS.md)
- [P3 — Trust Boundaries](P3-TRUST-BOUNDARY.md)
- [P4 — Security Design Review](P4-SECURITY-REVIEW.md)
- [P5 — STRIDE Threats](P5-STRIDE-THREATS.md)
- [P6 — Risk Validation](P6-RISK-VALIDATION.md)
- [P7 — Mitigation Planning](P7-MITIGATION-PLANNING.md)

## Re-running the assessment

Install the skill and invoke it from the repository root:

```bash
# Install (one-time)
git clone https://github.com/fr33d3m0n/threat-modeling.git \
    ~/.claude/skills/threat-modeling

# Run
# (from Claude Code, in this repository)
/threat-model
```

See the
[skill README](https://github.com/fr33d3m0n/threat-modeling/blob/main/README.md)
for full instructions and flags.
