# Ascension Hardening Research Dossier (Defensive)

## Purpose

This dossier is for **responsible client hardening** and disclosure to the Ascension team.

It summarizes:
- Observed detection/control surfaces
- Defensive risk model
- Validation priorities
- Implementation-ready hardening recommendations

> Scope guardrail: This project does **not** provide bypass instructions.

---

## Defensive Objective

Increase client security robustness while minimizing false positives and preserving player experience.

### Outcomes we want
1. Better detection signal quality
2. Lower control blind spots
3. Reproducible security telemetry
4. Faster triage for suspicious behavior
5. Clear disclosure package for maintainers

---

## Research Tracks

### 1) Control surface mapping
- Anti-tamper detection vectors
- Debug/instrumentation checks
- Protocol dispatch and handler validation points
- Integrity and telemetry paths

### 2) Gap analysis and confidence scoring
- Use `engines/mcp-runner/hardening_gap_audit.py`
- Produce risk-ranked control categories
- Prioritize categories with `HIGH` / `CRITICAL` risk

### 3) Validation-first hardening
- Add deterministic tests for confidence calibration
- Add contract tests for output schema compatibility
- Add CI checks to block regressions

---

## Priority Hardening Backlog

1. **Protocol robustness**
   - Strict opcode schema checks
   - Sequence/rate anomalies
   - Server-side sanity rules

2. **Integrity telemetry hardening**
   - Signed attestation events
   - Replay-resistant challenge linkage
   - Correlate integrity alerts with behavioral anomalies

3. **Debug/tamper signal calibration**
   - Multi-signal scoring instead of binary triggers
   - False-positive measurement + rollback criteria

4. **Thread/process anomaly scoring**
   - Parent lineage checks
   - Runtime behavior context before punitive action

---

## Disclosure Package Checklist

- [ ] Executive summary (1 page)
- [ ] Control coverage matrix (risk-ranked)
- [ ] Evidence snippets and reproducible artifacts
- [ ] Proposed hardening changes by priority
- [ ] Validation/test plan and rollback guardrails

---

## How to generate current audit artifacts

Run:

`python engines/mcp-runner/hardening_gap_audit.py`

Outputs:
- `reports/ASCENSION_HARDENING_GAP_AUDIT.json`
- `reports/ASCENSION_HARDENING_GAP_AUDIT.md`
