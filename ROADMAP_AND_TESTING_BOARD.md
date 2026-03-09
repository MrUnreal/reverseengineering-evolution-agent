# Roadmap & Testing Board

This is the execution board for the polished evolution pass.

## GitHub Repository
- https://github.com/MrUnreal/reverseengineering-evolution-agent

## Open Issues

### Roadmap
1. **#1** Unify analyzers under single CLI (`re-agent`)  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/1
2. **#2** Define canonical findings schema + validator  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/2
3. **#3** Demo mode + shareable insight cards  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/3
4. **#4** Community challenge mode + leaderboard  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/4

### Testing & Quality
5. **#5** CI smoke pipeline (lint + CLI smoke + schema validation)  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/5
6. **#6** Confidence calibration test harness  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/6
7. **#7** Golden dataset regression suite  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/7
8. **#8** Dashboard contract tests for report JSON  
   https://github.com/MrUnreal/reverseengineering-evolution-agent/issues/8

---

## Iteration Rules Applied (from `RE_RESEARCH_RULES.md`)

- **Rule 2 (Plan first):** Work is decomposed into scoped issues with acceptance criteria.
- **Rule 3 (Verify with signals):** Testing issues explicitly enforce confidence and schema checks.
- **Rule 7 (Quality output):** Canonical schema + CI gate + contract tests.
- **Rule 9 (Parallelize):** Roadmap and testing streams can progress concurrently.
- **Rule 17 (Know limits):** Keep offline artifacts stable; defer heavy dynamic steps to live analysis.
- **Rule 22 (Calibrate confidence):** Confidence harness prevents inflation.
- **Rule 28 (Legibility):** This board centralizes all actionable links.

---

## Suggested Execution Order (Polished Path)

### Sprint A — Foundation (Week 1)
- #1 Unified CLI
- #2 Findings schema + validator
- #5 CI smoke pipeline

### Sprint B — Reliability (Week 2)
- #6 Confidence calibration tests
- #7 Golden regression suite
- #8 Dashboard contract tests

### Sprint C — Growth Loop (Week 3)
- #3 Demo mode + share cards
- #4 Challenge mode + leaderboard

---

## Definition of Polished

- Single command developer experience
- Deterministic evidence schema
- CI-enforced quality bars
- Regression-proof outputs
- Demo/share flow that showcases value quickly
