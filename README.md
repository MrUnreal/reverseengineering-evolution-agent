# RE Evolution Agent

**AI-native reverse engineering platform** for mapping complex binaries into confidence-scored, shareable system intelligence.

Not just one game client. Not one-off notes. Not run-of-the-mill RE.

---

## What this is

RE Evolution Agent turns opaque binaries into:
- **Architecture maps** (what talks to what)
- **Evidence-backed findings** (why we believe it)
- **Confidence-scored hypotheses** (what is certain vs likely)
- **Repeatable artifacts** (JSON + dashboards + docs)

Think: **analysis engine + evidence model + visual outputs + iteration loop**.

---

## Why it’s different

Most RE projects stop at notes. This one is built like a product:

- **Schema-first findings** (`findings.v1`) for reproducibility
- **Automation-first pipeline** (batch analyzers + synthesis)
- **CI-backed quality gates** (syntax + schema validation)
- **Dashboard-native outputs** for fast exploration
- **Iteration rules** to prevent confidence inflation and analysis debt

This is a system for compounding knowledge, not a folder of ad-hoc dumps.

---

## Primary use cases

- Security research & anti-cheat validation
- Protocol/handler mapping for unknown clients
- Architecture extraction for legacy binaries
- Repeatable educational RE workflows
- Team-based RE with explicit evidence trails

---

## Targets

The platform is **target-agnostic**.

Current known target examples include:
- Ascension client (case study)
- Additional binaries via the same pipeline (planned/active)

Ascension is a **demonstration target**, not the product definition.

---

## Quick start (practical)

1. Read the execution board:  
   **[`ROADMAP_AND_TESTING_BOARD.md`](ROADMAP_AND_TESTING_BOARD.md)**
2. Explore visual outputs:  
   **[`docs/local-analysis-dashboard.html`](docs/local-analysis-dashboard.html)**
3. Run schema validation smoke:  
   `python mcp-runner/validate_findings_schema.py --schema schemas/findings.v1.schema.json --file docs/examples/findings.sample.v1.json`
4. Review strategy direction:  
   **[`VIRAL_RE_GAME_AGENT_STRATEGY.md`](VIRAL_RE_GAME_AGENT_STRATEGY.md)**

---

## Project shape

- `mcp-runner/` — core analyzers and synthesis scripts
- `mcp-headless/` — headless MCP/Ghidra runtime glue
- `GhidrAssistMCP/` — integrated MCP extension source (vendored, no submodule dependency)
- `docs/` — dashboards and visual artifacts
- `schemas/` — canonical data contracts
- `.github/workflows/` — CI smoke checks

---

## Current maturity snapshot

- ✅ Generic repo structure and cleanup complete
- ✅ No module dependency for `GhidrAssistMCP`
- ✅ Roadmap + testing issues live on GitHub
- ✅ CI smoke workflow in place
- ✅ Canonical findings schema + validator foundation
- 🚧 Unified CLI + advanced test harnesses in progress

---

## Principles

This project follows a strict iteration discipline:
- evidence over guesswork
- confidence calibration over bold claims
- reusable assets over one-off analysis
- productized outputs over raw notes

See: **[`RE_RESEARCH_RULES.md`](RE_RESEARCH_RULES.md)**

---

## Disclaimer

This repository is for **defensive security research, binary understanding, and education**.
No exploit tooling, cheating automation, or harmful use is supported.
