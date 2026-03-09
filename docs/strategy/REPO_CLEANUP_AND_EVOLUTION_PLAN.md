# Repo Cleanup and Evolution Plan

## Remote Repository

Created: `https://github.com/MrUnreal/reverseengineering-evolution-agent`

## What Must Stay (Core Product Surface)

### Core code and runtime
- `mcp-runner/` — primary analysis pipeline and executors
- `mcp-headless/` — containerized MCP runtime glue
- `GhidrAssistMCP/` — Ghidra extension source
- `agent-runner/` — autonomous orchestration layer
- `runner/` — baseline execution automation
- `structure-engine/` — structural analysis helpers

### Product/UI surface
- `docs/` — dashboards and user-facing analysis UI
- `streamlit-ui/` — interactive frontend if retained as app shell

### Product docs (keep and consolidate over time)
- `README.md`
- `docs/strategy/RE_RESEARCH_RULES.md`
- `docs/guides/GAME_RE_DESIGN.md`
- `docs/guides/GAME_RE_QUICKSTART.md`
- `docs/guides/RESEARCH_GUIDE.md`
- `docs/operations/PHASE_1_COMPLETION_SUMMARY.md`
- `docs/operations/PHASE_1_QUICK_REFERENCE.md`

### Infra and reproducibility
- `docker-compose.yml`
- `mcp-runner/requirements.txt`
- `agent-runner/requirements.txt`
- `ai-reverse-engineering/requirements.txt` (if demo kept)

## What Should NOT Live in Git (Archive/Ignore)

### Heavy local/dev artifacts
- `.venv/` (~265 MB) — local Python environment
- `data/` (~145 MB) — local Ghidra project data
- `samples/` (~32 MB) — binaries and sample game assets
- `sample_target/` (~8 MB) — target binaries

### Generated outputs and logs
- `reports/` — generated analysis output (can publish selected snapshots separately)
- `analysis-output.txt`
- `mcp-output.log`

### High-churn duplicate reports (candidate archive)
These are useful historically but should be moved into a versioned `archive/docs/` lane in a later pass:
- `ANALYSIS_COMPLETE_MANIFEST.md`
- `ANALYSIS_COMPLETE_SUMMARY.md`
- `ANALYSIS_TOOLKIT_REFERENCE.md`
- `ITERATION_2_SUMMARY.md`
- `LIVE_MCP_ANALYSIS_FINAL_REPORT.md`
- `README_OLD_DOCKER_NOTES.md`

## Immediate Cleanup Applied

- Hardened `.gitignore` to exclude:
  - local envs (`.venv/`, `venv/`)
  - binaries (`*.exe`, `*.dll`, `*.rep`)
  - local datasets (`data/`, `samples/`, `sample_target/`)
  - generated output (`reports/`, logs)

## Recommended Repo Shape (v2)

- `apps/`
  - `dashboard/` (from `docs/` and/or `streamlit-ui/`)
- `packages/`
  - `analysis-core/` (from `mcp-runner/`)
  - `agent-core/` (from `agent-runner/`)
  - `ghidra-integration/` (from `GhidrAssistMCP/`, `mcp-headless/`)
- `research/`
  - curated static docs only (no generated bulk)
- `infra/`
  - compose files, scripts, CI workflows

## 2-Week Evolution Path

### Week 1 — Productize the core
1. Unify analyzers behind one CLI (`re-agent analyze ...`).
2. Define a normalized schema for findings (`finding`, `evidence`, `confidence`, `source`).
3. Publish one golden demo report JSON + dashboard snapshot.
4. Add minimal CI: lint + smoke test + schema validation.

### Week 2 — Make it shareable and sticky
1. Add one-click demo mode (sample JSON, no heavy deps).
2. Add "before/after" case studies for 3 game RE scenarios.
3. Add benchmark card: time saved, handlers found, confidence delta.
4. Add leaderboard/challenge mode for community submissions.

## Viral Value Loop (North Star)

1. User uploads binary metadata/signatures.
2. Agent produces fast, visual, confidence-scored architecture map.
3. User shares dashboard permalink + key findings card.
4. New users import template packs and reproduce in minutes.
5. Community contributes signatures/rules -> model improves.

**Compounding moat:** public knowledge graph of reusable RE patterns + confidence-labeled evidence.

## Practical Next Actions

1. Publish `v0.1-foundation` tag now that clean baseline is live.
2. Keep root minimal; place all long-form docs under `docs/guides`, `docs/operations`, and `docs/strategy`.
3. Advance roadmap issues #1–#8 in execution order (CLI, schema, CI, tests, growth loop).
4. Track milestones in GitHub issues with labels:
   - `core-engine`
   - `dashboard`
   - `growth-loop`
   - `evidence-schema`
   - `dx`
