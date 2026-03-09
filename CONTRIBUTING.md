# Contributing

Thanks for improving RE Evolution Agent.

## Working style

- Keep changes scoped and reviewable.
- Prefer incremental improvements over large rewrites.
- Preserve evidence-first analysis quality (see `docs/strategy/RE_RESEARCH_RULES.md`).

## Repo conventions

- Put long-form docs under `docs/`:
  - `docs/guides/`
  - `docs/operations/`
  - `docs/strategy/`
- Keep root lean (`README.md`, core config, key entry docs only).
- Use canonical findings schema: `schemas/findings.v1.schema.json`.

## Quality checks

Before opening a PR:

1. Validate sample findings bundle:
   - `python mcp-runner/validate_findings_schema.py --schema schemas/findings.v1.schema.json --file docs/examples/findings.sample.v1.json`
2. Run Python compile smoke:
   - `python -m compileall -q mcp-runner agent-runner runner structure-engine streamlit-ui`
3. Ensure docs links are valid for moved files.

## Commit style

Use clear, action-based messages, e.g.:
- `docs: consolidate operations docs paths`
- `feat: add schema validation command`
- `fix: repair broken relative links`

## Scope guardrails

- This project supports defensive research and education.
- Do not add exploit automation or harmful-use content.
