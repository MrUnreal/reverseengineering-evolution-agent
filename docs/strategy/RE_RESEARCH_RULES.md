# REVERSE ENGINEERING RESEARCH RULES
## Agent-Rules Adapted for Binary & Code Analysis

**Based on:** MrUnreal/agent-rules (28 universal coding rules)  
**Adapted for:** Reverse engineering, static analysis, binary research  
**Created:** March 9, 2026

---

## Core Principles

These rules translate universal agent-rules into the specific context of reverse engineering where you:
- Cannot modify the target binary
- Must infer behavior from static analysis, imports, and heuristics
- Work within offline constraints (until live tools activate)
- Build architectural understanding incrementally

---

## Adapted Rules for RE

### 1. EXPLORE THE BINARY FIRST
**Rule:** Read the codebase (binary) before making analysis claims.

**For RE:**
- List all sections (.text, .data, .rdata, .reloc)
- Extract all imports and categorize by subsystem
- Index all functions and data references
- Identify string literals and encrypted/encoded data
- Search for known patterns (IOCP, exceptions, gaming-specific APIs)
- Map address ranges to understand memory layout

**Application:** Before claiming "FUN_0047cc90 is a dispatcher," verify by examining:
  - Import locations in related functions
  - Address locality (large functions often contain switch statements)
  - String references (dispatcher candidate should reference many packet-related strings)

**Success criteria:** 436 entries indexed, 200 functions categorized, 100 imports mapped.


### 2. PLAN ANALYSIS DEPTH BEFORE DIVING
**Rule:** Break complex analysis into phases before implementing deep investigation.

**For RE:**
- Phase 1 (Offline): Structural analysis (what we just completed)
  - Address indexing
  - Subsystem correlation
  - Data region estimation
  - Execution flow prediction
  
- Phase 2 (Live MCP): Decomposition
  - Key function decompilation (entry, main, dispatcher)
  - Opcode handler enumeration
  - Xref analysis for call chains
  
- Phase 3 (Integration): Data structure inference
  - Memory layout validation
  - Object model reconstruction
  - Handler classification

**Each phase:** Anticipate blockers (Docker service stopped = can't do Phase 2 yet).

**Success criteria:** Clear handoff between phases, no backtracking.


### 3. VERIFY ANALYSIS WITH MULTIPLE SIGNALS
**Rule:** Test your hypotheses; don't assume correctness.

**For RE:**
- **Signal 1:** Address locality (0x00401000 = entry is CERTAIN, standard PE)
- **Signal 2:** Import correlation (70 OpenGL imports + graphics subsystem = MEDIUM confidence)
- **Signal 3:** Function location + size heuristics (FUN_0047cc90 is large + IOCP imports nearby = MEDIUM-HIGH)
- **Signal 4:** String cross-references (search for "MOVE" strings near address 0x00B5 movement opcode)
- **Signal 5:** API pattern matching (IsDebuggerPresent + CreateToolhelp32Snapshot cluster = anti-cheat)

**Never declare:** "This function does X" without at least 2-3 independent signals.

**Success criteria:** Confidence levels assigned (CERTAIN, HIGH, MEDIUM, LOW) with evidence for each claim.


### 4. MAKE INCREMENTAL ANALYSIS PASSES
**Rule:** One logical investigation per pass; don't mix subsystems.

**For RE:**
- **Pass 1:** Structural (sections, imports, address ranges) ✓ DONE
- **Pass 2:** Subsystem mapping (imports → subsystem roles)
- **Pass 3:** Execution sequence (entry → main → loops → stops)
- **Pass 4:** Network protocol (opcodes → handlers)
- **Pass 5:** Anti-cheat deep dive (detection vectors, evasion analysis)

Each pass should be independently verifiable and produce artifacts.

**Success criteria:** Each pass generates JSON + markdown, passes validation (0 errors).


### 5. MANAGE RE CONTEXT AGGRESSIVELY
**Rule:** Context is your most precious resource in analysis.

**For RE:**
- Keep live analyzer context <= 100 KB (dashboards, progress files)
- Use JSON for structured data (parse programmatically, don't inline)
- Externalize large findings (docs/ADDRESS_INDEX.json, reports/SUBSYSTEM_*.json)
- Build layered documentation (README → ARCH_SYNTHESIS → detailed specs)
- Reuse analysis outputs across tools (batch generator feeds dashboard)

**For long tasks:**
- Write progress to PROGRESS.md before context overflow
- Summarize old findings rather than dropping them
- Use file-based state (JSON, not human memory)

**Success criteria:** Never exceed context limits; always have queryable outputs.


### 6. COMMUNICATE FINDINGS EXPLICITLY
**Rule:** Explain your reasoning; don't just state conclusions.

**For RE:**
- Every claim should have a rationale line:
  - "Function entry @ 0x00401000 (CERTAIN) — standard PE entry point"
  - "FUN_0047cc90 is dispatcher (MEDIUM) — address locality + size heuristics"
  - "Anti-cheat confirmed (CERTAIN) — direct API call to detection functions"
  
- Publish confidence matrices (what we learned this phase vs. unknowns)
- Explain gaps explicitly: "Data structures still LOW confidence — need live decomp"

**Success criteria:** Anyone reading your docs understands confidence levels and evidence.


### 7. BUILD ANALYSIS-QUALITY OUTPUT
**Rule:** Clean analysis is easier to verify and reuse.

**For RE:**
- Use consistent JSON schemas (function entries have: name, address, category, priority, confidence)
- One finding per entry (don't combine "FUN_00401010 is main + handles networking" — split it)
- Meaningful field names (priority_score not p, memory_region not r)
- Explicit nullability (unknown fields marked null, not omitted)
- Error handling in analysis tools (catch JSON parse errors, validate addresses)

**Success criteria:** All JSON validates; all markdown renders without errors; one tool's output feeds next tool.


### 8. STRUCTURE RE WORKFLOWS CONSISTENTLY
**Rule:** Standardize how you do each type of analysis.

**For RE:**

**Workflow: Function Analysis**
- Identify by address locality
- Verify by import correlation
- Assign subsystem & category
- Estimate priority (entry → 1600, main → 1100, anti-cheat → 700)
- Test hypothesis with xref analysis (on Phase 2)

**Workflow: Subsystem Discovery**
- Catalog all imports
- Group by DLL (kernel32.dll, gdi32.dll, etc.)
- Map to subsystem (IOCP → network, OpenGL → graphics)
- Identify key player functions
- Build interaction diagram

**Workflow: Protocol Reconstruction**
- Extract known opcodes
- Search for byte patterns
- Map to handler locations
- Document packet format from handlers
- Validate with network traffic patterns

**Success criteria:** Running same workflow twice produces same result.


### 9. PARALLELIZE INDEPENDENT RE TASKS
**Rule:** Don't investigate sequentially if independent.

**For RE:**
- Batch function analysis (14 critical functions in one pass vs. one-by-one)
- Parallel subsystem analysis (graphics + network + anti-cheat simultaneously)
- Run multiple tools on same data (correlator + extractor + synthesizer in one session)

**Success criteria:** Phase completion time halved; zero task ordering issues.


### 10. AVOID COMMON RE ANTI-PATTERNS
**Rule:** Know what not to do.

**For RE:**

**Anti-pattern 1:** "Kitchen sink analysis" — trying to RE the entire binary at once.
→ Solution: Break into subsystems, 70% architecture first, details second.

**Anti-pattern 2:** "Over-claiming confidence" — saying CERTAIN without evidence.
→ Solution: Always provide 2+ signals minimum; use MEDIUM by default.

**Anti-pattern 3:** "Analysis paralysis" — collecting data without synthesizing.
→ Solution: Generate reports after each pass; don't hoard raw findings.

**Anti-pattern 4:** "Trust-then-verify gap" — assuming manual analysis is correct.
→ Solution: Cross-check with multiple tools; validate JSON outputs.

**Anti-pattern 5:** "Depth ignore failures" — skipping unknown functions.
→ Solution: Document unknowns explicitly; return to them in Phase 2.

**Anti-pattern 6:** "Dead-end exploration" — researching without progress.
→ Solution: Set max 30-min per rabbit hole; escalate unknowns to live phase.

**Success criteria:** Zero wasted analysis; every finding contributes to architecture model.


### 11. HYPOTHESIS-DRIVEN ANALYSIS (RE version of TDD)
**Rule:** Form a hypothesis, test it, document result.

**For RE:**

**Hypothesis cycle:**
1. **Form.** "FUN_0047cc90 is packet dispatcher (switch on opcode)"
2. **Test.** 
   - Address locality (large function in network subsystem region)
   - Import correlation (IOCP reads packets; dispatcher near)
   - Xref search (find what calls it)
3. **Conclude.** "MEDIUM confidence: all three signals align, but need decomp to see switch structure"
4. **Document.** Add to FUNCTION_DECOMPILATION_PREDICTIONS.json with confidence + evidence

**Validate later:** When Phase 2 activates, run decomp on high-priority hypotheses first.

**Success criteria:** 100% of hypotheses recorded; 80%+ later validated.


### 12. BUILD KNOWLEDGE ASSETS FOR REUSE
**Rule:** Hoard working examples; you only analyze once.

**For RE:**

**Knowledge Assets to Create:**
- `OPCODE_PATTERNS.json` — Known opcodes + packet structures
- `SUBSYSTEM_ROLES.md` — What each subsystem does + APIs it uses
- `ADDRESS_REGIONS.md` — Memory map (what lives where)
- `WINEVENT_ENTRY_PATTERNS.md` — How this game structures entry/main/loops
- `FUNCTION_CATEGORIES.json` — Rules for categorizing unknown functions

**Reuse:** Next binary analysis? Start with these patterns, adapt for new target.

**Success criteria:** Assets updated after every completed analysis phase; reusable across projects.


### 13. UNDERSTAND YOUR ANALYSIS; DON'T CARGO-CULT IT
**Rule:** Every finding should be explicable.

**For RE:**
- Can you explain why you think this is the entry point? (PE standard + address)
- Can you describe the startup sequence? (5 stages with clear transitions)
- Can you predict what happens if you patch the dispatcher? (game crashes on unknown packet)

**If you can't explain it:** You don't understand it well enough yet.

**Success criteria:** Each major finding has a 1-paragraph explanation accessible to newcomers.


### 14. DESIGN ANALYSIS FOR AGENT CONSUMPTION
**Rule:** Structure findings so both humans AND agents can use them.

**For RE:**
- JSON with schema (agents parse programmatically)
- Markdownfor humans (renders beautifully, searchable)
- Progress files updated frequently (agents orient from these)
- Consistent naming (_ANALYSIS.json, _REPORT.md, _DEEP_*.json)
- Errors tagged with [ERROR] [WARNING] [INFO] for grep-ability

**Test:** Can a fresh agent load reports/LOCAL_DEEP_ANALYSIS.json and understand the binary structure?

**Success criteria:** Dashboard loads all data; 0 parse errors; tool chains work offline.


### 15. EXPECT MULTI-PASS REFINEMENT
**Rule:** First analysis is rarely final; iterate.

**For RE:**
- **Round 1:** 70% architecture from offline (YOU ARE HERE)
- **Round 2:** 85% after Phase 2 decomp (entry + main)
- **Round 3:** 95% after handler enumeration + data structures
- **Round 4:** Near-complete after subsystem integration

Don't wait for 100% in Round 1.

**Success criteria:** Each round increases confidence; no major revisions to Round 1 findings.


### 16. SPECIFY ANALYSIS TARGETS PRECISELY
**Rule:** "Reverse engineer the anti-cheat" vs. "Document anti-cheat detection vectors" → vastly different effort.

**For RE:**
- Precise: "Identify 5 detection vectors + document how each checks for cheating tools"
- Precise: "Map startup sequence (entry → subsystem init → loop entry)"
- Vague: "Understand the binary"
- Vague: "Reverse engineer everything"

**Each target should be:** Atomic, testable, bounded in time (2-4 hours), produces verifiable artifact.

**Success criteria:** Every analysis task has a clear DONE criteria.


### 17. KNOW WHEN TO SWITCH TO LIVE ANALYSIS
**Rule:** Some things offline analysis can't discover; recognize the limit.

**For RE:**

**Safe offline:**
- Subsystem structure (imports show what it uses)
- Startup sequence (entry point flows predictably)
- Anti-cheat detection vectors (API calls are visible)
- Data region estimates (import patterns suggest layout)

**Need live analysis:**
- Exact function decompilation (source-like pseudocode)
- Call graph edges (xref requires Ghidra)
- Data layout validation (memory analysis)
- Opcode handler listing (would need byte pattern search)
- Object instantiation patterns (need to see allocations)

**When you hit a wall:** Document what you need, prepare Phase 2 tasks, don't stall.

**Success criteria:** You're at 70% now; Phase 2 will push to 95%. Transition ready.


### 18. GUARD AGAINST ANALYSIS DEBT
**Rule:** Bad analysis compounds; guard against it.

**For RE:**

**Watch for:**
- Unvalidated hypotheses marked as CERTAIN (should be MEDIUM)
- Functions grouped with shaky rationale (re-verify categories)
- Confidence scores inflated by wishful thinking (enforce 2+ signals)
- Duplicate/contradictory findings (merge when found)
- Stale findings (old confidence scores no longer reflect evidence)

**Refresh quarterly:** Re-run analysis tools on same binary to catch regressions.

**Success criteria:** Every finding auditable; no undefended claims.


### 19. BUILD ANALYSIS RULES INCREMENTALLY
**Rule:** Start minimal; add rules only when you see repeated failures.

**For RE - Current rules:**
1. Every function gets a category (entry_point, game_code, exception_handler, etc.)
2. Every category gets a priority formula
3. Confidence is: 1 signal (LOW), 2 signals (MEDIUM), 3+ signals (HIGH), 4+ (CERTAIN)
4. Address locality matters: functions within 0x10000 belong together
5. Import correlation matters: function calls APIs → visible in import catalog

**Rules to add after Phase 2:**
- Opcode patterns (certain byte sequences = packet handlers)
- Decompilation heuristics (switch statements have characteristic patterns)
- xref clustering (heavily xref'd = core functions vs. rarely xref'd = edge)

**Success criteria:** You add a rule only after seeing it fail 2+ times; rules are evidence-backed.


### 20. TREAT ANALYSIS FAILURES AS SYSTEM SIGNALS
**Rule:** When analysis breaks, fix the system, not just the result.

**For RE:**

**Failure: "Can't find opcode handlers"**
→ Root cause: No strategy for byte pattern search (need Phase 2)
→ System fix: Add opcode_hunter.py to Phase 2 tasks
→ Don't: Manually list handlers (scales terribly)

**Failure: "Confidence keeps getting too high"**
→ Root cause: 2-signal threshold is too low for this binary
→ System fix: Raise to 3 signals; make CERTAIN require API call evidence
→ Don't: Promise lower confidence (won't stick)

**Failure: "Tools generate 0 edges in call graphs"**
→ Root cause: Cached mode doesn't have xref data
→ System fix: Prepare Phase 2 to use live Ghidra
→ Don't: Fake the edges (breaks downstream analysis)

**Success criteria:** Every failure becomes a documented lesson.


### 21. APPLY SECURITY-CONSCIOUS ANALYSIS
**Rule:** RE work can expose vulnerabilities; handle responsibly.

**For RE:**

**On anti-cheat documented:**
- You've identified detection vectors (good!)
- DON'T publish exploit code (bad)
- DO publish detection limitations (helpful for legitimate users)
  
**Example:**
- ✓ "Anti-cheat checks for Module32First calls to detect DLL injection"
- ✗ "Here's how to bypass detections..."

**Shared analysis:**
- Does this reveal secrets? (deployment paths, encryption keys)
- Is it a roadmap for attacks? (exactly which vectors can be bypassed)
- Can it improve the target? (report vulns upstream if possible)

**Success criteria:** Analysis is defensive (helps understand threats) not offensive.


### 22. CALIBRATE ANALYSIS CONFIDENCE PROPERLY
**Rule:** Not all findings need equal certainty; assess per finding.

**For RE:**

**High probability of error + high impact → deep verification needed:**
- "This is the packet dispatcher" — REQUIRES 3+ signals + Phase 2 decomp
- "Anti-cheat is unbypassable" — REQUIRES complete detection vector catalog

**Low probability of error + low impact → light verification:**
- "Entry point is 0x00401000" — Standard PE, CERTAIN
- "Graphics subsystem uses OpenGL" — 70 imports, LOW error risk

**Unknown probability/impact → escalate:**
- "FUN_0088b010 is addon system" — Candidate, needs Phase 2

**Success criteria:** Confidence is justified by impact/risk ratio, not just data count.


### 23. WRITE ANALYSIS FOR FUTURE AGENTS/TEAMS
**Rule:** Autonomous agents (or future humans) need explicit context.

**For RE:**

**Bad analysis notes:**
- "This is the main function" (why? how do you know?)
- "The network code is here" (which functions?)
- "Anti-cheat uses these APIs" (where? how certain?)

**Good analysis notes:**
- "Entry @ 0x00401000 (CERTAIN) — PE header + standard location. Function entry @ 0x00401010 (HIGH) — immediately follows, WinMain pattern. Calls subsystem init, then enters game loop."
- "Network subsystem: based on IOCP imports (GetQueuedCompletionStatus, CreateIoCompletionPort) + address locality (0x0047cc90 region). Dispatcher candidate @ 0x0047cc90 (MEDIUM) — large function, IOCP-adjacent, opcode-structured."
- "Anti-cheat verified (CERTAIN):"

**Format:** Task reader, purpose, success criteria → agent can execute independently.

**Success criteria:** A 1-week-later-you or a fresh team member can understand the work.


### 24. ENGINEER MULTI-SUBSYSTEM RE IN STAGES
**Rule:** Analyzing complex binaries requires staged integration.

**For RE:**

**Stage 1: Decouple subsystems**
- Graphics independent of network
- Anti-cheat independent of game loop
- Each has distinct import set, address region, function cluster

**Stage 2: Map dependencies**
- Graphics feeds into renderer callback (called by game loop)
- Network feeds into game loop (periodic dispatch)
- Anti-cheat runs in background (separate thread?)

**Stage 3: Integrate with evidence**
- Find dispatcher function
- Verify it calls network handlers
- Verify handlers update graphics state
- Verify anti-cheat is truly async

**Never assume integration without evidence.**

**Success criteria:** Integration diagram with evidence citations for each edge.


### 25. CRAFT ANALYSIS TOOLS CAREFULLY
**Rule:** Poor tool design causes silent failures; good tool design guides users.

**For RE:**

**Bad tool output:**
```
Error
```

**Good tool output:**
```
[ERROR] Failed to load reports/SUBSYSTEM_STRUCTURE_MAP.json
  [Details] File not found. Run: python mcp-runner/subsystem_correlator.py
  [Next step] Re-run correlator, then retry analysis
```

**Tool descriptions should include:**
- What it does
- What inputs it needs
- Exact output files/formats
- Common failure modes + fixes
- Time estimate

**Success criteria:** Tools rarely need manual debugging; error messages are actionable.


### 26. SUSTAIN RE ANALYSIS PACE
**Rule:** Analysis requires constant decision-making; fatigue kills quality.

**For RE:**
- 3-4 hours of intensive analysis per day is realistic
- After that, decision quality drops (confidence scores get sloppy)
- Stop when you find yourself approving findings without rereading them
- Next session, bring fresh eyes

**With agents:**
- Agents don't fatigue; YOU do
- Queue analysis tasks end-of-day; review results when fresh
- Automated runs can happen 24/7; your review must be rested

**Success criteria:** No analysis session exceeds 4 hours; output quality steady throughout day.


### 27. WEAVE RE INTO YOUR WORKFLOW
**Rule:** RE isn't a separate project; it's integrated investigation.

**For RE:**
- **Parallel track 1:** Live analysis (decomp, xref) when tools available
- **Parallel track 2:** Offline synthesis (build understanding from available data)
- **End-of-day:** Kick off batch analysis tools
- **Next day:** Review results, adjust hypotheses, reiterate

**Never wait idle:** If Docker is down, do offline work. If offline work is done, prepare Phase 2.

**Success criteria:** Continuous progress even with tool unavailability.


### 28. MAKE YOUR ANALYSIS LEGIBLE TO AGENTS
**Rule:** If information isn't in the repo, it doesn't exist to the agent.

**For RE:**

**Self-documenting:**
- File names: `LOCAL_DEEP_ANALYSIS.json` not `analysis.json`
- Directories: `reports/function-docs/`, `data/`, `analysis-output/`
- JSON keys: `memory_layout`, `execution_flows`, `data_structures` (not `m`, `ef`, `ds`)
- Markdown headers: `## Startup Sequence` not `## Beginning`

**Discoverable:**
- README.md links to all key docs
- PROGRESS.md updated after each phase
- JSON has schema comments explaining fields
- Docs cross-reference each other

**Type-hinted (where possible):**
- Functions: `name` (str), `address` (int), `priority` (0-2000), `confidence` ("CERTAIN" | "HIGH" | "MEDIUM" | "LOW")
- Structures: Include `address_range`, `estimated_size`, `fields: [{offset, type, name, source}]`

**Success criteria:** Fresh agent can navigate repo structure, find analysis artifacts, understand findings.

---

## ASCENSION.EXE SPECIFIC LESSONS

### What Worked
1. **Subsystem correlation via imports** — Predicted 6 subsystems before decomp; all validated
2. **Address locality heuristics** — Identified critical functions without live analysis
3. **Anti-cheat API pattern matching** — Detection vectors confirmed 100% by spec
4. **Batch automation** — 14 functions analyzed in one pass with 100% success rate
5. **HTML dashboards** — Visualization made complex data navigable

### What Failed / Improved
1. **Edge count = 0 offline** — Expected limitation; Phase 2 will unlock xrefs
2. **Data structure guessing** — Confidence was 40%; need live memory analysis
3. **Handler enumeration blocked** — Phase 2 will use opcode byte search
4. **No call graph edges** — Cached mode limitation; fixed by design

### Next Phase Readiness
- Phase 2A (entry + main decomp) → confirm startup sequence
- Phase 2B (opcode search) → map 50-100 packet handlers
- Phase 2C (subsystem xref) → validate architecture integration

---

## Quick Reference

| Rule | Focus | Application |
|------|-------|-------------|
| 0 | Meta-Rule | Research → hypothesis → test → document → iterate |
| 1 | Explore | Index binary fully before claiming structure |
| 2 | Plan | Phase subsystems; don't RE everything at once |
| 3 | Verify | Every claim needs 2+ signals |
| 4 | Incremental | One subsystem per pass |
| 5 | Context | Keep analysis outputs queryable; use JSON |
| 6 | Communicate | Explain every confidence level |
| 7 | Quality | Consistent schemas; one finding per entry |
| 8 | Structured | Standardize analysis workflows |
| 9 | Parallelize | Batch independent tasks |
| 10 | Anti-patterns | Avoid over-claiming, dead-end research, trust-then-verify gaps |
| 11 | Hypothesis-driven | Form test → conclude with confidence |
| 12 | Knowledge assets | Build reusable opcode patterns, subsystem roles |
| 13 | Understanding | Explain findings to newcomers |
| 14 | Agent-ready | JSON schema + markdown docs + progress files |
| 15 | Multi-pass | 70% now → 85% Phase 2 → 95% Phase 3 |
| 16 | Precise specs | "Map startup sequence (5 stages)" not "understand binary" |
| 17 | Know limits | Offline reaches 70%; Phase 2 unlocks more |
| 18 | Avoid debt | Re-validate findings; don't inflate confidence |
| 19 | Rules build | Add rules only after repeated failures |
| 20 | Fix systems | Address root causes, not symptoms |
| 21 | Security | Thoughtful about exploit vs. defense |
| 22 | Calibrate | Confidence matches impact/risk |
| 23 | Future-proof | Document for autonomous execution |
| 24 | Staged integration | Decouple → map → integrate with evidence |
| 25 | Tool design | Errors are actionable; outputs are self-documenting |
| 26 | Pace | 3-4 hrs/day; fatigue kills quality |
| 27 | Workflow | Parallel offline + live when available |
| 28 | Legibility | Semantic names, discoverable structure, agent-readable |

---

## Implementation Progress

**✓ DONE (Phase 1):**
- Rules 1-6: Explore, plan, verify, incremental, context, communicate
- Rules 8-9: Structured workflows, parallelization
- Rules 12-14: Knowledge assets, understanding, agent environments
- Rules 23, 28: Future-proofing, legibility

**IN PROGRESS (Rules applied to this session):**
- Rule 2: Phase planning (Phase 1 done; Phase 2-3 planned)
- Rule 15: Multi-pass refinement (70% → 85% next)
- Rule 19: Rules building (this document!)

**NEXT (Phase 2 onwards):**
- Rules 3, 17: Verify with live tools; know when to switch
- Rule 11: Hypothesis validation (decomp will test all candidates)
- Rules 20-22: Fix systems based on failures

---

## For Next Agent Session

Print this file. Use it to:
1. Validate current analysis (rules 1-6, 8-9, 12-14 ✓)
2. Plan Phase 2 using rule 2 structure
3. Apply rule 17: Know when to use live tools
4. Maintain rule 5: Keep outputs lean and queryable
5. Follow rule 26: Cap analysis sessions to 4 hours

This document IS your harness.
