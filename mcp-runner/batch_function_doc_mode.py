#!/usr/bin/env python3
"""
Batch Function Documenting Mode
Runs function_doc_mode repeatedly over selected functions and generates call-graph docs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple
import re

DEFAULT_REPORT = Path("./reports/mcp-analysis.report.json")
DEFAULT_OUTPUT_DIR = Path("./reports/function-docs")
SCRIPT_PATH = Path("./mcp-runner/function_doc_mode.py")

NOISE_PREFIXES = (
    "Catch_All@",
    "Unwind@",
)

PRIORITY_NAMES = [
    "entry",
    "FUN_00401010",
    "FUN_004133c7",
    "FUN_0047cc90",
    "FUN_0088b010",
    "thunk_FUN_00401010",
    "thunk_FUN_004133c7",
    "Module32First",
    "Module32Next",
    "CreateToolhelp32Snapshot",
    "Thread32First",
    "Thread32Next",
    "AssertAndCrash",
]


def parse_functions_from_report(report_path: Path) -> List[Tuple[str, str]]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    text = report.get("calls", {}).get("list_functions", {}).get("text", "")

    functions: List[Tuple[str, str]] = []
    for line in text.splitlines():
        m = re.match(r"^\s*-\s+(.+?)\s+@\s+([0-9A-Fa-f]+)\s+\((\d+)\s+params\)", line)
        if not m:
            continue
        name, addr, _ = m.groups()
        functions.append((name.strip(), addr.upper()))
    return functions


def pick_targets(functions: List[Tuple[str, str]], max_count: int) -> List[str]:
    by_name = {name: addr for name, addr in functions}

    selected: List[str] = []

    # 1) Priority list first
    for p in PRIORITY_NAMES:
        if p in by_name and p not in selected:
            selected.append(p)

    # 2) Add additional non-noise functions
    for name, _ in functions:
        if name in selected:
            continue
        if name.startswith(NOISE_PREFIXES):
            continue
        selected.append(name)
        if len(selected) >= max_count:
            break

    return selected[:max_count]


def run_one(py: str, function_name: str, depth: int, direction: str, no_live: bool) -> int:
    cmd = [
        py,
        str(SCRIPT_PATH),
        "--function",
        function_name,
        "--depth",
        str(depth),
        "--direction",
        direction,
    ]
    if no_live:
        cmd.append("--no-live")

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout, end="")
    if result.returncode != 0:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch function documenting mode")
    parser.add_argument("--python", default=sys.executable, help="Python executable")
    parser.add_argument("--report", default=str(DEFAULT_REPORT))
    parser.add_argument("--max-count", type=int, default=20)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--direction", choices=["both", "callers", "callees"], default="both")
    parser.add_argument("--no-live", action="store_true")
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[batch-doc-mode] Report missing: {report_path}", file=sys.stderr)
        return 1

    if not SCRIPT_PATH.exists():
        print(f"[batch-doc-mode] Missing script: {SCRIPT_PATH}", file=sys.stderr)
        return 1

    functions = parse_functions_from_report(report_path)
    targets = pick_targets(functions, max_count=max(1, args.max_count))

    print(f"[batch-doc-mode] Targets selected: {len(targets)}")
    for i, name in enumerate(targets, 1):
        print(f"  {i:2d}. {name}")

    failures = 0
    for name in targets:
        print(f"\n[batch-doc-mode] Generating docs for: {name}")
        rc = run_one(args.python, name, args.depth, args.direction, args.no_live)
        if rc != 0:
            failures += 1

    print("\n[batch-doc-mode] Done")
    print(f"[batch-doc-mode] Success: {len(targets) - failures} | Failed: {failures}")
    print(f"[batch-doc-mode] Output directory: {DEFAULT_OUTPUT_DIR}")
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
