#!/usr/bin/env python3
"""
Lightweight schema validator for findings.v1 bundles.

No third-party dependencies required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ALLOWED_CONFIDENCE = {"CERTAIN", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def fail(msg: str) -> int:
    print(f"[schema][ERROR] {msg}")
    return 1


def validate_findings_bundle(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    required_top = ["schema_version", "generated_at", "target", "findings"]
    for key in required_top:
        if key not in data:
            errors.append(f"missing top-level key: {key}")

    if data.get("schema_version") != "findings.v1":
        errors.append("schema_version must be 'findings.v1'")

    target = data.get("target")
    if not isinstance(target, dict):
        errors.append("target must be an object")
    else:
        if "name" not in target or not isinstance(target.get("name"), str):
            errors.append("target.name must be a string")

    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) == 0:
        errors.append("findings must be a non-empty array")
        return errors

    for idx, finding in enumerate(findings):
        prefix = f"findings[{idx}]"
        if not isinstance(finding, dict):
            errors.append(f"{prefix} must be an object")
            continue

        for req in ["id", "title", "confidence", "evidence", "source"]:
            if req not in finding:
                errors.append(f"{prefix} missing required field: {req}")

        if not isinstance(finding.get("id"), str):
            errors.append(f"{prefix}.id must be a string")

        if finding.get("confidence") not in ALLOWED_CONFIDENCE:
            errors.append(
                f"{prefix}.confidence must be one of {sorted(ALLOWED_CONFIDENCE)}"
            )

        evidence = finding.get("evidence")
        if not isinstance(evidence, list) or len(evidence) == 0:
            errors.append(f"{prefix}.evidence must be a non-empty array")
        else:
            for eidx, ev in enumerate(evidence):
                eprefix = f"{prefix}.evidence[{eidx}]"
                if not isinstance(ev, dict):
                    errors.append(f"{eprefix} must be an object")
                    continue
                if not isinstance(ev.get("signal_type"), str):
                    errors.append(f"{eprefix}.signal_type must be a string")
                if not isinstance(ev.get("detail"), str):
                    errors.append(f"{eprefix}.detail must be a string")

        source = finding.get("source")
        if not isinstance(source, dict):
            errors.append(f"{prefix}.source must be an object")
        else:
            if not isinstance(source.get("tool"), str):
                errors.append(f"{prefix}.source.tool must be a string")
            if not isinstance(source.get("artifact"), str):
                errors.append(f"{prefix}.source.artifact must be a string")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate findings.v1 bundle")
    parser.add_argument("--schema", required=True, help="Schema path (informational)")
    parser.add_argument("--file", required=True, help="JSON findings bundle to validate")
    args = parser.parse_args()

    schema_path = Path(args.schema)
    file_path = Path(args.file)

    if not schema_path.exists():
        return fail(f"schema file not found: {schema_path}")
    if not file_path.exists():
        return fail(f"input file not found: {file_path}")

    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return fail(f"failed to parse JSON: {exc}")

    if not isinstance(data, dict):
        return fail("top-level JSON must be an object")

    errors = validate_findings_bundle(data)
    if errors:
        print("[schema] Validation FAILED")
        for err in errors:
            print(f"  - {err}")
        return 1

    print(f"[schema] Validation OK: {file_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
