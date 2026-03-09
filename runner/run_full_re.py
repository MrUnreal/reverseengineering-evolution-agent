import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


def log(msg: str) -> None:
    print(f"[re-runner] {msg}", flush=True)


def env_int(name: str, default: int) -> int:
    val = os.getenv(name, str(default)).strip()
    try:
        return int(val)
    except ValueError:
        return default


API_BASE = os.getenv("GHIDRA_API_BASE", "http://ghidra-api:9090").rstrip("/")
INPUT_DIR = Path(os.getenv("INPUT_DIR", "/samples"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/reports"))
POLL_INTERVAL_SECONDS = max(1, env_int("POLL_INTERVAL_SECONDS", 5))
TIMEOUT_SECONDS = max(30, env_int("TIMEOUT_SECONDS", 3600))
MIN_STRING_LENGTH = max(1, env_int("MIN_STRING_LENGTH", 6))
MAX_DECOMPILE_FUNCTIONS = max(0, env_int("MAX_DECOMPILE_FUNCTIONS", 30))
TARGET_FILENAME = os.getenv("TARGET_FILENAME", "").strip()


session = requests.Session()
session.headers.update({"Content-Type": "application/json"})


def request_json(method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 60) -> Tuple[int, Dict[str, Any]]:
    url = f"{API_BASE}{path}"
    if method == "GET":
        resp = session.get(url, timeout=timeout)
    elif method == "POST":
        resp = session.post(url, json=payload or {}, timeout=timeout)
    else:
        raise ValueError(f"Unsupported method: {method}")

    text = resp.text or ""
    if "application/json" in resp.headers.get("Content-Type", ""):
        body = resp.json()
    else:
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = {"raw": text}
    return resp.status_code, body


def wait_for_api(max_wait_seconds: int = 180) -> None:
    log(f"Waiting for API at {API_BASE} ...")
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        try:
            status, _ = request_json("GET", "/")
            if status < 500:
                log("API is reachable.")
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"API did not become reachable within {max_wait_seconds}s")


def submit_analysis(file_path: Path) -> str:
    payload = {
        "file_b64": base64.b64encode(file_path.read_bytes()).decode("utf-8"),
        "filename": file_path.name,
        "persist": True,
    }

    # repo code uses /analyze_b64 while README shows /tools/analyze
    candidates = [
        ("POST", "/analyze_b64", payload),
        ("POST", "/tools/analyze", payload),
    ]

    last_error = "Unknown submission failure"
    for method, path, body in candidates:
        try:
            status, data = request_json(method, path, body, timeout=180)
            if status < 300:
                job_id = data.get("job_id") or data.get("id")
                if job_id:
                    log(f"Submitted {file_path.name}: job_id={job_id} via {path}")
                    return str(job_id)
                last_error = f"No job_id in response from {path}: {data}"
            else:
                last_error = f"{path} returned {status}: {data}"
        except Exception as ex:
            last_error = f"{path} failed: {ex}"

    raise RuntimeError(last_error)


def get_status(job_id: str) -> Dict[str, Any]:
    candidates = [
        ("GET", f"/status/{job_id}", None),
        ("POST", "/tools/status", {"job_id": job_id}),
    ]

    for method, path, payload in candidates:
        try:
            status, data = request_json(method, path, payload)
            if status < 300 and isinstance(data, dict):
                return data
        except Exception:
            continue

    return {"status": "unknown", "job_id": job_id}


def call_tool(tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    candidates = [
        ("POST", f"/tools/{tool_name}", payload),
        ("POST", f"/{tool_name}", payload),
    ]

    last: Dict[str, Any] = {"error": f"No response for tool {tool_name}"}
    for method, path, body in candidates:
        try:
            status, data = request_json(method, path, body)
            if status < 300 and isinstance(data, dict):
                return data
            last = {"error": f"{path} returned {status}", "response": data}
        except Exception as ex:
            last = {"error": f"{path} failed", "details": str(ex)}
    return last


def wait_until_done(job_id: str) -> Dict[str, Any]:
    started = time.time()
    while True:
        status_info = get_status(job_id)
        status = str(status_info.get("status", "")).lower()
        if status in {"completed", "done", "success"}:
            return status_info
        if status in {"failed", "error"}:
            raise RuntimeError(f"Analysis failed for {job_id}: {status_info}")
        if time.time() - started > TIMEOUT_SECONDS:
            raise TimeoutError(f"Timed out waiting for analysis completion: {job_id}")
        log(f"Job {job_id} status={status or 'unknown'}; waiting {POLL_INTERVAL_SECONDS}s")
        time.sleep(POLL_INTERVAL_SECONDS)


def summarize_functions(functions: List[Dict[str, Any]], job_id: str) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for fn in functions[:MAX_DECOMPILE_FUNCTIONS]:
        name = fn.get("name")
        addr = fn.get("address")
        if not addr:
            continue

        decomp = call_tool("decompile_function", {"job_id": job_id, "addr": addr})
        xrefs = call_tool("get_xrefs", {"job_id": job_id, "addr": addr})

        enriched.append(
            {
                "name": name,
                "address": addr,
                "decompile": decomp,
                "xrefs": xrefs,
            }
        )
    return enriched


def collect_artifacts(job_id: str) -> Dict[str, Any]:
    functions_resp = call_tool("list_functions", {"job_id": job_id})
    imports_resp = call_tool("list_imports", {"job_id": job_id})
    strings_resp = call_tool("list_strings", {"job_id": job_id, "min_length": MIN_STRING_LENGTH})

    functions = functions_resp.get("functions", [])
    if not isinstance(functions, list):
        functions = []

    return {
        "job_id": job_id,
        "functions_total": len(functions),
        "functions": functions,
        "imports": imports_resp.get("imports", []),
        "strings": strings_resp.get("strings", []),
        "decompiled_sample": summarize_functions(functions, job_id),
    }


def discover_binaries(directory: Path) -> Iterable[Path]:
    if TARGET_FILENAME:
        target = directory / TARGET_FILENAME
        if target.is_file():
            return [target]
        raise FileNotFoundError(f"TARGET_FILENAME={TARGET_FILENAME} not found in {directory}")

    return [p for p in directory.iterdir() if p.is_file()]


def analyze_file(binary_path: Path) -> Dict[str, Any]:
    log(f"Analyzing: {binary_path}")
    job_id = submit_analysis(binary_path)
    completion_status = wait_until_done(job_id)
    artifacts = collect_artifacts(job_id)

    report = {
        "binary": binary_path.name,
        "api_base": API_BASE,
        "completion_status": completion_status,
        "artifacts": artifacts,
        "notes": {
            "project_persistence": "Headless Ghidra project data is persisted under /data/ghidra_projects in the ghidra-api container volume.",
            "open_later": "Use desktop Ghidra and open the persisted project directory to continue manual RE.",
        },
    }
    return report


def write_report(binary_name: str, report: Dict[str, Any]) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"{binary_name}.report.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_path


def main() -> int:
    if not INPUT_DIR.exists():
        log(f"Input directory does not exist: {INPUT_DIR}")
        return 2

    wait_for_api()

    binaries = list(discover_binaries(INPUT_DIR))
    if not binaries:
        log(f"No files found in {INPUT_DIR}")
        return 3

    failures = 0
    for binary_path in binaries:
        try:
            report = analyze_file(binary_path)
            out = write_report(binary_path.name, report)
            log(f"Wrote report: {out}")
        except Exception as ex:
            failures += 1
            error_report = {
                "binary": binary_path.name,
                "error": str(ex),
            }
            out = write_report(binary_path.name, error_report)
            log(f"Failed analysis for {binary_path.name}; wrote error report: {out}")

    if failures:
        log(f"Completed with failures: {failures}/{len(binaries)}")
        return 1

    log(f"Completed successfully for {len(binaries)} binary file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
