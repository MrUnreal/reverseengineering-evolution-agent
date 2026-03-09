import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests


def log(msg: str) -> None:
    print(f"[mcp-runner] {msg}", flush=True)


MCP_BASE = os.getenv("MCP_BASE", "http://ghidrassist-mcp:8080").rstrip("/")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/reports"))
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "900"))
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "3"))
PROGRAM_NAME = os.getenv("PROGRAM_NAME", "")


session = requests.Session()
session.headers.update({"Content-Type": "application/json"})


class McpClient:
    def __init__(self, base_url: str):
        self.base = base_url
        self.next_id = 1
        self.session_id: Optional[str] = None

    def _rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        }
        self.next_id += 1

        headers = dict(session.headers)
        headers["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        resp = session.post(f"{self.base}/mcp", headers=headers, data=json.dumps(payload), timeout=60)
        if not self.session_id:
            self.session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")

        try:
            data = resp.json()
        except Exception:
            text = resp.text or ""
            data = self._decode_possible_sse(text)
            if data is None:
                data = {"raw": text, "status_code": resp.status_code}

        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"MCP error in {method}: {data['error']}")
        if isinstance(data, dict) and data.get("stackTrace") and data.get("message"):
            raise RuntimeError(f"MCP transport error in {method}: {data.get('message')}")
        return data

    def _decode_possible_sse(self, text: str) -> Optional[Dict[str, Any]]:
        if "data:" not in text:
            return None

        # pick the last data: payload in case multiple events are present
        data_lines = [line[len("data:"):].strip() for line in text.splitlines() if line.startswith("data:")]
        if not data_lines:
            return None

        payload = data_lines[-1]
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def _notify(self, method: str, params: Dict[str, Any]) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }

        headers = dict(session.headers)
        headers["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        session.post(f"{self.base}/mcp", headers=headers, data=json.dumps(payload), timeout=60)

    def initialize(self) -> Dict[str, Any]:
        init = self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "reverseengineering-mcp-runner", "version": "0.1.0"},
            },
        )
        # required notification in MCP handshake
        self._notify("notifications/initialized", {})
        return init

    def tools_list(self) -> Dict[str, Any]:
        return self._rpc("tools/list", {})

    def tools_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})


def wait_for_server(base: str) -> None:
    deadline = time.time() + TIMEOUT_SECONDS
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        try:
            # /sse may keep connection open indefinitely; /mcp gives fast HTTP responses
            r = session.get(f"{base}/mcp", timeout=3)
            if r.status_code < 500:
                log(f"MCP endpoint reachable via /mcp (status={r.status_code})")
                return
        except Exception as ex:
            if attempts % 20 == 0:
                log(f"Waiting for MCP server... ({ex})")
        time.sleep(POLL_INTERVAL_SECONDS)
    raise TimeoutError(f"MCP server was not reachable at {base} within timeout")


def parse_text_content(call_result: Dict[str, Any]) -> str:
    result = call_result.get("result", {}) if isinstance(call_result, dict) else {}
    content = result.get("content", []) if isinstance(result, dict) else []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                return str(item.get("text", ""))
    return json.dumps(call_result, indent=2)


def answer_question(question: str, calls: Dict[str, Any]) -> Dict[str, Any]:
    q = question.lower().strip()

    fn_text = calls.get("list_functions", {}).get("text", "")
    imp_text = calls.get("list_imports", {}).get("text", "")
    str_text = calls.get("list_strings", {}).get("text", "")

    if "entry" in q or "main" in q:
        return {
            "question": question,
            "method": "list_functions",
            "answer": "Use the function list to identify likely entry routines (main/start/WinMain).",
            "evidence_excerpt": fn_text[:1200],
        }

    if "network" in q or "socket" in q or "http" in q:
        return {
            "question": question,
            "method": "list_imports + list_strings",
            "answer": "Check imports/strings for networking indicators (WinHTTP/WinINet/Winsock, URLs, domains).",
            "evidence_excerpt": (imp_text + "\n\n" + str_text)[:1200],
        }

    if "string" in q or "suspicious" in q or "ioc" in q:
        return {
            "question": question,
            "method": "list_strings",
            "answer": "Extracted strings can reveal URLs, command patterns, mutex names, or file paths.",
            "evidence_excerpt": str_text[:1200],
        }

    return {
        "question": question,
        "method": "program metadata",
        "answer": "No specialized question route; inspect program info/functions/imports/strings sections.",
        "evidence_excerpt": json.dumps({
            "program": calls.get("get_program_info", {}).get("text", "")[:400],
            "imports": imp_text[:400],
            "strings": str_text[:400],
        }, indent=2),
    }


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    wait_for_server(MCP_BASE)

    client = McpClient(MCP_BASE)
    report: Dict[str, Any] = {
        "mcp_base": MCP_BASE,
        "program_name": PROGRAM_NAME,
    }
    raw_questions = os.getenv("QUESTIONS", "").strip()
    questions = [q.strip() for q in raw_questions.split("||") if q.strip()] if raw_questions else []

    try:
        report["initialize"] = client.initialize()
        report["tools_list"] = client.tools_list()

        base_args: Dict[str, Any] = {}
        if PROGRAM_NAME:
            base_args["program_name"] = PROGRAM_NAME

        calls = {}
        for tool_name, args in [
            ("get_program_info", {}),
            ("list_functions", {"limit": 200}),
            ("list_imports", {}),
            ("list_strings", {"limit": 200}),
        ]:
            merged = dict(base_args)
            merged.update(args)
            result = client.tools_call(tool_name, merged)
            calls[tool_name] = {
                "raw": result,
                "text": parse_text_content(result),
            }

        report["calls"] = calls
        if questions:
            report["qna"] = [answer_question(q, calls) for q in questions]
        out = OUTPUT_DIR / "mcp-analysis.report.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        log(f"Wrote MCP report: {out}")
        return 0
    except Exception as ex:
        report["error"] = str(ex)
        out = OUTPUT_DIR / "mcp-analysis.error.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        log(f"MCP analysis failed: {ex}")
        log(f"Wrote error report: {out}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
