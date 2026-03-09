#!/usr/bin/env python3
"""
Function Documenting Mode
Generate per-function call graph documentation (JSON + Mermaid + Markdown).

Usage examples:
  python mcp-runner/function_doc_mode.py --function entry
  python mcp-runner/function_doc_mode.py --function 0x00401000 --depth 3
  python mcp-runner/function_doc_mode.py --function FUN_0047cc90 --no-live
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests


DEFAULT_MCP_BASE = os.getenv("MCP_BASE", "http://ghidrassist-mcp:8080").rstrip("/")
DEFAULT_REPORT = Path("./reports/mcp-analysis.report.json")
DEFAULT_OUTPUT_DIR = Path("./reports/function-docs")


@dataclass
class FunctionInfo:
    name: str
    address: str
    params: int = 0


class McpClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.next_id = 1
        self.session_id: Optional[str] = None
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _decode_possible_sse(self, text: str) -> Optional[Dict[str, Any]]:
        if "data:" not in text:
            return None
        data_lines = [line[len("data:"):].strip() for line in text.splitlines() if line.startswith("data:")]
        if not data_lines:
            return None
        payload = data_lines[-1]
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def _rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params,
        }
        self.next_id += 1

        headers = dict(self.session.headers)
        headers["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        resp = self.session.post(f"{self.base}/mcp", headers=headers, data=json.dumps(payload), timeout=60)
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
        return data

    def _notify(self, method: str, params: Dict[str, Any]) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        headers = dict(self.session.headers)
        headers["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        self.session.post(f"{self.base}/mcp", headers=headers, data=json.dumps(payload), timeout=60)

    def initialize(self) -> Dict[str, Any]:
        init = self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "function-doc-mode", "version": "0.1.0"},
            },
        )
        self._notify("notifications/initialized", {})
        return init

    def tools_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})


def parse_text_content(call_result: Dict[str, Any]) -> str:
    result = call_result.get("result", {}) if isinstance(call_result, dict) else {}
    content = result.get("content", []) if isinstance(result, dict) else []
    if isinstance(content, list):
        text_parts: List[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text", "")))
        if text_parts:
            return "\n\n".join(text_parts)
    return ""


def load_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing report: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def parse_functions(functions_text: str) -> List[FunctionInfo]:
    out: List[FunctionInfo] = []
    for line in functions_text.splitlines():
        m = re.match(r"^\s*-\s+(.+?)\s+@\s+([0-9A-Fa-f]+)\s+\((\d+)\s+params\)", line)
        if not m:
            continue
        name, addr, pcount = m.groups()
        out.append(FunctionInfo(name=name.strip(), address=addr.upper(), params=int(pcount)))
    return out


def normalize_addr(s: str) -> str:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return s.upper()


def resolve_target(function_arg: str, known: List[FunctionInfo]) -> Tuple[str, Optional[str]]:
    q = function_arg.strip()
    q_addr = normalize_addr(q)

    by_name = {f.name.lower(): f for f in known}
    by_addr = {f.address.upper(): f for f in known}

    if q.lower() in by_name:
        f = by_name[q.lower()]
        return f.name, f.address

    if q_addr in by_addr:
        f = by_addr[q_addr]
        return f.name, f.address

    # best-effort substring match on function name
    for f in known:
        if q.lower() in f.name.lower():
            return f.name, f.address

    # unknown to local cache; return as-is for live query
    return q, None


def _extract_json_objects(text: str) -> List[Dict[str, Any]]:
    objs: List[Dict[str, Any]] = []
    if not text:
        return objs

    # Fast path: full JSON document
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return [parsed]
    except Exception:
        pass

    # Best-effort scan of JSON-looking fragments
    for match in re.finditer(r"\{[\s\S]{20,}\}", text):
        frag = match.group(0)
        try:
            parsed = json.loads(frag)
            if isinstance(parsed, dict):
                objs.append(parsed)
        except Exception:
            continue
    return objs


def parse_edges_from_graph_payload(payload: Dict[str, Any], target_name: str) -> Set[Tuple[str, str]]:
    edges: Set[Tuple[str, str]] = set()

    # Common shape 1: {edges:[{from,to}, ...]}
    for e in payload.get("edges", []) if isinstance(payload.get("edges"), list) else []:
        if isinstance(e, dict):
            src = str(e.get("from") or e.get("caller") or "").strip()
            dst = str(e.get("to") or e.get("callee") or "").strip()
            if src and dst:
                edges.add((src, dst))

    # Common shape 2: {callers:[...], callees:[...], function:"..."}
    focus = str(payload.get("function") or payload.get("target") or target_name).strip() or target_name

    callers = payload.get("callers", []) if isinstance(payload.get("callers"), list) else []
    for c in callers:
        if isinstance(c, dict):
            name = str(c.get("name") or c.get("function") or c.get("address") or "").strip()
        else:
            name = str(c).strip()
        if name:
            edges.add((name, focus))

    callees = payload.get("callees", []) if isinstance(payload.get("callees"), list) else []
    for c in callees:
        if isinstance(c, dict):
            name = str(c.get("name") or c.get("function") or c.get("address") or "").strip()
        else:
            name = str(c).strip()
        if name:
            edges.add((focus, name))

    return edges


def parse_edges_from_text(text: str, target_name: str) -> Set[Tuple[str, str]]:
    edges: Set[Tuple[str, str]] = set()
    if not text:
        return edges

    # Pattern A: explicit arrows
    for line in text.splitlines():
        m = re.search(r"([^\-\s][^\-]*)\s*->\s*([^\s].+)", line)
        if m:
            src = m.group(1).strip(" -:\t")
            dst = m.group(2).strip(" -:\t")
            if src and dst:
                edges.add((src, dst))

    # Pattern B: sectioned callers/callees lists
    mode = None
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if not line:
            continue
        if "callers" in low:
            mode = "callers"
            continue
        if "callees" in low:
            mode = "callees"
            continue
        m = re.match(r"^[-*]\s+(.+)$", line)
        if mode and m:
            item = m.group(1).strip()
            if mode == "callers":
                edges.add((item, target_name))
            elif mode == "callees":
                edges.add((target_name, item))

    return edges


def parse_call_graph(raw: Optional[Dict[str, Any]], text: str, target_name: str) -> List[Tuple[str, str]]:
    edges: Set[Tuple[str, str]] = set()

    if raw:
        # Try direct JSON in result.content items
        result = raw.get("result", {}) if isinstance(raw, dict) else {}
        content = result.get("content", []) if isinstance(result, dict) else []
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "json" and isinstance(item.get("json"), dict):
                        edges |= parse_edges_from_graph_payload(item["json"], target_name)
                    if item.get("type") == "text":
                        t = str(item.get("text", ""))
                        for obj in _extract_json_objects(t):
                            edges |= parse_edges_from_graph_payload(obj, target_name)

        # Fallback: inspect top-level JSON-like fragments
        for obj in _extract_json_objects(json.dumps(raw)):
            edges |= parse_edges_from_graph_payload(obj, target_name)

    # Text parsing fallback
    edges |= parse_edges_from_text(text, target_name)

    # Clean obvious noise and self loops
    cleaned = {
        (a.strip(), b.strip())
        for (a, b) in edges
        if a.strip() and b.strip() and a.strip() != b.strip()
    }

    return sorted(cleaned)


def sanitize_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_\-\.]+", "_", name.strip())
    slug = slug.strip("_")
    return slug[:120] or "function"


def to_mermaid(edges: List[Tuple[str, str]], target_name: str) -> str:
    if not edges:
        return "graph TD\n  A[\"No edges resolved\"]"

    nodes = sorted({n for e in edges for n in e})
    node_ids = {n: f"N{i}" for i, n in enumerate(nodes, 1)}

    lines = ["graph TD"]
    for n in nodes:
        style = ":::focus" if n == target_name else ""
        label = n.replace('"', "'")
        lines.append(f"  {node_ids[n]}[\"{label}\"]{style}")

    for src, dst in edges:
        lines.append(f"  {node_ids[src]} --> {node_ids[dst]}")

    lines.append("\n  classDef focus fill:#1f3b6e,stroke:#79a8ff,stroke-width:2px,color:#fff")
    return "\n".join(lines)


def write_outputs(
    output_dir: Path,
    function_name: str,
    function_address: Optional[str],
    source: str,
    depth: int,
    direction: str,
    edges: List[Tuple[str, str]],
    mermaid: str,
    raw_text: str,
) -> Dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    slug = sanitize_slug(function_name if function_name else (function_address or "function"))

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    json_path = output_dir / f"{slug}.callgraph.json"
    md_path = output_dir / f"{slug}.callgraph.md"

    payload = {
        "generated_at": ts,
        "function": {
            "name": function_name,
            "address": function_address,
        },
        "query": {
            "depth": depth,
            "direction": direction,
            "source": source,
        },
        "node_count": len({n for e in edges for n in e}),
        "edge_count": len(edges),
        "edges": [{"from": a, "to": b} for a, b in edges],
        "mermaid": mermaid,
        "raw_excerpt": raw_text[:4000],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = []
    md.append(f"# Function Call Graph: `{function_name}`")
    md.append("")
    md.append(f"- **Address:** `{function_address or 'unknown'}`")
    md.append(f"- **Source:** `{source}`")
    md.append(f"- **Depth:** `{depth}`")
    md.append(f"- **Direction:** `{direction}`")
    md.append(f"- **Nodes:** `{payload['node_count']}`")
    md.append(f"- **Edges:** `{payload['edge_count']}`")
    md.append("")
    md.append("## Mermaid Graph")
    md.append("")
    md.append("```mermaid")
    md.append(mermaid)
    md.append("```")
    md.append("")
    md.append("## Edge List")
    md.append("")
    if edges:
        md.append("| Caller | Callee |")
        md.append("|---|---|")
        for a, b in edges:
            md.append(f"| `{a}` | `{b}` |")
    else:
        md.append("No call edges were resolved from available data.")
    md.append("")
    md.append("## Raw MCP Excerpt")
    md.append("")
    md.append("```text")
    md.append((raw_text or "(empty)")[:3000])
    md.append("```")

    md_path.write_text("\n".join(md), encoding="utf-8")

    # Maintain generated index for docs portal
    index_path = output_dir / "index.json"
    if index_path.exists():
        try:
            idx = json.loads(index_path.read_text(encoding="utf-8"))
            if not isinstance(idx, list):
                idx = []
        except Exception:
            idx = []
    else:
        idx = []

    entry = {
        "name": function_name,
        "address": function_address,
        "markdown": f"../reports/function-docs/{md_path.name}",
        "json": f"../reports/function-docs/{json_path.name}",
        "generated_at": ts,
    }

    idx = [e for e in idx if not (e.get("name") == function_name and e.get("address") == function_address)]
    idx.append(entry)
    idx.sort(key=lambda e: (e.get("name") or "").lower())
    index_path.write_text(json.dumps(idx, indent=2), encoding="utf-8")

    return {
        "json": str(json_path),
        "markdown": str(md_path),
        "index": str(index_path),
    }


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate function call graph docs")
    p.add_argument("--function", required=True, help="Function name or address")
    p.add_argument("--depth", type=int, default=2, help="Call graph depth (1-5)")
    p.add_argument("--direction", choices=["both", "callers", "callees"], default="both")
    p.add_argument("--program-name", default=os.getenv("PROGRAM_NAME", ""))
    p.add_argument("--mcp-base", default=DEFAULT_MCP_BASE)
    p.add_argument("--report", default=str(DEFAULT_REPORT))
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    p.add_argument("--no-live", action="store_true", help="Skip live MCP get_call_graph")
    return p.parse_args()


def main() -> int:
    args = build_args()

    report = load_report(Path(args.report))
    list_functions_text = report.get("calls", {}).get("list_functions", {}).get("text", "")
    known_functions = parse_functions(list_functions_text)

    target_name, target_addr = resolve_target(args.function, known_functions)
    raw = None
    text = ""
    source = "cached-report"

    if not args.no_live:
        try:
            client = McpClient(args.mcp_base)
            client.initialize()
            call_args: Dict[str, Any] = {
                "function": target_name,
                "depth": max(1, min(5, int(args.depth))),
                "direction": args.direction,
            }
            if args.program_name:
                call_args["program_name"] = args.program_name
            raw = client.tools_call("get_call_graph", call_args)
            text = parse_text_content(raw)
            source = "live-mcp:get_call_graph"
        except Exception as ex:
            text = f"Live get_call_graph unavailable: {ex}"
            source = "cached-report (live failed)"

    edges = parse_call_graph(raw=raw, text=text, target_name=target_name)
    mermaid = to_mermaid(edges, target_name)

    outputs = write_outputs(
        output_dir=Path(args.output_dir),
        function_name=target_name,
        function_address=target_addr,
        source=source,
        depth=max(1, min(5, int(args.depth))),
        direction=args.direction,
        edges=edges,
        mermaid=mermaid,
        raw_text=text,
    )

    print("[function-doc-mode] Generated:")
    print(f"  - {outputs['markdown']}")
    print(f"  - {outputs['json']}")
    print(f"  - {outputs['index']}")
    print(f"[function-doc-mode] Target: {target_name} ({target_addr or 'unknown'})")
    print(f"[function-doc-mode] Edges: {len(edges)} | Source: {source}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
