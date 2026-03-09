import json
import os
from typing import Any, Dict, Optional

import requests
import streamlit as st


MCP_BASE = os.getenv("MCP_BASE", "http://localhost:8080").rstrip("/")
DEFAULT_PROGRAM = os.getenv("PROGRAM_NAME", "flux-setup.exe")


class McpClient:
    def __init__(self, base_url: str):
        self.base = base_url
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.next_id = 1
        self.session_id: Optional[str] = None

    def _decode_possible_sse(self, text: str) -> Optional[Dict[str, Any]]:
        if "data:" not in text:
            return None
        data_lines = [line[len("data:"):].strip() for line in text.splitlines() if line.startswith("data:")]
        if not data_lines:
            return None
        try:
            return json.loads(data_lines[-1])
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

        resp = self.session.post(f"{self.base}/mcp", headers=headers, json=payload, timeout=30)
        if not self.session_id:
            self.session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")

        try:
            data = resp.json()
        except Exception:
            text = resp.text or ""
            data = self._decode_possible_sse(text) or {"raw": text, "status_code": resp.status_code}

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
        self.session.post(f"{self.base}/mcp", headers=headers, json=payload, timeout=30)

    def initialize(self) -> Dict[str, Any]:
        init = self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "streamlit-mcp-ui", "version": "0.1.0"},
            },
        )
        self._notify("notifications/initialized", {})
        return init

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})


def extract_text(result: Dict[str, Any]) -> str:
    payload = result.get("result", {}) if isinstance(result, dict) else {}
    content = payload.get("content", []) if isinstance(payload, dict) else []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                return str(item.get("text", ""))
    return json.dumps(result, indent=2)


def answer_question(question: str, functions_text: str, imports_text: str, strings_text: str) -> str:
    q = question.lower()

    if any(x in q for x in ["entry", "main", "start"]):
        return (
            "Likely entry candidates were found in function output (look for `entry`, `WinMain`, startup stubs).\n\n"
            + functions_text[:3000]
        )

    if any(x in q for x in ["network", "http", "socket", "dns", "url"]):
        return (
            "Network indicators are usually seen in imports/strings (WinHTTP/WinINet/Winsock, URLs/domains).\n\n"
            + imports_text[:1600]
            + "\n\n"
            + strings_text[:1600]
        )

    if any(x in q for x in ["string", "ioc", "suspicious", "persistence", "registry"]):
        return (
            "Suspicious indicators from strings/imports:\n\n"
            + strings_text[:2600]
            + "\n\n"
            + imports_text[:1200]
        )

    return (
        "General triage snapshot:\n\n"
        + functions_text[:1200]
        + "\n\n"
        + imports_text[:1200]
        + "\n\n"
        + strings_text[:1200]
    )


st.set_page_config(page_title="RE MCP Chat", layout="wide")
st.title("Reverse Engineering MCP Chat")
st.caption("Ask questions about the loaded executable using live GhidrAssistMCP tools.")

col1, col2 = st.columns([2, 1])
with col1:
    mcp_base = st.text_input("MCP Base URL", value=MCP_BASE)
with col2:
    program_name = st.text_input("Program Name", value=DEFAULT_PROGRAM)

if "client" not in st.session_state or st.session_state.get("mcp_base") != mcp_base:
    st.session_state.client = McpClient(mcp_base)
    st.session_state.mcp_base = mcp_base
    st.session_state.initialized = False

if st.button("Connect to MCP") or not st.session_state.initialized:
    try:
        init_result = st.session_state.client.initialize()
        st.session_state.initialized = True
        st.success("Connected to MCP server")
        with st.expander("Initialize response"):
            st.json(init_result)
    except Exception as ex:
        st.error(f"Failed to connect/initialize: {ex}")

question = st.text_area("Ask about the EXE", value="What looks suspicious about this installer?", height=120)

if st.button("Analyze & Answer"):
    if not st.session_state.initialized:
        st.warning("Connect to MCP first.")
    else:
        with st.spinner("Calling MCP tools..."):
            base_args = {"program_name": program_name} if program_name else {}
            prog = st.session_state.client.call_tool("get_program_info", base_args)
            funcs = st.session_state.client.call_tool("list_functions", {**base_args, "limit": 120})
            imps = st.session_state.client.call_tool("list_imports", {**base_args, "limit": 120})
            strs = st.session_state.client.call_tool("list_strings", {**base_args, "limit": 220, "min_length": 4})

            prog_text = extract_text(prog)
            funcs_text = extract_text(funcs)
            imps_text = extract_text(imps)
            strs_text = extract_text(strs)

            answer = answer_question(question, funcs_text, imps_text, strs_text)

        st.subheader("Answer")
        st.write(answer)

        with st.expander("Program info"):
            st.text(prog_text)
        with st.expander("Functions"):
            st.text(funcs_text)
        with st.expander("Imports"):
            st.text(imps_text)
        with st.expander("Strings"):
            st.text(strs_text)
