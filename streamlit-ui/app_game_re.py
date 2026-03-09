"""
Enhanced Streamlit UI with Game RE capabilities
"""
import json
import os
from typing import Any, Dict, Optional, List
from pathlib import Path

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
                "clientInfo": {"name": "streamlit-game-re-ui", "version": "0.2.0"},
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


def load_knowledge_graph(json_path: str) -> Optional[Dict]:
    """Load knowledge graph from autonomous analysis"""
    if os.path.exists(json_path):
        with open(json_path) as f:
            return json.load(f)
    return None


def display_structure_viewer(structures: Dict):
    """Interactive structure viewer"""
    st.subheader("Discovered Structures")
    
    if not structures:
        st.info("No structures discovered yet. Run autonomous analysis first.")
        return
    
    selected = st.selectbox(
        "Select structure to view:",
        options=list(structures.keys())
    )
    
    if selected:
        struct = structures[selected]
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"### {selected}")
            st.caption(f"Size: {struct['size']} bytes | Confidence: {struct['confidence']:.1%}")
        with col2:
            if st.button("Export to C Header"):
                st.code(generate_c_struct(selected, struct), language='c')
        
        # Display fields as table
        if struct.get('fields'):
            import pandas as pd
            
            field_data = []
            for field in struct['fields']:
                field_data.append({
                    'Offset': f"0x{field['offset']:02X}",
                    'Name': field['name'],
                    'Type': field['type'],
                    'Size': field['size'],
                    'Confidence': f"{field['confidence']:.0%}"
                })
            
            df = pd.DataFrame(field_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Show access patterns
        with st.expander("Field Access Patterns"):
            for field in struct.get('fields', []):
                st.write(f"**{field['name']}** (offset 0x{field['offset']:02X})")
                for access in field.get('accesses', [])[:5]:  # Show first 5
                    st.caption(f"  • {access['access_type']} at 0x{access['location']:08X} in {access['context']}")


def generate_c_struct(name: str, struct_data: Dict) -> str:
    """Generate C structure definition"""
    lines = [
        f"// Confidence: {struct_data['confidence']:.1%}",
        f"struct {name} {{",
    ]
    
    prev_end = 0
    for field in sorted(struct_data['fields'], key=lambda f: f['offset']):
        # Padding
        if field['offset'] > prev_end:
            pad_size = field['offset'] - prev_end
            lines.append(f"    char _pad{prev_end:02X}[{pad_size}];")
        
        # Field
        type_map = {
            'INT32': 'int32_t',
            'FLOAT': 'float',
            'POINTER': 'void*',
            'VECTOR3': 'float[3]',
        }
        ftype = type_map.get(field['type'], 'uint8_t[]')
        lines.append(f"    {ftype} {field['name']};  // +0x{field['offset']:02X}")
        
        prev_end = field['offset'] + field['size']
    
    lines.append(f"}};  // size: 0x{struct_data['size']:X}")
    
    return "\n".join(lines)


# ===== Main UI =====
st.set_page_config(page_title="Game RE Suite", layout="wide")

# Sidebar for mode selection
with st.sidebar:
    st.title("Analysis Mode")
    mode = st.radio(
        "Select workflow:",
        ["Single Binary Triage", "Game RE (Multi-Binary)", "Structure Browser"]
    )
    
    st.divider()
    
    st.caption("MCP Connection")
    mcp_base = st.text_input("MCP Base URL", value=MCP_BASE, label_visibility="collapsed")
    
    if st.button("🔌 Connect", use_container_width=True):
        if "client" not in st.session_state or st.session_state.get("mcp_base") != mcp_base:
            st.session_state.client = McpClient(mcp_base)
            st.session_state.mcp_base = mcp_base
            st.session_state.initialized = False
        
        try:
            init_result = st.session_state.client.initialize()
            st.session_state.initialized = True
            st.success("✓ Connected")
        except Exception as ex:
            st.error(f"Failed: {ex}")


# ===== Single Binary Triage Mode =====
if mode == "Single Binary Triage":
    st.title("🔍 Single Binary Triage")
    st.caption("Quick malware/executable analysis using MCP tools")
    
    program_name = st.text_input("Binary name", value=DEFAULT_PROGRAM)
    
    question = st.text_area(
        "Ask about the binary:",
        value="What looks suspicious about this installer?",
        height=100
    )
    
    if st.button("🔬 Analyze & Answer", type="primary"):
        if "initialized" not in st.session_state or not st.session_state.initialized:
            st.warning("⚠️ Connect to MCP first (sidebar)")
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

            st.subheader("💡 Answer")
            st.write(answer)

            with st.expander("📋 Program Info"):
                st.code(prog_text)
            with st.expander("⚙️ Functions"):
                st.code(funcs_text)
            with st.expander("📚 Imports"):
                st.code(imps_text)
            with st.expander("🔤 Strings"):
                st.code(strs_text)


# ===== Game RE Mode =====
elif mode == "Game RE (Multi-Binary)":
    st.title("🎮 Game Reverse Engineering")
    st.caption("Autonomously analyze game DLLs, discover structures, and generate SDK")
    
    st.info("📁 Upload game DLLs to `/samples/game/` directory, then run autonomous analysis")
    
    # File uploader (mock - in real deployment would save to volume)
    uploaded_files = st.file_uploader(
        "Upload game binaries (DLLs/EXE)",
        accept_multiple_files=True,
        type=['dll', 'exe']
    )
    
    if uploaded_files:
        st.write(f"📦 Ready to analyze {len(uploaded_files)} files:")
        for f in uploaded_files:
            st.caption(f"  • {f.name} ({f.size/1024:.1f} KB)")
    
    col1, col2 = st.columns(2)
    with col1:
        analysis_budget = st.slider(
            "Analysis budget (functions):",
            min_value=100,
            max_value=2000,
            value=500,
            step=100
        )
    
    with col2:
        deep_analysis = st.checkbox("Deep structure inference", value=True)
    
    if st.button("🚀 Start Autonomous Analysis", type="primary"):
        st.warning("This would trigger the autonomous analyzer container. Not yet connected to live backend.")
        
        # In real implementation, this would:
        # 1. Save uploaded files to /samples/game/
        # 2. Trigger agent-runner container with these files
        # 3. Stream progress updates
        # 4. Display results when complete
        
        with st.spinner("Analyzing game binaries..."):
            import time
            progress_bar = st.progress(0)
            status = st.empty()
            
            phases = [
                "Loading binaries...",
                "Building dependency graph...",
                "Discovering VTables...",
                "Analyzing functions...",
                "Synthesizing structures...",
                "Generating SDK...",
            ]
            
            for i, phase in enumerate(phases):
                status.text(phase)
                progress_bar.progress((i + 1) / len(phases))
                time.sleep(0.5)
        
        st.success("✅ Analysis complete! View results in Structure Browser mode.")
    
    # Show sample output structure
    with st.expander("📊 Example Output"):
        st.json({
            "functions_analyzed": 487,
            "structures_discovered": 23,
            "classes_discovered": 15,
            "dlls": ["GameEngine.dll", "Graphics.dll", "Physics.dll"],
            "top_structures": [
                {"name": "Entity", "size": 112, "confidence": 0.92},
                {"name": "Vector3", "size": 12, "confidence": 0.98},
                {"name": "Camera", "size": 256, "confidence": 0.85}
            ]
        })


# ===== Structure Browser Mode =====
elif mode == "Structure Browser":
    st.title("📐 Structure Browser")
    st.caption("View discovered structures from autonomous analysis")
    
    # Try to load knowledge graph
    kg_path = "/reports/game-sdk/knowledge_graph.json"
    if os.path.exists(kg_path):
        kg = load_knowledge_graph(kg_path)
        
        # Display stats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Functions", len(kg.get('nodes', [])))
        with col2:
            st.metric("Structures", len(kg.get('structures', {})))
        with col3:
            st.metric("Classes", len(kg.get('classes', {})))
        with col4:
            st.metric("DLLs", len(kg.get('dlls', {})))
        
        st.divider()
        
        # Structure viewer
        display_structure_viewer(kg.get('structures', {}))
        
        # Class hierarchy
        with st.expander("🏛️ Class Hierarchy"):
            classes = kg.get('classes', {})
            if classes:
                for class_name, class_data in classes.items():
                    st.markdown(f"**{class_name}**")
                    st.caption(f"  VTable @ 0x{class_data['vtable_address']:08X}")
                    if class_data.get('base_classes'):
                        st.caption(f"  Inherits: {', '.join(class_data['base_classes'])}")
                    for method_addr, method_name in class_data.get('virtual_methods', [])[:5]:
                        st.caption(f"    • {method_name} @ 0x{method_addr:08X}")
            else:
                st.info("No classes discovered")
        
        # Export options
        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Download Full SDK (C Headers)", use_container_width=True):
                sdk_path = "/reports/game-sdk/game_sdk.h"
                if os.path.exists(sdk_path):
                    with open(sdk_path) as f:
                        st.download_button(
                            "Download game_sdk.h",
                            f.read(),
                            file_name="game_sdk.h",
                            mime="text/plain"
                        )
        
        with col2:
            if st.button("📥 Download Knowledge Graph (JSON)", use_container_width=True):
                st.download_button(
                    "Download knowledge_graph.json",
                    json.dumps(kg, indent=2),
                    file_name="knowledge_graph.json",
                    mime="application/json"
                )
    
    else:
        st.info("🔍 No analysis results found. Run Game RE analysis first.")
        st.caption(f"Looking for: {kg_path}")
