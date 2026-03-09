#!/usr/bin/env python3
"""
Data Structure Analyzer - Find and document data structures, vtables, imports
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
import requests

MCP_BASE = os.getenv("MCP_BASE", "http://ghidrassist-mcp:8080").rstrip("/")
PROGRAM_NAME = os.getenv("PROGRAM_NAME", "Ascension.exe")

class McpClient:
    def __init__(self, base_url: str):
        self.base = base_url
        self.next_id = 1
        self.session_id = None
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _rpc(self, method: str, params: Dict) -> Dict:
        payload = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.next_id += 1
        headers = dict(self.session.headers)
        headers["Accept"] = "application/json, text/event-stream"
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        resp = self.session.post(f"{self.base}/mcp", headers=headers, 
                                 data=json.dumps(payload), timeout=90)
        if not self.session_id:
            self.session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
        data = resp.json()
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"MCP error: {data['error']}")
        return data

    def _notify(self, method: str, params: Dict) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        headers = dict(self.session.headers)
        if self.session_id:
            headers["mcp-session-id"] = self.session_id
        self.session.post(f"{self.base}/mcp", headers=headers, 
                         data=json.dumps(payload), timeout=60)

    def initialize(self):
        result = self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "data-structure-analyzer", "version": "1.0.0"},
        })
        self._notify("notifications/initialized", {})
        return result

    def call_tool(self, name: str, arguments: Dict) -> str:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        content = result.get("result", {}).get("content", [])
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    return str(item.get("text", ""))
        return json.dumps(result, indent=2)

def analyze_imports(client: McpClient) -> Dict:
    """Comprehensive import analysis"""
    print("[*] Analyzing all imports...")
    
    imports = {}
    offset = 0
    limit = 200
    all_imports_text = ""
    
    while True:
        try:
            chunk = client.call_tool("list_imports", {
                "program_name": PROGRAM_NAME,
                "offset": offset,
                "limit": limit
            })
            
            if not chunk or "No imports" in chunk:
                break
            
            all_imports_text += chunk + "\n"
            
            line_count = len([l for l in chunk.split('\n') if ' from ' in l])
            print(f"  [+] Fetched {line_count} imports (offset {offset})")
            
            if line_count < limit:
                break
            
            offset += limit
            
        except Exception as e:
            print(f"  [-] Error fetching imports at offset {offset}: {e}")
            break
    
    # Categorize imports by DLL
    by_dll = defaultdict(list)
    
    for line in all_imports_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+from\s+(.+?)\s+@', line)
        if match:
            func_name, dll_name = match.groups()
            by_dll[dll_name].append(func_name)
    
    print(f"[+] Total DLLs imported from: {len(by_dll)}")
    for dll, funcs in by_dll.items():
        print(f"  {dll}: {len(funcs)} functions")
    
    return {
        "by_dll": dict(by_dll),
        "total_imports": sum(len(v) for v in by_dll.values()),
        "raw": all_imports_text[:10000]
    }

def analyze_data_sections(client: McpClient) -> Dict:
    """Analyze memory segments and data sections"""
    print("\n[*] Analyzing memory segments...")
    
    try:
        segments = client.call_tool("list_segments", {
            "program_name": PROGRAM_NAME
        })
        
        return {"segments": segments[:5000]}
    except Exception as e:
        print(f"  [-] Error analyzing segments: {e}")
        return {}

def find_potential_vtables(client: McpClient) -> List[Dict]:
    """Find potential virtual function tables"""
    print("\n[*] Searching for potential vtables...")
    
    vtables = []
    
    # Look for data containing function pointers
    try:
        data_list = client.call_tool("list_data", {
            "program_name": PROGRAM_NAME,
            "limit": 500
        })
        
        # Parse for pointer arrays
        for line in data_list.split('\n'):
            if 'pointer' in line.lower() or 'array' in line.lower():
                match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)', line)
                if match:
                    name, addr = match.groups()
                    
                    # Get hex dump to see if it's a table of pointers
                    try:
                        hexdump = client.call_tool("get_hexdump", {
                            "program_name": PROGRAM_NAME,
                            "address": f"0x{addr}",
                            "len": 64
                        })
                        
                        vtables.append({
                            "name": name,
                            "address": f"0x{addr}",
                            "hexdump": hexdump[:500]
                        })
                        
                        if len(vtables) >= 20:
                            break
                    except:
                        pass
    
    except Exception as e:
        print(f"  [-] Error finding vtables: {e}")
    
    print(f"[+] Found {len(vtables)} potential vtable candidates")
    return vtables

def analyze_data_types(client: McpClient) -> Dict:
    """Get defined data types and structures"""
    print("\n[*] Analyzing defined data types...")
    
    try:
        # Get all data types
        types_result = client.call_tool("list_data_types", {
            "program_name": PROGRAM_NAME,
            "limit": 200
        })
        
        # Look for interesting structures
        interesting_types = []
        for line in types_result.split('\n'):
            if any(keyword in line.lower() for keyword in ['struct', 'class', 'packet', 'message']):
                interesting_types.append(line.strip())
        
        return {
            "all_types": types_result[:5000],
            "interesting_count": len(interesting_types),
            "interesting_types": interesting_types[:50]
        }
    
    except Exception as e:
        print(f"  [-] Error analyzing data types: {e}")
        return {}

def find_string_references(client: McpClient, target_strings: List[str]) -> Dict:
    """Find xrefs to specific interesting strings"""
    print("\n[*] Finding cross-references to key strings...")
    
    results = {}
    
    for target in target_strings[:10]:  # Limit to 10 to avoid excessive time
        try:
            # First find the string
            str_results = client.call_tool("list_strings", {
                "program_name": PROGRAM_NAME,
                "filter": target,
                "min_length": 3
            })
            
            # Extract address
            match = re.search(r'@\s+([0-9a-fA-F]+)', str_results)
            if match:
                addr = match.group(1)
                
                # Get xrefs to this string
                xrefs = client.call_tool("xrefs", {
                    "program_name": PROGRAM_NAME,
                    "address": f"0x{addr}",
                    "direction": "to",
                    "limit": 20
                })
                
                if xrefs and "No references" not in xrefs:
                    results[target] = {
                        "string_address": f"0x{addr}",
                        "xrefs": xrefs[:1000]
                    }
                    print(f"  [+] Found xrefs to '{target}'")
        
        except Exception as e:
            pass
    
    return results

def main():
    print("=" * 80)
    print("DATA STRUCTURE ANALYZER - Comprehensive Data Analysis")
    print("=" * 80)
    
    client = McpClient(MCP_BASE)
    
    try:
        print("\n[*] Initializing MCP connection...")
        client.initialize()
        print("[+] Connected to Ghidra MCP server")
        
        report = {
            "target": PROGRAM_NAME,
            "analysis_type": "comprehensive_data_structure_analysis",
            "findings": {}
        }
        
        # 1. Analyze imports
        report["findings"]["imports"] = analyze_imports(client)
        
        # 2. Analyze memory segments
        report["findings"]["memory_segments"] = analyze_data_sections(client)
        
        # 3. Find vtables
        report["findings"]["potential_vtables"] = find_potential_vtables(client)
        
        # 4. Analyze data types
        report["findings"]["data_types"] = analyze_data_types(client)
        
        # 5. Find xrefs to key strings
        key_strings = ["Realm:", "movement", "packet", "opcode", "spell", "error"]
        report["findings"]["string_xrefs"] = find_string_references(client, key_strings)
        
        # Save report
        output_path = Path("/reports/DATA_STRUCTURE_ANALYSIS.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Analysis complete! Report saved to {output_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        imports = report["findings"]["imports"]
        print(f"Total imports: {imports['total_imports']}")
        print(f"DLLs imported from: {len(imports['by_dll'])}")
        print(f"Potential vtables found: {len(report['findings']['potential_vtables'])}")
        print(f"String xrefs analyzed: {len(report['findings']['string_xrefs'])}")
        
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
