#!/usr/bin/env python3
"""
Function Deep Analyzer - Comprehensive function analysis
Decompile key functions, analyze call graphs, find patterns
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List
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
                                 data=json.dumps(payload), timeout=60)
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
            "clientInfo": {"name": "function-deep-analyzer", "version": "1.0.0"},
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

def get_all_functions(client: McpClient) -> List[Dict]:
    """Get all functions with metadata"""
    print("[*] Fetching all functions...")
    
    functions = []
    offset = 0
    limit = 500
    
    while True:
        try:
            chunk = client.call_tool("list_functions", {
                "program_name": PROGRAM_NAME,
                "offset": offset,
                "limit": limit
            })
            
            if not chunk or "No functions" in chunk:
                break
            
            # Parse functions
            for line in chunk.split('\n'):
                match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
                if match:
                    name, addr, params = match.groups()
                    functions.append({
                        "name": name,
                        "address": f"0x{addr}",
                        "params": int(params)
                    })
            
            print(f"  [+] Fetched {len(functions)} functions so far...")
            
            # Check if we're done
            if "Showing" in chunk and "of" in chunk:
                showing_match = re.search(r'Showing (\d+) of (\d+)', chunk)
                if showing_match:
                    shown, total = map(int, showing_match.groups())
                    if offset + shown >= total:
                        break
            
            offset += limit
            
        except Exception as e:
            print(f"  [-] Error fetching functions at offset {offset}: {e}")
            break
    
    print(f"[+] Total functions: {len(functions)}")
    return functions

def analyze_entry_and_main(client: McpClient, functions: List[Dict]) -> Dict:
    """Deep dive into entry point and main initialization"""
    print("\n[*] Analyzing entry point and initialization...")
    
    results = {}
    
    # Find entry and potential main functions
    entry_candidates = [f for f in functions if 'entry' in f['name'].lower() or f['address'] == '0x00401000']
    main_candidates = [f for f in functions if 'FUN_' in f['name'] and f['address'] in ['0x00401010', '0x004133c7']]
    
    for func in entry_candidates + main_candidates[:5]:
        try:
            print(f"  [*] Decompiling {func['name']} @ {func['address']}")
            
            # Get decompiled code
            decomp = client.call_tool("get_code", {
                "program_name": PROGRAM_NAME,
                "function": func['address'],
                "format": "decompiler"
            })
            
            # Get call graph
            callgraph = client.call_tool("get_call_graph", {
                "program_name": PROGRAM_NAME,
                "function": func['address'],
                "depth": 3,
                "direction": "callees"
            })
            
            # Get basic blocks
            blocks = client.call_tool("get_basic_blocks", {
                "program_name": PROGRAM_NAME,
                "function": func['address']
            })
            
            results[func['name']] = {
                "address": func['address'],
                "decompiled": decomp[:5000],
                "call_graph": callgraph[:2000],
                "basic_blocks": blocks[:2000]
            }
            
            print(f"  [+] Analyzed {func['name']}")
            
        except Exception as e:
            print(f"  [-] Error analyzing {func['name']}: {e}")
    
    return results

def find_and_analyze_network_functions(client: McpClient) -> Dict:
    """Find all functions that do networking"""
    print("\n[*] Finding network-related functions...")
    
    network_apis = [
        'WSAEnumNetworkEvents', 'WSAEventSelect', 'WSACreateEvent', 'WSACloseEvent',
        'HttpSendRequestA', 'HttpQueryInfoA', 'InternetReadFileExA', 
        'InternetConnectA', 'InternetOpenA', 'InternetSetStatusCallbackA'
    ]
    
    results = {}
    
    for api in network_apis:
        try:
            print(f"  [*] Finding callers of {api}...")
            
            xrefs = client.call_tool("xrefs", {
                "program_name": PROGRAM_NAME,
                "function": api,
                "direction": "to",
                "limit": 50
            })
            
            if xrefs and "No references" not in xrefs:
                # Extract caller addresses
                caller_addrs = re.findall(r'0x([0-9a-fA-F]{6,8})', xrefs)
                
                results[api] = {
                    "xrefs": xrefs[:1000],
                    "caller_count": len(caller_addrs),
                    "decompiled_callers": {}
                }
                
                # Decompile first few callers
                for addr in caller_addrs[:2]:
                    try:
                        decomp = client.call_tool("get_code", {
                            "program_name": PROGRAM_NAME,
                            "function": f"0x{addr}",
                            "format": "decompiler"
                        })
                        
                        results[api]["decompiled_callers"][f"0x{addr}"] = decomp[:3000]
                        print(f"    [+] Decompiled caller at 0x{addr}")
                    except:
                        pass
                
                print(f"  [+] Found {len(caller_addrs)} callers of {api}")
        
        except Exception as e:
            print(f"  [-] Error analyzing {api}: {e}")
    
    return results

def find_large_functions(client: McpClient, functions: List[Dict]) -> Dict:
    """Find and analyze large/complex functions (potential dispatchers)"""
    print("\n[*] Finding large/complex functions...")
    
    results = {}
    analyzed_count = 0
    
    # Skip exception handlers
    interesting_funcs = [f for f in functions 
                        if 'Catch_All' not in f['name'] 
                        and 'Unwind' not in f['name']
                        and 'thunk_' not in f['name']]
    
    for func in interesting_funcs[:30]:  # Analyze first 30 non-exception functions
        try:
            # Get basic blocks to estimate complexity
            blocks_result = client.call_tool("get_basic_blocks", {
                "program_name": PROGRAM_NAME,
                "function": func['address']
            })
            
            block_count = blocks_result.count("Block") + blocks_result.count("block")
            
            # Only analyze complex functions
            if block_count > 10:
                print(f"  [*] Analyzing complex function {func['name']} @ {func['address']} ({block_count} blocks)")
                
                decomp = client.call_tool("get_code", {
                    "program_name": PROGRAM_NAME,
                    "function": func['address'],
                    "format": "decompiler"
                })
                
                results[func['name']] = {
                    "address": func['address'],
                    "block_count": block_count,
                    "decompiled": decomp[:4000],
                    "blocks": blocks_result[:2000]
                }
                
                analyzed_count += 1
                print(f"  [+] Analyzed {func['name']} ({analyzed_count} complex functions so far)")
                
                if analyzed_count >= 15:  # Limit to avoid excessive processing
                    break
        
        except Exception as e:
            pass  # Skip functions that can't be analyzed
    
    print(f"[+] Analyzed {analyzed_count} complex functions")
    return results

def main():
    print("=" * 80)
    print("FUNCTION DEEP ANALYZER - Comprehensive Function Analysis")
    print("=" * 80)
    
    client = McpClient(MCP_BASE)
    
    try:
        print("\n[*] Initializing MCP connection...")
        client.initialize()
        print("[+] Connected to Ghidra MCP server")
        
        report = {
            "target": PROGRAM_NAME,
            "analysis_type": "comprehensive_function_analysis",
            "findings": {}
        }
        
        # 1. Get all functions
        functions = get_all_functions(client)
        report["findings"]["total_functions"] = len(functions)
        report["findings"]["function_list"] = functions
        
        # 2. Analyze entry/main
        report["findings"]["entry_analysis"] = analyze_entry_and_main(client, functions)
        
        # 3. Find and analyze network functions
        report["findings"]["network_functions"] = find_and_analyze_network_functions(client)
        
        # 4. Find large/complex functions
        report["findings"]["complex_functions"] = find_large_functions(client, functions)
        
        # Save report
        output_path = Path("/reports/FUNCTION_DEEP_ANALYSIS.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Analysis complete! Report saved to {output_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total functions: {len(functions)}")
        print(f"Entry/init functions analyzed: {len(report['findings']['entry_analysis'])}")
        print(f"Network APIs analyzed: {len(report['findings']['network_functions'])}")
        print(f"Complex functions analyzed: {len(report['findings']['complex_functions'])}")
        
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
