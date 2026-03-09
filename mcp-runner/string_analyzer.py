#!/usr/bin/env python3
"""
String Analyzer - Categorize and analyze all strings in the binary
Find game-specific patterns, file paths, URLs, error messages, etc.
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
            "clientInfo": {"name": "string-analyzer", "version": "1.0.0"},
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

def categorize_strings(all_strings: str) -> Dict[str, List[Dict]]:
    """Categorize strings by type"""
    print("[*] Categorizing strings...")
    
    categories = defaultdict(list)
    
    for line in all_strings.split('\n'):
        match = re.match(r'@\s+([0-9a-fA-F]+)\s+\((\d+)\s+chars\):\s+"(.+)"', line)
        if not match:
            continue
        
        addr, length, content = match.groups()
        entry = {"address": f"0x{addr}", "length": int(length), "content": content, "line": line.strip()}
        
        # Categorize by pattern
        content_lower = content.lower()
        
        # File paths and extensions
        if re.search(r'\.(exe|dll|mpq|dbc|txt|log|ini|cfg|dat|lua|xml|toc|json)($|")', content_lower):
            categories['files'].append(entry)
        
        # URLs and network
        if re.search(r'(https?://|www\.|\.com|\.net|\.org|realm|server|login|auth)', content_lower):
            categories['network'].append(entry)
        
        # Error messages
        if re.search(r'(error|failed|warning|exception|crash|assert|fatal|panic)', content_lower):
            categories['errors'].append(entry)
        
        # Game-specific: WoW terms
        if re.search(r'(spell|cast|buff|debuff|talent|skill|quest|guild|raid|dungeon|instance|arena|battleground)', content_lower):
            categories['game_systems'].append(entry)
        
        # Game-specific: movement/position
        if re.search(r'(move|position|location|coordinate|path|waypoint|teleport|map|zone)', content_lower):
            categories['movement'].append(entry)
        
        # Game-specific: combat
        if re.search(r'(attack|damage|heal|combat|target|mob|npc|creature|player)', content_lower):
            categories['combat'].append(entry)
        
        # Packet/protocol terms
        if re.search(r'(packet|opcode|msg_|cmsg|smsg|handler|recv|send)', content_lower):
            categories['protocol'].append(entry)
        
        # UI and interface
        if re.search(r'(frame|button|window|interface|ui|addon|script|event)', content_lower):
            categories['ui'].append(entry)
        
        # Database/data
        if re.search(r'(database|query|table|sql|dbc|cache)', content_lower):
            categories['database'].append(entry)
        
        # Lua/scripting
        if re.search(r'(lua|function|script|register|callback|event)', content_lower):
            categories['scripting'].append(entry)
        
        # Debug/logging
        if re.search(r'(debug|log|trace|dump|print|console)', content_lower):
            categories['debug'].append(entry)
        
        # Paths (Windows)
        if re.search(r'(\\|c:|program files|appdata|temp)', content_lower):
            categories['windows_paths'].append(entry)
        
        # Version/build info
        if re.search(r'(version|build|release|patch|\.exe|copyright)', content_lower):
            categories['version_info'].append(entry)
        
        # Class/function names (C++ style)
        if re.search(r'::|__', content):
            categories['cpp_symbols'].append(entry)
    
    # Convert to regular dict for JSON serialization
    return dict(categories)

def find_interesting_strings(client: McpClient) -> Dict:
    """Get ALL strings and find interesting patterns"""
    print("[*] Fetching all strings from binary...")
    
    # Get strings in chunks to ensure we get everything
    all_strings_text = ""
    offset = 0
    limit = 1000
    
    while True:
        try:
            chunk = client.call_tool("list_strings", {
                "program_name": PROGRAM_NAME,
                "min_length": 4,
                "offset": offset,
                "limit": limit
            })
            
            if not chunk or "No strings" in chunk:
                break
            
            all_strings_text += chunk + "\n"
            
            # Check if we got fewer results than limit (end of data)
            line_count = len([l for l in chunk.split('\n') if l.strip().startswith('@')])
            print(f"  [+] Fetched {line_count} strings (offset {offset})")
            
            if line_count < limit:
                break
            
            offset += limit
            
        except Exception as e:
            print(f"  [-] Error fetching strings at offset {offset}: {e}")
            break
    
    print(f"[+] Total strings text: {len(all_strings_text)} bytes")
    
    # Categorize
    categorized = categorize_strings(all_strings_text)
    
    # Print summary
    print("\n[*] String category summary:")
    for category, items in sorted(categorized.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {category}: {len(items)} strings")
    
    return {
        "total_strings": all_strings_text.count('\n@'),
        "categories": categorized,
        "raw_sample": all_strings_text[:5000]
    }

def search_specific_patterns(client: McpClient) -> Dict:
    """Search for very specific game-related patterns"""
    print("\n[*] Searching for specific patterns...")
    
    patterns = {
        'realm_strings': ['realm', 'server', 'login', 'auth'],
        'opcode_strings': ['opcode', 'MSG_', 'CMSG', 'SMSG'],
        'spell_strings': ['spell', 'cast', 'aura'],
        'movement_strings': ['movement', 'position', 'teleport'],
        'file_formats': ['.mpq', '.dbc', '.lua', '.m2', '.wmo', '.adt'],
    }
    
    results = {}
    
    for category, keywords in patterns.items():
        results[category] = []
        for keyword in keywords:
            try:
                matches = client.call_tool("list_strings", {
                    "program_name": PROGRAM_NAME,
                    "filter": keyword,
                    "min_length": 3
                })
                
                if matches and "No strings" not in matches:
                    results[category].append({
                        "keyword": keyword,
                        "results": matches[:500]
                    })
                    print(f"  [+] Found matches for '{keyword}'")
            except Exception as e:
                print(f"  [-] Error searching for '{keyword}': {e}")
    
    return results

def main():
    print("=" * 80)
    print("STRING ANALYZER - Comprehensive String Analysis")
    print("=" * 80)
    
    client = McpClient(MCP_BASE)
    
    try:
        print("\n[*] Initializing MCP connection...")
        client.initialize()
        print("[+] Connected to Ghidra MCP server")
        
        report = {
            "target": PROGRAM_NAME,
            "analysis_type": "comprehensive_string_analysis",
            "findings": {}
        }
        
        # 1. Get and categorize ALL strings
        report["findings"]["string_analysis"] = find_interesting_strings(client)
        
        # 2. Search for specific patterns
        report["findings"]["specific_patterns"] = search_specific_patterns(client)
        
        # Save report
        output_path = Path("/reports/STRING_ANALYSIS.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Analysis complete! Report saved to {output_path}")
        
        # Print key findings
        print("\n" + "=" * 80)
        print("KEY FINDINGS")
        print("=" * 80)
        
        categories = report["findings"]["string_analysis"].get("categories", {})
        for cat in ['protocol', 'network', 'game_systems', 'movement', 'combat', 'errors']:
            if cat in categories:
                items = categories[cat]
                print(f"\n{cat.upper()} ({len(items)} strings):")
                for item in items[:5]:
                    print(f"  {item['address']}: \"{item['content'][:80]}\"")
        
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
