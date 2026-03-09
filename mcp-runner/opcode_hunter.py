#!/usr/bin/env python3
"""
Opcode Hunter - Find packet opcodes, handlers, and dispatch tables
Correlates with known WoW 3.3.5a TrinityCore opcodes
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict
import requests

# Known 3.3.5a opcodes from TrinityCore (sample of critical ones)
KNOWN_OPCODES_335 = {
    # Auth/Login
    'CMSG_AUTH_SESSION': 0x1ED,
    'SMSG_AUTH_RESPONSE': 0x1EE,
    'CMSG_PING': 0x1DC,
    'SMSG_PONG': 0x1DD,
    
    # Movement
    'MSG_MOVE_START_FORWARD': 0x0B5,
    'MSG_MOVE_START_BACKWARD': 0x0B6,
    'MSG_MOVE_STOP': 0x0B7,
    'MSG_MOVE_HEARTBEAT': 0x0EE,
    'MSG_MOVE_JUMP': 0x0BB,
    'MSG_MOVE_SET_FACING': 0x0DA,
    
    # Combat/Spells
    'CMSG_CAST_SPELL': 0x12E,
    'SMSG_SPELL_START': 0x131,
    'SMSG_SPELL_GO': 0x132,
    'CMSG_ATTACK_SWING': 0x141,
    'SMSG_ATTACKSTART': 0x143,
    
    # World/Objects
    'SMSG_UPDATE_OBJECT': 0x0A9,
    'SMSG_COMPRESSED_UPDATE_OBJECT': 0x1F6,
    'CMSG_QUERY_TIME': 0x1CE,
    'SMSG_QUERY_TIME_RESPONSE': 0x1CF,
    
    # Chat
    'CMSG_MESSAGECHAT': 0x095,
    'SMSG_MESSAGECHAT': 0x096,
    
    # Auction/Trade
    'CMSG_AUCTION_LIST_ITEMS': 0x243,
    'SMSG_AUCTION_LIST_RESULT': 0x244,
}

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
            "clientInfo": {"name": "opcode-hunter", "version": "1.0.0"},
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

def search_memory_for_opcodes(client: McpClient) -> List[Dict]:
    """Search memory for potential opcode constants"""
    print("[*] Searching memory for opcode patterns...")
    
    results = []
    
    # Search for small integer constants that match known opcodes
    for name, value in KNOWN_OPCODES_335.items():
        try:
            # Search for the hex value (convert to byte pattern)
            # For little-endian 16-bit: 0x01ED -> ed 01
            byte_pattern = f"{value & 0xFF:02x} {(value >> 8) & 0xFF:02x}"
            
            search_result = client.call_tool("search_bytes", {
                "program_name": PROGRAM_NAME,
                "pattern": byte_pattern,
                "limit": 50
            })
            
            if search_result and "No matches" not in search_result and "0 matches" not in search_result:
                results.append({
                    "opcode_name": name,
                    "opcode_value": hex(value),
                    "byte_pattern": byte_pattern,
                    "search_results": search_result[:500]
                })
                print(f"  [+] Found potential {name} ({hex(value)}) - pattern: {byte_pattern}")
        except Exception as e:
            print(f"  [-] Error searching for {name}: {e}")
    
    return results

def find_packet_strings(client: McpClient) -> Dict:
    """Find strings related to packets, opcodes, handlers"""
    print("[*] Searching for packet-related strings...")
    
    try:
        all_strings = client.call_tool("list_strings", {
            "program_name": PROGRAM_NAME,
            "min_length": 4
        })
        
        patterns = {
            'opcodes': r'(?i)(opcode|op_code|msg_|smsg_|cmsg_)',
            'packets': r'(?i)(packet|recv|send|handler|dispatch)',
            'network': r'(?i)(realm|server|client|session|auth)',
            'protocol': r'(?i)(header|size|length|payload)',
        }
        
        categorized = defaultdict(list)
        
        for line in all_strings.split('\n'):
            for category, pattern in patterns.items():
                if re.search(pattern, line):
                    categorized[category].append(line.strip())
                    break
        
        return dict(categorized)
    except Exception as e:
        print(f"  [-] Error getting strings: {e}")
        return {}

def find_switch_tables(client: McpClient) -> List[Dict]:
    """Find large switch statements that could be opcode dispatchers"""
    print("[*] Looking for switch/jump tables (opcode dispatchers)...")
    
    results = []
    
    try:
        # Get all functions
        functions = client.call_tool("list_functions", {
            "program_name": PROGRAM_NAME,
            "limit": 500
        })
        
        # Look for functions with many branches (likely packet handlers)
        for line in functions.split('\n'):
            match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)', line)
            if match:
                name, addr = match.groups()
                
                # Skip exception handlers
                if 'Catch_All' in name or 'Unwind' in name:
                    continue
                
                # Get basic blocks for this function
                try:
                    blocks = client.call_tool("get_basic_blocks", {
                        "program_name": PROGRAM_NAME,
                        "function": f"0x{addr}"
                    })
                    
                    # Count branches/blocks
                    block_count = blocks.count("Block") + blocks.count("block")
                    branch_count = blocks.count("branch") + blocks.count("switch") + blocks.count("jump")
                    
                    if block_count > 20 or branch_count > 10:  # Likely a dispatcher
                        results.append({
                            "function": name,
                            "address": f"0x{addr}",
                            "block_count": block_count,
                            "branch_count": branch_count,
                            "analysis": blocks[:300]
                        })
                        print(f"  [+] Found potential dispatcher: {name} @ 0x{addr} ({block_count} blocks, {branch_count} branches)")
                except Exception as e:
                    pass  # Function might not support CFG analysis
    
    except Exception as e:
        print(f"  [-] Error analyzing functions: {e}")
    
    return results

def find_xrefs_to_network_apis(client: McpClient) -> Dict:
    """Find cross-references to network APIs (WSARecv, recv, etc)"""
    print("[*] Finding cross-references to network APIs...")
    
    network_apis = [
        'WSAEnumNetworkEvents', 'WSAEventSelect', 'WSACreateEvent', 
        'HttpSendRequestA', 'InternetReadFileExA', 'InternetConnectA'
    ]
    
    xrefs = {}
    
    for api in network_apis:
        try:
            result = client.call_tool("xrefs", {
                "program_name": PROGRAM_NAME,
                "function": api,
                "direction": "to",
                "limit": 100
            })
            
            if result and "No references" not in result and "0 references" not in result:
                xrefs[api] = result
                print(f"  [+] Found xrefs to {api}")
        except Exception as e:
            print(f"  [-] Error finding xrefs to {api}: {e}")
    
    return xrefs

def decompile_network_functions(client: McpClient, xrefs: Dict) -> Dict:
    """Decompile functions that call network APIs to find packet processing"""
    print("[*] Decompiling network-related functions...")
    
    decompiled = {}
    
    for api, xref_result in xrefs.items():
        # Extract addresses from xref results
        addresses = re.findall(r'0x([0-9a-fA-F]{6,8})', xref_result)
        
        for addr in addresses[:3]:  # Limit to first 3 per API
            try:
                decomp = client.call_tool("get_code", {
                    "program_name": PROGRAM_NAME,
                    "function": f"0x{addr}",
                    "format": "decompiler"
                })
                
                if decomp and len(decomp) > 100:
                    decompiled[f"{api}_0x{addr}"] = decomp[:2000]
                    print(f"  [+] Decompiled function at 0x{addr} (calls {api})")
            except Exception as e:
                print(f"  [-] Error decompiling 0x{addr}: {e}")
    
    return decompiled

def analyze_opcode_constants(strings_data: Dict) -> Dict:
    """Extract potential opcode constants from strings and memory"""
    print("[*] Analyzing potential opcode constants...")
    
    constants = []
    
    # Look for hex constants in strings
    all_text = ' '.join([' '.join(lines) for lines in strings_data.values()])
    
    hex_patterns = re.findall(r'0x([0-9a-fA-F]{2,4})\b', all_text)
    
    # Check if any match known opcodes
    for hex_val in hex_patterns:
        try:
            int_val = int(hex_val, 16)
            # Opcodes are typically < 0x1000 in 3.3.5
            if int_val < 0x1000:
                # Check if it matches a known opcode
                for name, known_val in KNOWN_OPCODES_335.items():
                    if int_val == known_val:
                        constants.append({
                            "value": hex(int_val),
                            "matched_opcode": name,
                            "confidence": "HIGH"
                        })
                        print(f"  [+] Found exact match: {name} = {hex(int_val)}")
        except:
            pass
    
    return {"constants": constants}

def main():
    print("=" * 80)
    print("OPCODE HUNTER - WoW 3.3.5a Packet Analysis")
    print("=" * 80)
    
    client = McpClient(MCP_BASE)
    
    try:
        print("\n[*] Initializing MCP connection...")
        client.initialize()
        print("[+] Connected to Ghidra MCP server")
        
        report = {
            "target": PROGRAM_NAME,
            "known_opcodes_baseline": KNOWN_OPCODES_335,
            "findings": {}
        }
        
        # 1. Find packet-related strings
        report["findings"]["packet_strings"] = find_packet_strings(client)
        
        # 2. Search memory for known opcode values
        report["findings"]["opcode_memory_hits"] = search_memory_for_opcodes(client)
        
        # 3. Find switch tables (opcode dispatchers)
        report["findings"]["potential_dispatchers"] = find_switch_tables(client)
        
        # 4. Find network API xrefs
        report["findings"]["network_api_xrefs"] = find_xrefs_to_network_apis(client)
        
        # 5. Decompile network functions
        report["findings"]["decompiled_network_functions"] = decompile_network_functions(
            client, report["findings"]["network_api_xrefs"]
        )
        
        # 6. Analyze constants
        report["findings"]["opcode_constants"] = analyze_opcode_constants(
            report["findings"]["packet_strings"]
        )
        
        # Save report
        output_path = Path("/reports/OPCODE_ANALYSIS.json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Analysis complete! Report saved to {output_path}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Packet strings found: {sum(len(v) for v in report['findings']['packet_strings'].values())}")
        print(f"Opcode memory hits: {len(report['findings']['opcode_memory_hits'])}")
        print(f"Potential dispatchers: {len(report['findings']['potential_dispatchers'])}")
        print(f"Network API xrefs: {len(report['findings']['network_api_xrefs'])}")
        print(f"Decompiled functions: {len(report['findings']['decompiled_network_functions'])}")
        
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
