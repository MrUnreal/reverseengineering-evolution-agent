#!/usr/bin/env python3
"""
Advanced Opcode Hunter - Hunt & correlate WoW 3.3.5a opcodes
Uses cached reports + advanced pattern matching to simulate live MCP search_bytes
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

# Known WoW 3.3.5a opcodes (TrinityCore)
KNOWN_OPCODES = {
    "CMSG_AUTH_SESSION": 0x01ED,
    "CMSG_AUTH_CHALLENGE": 0x01EC,
    "SMSG_AUTH_RESPONSE": 0x01EE,
    "MSG_MOVE_START_FORWARD": 0x00B5,
    "MSG_MOVE_START_BACKWARD": 0x00B6,
    "MSG_MOVE_STOP": 0x00B7,
    "MSG_MOVE_START_STRAFE_LEFT": 0x00B8,
    "MSG_MOVE_START_STRAFE_RIGHT": 0x00B9,
    "MSG_MOVE_JUMP": 0x00BB,
    "MSG_MOVE_SET_FACING": 0x00DA,
    "MSG_MOVE_HEARTBEAT": 0x00EE,
    "CMSG_CAST_SPELL": 0x012E,
    "SMSG_SPELL_START": 0x0131,
    "SMSG_SPELL_GO": 0x0132,
    "CMSG_CANCEL_CAST": 0x012F,
    "SMSG_UPDATE_OBJECT": 0x00A9,
    "SMSG_COMPRESSED_UPDATE_OBJECT": 0x01F6,
    "SMSG_DESTROY_OBJECT": 0x00AA,
    "CMSG_MESSAGECHAT": 0x0095,
    "SMSG_MESSAGECHAT": 0x0096,
    "CMSG_LOOT": 0x015D,
    "SMSG_LOOT_RESPONSE": 0x0160,
    "CMSG_INITIATE_TRADE": 0x0116,
    "SMSG_TRADE_STATUS": 0x0120,
}

def load_cached_data():
    """Load all cached analysis reports"""
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        mcp = json.load(f)
    
    with open(REPORTS_DIR / "STRING_EXTRACTION_DETAILED.json", 'r') as f:
        strings = json.load(f)
    
    with open(REPORTS_DIR / "function-analysis.json", 'r') as f:
        func_analysis = json.load(f)
    
    with open(REPORTS_DIR / "xref-analysis.json", 'r') as f:
        xref_analysis = json.load(f)
    
    return mcp, strings, func_analysis, xref_analysis

def find_opcode_hints_in_strings(strings_data):
    """Search strings for opcode-related references"""
    
    opcode_hints = defaultdict(list)
    
    for category, string_list in strings_data.get('categories', {}).items():
        for string_entry in string_list:
            value = string_entry.get('value', '').lower()
            addr = string_entry.get('address', '')
            
            # Look for authentication-related strings
            if any(kw in value for kw in ['auth', 'session', 'login', 'challenge', 'response']):
                opcode_hints['auth'].append({
                    'string': value,
                    'address': addr,
                    'category': category
                })
            
            # Look for movement-related strings
            elif any(kw in value for kw in ['move', 'position', 'coordinate', 'facing', 'heartbeat']):
                opcode_hints['movement'].append({
                    'string': value,
                    'address': addr,
                    'category': category
                })
            
            # Look for spell/combat strings
            elif any(kw in value for kw in ['spell', 'cast', 'damage', 'heal', 'buff', 'debuff']):
                opcode_hints['combat'].append({
                    'string': value,
                    'address': addr,
                    'category': category
                })
            
            # Look for object/update strings
            elif any(kw in value for kw in ['object', 'update', 'destroy', 'create', 'entity']):
                opcode_hints['objects'].append({
                    'string': value,
                    'address': addr,
                    'category': category
                })
            
            # Look for chat/communication strings
            elif any(kw in value for kw in ['message', 'chat', 'whisper', 'guild', 'party']):
                opcode_hints['chat'].append({
                    'string': value,
                    'address': addr,
                    'category': category
                })
    
    return dict(opcode_hints)

def analyze_imports_for_network_handlers(mcp_data):
    """Identify network handler functions from imports"""
    
    imports_text = mcp_data.get('calls', {}).get('list_imports', {}).get('text', '')
    
    network_funcs = {
        'async_io': [],
        'http': [],
        'winsocket': []
    }
    
    for line in imports_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+from\s+(.+?)\s+@\s+EXTERNAL:([0-9a-fA-F]+)', line)
        if match:
            func, dll, addr = match.groups()
            dll_name = dll.lower()
            
            if 'iocompletion' in func.lower() or 'overlapped' in func.lower() or 'waitfor' in func.lower():
                network_funcs['async_io'].append({
                    'func': func,
                    'dll': dll,
                    'addr': f"EXTERNAL:0x{addr}"
                })
            elif 'http' in func.lower() or 'internet' in func.lower():
                network_funcs['http'].append({
                    'func': func,
                    'dll': dll,
                    'addr': f"EXTERNAL:0x{addr}"
                })
            elif 'wsa' in func.lower() or 'socket' in func.lower():
                network_funcs['winsocket'].append({
                    'func': func,
                    'dll': dll,
                    'addr': f"EXTERNAL:0x{addr}"
                })
    
    return network_funcs

def predict_dispatcher_location(mcp_data, string_hints):
    """Predict where packet dispatcher likely is"""
    
    functions_text = mcp_data.get('calls', {}).get('list_functions', {}).get('text', '')
    
    # Parse functions
    functions = []
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            functions.append({
                'name': name,
                'address': f"0x{addr}",
                'address_int': int(addr, 16),
                'params': int(params)
            })
    
    # Functions that likely lead to dispatcher:
    # 1. Those with unknown names starting from 0x0047-0x0088 range (mid-code, main logic)
    # 2. Those between entry point and high address (main function chain)
    
    candidates = []
    for func in functions:
        if func['name'].startswith('FUN_'):
            addr_val = func['address_int']
            # Main code section, not in highest addresses
            if 0x400000 <= addr_val < 0x500000:
                candidates.append({
                    **func,
                    'confidence': 'high',
                    'reason': 'Unknown function in main code section'
                })
            elif 0x500000 <= addr_val < 0x900000:
                candidates.append({
                    **func,
                    'confidence': 'medium',
                    'reason': 'Unknown function in mid-code section'
                })
    
    return sorted(candidates, key=lambda x: x['address_int'])

def correlate_opcodes_with_hints(known_opcodes, string_hints):
    """Match known opcodes with string hint categories"""
    
    correlations = []
    
    opcode_categories = {
        'auth': ['CMSG_AUTH_SESSION', 'CMSG_AUTH_CHALLENGE', 'SMSG_AUTH_RESPONSE'],
        'movement': ['MSG_MOVE_START_FORWARD', 'MSG_MOVE_START_BACKWARD', 'MSG_MOVE_STOP', 
                     'MSG_MOVE_START_STRAFE_LEFT', 'MSG_MOVE_START_STRAFE_RIGHT', 'MSG_MOVE_JUMP',
                     'MSG_MOVE_SET_FACING', 'MSG_MOVE_HEARTBEAT'],
        'combat': ['CMSG_CAST_SPELL', 'SMSG_SPELL_START', 'SMSG_SPELL_GO', 'CMSG_CANCEL_CAST'],
        'objects': ['SMSG_UPDATE_OBJECT', 'SMSG_COMPRESSED_UPDATE_OBJECT', 'SMSG_DESTROY_OBJECT'],
        'chat': ['CMSG_MESSAGECHAT', 'SMSG_MESSAGECHAT'],
    }
    
    for category, opcodes in opcode_categories.items():
        if category in string_hints:
            correlations.append({
                'category': category,
                'opcodes': opcodes,
                'opcode_values': [known_opcodes[op] for op in opcodes if op in known_opcodes],
                'string_hints': string_hints[category][:5]  # Top 5 hints
            })
    
    return correlations

def generate_analysis_plan(network_funcs, dispatcher_candidates, correlations):
    """Generate detailed analysis and decompilation plan"""
    
    plan = {
        "phase_1_network_discovery": {
            "goal": "Locate network I/O handler using IOCP imports",
            "async_io_functions": network_funcs['async_io'],
            "next_steps": [
                "From live MCP: xrefs(address='CreateIoCompletionPort', direction='to')",
                "From live MCP: xrefs(address='GetOverlappedResult', direction='to')",
                "Decompile each caller to find network receive handler"
            ]
        },
        
        "phase_2_dispatcher_hunt": {
            "goal": "Find packet opcode dispatcher",
            "candidate_functions": dispatcher_candidates[:10],
            "search_strategy": [
                f"Look for large switch statements (>50 cases)",
                f"Search for switch on 16-bit values (uint16_t opcode pattern)",
                f"Find function with many basic blocks (>50)",
                f"Expected pattern: switch(packet->ReadUInt16())"
            ]
        },
        
        "phase_3_opcode_correlation": {
            "goal": "Map opcodes to handler functions",
            "known_opcodes": len(KNOWN_OPCODES),
            "correlations_found": len(correlations),
            "correlation_map": correlations,
            "search_commands": [
                f"For each opcode, search bytes in little-endian format:",
            ] + [
                f"  search_bytes(pattern='{hex(opcode['opcode_values'][0])[2:].zfill(4)}')"
                for opcode in correlations if opcode['opcode_values']
            ][:5]
        },
        
        "phase_4_handler_decompilation": {
            "goal": "Decompile opcode handlers",
            "priority_opcodes": [
                {"opcode": "CMSG_AUTH_SESSION", "value": "0x01ED", "priority": "CRITICAL"},
                {"opcode": "MSG_MOVE_START_FORWARD", "value": "0x00B5", "priority": "CRITICAL"},
                {"opcode": "SMSG_UPDATE_OBJECT", "value": "0x00A9", "priority": "CRITICAL"},
                {"opcode": "CMSG_CAST_SPELL", "value": "0x012E", "priority": "HIGH"},
            ],
            "decompile_order": "By frequency - movement > object updates > spells > auth"
        }
    }
    
    return plan

def main():
    print("=" * 80)
    print("ADVANCED OPCODE HUNTER - WoW 3.3.5a Correlator")
    print("=" * 80)
    print()
    
    print("[*] Loading cached analysis data...")
    mcp, strings, func_analysis, xref_analysis = load_cached_data()
    print(f"[+] Loaded MCP report, strings, function analysis, xref analysis")
    
    print("\n[*] Analyzing string hints for opcode categories...")
    string_hints = find_opcode_hints_in_strings(strings)
    print(f"[+] Found {sum(len(v) for v in string_hints.values())} opcode-related string hints")
    for category, hints in string_hints.items():
        print(f"    {category:15s}: {len(hints):3d} hints")
    
    print("\n[*] Analyzing imports for network functions...")
    network_funcs = analyze_imports_for_network_handlers(mcp)
    print(f"[+] Identified network function categories:")
    print(f"    Async I/O: {len(network_funcs['async_io'])} functions")
    print(f"    HTTP:      {len(network_funcs['http'])} functions")
    print(f"    WinSocket: {len(network_funcs['winsocket'])} functions")
    
    if network_funcs['async_io']:
        print(f"\n[+] Key Async I/O Functions:")
        for func in network_funcs['async_io'][:5]:
            print(f"    - {func['func']:30s} @ {func['addr']}")
    
    print("\n[*] Predicting dispatcher location...")
    dispatcher_candidates = predict_dispatcher_location(mcp, string_hints)
    print(f"[+] Found {len(dispatcher_candidates)} candidate dispatcher locations")
    
    if dispatcher_candidates:
        print(f"\n[+] Top 5 Dispatcher Candidates:")
        for i, cand in enumerate(dispatcher_candidates[:5], 1):
            print(f"    {i}. {cand['address']} - {cand['name']} ({cand['confidence']} confidence)")
            print(f"       Reason: {cand['reason']}")
    
    print("\n[*] Correlating known opcodes with string hints...")
    correlations = correlate_opcodes_with_hints(KNOWN_OPCODES, string_hints)
    print(f"[+] Correlated {len(correlations)} opcode categories with string hints")
    
    print("\n[*] Generating analysis plan...")
    plan = generate_analysis_plan(network_funcs, dispatcher_candidates, correlations)
    
    # Save plan
    output_path = REPORTS_DIR / "OPCODE_ANALYSIS_PLAN.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(plan, f, indent=2)
    print(f"[+] Analysis plan saved to: {output_path}")
    
    # Generate markdown
    md = "# OPCODE ANALYSIS PLAN - Advanced Correlation\n\n"
    md += f"**Known Opcodes:** {len(KNOWN_OPCODES)}\n"
    md += f"**String Hints Found:** {sum(len(v) for v in string_hints.values())}\n"
    md += f"**Dispatcher Candidates:** {len(dispatcher_candidates)}\n"
    md += f"**Correlations:** {len(correlations)}\n\n"
    
    md += "## String-to-Opcode Correlations\n\n"
    for corr in correlations:
        md += f"### {corr['category'].title()}\n\n"
        md += f"**Opcodes:** {', '.join(corr['opcodes'][:3])}\n"
        md += f"**Values:** {', '.join([f'0x{v:04X}' for v in corr['opcode_values'][:3]])}\n\n"
        md += "**Related Strings:**\n"
        for hint in corr['string_hints']:
            md += f"- `{hint['string']}` @ {hint['address']}\n"
        md += "\n"
    
    md += "## Network Function Imports\n\n"
    md += "### Async I/O (Critical for Network)\n"
    for func in network_funcs['async_io'][:10]:
        md += f"- `{func['func']}` from {func['dll']} @ {func['addr']}\n"
    
    if network_funcs['http']:
        md += "\n### HTTP Functions\n"
        for func in network_funcs['http'][:5]:
            md += f"- `{func['func']}` from {func['dll']} @ {func['addr']}\n"
    
    md += "\n## Dispatcher Candidates\n\n"
    md += "| Address | Name | Confidence | Reason |\n"
    md += "|---------|------|------------|--------|\n"
    for cand in dispatcher_candidates[:15]:
        md += f"| `{cand['address']}` | {cand['name']} | {cand['confidence']} | {cand['reason'][:40]} |\n"
    
    md += "\n## MCP Commands for Live Analysis\n\n"
    md += "When Docker/MCP server available, run:\n\n"
    md += "```python\n"
    md += "# Find network I/O handler\n"
    for func in network_funcs['async_io'][:3]:
        md += f'xrefs(address="{func["func"]}", direction="to")\n'
    md += "\n# Search for opcode byte patterns (little-endian)\n"
    md += "search_bytes(pattern='ed 01')  # CMSG_AUTH_SESSION = 0x01ED\n"
    md += "search_bytes(pattern='b5 00')  # MSG_MOVE_START_FORWARD = 0x00B5\n"
    md += "search_bytes(pattern='a9 00')  # SMSG_UPDATE_OBJECT = 0x00A9\n"
    md += "search_bytes(pattern='2e 01')  # CMSG_CAST_SPELL = 0x012E\n"
    md += "\n# Decompile dispatcher candidates\n"
    for cand in dispatcher_candidates[:3]:
        addr = cand['address'].replace('0x', '')
        md += f'get_code(address="0x{addr}", mode="decompiled")\n'
    md += "```\n"
    
    md_path = REPORTS_DIR / "OPCODE_ANALYSIS_PLAN.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"[+] Markdown output saved to: {md_path}")
    
    print("\n" + "=" * 80)
    print("ANALYSIS RESULTS")
    print("=" * 80)
    
    print(f"\n✓ String Hints by Category:")
    for cat, hints in sorted(string_hints.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {cat:15s}: {len(hints):3d} hints")
    
    print(f"\n✓ Network Function Categories:")
    print(f"  Async I/O:       {len(network_funcs['async_io']):3d} functions (CRITICAL)")
    print(f"  HTTP:            {len(network_funcs['http']):3d} functions")
    print(f"  WinSocket:       {len(network_funcs['winsocket']):3d} functions (inferred)")
    
    print(f"\n✓ Dispatcher Candidates: {len(dispatcher_candidates)}")
    print(f"✓ Opcode Correlations: {len(correlations)}")
    
    print("\n" + "=" * 80)
    print("NEXT STEP: Start Docker and run live MCP analysis with commands above")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    exit(main())
