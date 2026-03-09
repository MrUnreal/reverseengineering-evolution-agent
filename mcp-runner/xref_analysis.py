#!/usr/bin/env python3
"""
Advanced Cross-Reference Analysis - Trace function call chains
Identify actual implementations by following xrefs from imports
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

def extract_report_data():
    """Load MCP report"""
    report_path = Path('./reports/mcp-analysis.report.json')
    if not report_path.exists():
        return None
    with open(report_path, 'r') as f:
        return json.load(f)

def parse_functions_and_imports(report: Dict) -> Tuple:
    """Parse functions and imports from report"""
    functions_text = report.get('calls', {}).get('list_functions', {}).get('text', '')
    imports_text = report.get('calls', {}).get('list_imports', {}).get('text', '')
    
    functions = {}
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*- (.+?)\s+@\s+([0-9a-fA-F]+)', line)
        if match:
            name, addr = match.groups()
            functions[addr.lower()] = name
    
    imports = {}
    for line in imports_text.split('\n'):
        match = re.match(r'^\s*- (.+?)\s+from\s+(.+?)\s+@\s+([0-9a-f:]+)', line)
        if match:
            api_name, dll, addr = match.groups()
            imports[api_name] = {'dll': dll.strip(), 'address': addr}
    
    return functions, imports

def trace_critical_functions(functions: Dict, imports: Dict) -> Dict[str, List]:
    """Identify critical functions by their likely role"""
    
    critical_apis = {
        'network_send': [
            'WSASend', 'WSARecv', 'send', 'recv', 'SendPacket', 'SendMessage',
            'HttpSendRequestA', 'InternetConnectA'
        ],
        'movement': [
            'MoveTo', 'MoveCharacter', 'UpdatePosition', 'SetPosition',
            'ClientMovement', 'UpdateMovement'
        ],
        'spell_cast': [
            'CastSpell', 'ExecuteSpell', 'TriggerSpell', 'CheckSpell',
            'ValidateSpell', 'CastCheck'
        ],
        'entity_update': [
            'UpdateEntity', 'UpdateUnit', 'UpdatePlayer', 'UpdateObject',
            'EntityUpdate', 'OnUpdate'
        ],
        'packet_handler': [
            'HandlePacket', 'ProcessPacket', 'OnPacket', 'PacketDispatcher',
            'ProcessMessage', 'DispatchMessage'
        ],
        'combat': [
            'AttackSwing', 'AttackStart', 'AttackStop', 'DealDamage',
            'TakeDamage', 'ProcessAttack'
        ]
    }
    
    found_functions = defaultdict(list)
    
    # Search in APIs
    for api_name, api_info in imports.items():
        for category, keywords in critical_apis.items():
            for keyword in keywords:
                if keyword.lower() in api_name.lower():
                    found_functions[category].append({
                        'type': 'imported_api',
                        'name': api_name,
                        'dll': api_info['dll'],
                        'address': api_info['address']
                    })
    
    # Search in function names (where available)
    for addr, name in functions.items():
        for category, keywords in critical_apis.items():
            for keyword in keywords:
                if keyword.lower() in name.lower():
                    found_functions[category].append({
                        'type': 'local_function',
                        'name': name,
                        'address': addr.upper()
                    })
    
    return dict(found_functions)

def infer_packet_protocol(report: Dict) -> Dict:
    """Try to infer packet protocol from strings"""
    strings_text = report.get('calls', {}).get('list_strings', {}).get('text', '')
    
    # Look for packet opcodes and message types
    packet_patterns = {
        'client_to_server': r'(CMSG_|CLIENT_|C_[A-Z_]+)',
        'server_to_client': r'(SMSG_|SERVER_|S_[A-Z_]+)',
        'message_types': r'(MSG_|MESSAGE_)',
        'packet_structures': r'(packet|message|frame|header)',
    }
    
    findings = {}
    for category, pattern in packet_patterns.items():
        matches = re.findall(pattern, strings_text, re.IGNORECASE)
        unique_matches = list(set(matches))
        if unique_matches:
            findings[category] = unique_matches[:10]
    
    return findings

def build_bot_architecture_map(critical_funcs: Dict) -> Dict:
    """Build a map of how bot should interact with game"""
    
    return {
        'bot_spell_cast_integration': {
            'required_function': 'CastSpell or ExecuteSpell (currently unknown address)',
            'strategy': [
                '1. Locate SpellSystem class or global spell handler',
                '2. Reverse engineer spell ID format (likely uint32)',
                '3. Reverse engineer cooldown/requirement checking',
                '4. Hook or call CastSpell with bot spell selections',
                '5. Monitor spell success via packet inspection'
            ],
            'critical_apis_needed': critical_funcs.get('spell_cast', []),
            'networking': critical_funcs.get('packet_handler', [])
        },
        'bot_movement_integration': {
            'required_function': 'MoveTo or UpdatePosition (currently unknown address)',
            'strategy': [
                '1. Identify entity position struct (likely Vector3)',
                '2. Locate player entity in GameWorld',
                '3. Call MoveTo with calculated waypoint',
                '4. Monitor CMSG_MOVE packets for confirmation',
                '5. Detect stuck status via position delta'
            ],
            'critical_apis_needed': critical_funcs.get('movement', []),
            'networking': critical_funcs.get('network_send', [])
        },
        'bot_packet_monitoring': {
            'required_function': 'Packet handler dispatcher',
            'strategy': [
                '1. Hook WSARecv or packet dispatcher',
                '2. Only intercept SMSG (server->client) packets',
                '3. Parse packet header (opcode + size)',
                '4. Identify spell/combat/loot notifications',
                '5. Update bot state machine accordingly'
            ],
            'critical_apis_needed': critical_funcs.get('network_send', []),
            'handlers': critical_funcs.get('packet_handler', [])
        },
        'bot_combat_integration': {
            'required_function': 'AttackSwing or similar',
            'strategy': [
                '1. Locate player::target_unit reference',
                '2. Call AttackSwing or build CMSG_ATTACK_SWING',
                '3. Monitor health bars via entity update loop',
                '4. Manage threat/aggro via packets',
                '5. Implement kiting/fleeing logic'
            ],
            'critical_apis_needed': critical_funcs.get('combat', []),
            'entity_updates': critical_funcs.get('entity_update', [])
        }
    }

def create_decompilation_task_list(functions: Dict) -> List[Dict]:
    """Create priority list for function decompilation"""
    
    # Identify the most likely candidates for decompilation
    interesting_functions = []
    
    for addr, name in functions.items():
        priority = 0
        category = None
        
        if name in ['entry', '_main', 'WinMain']:
            priority = 100
            category = 'initialization'
        elif 'main' in name.lower() or 'init' in name.lower():
            priority = 95
            category = 'initialization'
        elif any(x in name.lower() for x in ['spell', 'cast', 'ability']):
            priority = 90
            category = 'spell_system'
        elif any(x in name.lower() for x in ['move', 'walk', 'position']):
            priority = 85
            category = 'movement'
        elif any(x in name.lower() for x in ['packet', 'send', 'recv']):
            priority = 88
            category = 'networking'
        elif any(x in name.lower() for x in ['entity', 'update', 'object']):
            priority = 80
            category = 'game_state'
        elif any(x in name.lower() for x in ['attack', 'combat', 'target']):
            priority = 82
            category = 'combat'
        elif name.startswith('UnknownFunction'):
            # Prioritize unknown functions early in address space
            addr_int = int(addr, 16)
            if 0x00401000 <= addr_int <= 0x00410000:
                priority = 75
                category = 'early_functions'
        
        if priority > 0:
            interesting_functions.append({
                'address': addr.upper(),
                'name': name,
                'priority': priority,
                'decompilation_target': True,
                'category': category
            })
    
    # Sort by priority (descending)
    return sorted(interesting_functions, key=lambda x: x['priority'], reverse=True)

def main():
    print("\n" + "="*80)
    print("ADVANCED CROSS-REFERENCE ANALYSIS: Function Call Chain Mapping")
    print("="*80)
    
    report = extract_report_data()
    if not report:
        print("ERROR: Could not load report")
        return
    
    functions, imports = parse_functions_and_imports(report)
    print(f"\n[+] Loaded {len(functions)} functions, {len(imports)} imports")
    
    # Find critical functions
    print("\n[1] CRITICAL FUNCTION IDENTIFICATION")
    print("-" * 80)
    critical = trace_critical_functions(functions, imports)
    
    for category, funcs in critical.items():
        if funcs:
            print(f"\n  {category.upper()} ({len(funcs)} found):")
            for func in funcs[:3]:
                func_type = func['type']
                if func_type == 'imported_api':
                    print(f"    [IMPORT] {func['name']} from {func['dll']}")
                else:
                    print(f"    [LOCAL] {func['address']}: {func['name']}")
            if len(funcs) > 3:
                print(f"    ... and {len(funcs)-3} more")
    
    # Infer protocol
    print("\n[2] PACKET PROTOCOL INFERENCE")
    print("-" * 80)
    protocol = infer_packet_protocol(report)
    for category, items in protocol.items():
        if items:
            print(f"\n  {category}: {items}")
    
    # Build implementation map
    print("\n[3] BOT IMPLEMENTATION ARCHITECTURE")
    print("-" * 80)
    bot_arch = build_bot_architecture_map(critical)
    
    for system, spec in bot_arch.items():
        print(f"\n  [{system.upper()}]")
        print(f"    Required: {spec['required_function']}")
        print(f"    Strategy:")
        for step in spec['strategy']:
            print(f"      {step}")
    
    # Decompilation targets
    print("\n[4] RECOMMENDED DECOMPILATION TARGETS (by priority)")
    print("-" * 80)
    decompile_targets = create_decompilation_task_list(functions)
    
    for i, target in enumerate(decompile_targets[:20], 1):
        print(f"  {i:2d}. [{target['category']:15s}] {target['address']}: {target['name']}")
    
    if len(decompile_targets) > 20:
        print(f"  ... and {len(decompile_targets)-20} more")
    
    # Save comprehensive output
    print("\n[5] GENERATING XREF ANALYSIS REPORT")
    print("-" * 80)
    
    output = {
        "timestamp": "2026-03-08",
        "analysis_type": "xref_and_call_chain_analysis",
        "critical_functions": {
            k: [{'name': f['name'], 'type': f['type'], 
                 'address': f.get('address', 'N/A')} for f in v]
            for k, v in critical.items()
        },
        "packet_protocol_hints": protocol,
        "bot_integration_architecture": bot_arch,
        "decompilation_priority_list": decompile_targets[:50],
        "analysis_summary": {
            "total_functions_analyzed": len(functions),
            "critical_functions_found": sum(len(v) for v in critical.values()),
            "next_steps": [
                "1. USE GHIDRA GUI: Load Ascension.exe with debug symbols",
                "2. DECOMPILE: Start with highest priority functions above",
                "3. XREF ANALYSIS: Right-click functions, view 'Xrefs To/From'",
                "4. TRACE CALLS: Follow call chains from imports to local functions",
                "5. MAP STRUCTURES: Identify class layouts from member accesses",
                "6. BUILD HOOKS: Create function hooks for critical operations",
                "7. INTERCEPT: Monitor packets and game state changes"
            ]
        }
    }
    
    with open('./reports/xref-analysis.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("Analysis complete - see xref-analysis.json for detailed findings")

if __name__ == '__main__':
    main()
