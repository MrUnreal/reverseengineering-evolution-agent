#!/usr/bin/env python3
"""
Targeted Function Hunting - Find spell casting, movement, packets, combat, etc.
Uses pattern matching on strings and function names to identify bot-critical code.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

def extract_all_data_from_report():
    """Load all available data from MCP report"""
    report_path = Path('./reports/mcp-analysis.report.json')
    if not report_path.exists():
        return None
    
    with open(report_path, 'r') as f:
        return json.load(f)

def find_functions_by_keyword(functions_text: str, keywords: List[str]) -> Dict[str, List]:
    """Find functions that match keywords"""
    results = defaultdict(list)
    
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*- (.+?)\s+@\s+([0-9a-fA-F]+)', line)
        if match:
            name, addr = match.groups()
            name_lower = name.lower()
            
            for keyword in keywords:
                if keyword.lower() in name_lower:
                    results[keyword].append({
                        'name': name,
                        'address': addr.upper(),
                        'line': line.strip()
                    })
    
    return dict(results)

def find_strings_by_pattern(strings_text: str, patterns: Dict[str, List[str]]) -> Dict[str, List]:
    """Find strings matching game system patterns"""
    results = defaultdict(list)
    
    lines = strings_text.split('\n')
    for line in lines:
        for category, keywords in patterns.items():
            for keyword in keywords:
                if keyword.lower() in line.lower():
                    # Extract address and content
                    match = re.match(r'^\s*@\s+([0-9a-fA-F]+)\s+\((.+?)\):\s+"(.+)"', line)
                    if match:
                        addr, size, content = match.groups()
                        results[category].append({
                            'address': addr.upper(),
                            'size': size,
                            'content': content,
                            'line': line.strip()
                        })
                    break
    
    return dict(results)

def analyze_spell_system(strings_data: Dict, functions_data: str) -> Dict:
    """Identify spell casting related functions"""
    
    spell_keywords = ['spell', 'cast', 'ability', 'cooldown', 'duration', 'trigger', 'ready']
    spell_functions = find_functions_by_keyword(functions_data, spell_keywords)
    
    # String patterns for spell system
    spell_patterns = {
        'spell_mechanics': ['spell', 'cast', 'cooldown', 'ready', 'trigger', 'duration', 'effect'],
        'spell_ui': ['castbar', 'spellbook', 'actionbar', 'macros', 'bindings'],
        'spell_ids': ['spell_id', 'spellid', '0x', 'id =']
    }
    
    return {
        'functions': spell_functions,
        'strings': find_strings_by_pattern(strings_data, spell_patterns),
        'summary': f"Found {sum(len(v) for v in spell_functions.values())} spell-related functions"
    }

def analyze_movement_system(strings_data: str, functions_data: str) -> Dict:
    """Identify movement and navigation functions"""
    
    movement_keywords = ['move', 'walk', 'run', 'position', 'path', 'navigation', 'waypoint', 'teleport', 'jump']
    movement_functions = find_functions_by_keyword(functions_data, movement_keywords)
    
    movement_patterns = {
        'movement_mechanics': ['move', 'movement', 'position', 'walk', 'run', 'velocity', 'speed'],
        'pathfinding': ['path', 'navigation', 'waypoint', 'astar', 'pathfind', 'navigate'],
        'coordinates': ['x=', 'y=', 'z=', 'vector', 'position', 'location'],
        'movement_files': ['clientmovement', 'movelogfile', 'movement.txt']
    }
    
    return {
        'functions': movement_functions,
        'strings': find_strings_by_pattern(strings_data, movement_patterns),
        'summary': f"Found {sum(len(v) for v in movement_functions.values())} movement-related functions"
    }

def analyze_network_system(strings_data: str, functions_data: str) -> Dict:
    """Identify packet and network communication functions"""
    
    network_keywords = ['send', 'recv', 'packet', 'socket', 'connect', 'disconnect', 'opcode']
    network_functions = find_functions_by_keyword(functions_data, network_keywords)
    
    network_patterns = {
        'packet_handling': ['packet', 'opcode', 'send', 'recv', 'handler', 'parse', 'build'],
        'socket_ops': ['socket', 'connect', 'disconnect', 'bind', 'listen', 'accept'],
        'realm_comms': ['realm', 'server', 'port', 'address', 'connection'],
        'protocol': ['wsa', 'client', 'server', 'msg_', 'smsg_', 'cmsg_']
    }
    
    return {
        'functions': network_functions,
        'strings': find_strings_by_pattern(strings_data, network_patterns),
        'summary': f"Found {sum(len(v) for v in network_functions.values())} network-related functions"
    }

def analyze_combat_system(strings_data: str, functions_data: str) -> Dict:
    """Identify combat and targeting functions"""
    
    combat_keywords = ['attack', 'combat', 'target', 'damage', 'hit', 'heal', 'buff', 'debuff']
    combat_functions = find_functions_by_keyword(functions_data, combat_keywords)
    
    combat_patterns = {
        'targeting': ['target', 'focus', 'select', 'targeting'],
        'combat_mechanics': ['attack', 'combat', 'damage', 'heal', 'hit'],
        'buffs_debuffs': ['buff', 'buff', 'aura', 'effect'],
        'combat_state': ['incombat', 'fighting', 'fleeing', 'dead']
    }
    
    return {
        'functions': combat_functions,
        'strings': find_strings_by_pattern(strings_data, combat_patterns),
        'summary': f"Found {sum(len(v) for v in combat_functions.values())} combat-related functions"
    }

def analyze_ui_system(strings_data: str, functions_data: str) -> Dict:
    """Identify UI and addon system functions"""
    
    ui_keywords = ['ui', 'frame', 'button', 'addon', 'script', 'event', 'handler']
    ui_functions = find_functions_by_keyword(functions_data, ui_keywords)
    
    ui_patterns = {
        'addon_system': ['addon', 'interface.mpq', 'lua', 'script'],
        'ui_framework': ['frame', 'button', 'text', 'texture', 'animation'],
        'event_system': ['event', 'handler', 'callback', 'register', 'fire'],
        'ui_strings': ['showui', 'hideui', 'reloadui']
    }
    
    return {
        'functions': ui_functions,
        'strings': find_strings_by_pattern(strings_data, ui_patterns),
        'summary': f"Found {sum(len(v) for v in ui_functions.values())} UI-related functions"
    }

def identify_critical_call_chains(report: Dict) -> Dict:
    """Map out likely call chains for critical game operations"""
    
    # Based on architecture analysis, infer probable call chains
    return {
        'spell_cast_chain': [
            'SpellSystem::CastSpell(spell_id) entrypoint',
            '  -> Validate spell (cooldown check, requirements)',
            '  -> Check mana/resource requirements',
            '  -> Start cast animation/bar',
            '  -> Build CMSG_CAST_SPELL packet',
            '  -> Send to realm via NetworkManager::SendPacket()',
            '  -> Await SMSG_SPELL_START/SMSG_SPELL_GO',
            '  -> Apply spell effects on player/target'
        ],
        'movement_chain': [
            'InputManager::OnKeyPress(MOVE_FORWARD)',
            '  -> Get player position from GameWorld::player',
            '  -> Calculate new position',
            '  -> Call GameEntity::MoveTo(new_pos)',
            '  -> Update animation to walk/run',
            '  -> Build CMSG_MOVE_START/MOVE_STOP packet',
            '  -> Send via NetworkManager',
            '  -> RenderManager renders new position'
        ],
        'packet_receive_chain': [
            'NetworkManager::OnRecvCallback() triggered',
            '  -> Receive packet from socket',
            '  -> Parse opcode from header',
            '  -> Dispatch to handler based on opcode',
            '  -> Update GameWorld state',
            '  -> Trigger associated events/callbacks',
            '  -> Mark for re-render'
        ],
        'combat_chain': [
            'InputManager::OnClick(target_unit)',
            '  -> ValidateTarget in range/visible',
            '  -> Update player::target',
            '  -> Start auto-attack timer',
            '  -> Build CMSG_ATTACK_SWING packet',
            '  -> Send to realm',
            '  -> OnAttackResponse updates damage',
            '  -> Update UI health bars'
        ]
    }

def main():
    print("\n" + "="*80)
    print("TARGETED FUNCTION HUNTING: Bot-Critical Code Path Analysis")
    print("="*80)
    
    report = extract_all_data_from_report()
    if not report:
        print("ERROR: MCP report not found")
        return
    
    functions_text = report.get('calls', {}).get('list_functions', {}).get('text', '')
    strings_text = report.get('calls', {}).get('list_strings', {}).get('text', '')
    
    if not functions_text or not strings_text:
        print("ERROR: Required data not in report")
        return
    
    # Analyze each subsystem
    print("\n[1] SPELL CASTING SYSTEM")
    print("-" * 80)
    spell_analysis = analyze_spell_system(strings_text, functions_text)
    if spell_analysis['functions']:
        for keyword, funcs in spell_analysis['functions'].items():
            print(f"\n  Keyword '{keyword}' ({len(funcs)} matches):")
            for func in funcs[:5]:
                print(f"    {func['address']}: {func['name']}")
            if len(funcs) > 5:
                print(f"    ... and {len(funcs)-5} more")
    if spell_analysis['strings']:
        for category, items in spell_analysis['strings'].items():
            if items:
                print(f"\n  {category.upper()} strings ({len(items)} found):")
                for item in items[:3]:
                    print(f"    {item['address']}: {item['content']}")
    
    print("\n[2] MOVEMENT & NAVIGATION SYSTEM")
    print("-" * 80)
    movement_analysis = analyze_movement_system(strings_text, functions_text)
    if movement_analysis['functions']:
        for keyword, funcs in movement_analysis['functions'].items():
            print(f"\n  Keyword '{keyword}' ({len(funcs)} matches):")
            for func in funcs[:5]:
                print(f"    {func['address']}: {func['name']}")
            if len(funcs) > 5:
                print(f"    ... and {len(funcs)-5} more")
    if movement_analysis['strings']:
        for category, items in movement_analysis['strings'].items():
            if items:
                print(f"\n  {category.upper()} strings ({len(items)} found):")
                for item in items[:3]:
                    print(f"    {item['address']}: {item['content']}")
    
    print("\n[3] NETWORK & PACKET SYSTEM")
    print("-" * 80)
    network_analysis = analyze_network_system(strings_text, functions_text)
    if network_analysis['functions']:
        for keyword, funcs in network_analysis['functions'].items():
            print(f"\n  Keyword '{keyword}' ({len(funcs)} matches):")
            for func in funcs[:5]:
                print(f"    {func['address']}: {func['name']}")
            if len(funcs) > 5:
                print(f"    ... and {len(funcs)-5} more")
    if network_analysis['strings']:
        for category, items in network_analysis['strings'].items():
            if items:
                print(f"\n  {category.upper()} strings ({len(items)} found):")
                for item in items[:3]:
                    print(f"    {item['address']}: {item['content']}")
    
    print("\n[4] COMBAT SYSTEM")
    print("-" * 80)
    combat_analysis = analyze_combat_system(strings_text, functions_text)
    if combat_analysis['functions']:
        for keyword, funcs in combat_analysis['functions'].items():
            print(f"\n  Keyword '{keyword}' ({len(funcs)} matches):")
            for func in funcs[:5]:
                print(f"    {func['address']}: {func['name']}")
            if len(funcs) > 5:
                print(f"    ... and {len(funcs)-5} more")
    if combat_analysis['strings']:
        for category, items in combat_analysis['strings'].items():
            if items:
                print(f"\n  {category.upper()} strings ({len(items)} found):")
                for item in items[:3]:
                    print(f"    {item['address']}: {item['content']}")
    
    print("\n[5] UI & ADDON SYSTEM")
    print("-" * 80)
    ui_analysis = analyze_ui_system(strings_text, functions_text)
    if ui_analysis['functions']:
        for keyword, funcs in ui_analysis['functions'].items():
            print(f"\n  Keyword '{keyword}' ({len(funcs)} matches):")
            for func in funcs[:5]:
                print(f"    {func['address']}: {func['name']}")
            if len(funcs) > 5:
                print(f"    ... and {len(funcs)-5} more")
    if ui_analysis['strings']:
        for category, items in ui_analysis['strings'].items():
            if items:
                print(f"\n  {category.upper()} strings ({len(items)} found):")
                for item in items[:3]:
                    print(f"    {item['address']}: {item['content']}")
    
    print("\n[6] PROBABLE CALL CHAINS FOR BOT")
    print("-" * 80)
    chains = identify_critical_call_chains(report)
    for chain_name, steps in chains.items():
        print(f"\n  [{chain_name.upper()}]")
        for step in steps:
            print(f"    {step}")
    
    # Save comprehensive function map
    output = {
        "timestamp": "2026-03-08",
        "analysis_type": "targeted_function_hunting",
        "spell_system": spell_analysis,
        "movement_system": movement_analysis,
        "network_system": network_analysis,
        "combat_system": combat_analysis,
        "ui_system": ui_analysis,
        "probable_call_chains": chains,
        "recommendations": {
            "highest_priority": [
                "Find spell casting entry point - enables all spell automation",
                "Find movement function - enables pathfinding and navigation",
                "Find packet send/recv handlers - enables network interception",
                "Find entity update loop - enables state tracking"
            ],
            "decompilation_targets": [
                "0x00401010: likely WinMain or game loop init",
                "0x004133C7: unknown game function (check for spell/movement/combat)",
                "0x0047CC90: unknown game function",
                "0x0088B010: unknown game function",
                "Largest vtable (0x9C5E70): probably base GameObject/Unit class"
            ],
            "search_strategy": [
                "Look for CMSG_CAST_SPELL or spell ID constants in strings",
                "Search for movement velocity/speed calculations",
                "Find packet structure definitions (header, opcode handling)",
                "Locate player object singleton and its update() method",
                "Trace imports for SendPacket() function signature"
            ]
        }
    }
    
    with open('./reports/function-hunting.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\n[OK] Function hunting complete - saved to function-hunting.json")

if __name__ == '__main__':
    main()
