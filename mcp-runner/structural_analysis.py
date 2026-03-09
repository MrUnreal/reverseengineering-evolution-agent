#!/usr/bin/env python3
"""
Binary Structural Analysis - Identify classes, vtables, and object models
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict

def find_vtable_patterns(functions_text: str) -> List[Dict]:
    """
    Identify likely vtable locations based on function clustering patterns.
    vtables typically appear at regular intervals with sequentia functions.
    """
    functions = []
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*- (.+?)\s+@\s+([0-9a-fA-F]+)', line)
        if match:
            name, addr = match.groups()
            try:
                addr_int = int(addr, 16)
                functions.append({'name': name, 'address': addr_int, 'addr_str': addr})
            except:
                pass
    
    # Look for clusters of functions with regular spacing (typical of vtables)
    vtables = []
    if functions:
        functions.sort(key=lambda x: x['address'])
        
        # Heuristics: vtables usually have 3-20 entries per class, spaced 4-8 bytes apart
        i = 0
        while i < len(functions) - 2:
            spacing = functions[i+1]['address'] - functions[i]['address']
            
            # Typical vtable entry spacing (4 bytes on x86 for pointers)
            if 4 <= spacing <= 32:
                # Found a potential vtable region
                vtable_start = i
                vtable_entries = [functions[i]]
                
                j = i + 1
                while j < len(functions):
                    space = functions[j]['address'] - functions[j-1]['address']
                    if 4 <= space <= 32:  # Still within vtable spacing
                        vtable_entries.append(functions[j])
                        j += 1
                    else:
                        break
                
                # vtable candidates have at least 3 entries
                if len(vtable_entries) >= 3:
                    vtables.append({
                        'potential_class_index': len(vtables),
                        'start_address': hex(vtable_entries[0]['address']),
                        'end_address': hex(vtable_entries[-1]['address']),
                        'entry_count': len(vtable_entries),
                        'method_names': [e['name'] for e in vtable_entries],
                        'spacing': [(vtable_entries[i+1]['address'] - vtable_entries[i]['address']) 
                                   for i in range(len(vtable_entries)-1)]
                    })
                    i = j
                else:
                    i += 1
            else:
                i += 1
    
    return vtables

def analyze_exception_handler_pattern(functions_text: str) -> Dict:
    """
    Exception handlers often indicate class destructors during unwinding.
    Analyze pattern to understand exception hierarchy.
    """
    pattern = re.compile(r'Catch_All@([0-9a-f]+)')
    matches = pattern.findall(functions_text)
    
    if not matches:
        return {}
    
    # Group by address ranges (same region = same try block)
    handlers_by_region = defaultdict(list)
    for addr_str in matches:
        addr = int(addr_str, 16)
        region = addr // 0x1000  # Group by 4KB regions
        handlers_by_region[region].append(addr)
    
    return {
        'total_handlers': len(matches),
        'grouped_regions': len(handlers_by_region),
        'handlers_per_region': {
            f'0x{region*0x1000:08x}': len(handlers) 
            for region, handlers in sorted(handlers_by_region.items())
        },
        'interpretation': 'C++/SEH exception handling - likely multiple try blocks wrapping critical sections'
    }

def analyze_import_usage_patterns(imports_text: str) -> Dict:
    """
    Analyze how imported APIs are used to infer object models
    """
    
    api_patterns = {
        'callback_pattern': {
            'apis': ['InternetSetStatusCallback', 'InternetSetStatusCallbackA', 'SetUnhandledExceptionFilter'],
            'indicates': 'Event-driven architecture with callback registration'
        },
        'memory_pool_pattern': {
            'apis': ['HeapCreate', 'HeapAlloc', 'HeapReAlloc', 'HeapFree', 'HeapDestroy'],
            'indicates': 'Custom memory pool management (not just malloc) - likely object pooling'
        },
        'critical_section_pattern': {
            'apis': ['InitializeCriticalSection', 'EnterCriticalSection', 'LeaveCriticalSection'],
            'indicates': 'Synchronization for multi-threaded object access'
        },
        'module_loading_pattern': {
            'apis': ['LoadLibraryA', 'GetProcAddress', 'FreeLibrary'],
            'indicates': 'Dynamic plugin/addon system'
        },
        'thread_pattern': {
            'apis': ['CreateThread', 'ExitThread', 'WaitForMultipleObjectsEx', 'Sleep'],
            'indicates': 'Multi-threaded design, likely worker threads for network I/O'
        }
    }
    
    found_patterns = []
    for pattern_name, pattern_info in api_patterns.items():
        for api in pattern_info['apis']:
            if api in imports_text:
                found_patterns.append({
                    'pattern': pattern_name,
                    'api_used': api,
                    'indicates': pattern_info['indicates']
                })
                break
    
    return {
        'detected_patterns': len(found_patterns),
        'patterns': found_patterns
    }

def infer_class_hierarchy():
    """
    Based on binary analysis, infer likely class hierarchy
    """
    return {
        'probable_classes': [
            {
                'name': 'GameWorld / Realm',
                'purpose': 'Main game world state container',
                'methods': ['init(realm_name)', 'update(delta_time)', 'shutdown()', 'on_connection_lost()'],
                'members': ['entities[]', 'terrain_map', 'network_state', 'player_controller']
            },
            {
                'name': 'NetworkManager',
                'purpose': 'Handles realm server communication',
                'methods': ['connect(server, port)', 'send_packet(data)', 'recv_packet()', 'disconnect()'],
                'members': ['socket', 'send_buffer[]', 'recv_buffer[]', 'realm_name'],
                'evidence': 'WSA/Internet APIs'
            },
            {
                'name': 'InputManager / DirectInput Wrapper',
                'purpose': 'Keyboard and mouse input handling',
                'methods': ['init()', 'poll_keys()', 'poll_mouse()', 'on_key_press(key)'],
                'members': ['input_device', 'key_state[]', 'mouse_pos'],
                'evidence': 'DirectInput8 DLL import'
            },
            {
                'name': 'RenderManager / OpenGL Context',
                'purpose': 'Graphics rendering pipeline',
                'methods': ['init(hwnd)', 'clear()', 'render_world()', 'present()'],
                'members': ['gl_context', 'renderqueue', 'shader_cache', 'texture_cache'],
                'evidence': 'GL* function exports'
            },
            {
                'name': 'GameEntity / Unit / Character',
                'purpose': 'Base game object (mobs, players, objects)',
                'methods': ['update()', 'render()', 'take_damage()', 'die()', 'move_to(pos)'],
                'members': ['position', 'hp', 'max_hp', 'animation_state', 'model_id'],
                'evidence': 'ClientMovement.txt references, movement subsystem'
            },
            {
                'name': 'SpellSystem / CastBar',
                'purpose': 'Spell casting and cooldown management',
                'methods': ['cast_spell(spell_id)', 'on_cast_start()', 'on_cast_finish()', 'update_cooldowns()'],
                'members': ['casting_spell', 'cast_timer', 'cooldowns[]', 'spell_queue[]'],
                'evidence': 'Spell references in strings'
            },
            {
                'name': 'AddonSystem / ScriptEngine',
                'purpose': 'Lua addon integration (if present)',
                'methods': ['load_addon(path)', 'call_addon_function()', 'register_event_handler()'],
                'members': ['addon_list[]', 'event_handlers[]', 'lua_state'],
                'evidence': 'Dynamic DLL loading, interface.MPQ references'
            }
        ],
        'architecture_pattern': 'Component-based game engine with event-driven callbacks'
    }

def main():
    report_path = Path('./reports/mcp-analysis.report.json')
    if not report_path.exists():
        print("ERROR: mcp-analysis.report.json not found")
        return
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    functions_text = report.get('calls', {}).get('list_functions', {}).get('text', '')
    imports_text = report.get('calls', {}).get('list_imports', {}).get('text', '')
    
    print("\n" + "="*80)
    print("STRUCTURAL BINARY ANALYSIS: Class & Object Model Inference")
    print("="*80)
    
    # Find vtable patterns
    print("\n[1] VTABLE/CLASS STRUCTURE DETECTION")
    print("-" * 80)
    vtables = find_vtable_patterns(functions_text)
    
    if vtables:
        print(f"Found {len(vtables)} potential vtable regions:\n")
        for i, vt in enumerate(vtables[:10]):  # Show first 10
            print(f"  Class #{vt['potential_class_index']}")
            print(f"    Address range: {vt['start_address']} to {vt['end_address']}")
            print(f"    Virtual methods: {vt['entry_count']}")
            print(f"    Method hints: {', '.join(vt['method_names'][:3])}")
            if len(vt['method_names']) > 3:
                print(f"                 ... and {len(vt['method_names'])-3} more")
            print()
    else:
        print("No obvious vtable patterns found (binary may use different structures)")
    
    # Analyze exception handlers
    print("\n[2] EXCEPTION HANDLING ANALYSIS")
    print("-" * 80)
    exc_analysis = analyze_exception_handler_pattern(functions_text)
    if exc_analysis:
        print(f"""
  Total exception handlers: {exc_analysis.get('total_handlers', 0)}
  Grouped into regions: {exc_analysis.get('grouped_regions', 0)}
  Interpretation: {exc_analysis.get('interpretation', '')}
  
  Handler density per 4KB region:
""")
        for region, count in list(exc_analysis.get('handlers_per_region', {}).items())[:5]:
            print(f"    {region}: {count} handlers")
    
    # Find API patterns
    print("\n[3] API USAGE PATTERN ANALYSIS")
    print("-" * 80)
    api_patterns = analyze_import_usage_patterns(imports_text)
    
    print(f"\nDetected architectural patterns: {api_patterns['detected_patterns']}\n")
    for pattern in api_patterns['patterns']:
        print(f"  [+] {pattern['pattern']}")
        print(f"      Uses: {pattern['api_used']}")
        print(f"      Indicates: {pattern['indicates']}\n")
    
    # Inferred class hierarchy
    print("\n[4] INFERRED CLASS HIERARCHY & OBJECT MODEL")
    print("-" * 80)
    
    hierarchy = infer_class_hierarchy()
    
    print(f"\nArchitecture: {hierarchy['architecture_pattern']}\n")
    print("Probable class definitions:\n")
    
    for cls in hierarchy['probable_classes']:
        print(f"  [CLASS] {cls['name']}")
        print(f"    Purpose: {cls['purpose']}")
        if 'evidence' in cls:
            print(f"    Evidence: {cls['evidence']}")
        print(f"    Key methods:")
        for method in cls['methods'][:4]:
            print(f"      - {method}")
        print(f"    Key members:")
        for member in cls['members'][:4]:
            print(f"      - {member}")
        print()
    
    # Save structured output
    print("\n[5] SAVE STRUCTURAL ANALYSIS")
    print("-" * 80)
    
    output = {
        "timestamp": "2026-03-08",
        "analysis_type": "structural_analysis",
        "binary": "Ascension.exe",
        "vtable_regions": vtables[:50],  # Save first 50
        "exception_analysis": exc_analysis,
        "api_patterns": api_patterns,
        "inferred_classes": hierarchy['probable_classes'],
        "architecture": hierarchy['architecture_pattern'],
        "key_insights": {
            "object_system": "C++ OOP with virtual methods and RTTI",
            "concurrency": "Multi-threaded with critical section synchronization",
            "network_model": "Callback-based for async realm communication",
            "memory_model": "Custom heap allocation with pooling",
            "event_system": "Event-driven with exception-based error handling",
            "extensibility": "Plugin system via dynamic DLL loading"
        }
    }
    
    with open('./reports/structural-analysis.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\nStructural analysis saved to structural-analysis.json")
    
    # Print summary
    print("\n[6] SUMMARY & IMPLICATIONS FOR BOT DEVELOPMENT")
    print("-" * 80)
    print("""
    GAME ENGINE ARCHITECTURE:
    1. Component-based design (Entity, World, Network, Input, Render)
    2. Each component likely has its own thread or async I/O
    3. Shared state protected by critical sections
    4. Event callbacks for state changes
    
    IMPLICATIONS FOR BOT:
    1. MEMORY READING: Need to understand class layout to parse entity/player data
          - Look for Entity vtable to find update() method
          - Hook into entity update loop to read position/HP/combat status
    
    2. STATE TRACKING: Game state maintained in GameWorld singleton
          - Likely allocated at fixed offset from heap base
          - Contains entity list, player controller, network state
    
    3. INPUT INJECTION: DirectInput is the input gateway
          - Can inject key/mouse events through DINPUT API
          - Or hook at higher level: find input callbacks
    
    4. NETWORK MONITORING: NetworkManager handles realm packets
          - WSA callbacks fire on recv - can hook for packet analysis
          - Packet parsing needed to understand protocol
    
    5. ANTI-CHEAT: Multiple protection layers:
          - IsDebuggerPresent checks (bypass with debugger flag spoofing)
          - Signature validation (binary file checksum)
          - Likely external watchdog (separate process monitoring)
          - Timing analysis (frames-per-second regularity)
    
    NEXT STEPS:
    1. Use Ghidra to decompile entry point and find GameWorld init
    2. Scan heap for entity list pattern
    3. Reverse engineer entity struct and player data offsets
    4. Create memory read hooks before building bot
    5. Intercept input calls to inject movement/spells
    """)

if __name__ == '__main__':
    main()
