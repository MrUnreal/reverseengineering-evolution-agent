#!/usr/bin/env python3
"""
Deep binary analysis for Ascension.exe
Identifies key functions, analyzes subsystems, and creates function name map
"""

import json
import re
from collections import defaultdict
from pathlib import Path

def analyze_strings_for_subsystems(strings_text):
    """Analyze strings to identify subsystem functions"""
    
    subsystems = {
        'network': {
            'patterns': ['network', 'sock', 'send', 'recv', 'packet', 'realm', 'server', 'port', 'bind', 'listen', 'connect', 'wsasocket', 'wsarecv', 'wsasend'],
            'references': []
        },
        'rendering': {
            'patterns': ['render', 'd3d', 'device', 'texture', 'shader', 'camera', 'scene', 'draw', 'mesh', 'vertex'],
            'references': []
        },
        'input': {
            'patterns': ['input', 'keyboard', 'mouse', 'key', 'button', 'click', 'move', 'getasynckeystate', 'getmessage'],
            'references': []
        },
        'game_state': {
            'patterns': ['player', 'character', 'unit', 'spell', 'inventory', 'status', 'hp', 'mana', 'target', 'combat'],
            'references': []
        },
        'memory': {
            'patterns': ['malloc', 'free', 'virtual', 'heap', 'alloc', 'new', 'delete'],
            'references': []
        },
        'file_io': {
            'patterns': ['file', 'read', 'write', 'open', 'close', 'mpq', 'dbc', 'load'],
            'references': []
        },
        'addon_system': {
            'patterns': ['addon', 'lua', 'script', 'interface', 'ui', 'frame', 'button', 'event'],
            'references': []
        },
        'crypto': {
            'patterns': ['encrypt', 'decrypt', 'hash', 'signature', 'key', 'rsa', 'md5', 'sha'],
            'references': []
        }
    }
    
    lines = strings_text.split('\n')
    for line in lines:
        line_lower = line.lower()
        for subsystem, data in subsystems.items():
            for pattern in data['patterns']:
                if pattern in line_lower:
                    data['references'].append(line.strip())
                    break
    
    return subsystems

def analyze_imports_for_subsystems(imports_text):
    """Analyze imports to identify what API categories are used"""
    
    import_categories = {
        'networking': ['WSASocket', 'WSARecv', 'WSASend', 'WSAConnect', 'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv'],
        'file_io': ['CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile', 'CloseHandle', 'OpenFileMapping'],
        'memory': ['VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'HeapAlloc', 'HeapFree', 'malloc', 'free'],
        'threading': ['CreateThread', 'ExitThread', 'WaitForMultipleObjects', 'Sleep', 'EnterCriticalSection', 'LeaveCriticalSection'],
        'dll_loading': ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'FreeLibrary'],
        'registry': ['RegOpenKeyEx', 'RegQueryValueEx', 'RegSetValueEx', 'RegCloseKey'],
        'debugging': ['IsDebuggerPresent', 'OutputDebugString', 'DebugBreak', 'SetUnhandledExceptionFilter'],
        'ui': ['CreateWindowEx', 'PostMessage', 'SendMessage', 'GetMessage', 'DispatchMessage'],
        'process': ['GetCurrentProcess', 'CreateProcess', 'TerminateProcess', 'GetProcessId'],
        'crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptCreateHash', 'CryptGetHashParam']
    }
    
    categories = defaultdict(set)
    lines = imports_text.split('\n')
    
    for line in lines:
        for category, apis in import_categories.items():
            for api in apis:
                if api in line:
                    categories[category].add(line.strip())
    
    return dict(categories)

def identify_key_functions(functions_text):
    """Identify potentially important functions based on naming patterns"""
    
    function_patterns = {
        'main_entry': r'^(entry|_main|_start|WinMain|DllMain)',
        'init': r'(Init|Initialize|Setup|Start|Begin)',
        'game_loop': r'(GameLoop|MainLoop|UpdateLoop|Tick|Update)',
        'network': r'(Network|Socket|Send|Recv|Connect|Packet)',
        'world': r'(World|Scene|Map|Zone|Realm)',
        'entity': r'(Entity|Object|Unit|Character|NPC)',
        'spell': r'(Spell|Skill|Ability|Cast|Action)',
        'combat': r'(Combat|Fight|Attack|Damage|Health)',
        'ui': r'(UI|Frame|Window|Dialog|Menu)',
        'render': r'(Render|Draw|Camera|Scene|Display)',
        'physics': r'(Physics|Collision|Move|Position|Transform)'
    }
    
    results = defaultdict(list)
    lines = functions_text.split('\n')
    
    for line in lines:
        for category, pattern in function_patterns.items():
            if re.search(pattern, line, re.IGNORECASE):
                results[category].append(line.strip())
    
    return dict(results)

def main():
    # Support both Docker (/reports) and local (./reports) paths
    report_path = Path('/reports/mcp-analysis.report.json')
    if not report_path.exists():
        report_path = Path('./reports/mcp-analysis.report.json')
    
    if not report_path.exists():
        print(f"ERROR: mcp-analysis.report.json not found at {report_path}")
        return
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    # Extract text content from MCP calls
    strings_text = report.get('calls', {}).get('list_strings', {}).get('text', '')
    imports_text = report.get('calls', {}).get('list_imports', {}).get('text', '')
    functions_text = report.get('calls', {}).get('list_functions', {}).get('text', '')
    
    print("\n" + "="*80)
    print("DEEP BINARY ANALYSIS: Ascension.exe")
    print("="*80)
    
    # 1. Program structure
    program_info = report.get('calls', {}).get('get_program_info', {}).get('text', '')
    print("\n[1] BINARY STRUCTURE")
    print("-" * 80)
    print(program_info)
    
    # 2. Key functions by category
    print("\n[2] KEY FUNCTION IDENTIFICATION")
    print("-" * 80)
    key_funcs = identify_key_functions(functions_text)
    for category, functions in sorted(key_funcs.items()):
        if functions:
            print(f"\n{category.upper()} FUNCTIONS ({len(functions)} found):")
            for func in functions[:10]:  # First 10 per category
                print(f"  {func}")
            if len(functions) > 10:
                print(f"  ... and {len(functions) - 10} more")
    
    # 3. Subsystem detection from strings
    print("\n[3] SUBSYSTEM DETECTION (via strings analysis)")
    print("-" * 80)
    subsystems = analyze_strings_for_subsystems(strings_text)
    for subsystem, data in sorted(subsystems.items()):
        refs = data['references']
        if refs:
            print(f"\n{subsystem.upper()} ({len(set(refs))} unique indicators):")
            for ref in list(set(refs))[:5]:
                print(f"  - {ref}")
            if len(set(refs)) > 5:
                print(f"  ... and {len(set(refs)) - 5} more references")
    
    # 4. API usage analysis
    print("\n[4] API DEPENDENCY ANALYSIS")
    print("-" * 80)
    api_categories = analyze_imports_for_subsystems(imports_text)
    for category in sorted(api_categories.keys()):
        apis = api_categories[category]
        if apis:
            print(f"\n{category.upper()} ({len(apis)} imports):")
            for api in sorted(apis)[:5]:
                print(f"  {api}")
            if len(apis) > 5:
                print(f"  ... and {len(apis) - 5} more")
    
    # 5. Architecture inference
    print("\n[5] INFERRED ARCHITECTURE")
    print("-" * 80)
    
    inferences = []
    
    if 'networking' in api_categories and len(api_categories['networking']) > 0:
        inferences.append("+ Networked multiplayer: Uses socket APIs (realm communication)")
    
    if 'debugging' in api_categories and 'IsDebuggerPresent' in str(api_categories.get('debugging', [])):
        inferences.append("[!] Anti-debugging present: IsDebuggerPresent checks indicate protection")
    
    if 'crypto' in api_categories and len(api_categories['crypto']) > 0:
        inferences.append("+ Encryption/validation: Uses crypto APIs for authentication")
    
    if 'dll_loading' in api_categories:
        inferences.append("+ Plugin/addon system: Dynamic DLL loading capability")
    
    if 'rendering' in subsystems and subsystems['rendering']['references']:
        inferences.append("+ Direct rendering: Likely D3D/graphics rendering engine")
    
    if 'entity' in key_funcs and len(key_funcs['entity']) > 0:
        inferences.append("+ Entity system: Object/entity management for game world")
    
    if 'world' in key_funcs:
        inferences.append("+ World/map system: Zone/world management for game areas")
    
    if 'spell' in key_funcs:
        inferences.append("+ Spell system: Magic/ability casting system")
    
    for inference in inferences:
        print(f"  {inference}")
    
    # 6. Next steps for deeper analysis
    print("\n[6] RECOMMENDED NEXT ANALYSIS STEPS")
    print("-" * 80)
    print("""
  1. Decompile entry point (00401000) - understand initialization flow
  2. Analyze API thunk functions to identify real function signatures
  3. Trace cross-references from key imports (WSASocket, CreateThread, etc.)
  4. Map class structure via RTTI (vtables at 0x00408000 region)
  5. Find game loop - likely calls most subsystems repeatedly
  6. Identify global state structure - likely large heap allocation post-init
  7. Map realm communication protocol - intercept and analyze network packets
  8. Locate addon/Lua integration points - may be separate DLL or embedded
  9. Identify anti-cheat hooks - signature validation, external monitoring
 10. Map DirectX/rendering pipeline - understand mesh/texture/shader flow
    """)
    
    # Save structured analysis output
    analysis_output = {
        "timestamp": "2026-03-08",
        "binary": "Ascension.exe",
        "key_functions": key_funcs,
        "subsystems": {k: {"count": len(v["references"]), "samples": list(set(v["references"]))[:3]} 
                       for k, v in subsystems.items() if v["references"]},
        "api_categories": {k: list(v) for k, v in api_categories.items() if v},
        "inferences": inferences
    }
    
    # Save to appropriate location based on context
    if Path('/reports').exists():
        with open('/reports/deep-analysis.json', 'w') as f:
            json.dump(analysis_output, f, indent=2)
    
    # Also save to local path
    Path('./reports').mkdir(exist_ok=True)
    with open('./reports/deep-analysis.json', 'w') as f:
        json.dump(analysis_output, f, indent=2)
    
    print("\n[OK] Analysis complete - results saved to deep-analysis.json")

if __name__ == '__main__':
    main()
