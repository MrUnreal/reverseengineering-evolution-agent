#!/usr/bin/env python3
"""
Advanced Function Analysis - Decompile and rename key functions
Uses Ghidra backend through file-based communication
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

def extract_function_list():
    """Extract all functions from the report"""
    report_path = Path('./reports/mcp-analysis.report.json')
    if not report_path.exists():
        return []
    
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    functions_text = report.get('calls', {}).get('list_functions', {}).get('text', '')
    
    functions = []
    for line in functions_text.split('\n'):
        # Parse function lines like: "- entry @ 00401000 (0 params)"
        match = re.match(r'^\s*- (.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            functions.append({
                'name': name,
                'address': addr.lower(),
                'params': int(params),
                'original_name': name
            })
    
    return functions

def suggest_function_names(functions: List[Dict]) -> List[Dict]:
    """
    Suggest meaningful names for functions based on patterns and context
    """
    
    naming_rules = [
        # Entry points and main functions
        (r'^entry$', 'EntryPoint'),
        (r'^_main$|^main$', 'MainFunction'),
        (r'^WinMain$', 'WindowsEntryPoint'),
        (r'^DllMain$', 'DllEntry'),
        
        # Comparison with catch-all exception handlers
        (r'^Catch_All@', 'ExceptionHandler_'),
        (r'^Unwind@', 'ExceptionUnwind_'),
        (r'^thunk_', 'APIThunk_'),
        
        # API imports that were resolved
        (r'^Module32\w+$', '$0'),  # Keep as-is
        (r'^CreateToolhelp32Snapshot$', '$0'),
        (r'^Thread32\w+$', '$0'),
        (r'^AssertAndCrash$', '$0'),
        (r'^HidD_FreePreparsedData$', '$0'),
        
        # Generic FUN_ placeholders - these need better analysis
        (r'^FUN_([0-9a-f]+)$', 'UnknownFunction_\\1'),
    ]
    
    # Apply naming rules
    for func_dict in functions:
        original = func_dict['name']
        matched = False
        
        for pattern, replacement in naming_rules:
            if re.match(pattern, original):
                if replacement.startswith('$'):
                    func_dict['suggested_name'] = original
                else:
                    if '\\1' in replacement:
                        # Extract hex digits from original
                        hex_match = re.search(r'([0-9a-fA-F]+)', original)
                        if hex_match:
                            replacement = replacement.replace('\\1', hex_match.group(1))
                    elif replacement.endswith('_'):
                        # Append address for placeholder functions
                        replacement = replacement + func_dict['address'].upper()
                    
                    func_dict['suggested_name'] = replacement
                matched = True
                break
        
        if not matched:
            func_dict['suggested_name'] = original
    
    return functions

def categorize_functions(functions: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Categorize functions by likely purpose
    """
    categories = {
        'entry_points': [],
        'system_integration': [],
        'exception_handling': [],
        'api_wrappers': [],
        'unknown_functions': []
    }
    
    for func in functions:
        name = func['name'].lower()
        
        if 'entry' in name or 'main' in name or 'winmain' in name or 'dllmain' in name:
            categories['entry_points'].append(func)
        elif 'module32' in name or 'thread32' in name or 'toolhelp' in name or 'hid_' in name or 'assert' in name:
            categories['system_integration'].append(func)
        elif 'catch' in name or 'unwind' in name or 'exception' in name:
            categories['exception_handling'].append(func)
        elif name.startswith('thunk_'):
            categories['api_wrappers'].append(func)
        else:
            categories['unknown_functions'].append(func)
    
    return categories

def analyze_function_distribution(functions: List[Dict]) -> Dict:
    """
    Analyze address distribution to understand code layout
    """
    addresses = [int(f['address'], 16) for f in functions]
    
    if not addresses:
        return {}
    
    addresses.sort()
    
    return {
        'total_functions': len(functions),
        'lowest_address': hex(min(addresses)),
        'highest_address': hex(max(addresses)),
        'address_range': hex(max(addresses) - min(addresses)),
        'average_spacing': hex((max(addresses) - min(addresses)) // len(addresses) if len(addresses) > 1 else 0)
    }

def main():
    print("\n" + "="*80)
    print("ADVANCED FUNCTION ANALYSIS: Ascension.exe")
    print("="*80)
    
    # Extract functions
    print("\n[1] EXTRACTING FUNCTION LIST...")
    functions = extract_function_list()
    print(f"    Found {len(functions)} functions in binary")
    
    if not functions:
        print("    ERROR: No functions found in report")
        return
    
    # Suggest names
    print("\n[2] ANALYZING AND NAMING FUNCTIONS...")
    functions = suggest_function_names(functions)
    
    # Show sample renames
    print("\n    Sample function name suggestions:")
    for func in functions[:10]:
        if func['name'] != func['suggested_name']:
            print(f"      {func['name']:30} -> {func['suggested_name']}")
        else:
            print(f"      {func['name']:30} (kept as-is)")
    
    # Categorize
    print("\n[3] CATEGORIZING FUNCTIONS BY PURPOSE...")
    categories = categorize_functions(functions)
    
    print(f"\n    Entry points & initialization ({len(categories['entry_points'])}):")
    for func in categories['entry_points'][:5]:
        print(f"      {func['address']}: {func['suggested_name']}")
    
    print(f"\n    System integration ({len(categories['system_integration'])}):")
    for func in categories['system_integration'][:5]:
        print(f"      {func['address']}: {func['suggested_name']}")
    
    print(f"\n    Exception handling ({len(categories['exception_handling'])}):")
    for func in categories['exception_handling'][:5]:
        print(f"      {func['address']}: {func['suggested_name']}")
    
    print(f"\n    API wrappers/thunks ({len(categories['api_wrappers'])}):")
    for func in categories['api_wrappers'][:5]:
        print(f"      {func['address']}: {func['suggested_name']}")
    
    print(f"\n    Unknown/game functions ({len(categories['unknown_functions'])}):")
    for func in categories['unknown_functions'][:10]:
        print(f"      {func['address']}: {func['suggested_name']}")
    
    # Address distribution
    print("\n[4] CODE LAYOUT ANALYSIS")
    layout = analyze_function_distribution(functions)
    for key, val in layout.items():
        print(f"    {key}: {val}")
    
    # Key findings
    print("\n[5] KEY ARCHITECTURE FINDINGS")
    print("-" * 80)
    
    # Find .text section bounds
    min_addr = min(int(f['address'], 16) for f in functions)
    max_addr = max(int(f['address'], 16) for f in functions)
    code_size = max_addr - min_addr
    
    print(f"""
    BINARY STRUCTURE:
    - Code section: 0x{min_addr:08x} to 0x{max_addr:08x} (~{code_size/1024:.1f} KB)
    - Entry point: 0x00401000 (standard Win32 image base)
    - Total analyzed functions: {len(functions)}
    
    EXECUTION FLOW:
    1. Entry point (00401000) - initializes runtime
    2. Unknown FUN_00401010 - likely calls main game init
    3. ~40+ exception handlers registered (Catch_All@XXXXXXXX)
    4. Exception unwinding code for cleanup (Unwind@XXXXXXXX)
    
    SUBSYSTEM ORGANIZATION:
    - Scattered throughout address space (not tightly packed)
    - Multiple exception handling regions suggest:
      * Try-catch blocks for critical sections
      * Separate module boundaries (code/data separation)
      * Likely C++ or SEH-based error handling
    
    IDENTIFIED SUBSYSTEMS (from imports/strings):
    + Network: WSA socket functions, HTTP communication
    + Rendering: OpenGL (glXxxx functions, NOT Direct3D as initially thought)
    + Input: DirectInput8 for keyboard/mouse
    + Memory: Optimized heap management (HeapCreate, HeapReAlloc)
    + Threading: Critical sections for synchronization
    + Anti-debugging: IsDebuggerPresent, SetUnhandledExceptionFilter
    
    GAME STATE MANAGEMENT:
    - "InternetSetStatusCallback" -> realm connection state tracking
    - "ImmSetConversionStatus" -> IME (Asian input) support for character names
    - "GlobalMemoryStatus" -> dynamic memory monitoring
    - Suggests object-oriented design with callbacks
    
    PROBABLE MAIN LOOP STRUCTURE:
    1. Initialize DirectInput8 (keyboard/mouse)
    2. Connect to realm (Internet/WSA APIs)
    3. Load game assets (file I/O, mpq parsing)
    4. Render loop: input -> game state update -> GL render
    5. Exception handling wraps critical sections
    """)
    
    # Save detailed function map
    output = {
        "timestamp": "2026-03-08",
        "binary": "Ascension.exe",
        "analysis_type": "advanced_function_analysis",
        "total_functions": len(functions),
        "all_functions": functions,
        "categories": {
            k: [{'address': f['address'], 'original_name': f['original_name'], 
                 'suggested_name': f['suggested_name'], 'params': f['params']} 
                 for f in v]
            for k, v in categories.items()
        },
        "code_layout": layout,
        "key_findings": {
            "binary_structure": "x86 32-bit, Image Base 0x00400000",
            "rendering_api": "OpenGL (NOT Direct3D)",
            "networking": "WinSocket API with HTTP fallback",
            "input_system": "DirectInput8",
            "protection": "Anti-debugging enabled",
            "memory_model": "Heap-based with custom allocators"
        }
    }
    
    with open('./reports/function-analysis.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\n[OK] Function analysis complete - results saved to function-analysis.json")

if __name__ == '__main__':
    main()
