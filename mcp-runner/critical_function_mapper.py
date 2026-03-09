#!/usr/bin/env python3
"""
Critical Function Mapper - Map the most important functions for reverse engineering
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

def load_all_data():
    """Load all available data"""
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        mcp_report = json.load(f)
    
    with open(REPORTS_DIR / "function-analysis.json", 'r') as f:
        func_analysis = json.load(f)
    
    with open(REPORTS_DIR / "xref-analysis.json", 'r') as f:
        xref_analysis = json.load(f)
    
    return mcp_report, func_analysis, xref_analysis

def parse_functions_detailed(mcp_report):
    """Parse function list with detailed analysis"""
    functions_text = mcp_report.get('calls', {}).get('list_functions', {}).get('text', '')
    
    functions = []
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            func = {
                "name": name,
                "address": f"0x{addr}",
                "address_int": int(addr, 16),
                "params": int(params),
                "category": categorize_function(name),
                "priority": calculate_priority(name, int(addr, 16))
            }
            functions.append(func)
    
    return sorted(functions, key=lambda x: x['priority'], reverse=True)

def categorize_function(name: str) -> str:
    """Categorize function by name patterns"""
    if name in ['entry']:
        return 'entry_point'
    elif 'Catch_All' in name:
        return 'exception_handler'
    elif 'Unwind@' in name:
        return 'unwind_handler'
    elif 'thunk_' in name:
        return 'thunk'
    elif name.startswith('FUN_'):
        return 'unknown_game_code'
    elif 'Module32' in name or 'Thread32' in name or 'Toolhelp' in name:
        return 'anti_cheat'
    elif 'Assert' in name or 'Crash' in name:
        return 'crash_handler'
    elif 'HidD_' in name or 'Hid' in name:
        return 'input_system'
    else:
        return 'named_function'

def calculate_priority(name: str, addr: int) -> int:
    """Calculate reverse engineering priority (higher = more important)"""
    priority = 0
    
    # Entry point is highest priority
    if name == 'entry':
        priority += 1000
    
    # Unknown functions are high priority (game code)
    if name.startswith('FUN_'):
        priority += 500
    
    # Anti-cheat is high priority
    if 'Module32' in name or 'Thread32' in name:
        priority += 400
    
    # Named non-system functions are medium-high priority
    if not any(x in name for x in ['Catch_All', 'Unwind@', 'thunk_']):
        priority += 300
    
    # Functions near entry point are important
    if 0x400000 <= addr < 0x410000:
        priority += 200
    
    # Functions in main code section
    if 0x400000 <= addr < 0x800000:
        priority += 100
    
    return priority

def analyze_critical_paths(func_analysis):
    """Analyze critical code paths for game systems"""
    
    # Look for interesting patterns in function analysis
    critical_paths = {
        "network_handlers": [],
        "rendering_pipeline": [],
        "game_loop_candidates": [],
        "initialization_sequence": []
    }
    
    # Parse function analysis for patterns
    if isinstance(func_analysis, dict):
        # Look for patterns in the analysis
        for key, value in func_analysis.items():
            if 'network' in key.lower() or 'socket' in key.lower():
                critical_paths["network_handlers"].append({
                    "type": key,
                    "details": str(value)[:200]
                })
            elif 'render' in key.lower() or 'draw' in key.lower() or 'gl' in key.lower():
                critical_paths["rendering_pipeline"].append({
                    "type": key,
                    "details": str(value)[:200]
                })
    
    return critical_paths

def generate_decompilation_plan(functions):
    """Generate prioritized decompilation plan"""
    
    plan = {
        "high_priority": [],
        "medium_priority": [],
        "low_priority": [],
        "skip": []
    }
    
    for func in functions:
        category = func['category']
        priority = func['priority']
        
        if priority >= 500:
            plan['high_priority'].append(func)
        elif priority >= 300:
            plan['medium_priority'].append(func)
        elif priority >= 100:
            plan['low_priority'].append(func)
        else:
            plan['skip'].append(func)
    
    return plan

def generate_report():
    """Generate critical function mapping report"""
    
    print("[*] Loading analysis data...")
    mcp_report, func_analysis, xref_analysis = load_all_data()
    
    print("[*] Parsing functions with priority analysis...")
    functions = parse_functions_detailed(mcp_report)
    print(f"[+] Analyzed {len(functions)} functions")
    
    print("[*] Analyzing critical paths...")
    critical_paths = analyze_critical_paths(func_analysis)
    
    print("[*] Generating decompilation plan...")
    decompilation_plan = generate_decompilation_plan(functions)
    
    # Generate summary statistics
    categories = defaultdict(int)
    for func in functions:
        categories[func['category']] += 1
    
    report = {
        "total_functions": len(functions),
        "categories": dict(categories),
        "top_priority_functions": functions[:20],
        "critical_paths": critical_paths,
        "decompilation_plan": {
            "high_priority": len(decompilation_plan['high_priority']),
            "medium_priority": len(decompilation_plan['medium_priority']),
            "low_priority": len(decompilation_plan['low_priority']),
            "skip": len(decompilation_plan['skip']),
            "high_priority_list": decompilation_plan['high_priority']
        }
    }
    
    # Save JSON
    output_path = REPORTS_DIR / "CRITICAL_FUNCTIONS.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f"[+] JSON report saved to: {output_path}")
    
    # Generate markdown
    md = "# CRITICAL FUNCTION MAPPING - Ascension.exe\n\n"
    md += "## Executive Summary\n\n"
    md += f"**Total Functions:** {len(functions)}\n"
    md += f"**High Priority for Decompilation:** {report['decompilation_plan']['high_priority']}\n"
    md += f"**Medium Priority:** {report['decompilation_plan']['medium_priority']}\n"
    md += f"**Low Priority:** {report['decompilation_plan']['low_priority']}\n\n"
    
    md += "## Top 20 Priority Functions\n\n"
    md += "| Priority | Address | Name | Category | Params |\n"
    md += "|----------|---------|------|----------|-------:|\n"
    for func in functions[:20]:
        md += f"| {func['priority']} | {func['address']} | `{func['name']}` | {func['category']} | {func['params']} |\n"
    
    md += "\n## High Priority Decompilation Targets\n\n"
    md += "These functions should be decompiled first:\n\n"
    
    for func in decompilation_plan['high_priority']:
        md += f"### {func['name']} @ {func['address']}\n\n"
        md += f"- **Category:** {func['category']}\n"
        md += f"- **Parameters:** {func['params']}\n"
        md += f"- **Priority Score:** {func['priority']}\n"
        md += f"- **Why Important:** "
        
        if func['category'] == 'entry_point':
            md += "Entry point - initialization and main flow\n"
        elif func['category'] == 'unknown_game_code':
            md += "Unknown function likely contains core game logic\n"
        elif func['category'] == 'anti_cheat':
            md += "Anti-cheat/monitoring code - important for understanding protections\n"
        elif func['category'] == 'crash_handler':
            md += "Error handling - reveals internal state and debugging info\n"
        else:
            md += "Named function with game-specific logic\n"
        
        md += "\n"
    
    md += "## Recommended Analysis Strategy\n\n"
    md += "1. **Start with Entry Point** (`entry` @ 0x00401000)\n"
    md += "   - Decompile to understand initialization sequence\n"
    md += "   - Follow call chain to WinMain or main game loop\n"
    md += "   - Identify subsystem initialization order\n\n"
    
    md += "2. **Analyze Unknown Game Functions** (4 functions)\n"
    md += "   - `FUN_00401010` - Right after entry, likely main function\n"
    md += "   - `FUN_004133c7` - Early code section, likely initialization\n"
    md += "   - `FUN_0047cc90` - Mid code section, possible game loop\n"
    md += "   - `FUN_0088b010` - High address, possible plugin/addon system\n\n"
    
    md += "3. **Examine Anti-Cheat System**\n"
    md += "   - `Module32First/Next` - Process enumeration\n"
    md += "   - `Thread32First/Next` - Thread enumeration\n"
    md += "   - `CreateToolhelp32Snapshot` - System snapshot\n"
    md += "   - Purpose: Detect debuggers, injected DLLs, modified game state\n\n"
    
    md += "4. **Investigate Crash Handler**\n"
    md += "   - `AssertAndCrash` @ 0x008C51D0\n"
    md += "   - May contain debugging strings or state dumps\n"
    md += "   - Useful for understanding internal data structures\n\n"
    
    md += "5. **Search for Network Code**\n"
    md += "   - Look for xrefs to async I/O functions:\n"
    md += "     - `WaitForMultipleObjectsEx`\n"
    md += "     - `GetOverlappedResult`\n"
    md += "     - `CreateIoCompletionPort`\n"
    md += "   - These will lead to network packet handling code\n"
    md += "   - Look for switch statements with many cases (opcode dispatchers)\n\n"
    
    md += "## Next Steps\n\n"
    md += "When live MCP server is available:\n\n"
    md += "```python\n"
    md += "# Decompile entry point and trace initialization\n"
    md += "get_code(address=\"0x00401000\", mode=\"decompiled\")\n"
    md += "get_call_graph(address=\"0x00401000\", depth=3)\n\n"
    
    md += "# Decompile unknown functions\n"
    md += "get_code(address=\"0x00401010\", mode=\"decompiled\")\n"
    md += "get_code(address=\"0x004133c7\", mode=\"decompiled\")\n"
    md += "get_code(address=\"0x0047cc90\", mode=\"decompiled\")\n"
    md += "get_code(address=\"0x0088b010\", mode=\"decompiled\")\n\n"
    
    md += "# Find network I/O handlers\n"
    md += "xrefs(address=\"CreateIoCompletionPort\")\n"
    md += "xrefs(address=\"GetOverlappedResult\")\n\n"
    
    md += "# Search for opcode constants\n"
    md += "search_bytes(pattern=\"ed 01\")  # CMSG_AUTH_SESSION = 0x01ED\n"
    md += "search_bytes(pattern=\"b5 00\")  # MSG_MOVE_START_FORWARD = 0x00B5\n"
    md += "```\n"
    
    md_path = REPORTS_DIR / "CRITICAL_FUNCTIONS.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"[+] Markdown documentation saved to: {md_path}")
    
    return report

def main():
    print("=" * 80)
    print("CRITICAL FUNCTION MAPPER")
    print("=" * 80)
    print()
    
    try:
        report = generate_report()
        
        print("\n" + "=" * 80)
        print("KEY INSIGHTS")
        print("=" * 80)
        print(f"\nHigh Priority Functions: {report['decompilation_plan']['high_priority']}")
        print(f"Unknown Game Code: {report['categories'].get('unknown_game_code', 0)}")
        print(f"Anti-Cheat Functions: {report['categories'].get('anti_cheat', 0)}")
        
        print("\nTop 5 Decompilation Targets:")
        for i, func in enumerate(report['top_priority_functions'][:5], 1):
            print(f"  {i}. {func['name']} @ {func['address']} (priority: {func['priority']})")
        
        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETE")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
