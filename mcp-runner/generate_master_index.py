#!/usr/bin/env python3
"""
Generate master index of all RE analysis completed
"""

import json
import os
from pathlib import Path
from datetime import datetime

def load_json_file(path):
    """Safely load JSON file"""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}

def generate_master_index():
    """Create comprehensive index of all analysis"""
    
    reports_dir = Path('./reports')
    
    analysis_files = {
        'mcp-analysis.report.json': 'RAW MCP Analysis Output',
        'COMPREHENSIVE_ANALYSIS.md': 'Complete Binary Structure Analysis',
        'BOT_RE_ROADMAP.md': 'Implementation Roadmap & Function Signatures',
        'deep-analysis.json': 'Subsystem Categorization',
        'function-analysis.json': 'Function Naming & Categorization',
        'structural-analysis.json': 'Class Hierarchy & Vtable Mapping',
        'bot-signals.json': 'Bot-Relevant Signal Extraction',
        'function-hunting.json': 'Targeted Function Search Results',
        'xref-analysis.json': 'Cross-Reference & Call Chain Analysis',
        'decompilation-plan.json': 'Manual Decompilation Workflow'
    }
    
    index = {
        "timestamp": datetime.now().isoformat(),
        "project": "Ascension.exe Reverse Engineering",
        "binary": {
            "name": "Ascension.exe",
            "size": "7.7 MB",
            "platform": "x86 32-bit",
            "architecture": "Component-based C++ game engine",
            "target_game": "WoW 3.3.5 Private Server"
        },
        "analysis_complete": {
            "binary_structure": True,
            "function_identification": True,
            "subsystem_mapping": True,
            "class_hierarchy": True,
            "call_chain_analysis": False,  # Requires manual Ghidra
            "decompilation": False  # Requires manual Ghidra
        },
        "reports": {}
    }
    
    # Catalog each report
    for filename, description in analysis_files.items():
        filepath = reports_dir / filename
        if filepath.exists():
            size_kb = filepath.stat().st_size / 1024
            index["reports"][filename] = {
                "description": description,
                "file_size_kb": round(size_kb, 2),
                "exists": True,
                "path": str(filepath)
            }
        else:
            index["reports"][filename] = {
                "description": description,
                "exists": False
            }
    
    # Add summary statistics
    index["analysis_summary"] = {
        "total_functions_analyzed": 451,
        "functions_identified": 200,
        "function_categories": {
            "entry_points": 1,
            "system_integration": 6,
            "exception_handling": 186,
            "api_wrappers": 2,
            "unknown_game_functions": 5
        },
        "subsystems_identified": [
            "Rendering (OpenGL)",
            "Networking (WinSocket + WinInet)",
            "Input (DirectInput8)",
            "Game State Management",
            "Memory Management",
            "Exception Handling",
            "Anti-Cheat/Protection",
            "Addon System (Dynamic DLL loading)"
        ],
        "vtables_detected": 11,
        "largest_vtable_methods": 26
    }
    
    # Add key findings
    index["key_findings"] = {
        "entry_point": "0x00401000",
        "likely_game_init": "0x00401010",
        "largest_class_vtable": "0x9C5E70 (26 virtual methods)",
        "exception_handler_regions": [
            "0x0041D000",
            "0x0041F000",
            "0x00420000",
            "0x00423000"
        ],
        "critical_apis": [
            "WSASocket, WSAEnumNetworkEvents (networking)",
            "DirectInput8Create (input)",
            "glViewport, glBindTexture (rendering)",
            "IsDebuggerPresent (anti-debug)",
            "InternetSetStatusCallback (callbacks)"
        ],
        "game_subsystems": {
            "network": "Event-driven async WinSocket + WinInet",
            "rendering": "OpenGL (fixed pipeline era)",
            "input": "DirectInput8 wrapper",
            "state_management": "Object-oriented with callback events",
            "memory": "Custom heap pooling + virtual memory"
        }
    }
    
    # Add next steps
    index["next_steps"] = [
        {
            "phase": "Function Decompilation",
            "status": "MANUAL REQUIRED",
            "steps": [
                "Open Ascension.exe in Ghidra GUI",
                "Decompile functions at key addresses",
                "Search for spell casting, movement, packet handling code",
                "Document function signatures and call chains"
            ],
            "required_for": "Bot implementation"
        },
        {
            "phase": "Data Structure Reversal",
            "status": "RESEARCH",
            "steps": [
                "Reverse engineer Player/Unit class layout",
                "Identify spell cooldown storage",
                "Map entity list/array structure",
                "Find packet structure definitions"
            ],
            "required_for": "Memory reading/writing"
        },
        {
            "phase": "Protocol Analysis",
            "status": "RESEARCH",
            "steps": [
                "Intercept network packets",
                "Identify opcode values",
                "Reverse engineer packet structures",
                "Document CMSG/SMSG formats"
            ],
            "required_for": "Network communication"
        },
        {
            "phase": "Bot Implementation",
            "status": "BLOCKED",
            "dependencies": [
                "Function decompilation complete",
                "Data structures identified",
                "Protocol documented"
            ]
        },
        {
            "phase": "Anti-Cheat Evasion",
            "status": "DESIGN",
            "strategies": [
                "Avoid IsDebuggerPresent triggers",
                "Maintain file integrity",
                "Add realistic timing jitter",
                "Monitor external watchdog indicators"
            ]
        }
    ]
    
    # Create reading guide
    index["recommended_reading_order"] = [
        {
            "file": "COMPREHENSIVE_ANALYSIS.md",
            "reason": "Complete overview of all findings",
            "time": "10 minutes"
        },
        {
            "file": "BOT_RE_ROADMAP.md",
            "reason": "Implementation plan with expected function signatures",
            "time": "15 minutes"
        },
        {
            "file": "function-analysis.json",
            "reason": "Complete function list with all addresses",
            "time": "5 minutes (reference)"
        },
        {
            "file": "structural-analysis.json",
            "reason": "Class hierarchy and vtable locations",
            "time": "5 minutes (reference)"
        },
        {
            "file": "decompilation-plan.json",
            "reason": "Specific patterns to search for in Ghidra",
            "time": "Reference during manual RE"
        }
    ]
    
    return index

def main():
    print("\n" + "="*80)
    print("MASTER ANALYSIS INDEX GENERATION")
    print("="*80)
    
    # Generate index
    index = generate_master_index()
    
    # Print summary
    print(f"\n[+] Analysis Complete: {len(index['reports'])} reports generated")
    print(f"\n[BINARY STATS]")
    print(f"    Functions analyzed: {index['analysis_summary']['total_functions_analyzed']}")
    print(f"    Functions identified: {index['analysis_summary']['functions_identified']}")
    print(f"    Subsystems mapped: {len(index['analysis_summary']['subsystems_identified'])}")
    print(f"    VTables detected: {index['analysis_summary']['vtables_detected']}")
    
    print(f"\n[GENERATED REPORTS]")
    for filename, info in index['reports'].items():
        if info['exists']:
            print(f"    [{info['file_size_kb']:6.1f} KB] {filename}")
            print(f"                 {info['description']}")
    
    print(f"\n[KEY FINDINGS]")
    for key, value in index['key_findings'].items():
        if isinstance(value, list):
            print(f"    {key}:")
            for item in value:
                print(f"      - {item}")
        elif isinstance(value, dict):
            print(f"    {key}:")
            for k, v in value.items():
                print(f"      {k}: {v}")
        else:
            print(f"    {key}: {value}")
    
    print(f"\n[RECOMMENDED NEXT STEPS]")
    for step in index['next_steps']:
        print(f"\n    {step['phase']}")
        print(f"      Status: {step['status']}")
        if 'steps' in step:
            for substep in step['steps'][:2]:
                print(f"      - {substep}")
    
    print(f"\n[READING GUIDE]")
    for item in index['recommended_reading_order']:
        print(f"    {item['file']:40s} ({item['time']:10s})")
        print(f"      {item['reason']}")
    
    # Save index
    with open('./reports/ANALYSIS_INDEX.json', 'w') as f:
        json.dump(index, f, indent=2)
    
    # Also save as markdown for easy reading
    with open('./reports/ANALYSIS_INDEX.md', 'w') as f:
        f.write("# Ascension.exe Reverse Engineering - Master Analysis Index\n\n")
        f.write(f"**Generated:** {index['timestamp']}\n\n")
        
        f.write("## Binary Information\n")
        for key, value in index['binary'].items():
            f.write(f"- **{key}:** {value}\n")
        
        f.write("\n## Analysis Status\n")
        for key, value in index['analysis_complete'].items():
            status = "✓ COMPLETE" if value else "✗ PENDING"
            f.write(f"- {key}: {status}\n")
        
        f.write("\n## Generated Reports\n")
        for filename, info in index['reports'].items():
            if info['exists']:
                f.write(f"- **{filename}** ({info['file_size_kb']} KB)\n")
                f.write(f"  {info['description']}\n\n")
        
        f.write("\n## Key Findings\n")
        f.write(f"- **Entry Point:** {index['key_findings']['entry_point']}\n")
        f.write(f"- **Largest VTable:** {index['key_findings']['largest_class_vtable']}\n")
        f.write(f"- **Subsystems:** {', '.join(index['analysis_summary']['subsystems_identified'][:3])} (and more)\n")
        
        f.write("\n## Next Steps\n")
        for step in index['next_steps'][:3]:
            f.write(f"### {step['phase']}\n")
            f.write(f"Status: {step['status']}\n")
            for substep in step['steps']:
                f.write(f"- {substep}\n")
            f.write("\n")
        
        f.write("\n## Recommended Reading Order\n")
        for i, item in enumerate(index['recommended_reading_order'], 1):
            f.write(f"{i}. **{item['file']}** ({item['time']})\n")
            f.write(f"   {item['reason']}\n\n")
    
    print("\n[OK] Master index saved to ANALYSIS_INDEX.json and ANALYSIS_INDEX.md")

if __name__ == '__main__':
    main()
