#!/usr/bin/env python3
"""
Master Documentation Generator - Consolidate all findings into comprehensive docs
Works with existing analysis reports

"""

import json
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
import re

REPORTS_DIR = Path("./reports")

def load_existing_reports() -> Dict:
    """Load all existing analysis reports"""
    reports = {}
    
    for json_file in REPORTS_DIR.glob("*.json"):
        try:
            with open(json_file, 'r') as f:
                reports[json_file.stem] = json.load(f)
            print(f"[+] Loaded {json_file.name}")
        except Exception as e:
            print(f"[-] Error loading {json_file.name}: {e}")
    
    return reports

def generate_executive_summary(reports: Dict) -> str:
    """Generate executive summary from all reports"""
    
    md = "# ASCENSION.EXE - COMPLETE REVERSE ENGINEERING ANALYSIS\n\n"
    md += "## Executive Summary\n\n"
    md += f"**Analysis Date:** March 9, 2026\n"
    md += f"**Target:** Ascension.exe (WoW 3.3.5a Private Server Client)\n"
    md += f"**Reports Analyzed:** {len(reports)}\n\n"
    
    md += "### Key Findings\n\n"
    
    # Binary info
    if 'mcp-analysis.report' in reports:
        prog_info = reports['mcp-analysis.report'].get('calls', {}).get('get_program_info', {})
        if prog_info:
            md += "#### Binary Information\n"
            text = prog_info.get('text', '')
            for line in text.split('\n'):
                if ':' in line and not line.startswith('['):
                    md += f"- {line.strip()}\n"
            md += "\n"
    
    # Import summary
    if 'mcp-analysis.report' in reports:
        imports = reports['mcp-analysis.report'].get('calls', {}).get('list_imports', {}).get('text', '')
        import_count = imports.count(' from ')
        dlls = set(re.findall(r'from\s+(\S+\.dll)', imports, re.IGNORECASE))
        md += f"#### Imports\n"
        md += f"- **Total Imports:** {import_count}\n"
        md += f"- **DLLs:** {len(dlls)}\n"
        md += f"- **Key Libraries:** {', '.join(sorted(dlls)[:10])}\n\n"
    
    # Function summary
    if 'mcp-analysis.report' in reports:
        functions = reports['mcp-analysis.report'].get('calls', {}).get('list_functions', {}).get('text', '')
        func_count = functions.count('\n- ')
        md += f"#### Functions\n"
        md += f"- **Total Functions:** {func_count}\n"
        md += f"- **Exception Handlers:** {functions.count('Catch_All')}\n"
        md += f"- **Unwind Handlers:** {functions.count('Unwind@')}\n\n"
    
    return md

def document_network_architecture(reports: Dict) -> str:
    """Document network and packet handling"""
    
    md = "## Network Architecture\n\n"
    
    # From comprehensive analysis
    if 'COMPREHENSIVE_ANALYSIS' in reports or Path(REPORTS_DIR / "COMPREHENSIVE_ANALYSIS.md").exists():
        try:
            with open(REPORTS_DIR / "COMPREHENSIVE_ANALYSIS.md", 'r') as f:
                content = f.read()
                
            # Extract network subsystem section
            if "Network Subsystem" in content:
                start = content.find("### Network Subsystem")
                end = content.find("###", start + 1)
                if end == -1:
                    end = len(content)
                md += content[start:end] + "\n"
        except:
            pass
    
    # Network APIs from imports
    if 'mcp-analysis.report' in reports:
        imports = reports['mcp-analysis.report'].get('calls', {}).get('list_imports', {}).get('text', '')
        
        md += "### Network APIs Detected\n\n"
        network_apis = []
        for line in imports.split('\n'):
            if any(keyword in line.lower() for keyword in ['wsa', 'socket', 'internet', 'http', 'network']):
                match = re.match(r'^\s*-\s+(.+?)\s+from', line)
                if match:
                    network_apis.append(match.group(1))
        
        if network_apis:
            for api in network_apis[:30]:
                md += f"- `{api}`\n"
            md += "\n"
    
    # Realm strings
    md += "### Realm/Server Communication\n\n"
    md += "String references found:\n"
    md += "- `Realm: ???` @ 0x009E1E50\n"
    md += "- `Realm: ` @ 0x009E1E64\n\n"
    md += "**Analysis:** Event-driven async networking with WinSocket and WinInet APIs\n\n"
    
    return md

def document_rendering_system(reports: Dict) -> str:
    """Document rendering and graphics"""
    
    md = "## Rendering System\n\n"
    md += "### OpenGL Subsystem\n\n"
    
    if 'mcp-analysis.report' in reports:
        imports = reports['mcp-analysis.report'].get('calls', {}).get('list_imports', {}).get('text', '')
        
        gl_apis = []
        for line in imports.split('\n'):
            if 'gl' in line.lower() and 'from OPENGL32.dll' in line:
                match = re.match(r'^\s*-\s+(.+?)\s+from', line)
                if match:
                    gl_apis.append(match.group(1))
        
        if gl_apis:
            md += "**OpenGL Functions Imported:**\n\n"
            for api in gl_apis[:50]:
                md += f"- `{api}`\n"
            md += f"\n**Total OpenGL imports:** {len(gl_apis)}\n\n"
    
    md += "**Architecture:** OpenGL 1.4 era (fixed pipeline), texture management, vertex arrays\n\n"
    md += "**Asset Files Referenced:**\n"
    md += "- common.MPQ\n"
    md += "- lichking.MPQ\n"
    md += "- terrain.MPQ\n"
    md += "- texture.MPQ\n"
    md += "- model.MPQ\n\n"
    
    return md

def document_game_systems(reports: Dict) -> str:
    """Document game-specific systems"""
    
    md = "## Game Systems\n\n"
    
    # From structural analysis
    if 'structural-analysis' in reports:
        vtables = reports['structural-analysis'].get('vtable_regions', [])
        md += f"### Virtual Function Tables\n\n"
        md += f"**Identified VTable Regions:** {len(vtables)}\n\n"
        
        for i, vtable in enumerate(vtables[:5]):
            md += f"#### VTable {i+1}\n"
            md += f"- **Address Range:** {vtable.get('start_address')} - {vtable.get('end_address')}\n"
            md += f"- **Entry Count:** {vtable.get('entry_count')}\n"
            md += f"- **Methods:** {', '.join(vtable.get('method_names', [])[:5])}...\n\n"
    
    # String-based system detection
    if 'mcp-analysis.report' in reports:
        strings = reports['mcp-analysis.report'].get('calls', {}).get('list_strings', {}).get('text', '')
        
        # Movement system
        movement_refs = [line for line in strings.split('\n') if 'movement' in line.lower() or 'movelog' in line.lower()]
        if movement_refs:
            md += "### Movement System\n\n"
            md += "**String References:**\n"
            for ref in movement_refs[:5]:
                md += f"- {ref.strip()}\n"
            md += "\n"
        
        # IME Support (Asian language input)
        ime_refs = [line for line in strings.split('\n') if 'imm' in line.lower()]
        if ime_refs:
            md += "### Input Method Editor (IME) Support\n\n"
            md += "**Purpose:** Asian language input support for international players\n"
            md += f"**APIs:** {len(ime_refs)} IME-related functions\n\n"
    
    return md

def document_anti_analysis(reports: Dict) -> str:
    """Document anti-debugging and anti-cheat"""
    
    md = "## Anti-Analysis & Protection\n\n"
    
    if 'mcp-analysis.report' in reports:
        imports = reports['mcp-analysis.report'].get('calls', {}).get('list_imports', {}).get('text', '')
        
        # Anti-debugging
        if 'IsDebuggerPresent' in imports:
            md += "### Anti-Debugging\n\n"
            md += "- **API:** `IsDebuggerPresent` - Detects attached debuggers\n"
            md += "- **API:** `SetUnhandledExceptionFilter` / `UnhandledExceptionFilter` - Custom exception handling\n\n"
        
        # Process enumeration (potential anti-cheat)
        if 'CreateToolhelp32Snapshot' in imports:
            md += "### Process Monitoring\n\n"
            md += "**Toolhelp32 APIs:**\n"
            md += "- `CreateToolhelp32Snapshot` - Take system snapshot\n"
            md += "- `Module32First` / `Module32Next` - Enumerate loaded modules\n"
            md += "- `Thread32First` / `Thread32Next` - Enumerate threads\n\n"
            md += "**Purpose:** Likely monitors for external tools (bots, memory editors, debuggers)\n\n"
    
    md += "### Exception Handlers\n\n"
    if 'function-analysis' in reports:
        func_analysis = reports['function-analysis']
        handlers = [f for f in func_analysis.get('decompilation_priority_list', []) 
                   if 'exception' in f.get('category', '').lower()]
        md += f"**Total Exception Handlers:** {len(handlers)}\n"
        md += "**Architecture:** C++/SEH try-catch blocks protecting critical game logic\n\n"
    
    return md

def document_memory_management(reports: Dict) -> str:
    """Document memory allocation and management"""
    
    md = "## Memory Management\n\n"
    
    if 'mcp-analysis.report' in reports:
        imports = reports['mcp-analysis.report'].get('calls', {}).get('list_imports', {}).get('text', '')
        
        md += "### Memory APIs\n\n"
        
        heap_apis = [line for line in imports.split('\n') if 'heap' in line.lower()]
        if heap_apis:
            md += "**Heap Management:**\n"
            for api in heap_apis[:10]:
                md += f"- {api.strip()}\n"
            md += "\n"
        
        virtual_apis = [line for line in imports.split('\n') if 'virtual' in line.lower()]
        if virtual_apis:
            md += "**Virtual Memory:**\n"
            for api in virtual_apis[:10]:
                md += f"- {api.strip()}\n"
            md += "\n"
    
    md += "**Architecture:**\n"
    md += "- Custom memory pools via `HeapCreate` / `HeapAlloc` / `HeapReAlloc`\n"
    md += "- Large allocations via `VirtualAlloc` for assets\n"
    md += "- Memory usage monitoring via `HeapSize` and `GlobalMemoryStatus`\n\n"
    
    return md

def document_function_locations(reports: Dict) -> str:
    """Document important function addresses"""
    
    md = "## Key Function Addresses\n\n"
    
    if 'mcp-analysis.report' in reports:
        functions = reports['mcp-analysis.report'].get('calls', {}).get('list_functions', {}).get('text', '')
        
        md += "### Entry Points\n\n"
        md += "| Function | Address | Purpose |\n"
        md += "|----------|---------|----------|\n"
        md += "| `entry` | `0x00401000` | Program entry point |\n"
        md += "| `FUN_00401010` | `0x00401010` | Likely WinMain or game initialization |\n\n"
        
        md += "### System Integration\n\n"
        md += "| Function | Address | Purpose |\n"
        md += "|----------|---------|----------|\n"
        md += "| `Module32First` | `0x008A1310` | System module enumeration |\n"
        md += "| `CreateToolhelp32Snapshot` | `0x008A131C` | Process/thread snapshot |\n"
        md += "| `HidD_FreePreparsedData` | `0x009C5056` | HID device cleanup |\n\n"
        
        md += "### Unknown/Game Functions (Require Analysis)\n\n"
        md += "| Address | Initial Name | Notes |\n"
        md += "|---------|--------------|-------|\n"
        md += "| `0x004133C7` | `FUN_004133c7` | Called from entry thunk |\n"
        md += "| `0x0047CC90` | `FUN_0047cc90` | Unknown subsystem |\n"
        md += "| `0x0088B010` | `FUN_0088b010` | Unknown subsystem |\n\n"
    
    return md

def document_next_steps(reports: Dict) -> str:
    """Document recommended next steps for analysis"""
    
    md = "## Recommended Next Steps\n\n"
    md += "### Immediate Priorities\n\n"
    
    md += "1. **Network Protocol Analysis**\n"
    md += "   - Decompile functions calling `WSAEnumNetworkEvents`\n"
    md += "   - Trace packet dispatch logic from network receive to game state\n"
    md += "   - Map opcodes to handlers using TrinityCore 3.3.5a as reference\n"
    md += "   - Document packet structures\n\n"
    
    md += "2. **Entry Point Deep Dive**\n"
    md += "   - Fully decompile `entry` @ 0x00401000\n"
    md += "   - Trace initialization sequence through `FUN_00401010`\n"
    md += "   - Map global object constructors\n"
    md += "   - Identify singleton patterns\n\n"
    
    md += "3. **Class Hierarchy Reconstruction**\n"
    md += "   - Analyze vtable regions to reconstruct C++ classes\n"
    md += "   - Use struct recovery on this pointer usage patterns\n"
    md += "   - Name classes based on methods they call\n"
    md += "   - Correlate with TrinityCore/AzerothCore class names\n\n"
    
    md += "4. **String-Guided Analysis**\n"
    md += "   - Find xrefs to \"Realm:\" strings → authentication/server logic\n"
    md += "   - Find xrefs to \"movement\" strings → player movement handlers\n"
    md += "   - Find xrefs to error messages → exception paths\n\n"
    
    md += "5. **Dynamic Analysis**\n"
    md += "   - Set up packet capture with WowPacketParser on live connection\n"
    md += "   - Use frida/x64dbg to hook WSA* functions and log traffic\n"
    md += "   - Correlate live packets with decompiled handlers\n"
    md += "   - Build action→packet→memory mutation traces\n\n"
    
    md += "### Tools & Resources\n\n"
    md += "- **TrinityCore 3.3.5a Branch:** Reference implementation for opcodes/structures\n"
    md += "- **WowPacketParser:** Parse captured .pkt files into SQL/text\n"
    md += "- **IDA Pro/Ghidra:** Continue deep analysis with debugger integration\n"
    md += "- **Frida:** Dynamic instrumentation for runtime hooking\n\n"
    
    return md

def generate_master_doc() -> str:
    """Generate complete master documentation"""
    
    print("[*] Loading existing reports...")
    reports = load_existing_reports()
    print(f"[+] Loaded {len(reports)} reports\n")
    
    print("[*] Generating master documentation...\n")
    
    doc = ""
    doc += generate_executive_summary(reports)
    doc += "\n---\n\n"
    doc += document_network_architecture(reports)
    doc += "\n---\n\n"
    doc += document_rendering_system(reports)
    doc += "\n---\n\n"
    doc += document_game_systems(reports)
    doc += "\n---\n\n"
    doc += document_anti_analysis(reports)
    doc += "\n---\n\n"
    doc += document_memory_management(reports)
    doc += "\n---\n\n"
    doc += document_function_locations(reports)
    doc += "\n---\n\n"
    doc += document_next_steps(reports)
    
    return doc

def main():
    print("=" * 80)
    print("MASTER DOCUMENTATION GENERATOR")
    print("=" * 80)
    print()
    
    try:
        # Generate master doc
        master_doc = generate_master_doc()
        
        # Save to file
        output_path = REPORTS_DIR / "MASTER_DOCUMENTATION.md"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(master_doc)
        
        print(f"\n[+] Master documentation saved to: {output_path}")
        print(f"[+] Document size: {len(master_doc)} characters")
        
        # Also create a summary
        summary_path = REPORTS_DIR / "ANALYSIS_SUMMARY.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("ASCENSION.EXE REVERSE ENGINEERING - QUICK SUMMARY\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Total Reports Analyzed: {len(load_existing_reports())}\n")
            f.write(f"Master Documentation: {output_path}\n")
            f.write(f"\nKey Findings:\n")
            f.write("- Binary: x86 32-bit WoW 3.3.5a client\n")
            f.write("- Rendering: OpenGL (NOT Direct3D)\n")
            f.write("- Networking: Async WinSocket + WinInet\n")
            f.write("- Protection: Anti-debug, process monitoring, exception handlers\n")
            f.write("- Architecture: Component-based C++ game engine\n")
            f.write("\nSee MASTER_DOCUMENTATION.md for complete analysis.\n")
        
        print(f"[+] Analysis summary saved to: {summary_path}")
        
        return 0
    
    except Exception as e:
        print(f"\n[!] Error generating documentation: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())
