#!/usr/bin/env python3
"""
Deep Function Correlator - Correlate functions with strings, imports, and xrefs
to understand what each function does
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

def load_all_data():
    """Load all available analysis data"""
    
    data = {}
    
    # Load MCP report
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        mcp_report = json.load(f)
        data['functions'] = mcp_report.get('calls', {}).get('list_functions', {}).get('text', '')
        data['imports'] = mcp_report.get('calls', {}).get('list_imports', {}).get('text', '')
        data['strings'] = mcp_report.get('calls', {}).get('list_strings', {}).get('text', '')
    
    # Load function analysis
    with open(REPORTS_DIR / "function-analysis.json", 'r') as f:
        data['func_analysis'] = json.load(f)
    
    # Load xref analysis
    with open(REPORTS_DIR / "xref-analysis.json", 'r') as f:
        data['xref_analysis'] = json.load(f)
    
    # Load structural analysis
    with open(REPORTS_DIR / "structural-analysis.json", 'r') as f:
        data['structural'] = json.load(f)
    
    return data

def parse_functions(functions_text: str):
    """Parse function list into structured data"""
    
    functions = []
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            functions.append({
                "name": name,
                "address": f"0x{addr}",
                "params": int(params),
                "raw_line": line.strip()
            })
    
    return functions

def parse_imports(imports_text: str):
    """Parse imports into structured data with DLL mapping"""
    
    imports_by_dll = defaultdict(list)
    all_imports = []
    
    for line in imports_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+from\s+(.+?)\s+@\s+EXTERNAL:([0-9a-fA-F]+)', line)
        if match:
            func_name, dll_name, external_addr = match.groups()
            import_entry = {
                "function": func_name,
                "dll": dll_name,
                "external_address": f"EXTERNAL:0x{external_addr}"
            }
            imports_by_dll[dll_name].append(import_entry)
            all_imports.append(import_entry)
    
    return dict(imports_by_dll), all_imports

def categorize_functions(functions: list, imports_by_dll: dict):
    """Categorize functions by apparent purpose"""
    
    categories = defaultdict(list)
    
    # Known system functions from imports
    system_funcs = set()
    for dll, funcs in imports_by_dll.items():
        system_funcs.update([f['function'] for f in funcs])
    
    for func in functions:
        name = func['name']
        
        # System imports
        if name in system_funcs:
            categories['system_imports'].append(func)
        
        # Exception handling
        elif 'Catch_All' in name:
            categories['exception_handlers'].append(func)
        
        # Unwind/cleanup
        elif 'Unwind@' in name:
            categories['unwind_handlers'].append(func)
        
        # Thunks
        elif 'thunk_' in name:
            categories['thunks'].append(func)
        
        # Entry point
        elif 'entry' in name.lower():
            categories['entry_points'].append(func)
        
        # Unknown functions (likely game code)
        elif name.startswith('FUN_'):
            categories['unknown_game_code'].append(func)
        
        # Named functions
        else:
            categories['named_functions'].append(func)
    
    return dict(categories)

def map_network_subsystem(data):
    """Map the complete network subsystem"""
    
    imports_by_dll, _ = parse_imports(data['imports'])
    
    network_api_categories = {
        'winsock': [],
        'wininet': [],
        'async_io': []
    }
    
    # Categorize network APIs
    for dll in ['WS2_32.dll', 'WININET.dll', 'KERNEL32.DLL']:
        if dll in imports_by_dll:
            for imp in imports_by_dll[dll]:
                func = imp['function']
                
                if any(kw in func for kw in ['WSA', 'socket', 'recv', 'send']):
                    network_api_categories['winsock'].append(func)
                elif any(kw in func for kw in ['Internet', 'Http']):
                    network_api_categories['wininet'].append(func)
                elif any(kw in func for kw in ['IoCompletion', 'Overlapped', 'WaitFor']):
                    network_api_categories['async_io'].append(func)
    
    return network_api_categories

def map_rendering_subsystem(data):
    """Map the complete rendering subsystem"""
    
    imports_by_dll, _ = parse_imports(data['imports'])
    
    rendering_apis = {
        'opengl_core': [],
        'opengl_setup': [],
        'opengl_textures': [],
        'opengl_rendering': [],
        'opengl_state': []
    }
    
    if 'OPENGL32.dll' in imports_by_dll:
        for imp in imports_by_dll['OPENGL32.dll']:
            func = imp['function']
            
            if any(kw in func for kw in ['wgl', 'GetProcAddress', 'Context']):
                rendering_apis['opengl_setup'].append(func)
            elif any(kw in func for kw in ['Texture', 'glBind', 'glGen', 'glDelete']):
                rendering_apis['opengl_textures'].append(func)
            elif any(kw in func for kw in ['Draw', 'Vertex', 'Color', 'Normal', 'TexCoord', 'glClear']):
                rendering_apis['opengl_rendering'].append(func)
            elif any(kw in func for kw in ['Enable', 'Disable', 'Get', 'Set', 'Viewport', 'Matrix']):
                rendering_apis['opengl_state'].append(func)
            else:
                rendering_apis['opengl_core'].append(func)
    
    return rendering_apis

def generate_subsystem_map():
    """Generate complete subsystem mapping documentation"""
    
    print("[*] Loading all analysis data...")
    data = load_all_data()
    
    print("[*] Parsing functions...")
    functions = parse_functions(data['functions'])
    print(f"[+] Parsed {len(functions)} functions")
    
    print("[*] Parsing imports...")
    imports_by_dll, all_imports = parse_imports(data['imports'])
    print(f"[+] Parsed {len(all_imports)} imports from {len(imports_by_dll)} DLLs")
    
    print("[*] Categorizing functions...")
    func_categories = categorize_functions(functions, imports_by_dll)
    for category, funcs in func_categories.items():
        print(f"  {category:25s}: {len(funcs):4d} functions")
    
    print("\n[*] Mapping network subsystem...")
    network_map = map_network_subsystem(data)
    
    print("[*] Mapping rendering subsystem...")
    rendering_map = map_rendering_subsystem(data)
    
    # Generate comprehensive report
    report = {
        "total_functions": len(functions),
        "total_imports": len(all_imports),
        "function_categories": {k: len(v) for k, v in func_categories.items()},
        "detailed_categories": func_categories,
        "imports_by_dll": {dll: len(funcs) for dll, funcs in imports_by_dll.items()},
        "network_subsystem": network_map,
        "rendering_subsystem": rendering_map
    }
    
    output_path = REPORTS_DIR / "SUBSYSTEM_MAPPING.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Report saved to: {output_path}")
    
    # Generate markdown documentation
    md = "# SUBSYSTEM MAPPING - Ascension.exe\n\n"
    md += f"**Total Functions:** {len(functions)}\n"
    md += f"**Total Imports:** {len(all_imports)}\n"
    md += f"**DLLs Imported:** {len(imports_by_dll)}\n\n"
    
    md += "## Function Distribution\n\n"
    md += "| Category | Count | %% of Total |\n"
    md += "|----------|------:|----------:|\n"
    for category, funcs in sorted(func_categories.items(), key=lambda x: len(x[1]), reverse=True):
        pct = (len(funcs) / len(functions)) * 100
        md += f"| {category} | {len(funcs)} | {pct:.1f}% |\n"
    
    md += "\n## Network Subsystem\n\n"
    md += "### WinSocket APIs\n\n"
    for api in network_map['winsock']:
        md += f"- `{api}`\n"
    
    md += "\n### WinInet APIs\n\n"
    for api in network_map['wininet']:
        md += f"- `{api}`\n"
    
    md += "\n### Async I/O APIs\n\n"
    for api in network_map['async_io']:
        md += f"- `{api}`\n"
    
    md += "\n## Rendering Subsystem\n\n"
    
    for subsys, apis in rendering_map.items():
        if apis:
            md += f"### {subsys.replace('_', ' ').title()}\n\n"
            for api in apis[:30]:  # Limit to 30 per category
                md += f"- `{api}`\n"
            md += "\n"
    
    md += "\n## Unknown Game Functions (Require Decompilation)\n\n"
    md += "These functions likely contain core game logic:\n\n"
    md += "| Address | Name | Parameters |\n"
    md += "|---------|------|------------|\n"
    for func in func_categories.get('unknown_game_code', []):
        md += f"| {func['address']} | `{func['name']}` | {func['params']} |\n"
    
    md += "\n## Entry Points & Initialization\n\n"
    md += "| Address | Name | Parameters |\n"
    md += "|---------|------|------------|\n"
    for func in func_categories.get('entry_points', []):
        md += f"| {func['address']} | `{func['name']}` | {func['params']} |\n"
    
    md += "\n## Named Non-System Functions\n\n"
    md += "| Address | Name | Parameters |\n"
    md += "|---------|------|------------|\n"
    for func in func_categories.get('named_functions', [])[:30]:  # Show first 30
        md += f"| {func['address']} | `{func['name']}` | {func['params']} |\n"
    
    md_path = REPORTS_DIR / "SUBSYSTEM_MAPPING.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    
    print(f"[+] Markdown documentation saved to: {md_path}")
    
    return report

def main():
    print("=" * 80)
    print("DEEP FUNCTION CORRELATOR & SUBSYSTEM MAPPER")
    print("=" * 80)
    print()
    
    try:
        report = generate_subsystem_map()
        
        print("\n" + "=" * 80)
        print("KEY INSIGHTS")
        print("=" * 80)
        print(f"\nUnknown game functions: {report['function_categories'].get('unknown_game_code', 0)}")
        print(f"Exception handlers: {report['function_categories'].get('exception_handlers', 0)}")
        print(f"Network APIs: {sum(len(v) for v in report['network_subsystem'].values())}")
        print(f"Rendering APIs: {sum(len(v) for v in report['rendering_subsystem'].values())}")
        
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
