#!/usr/bin/env python3
"""
Comprehensive Address Index Generator
Creates a complete address-to-name-to-purpose mapping
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

def load_all_reports():
    """Load all available reports"""
    reports = {}
    
    # MCP report
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        reports['mcp'] = json.load(f)
    
    # Critical functions
    with open(REPORTS_DIR / "CRITICAL_FUNCTIONS.json", 'r') as f:
        reports['critical'] = json.load(f)
    
    # Subsystem mapping
    with open(REPORTS_DIR / "SUBSYSTEM_MAPPING.json", 'r') as f:
        reports['subsystem'] = json.load(f)
    
    # String extraction
    with open(REPORTS_DIR / "STRING_EXTRACTION_DETAILED.json", 'r') as f:
        reports['strings'] = json.load(f)
    
    return reports

def parse_all_functions(mcp_report):
    """Parse all functions into address index"""
    functions_text = mcp_report.get('calls', {}).get('list_functions', {}).get('text', '')
    
    functions = {}
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            addr_str = f"0x{addr}"
            functions[addr_str] = {
                "name": name,
                "address": addr_str,
                "params": int(params),
                "type": "function"
            }
    
    return functions

def parse_all_imports(mcp_report):
    """Parse all imports into address index"""
    imports_text = mcp_report.get('calls', {}).get('list_imports', {}).get('text', '')
    
    imports = {}
    for line in imports_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+from\s+(.+?)\s+@\s+EXTERNAL:([0-9a-fA-F]+)', line)
        if match:
            func_name, dll_name, external_addr = match.groups()
            addr_str = f"EXTERNAL:0x{external_addr}"
            imports[addr_str] = {
                "name": func_name,
                "address": addr_str,
                "dll": dll_name,
                "type": "import"
            }
    
    return imports

def parse_all_strings(strings_report):
    """Parse all strings into address index"""
    strings_index = {}
    
    for category, string_list in strings_report.get('categories', {}).items():
        for string_entry in string_list:
            addr = string_entry.get('address', '')
            if addr:
                strings_index[addr] = {
                    "address": addr,
                    "value": string_entry.get('value', ''),
                    "length": string_entry.get('length', 0),
                    "category": category,
                    "type": "string"
                }
    
    return strings_index

def categorize_by_purpose(address, name, entry_type):
    """Determine purpose/subsystem for each address"""
    
    purposes = []
    
    # System/DLL
    if entry_type == "import":
        dll = name.lower()
        if 'kernel' in dll or 'ntdll' in dll:
            purposes.append("system")
        if 'ws2' in dll or 'wininet' in dll:
            purposes.append("network")
        if 'opengl' in dll or 'gdi' in dll:
            purposes.append("rendering")
        if 'imm' in dll or 'user32' in dll:
            purposes.append("input")
    
    # Functions
    if entry_type == "function":
        if name in ['entry']:
            purposes.append("initialization")
        elif 'Module32' in name or 'Thread32' in name:
            purposes.append("anti_cheat")
        elif 'Catch_All' in name:
            purposes.append("exception_handling")
        elif 'Unwind' in name:
            purposes.append("stack_unwinding")
        elif name.startswith('FUN_'):
            purposes.append("game_logic")
        elif 'Assert' in name or 'Crash' in name:
            purposes.append("error_handling")
        elif 'HidD_' in name:
            purposes.append("input")
    
    # Strings
    if entry_type == "string":
        purposes.append("data")
    
    # Address-based inference
    if isinstance(address, str) and address.startswith('0x'):
        try:
            addr_val = int(address.replace('0x', ''), 16)
            if 0x400000 <= addr_val < 0x600000:
                purposes.append(".text")
            elif 0x600000 <= addr_val < 0x800000:
                purposes.append(".rdata")
            elif 0x800000 <= addr_val < 0xa00000:
                purposes.append(".data")
        except:
            pass
    
    return purposes if purposes else ["unknown"]

def generate_index():
    """Generate comprehensive address index"""
    
    print("[*] Loading all reports...")
    reports = load_all_reports()
    
    print("[*] Parsing functions...")
    functions = parse_all_functions(reports['mcp'])
    print(f"[+] Indexed {len(functions)} functions")
    
    print("[*] Parsing imports...")
    imports = parse_all_imports(reports['mcp'])
    print(f"[+] Indexed {len(imports)} imports")
    
    print("[*] Parsing strings...")
    strings = parse_all_strings(reports['strings'])
    print(f"[+] Indexed {len(strings)} strings")
    
    # Merge all into comprehensive index
    print("[*] Building comprehensive index...")
    comprehensive_index = {}
    
    # Add functions
    for addr, func in functions.items():
        purposes = categorize_by_purpose(addr, func['name'], 'function')
        comprehensive_index[addr] = {
            **func,
            "purposes": purposes
        }
    
    # Add imports
    for addr, imp in imports.items():
        purposes = categorize_by_purpose(addr, imp['dll'], 'import')
        comprehensive_index[addr] = {
            **imp,
            "purposes": purposes
        }
    
    # Add strings
    for addr, string in strings.items():
        purposes = categorize_by_purpose(addr, string['category'], 'string')
        comprehensive_index[addr] = {
            **string,
            "purposes": purposes
        }
    
    print(f"[+] Total indexed entries: {len(comprehensive_index)}")
    
    # Generate statistics
    by_type = defaultdict(int)
    by_purpose = defaultdict(int)
    
    for entry in comprehensive_index.values():
        by_type[entry['type']] += 1
        for purpose in entry.get('purposes', []):
            by_purpose[purpose] += 1
    
    statistics = {
        "total_entries": len(comprehensive_index),
        "by_type": dict(by_type),
        "by_purpose": dict(by_purpose)
    }
    
    # Save JSON index
    output = {
        "statistics": statistics,
        "index": comprehensive_index
    }
    
    output_path = REPORTS_DIR / "ADDRESS_INDEX.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    print(f"[+] JSON index saved to: {output_path}")
    
    # Generate searchable markdown
    md = "# COMPREHENSIVE ADDRESS INDEX - Ascension.exe\n\n"
    md += "## Statistics\n\n"
    md += f"**Total Entries:** {statistics['total_entries']}\n\n"
    
    md += "### By Type\n\n"
    md += "| Type | Count |\n"
    md += "|------|------:|\n"
    for type_name, count in sorted(by_type.items()):
        md += f"| {type_name} | {count} |\n"
    
    md += "\n### By Purpose\n\n"
    md += "| Purpose | Count |\n"
    md += "|---------|------:|\n"
    for purpose, count in sorted(by_purpose.items(), key=lambda x: x[1], reverse=True):
        md += f"| {purpose} | {count} |\n"
    
    md += "\n## Complete Index\n\n"
    
    # Group by purpose for readability
    by_purpose_grouped = defaultdict(list)
    for addr, entry in comprehensive_index.items():
        for purpose in entry.get('purposes', ['unknown']):
            by_purpose_grouped[purpose].append((addr, entry))
    
    for purpose in sorted(by_purpose_grouped.keys()):
        entries = by_purpose_grouped[purpose]
        md += f"### {purpose.replace('_', ' ').title()} ({len(entries)} entries)\n\n"
        
        md += "| Address | Name | Type | Details |\n"
        md += "|---------|------|------|--------|\n"
        
        for addr, entry in sorted(entries, key=lambda x: x[0])[:50]:  # Limit to 50 per category
            name = entry.get('name', entry.get('value', ''))[:40]
            entry_type = entry.get('type', 'unknown')
            
            details = ""
            if entry_type == "function":
                details = f"{entry.get('params', 0)} params"
            elif entry_type == "import":
                details = entry.get('dll', '')
            elif entry_type == "string":
                details = f"{entry.get('length', 0)} chars"
            
            md += f"| `{addr}` | {name} | {entry_type} | {details} |\n"
        
        if len(entries) > 50:
            md += f"\n*... and {len(entries) - 50} more entries*\n"
        
        md += "\n"
    
    md_path = REPORTS_DIR / "ADDRESS_INDEX.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"[+] Markdown index saved to: {md_path}")
    
    return output

def main():
    print("=" * 80)
    print("COMPREHENSIVE ADDRESS INDEX GENERATOR")
    print("=" * 80)
    print()
    
    try:
        result = generate_index()
        
        print("\n" + "=" * 80)
        print("KEY INSIGHTS")
        print("=" * 80)
        
        stats = result['statistics']
        print(f"\nTotal Addressable Entries: {stats['total_entries']}")
        print(f"  Functions: {stats['by_type'].get('function', 0)}")
        print(f"  Imports: {stats['by_type'].get('import', 0)}")
        print(f"  Strings: {stats['by_type'].get('string', 0)}")
        
        print("\nTop Purposes:")
        for purpose, count in sorted(stats['by_purpose'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {purpose:20s}: {count}")
        
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
