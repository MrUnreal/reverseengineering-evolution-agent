#!/usr/bin/env python3
"""
VTable Extractor - Extract and document all virtual tables from cached reports
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

def load_analysis_data():
    """Load structural analysis with vtable data"""
    
    with open(REPORTS_DIR / "structural-analysis.json", 'r') as f:
        return json.load(f)

def analyze_vtables(data):
    """Analyze all discovered vtables"""
    
    vtables = data.get('vtables', [])
    
    vtable_analysis = {
        "total_vtables": len(vtables),
        "vtables": []
    }
    
    for i, vt in enumerate(vtables, 1):
        addr = vt.get('address', 'UNKNOWN')
        desc = vt.get('description', '')
        
        # Try to infer class purpose from address patterns
        addr_val = int(addr.replace('0x', ''), 16) if addr.startswith('0x') else 0
        
        # Group by address ranges
        region = "unknown"
        if 0x400000 <= addr_val < 0x600000:
            region = ".text (code)"
        elif 0x600000 <= addr_val < 0x800000:
            region = ".rdata (readonly)"
        elif 0x800000 <= addr_val < 0xa00000:
            region = ".data"
        elif 0xa00000 <= addr_val < 0xc00000:
            region = ".rsrc (resources)"
        
        vtable_entry = {
            "id": i,
            "address": addr,
            "description": desc,
            "region": region,
            "likely_methods": []
        }
        
        vtable_analysis['vtables'].append(vtable_entry)
    
    return vtable_analysis

def correlate_with_functions(vtable_analysis, mcp_data):
    """Correlate vtable addresses with nearby functions"""
    
    # Parse function addresses from MCP report
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        mcp_report = json.load(f)
        functions_text = mcp_report.get('calls', {}).get('list_functions', {}).get('text', '')
    
    function_addrs = []
    for line in functions_text.split('\n'):
        match = re.match(r'^\s*-\s+(.+?)\s+@\s+([0-9a-fA-F]+)\s+\((\d+)\s+params\)', line)
        if match:
            name, addr, params = match.groups()
            function_addrs.append({
                "name": name,
                "address": int(addr, 16),
                "params": int(params)
            })
    
    # For each vtable, find functions within +/- 0x1000 bytes
    for vt in vtable_analysis['vtables']:
        vt_addr_str = vt['address']
        if not vt_addr_str.startswith('0x'):
            continue
        
        vt_addr = int(vt_addr_str.replace('0x', ''), 16)
        
        nearby_funcs = []
        for func in function_addrs:
            distance = abs(func['address'] - vt_addr)
            if distance < 0x2000:  # Within 8KB
                nearby_funcs.append({
                    "name": func['name'],
                    "address": f"0x{func['address']:08X}",
                    "params": func['params'],
                    "distance_bytes": distance
                })
        
        vt['likely_methods'] = sorted(nearby_funcs, key=lambda x: x['distance_bytes'])[:10]
    
    return vtable_analysis

def generate_report():
    """Generate comprehensive vtable report"""
    
    print("[*] Loading structural analysis...")
    data = load_analysis_data()
    
    print("[*] Analyzing vtables...")
    vtable_analysis = analyze_vtables(data)
    print(f"[+] Found {vtable_analysis['total_vtables']} vtables")
    
    print("[*] Correlating with functions...")
    with open(REPORTS_DIR / "mcp-analysis.report.json", 'r') as f:
        mcp_data = json.load(f)
    
    vtable_analysis = correlate_with_functions(vtable_analysis, mcp_data)
    
    # Save JSON report
    output_path = REPORTS_DIR / "VTABLE_ANALYSIS.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(vtable_analysis, f, indent=2)
    
    print(f"[+] JSON report saved to: {output_path}")
    
    # Generate markdown documentation
    md = "# VIRTUAL TABLE ANALYSIS - Ascension.exe\n\n"
    md += f"**Total VTables Discovered:** {vtable_analysis['total_vtables']}\n\n"
    
    md += "## VTable Regions\n\n"
    
    # Group by region
    by_region = defaultdict(list)
    for vt in vtable_analysis['vtables']:
        by_region[vt['region']].append(vt)
    
    md += "| Region | Count |\n"
    md += "|--------|------:|\n"
    for region, vts in sorted(by_region.items()):
        md += f"| {region} | {len(vts)} |\n"
    
    md += "\n## Detailed VTable Analysis\n\n"
    
    for vt in vtable_analysis['vtables']:
        md += f"### VTable #{vt['id']} - {vt['address']}\n\n"
        md += f"**Region:** {vt['region']}\n\n"
        
        if vt['description']:
            md += f"**Description:** {vt['description']}\n\n"
        
        if vt['likely_methods']:
            md += "**Nearby Functions (Potential Methods):**\n\n"
            md += "| Function | Address | Params | Distance |\n"
            md += "|----------|---------|-------:|---------:|\n"
            for func in vt['likely_methods']:
                md += f"| `{func['name']}` | {func['address']} | {func['params']} | {func['distance_bytes']} bytes |\n"
        else:
            md += "*No functions found within 8KB range*\n"
        
        md += "\n"
    
    md += "## Analysis Notes\n\n"
    md += "- VTables in `.text` region likely contain function pointers\n"
    md += "- VTables in `.rdata` region are const virtual tables (typical C++ layout)\n"
    md += "- VTables in `.data` region may be dynamically modified or plugin interfaces\n"
    md += "- Distance from vtable address to function indicates likelihood of association\n"
    md += "- Functions within 0x100 bytes are very likely class methods\n"
    md += "- Functions 0x100-0x1000 bytes away may be related or in same compilation unit\n"
    
    md_path = REPORTS_DIR / "VTABLE_ANALYSIS.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    
    print(f"[+] Markdown documentation saved to: {md_path}")
    
    return vtable_analysis

def main():
    print("=" * 80)
    print("VTABLE EXTRACTOR & ANALYZER")
    print("=" * 80)
    print()
    
    try:
        report = generate_report()
        
        print("\n" + "=" * 80)
        print("KEY INSIGHTS")
        print("=" * 80)
        print(f"\nTotal VTables: {report['total_vtables']}")
        
        # Count vtables with nearby methods
        with_methods = sum(1 for vt in report['vtables'] if vt['likely_methods'])
        print(f"VTables with nearby functions: {with_methods}/{report['total_vtables']}")
        
        # Show closest associations
        print("\nClosest Function Associations:")
        for vt in report['vtables'][:5]:
            if vt['likely_methods']:
                closest = vt['likely_methods'][0]
                print(f"  VTable {vt['address']}: {closest['name']} @ {closest['distance_bytes']} bytes")
        
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
