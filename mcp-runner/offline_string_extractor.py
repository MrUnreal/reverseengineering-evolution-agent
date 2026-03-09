#!/usr/bin/env python3
"""
Offline String Extractor - Extract all strings from existing reports
and categorize them for game-specific analysis
"""

import json
import re
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

def extract_strings_from_report():
    """Extract strings from MCP analysis report"""
    
    report_path = REPORTS_DIR / "mcp-analysis.report.json"
    with open(report_path, 'r') as f:
        report = json.load(f)
    
    strings_text = report.get('calls', {}).get('list_strings', {}).get('text', '')
    
    return strings_text

def categorize_all_strings(strings_text: str):
    """Categorize strings by game system"""
    
    categories = defaultdict(list)
    
    for line in strings_text.split('\n'):
        match = re.match(r'@\s+([0-9a-fA-F]+)\s+\((\d+)\s+chars\):\s+"(.+)"', line)
        if not match:
            continue
        
        addr, length, content = match.groups()
        entry = {
            "address": f"0x{addr}",
            "length": int(length),
            "content": content
        }
        
        content_lower = content.lower()
        
        # File extensions and paths
        if re.search(r'\.(mpq|dbc|adt|wmo|m2|blp|lua|toc|xml|txt|log|ini|cfg)', content_lower):
            categories['game_files'].append(entry)
        
        # WoW-specific terms
        if re.search(r'(spell|aura|buff|debuff|cast|channel|talent|skill)', content_lower):
            categories['spell_system'].append(entry)
        
        if re.search(r'(quest|npc|creature|gossip|dialog)', content_lower):
            categories['quest_system'].append(entry)
        
        if re.search(r'(movement|position|teleport|coord|waypoint|path)', content_lower):
            categories['movement'].append(entry)
        
        if re.search(r'(realm|server|login|auth|session|connection)', content_lower):
            categories['network'].append(entry)
        
        if re.search(r'(packet|opcode|msg_|cmsg|smsg|handler)', content_lower):
            categories['protocol'].append(entry)
        
        if re.search(r'(guild|raid|party|group|arena|battleground)', content_lower):
            categories['social'].append(entry)
        
        if re.search(r'(item|equip|inventory|bag|loot|vendor)', content_lower):
            categories['items'].append(entry)
        
        if re.search(r'(combat|attack|damage|heal|threat|aggro)', content_lower):
            categories['combat'].append(entry)
        
        if re.search(r'(ui|frame|button|window|addon|interface)', content_lower):
            categories['ui'].append(entry)
        
        if re.search(r'(error|fail|warn|exception|crash|assert)', content_lower):
            categories['errors'].append(entry)
        
        if re.search(r'(debug|log|trace|print|console)', content_lower):
            categories['debug'].append(entry)
        
        # DLL imports (special category)
        if content.endswith('.dll') or content.endswith('.DLL'):
            categories['dlls'].append(entry)
        
        # OpenGL/rendering
        if content.startswith('gl') or content.startswith('wgl'):
            categories['opengl'].append(entry)
        
        # Windows APIs
        if re.search(r'^(Get|Set|Create|Delete|Load|Free|Read|Write)', content):
            categories['windows_apis'].append(entry)
    
    return dict(categories)

def find_game_specific_patterns(strings_text: str):
    """Find very specific WoW/game patterns"""
    
    findings = {
        "realm_references": [],
        "map_zone_references": [],
        "file_paths": [],
        "urls_domains": [],
        "version_info": []
    }
    
    for line in strings_text.split('\n'):
        match = re.match(r'@\s+([0-9a-fA-F]+)\s+\((\d+)\s+chars\):\s+"(.+)"', line)
        if not match:
            continue
        
        addr, length, content = match.groups()
        
        # Realm-related
        if 'realm' in content.lower():
            findings["realm_references"].append({"addr": f"0x{addr}", "content": content})
        
        # File paths with backslashes or forward slashes
        if '\\' in content or ('/' in content and '.' in content):
            findings["file_paths"].append({"addr": f"0x{addr}", "content": content})
        
        # URLs or domains
        if re.search(r'(https?://|www\.|\.com|\.net|\.org)', content.lower()):
            findings["urls_domains"].append({"addr": f"0x{addr}", "content": content})
        
        # Version/build info
        if re.search(r'(version|build|\d+\.\d+\.\d+|patch|release)', content.lower()):
            findings["version_info"].append({"addr": f"0x{addr}", "content": content})
        
        # Map/zone mentions
        if re.search(r'(map|zone|area|instance|dungeon)', content.lower()):
            findings["map_zone_references"].append({"addr": f"0x{addr}", "content": content})
    
    return findings

def main():
    print("=" * 80)
    print("OFFLINE STRING EXTRACTOR & ANALYZER")
    print("=" * 80)
    print()
    
    # Extract strings
    print("[*] Extracting strings from analysis report...")
    strings_text = extract_strings_from_report()
    total_strings = len([l for l in strings_text.split('\n') if l.strip().startswith('@')])
    print(f"[+] Extracted {total_strings} strings\n")
    
    # Categorize
    print("[*] Categorizing strings by game system...")
    categories = categorize_all_strings(strings_text)
    
    print("\n[*] String Categories:")
    for category, items in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {category:20s}: {len(items):4d} strings")
    
    # Find specific patterns
    print("\n[*] Finding game-specific patterns...")
    patterns = find_game_specific_patterns(strings_text)
    for pattern_type, items in patterns.items():
        if items:
            print(f"  {pattern_type}: {len(items)} found")
    
    # Save detailed report
    output = {
        "total_strings": total_strings,
        "categories": categories,
        "specific_patterns": patterns
    }
    
    output_path = REPORTS_DIR / "STRING_EXTRACTION_DETAILED.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n[+] Detailed report saved to: {output_path}")
    
    # Create markdown documentation
    md = "# STRING ANALYSIS - Ascension.exe\n\n"
    md += f"**Total Strings:** {total_strings}\n\n"
    
    md += "## String Categories\n\n"
    md += "| Category | Count | Key Examples |\n"
    md += "|----------|-------|-------------|\n"
    
    for category, items in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
        examples = ', '.join([f"`{item['content'][:30]}`" for item in items[:3]])
        md += f"| {category} | {len(items)} | {examples} |\n"
    
    md += "\n## Key Findings\n\n"
    
    if patterns['realm_references']:
        md += "### Realm References\n\n"
        for item in patterns['realm_references'][:10]:
            md += f"- **{item['addr']}**: `\"{item['content']}\"`\n"
        md += "\n"
    
    if patterns['file_paths']:
        md += "### File Paths\n\n"
        for item in patterns['file_paths'][:15]:
            md += f"- **{item['addr']}**: `\"{item['content']}\"`\n"
        md += "\n"
    
    if patterns['urls_domains']:
        md += "### URLs/Domains\n\n"
        for item in patterns['urls_domains'][:10]:
            md += f"- **{item['addr']}**: `\"{item['content']}\"`\n"
        md += "\n"
    
    # Top categories detail
    md += "## Detailed Category Listings\n\n"
    
    for category in ['spell_system', 'movement', 'network', 'protocol', 'combat', 'game_files']:
        if category in categories and categories[category]:
            md += f"### {category.replace('_', ' ').title()}\n\n"
            for item in categories[category][:20]:
                md += f"- **{item['address']}** ({item['length']} chars): `\"{item['content']}\"`\n"
            md += "\n"
    
    md_path = REPORTS_DIR / "STRING_ANALYSIS_DETAILED.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    
    print(f"[+] Markdown documentation saved to: {md_path}")
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    exit(main())
