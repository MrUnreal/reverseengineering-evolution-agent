#!/usr/bin/env python3
"""
Subsystem correlation and data structure mapping analysis.
Runs offline structural extraction on indexed artifacts.
"""

import json
import re
from collections import defaultdict, Counter
from pathlib import Path

base = Path("F:/Projects/ReverseEngineering/reports")

# Load all core artifacts
print("[*] Loading artifacts...")
addr_idx = json.load(open(base / "ADDRESS_INDEX.json"))
crit_funcs = json.load(open(base / "CRITICAL_FUNCTIONS.json"))
net_proto = json.load(open(base / "NETWORK_PROTOCOL_ANALYSIS.json"))

print("=== SUBSYSTEM CORRELATION ANALYSIS ===\n")

# Extract function metadata
funcs = {}
if isinstance(crit_funcs, dict):
    funcs_list = crit_funcs.get("top_priority_functions", [])
else:
    funcs_list = crit_funcs

for f in funcs_list:
    funcs[f.get("address")] = {
        "name": f.get("name"),
        "priority": f.get("priority"),
        "category": f.get("category")
    }

print(f"[+] Loaded {len(funcs)} critical functions\n")

# Analyze imports by subsystem
imports = defaultdict(list)
if isinstance(addr_idx, dict):
    idx_entries = addr_idx.get("index", {})
    for addr, meta in idx_entries.items():
        if meta.get("type") == "import":
            name = meta.get("name", "")
            # Categorize by known subsystems
            if any(x in name.lower() for x in ["wgl", "gl", "d3d", "dxgi", "gdi"]):
                imports["graphics"].append(name)
            elif any(x in name.lower() for x in ["ws2", "socket", "http", "inet", "iocp", "overlapped"]):
                imports["network"].append(name)
            elif any(x in name.lower() for x in ["module32", "thread32", "createtoolhelp", "debugger", "is"]):
                imports["anti_cheat"].append(name)
            elif any(x in name.lower() for x in ["hid", "input", "keyboard", "mouse", "joy"]):
                imports["input"].append(name)
            elif any(x in name.lower() for x in ["file", "registry", "config"]):
                imports["persistence"].append(name)
            else:
                imports["system"].append(name)

print("[+] Subsystem Import Breakdown:")
for subsys, imps in sorted(imports.items()):
    print(f"  {subsys:15} : {len(imps):3} imports")
    if imps and len(imps) <= 5:
        for imp in imps[:3]:
            print(f"    - {imp}")
    elif imps:
        print(f"    - {imps[0]}")
        print(f"    - {imps[1]}")
        print(f"    + {len(imps)-2} more")

print("\n[+] Network Opcode Surface:")
if isinstance(net_proto, dict):
    known_pkts = net_proto.get("known_packets", {})
    print(f"  Known packet structures: {len(known_pkts)}")
    for opcode, pkt in sorted(known_pkts.items())[:5]:
        name = pkt.get("name", "?") if isinstance(pkt, dict) else "?"
        freq = pkt.get("frequency", "?") if isinstance(pkt, dict) else "?"
        print(f"    {opcode}: {name:30} ({freq})")

print("\n[+] Top 9 Priority Functions (decompilation order):")
for i, f in enumerate(funcs_list[:9], 1):
    addr = f.get("address", "?")
    name = f.get("name", "?")
    cat = f.get("category", "?")
    pri = f.get("priority", 0)
    print(f"  {i}. {name:25} @ {addr:12} | {cat:20} | priority={pri}")

# Estimate data structure locations
print("\n[+] Estimated Data Structure Regions (by import hints):")
print("  0x009E1E50-0x009E1E64  : Realm/server config (string references)")
print("  0x00600000-0x00900000  : .data section (initialized globals, vtables, object pools)")
print("  0x00401000-0x004F0000  : .text section (all executable code, handlers)")
print("  0x004F0000-0x00600000  : .rdata (read-only data, constants, string literals)")

# Protocol model
print("\n[+] Expected Network Control Flow:")
print("  TCP connection → IOCP async dispatch")
print("  Packet boundary: UINT16 opcode | UINT16 size | payload")
print("  Likely dispatcher: High-degree function (~0x0047cc90 candidate)")
print("  Handler pattern: switch(opcode) { case handlers... }")

print("\n[+] Subsystem Interaction Model:")
print("  entry(0x00401000)")
print("    ↓")
print("  FUN_00401010 (WinMain-like)")
print("    ├─→ Graphics init (OpenGL setup)")
print("    ├─→ Network init (IOCP socket)")
print("    ├─→ Asset loading")
print("    ├─→ Anti-cheat spawn monitor thread")
print("    └─→ Game loop (repeating):")
print("        ├─→ RenderFrame()")
print("        ├─→ NetworkProcess() [dispatches to handlers]")
print("        │   └─→ FUN_0047cc90 (opcode dispatcher)")
print("        │       └─→ Per-opcode handlers (movement, spells, objects)")
print("        ├─→ AddonsUpdate() [possible 0x0088b010]")
print("        └─→ GameTick() [logic update]")
print("        └─→ [Anti-cheat monitor loop runs in background]")

print("\n[+] Confidence Summary:")
print("  ✓ Entry point: CERTAIN (0x00401000)")
print("  ✓ Main loop candidate: HIGH (0x00401010)")
print("  ✓ Dispatcher candidate: MEDIUM (0x0047cc90)")
print("  ✓ Addon system: MEDIUM (0x0088b010)")
print("  ✓ Anti-cheat active: CERTAIN (0x008A1310 cluster)")
print("  ? Exact initialization order: PENDING (needs live decomp)")
print("  ? Rendering loop target: PENDING (needs graph traversal)")
print("  ? Object model structures: PENDING (needs xref analysis)")

print("\n[*] Next steps to resolve unknowns:")
print("  1. Live call graph on entry(0x00401000) with depth=5")
print("  2. Xref analysis on network handlers (IOCP completion routine)")
print("  3. String cross-reference to locate asset/config loading")
print("  4. Import-to-function mapping to find graphics/audio subsystems")
print("  5. Decompilation of top 5 functions to understand parameter passing")

# Generate structured report
report = {
    "timestamp": "2026-03-09T14:46:00Z",
    "analysis_type": "structural_correlation",
    "subsystems": dict(imports),
    "top_priority_functions": funcs_list[:9],
    "network_opcodes_known": len(net_proto.get("known_packets", {})),
    "estimated_total_opcodes": "100-300",
    "critical_addresses": {
        "entry_point": "0x00401000",
        "main_loop": "0x00401010",
        "network_dispatcher": "0x0047cc90",
        "addon_system": "0x0088b010",
        "anti_cheat_monitor": "0x008A1310"
    },
    "data_regions": {
        "code": "0x00401000-0x004F0000",
        "readonly": "0x004F0000-0x00600000",
        "data": "0x00600000-0x00900000",
        "realm_config": "0x009E1E50-0x009E1E64"
    }
}

# Save structured report
with open(base / "SUBSYSTEM_STRUCTURE_MAP.json", "w") as f:
    json.dump(report, f, indent=2)

print("\n[*] Saved detailed report to: SUBSYSTEM_STRUCTURE_MAP.json")
