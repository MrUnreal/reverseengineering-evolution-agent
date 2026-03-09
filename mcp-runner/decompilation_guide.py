#!/usr/bin/env python3
"""
Ghidra Direct Function Decompilation - Use MCP to decompile key functions
Identifies actual game logic by decompiling selected functions
"""

import json
import subprocess
import re
import time
from pathlib import Path
from typing import Optional

def generate_ghidra_script():
    """Generate a Ghidra script for function analysis"""
    
    script = '''// @author 
// @category Search
// @keybinding 
// @menupath Tools.AnalyzeGameFunctions
// @toolbar 

import ghidra.app.decompiler.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import java.io.*;

public class AnalyzeGameFunctions extends GhidraScript {
    
    public void run() throws Exception {
        println("=== GAME FUNCTION ANALYSIS ===");
        
        // Get decompiler interface
        DecompilerInterface decomp = new DecompilerInterface();
        decomp.openProgram(currentProgram);
        
        // Key functions to analyze
        String[] targetFunctions = {
            "entry",
            "FUN_00401010", 
            "FUN_004133c7",
            "FUN_0047cc90",
            "FUN_0088b010"
        };
        
        PrintWriter writer = new PrintWriter(new FileWriter("ghidra_decompilation.txt"));
        
        FunctionManager fm = currentProgram.getFunctionManager();
        
        for (String funcName : targetFunctions) {
            println("\\nSearching for: " + funcName);
            
            for (Function func : fm.getFunctions(true)) {
                if (func.getName().equalsIgnoreCase(funcName)) {
                    writer.println("\\n========== " + funcName + " ==========");
                    writer.println("Address: " + func.getEntryPoint());
                    writer.println("Size: " + func.getBody().getNumAddresses());
                    
                    // Try decompilation
                    try {
                        DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                        if (results.decompileCompleted()) {
                            writer.println("\\nDECOMPILED:\\n");
                            writer.println(results.getDecompiledFunction().getC());
                        } else {
                            writer.println("\\nDECOMPILATION FAILED");
                        }
                    } catch (Exception e) {
                        writer.println("Exception: " + e.getMessage());
                    }
                    
                    // Get xrefs
                    writer.println("\\nCALL FROM:");
                    for (Reference ref : func.getEntryPoint().getReferencesTo()) {
                        if (ref.getReferenceType().isCall()) {
                            writer.println("  " + ref.getFromAddress() + " (in " + fm.getFunctionContaining(ref.getFromAddress()).getName() + ")");
                        }
                    }
                }
            }
        }
        
        writer.close();
        decomp.closeProgram();
        println("Analysis saved to ghidra_decompilation.txt");
    }
}
'''
    
    return script

def create_mcp_decompilation_script():
    """Create a Python script that calls MCP for decompilation"""
    
    return '''#!/usr/bin/env python3
"""
Use MCP decompiler to analyze key functions
"""
import json
import requests
import time
import random

def call_mcp_decompile(func_name, func_addr):
    """Call MCP to decompile a function"""
    
    payload = {
        "jsonrpc": "2.0",
        "id": random.randint(1, 10000),
        "method": "tools/call",
        "params": {
            "name": "decompiler",
            "arguments": {
                "action": "decompile",
                "function": func_addr if func_addr.startswith("0x") else f"0x{func_addr}",
                "format": "C"
            }
        }
    }
    
    try:
        response = requests.post(
            "http://localhost:8080/mcp",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def call_mcp_xrefs(func_addr):
    """Get cross-references for a function"""
    
    payload = {
        "jsonrpc": "2.0",
        "id": random.randint(1, 10000),
        "method": "tools/call",
        "params": {
            "name": "xrefs",
            "arguments": {
                "action": "from",
                "address": func_addr if func_addr.startswith("0x") else f"0x{func_addr}"
            }
        }
    }
    
    try:
        response = requests.post(
            "http://localhost:8080/mcp",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# Key functions to decompile
functions_to_analyze = [
    ("entry", "00401000"),
    ("WinMain/GameInit", "00401010"),
    ("UnknownFunc1", "004133c7"),
    ("UnknownFunc2", "0047cc90"),
    ("UnknownFunc3", "0088b010"),
]

results = {"timestamp": "2026-03-08", "decompiled_functions": []}

for func_name, func_addr in functions_to_analyze:
    print(f"\\nDecompiling {func_name} @ {func_addr}...")
    time.sleep(0.5)  # Rate limit
    
    decomp_result = call_mcp_decompile(func_name, func_addr)
    xref_result = call_mcp_xrefs(func_addr)
    
    results["decompiled_functions"].append({
        "name": func_name,
        "address": func_addr,
        "decompilation": decomp_result,
        "xrefs": xref_result
    })

with open("./reports/mcp-decompilation.json", "w") as f:
    json.dump(results, f, indent=2)

print("\\nDecompilation complete - saved to mcp-decompilation.json")
'''

def main():
    print("\n" + "="*80)
    print("DIRECT FUNCTION DECOMPILATION: Extracting Game Logic")
    print("="*80)
    
    # First, let's at least show what we WOULD do
    print("\n[1] GENERATING DECOMPILATION STRATEGIES")
    print("-" * 80)
    
    print("""
    STRATEGY 1: Use Ghidra GUI (RECOMMENDED)
    ==========================================
    1. Open Ascension.exe in Ghidra
    2. Use Search menu to find functions:
       - entry @ 0x00401000
       - FUN_00401010 (likely WinMain)
       - FUN_004133C7 (unknown game func)
       - FUN_0047CC90 (unknown game func)
       - FUN_0088B010 (unknown game func)
    
    3. Right-click each function, select "Decompile"
    4. Look for patterns:
       - Spell casting: loop over spells, check cooldowns
       - Movement: update position, send packets
       - Combat: target validation, damage calculation
    
    5. Use "Show Xrefs" to trace call chains
    6. Create bookmarks on key functions
    7. Export findings to json
    
    STRATEGY 2: Automated Decompilation (MCP)
    ==========================================
    1. Start MCP backend (already running)
    2. Query decompiler tool with function addresses
    3. Parse decompiled C output
    4. Extract game logic patterns
    5. Map function call chains
    """)
    
    print("\n[2] KEY FUNCTIONS REQUIRING ANALYSIS")
    print("-" * 80)
    
    functions_to_find = {
        "entry @ 0x00401000": {
            "purpose": "Program entry point",
            "expected": ["WinMain call", "DLL loading", "GameWorld init"],
            "importance": "CRITICAL"
        },
        "FUN_00401010": {
            "purpose": "Unknown (likely game initialization)",
            "expected": ["Creates GameWorld singleton", "Initializes subsystems"],
            "importance": "CRITICAL"
        },
        "FUN_004133C7": {
            "purpose": "Unknown (likely core game logic)",
            "expected": ["Game loop or major subsystem", "String/function patterns"],
            "importance": "HIGH"
        },
        "Any function calling WSASend": {
            "purpose": "Packet sending",
            "expected": ["Build packet header", "Fill with game data", "Call WSASend"],
            "importance": "CRITICAL"
        },
        "Any function calling UpdatePosition/MoveTo": {
            "purpose": "Entity movement",
            "expected": ["Position calculation", "Distance check"],
            "importance": "HIGH"
        },
        "Exception handler regions (0x0041D000+)": {
            "purpose": "Protected game logic",
            "expected": ["Try-catch blocks", "Critical sections"],
            "importance": "MEDIUM"
        }
    }
    
    for func, details in functions_to_find.items():
        print(f"\n  {func}")
        print(f"    Purpose: {details['purpose']}")
        print(f"    Expected content: {', '.join(details['expected'])}")
        print(f"    Importance: {details['importance']}")
    
    print("\n[3] PATTERN MATCHING GUIDE")
    print("-" * 80)
    
    patterns = {
        "spell_casting": {
            "indicators": [
                "Loop checking cooldowns",
                "Check mana/requirements",
                "Build packet with spell ID",
                "Call SendPacket or WSASend",
                "String: 'spell'/'cooldown'/'mana'"
            ],
            "search_terms": ["spell", "cast", "cooldown", "mana", "ready"]
        },
        "movement": {
            "indicators": [
                "Load player entity/unit",
                "Get current position (X, Y, Z)",
                "Calculate new position",
                "Build CMSG_MOVE* packet",
                "String: 'movement'/'MoveTo'/'position'"
            ],
            "search_terms": ["move", "position", "Y =", "X =", "velocity"]
        },
        "packet_handling": {
            "indicators": [
                "Receive from socket",
                "Parse opcode from buffer[0]",
                "Switch on opcode",
                "Dispatch to handler function",
                "String: 'opcode'/'packet'/'message'"
            ],
            "search_terms": ["opcode", "packet", "handler", "message", "buffer["]
        },
        "entity_update": {
            "indicators": [
                "Get entity from array/list/map",
                "Check if entity valid",
                "Update position/animation",
                "Check for visibility/rendering",
                "String: 'entity'/'unit'/'object'"
            ],
            "search_terms": ["entity", "unit", "update", "render", "visible"]
        }
    }
    
    for pattern, details in patterns.items():
        print(f"\n  [{pattern.upper()}]")
        print(f"    Search for: {', '.join(details['search_terms'])}")
        print(f"    Indicators in decompiled code:")
        for indicator in details['indicators']:
            print(f"      - {indicator}")
    
    print("\n[4] MANUAL ANALYSIS TODO LIST")
    print("-" * 80)
    print("""
    [ ] 1. Open Ascension.exe in Ghidra
    [ ] 2. Decompile entry @ 0x00401000
        [ ] Find WinMain implementation
        [ ] Trace to game initialization function
    
    [ ] 3. Decompile FUN_00401010
        [ ] Identify if it's the main game loop
        [ ] Look for subsystem initialization calls
    
    [ ] 4. Search for packet-sending code
        [ ] Find WSASend/send call sites
        [ ] Reverse engineer packet building
        [ ] Document CMSG structure
    
    [ ] 5. Search for player/entity movement
        [ ] Find calls to position update
        [ ] Identify position struct layout
        [ ] Find movement validation
    
    [ ] 6. Locate spell casting entry point
        [ ] Find spell validation code
        [ ] Understand cooldown storage
        [ ] Map spell ID format
    
    [ ] 7. Find game state singleton
        [ ] Look for static/global world object
        [ ] Identify player entity location
        [ ] Map entity list structure
    
    [ ] 8. Document important addresses
        [ ] Create address reference map
        [ ] Save function signatures
    """)
    
    # Save analysis plan to file
    output = {
        "timestamp": "2026-03-08",
        "analysis_type": "decompilation_planning",
        "critical_functions": list(functions_to_find.keys()),
        "pattern_matching_guide": patterns,
        "recommended_workflow": [
            "1. Open Ascension.exe in Ghidra (File -> Open)",
            "2. Wait for auto-analysis to complete (watch bottom bar)",
            "3. Use Search -> For Strings to find:",
            "   - 'spell' 'cast' 'movement' 'packet' 'opcode'",
            "4. Right-click each string, 'Go To' to see containing function",
            "5. Right-click function, 'Decompile' to get C pseudocode",
            "6. Document patterns and function purposes",
            "7. Create bookmarks on important functions",
            "8. Export findings to RE report"
        ],
        "next_step": "MANUALLY DECOMPILE KEY FUNCTIONS IN GHIDRA GUI"
    }
    
    with open('./reports/decompilation-plan.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print("\n[NEXT STEP]")
    print("-" * 80) 
    print("""
    The deepest RE analysis requires manual decompilation in Ghidra GUI:
    
    1. WINDOWS: Open %GHIDRA_PATH%/ghidraRun.bat
    2. CREATE/OPEN PROJECT: File -> New Project
    3. IMPORT: File -> Import File -> select Ascension.exe
    4. AUTO-ANALYZE: Let it complete (watch progress bar)
    5. SEARCH: Ctrl+F to find interesting functions/strings
    6. DECOMPILE: Select function, Window -> Decompile
    7. ANALYZE PATTERNS: Look for game logic implementations
    8. BOOKMARK: Mark important functions
    9. EXPORT: Create function reference document
    
    Key strings to search:
    - "spell" - spell casting system
    - "movement" - movement mechanics
    - "packet" - network communication
    - "opcode" - message parsing
    - "cooldown" - ability management
    - "target" - targeting system
    - "combat" - combat logic
    """)
    
    print("\n[OK] Decompilation guide saved to decompilation-plan.json")

if __name__ == '__main__':
    main()
