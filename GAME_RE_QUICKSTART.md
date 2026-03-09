# Game RE Quick Start Guide

## 🎯 Goal
Automatically reverse engineer game DLLs to extract:
- C++ class hierarchies (from VTables)
- Structure definitions (Entity, Vector3, Camera, etc.)
- Function relationships (call graphs, dependency trees)
- SDK-style C headers for modding/cheating/research

## 🚀 Quick Start (3 Commands)

### 1. Place your game DLLs
```bash
mkdir -p samples/game
cp /path/to/your/game/*.dll samples/game/
cp /path/to/your/game/*.exe samples/game/
```

### 2. Start MCP backend + UI
```bash
docker compose --profile mcp up -d ghidrassist-mcp mcp-ui
```

### 3. Open browser
```
http://localhost:8501
```

- Select **"Game RE (Multi-Binary)"** mode
- Upload your DLLs (or they'll be auto-detected from samples/game/)
- Click **"Start Autonomous Analysis"**
- Switch to **"Structure Browser"** to view results
- Download SDK headers

## 🧠 What Happens Automatically

### Phase 1: VTable Discovery
```
Scanning .rdata for pointer arrays...
✓ Found 23 VTables
✓ Validated 18 as C++ classes
✓ Detected 5 inheritance relationships
```

**Output:** `Entity`, `Camera`, `Player`, `Renderer` classes

### Phase 2: Structure Inference
```
Analyzing 487 functions for memory access patterns...
✓ Discovered Vector3 (3 floats @ entity+0x10)
✓ Discovered position field (high confidence: 98%)
✓ Inferred 15 complete structures
```

**Output:** Complete field definitions with offsets and types

### Phase 3: Knowledge Graph
```
Building call graph...
✓ 487 functions analyzed
✓ 2,341 function calls mapped
✓ 12 cross-DLL entry points found
```

**Output:** JSON graph for visualization/further analysis

### Phase 4: SDK Generation
```
Generating C headers...
✓ game_sdk.h (combined)
✓ Entity.h, Vector3.h, Camera.h (individual)
```

## 📊 Example Output

### Discovered Structure
```c
// Entity.h
// Confidence: 92%
struct Entity {
    void** vtable;           // +0x00 (VTable pointer)
    uint32_t entity_id;      // +0x08
    Vector3 position;        // +0x10 (3 floats)
    Vector3 rotation;        // +0x1C
    Vector3 velocity;        // +0x28
    void* parent_entity;     // +0x34
    uint32_t flags;          // +0x38
    char name[64];           // +0x40
};  // size: 0x80 (128 bytes)
```

### Discovered Class Hierarchy
```c
// Player.h
class Entity {
public:
    virtual void Update(float deltaTime);    // vtable[0] @ 0x401234
    virtual void Render(void* renderer);     // vtable[1] @ 0x401678
    virtual void OnDestroy();                // vtable[2] @ 0x401ABC
};

class Player : public Entity {
public:
    virtual void Update(float deltaTime);    // overridden
    virtual void Render(void* renderer);     // overridden
    virtual void OnInput(int key);           // new method @ 0x402000
};
```

## 🎮 Real-World Examples

### Example 1: Unity Game
```bash
# Detect Unity engine
samples/game/
├── UnityPlayer.dll
├── GameAssembly.dll  # IL2CPP
└── Game.exe

# Analysis discovers:
→ GameObject structure
→ Transform component
→ MonoBehaviour base class
→ IL2CPP metadata patterns
```

### Example 2: Custom Engine
```bash
# Unknown game engine
samples/game/
├── GameEngine.dll
├── Graphics.dll
├── Physics.dll
└── Game.exe

# Autonomous analysis:
→ 23 structures discovered
→ 15 C++ classes reconstructed
→ Call graph shows rendering pipeline
→ Physics structures (RigidBody, Collider) inferred
```

### Example 3: Targeting Specific System
```python
# Custom script to focus on network code
from agent_runner.autonomous_analyzer import AutonomousAnalyzer

analyzer = AutonomousAnalyzer(mcp, vtable_analyzer, type_propagator)

# Prioritize functions with network imports
analyzer.set_priority_boost({
    'imports': ['send', 'recv', 'WSASend', 'connect'],
    'strings': ['http', 'api', 'server'],
    'boost_factor': 10.0
})

analyzer.analyze_game(["GameEngine.dll"], budget=300)

# Result: NetworkPacket, Connection, Session structures
```

## 🔧 Advanced Usage

### Custom Analysis Budget
```bash
# Light analysis (quick overview)
ANALYSIS_BUDGET=100 docker compose --profile game-re up game-re-agent

# Deep analysis (comprehensive)
ANALYSIS_BUDGET=2000 docker compose --profile game-re up game-re-agent
```

### Export Options
```python
# From Python REPL or notebook:
from structure_engine.type_propagator import TypePropagator

propagator = TypePropagator(mcp_client)
entity = propagator.structures["Entity"]

# Export as C header
propagator.export_to_c_header("Entity", "output/entity.h")

# Export as JSON (for tools)
import json
with open("output/entity.json", "w") as f:
    json.dump(asdict(entity), f, indent=2)

# Export as ReClass.NET format
propagator.export_to_reclass("Entity", "output/entity.rcnet")
```

### Visualization
```python
# Generate call graph visualization
import networkx as nx
import matplotlib.pyplot as plt

G = nx.DiGraph()
for edge in knowledge_graph['edges']:
    G.add_edge(edge['from'], edge['to'])

# Find most important functions (PageRank)
centrality = nx.pagerank(G)
top_functions = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:10]

print("Top 10 most important functions:")
for addr, score in top_functions:
    func = knowledge_graph['nodes'][addr]
    print(f"  {func['name']} @ 0x{addr:08X} (centrality: {score:.4f})")
```

## 🐛 Troubleshooting

### "No structures discovered"
**Cause:** Budget too low or functions don't use structures

**Fix:**
```bash
# Increase budget
ANALYSIS_BUDGET=1000 docker compose --profile game-re up game-re-agent

# Check if functions are being analyzed:
docker compose logs game-re-agent | grep "Analyzed"
```

### "Low confidence scores"
**Cause:** Obfuscated code or unusual patterns

**Fix:**
- Lower confidence threshold in UI (Settings → Min Confidence: 0.5)
- Enable deep analysis mode
- Manually annotate key functions in Ghidra desktop

### "VTables not detected"
**Cause:** Non-standard vtable layout or static linking

**Fix:**
```python
# Use RTTI scanning fallback:
analyzer.enable_rtti_scanning = True

# Or manually register known vtable:
analyzer.register_vtable(address=0x504000, method_count=8)
```

## 📚 Next Steps

1. **Try the example workflow:**
   - Use provided sample game or your own
   - Run analysis
   - Explore structures in UI
   - Download SDK headers

2. **Integrate with mods/cheats:**
   - Use generated headers in your C++ project
   - Access game structures from external tools
   - Hook functions at discovered addresses

3. **Contribute improvements:**
   - Add structure templates for popular engines
   - Improve pattern detection heuristics
   - Submit ARM/x64 analysis enhancements

## 🎓 Learning Resources

- **Ghidra Scripting:** https://ghidra.re/courses/GhidraClass/
- **C++ Reverse Engineering:** https://github.com/topics/reverse-engineering
- **Game Hacking:** https://guidedhacking.com/
- **VTable Internals:** https://shaharmike.com/cpp/vtable-part1/

## 💡 Pro Tips

1. **Start small:** Analyze 1-2 DLLs first with budget=200 to test
2. **Use UI for exploration:** Browser UI is great for iterative discovery
3. **Export early:** Generate headers after partial analysis to validate
4. **Manual refinement:** Use Ghidra desktop to verify/improve structures
5. **Incremental analysis:** Save checkpoints for large games (10K+ functions)

## 🔗 Architecture Reference

```
Game DLLs → Ghidra Headless → MCP Server → Autonomous Agent
              ↓                   ↓              ↓
         Decompiler          34 Tools       Structure Engine
              ↓                   ↓              ↓
         Functions            Xrefs         VTable Analyzer
                                ↓              ↓
                          Type Propagator → SDK Generator
                                                ↓
                                          C Headers + JSON
```

## 🚢 Production Deployment

For large-scale analysis or CI/CD integration:

```yaml
# docker-compose.prod.yml
services:
  game-re-batch:
    image: reverseengineering-game-re-agent
    volumes:
      - /mnt/game-library:/samples/game:ro
      - /mnt/analysis-output:/reports
    environment:
      ANALYSIS_BUDGET: 1500
      BATCH_MODE: "true"
      PARALLEL_WORKERS: 4
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 16G
```

Run batch analysis on entire game library:
```bash
docker compose -f docker-compose.prod.yml up game-re-batch
```

---

**Ready to go!** Try the Quick Start workflow above or dive into the full README for advanced features.
