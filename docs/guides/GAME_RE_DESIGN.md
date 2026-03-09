# Game Reverse Engineering Suite Design

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit UI                              │
│  Upload Game DLLs → Visualize Structure Graph → Export SDK  │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│              Analysis Orchestrator                           │
│  • Multi-binary loader                                       │
│  • Dependency resolution                                     │
│  • Autonomous workflow engine                                │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│                Structure Inference Engine                    │
│  • Cross-binary type propagation                             │
│  • Pattern matching (Vector3, Entity, etc.)                  │
│  • VTable reconstruction                                     │
│  • Size/layout validation                                    │
└────────────────┬────────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────────┐
│              MCP Server (Ghidra + Extensions)                │
│  • 34 base tools                                             │
│  • Custom game RE tools (structure inferrer, xref tracer)    │
└──────────────────────────────────────────────────────────────┘
```

## Key Capabilities

### 1. Multi-Binary Project Management
**Goal:** Analyze multiple interdependent DLLs as unified game engine

**Implementation:**
- Extend `mcp-headless` to accept multiple binaries via environment variable
- Create Ghidra project with all DLLs imported
- Build dependency graph from import/export tables
- Track cross-binary references

**New MCP Tools:**
- `load_multiple_binaries(paths: List[str]) -> ProjectID`
- `get_dependency_graph() -> Dict[str, List[str]]`
- `find_cross_binary_xrefs(from_dll: str, to_dll: str) -> List[XRef]`

### 2. Structure Inference Engine
**Goal:** Automatically discover and reconstruct C++ classes, structs, and game object hierarchies

**Techniques:**

#### A. VTable Analysis
- Scan for repeating pointer patterns at object+0x0
- Group functions sharing VTable → identify class hierarchy
- Reconstruct virtual method signatures from usage

#### B. Type Propagation
```python
# Example workflow:
1. Find function: SetPosition(void* entity, float x, float y, float z)
2. Infer: entity+0x10 = float[3] (position vector)
3. Follow all xrefs to entity parameter
4. Propagate structure definition across call sites
5. Cluster similar objects → identify Entity base class
```

#### C. Pattern Matching
Common game engine patterns:
```cpp
// Vector3 detection
struct Vector3 {
    float x, y, z;  // Often at +0x0, +0x4, +0x8
};

// Entity detection
struct Entity {
    void** vtable;        // +0x0: VTable pointer
    uint32_t id;          // Common at +0x8
    Vector3 position;     // Common at +0x10
    Vector3 rotation;     // Common at +0x1C
    char name[64];        // String buffers
};
```

#### D. Size Validation
- Track all memory accesses to structure (entity+0x??)
- Largest offset+size = minimum structure size
- Verify alignment (4-byte, 8-byte boundaries)

### 3. Autonomous Analysis Agent
**Goal:** Agent explores game engine autonomously, building knowledge graph

**Workflow Loop:**
```python
while analysis_budget > 0:
    1. Identify high-value targets:
       - Exported functions (public API)
       - VTable clusters (class hierarchies)
       - String references (debug symbols, file paths)
    
    2. Decompile and analyze:
       - Extract function signatures
       - Identify parameter types via usage
       - Follow data flow to structure fields
    
    3. Synthesize structures:
       - Merge observations across functions
       - Resolve conflicts (same offset, different types)
       - Build confidence scores
    
    4. Generate hypotheses:
       - "Function 0x1234 is likely Entity::Update()"
       - "Structure at entity+0x10 is Vector3 position"
    
    5. Validate:
       - Check consistency across all xrefs
       - Test against known patterns
       - Flag ambiguities for user review
    
    6. Update knowledge graph:
       - Store structure definitions
       - Link functions to classes
       - Build call dependency tree
```

**Agent Decision Making:**
```python
# Prioritization heuristics:
priority_score = (
    num_xrefs * 2 +              # Popular functions = important
    has_string_refs * 5 +         # Strings = semantic hints
    cross_dll_calls * 10 +        # Inter-module = public API
    vtable_detected * 8 +         # VTable = class definition
    param_count * 1               # Complex functions = core logic
)
```

### 4. Game-Specific Features

#### A. Unity/Unreal Detection
```python
SIGNATURES = {
    "Unity": [
        "mono.dll",
        "UnityEngine.dll",
        "il2cpp metadata patterns"
    ],
    "Unreal": [
        "UE4Game.exe",
        "FName", "UObject" patterns,
        ".upk/.uasset strings"
    ]
}
```

#### B. Anti-Analysis Detection
- Identify anti-debug checks
- Flag obfuscated functions (high cyclomatic complexity)
- Detect packers (UPX, Themida, VMProtect)

#### C. Asset Path Extraction
- Mine strings for file paths
- Reconstruct asset directory structure
- Link code to resources

## Implementation Phases

### Phase 1: Multi-Binary Foundation (Week 1)
**Files to create:**
- `mcp-headless/scripts/LoadMultipleBinariesScript.java`
- `mcp-runner/multi_binary_loader.py`
- `mcp-runner/dependency_graph.py`

**Docker changes:**
- Add volume mount for batch DLL loading: `./game-dlls:/dlls:ro`
- Environment variable: `ANALYSIS_MODE=multi_binary`

### Phase 2: Structure Inference (Week 2)
**Files to create:**
- `structure-engine/vtable_analyzer.py`
- `structure-engine/type_propagator.py`
- `structure-engine/pattern_matcher.py`
- `structure-engine/structure_synthesizer.py`

**MCP tool additions:**
- Custom Ghidra extension: `GameRE-MCP-Tools`
- Tools: `infer_structure`, `find_vtables`, `propagate_types`

### Phase 3: Autonomous Agent (Week 3)
**Files to create:**
- `agent-runner/autonomous_analyzer.py`
- `agent-runner/knowledge_graph.py`
- `agent-runner/hypothesis_engine.py`

**Agent capabilities:**
- Priority queue for analysis targets
- Memory system (avoid re-analyzing same functions)
- Confidence scoring for hypotheses
- Conflict resolution

### Phase 4: UI Integration (Week 4)
**Streamlit enhancements:**
- Multi-file upload widget
- Interactive structure viewer (expandable tree)
- Dependency graph visualization (NetworkX + Plotly)
- Export to C header files

## Example Workflow

### User Scenario: Reversing Game DLLs
```bash
# 1. Upload game binaries
samples/game/
├── GameEngine.dll
├── Graphics.dll
├── Physics.dll
└── Game.exe

# 2. Start analysis
$ docker compose --profile game-re up -d

# 3. Agent discovers:
✓ Loaded 4 binaries (2,847 functions total)
✓ Built dependency graph: Game.exe → GameEngine.dll → [Graphics, Physics]
✓ Found 23 VTables → 23 C++ classes
✓ Inferred 15 structures (Entity, Vector3, Matrix4x4, Camera, ...)
✓ Identified 8 key systems (Renderer, PhysicsWorld, EntityManager, ...)

# 4. Export SDK
$ curl http://localhost:8501/export/sdk
→ Downloads game_sdk.h with reconstructed structures
```

### Generated Output
```cpp
// game_sdk.h (auto-generated)

// Structure confidence: HIGH (98%)
struct Vector3 {
    float x;  // offset 0x0
    float y;  // offset 0x4
    float z;  // offset 0x8
};  // size: 0xC

// Structure confidence: MEDIUM (75%)
struct Entity {
    void** vtable;           // offset 0x0
    uint32_t entity_id;      // offset 0x8
    Vector3 position;        // offset 0x10
    Vector3 rotation;        // offset 0x1C
    void* parent_entity;     // offset 0x28
    char name[64];           // offset 0x30
};  // size: 0x70

// Identified virtual methods:
class EntityBase {
public:
    virtual void Update(float deltaTime);      // vtable[0]
    virtual void Render(void* renderer);       // vtable[1]
    virtual void OnDestroy();                  // vtable[2]
};

// High-confidence function signatures:
extern "C" {
    Entity* CreateEntity(const char* name, Vector3* position);  // GameEngine.dll+0x1234
    void DestroyEntity(Entity* entity);                         // GameEngine.dll+0x1678
    void SetEntityPosition(Entity* entity, Vector3* pos);       // GameEngine.dll+0x1ABC
}
```

## Technical Challenges & Solutions

### Challenge 1: Structure Field Ambiguity
**Problem:** Same offset accessed as int32 and float in different functions
**Solution:** 
- Track all access patterns with context
- Use union types where ambiguous
- Flag for manual review with confidence scores

### Challenge 2: Cross-Binary Type Consistency
**Problem:** Structure definition varies between DLLs (different versions?)
**Solution:**
- Version detection via build timestamps
- Track structure variants
- Merge common fields, flag differences

### Challenge 3: Virtual Method Resolution
**Problem:** VTable calls via register indirect → hard to resolve target
**Solution:**
- Data flow analysis to track vtable pointer origin
- Build callgraph from all possible VTable targets
- Use IDA/Ghidra decompiler to simplify

### Challenge 4: Performance at Scale
**Problem:** Large games = 10,000+ functions = hours of analysis
**Solution:**
- Incremental analysis (save intermediate state)
- Parallel processing (multiple Ghidra instances)
- Smart prioritization (analyze exported functions first)
- Caching (don't re-analyze unchanged binaries)

## Tech Stack Additions

```yaml
New Dependencies:
  - networkx (dependency graphs)
  - plotly (interactive visualizations)
  - capstone (disassembly fallback)
  - r2pipe (optional Radare2 integration)

Ghidra Extensions:
  - CFG analysis helpers
  - Structure editor automation
  - VTable scanner
  
AI/ML Components:
  - Function similarity (for pattern matching)
  - Name prediction (based on behavior)
  - Structure clustering (find similar objects)
```

## Next Steps

1. **Prototype multi-binary loader** (validate Ghidra can handle 10+ DLLs)
2. **Build VTable analyzer** (start with simple pointer pattern detection)
3. **Create structure knowledge base** (store/retrieve inferred types)
4. **Implement basic agent loop** (priority queue + analysis budget)
5. **Add game engine signatures** (Unity/Unreal detection)

## Success Metrics

- **Coverage:** % of functions analyzed and classified
- **Accuracy:** Structure field predictions validated against ground truth
- **Autonomy:** % of workflow requiring no human intervention
- **Speed:** Time to generate SDK for 5,000 function game (target: <30min)
