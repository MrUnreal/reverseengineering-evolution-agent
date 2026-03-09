"""
Autonomous Game RE Agent - Orchestrates multi-binary analysis
"""
import json
import time
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import heapq
from collections import defaultdict


@dataclass
class AnalysisTarget:
    """Represents something to analyze (function, vtable, structure)"""
    type: str  # 'function', 'vtable', 'structure', 'export'
    address: int
    name: str
    priority: float
    dll_name: str
    metadata: Dict = None
    
    def __lt__(self, other):
        # For priority queue (higher priority = analyzed first)
        return self.priority > other.priority


class KnowledgeGraph:
    """
    Stores discovered knowledge about the game engine
    
    Nodes: Functions, Structures, VTables, DLLs
    Edges: Calls, References, Inherits, Uses
    """
    
    def __init__(self):
        self.nodes: Dict[int, Dict] = {}  # address -> node data
        self.edges: List[Tuple[int, int, str]] = []  # (from, to, relationship)
        self.structures: Dict[str, Dict] = {}
        self.classes: Dict[str, Dict] = {}
        self.dlls: Dict[str, Dict] = {}
        
    def add_function(self, address: int, name: str, dll: str, **kwargs):
        """Add function node"""
        self.nodes[address] = {
            'type': 'function',
            'address': address,
            'name': name,
            'dll': dll,
            **kwargs
        }
    
    def add_call_edge(self, caller: int, callee: int):
        """Add function call relationship"""
        self.edges.append((caller, callee, 'calls'))
    
    def add_structure(self, name: str, structure_data: Dict):
        """Add discovered structure"""
        self.structures[name] = structure_data
    
    def add_class(self, name: str, class_data: Dict):
        """Add discovered C++ class"""
        self.classes[name] = class_data
    
    def get_high_centrality_functions(self, top_n: int = 10) -> List[int]:
        """
        Find most important functions by centrality
        (Functions with most callers and callees)
        """
        in_degree = defaultdict(int)
        out_degree = defaultdict(int)
        
        for src, dst, rel in self.edges:
            if rel == 'calls':
                out_degree[src] += 1
                in_degree[dst] += 1
        
        # Combine in and out degree for centrality score
        centrality = {
            addr: in_degree[addr] + out_degree[addr]
            for addr in set(in_degree.keys()) | set(out_degree.keys())
        }
        
        # Return top N
        sorted_addrs = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        return [addr for addr, score in sorted_addrs[:top_n]]
    
    def export_json(self, output_path: str):
        """Save knowledge graph to JSON"""
        data = {
            'nodes': list(self.nodes.values()),
            'edges': [
                {'from': src, 'to': dst, 'type': rel}
                for src, dst, rel in self.edges
            ],
            'structures': self.structures,
            'classes': self.classes,
            'dlls': self.dlls,
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)


class AutonomousAnalyzer:
    """
    Autonomous agent that explores game binaries and builds understanding
    
    Workflow:
    1. Load multiple DLLs
    2. Build dependency graph
    3. Prioritize analysis targets
    4. Iteratively analyze and learn
    5. Synthesize structures and classes
    6. Export SDK
    """
    
    def __init__(self, mcp_client, vtable_analyzer, type_propagator):
        self.mcp = mcp_client
        self.vtable_analyzer = vtable_analyzer
        self.type_propagator = type_propagator
        
        self.knowledge = KnowledgeGraph()
        self.analyzed_functions: Set[int] = set()
        self.analysis_queue: List[AnalysisTarget] = []
        
        self.stats = {
            'functions_analyzed': 0,
            'structures_discovered': 0,
            'classes_discovered': 0,
            'analysis_time': 0.0,
        }
    
    def analyze_game(self, dll_paths: List[str], output_dir: str, 
                    budget: int = 1000):
        """
        Main analysis loop
        
        Args:
            dll_paths: List of DLL files to analyze
            output_dir: Where to save results
            budget: Maximum number of functions to analyze
        """
        start_time = time.time()
        
        print(f"[*] Starting autonomous analysis of {len(dll_paths)} binaries")
        print(f"[*] Analysis budget: {budget} functions\n")
        
        # Phase 1: Load all binaries
        print("[Phase 1] Loading binaries...")
        self._load_binaries(dll_paths)
        
        # Phase 2: Build dependency graph
        print("[Phase 2] Building dependency graph...")
        dep_graph = self._build_dependency_graph()
        print(f"  → Found {len(dep_graph)} DLL dependencies\n")
        
        # Phase 3: Discover VTables and classes
        print("[Phase 3] Discovering C++ classes...")
        vtables = self._discover_vtables()
        print(f"  → Found {len(vtables)} VTables\n")
        
        # Phase 4: Prioritize analysis targets
        print("[Phase 4] Prioritizing analysis targets...")
        self._build_priority_queue()
        print(f"  → Queued {len(self.analysis_queue)} targets\n")
        
        # Phase 5: Iterative analysis
        print("[Phase 5] Analyzing functions...")
        self._analyze_iteratively(budget)
        
        # Phase 6: Synthesize structures
        print("\n[Phase 6] Synthesizing structures...")
        self._synthesize_all_structures()
        
        # Phase 7: Export results
        print("[Phase 7] Exporting results...")
        self._export_results(output_dir)
        
        self.stats['analysis_time'] = time.time() - start_time
        
        self._print_summary()
    
    def _load_binaries(self, dll_paths: List[str]):
        """Load multiple DLLs into Ghidra project"""
        for dll_path in dll_paths:
            try:
                # Use MCP to load binary (this would need multi-binary support)
                result = self.mcp.call_tool("load_program", {
                    "path": dll_path
                })
                
                dll_name = Path(dll_path).name
                self.knowledge.dlls[dll_name] = {
                    'path': dll_path,
                    'loaded': True,
                }
                
                print(f"  ✓ Loaded {dll_name}")
            except Exception as e:
                print(f"  ✗ Failed to load {dll_path}: {e}")
    
    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """
        Build import/export dependency graph between DLLs
        
        Returns:
            Dict mapping DLL name to list of imported DLLs
        """
        dep_graph = {}
        
        for dll_name in self.knowledge.dlls:
            try:
                imports = self.mcp.call_tool("list_imports", {})
                
                imported_dlls = set()
                for imp in imports.get("imports", []):
                    imported_dll = imp.get("library", "")
                    if imported_dll:
                        imported_dlls.add(imported_dll)
                
                dep_graph[dll_name] = list(imported_dlls)
                
            except Exception as e:
                print(f"  Warning: Could not get imports for {dll_name}: {e}")
                dep_graph[dll_name] = []
        
        return dep_graph
    
    def _discover_vtables(self) -> List:
        """Use VTable analyzer to find C++ classes"""
        try:
            # Get .rdata section (where vtables live)
            # This is simplified - real impl would parse PE headers
            
            # For now, use list_functions to find vtable references
            functions = self.mcp.call_tool("list_functions", {})
            
            # Look for constructor patterns
            # Constructors typically write vtable pointer to [eax]
            
            vtables = []
            # Placeholder - real implementation would scan sections
            
            return vtables
        except Exception as e:
            print(f"  Warning: VTable discovery failed: {e}")
            return []
    
    def _build_priority_queue(self):
        """
        Build priority queue of analysis targets
        
        Priority factors:
        - Exported functions (public API) = HIGH
        - Cross-DLL calls = HIGH
        - String references = MEDIUM
        - Many cross-references = MEDIUM
        - VTable methods = HIGH
        """
        try:
            # Get all functions
            functions_result = self.mcp.call_tool("list_functions", {})
            functions = functions_result.get("functions", [])
            
            # Get exports
            exports_result = self.mcp.call_tool("list_imports", {})  # Also returns exports
            exports = {e["address"] for e in exports_result.get("exports", [])}
            
            # Get strings for reference counting
            strings_result = self.mcp.call_tool("list_strings", {})
            string_refs = defaultdict(int)
            for s in strings_result.get("strings", []):
                for xref in s.get("xrefs", []):
                    string_refs[xref] += 1
            
            # Score each function
            for func in functions:
                address_str = func.get("address", "0x0")
                address = int(address_str, 16) if isinstance(address_str, str) else address_str
                name = func.get("name", f"FUN_{address:08X}")
                
                # Calculate priority
                priority = 0.0
                
                # Exported = high priority
                if address_str in exports:
                    priority += 50.0
                
                # Has string references
                priority += string_refs.get(address, 0) * 5.0
                
                # Has many callers (get from xrefs)
                # Simplified - would query xrefs in real impl
                
                # Create target
                target = AnalysisTarget(
                    type='function',
                    address=address,
                    name=name,
                    priority=priority,
                    dll_name='main',  # Would track per-DLL
                    metadata=func
                )
                
                heapq.heappush(self.analysis_queue, target)
                
        except Exception as e:
            print(f"  Error building priority queue: {e}")
    
    def _analyze_iteratively(self, budget: int):
        """
        Main analysis loop - process targets by priority
        """
        progress_interval = max(1, budget // 20)  # Print progress every 5%
        
        while self.analysis_queue and self.stats['functions_analyzed'] < budget:
            target = heapq.heappop(self.analysis_queue)
            
            if target.address in self.analyzed_functions:
                continue
            
            # Analyze this target
            self._analyze_function(target)
            
            self.analyzed_functions.add(target.address)
            self.stats['functions_analyzed'] += 1
            
            # Print progress
            if self.stats['functions_analyzed'] % progress_interval == 0:
                pct = (self.stats['functions_analyzed'] / budget) * 100
                print(f"  [{pct:.0f}%] Analyzed {self.stats['functions_analyzed']}/{budget} functions")
    
    def _analyze_function(self, target: AnalysisTarget):
        """
        Deep analysis of a single function
        
        Steps:
        1. Get decompiled code
        2. Identify parameters and their types
        3. Track structure field accesses
        4. Find callees and add to queue
        5. Store in knowledge graph
        """
        try:
            # Get function info
            func_info = self.mcp.call_tool("get_function_info", {
                "address": hex(target.address)
            })
            
            # Add to knowledge graph
            self.knowledge.add_function(
                address=target.address,
                name=target.name,
                dll=target.dll_name,
                **func_info
            )
            
            # Get callees
            call_graph = self.mcp.call_tool("get_call_graph", {
                "address": hex(target.address),
                "depth": 1
            })
            
            for callee in call_graph.get("callees", []):
                callee_addr = int(callee["address"], 16)
                self.knowledge.add_call_edge(target.address, callee_addr)
                
                # Add callee to queue if not analyzed
                if callee_addr not in self.analyzed_functions:
                    # Lower priority for indirect discoveries
                    new_target = AnalysisTarget(
                        type='function',
                        address=callee_addr,
                        name=callee.get("name", f"FUN_{callee_addr:08X}"),
                        priority=target.priority * 0.5,  # Decay priority
                        dll_name=target.dll_name,
                        metadata=callee
                    )
                    heapq.heappush(self.analysis_queue, new_target)
            
            # Analyze for structure accesses
            # If function takes pointer parameters, track field accesses
            param_count = func_info.get("param_count", 0)
            if param_count > 0:
                # Assume first param might be structure
                structure_name = f"Struct_Used_By_{target.name}"
                self.type_propagator.analyze_function_for_structure_access(
                    target.address, 0, structure_name
                )
            
        except Exception as e:
            # Non-fatal - continue analysis
            pass
    
    def _synthesize_all_structures(self):
        """Synthesize all discovered structures"""
        # Get all structure names from type propagator
        structure_names = set()
        for (struct_name, offset), accesses in self.type_propagator.field_accesses.items():
            structure_names.add(struct_name)
        
        for struct_name in structure_names:
            try:
                structure = self.type_propagator.synthesize_structure(struct_name)
                
                # Only keep structures with 2+ fields
                if len(structure.fields) >= 2:
                    self.knowledge.add_structure(struct_name, asdict(structure))
                    self.stats['structures_discovered'] += 1
            except Exception as e:
                print(f"  Warning: Failed to synthesize {struct_name}: {e}")
        
        print(f"  → Discovered {self.stats['structures_discovered']} structures")
    
    def _export_results(self, output_dir: str):
        """Export all results to files"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Export knowledge graph
        self.knowledge.export_json(str(output_path / "knowledge_graph.json"))
        
        # Export structures as C headers
        for struct_name in self.knowledge.structures:
            safe_name = struct_name.replace(':', '_').replace(' ', '_')
            header_path = output_path / f"{safe_name}.h"
            try:
                self.type_propagator.export_to_c_header(struct_name, str(header_path))
            except Exception as e:
                print(f"  Warning: Failed to export {struct_name}: {e}")
        
        # Export combined SDK header
        self._export_combined_sdk(output_path / "game_sdk.h")
        
        # Export statistics
        with open(output_path / "analysis_stats.json", 'w') as f:
            json.dump(self.stats, f, indent=2)
        
        print(f"  → Saved results to {output_dir}")
    
    def _export_combined_sdk(self, output_path: Path):
        """Export all discoveries to single SDK header"""
        with open(output_path, 'w') as f:
            f.write("// Auto-Generated Game SDK\n")
            f.write(f"// Functions analyzed: {self.stats['functions_analyzed']}\n")
            f.write(f"// Structures discovered: {self.stats['structures_discovered']}\n")
            f.write(f"// Analysis time: {self.stats['analysis_time']:.1f}s\n\n")
            
            f.write("#pragma once\n")
            f.write("#include <stdint.h>\n\n")
            
            # Write structures
            f.write("// ===== Discovered Structures =====\n\n")
            for struct_name, struct_data in self.knowledge.structures.items():
                f.write(f"// {struct_name}\n")
                f.write(f"// Confidence: {struct_data['confidence']:.1%}\n")
                f.write(f"struct {struct_name} {{\n")
                
                for field in struct_data['fields']:
                    ftype = self.type_propagator._field_type_to_c(
                        field['type'], field['size']
                    )
                    f.write(f"    {ftype} {field['name']};  "
                           f"// +0x{field['offset']:02X}\n")
                
                f.write(f"}};  // size: 0x{struct_data['size']:X}\n\n")
            
            # Write function signatures for high-priority functions
            f.write("\n// ===== Key Functions =====\n\n")
            high_centrality = self.knowledge.get_high_centrality_functions(20)
            
            for addr in high_centrality:
                node = self.knowledge.nodes.get(addr)
                if node:
                    name = node['name']
                    f.write(f"// Function @ 0x{addr:08X}\n")
                    f.write(f"void {name}();  // TODO: determine signature\n\n")
    
    def _print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print(f"Functions analyzed: {self.stats['functions_analyzed']}")
        print(f"Structures discovered: {self.stats['structures_discovered']}")
        print(f"Classes discovered: {self.stats['classes_discovered']}")
        print(f"Total time: {self.stats['analysis_time']:.1f}s")
        print(f"Analysis rate: {self.stats['functions_analyzed']/self.stats['analysis_time']:.1f} functions/sec")
        print("="*60)


def main():
    """Example usage"""
    from mcp_runner.run_mcp_analysis import McpClient
    from structure_engine.vtable_analyzer import VTableAnalyzer
    from structure_engine.type_propagator import TypePropagator
    
    # Initialize components
    mcp = McpClient("http://ghidrassist-mcp:8080")
    vtable_analyzer = VTableAnalyzer(mcp)
    type_propagator = TypePropagator(mcp)
    
    # Create autonomous analyzer
    analyzer = AutonomousAnalyzer(mcp, vtable_analyzer, type_propagator)
    
    # Analyze game DLLs
    game_dlls = [
        "/samples/game/GameEngine.dll",
        "/samples/game/Graphics.dll",
        "/samples/game/Physics.dll",
        "/samples/game/Game.exe",
    ]
    
    analyzer.analyze_game(
        dll_paths=game_dlls,
        output_dir="/reports/game-sdk",
        budget=500  # Analyze top 500 functions
    )


if __name__ == "__main__":
    main()
