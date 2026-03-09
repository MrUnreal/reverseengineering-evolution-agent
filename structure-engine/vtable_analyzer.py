"""
VTable Analyzer - Automatically discover C++ classes from vtable patterns
"""
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class VTable:
    """Represents a discovered virtual table"""
    address: int
    method_count: int
    methods: List[int]  # Function addresses
    xrefs: List[int]    # Where this vtable is referenced
    confidence: float   # 0.0-1.0


@dataclass
class ClassHierarchy:
    """Inferred C++ class structure"""
    name: str
    vtable_address: int
    base_classes: List[str]
    virtual_methods: List[Tuple[int, str]]  # (address, name)
    instances: List[int]  # Where objects of this class are allocated
    size_estimate: int


class VTableAnalyzer:
    """
    Discovers C++ classes by finding VTable patterns
    
    Strategy:
    1. Scan .rdata/.data sections for pointer arrays
    2. Validate pointers target code section
    3. Group similar vtables (inheritance detection)
    4. Find constructor usage (objects with same vtable)
    """
    
    def __init__(self, mcp_client):
        self.mcp = mcp_client
        self.vtables: Dict[int, VTable] = {}
        self.classes: Dict[str, ClassHierarchy] = {}
        
    def scan_for_vtables(self, data_section: bytes, base_address: int, 
                         code_ranges: List[Tuple[int, int]]) -> List[VTable]:
        """
        Scan data section for arrays of code pointers (vtables)
        
        Args:
            data_section: Raw bytes from .rdata or .data
            base_address: Virtual address of section start
            code_ranges: List of (start, end) tuples for code sections
        
        Returns:
            List of discovered VTables
        """
        vtables = []
        ptr_size = 4  # Assume 32-bit, adjust for x64
        
        i = 0
        while i < len(data_section) - ptr_size * 3:  # Need at least 3 pointers
            # Read potential vtable
            methods = []
            offset = i
            
            while offset < len(data_section) - ptr_size:
                ptr = int.from_bytes(
                    data_section[offset:offset+ptr_size], 
                    byteorder='little'
                )
                
                # Check if pointer targets code section
                if not self._is_code_pointer(ptr, code_ranges):
                    break
                    
                methods.append(ptr)
                offset += ptr_size
                
            # Valid vtable: 3+ consecutive code pointers
            if len(methods) >= 3:
                vtable_addr = base_address + i
                
                # Find cross-references to this vtable
                xrefs = self._find_vtable_xrefs(vtable_addr)
                
                # Calculate confidence based on method count and xref patterns
                confidence = self._calculate_vtable_confidence(methods, xrefs)
                
                vtable = VTable(
                    address=vtable_addr,
                    method_count=len(methods),
                    methods=methods,
                    xrefs=xrefs,
                    confidence=confidence
                )
                
                vtables.append(vtable)
                self.vtables[vtable_addr] = vtable
                
                i = offset  # Skip past this vtable
            else:
                i += ptr_size
                
        return vtables
    
    def _is_code_pointer(self, ptr: int, code_ranges: List[Tuple[int, int]]) -> bool:
        """Check if address points to code section"""
        return any(start <= ptr < end for start, end in code_ranges)
    
    def _find_vtable_xrefs(self, vtable_addr: int) -> List[int]:
        """Find where this vtable is referenced (constructor locations)"""
        try:
            result = self.mcp.call_tool("get_xrefs_to", {
                "address": hex(vtable_addr)
            })
            
            # Parse xref locations
            xrefs = []
            for xref in result.get("xrefs", []):
                xrefs.append(int(xref["from"], 16))
            
            return xrefs
        except:
            return []
    
    def _calculate_vtable_confidence(self, methods: List[int], 
                                     xrefs: List[int]) -> float:
        """
        Calculate confidence score for vtable detection
        
        Factors:
        - Method count (3-50 is typical)
        - Cross-reference count (constructors use vtable)
        - Method prologue patterns (push ebp; mov ebp, esp)
        """
        score = 0.0
        
        # Method count heuristic
        if 3 <= len(methods) <= 50:
            score += 0.4
        elif len(methods) > 50:
            score += 0.1  # Suspicious, might be false positive
        
        # Xref count (constructors)
        if len(xrefs) >= 1:
            score += min(0.3, len(xrefs) * 0.1)
        
        # Validate first few methods have function prologues
        valid_methods = sum(1 for m in methods[:5] if self._has_function_prologue(m))
        score += (valid_methods / 5) * 0.3
        
        return min(1.0, score)
    
    def _has_function_prologue(self, address: int) -> bool:
        """Check if address starts with common function prologue"""
        try:
            code = self.mcp.call_tool("get_code", {
                "address": hex(address),
                "length": 10
            })
            
            bytes_data = bytes.fromhex(code.get("bytes", ""))
            
            # Common x86 prologues
            prologues = [
                bytes([0x55, 0x8B, 0xEC]),           # push ebp; mov ebp, esp
                bytes([0x55, 0x89, 0xE5]),           # push ebp; mov ebp, esp (AT&T)
                bytes([0x48, 0x89, 0x5C, 0x24]),     # x64: mov [rsp+??], rbx
                bytes([0x40, 0x53]),                 # x64: push rbx (with REX)
            ]
            
            return any(bytes_data.startswith(p) for p in prologues)
        except:
            return False
    
    def build_class_hierarchy(self, vtables: List[VTable]) -> Dict[str, ClassHierarchy]:
        """
        Group vtables into classes and detect inheritance
        
        Inheritance detection:
        - VTable A contains prefix of VTable B → A is base class
        - Constructors that set multiple vtables → inheritance chain
        """
        classes = {}
        
        # Sort by method count (base classes typically have fewer methods)
        sorted_vtables = sorted(vtables, key=lambda v: v.method_count)
        
        for vtable in sorted_vtables:
            # Check if this extends another class
            base_classes = []
            for existing_addr, existing_vtable in self.vtables.items():
                if existing_addr == vtable.address:
                    continue
                
                # Check if vtable methods start with existing vtable methods
                if self._is_derived_vtable(vtable, existing_vtable):
                    base_class_name = self._get_class_name(existing_addr)
                    base_classes.append(base_class_name)
            
            # Generate class name
            class_name = self._get_class_name(vtable.address)
            
            # Get method names (or generate placeholders)
            virtual_methods = []
            for i, method_addr in enumerate(vtable.methods):
                method_name = self._get_method_name(method_addr, class_name, i)
                virtual_methods.append((method_addr, method_name))
            
            # Estimate object size by analyzing constructors
            size_estimate = self._estimate_class_size(vtable)
            
            classes[class_name] = ClassHierarchy(
                name=class_name,
                vtable_address=vtable.address,
                base_classes=base_classes,
                virtual_methods=virtual_methods,
                instances=vtable.xrefs,
                size_estimate=size_estimate
            )
        
        self.classes = classes
        return classes
    
    def _is_derived_vtable(self, derived: VTable, base: VTable) -> bool:
        """Check if derived vtable extends base vtable"""
        if derived.method_count < base.method_count:
            return False
        
        # Check if first N methods match
        matching = sum(
            1 for d, b in zip(derived.methods, base.methods) 
            if d == b
        )
        
        # At least 70% of base methods must match
        return (matching / base.method_count) >= 0.7
    
    def _get_class_name(self, vtable_addr: int) -> str:
        """Generate or retrieve class name from vtable address"""
        # Try to find RTTI string near vtable
        try:
            # Look for type_info structure (usually before vtable)
            strings = self.mcp.call_tool("list_strings", {})
            for s in strings.get("strings", []):
                s_addr = int(s["address"], 16)
                # RTTI typically within 0x100 bytes before vtable
                if vtable_addr - 0x100 <= s_addr <= vtable_addr:
                    return s["value"].strip()
        except:
            pass
        
        # Fallback: generate name from address
        return f"Class_{vtable_addr:08X}"
    
    def _get_method_name(self, method_addr: int, class_name: str, 
                        index: int) -> str:
        """Get or generate virtual method name"""
        try:
            func_info = self.mcp.call_tool("get_function_info", {
                "address": hex(method_addr)
            })
            
            existing_name = func_info.get("name", "")
            if existing_name and not existing_name.startswith("FUN_"):
                return existing_name
        except:
            pass
        
        # Generate semantic name based on index
        common_virtuals = [
            "destructor", "addref", "release",  # IUnknown pattern
            "update", "render", "on_destroy",   # Game engine pattern
        ]
        
        if index < len(common_virtuals):
            return f"{class_name}::{common_virtuals[index]}"
        else:
            return f"{class_name}::vmethod_{index}"
    
    def _estimate_class_size(self, vtable: VTable) -> int:
        """
        Estimate class size by analyzing constructor memory accesses
        
        Strategy:
        - Find constructors (functions that write vtable pointer)
        - Track highest offset written
        - That's minimum object size
        """
        max_offset = 4  # At least vtable pointer (4 bytes on x86)
        
        for xref_addr in vtable.xrefs[:5]:  # Check first 5 constructors
            try:
                # Get constructor code
                func_info = self.mcp.call_tool("get_function_info", {
                    "address": hex(xref_addr)
                })
                
                # Look for memory writes in constructor
                # Pattern: mov [eax+offset], value
                # This is simplified - real impl would decompile and analyze
                
                # Heuristic: constructors typically initialize 20-200 bytes
                max_offset = max(max_offset, 64)
            except:
                continue
        
        # Align to pointer size
        return (max_offset + 3) & ~3
    
    def export_to_cpp_headers(self, output_path: str):
        """Generate C++ header file with class definitions"""
        with open(output_path, 'w') as f:
            f.write("// Auto-generated class definitions\n")
            f.write("// Generated by VTable Analyzer\n\n")
            f.write("#pragma once\n\n")
            
            for class_name, cls in self.classes.items():
                # Write class declaration
                if cls.base_classes:
                    bases = ", public ".join(cls.base_classes)
                    f.write(f"class {class_name} : public {bases} {{\n")
                else:
                    f.write(f"class {class_name} {{\n")
                
                f.write("public:\n")
                
                # Write virtual methods
                for addr, method_name in cls.virtual_methods:
                    f.write(f"    virtual void {method_name}();  // @ 0x{addr:08X}\n")
                
                f.write(f"}}; // size: 0x{cls.size_estimate:X} (estimated)\n\n")
                
                # Write vtable address as comment
                f.write(f"// vtable @ 0x{cls.vtable_address:08X}\n")
                f.write(f"// instances: {len(cls.instances)}\n\n")
