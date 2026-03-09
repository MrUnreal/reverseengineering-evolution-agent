"""
Type Propagator - Infer structure field types from usage patterns
"""
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class FieldType(Enum):
    """Possible field types"""
    UNKNOWN = 0
    INT8 = 1
    INT16 = 2
    INT32 = 3
    INT64 = 4
    FLOAT = 5
    DOUBLE = 6
    POINTER = 7
    STRING = 8
    VECTOR3 = 9    # float[3]
    VECTOR4 = 10   # float[4]
    MATRIX = 11    # float[16]
    BOOL = 12


@dataclass
class FieldAccess:
    """Record of a field being accessed"""
    offset: int
    size: int
    access_type: str  # 'read', 'write', 'call'
    location: int     # Address where access happens
    context: str      # Function name or description


@dataclass
class StructureField:
    """Inferred structure field"""
    offset: int
    size: int
    type: FieldType
    name: str
    confidence: float
    accesses: List[FieldAccess] = field(default_factory=list)


@dataclass
class Structure:
    """Complete structure definition"""
    name: str
    size: int
    fields: List[StructureField]
    base_structures: List[str] = field(default_factory=list)
    confidence: float = 0.0


class TypePropagator:
    """
    Infers structure fields by tracking how memory is accessed
    
    Example:
      mov eax, [ecx+0x10]
      movss xmm0, [eax+0x0]
      movss xmm1, [eax+0x4]
      movss xmm2, [eax+0x8]
      → Infers: ecx+0x10 is pointer to Vector3
    """
    
    def __init__(self, mcp_client):
        self.mcp = mcp_client
        self.structures: Dict[str, Structure] = {}
        self.field_accesses: Dict[Tuple[str, int], List[FieldAccess]] = {}
    
    def analyze_function_for_structure_access(self, function_addr: int, 
                                               param_index: int,
                                               structure_name: str) -> List[FieldAccess]:
        """
        Analyze a function to find how it accesses a structure parameter
        
        Args:
            function_addr: Address of function to analyze
            param_index: Which parameter is the structure (0 = first param)
            structure_name: Name to assign to structure
        
        Returns:
            List of field accesses discovered
        """
        accesses = []
        
        try:
            # Get function code
            func_info = self.mcp.call_tool("get_function_info", {
                "address": hex(function_addr)
            })
            
            # Get decompiled code for easier analysis
            code = self.mcp.call_tool("get_code", {
                "address": hex(function_addr),
                "decompile": True
            })
            
            # Parse decompiled code for structure accesses
            # Pattern: param_name->field or *(param + offset)
            lines = code.get("decompiled", "").split('\n')
            
            for line in lines:
                # Look for memory access patterns
                # Example: "float x = entity->position.x;" or "*(entity + 0x10)"
                
                # This is simplified - real implementation would use Ghidra's
                # data flow analysis and Pcode to track parameter usage
                
                if '->' in line or '+' in line:
                    # Try to extract offset and type
                    access = self._parse_memory_access(line, param_index)
                    if access:
                        access.location = function_addr
                        access.context = func_info.get("name", f"FUN_{function_addr:08X}")
                        accesses.append(access)
                        
                        # Store in global access map
                        key = (structure_name, access.offset)
                        self.field_accesses.setdefault(key, []).append(access)
            
        except Exception as e:
            print(f"Error analyzing function 0x{function_addr:08X}: {e}")
        
        return accesses
    
    def _parse_memory_access(self, line: str, param_index: int) -> Optional[FieldAccess]:
        """
        Parse decompiled line to extract memory access
        
        Example lines:
          "iVar1 = *(int *)(param_1 + 0x10);"
          "entity->health = 100;"
          "memcpy(param_2 + 0x20, src, 12);"
        """
        # Simplified pattern matching
        # Real implementation would use Ghidra's HighVariable and Varnode analysis
        
        import re
        
        # Pattern: *(type *)(param_N + offset)
        pattern = rf'param_{param_index}\s*\+\s*(0x[0-9a-fA-F]+)'
        match = re.search(pattern, line)
        
        if match:
            offset = int(match.group(1), 16)
            
            # Infer size from type
            if 'float' in line.lower():
                size, ftype = 4, FieldType.FLOAT
            elif 'double' in line.lower():
                size, ftype = 8, FieldType.DOUBLE
            elif 'char *' in line or 'string' in line.lower():
                size, ftype = 4, FieldType.POINTER  # Pointer to string
            elif 'int64' in line or 'long long' in line:
                size, ftype = 8, FieldType.INT64
            elif 'short' in line:
                size, ftype = 2, FieldType.INT16
            elif 'byte' in line or 'char' in line:
                size, ftype = 1, FieldType.INT8
            else:
                size, ftype = 4, FieldType.INT32  # Default
            
            # Determine if read or write
            if '=' in line and line.index('=') > line.index(f'param_{param_index}'):
                access_type = 'read'
            else:
                access_type = 'write'
            
            return FieldAccess(
                offset=offset,
                size=size,
                access_type=access_type,
                location=0,  # Set by caller
                context=""   # Set by caller
            )
        
        return None
    
    def propagate_types_across_calls(self, structure_name: str, 
                                     seed_functions: List[int]):
        """
        Follow function calls to propagate structure type information
        
        If function A calls function B and passes structure parameter,
        analyze B to discover more fields.
        """
        analyzed = set()
        queue = list(seed_functions)
        
        while queue:
            func_addr = queue.pop(0)
            if func_addr in analyzed:
                continue
            
            analyzed.add(func_addr)
            
            # Analyze this function
            accesses = self.analyze_function_for_structure_access(
                func_addr, 0, structure_name
            )
            
            # Find callees that might receive structure
            try:
                callees = self.mcp.call_tool("get_call_graph", {
                    "address": hex(func_addr),
                    "depth": 1
                })
                
                for callee in callees.get("callees", []):
                    callee_addr = int(callee["address"], 16)
                    if callee_addr not in analyzed:
                        queue.append(callee_addr)
                        
            except:
                pass
    
    def synthesize_structure(self, structure_name: str) -> Structure:
        """
        Combine all observed field accesses into coherent structure
        
        Steps:
        1. Group accesses by offset
        2. Resolve type conflicts (same offset, different types)
        3. Infer field names from context
        4. Calculate confidence scores
        """
        # Collect all unique offsets
        offset_groups: Dict[int, List[FieldAccess]] = {}
        
        for (struct_name, offset), accesses in self.field_accesses.items():
            if struct_name == structure_name:
                offset_groups.setdefault(offset, []).extend(accesses)
        
        # Synthesize fields
        fields = []
        for offset in sorted(offset_groups.keys()):
            accesses = offset_groups[offset]
            
            # Resolve type conflicts
            field_type = self._resolve_type_conflict(accesses)
            
            # Determine size
            sizes = [a.size for a in accesses]
            field_size = max(sizes) if sizes else 4
            
            # Generate field name
            field_name = self._generate_field_name(offset, accesses, field_type)
            
            # Calculate confidence
            confidence = self._calculate_field_confidence(accesses, field_type)
            
            fields.append(StructureField(
                offset=offset,
                size=field_size,
                type=field_type,
                name=field_name,
                confidence=confidence,
                accesses=accesses
            ))
        
        # Calculate total structure size
        if fields:
            last_field = max(fields, key=lambda f: f.offset + f.size)
            total_size = last_field.offset + last_field.size
            # Align to pointer size
            total_size = (total_size + 3) & ~3
        else:
            total_size = 0
        
        structure = Structure(
            name=structure_name,
            size=total_size,
            fields=fields,
            confidence=sum(f.confidence for f in fields) / len(fields) if fields else 0.0
        )
        
        self.structures[structure_name] = structure
        return structure
    
    def _resolve_type_conflict(self, accesses: List[FieldAccess]) -> FieldType:
        """
        When same offset accessed as different types, pick most likely
        
        Priority:
        1. Specific types (Vector3, String) over generic (INT32)
        2. Type with most occurrences
        3. Type from most recent access
        """
        # Count type occurrences
        type_counts: Dict[FieldType, int] = {}
        for access in accesses:
            # Infer type from size and context
            inferred = self._infer_type_from_access(access)
            type_counts[inferred] = type_counts.get(inferred, 0) + 1
        
        # Prioritize specific types
        specific_types = {FieldType.VECTOR3, FieldType.VECTOR4, FieldType.STRING, 
                         FieldType.MATRIX, FieldType.POINTER}
        
        for ftype in specific_types:
            if ftype in type_counts:
                return ftype
        
        # Return most common type
        if type_counts:
            return max(type_counts, key=type_counts.get)
        
        return FieldType.UNKNOWN
    
    def _infer_type_from_access(self, access: FieldAccess) -> FieldType:
        """Infer field type from how it's accessed"""
        # Check context for hints
        ctx_lower = access.context.lower()
        
        if 'position' in ctx_lower or 'vector' in ctx_lower:
            return FieldType.VECTOR3
        elif 'string' in ctx_lower or 'name' in ctx_lower:
            return FieldType.STRING
        elif 'matrix' in ctx_lower or 'transform' in ctx_lower:
            return FieldType.MATRIX
        elif 'bool' in ctx_lower or 'flag' in ctx_lower:
            return FieldType.BOOL
        
        # Infer from size
        size_to_type = {
            1: FieldType.INT8,
            2: FieldType.INT16,
            4: FieldType.INT32,
            8: FieldType.INT64,
        }
        
        return size_to_type.get(access.size, FieldType.UNKNOWN)
    
    def _generate_field_name(self, offset: int, accesses: List[FieldAccess], 
                            field_type: FieldType) -> str:
        """Generate semantic field name from usage context"""
        # Look for common patterns in access contexts
        contexts = [a.context.lower() for a in accesses]
        
        # Common game engine field names
        keywords = {
            'position': ['pos', 'position', 'location'],
            'rotation': ['rot', 'rotation', 'angle', 'orientation'],
            'scale': ['scale', 'size'],
            'velocity': ['vel', 'velocity', 'speed'],
            'health': ['hp', 'health', 'hitpoint'],
            'name': ['name', 'label', 'string'],
            'id': ['id', 'index', 'handle'],
            'parent': ['parent', 'owner'],
            'children': ['child', 'children'],
        }
        
        for field_name, patterns in keywords.items():
            if any(any(p in ctx for p in patterns) for ctx in contexts):
                return field_name
        
        # Fallback: type-based name
        type_names = {
            FieldType.VECTOR3: 'vector',
            FieldType.FLOAT: 'value',
            FieldType.INT32: 'field',
            FieldType.POINTER: 'ptr',
            FieldType.STRING: 'str',
        }
        
        base_name = type_names.get(field_type, 'field')
        return f"{base_name}_{offset:02X}"
    
    def _calculate_field_confidence(self, accesses: List[FieldAccess], 
                                    field_type: FieldType) -> float:
        """Calculate confidence score for field definition"""
        score = 0.0
        
        # More accesses = higher confidence
        score += min(0.4, len(accesses) * 0.1)
        
        # Consistent types across accesses = higher confidence
        inferred_types = [self._infer_type_from_access(a) for a in accesses]
        type_consistency = sum(1 for t in inferred_types if t == field_type) / len(inferred_types)
        score += type_consistency * 0.3
        
        # Both reads and writes = higher confidence
        has_read = any(a.access_type == 'read' for a in accesses)
        has_write = any(a.access_type == 'write' for a in accesses)
        if has_read and has_write:
            score += 0.3
        
        return min(1.0, score)
    
    def export_to_c_header(self, structure_name: str, output_path: str):
        """Generate C structure definition"""
        structure = self.structures.get(structure_name)
        if not structure:
            return
        
        with open(output_path, 'w') as f:
            f.write("// Auto-generated structure definition\n")
            f.write(f"// Confidence: {structure.confidence:.1%}\n\n")
            
            if structure.base_structures:
                f.write(f"// Inherits from: {', '.join(structure.base_structures)}\n\n")
            
            f.write(f"struct {structure_name} {{\n")
            
            prev_end = 0
            for field in sorted(structure.fields, key=lambda f: f.offset):
                # Add padding if needed
                if field.offset > prev_end:
                    padding_size = field.offset - prev_end
                    f.write(f"    char _pad{prev_end:02X}[{padding_size}];  // padding\n")
                
                # Write field
                type_str = self._field_type_to_c(field.type, field.size)
                f.write(f"    {type_str} {field.name};  "
                       f"// offset 0x{field.offset:02X}, confidence: {field.confidence:.0%}\n")
                
                prev_end = field.offset + field.size
            
            f.write(f"}};  // size: 0x{structure.size:X}\n")
    
    def _field_type_to_c(self, field_type: FieldType, size: int) -> str:
        """Convert FieldType to C type string"""
        mappings = {
            FieldType.INT8: 'int8_t',
            FieldType.INT16: 'int16_t',
            FieldType.INT32: 'int32_t',
            FieldType.INT64: 'int64_t',
            FieldType.FLOAT: 'float',
            FieldType.DOUBLE: 'double',
            FieldType.POINTER: 'void*',
            FieldType.STRING: 'char*',
            FieldType.VECTOR3: 'float[3]',
            FieldType.VECTOR4: 'float[4]',
            FieldType.MATRIX: 'float[16]',
            FieldType.BOOL: 'bool',
        }
        
        return mappings.get(field_type, f'uint8_t[{size}]')
