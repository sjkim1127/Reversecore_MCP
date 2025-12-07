"""
Ghidra MCP Tools - Advanced binary analysis tools using Ghidra.

This module provides MCP tools for interacting with Ghidra's analysis capabilities
through the centralized GhidraService. It enables AI assistants to perform advanced 
binary analysis, reverse engineering, and code annotation tasks.

Features:
- Structure/Enum/Data Type management
- Bookmark management
- Memory reading and patching
- Call graph analysis
- Function analysis triggers

Performance:
- Uses singleton GhidraService with project caching
- JVM is started once and reused across calls
- Projects are cached with LRU eviction
"""

from typing import Any, Optional

from fastmcp import Context

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.ghidra import ghidra_service
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

DEFAULT_TIMEOUT = get_config().default_tool_timeout


# =============================================================================
# Helper Functions
# =============================================================================


def _get_ghidra_program(file_path: str):
    """
    Get Ghidra program using the cached GhidraService.
    
    Returns:
        Tuple of (program, flat_api) from cached project
    
    Raises:
        ImportError: If PyGhidra is not available
    """
    if not ghidra_service.is_available():
        raise ImportError("PyGhidra is not installed. Install with: pip install pyghidra")
    
    ghidra_service._ensure_jvm_started()
    program, flat_api, _ = ghidra_service._get_project(file_path)
    return program, flat_api


# =============================================================================
# Structure Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_list_structures(
    file_path: str,
    offset: int = 0,
    limit: int = 100,
    ctx: Context = None,
) -> ToolResult:
    """
    List all defined structures in the program.
    
    Uses cached Ghidra project for performance - first call loads the project,
    subsequent calls reuse the cached session.
    
    Args:
        file_path: Path to the binary file
        offset: Pagination offset (default: 0)
        limit: Maximum number of structures to return (default: 100)
        
    Returns:
        List of structure names with their sizes
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        data_type_manager = program.getDataTypeManager()
        
        structures = []
        all_data_types = data_type_manager.getAllStructures()
        
        idx = 0
        for dt in all_data_types:
            if idx < offset:
                idx += 1
                continue
            if len(structures) >= limit:
                break
                
            structures.append({
                "name": dt.getName(),
                "size": dt.getLength(),
                "category": str(dt.getCategoryPath()),
                "num_fields": dt.getNumComponents() if hasattr(dt, "getNumComponents") else 0,
            })
            idx += 1
        
        return success(
            {"structures": structures, "total": idx, "offset": offset, "limit": limit},
            description=f"Found {len(structures)} structures (cached project)",
        )
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("STRUCTURE_LIST_ERROR", str(e))


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_get_structure(
    file_path: str,
    name: str,
    ctx: Context = None,
) -> ToolResult:
    """
    Get detailed information about a specific structure.
    
    Args:
        file_path: Path to the binary file
        name: Name of the structure to retrieve
        
    Returns:
        Structure definition with all fields, offsets, and types
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        data_type_manager = program.getDataTypeManager()
        
        # Search for the structure
        found_struct = None
        for dt in data_type_manager.getAllStructures():
            if dt.getName() == name:
                found_struct = dt
                break
        
        if found_struct is None:
            return failure("STRUCTURE_NOT_FOUND", f"Structure '{name}' not found")
        
        # Extract fields
        fields = []
        if hasattr(found_struct, "getNumComponents"):
            for i in range(found_struct.getNumComponents()):
                component = found_struct.getComponent(i)
                fields.append({
                    "offset": f"0x{component.getOffset():x}",
                    "name": component.getFieldName() or f"field_{component.getOffset():x}",
                    "type": component.getDataType().getName(),
                    "size": component.getLength(),
                    "comment": component.getComment() or "",
                })
        
        # Generate C definition
        field_strs = [
            f"    {f['type']} {f['name']}; // offset {f['offset']}, size {f['size']}"
            for f in fields
        ]
        c_definition = f"struct {name} {{\n" + "\n".join(field_strs) + "\n};"
        
        return success({
            "name": name,
            "size": found_struct.getLength(),
            "category": str(found_struct.getCategoryPath()),
            "fields": fields,
            "c_definition": c_definition,
        })
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("STRUCTURE_GET_ERROR", str(e))


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_create_structure(
    file_path: str,
    name: str,
    fields: str,
    size: int = 0,
    ctx: Context = None,
) -> ToolResult:
    """
    Create a new structure definition.
    
    Args:
        file_path: Path to the binary file
        name: Name for the new structure
        fields: JSON string of fields, e.g., 
                '[{"name": "id", "type": "int", "offset": 0}, 
                  {"name": "data", "type": "char[32]", "offset": 4}]'
        size: Optional total size (0 = auto-calculate)
        
    Returns:
        Success message with created structure info
    """
    import json as stdlib_json
    
    validated_path = validate_file_path(file_path)
    
    try:
        field_list = stdlib_json.loads(fields)
    except stdlib_json.JSONDecodeError as e:
        return failure("INVALID_FIELDS_JSON", f"Invalid fields JSON: {e}")
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        
        from ghidra.program.model.data import StructureDataType, CategoryPath
        
        data_type_manager = program.getDataTypeManager()
        
        # Create structure
        struct = StructureDataType(CategoryPath.ROOT, name, size)
        
        # Add fields
        for field in field_list:
            field_name = field.get("name", "unknown")
            field_type_str = field.get("type", "byte")
            field_offset = field.get("offset", 0)
            
            # Get or create data type
            field_type = data_type_manager.getDataType(f"/{field_type_str}")
            if field_type is None:
                # Use default byte type
                from ghidra.program.model.data import ByteDataType
                field_type = ByteDataType.dataType
            
            struct.insertAtOffset(field_offset, field_type, field_type.getLength(), field_name, None)
        
        # Add to program
        transaction = program.startTransaction("Create Structure")
        try:
            data_type_manager.addDataType(struct, None)
            program.endTransaction(transaction, True)
        except Exception:
            program.endTransaction(transaction, False)
            raise
        
        return success({
            "name": name,
            "size": struct.getLength(),
            "fields_count": len(field_list),
        }, description=f"Created structure '{name}' with {len(field_list)} fields")
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("STRUCTURE_CREATE_ERROR", str(e))


# =============================================================================
# Enum Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_list_enums(
    file_path: str,
    offset: int = 0,
    limit: int = 100,
    ctx: Context = None,
) -> ToolResult:
    """
    List all defined enums in the program.
    
    Args:
        file_path: Path to the binary file
        offset: Pagination offset (default: 0)
        limit: Maximum number of enums to return (default: 100)
        
    Returns:
        List of enum names with their values
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        data_type_manager = program.getDataTypeManager()
        
        enums = []
        all_data_types = data_type_manager.getAllDataTypes()
        
        idx = 0
        for dt in all_data_types:
            # Check if it's an enum
            if not hasattr(dt, "getCount"):
                continue
                
            if idx < offset:
                idx += 1
                continue
            if len(enums) >= limit:
                break
            
            # Get enum values
            values = []
            try:
                for i in range(dt.getCount()):
                    values.append({
                        "name": dt.getName(i),
                        "value": dt.getValue(i),
                    })
            except Exception:
                pass
            
            enums.append({
                "name": dt.getName(),
                "size": dt.getLength(),
                "count": dt.getCount() if hasattr(dt, "getCount") else 0,
                "values": values[:10],  # Limit values shown
            })
            idx += 1
        
        return success(
            {"enums": enums, "total": idx, "offset": offset, "limit": limit},
            description=f"Found {len(enums)} enums",
        )
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("ENUM_LIST_ERROR", str(e))


# =============================================================================
# Data Type Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_list_data_types(
    file_path: str,
    category: str = None,
    offset: int = 0,
    limit: int = 100,
    ctx: Context = None,
) -> ToolResult:
    """
    List all data types in the program's data type manager.
    
    Args:
        file_path: Path to the binary file
        category: Optional category filter (e.g., "BuiltIn", "Structure", "Enum")
        offset: Pagination offset (default: 0)
        limit: Maximum number of types to return (default: 100)
        
    Returns:
        List of data type names with their categories and sizes
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        data_type_manager = program.getDataTypeManager()
        
        data_types = []
        all_types = data_type_manager.getAllDataTypes()
        
        idx = 0
        for dt in all_types:
            type_category = str(dt.getCategoryPath())
            
            # Apply category filter if specified
            if category and category.lower() not in type_category.lower():
                continue
                
            if idx < offset:
                idx += 1
                continue
            if len(data_types) >= limit:
                break
            
            data_types.append({
                "name": dt.getName(),
                "category": type_category,
                "size": dt.getLength(),
                "description": dt.getDescription() or "",
            })
            idx += 1
        
        return success(
            {"data_types": data_types, "total": idx, "offset": offset, "limit": limit},
            description=f"Found {len(data_types)} data types",
        )
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("DATA_TYPE_LIST_ERROR", str(e))


# =============================================================================
# Bookmark Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_list_bookmarks(
    file_path: str,
    bookmark_type: str = None,
    offset: int = 0,
    limit: int = 100,
    ctx: Context = None,
) -> ToolResult:
    """
    List all bookmarks in the program.
    
    Args:
        file_path: Path to the binary file
        bookmark_type: Optional type filter ("Note", "Warning", "Error", "Info")
        offset: Pagination offset (default: 0)
        limit: Maximum number of bookmarks to return (default: 100)
        
    Returns:
        List of bookmarks with addresses, types, and comments
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        bookmark_manager = program.getBookmarkManager()
        
        bookmarks = []
        all_bookmarks = bookmark_manager.getBookmarksIterator()
        
        idx = 0
        for bookmark in all_bookmarks:
            bm_type = bookmark.getTypeString()
            
            # Apply type filter
            if bookmark_type and bm_type.lower() != bookmark_type.lower():
                continue
                
            if idx < offset:
                idx += 1
                continue
            if len(bookmarks) >= limit:
                break
            
            bookmarks.append({
                "address": str(bookmark.getAddress()),
                "type": bm_type,
                "category": bookmark.getCategory(),
                "comment": bookmark.getComment(),
            })
            idx += 1
        
        return success(
            {"bookmarks": bookmarks, "total": idx, "offset": offset, "limit": limit},
            description=f"Found {len(bookmarks)} bookmarks",
        )
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("BOOKMARK_LIST_ERROR", str(e))


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_add_bookmark(
    file_path: str,
    address: str,
    category: str,
    comment: str,
    bookmark_type: str = "Note",
    ctx: Context = None,
) -> ToolResult:
    """
    Add a bookmark at the specified address.
    
    Args:
        file_path: Path to the binary file
        address: Address to bookmark (e.g., "0x1400010a0")
        category: Category for the bookmark (e.g., "Analysis", "TODO")
        comment: Comment/description for the bookmark
        bookmark_type: Type of bookmark ("Note", "Warning", "Error", "Info")
        
    Returns:
        Success message
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        bookmark_manager = program.getBookmarkManager()
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Add bookmark
        transaction = program.startTransaction("Add Bookmark")
        try:
            bookmark_manager.setBookmark(addr, bookmark_type, category, comment)
            program.endTransaction(transaction, True)
        except Exception:
            program.endTransaction(transaction, False)
            raise
        
        return success({
            "address": address,
            "type": bookmark_type,
            "category": category,
            "comment": comment,
        }, description=f"Added bookmark at {address}")
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("BOOKMARK_ADD_ERROR", str(e))


# =============================================================================
# Memory Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_read_memory(
    file_path: str,
    address: str,
    length: int = 256,
    ctx: Context = None,
) -> ToolResult:
    """
    Read raw bytes from memory at the specified address.
    
    Args:
        file_path: Path to the binary file
        address: Starting address (e.g., "0x1400010a0")
        length: Number of bytes to read (default: 256, max: 4096)
        
    Returns:
        Hex dump of memory contents
    """
    validated_path = validate_file_path(file_path)
    length = min(length, 4096)  # Cap at 4KB
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Read bytes
        byte_array = flat_api.getBytes(addr, length)
        
        if byte_array is None:
            return failure("MEMORY_READ_ERROR", f"Could not read memory at {address}")
        
        # Format as hex dump
        hex_bytes = " ".join(f"{b & 0xFF:02X}" for b in byte_array)
        
        # Format as hex dump with ASCII
        hex_dump_lines = []
        for i in range(0, len(byte_array), 16):
            chunk = byte_array[i:i+16]
            hex_part = " ".join(f"{b & 0xFF:02X}" for b in chunk)
            ascii_part = "".join(
                chr(b & 0xFF) if 32 <= (b & 0xFF) <= 126 else "."
                for b in chunk
            )
            line_addr = addr.add(i)
            hex_dump_lines.append(f"{line_addr}: {hex_part:<48} |{ascii_part}|")
        
        return success({
            "address": address,
            "length": len(byte_array),
            "hex_bytes": hex_bytes,
            "hex_dump": "\n".join(hex_dump_lines),
        })
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("MEMORY_READ_ERROR", str(e))


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_get_bytes(
    file_path: str,
    address: str,
    length: int = 64,
    ctx: Context = None,
) -> ToolResult:
    """
    Get bytes at the specified address as a hex string.
    
    Args:
        file_path: Path to the binary file
        address: Starting address (e.g., "0x1400010a0")
        length: Number of bytes to retrieve (default: 64, max: 1024)
        
    Returns:
        Hex string of bytes
    """
    validated_path = validate_file_path(file_path)
    length = min(length, 1024)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Read bytes
        byte_array = flat_api.getBytes(addr, length)
        
        if byte_array is None:
            return failure("MEMORY_READ_ERROR", f"Could not read bytes at {address}")
        
        hex_string = " ".join(f"{b & 0xFF:02X}" for b in byte_array)
        
        return success({
            "address": address,
            "length": len(byte_array),
            "bytes": hex_string,
        })
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("GET_BYTES_ERROR", str(e))


# =============================================================================
# Patching Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_patch_bytes(
    file_path: str,
    address: str,
    hex_bytes: str,
    ctx: Context = None,
) -> ToolResult:
    """
    Patch bytes at the specified address.
    
    WARNING: This modifies the binary in Ghidra's cached project (not the original file).
    Changes persist until the project is evicted from cache or server restarts.
    
    Args:
        file_path: Path to the binary file
        address: Starting address to patch (e.g., "0x1400010a0")
        hex_bytes: Hex string of bytes to write (e.g., "90 90 90" for NOPs)
        
    Returns:
        Success message with number of bytes patched
    """
    validated_path = validate_file_path(file_path)
    
    # Parse hex bytes
    try:
        hex_bytes_clean = hex_bytes.replace(" ", "").replace(",", "")
        if len(hex_bytes_clean) % 2 != 0:
            return failure("INVALID_HEX", "Hex string must have even length")
        
        byte_values = bytes.fromhex(hex_bytes_clean)
    except ValueError as e:
        return failure("INVALID_HEX", f"Invalid hex string: {e}")
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        memory = program.getMemory()
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Patch bytes
        transaction = program.startTransaction("Patch Bytes")
        try:
            for i, byte_val in enumerate(byte_values):
                memory.setByte(addr.add(i), byte_val)
            program.endTransaction(transaction, True)
        except Exception:
            program.endTransaction(transaction, False)
            raise
        
        return success({
            "address": address,
            "bytes_patched": len(byte_values),
            "new_bytes": hex_bytes,
        }, description=f"Patched {len(byte_values)} bytes at {address}")
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("PATCH_ERROR", str(e))


# =============================================================================
# Analysis Tools
# =============================================================================


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_analyze_function(
    file_path: str,
    address: str,
    ctx: Context = None,
) -> ToolResult:
    """
    Trigger Ghidra's analysis on a specific function.
    
    Useful after making changes or for functions that weren't fully analyzed.
    
    Args:
        file_path: Path to the binary file
        address: Address of the function to analyze (e.g., "0x1400010a0")
        
    Returns:
        Analysis result summary with function details
    """
    validated_path = validate_file_path(file_path)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        
        from ghidra.app.cmd.function import CreateFunctionCmd
        
        function_manager = program.getFunctionManager()
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Check if function exists
        func = function_manager.getFunctionAt(addr)
        
        transaction = program.startTransaction("Analyze Function")
        try:
            if func is None:
                # Try to create function
                cmd = CreateFunctionCmd(addr)
                cmd.applyTo(program)
                func = function_manager.getFunctionAt(addr)
            
            if func is None:
                program.endTransaction(transaction, False)
                return failure("FUNCTION_NOT_FOUND", f"Could not find or create function at {address}")
            
            # Get function info
            result = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "signature": str(func.getSignature()),
                "body_size": func.getBody().getNumAddresses(),
                "parameter_count": func.getParameterCount(),
                "local_variable_count": len(list(func.getLocalVariables())),
                "calling_convention": str(func.getCallingConvention()),
            }
            
            program.endTransaction(transaction, True)
            
            return success(result, description=f"Analyzed function '{func.getName()}'")
            
        except Exception:
            program.endTransaction(transaction, False)
            raise
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("ANALYZE_ERROR", str(e))


@handle_tool_errors
@log_execution
@track_metrics
async def Ghidra_get_call_graph(
    file_path: str,
    address: str,
    depth: int = 3,
    direction: str = "both",
    ctx: Context = None,
) -> ToolResult:
    """
    Get the call graph for a function.
    
    Args:
        file_path: Path to the binary file
        address: Address of the function (e.g., "0x1400010a0")
        depth: How many levels deep to traverse (default: 3, max: 10)
        direction: "callers" (who calls this), "callees" (what this calls), or "both"
        
    Returns:
        Call graph showing function relationships
    """
    validated_path = validate_file_path(file_path)
    depth = min(depth, 10)
    
    try:
        program, flat_api = _get_ghidra_program(str(validated_path))
        
        function_manager = program.getFunctionManager()
        reference_manager = program.getReferenceManager()
        
        # Parse address
        addr = flat_api.toAddr(address)
        if addr is None:
            return failure("INVALID_ADDRESS", f"Could not parse address: {address}")
        
        # Get function
        func = function_manager.getFunctionAt(addr)
        if func is None:
            func = function_manager.getFunctionContaining(addr)
        
        if func is None:
            return failure("FUNCTION_NOT_FOUND", f"No function at {address}")
        
        root_name = func.getName()
        root_addr = str(func.getEntryPoint())
        
        callers = []
        callees = []
        
        # Get callers (functions that call this function)
        if direction in ("callers", "both"):
            refs_to = reference_manager.getReferencesTo(func.getEntryPoint())
            seen_callers = set()
            
            for ref in refs_to:
                if ref.getReferenceType().isCall():
                    caller_func = function_manager.getFunctionContaining(ref.getFromAddress())
                    if caller_func and caller_func.getName() not in seen_callers:
                        seen_callers.add(caller_func.getName())
                        callers.append({
                            "name": caller_func.getName(),
                            "address": str(caller_func.getEntryPoint()),
                        })
        
        # Get callees (functions this function calls)
        if direction in ("callees", "both"):
            func_body = func.getBody()
            seen_callees = set()
            
            for addr_range in func_body:
                refs_from = reference_manager.getReferencesFrom(addr_range)
                for ref in refs_from:
                    if ref.getReferenceType().isCall():
                        callee_func = function_manager.getFunctionAt(ref.getToAddress())
                        if callee_func and callee_func.getName() not in seen_callees:
                            seen_callees.add(callee_func.getName())
                            callees.append({
                                "name": callee_func.getName(),
                                "address": str(callee_func.getEntryPoint()),
                            })
        
        # Build graph representation
        graph_lines = [f"Call Graph for {root_name} ({root_addr})", "=" * 50]
        
        if callers:
            graph_lines.append(f"\n📥 Callers ({len(callers)}):")
            for c in callers[:20]:  # Limit output
                graph_lines.append(f"  ← {c['name']} ({c['address']})")
        
        graph_lines.append(f"\n🎯 {root_name} ({root_addr})")
        
        if callees:
            graph_lines.append(f"\n📤 Callees ({len(callees)}):")
            for c in callees[:20]:
                graph_lines.append(f"  → {c['name']} ({c['address']})")
        
        return success({
            "function": root_name,
            "address": root_addr,
            "callers": callers,
            "callees": callees,
            "caller_count": len(callers),
            "callee_count": len(callees),
            "graph": "\n".join(graph_lines),
        })
        
    except ImportError as e:
        return failure("GHIDRA_NOT_AVAILABLE", str(e))
    except Exception as e:
        ghidra_service._invalidate_project(str(validated_path))
        return failure("CALL_GRAPH_ERROR", str(e))


# =============================================================================
# Plugin Registration
# =============================================================================


class GhidraToolsPlugin(Plugin):
    """Plugin for advanced Ghidra analysis tools."""

    @property
    def name(self) -> str:
        return "ghidra_tools"

    @property
    def description(self) -> str:
        return "Advanced Ghidra analysis tools using cached GhidraService for structures, enums, memory, and call graphs."

    def register(self, mcp_server: Any) -> None:
        """Register Ghidra tools."""
        # Structure tools
        mcp_server.tool(Ghidra_list_structures)
        mcp_server.tool(Ghidra_get_structure)
        mcp_server.tool(Ghidra_create_structure)
        
        # Enum tools
        mcp_server.tool(Ghidra_list_enums)
        
        # Data type tools
        mcp_server.tool(Ghidra_list_data_types)
        
        # Bookmark tools
        mcp_server.tool(Ghidra_list_bookmarks)
        mcp_server.tool(Ghidra_add_bookmark)
        
        # Memory tools
        mcp_server.tool(Ghidra_read_memory)
        mcp_server.tool(Ghidra_get_bytes)
        
        # Patching tools
        mcp_server.tool(Ghidra_patch_bytes)
        
        # Analysis tools
        mcp_server.tool(Ghidra_analyze_function)
        mcp_server.tool(Ghidra_get_call_graph)

        # =====================================================================
        # Decompilation Tools (from decompilation module)
        # =====================================================================
        from reversecore_mcp.tools.ghidra.decompilation import (
            emulate_machine_code,
            get_pseudo_code,
            smart_decompile,
            recover_structures,
        )
        mcp_server.tool(emulate_machine_code)
        mcp_server.tool(get_pseudo_code)
        mcp_server.tool(smart_decompile)
        mcp_server.tool(recover_structures)

        logger.info(f"Registered {self.name} plugin with 17 Ghidra tools (unified)")

