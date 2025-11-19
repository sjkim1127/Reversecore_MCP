"""
Ghidra decompiler integration helper.

This module provides utilities for decompiling binaries using Ghidra's
DecompInterface API through PyGhidra.
"""

import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, TYPE_CHECKING

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Function

logger = get_logger(__name__)


def ensure_ghidra_available() -> bool:
    """
    Check if Ghidra and PyGhidra are available.
    
    Returns:
        True if Ghidra is available, False otherwise
    """
    try:
        import pyghidra  # noqa: F401
        return True
    except ImportError:
        return False


def decompile_function_with_ghidra(
    file_path: Path,
    function_address: str,
    timeout: int = 300
) -> Tuple[str, Dict[str, Any]]:
    """
    Decompile a function using Ghidra's decompiler.
    
    Args:
        file_path: Path to the binary file
        function_address: Function address (hex string or symbol name)
        timeout: Maximum execution time in seconds
        
    Returns:
        Tuple of (decompiled_code, metadata)
        
    Raises:
        ValidationError: If decompilation fails
        ImportError: If PyGhidra is not available
    """
    try:
        import pyghidra
        from ghidra.app.decompiler import DecompInterface, DecompileResults
    except ImportError as e:
        raise ImportError(
            "PyGhidra is not installed. Install with: pip install pyghidra"
        ) from e
    
    # Create temporary project directory
    with tempfile.TemporaryDirectory() as temp_dir:
        project_location = Path(temp_dir) / "ghidra_project"
        project_name = "temp_analysis"
        
        try:
            # Open program with PyGhidra
            logger.info(f"Opening binary with Ghidra: {file_path}")
            
            with pyghidra.open_program(
                str(file_path),
                project_location=str(project_location),
                project_name=project_name,
                analyze=True  # Run auto-analysis
            ) as flat_api:
                
                program = flat_api.getCurrentProgram()
                
                # Resolve function address
                function = _resolve_function(flat_api, function_address)
                
                if function is None:
                    raise ValidationError(
                        f"Could not find function at address: {function_address}",
                        details={"address": function_address}
                    )
                
                # Initialize decompiler
                decompiler = DecompInterface()
                decompiler.openProgram(program)
                
                try:
                    # Decompile the function
                    logger.info(f"Decompiling function: {function.getName()}")
                    
                    results: DecompileResults = decompiler.decompileFunction(
                        function,
                        timeout,
                        None  # monitor
                    )
                    
                    # Check for errors
                    if not results.decompileCompleted():
                        error_msg = results.getErrorMessage()
                        raise ValidationError(
                            f"Decompilation failed: {error_msg}",
                            details={
                                "function": function.getName(),
                                "address": function_address
                            }
                        )
                    
                    # Extract decompiled C code
                    decompiled_function = results.getDecompiledFunction()
                    c_code = decompiled_function.getC()
                    
                    # Extract metadata
                    high_function = results.getHighFunction()
                    metadata = {
                        "function_name": function.getName(),
                        "entry_point": str(function.getEntryPoint()),
                        "parameter_count": (
                            high_function.getFunctionPrototype().getNumParams()
                            if high_function else 0
                        ),
                        "local_symbol_count": (
                            high_function.getLocalSymbolMap().getNumSymbols()
                            if high_function else 0
                        ),
                        "signature": function.getSignature().getPrototypeString(),
                        "body_size": function.getBody().getNumAddresses(),
                        "decompiler": "ghidra"
                    }
                    
                    logger.info(f"Successfully decompiled {function.getName()}")
                    
                    return c_code, metadata
                    
                finally:
                    # Always dispose of decompiler resources
                    decompiler.dispose()
                    
        except Exception as e:
            logger.error(f"Ghidra decompilation failed: {e}", exc_info=True)
            raise


def _resolve_function(flat_api: "FlatProgramAPI", address_str: str) -> Optional["Function"]:
    """
    Resolve a function from an address string or symbol name.
    
    Args:
        flat_api: Ghidra FlatProgramAPI instance
        address_str: Address as hex string (e.g., "0x401000") or symbol name (e.g., "main")
        
    Returns:
        Function object or None if not found
    """
    program = flat_api.getCurrentProgram()
    function_manager = program.getFunctionManager()
    
    # Try as symbol name first
    symbol_table = program.getSymbolTable()
    symbols = symbol_table.getSymbols(address_str)
    
    if symbols.hasNext():
        symbol = symbols.next()
        address = symbol.getAddress()
        return function_manager.getFunctionAt(address)
    
    # Try as hex address
    try:
        # Remove 0x prefix if present
        addr_str = address_str.replace("0x", "").replace("0X", "")
        address = flat_api.toAddr(int(addr_str, 16))
        return function_manager.getFunctionAt(address)
    except (ValueError, Exception):
        pass
    
    # Try to find function containing this address
    try:
        addr_str = address_str.replace("0x", "").replace("0X", "")
        address = flat_api.toAddr(int(addr_str, 16))
        return function_manager.getFunctionContaining(address)
    except (ValueError, Exception):
        pass
    
    return None


def get_ghidra_version() -> Optional[str]:
    """
    Get the installed Ghidra version.
    
    Returns:
        Version string or None if not available
    """
    try:
        import pyghidra
        pyghidra.start()
        
        from ghidra import framework
        version = framework.Application.getApplicationVersion()
        return str(version)
    except Exception:
        return None


def recover_structures_with_ghidra(
    file_path: Path,
    function_address: str,
    timeout: int = 600
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Recover structure definitions from a function using Ghidra's data type analysis.
    
    This function analyzes a binary function to identify structure usage patterns
    and recover structure definitions with field names and types.
    
    Args:
        file_path: Path to the binary file
        function_address: Function address (hex string or symbol name)
        timeout: Maximum execution time in seconds
        
    Returns:
        Tuple of (structures_dict, metadata_dict)
        
    Raises:
        ValidationError: If structure recovery fails
        ImportError: If PyGhidra is not available
    """
    try:
        import pyghidra
        from ghidra.program.model.pcode import HighFunction, HighVariable
    except ImportError as e:
        raise ImportError(
            "PyGhidra is not installed. Install with: pip install pyghidra"
        ) from e
    
    # Create temporary project directory
    with tempfile.TemporaryDirectory() as temp_dir:
        project_location = Path(temp_dir) / "ghidra_project"
        project_name = "struct_analysis"
        
        try:
            # Open program with PyGhidra
            logger.info(f"Opening binary with Ghidra for structure recovery: {file_path}")
            
            with pyghidra.open_program(
                str(file_path),
                project_location=str(project_location),
                project_name=project_name,
                analyze=True  # Run auto-analysis for better structure detection
            ) as flat_api:
                
                program = flat_api.getCurrentProgram()
                
                # Resolve function address
                function = _resolve_function(flat_api, function_address)
                
                if function is None:
                    raise ValidationError(
                        f"Could not find function at address: {function_address}",
                        details={"address": function_address}
                    )
                
                # Initialize decompiler for high-level analysis
                from ghidra.app.decompiler import DecompInterface, DecompileResults
                
                decompiler = DecompInterface()
                decompiler.openProgram(program)
                
                try:
                    # Decompile the function to get high-level representation
                    logger.info(f"Analyzing structures in function: {function.getName()}")
                    
                    results: DecompileResults = decompiler.decompileFunction(
                        function,
                        timeout,
                        None
                    )
                    
                    if not results.decompileCompleted():
                        error_msg = results.getErrorMessage()
                        raise ValidationError(
                            f"Structure analysis failed: {error_msg}",
                            details={
                                "function": function.getName(),
                                "address": function_address
                            }
                        )
                    
                    # Extract structure information from high function
                    high_function: HighFunction = results.getHighFunction()
                    
                    if high_function is None:
                        raise ValidationError(
                            "Could not get high-level function representation",
                            details={"function": function.getName()}
                        )
                    
                    # Collect all data types used in the function
                    structures_found = {}
                    
                    # Analyze local variables for structure types
                    local_symbols = high_function.getLocalSymbolMap()
                    
                    for i in range(local_symbols.getNumSymbols()):
                        symbol = local_symbols.getSymbol(i)
                        high_var: HighVariable = symbol.getHighVariable()
                        
                        if high_var is not None:
                            data_type = high_var.getDataType()
                            
                            # Check if this is a structure or pointer to structure
                            if data_type is not None:
                                type_name = data_type.getName()
                                
                                # Look for structure types (including pointers to structures)
                                if "struct" in type_name.lower() or data_type.getLength() > 8:
                                    # Try to get the underlying structure
                                    actual_type = data_type
                                    
                                    # If it's a pointer, get the pointed-to type
                                    if hasattr(data_type, 'getDataType'):
                                        actual_type = data_type.getDataType()
                                    
                                    struct_name = actual_type.getName()
                                    
                                    if struct_name not in structures_found:
                                        # Extract structure fields
                                        fields = []
                                        
                                        if hasattr(actual_type, 'getNumComponents'):
                                            num_components = actual_type.getNumComponents()
                                            
                                            for j in range(num_components):
                                                component = actual_type.getComponent(j)
                                                field_name = component.getFieldName()
                                                field_type = component.getDataType().getName()
                                                field_offset = component.getOffset()
                                                field_size = component.getLength()
                                                
                                                fields.append({
                                                    "offset": f"0x{field_offset:x}",
                                                    "type": field_type,
                                                    "name": field_name if field_name else f"field_{field_offset:x}",
                                                    "size": field_size
                                                })
                                        
                                        structures_found[struct_name] = {
                                            "name": struct_name,
                                            "size": actual_type.getLength(),
                                            "fields": fields
                                        }
                    
                    # Also analyze function parameters for structure types
                    for param in function.getParameters():
                        param_type = param.getDataType()
                        
                        if param_type is not None:
                            type_name = param_type.getName()
                            
                            if "struct" in type_name.lower() and type_name not in structures_found:
                                # Extract parameter structure info
                                fields = []
                                
                                if hasattr(param_type, 'getNumComponents'):
                                    num_components = param_type.getNumComponents()
                                    
                                    for j in range(num_components):
                                        component = param_type.getComponent(j)
                                        field_name = component.getFieldName()
                                        field_type = component.getDataType().getName()
                                        field_offset = component.getOffset()
                                        field_size = component.getLength()
                                        
                                        fields.append({
                                            "offset": f"0x{field_offset:x}",
                                            "type": field_type,
                                            "name": field_name if field_name else f"field_{field_offset:x}",
                                            "size": field_size
                                        })
                                
                                structures_found[type_name] = {
                                    "name": type_name,
                                    "size": param_type.getLength(),
                                    "fields": fields
                                }
                    
                    # Generate C structure definitions
                    c_definitions = []
                    for struct_name, struct_data in structures_found.items():
                        if struct_data["fields"]:
                            fields_str = "\n    ".join([
                                f"{field['type']} {field['name']}; // offset {field['offset']}, size {field['size']}"
                                for field in struct_data["fields"]
                            ])
                            c_def = f"struct {struct_name} {{\n    {fields_str}\n}};"
                        else:
                            c_def = f"struct {struct_name} {{ /* size: {struct_data['size']} bytes */ }};"
                        
                        c_definitions.append(c_def)
                    
                    # Prepare result
                    result = {
                        "structures": list(structures_found.values()),
                        "c_definitions": "\n\n".join(c_definitions) if c_definitions else "// No structures found",
                        "count": len(structures_found)
                    }
                    
                    # Metadata
                    metadata = {
                        "function_name": function.getName(),
                        "entry_point": str(function.getEntryPoint()),
                        "structure_count": len(structures_found),
                        "analyzed_variables": local_symbols.getNumSymbols(),
                        "decompiler": "ghidra"
                    }
                    
                    logger.info(f"Successfully recovered {len(structures_found)} structure(s) from {function.getName()}")
                    
                    return result, metadata
                    
                finally:
                    # Always dispose of decompiler resources
                    decompiler.dispose()
                    
        except Exception as e:
            logger.error(f"Ghidra structure recovery failed: {e}", exc_info=True)
            raise
