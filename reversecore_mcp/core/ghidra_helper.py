"""
Ghidra decompiler integration helper.

This module provides utilities for decompiling binaries using Ghidra's
DecompInterface API through PyGhidra.
"""

import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


def ensure_ghidra_available() -> bool:
    """
    Check if Ghidra and PyGhidra are available.
    
    Returns:
        True if Ghidra is available, False otherwise
    """
    try:
        import pyghidra
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
        from ghidra.program.model.listing import Function
        from ghidra.program.flatapi import FlatProgramAPI
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
