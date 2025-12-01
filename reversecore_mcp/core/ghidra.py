"""
Ghidra Integration Module

This module provides a unified interface for Ghidra decompilation and analysis.
It consolidates functionality from the previous ghidra_helper.py and ghidra_manager.py
to provide:
- JVM lifecycle management (singleton pattern)
- Project caching for performance
- Decompilation and structure recovery APIs
- Thread-safe operations

Usage:
    from reversecore_mcp.core.ghidra import ghidra_service

    # Check availability
    if ghidra_service.is_available():
        code = await ghidra_service.decompile_async(file_path, function_address)
"""

import asyncio
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout

if TYPE_CHECKING:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Function

logger = get_logger(__name__)

# Pre-compiled pattern for hex prefix removal
_HEX_PREFIX_PATTERN = re.compile(r"^0[xX]")


class GhidraService:
    """
    Unified Ghidra service for decompilation and analysis.

    This singleton class manages:
    - JVM lifecycle (started once, reused)
    - Project caching (LRU eviction)
    - Thread-safe operations
    - Async wrapper methods
    """

    _instance: Optional["GhidraService"] = None
    _lock = threading.RLock()

    def __new__(cls) -> "GhidraService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return

        self._jvm_started = False
        self._projects: dict[str, Any] = {}
        self._project_lock = threading.RLock()
        self._max_projects = 1  # Limit to prevent OOM
        self._pyghidra = None
        self._flat_program_api = None
        self._initialized = True

    def is_available(self) -> bool:
        """Check if Ghidra and PyGhidra are available."""
        try:
            import pyghidra  # noqa: F401

            return True
        except ImportError:
            return False

    def _configure_environment(self) -> None:
        """Configure environment variables for Ghidra (JAVA_HOME, etc.)."""
        if os.environ.get("JAVA_HOME"):
            return

        java_path = shutil.which("java")
        if java_path:
            try:
                real_path = Path(java_path).resolve()
                if real_path.name == "java" and real_path.parent.name == "bin":
                    java_home = real_path.parent.parent
                    os.environ["JAVA_HOME"] = str(java_home)
                    logger.info(f"Set JAVA_HOME to {java_home}")
            except Exception as e:
                logger.warning(f"Failed to resolve JAVA_HOME: {e}")

    def _ensure_jvm_started(self) -> None:
        """Start the JVM if not already started."""
        if self._jvm_started:
            return

        with self._lock:
            if self._jvm_started:
                return

            try:
                import pyghidra

                self._configure_environment()

                # OPTIMIZATION: Configure JVM for large binary analysis
                # Memory settings optimized for modern systems (24-32GB RAM)
                jvm_args = [
                    "-Xms2g",  # Initial heap size (2GB)
                    "-Xmx16g",  # Maximum heap size (16GB) - handles very large binaries
                    "-XX:+UseG1GC",  # G1 garbage collector (better for large heaps)
                    "-XX:MaxGCPauseMillis=200",  # Limit GC pause time
                    "-XX:+ParallelRefProcEnabled",  # Parallel reference processing
                    "-XX:G1HeapRegionSize=32m",  # Larger regions for big objects
                    "-XX:InitiatingHeapOccupancyPercent=35",  # Start GC earlier
                ]

                logger.info("Starting Ghidra JVM...")
                try:
                    pyghidra.start(jvm_args=jvm_args)
                except Exception as e:
                    logger.debug(f"pyghidra.start() result: {e}")

                self._pyghidra = pyghidra
                self._jvm_started = True
                logger.info("Ghidra JVM started successfully")

            except ImportError:
                logger.error("pyghidra not installed")
                raise ImportError("pyghidra not installed. Install with: pip install pyghidra")
            except Exception as e:
                logger.error(f"Failed to start Ghidra JVM: {e}")
                raise

    def _get_project(self, file_path: str) -> tuple[Any, Any, Any]:
        """Get or load a cached project for the given file."""
        with self._project_lock:
            if file_path in self._projects:
                val = self._projects.pop(file_path)
                self._projects[file_path] = val
                return val

            # Evict if needed (LRU)
            if len(self._projects) >= self._max_projects:
                oldest_path, _ = self._projects.popitem()
                logger.info(f"Evicting Ghidra project: {oldest_path}")

            logger.info(f"Loading Ghidra project: {file_path}")
            ctx = self._pyghidra.open_program(file_path)
            flat_api = ctx.__enter__()
            program = flat_api.getCurrentProgram()

            self._projects[file_path] = (program, flat_api, ctx)
            return program, flat_api, ctx

    def _invalidate_project(self, file_path: str) -> None:
        """Remove a project from cache on error."""
        with self._project_lock:
            if file_path in self._projects:
                del self._projects[file_path]

    def _resolve_function(
        self, flat_api: "FlatProgramAPI", address_str: str, create_if_missing: bool = True
    ) -> Optional["Function"]:
        """
        Resolve a function from address string or symbol name.

        Args:
            flat_api: Ghidra FlatProgramAPI instance
            address_str: Function address (hex) or symbol name
            create_if_missing: If True, create a function at the address if none exists
        """
        program = flat_api.getCurrentProgram()
        function_manager = program.getFunctionManager()

        # Try as symbol name first
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getSymbols(address_str)

        if symbols.hasNext():
            symbol = symbols.next()
            address = symbol.getAddress()
            func = function_manager.getFunctionAt(address)
            if func is not None:
                return func

        # Try as hex address
        addr_str = _HEX_PREFIX_PATTERN.sub("", address_str)
        address = None

        try:
            address = flat_api.toAddr(int(addr_str, 16))
            func = function_manager.getFunctionAt(address)
            if func is not None:
                return func
        except (ValueError, Exception):
            pass

        # Try to find function containing this address
        if address is not None:
            try:
                func = function_manager.getFunctionContaining(address)
                if func is not None:
                    return func
            except Exception:
                pass

        # If no function found and create_if_missing, create one at the address
        # This is needed when analyze=False (no auto function detection)
        if create_if_missing and address is not None:
            try:
                logger.info(f"Creating function at address: {address}")
                func = flat_api.createFunction(address, None)  # Auto-generate name
                if func is not None:
                    return func
            except Exception as e:
                logger.debug(f"Failed to create function: {e}")

        return None

    def _extract_structure_fields(self, data_type) -> list:
        """Extract fields from a Ghidra data type structure."""
        fields = []

        if not hasattr(data_type, "getNumComponents"):
            return fields

        num_components = data_type.getNumComponents()

        for j in range(num_components):
            component = data_type.getComponent(j)
            field_name = component.getFieldName()
            field_type = component.getDataType().getName()
            field_offset = component.getOffset()
            field_size = component.getLength()

            fields.append(
                {
                    "offset": f"0x{field_offset:x}",
                    "type": field_type,
                    "name": field_name if field_name else f"field_{field_offset:x}",
                    "size": field_size,
                }
            )

        return fields

    def decompile(
        self,
        file_path: str,
        function_address: str | None = None,
        timeout: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """
        Decompile a function using Ghidra.

        Args:
            file_path: Path to the binary file
            function_address: Function address (hex string or symbol name)
            timeout: Maximum execution time in seconds (uses dynamic timeout if None)

        Returns:
            Tuple of (decompiled_code, metadata)

        Raises:
            ValidationError: If decompilation fails
            ImportError: If PyGhidra is not available
        """
        # Calculate dynamic timeout based on file size
        effective_timeout = (
            timeout if timeout else calculate_dynamic_timeout(file_path, base_timeout=300)
        )

        self._ensure_jvm_started()

        with self._lock:
            try:
                program, flat_api, _ = self._get_project(file_path)

                from ghidra.app.decompiler import DecompInterface
                from ghidra.util.task import ConsoleTaskMonitor

                decompiler = DecompInterface()
                decompiler.openProgram(program)
                monitor = ConsoleTaskMonitor()

                try:
                    if not function_address:
                        return "// Please specify a function address", {}

                    function = self._resolve_function(flat_api, function_address)

                    if function is None:
                        raise ValidationError(
                            f"Could not find function at address: {function_address}",
                            details={"address": function_address},
                        )

                    logger.info(f"Decompiling function: {function.getName()}")
                    results = decompiler.decompileFunction(function, effective_timeout, monitor)

                    if not results.decompileCompleted():
                        error_msg = results.getErrorMessage()
                        raise ValidationError(
                            f"Decompilation failed: {error_msg}",
                            details={
                                "function": function.getName(),
                                "address": function_address,
                            },
                        )

                    decompiled_function = results.getDecompiledFunction()
                    c_code = decompiled_function.getC()

                    high_function = results.getHighFunction()
                    metadata = {
                        "function_name": function.getName(),
                        "entry_point": str(function.getEntryPoint()),
                        "parameter_count": (
                            high_function.getFunctionPrototype().getNumParams()
                            if high_function
                            else 0
                        ),
                        "local_symbol_count": (
                            high_function.getLocalSymbolMap().getNumSymbols()
                            if high_function
                            else 0
                        ),
                        "signature": function.getSignature().getPrototypeString(),
                        "body_size": function.getBody().getNumAddresses(),
                        "decompiler": "ghidra",
                    }

                    logger.info(f"Successfully decompiled {function.getName()}")
                    return c_code, metadata

                finally:
                    decompiler.dispose()

            except Exception as e:
                logger.error(f"Ghidra decompilation failed: {e}")
                self._invalidate_project(file_path)
                raise

    async def decompile_async(
        self,
        file_path: str,
        function_address: str | None = None,
        timeout: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Execute decompilation asynchronously with dynamic timeout."""
        return await asyncio.to_thread(self.decompile, file_path, function_address, timeout)

    def recover_structures(
        self,
        file_path: str,
        function_address: str,
        timeout: int | None = None,
        skip_full_analysis: bool = True,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """
        Recover structure definitions from a function.

        Args:
            file_path: Path to the binary file
            function_address: Function address (hex string or symbol name)
            timeout: Maximum execution time in seconds (uses dynamic timeout if None)
            skip_full_analysis: Skip full binary analysis for faster startup (default True)
                               The decompiler performs targeted analysis on the function.

        Returns:
            Tuple of (structures_dict, metadata_dict)

        Performance Notes:
            - skip_full_analysis=True (default): ~30-60 seconds for large binaries
            - skip_full_analysis=False: Can take 10+ minutes, uses more memory
            - For repeated analysis of same binary, results are cached in JVM
        """
        # Calculate dynamic timeout based on file size
        effective_timeout = (
            timeout if timeout else calculate_dynamic_timeout(file_path, base_timeout=300)
        )

        self._ensure_jvm_started()

        with tempfile.TemporaryDirectory() as temp_dir:
            project_location = Path(temp_dir) / "ghidra_project"
            project_name = "struct_analysis"

            try:
                logger.info(
                    f"Analyzing structures in: {file_path} (skip_full_analysis={skip_full_analysis})"
                )

                # OPTIMIZATION: Always skip full analysis for structure recovery
                # The decompiler performs targeted analysis on the specific function
                # Full analysis is rarely needed and extremely slow on large binaries
                analyze = False  # Force skip - decompiler handles function analysis

                with self._pyghidra.open_program(
                    str(file_path),
                    project_location=str(project_location),
                    project_name=project_name,
                    analyze=analyze,
                ) as flat_api:
                    from ghidra.app.decompiler import DecompInterface

                    program = flat_api.getCurrentProgram()
                    function = self._resolve_function(flat_api, function_address)

                    if function is None:
                        raise ValidationError(
                            f"Could not find function at address: {function_address}",
                            details={"address": function_address},
                        )

                    decompiler = DecompInterface()
                    decompiler.openProgram(program)

                    try:
                        results = decompiler.decompileFunction(function, effective_timeout, None)

                        if not results.decompileCompleted():
                            error_msg = results.getErrorMessage()
                            raise ValidationError(
                                f"Structure analysis failed: {error_msg}",
                                details={
                                    "function": function.getName(),
                                    "address": function_address,
                                },
                            )

                        high_function = results.getHighFunction()
                        if high_function is None:
                            raise ValidationError(
                                "Could not get high-level function representation",
                                details={"function": function.getName()},
                            )

                        structures_found = {}
                        local_symbols = high_function.getLocalSymbolMap()

                        # Analyze local variables
                        for i in range(local_symbols.getNumSymbols()):
                            symbol = local_symbols.getSymbol(i)
                            high_var = symbol.getHighVariable()

                            if high_var is not None:
                                data_type = high_var.getDataType()

                                if data_type is not None:
                                    type_name = data_type.getName()

                                    if "struct" in type_name.lower() or data_type.getLength() > 8:
                                        actual_type = data_type
                                        if hasattr(data_type, "getDataType"):
                                            actual_type = data_type.getDataType()

                                        struct_name = actual_type.getName()
                                        if struct_name not in structures_found:
                                            fields = self._extract_structure_fields(actual_type)
                                            structures_found[struct_name] = {
                                                "name": struct_name,
                                                "size": actual_type.getLength(),
                                                "fields": fields,
                                            }

                        # Analyze function parameters
                        for param in function.getParameters():
                            param_type = param.getDataType()
                            if param_type is not None:
                                type_name = param_type.getName()
                                if (
                                    "struct" in type_name.lower()
                                    and type_name not in structures_found
                                ):
                                    fields = self._extract_structure_fields(param_type)
                                    structures_found[type_name] = {
                                        "name": type_name,
                                        "size": param_type.getLength(),
                                        "fields": fields,
                                    }

                        # Generate C definitions
                        c_definitions = []
                        for struct_name, struct_data in structures_found.items():
                            if struct_data["fields"]:
                                field_strs = [
                                    f"{f['type']} {f['name']}; // offset {f['offset']}, size {f['size']}"
                                    for f in struct_data["fields"]
                                ]
                                fields_str = "\n    ".join(field_strs)
                                c_def = f"struct {struct_name} {{\n    {fields_str}\n}};"
                            else:
                                c_def = f"struct {struct_name} {{ /* size: {struct_data['size']} bytes */ }};"
                            c_definitions.append(c_def)

                        result = {
                            "structures": list(structures_found.values()),
                            "c_definitions": "\n\n".join(c_definitions)
                            if c_definitions
                            else "// No structures found",
                            "count": len(structures_found),
                        }

                        metadata = {
                            "function_name": function.getName(),
                            "entry_point": str(function.getEntryPoint()),
                            "structure_count": len(structures_found),
                            "analyzed_variables": local_symbols.getNumSymbols(),
                            "decompiler": "ghidra",
                        }

                        logger.info(
                            f"Recovered {len(structures_found)} structure(s) from {function.getName()}"
                        )
                        return result, metadata

                    finally:
                        decompiler.dispose()

            except Exception as e:
                logger.error(f"Ghidra structure recovery failed: {e}", exc_info=True)
                raise

    async def recover_structures_async(
        self,
        file_path: str,
        function_address: str,
        timeout: int | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Execute structure recovery asynchronously with dynamic timeout."""
        return await asyncio.to_thread(
            self.recover_structures, file_path, function_address, timeout
        )

    def get_version(self) -> str | None:
        """Get the installed Ghidra version."""
        try:
            self._ensure_jvm_started()
            from ghidra import framework

            version = framework.Application.getApplicationVersion()
            return str(version)
        except Exception:
            return None

    def close_all(self) -> None:
        """Close all cached projects and clean up resources."""
        with self._project_lock:
            for file_path, (_program, _flat_api, ctx) in list(self._projects.items()):
                try:
                    ctx.__exit__(None, None, None)
                except Exception as e:
                    logger.warning(f"Error closing project {file_path}: {e}")
            self._projects.clear()
            logger.info("All Ghidra projects closed")


# Global singleton instance
ghidra_service = GhidraService()


# Legacy compatibility aliases (deprecated - will be removed in future version)
def ensure_ghidra_available() -> bool:
    """Check if Ghidra is available. (Deprecated: use ghidra_service.is_available())"""
    return ghidra_service.is_available()


def decompile_function_with_ghidra(
    file_path: Path, function_address: str, timeout: int = 300
) -> tuple[str, dict[str, Any]]:
    """
    Decompile a function using Ghidra.
    (Deprecated: use ghidra_service.decompile())
    """
    return ghidra_service.decompile(str(file_path), function_address, timeout)


def recover_structures_with_ghidra(
    file_path: Path, function_address: str, timeout: int = 600, skip_full_analysis: bool = True
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Recover structures using Ghidra.

    Args:
        file_path: Path to the binary file
        function_address: Function address or name
        timeout: Timeout in seconds
        skip_full_analysis: Skip full binary analysis for faster startup (default True)

    (Deprecated: use ghidra_service.recover_structures())
    """
    return ghidra_service.recover_structures(
        str(file_path), function_address, timeout, skip_full_analysis
    )


def get_ghidra_version() -> str | None:
    """
    Get Ghidra version.
    (Deprecated: use ghidra_service.get_version())
    """
    return ghidra_service.get_version()


# Also provide GhidraManager alias for backward compatibility
class GhidraManager(GhidraService):
    """
    Legacy alias for GhidraService.
    (Deprecated: use GhidraService or ghidra_service directly)
    """

    pass


ghidra_manager = ghidra_service
