"""
Ghidra Manager

This module manages the Ghidra JVM lifecycle and project reuse.
It ensures the JVM is started only once and projects are cached for performance.
"""

import asyncio
import threading
from typing import Dict, Any, Optional

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


class GhidraManager:
    """
    Manages Ghidra JVM and project lifecycle.

    Features:
    - Singleton JVM instance
    - Project caching
    - Thread-safe execution
    """

    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(GhidraManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._jvm_started = False
        self._projects: Dict[str, Any] = (
            {}
        )  # Cache for loaded programs (path -> (program, flat_api))
        self._project_lock = threading.RLock()
        self._max_projects = 1  # Keep only 1 project in memory to avoid OOM
        self._initialized = True
        self._pyghidra = None
        self._flat_program_api = None

    def _ensure_jvm_started(self):
        """Start the JVM if not already started."""
        if self._jvm_started:
            return

        with self._lock:
            if self._jvm_started:
                return

            try:
                import pyghidra
                from pyghidra.core import FlatProgramAPI

                logger.info("Starting Ghidra JVM...")
                # pyghidra.start() is often called automatically on import or first use
                # but explicit start ensures control
                try:
                    pyghidra.start()
                except Exception as e:
                    # It might be already running or failed
                    logger.debug(f"pyghidra.start() result: {e}")

                self._pyghidra = pyghidra
                self._flat_program_api = FlatProgramAPI
                self._jvm_started = True
                logger.info("Ghidra JVM started successfully")

            except ImportError:
                logger.error("pyghidra not installed")
                raise ImportError("pyghidra not installed")
            except Exception as e:
                logger.error(f"Failed to start Ghidra JVM: {e}")
                raise

    def _get_project(self, file_path: str):
        """Get or load a project for the given file."""
        with self._project_lock:
            if file_path in self._projects:
                # Move to end (LRU)
                val = self._projects.pop(file_path)
                self._projects[file_path] = val
                return val

            # Evict if needed
            if len(self._projects) >= self._max_projects:
                oldest_path, (oldest_prog, oldest_api) = (
                    self._projects.popitem()
                )  # pop first (oldest)
                logger.info(f"Evicting Ghidra project: {oldest_path}")
                # Note: We can't easily 'close' a FlatProgram created via open_program
                # if we want to be safe, but we can release references.
                # In a real persistent scenario, we might need to handle transactions.
                # For now, we just drop the reference.

            logger.info(f"Loading Ghidra project: {file_path}")
            # We use open_program but we need to keep it alive.
            # pyghidra.open_program returns a context manager.
            # We enter it manually.
            ctx = self._pyghidra.open_program(file_path)
            flat_api = ctx.__enter__()
            program = flat_api.getCurrentProgram()

            # Store context too so we can exit it later if needed (though we might just keep it open)
            # Actually, if we exit the context, it might close the program.
            # So we keep the context open until eviction.
            self._projects[file_path] = (program, flat_api, ctx)
            return program, flat_api, ctx

    def decompile(self, file_path: str, function_address: Optional[str] = None) -> str:
        """
        Decompile a function or the entire file.

        Args:
            file_path: Path to the binary
            function_address: Address of function to decompile (optional)

        Returns:
            Decompiled C code
        """
        self._ensure_jvm_started()

        with self._lock:
            try:
                # Get cached project
                program, flat_api, _ = self._get_project(file_path)

                from ghidra.app.decompiler import DecompInterface
                from ghidra.util.task import ConsoleTaskMonitor

                decompiler = DecompInterface()
                decompiler.openProgram(program)

                monitor = ConsoleTaskMonitor()

                if function_address:
                    # Parse address
                    addr = flat_api.toAddr(function_address)
                    if not addr:
                        # Try adding base address if needed, or assume hex
                        try:
                            if function_address.startswith("0x"):
                                addr = flat_api.toAddr(int(function_address, 16))
                            else:
                                # Try to find symbol
                                funcs = flat_api.getGlobalFunctions(function_address)
                                if funcs:
                                    addr = funcs[0].getEntryPoint()
                        except Exception:  # Catch all exceptions when parsing address
                            pass

                    if not addr:
                        return f"// Error: Invalid address {function_address}"

                    func = flat_api.getFunctionAt(addr)
                    if not func:
                        return f"// Error: No function at {function_address}"

                    res = decompiler.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        return "// Error: Decompilation failed"

                    return res.getDecompiledFunction().getC()
                else:
                    return "// Full file decompilation not supported in this mode. Please specify a function."

            except Exception as e:
                logger.error(f"Ghidra decompilation failed: {e}")
                # Invalidate cache on error
                with self._project_lock:
                    if file_path in self._projects:
                        del self._projects[file_path]
                raise

    async def decompile_async(
        self, file_path: str, function_address: Optional[str] = None
    ) -> str:
        """Execute decompilation asynchronously."""
        return await asyncio.to_thread(self.decompile, file_path, function_address)


# Global instance
ghidra_manager = GhidraManager()
