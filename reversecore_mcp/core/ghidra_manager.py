"""
Ghidra Manager

This module manages the Ghidra JVM lifecycle and project reuse.
It ensures the JVM is started only once and projects are cached for performance.
"""

import asyncio
import threading
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger


# Custom Exceptions for Structured Error Handling
class GhidraError(Exception):
    """Base exception for Ghidra operations."""

    pass


class DecompilationError(GhidraError):
    """Raised when decompilation fails."""

    pass


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
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._jvm_started = False
        self._projects: dict[
            str, Any
        ] = {}  # Cache for loaded programs (path -> (program, flat_api))
        self._project_lock = threading.RLock()
        # Use config value instead of hardcoded 1
        self._max_projects = get_config().ghidra_max_projects
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

    def _close_project(self, file_path: str, ctx: Any) -> None:
        """Properly close a Ghidra project context manager."""
        try:
            ctx.__exit__(None, None, None)
            logger.info(f"Closed Ghidra project: {file_path}")
        except Exception as e:
            logger.warning(f"Error closing Ghidra project {file_path}: {e}")

    def _get_project(self, file_path: str):
        """Get or load a project for the given file."""
        with self._project_lock:
            if file_path in self._projects:
                # Move to end (LRU)
                val = self._projects.pop(file_path)
                self._projects[file_path] = val
                return val

            # Evict if needed - properly close the context manager
            if len(self._projects) >= self._max_projects:
                oldest_path, (oldest_prog, oldest_api, oldest_ctx) = (
                    self._projects.popitem()
                )  # pop first (oldest)
                logger.info(f"Evicting Ghidra project: {oldest_path}")
                self._close_project(oldest_path, oldest_ctx)

            logger.info(f"Loading Ghidra project: {file_path}")
            # We use open_program but we need to keep it alive.
            # pyghidra.open_program returns a context manager.
            # We enter it manually.
            ctx = self._pyghidra.open_program(file_path)
            flat_api = ctx.__enter__()
            program = flat_api.getCurrentProgram()

            # Store context so we can exit it on eviction
            self._projects[file_path] = (program, flat_api, ctx)
            return program, flat_api, ctx

    def close_all(self) -> None:
        """Close all cached projects. Call on shutdown to prevent resource leaks."""
        with self._project_lock:
            for path, (_prog, _api, ctx) in list(self._projects.items()):
                self._close_project(path, ctx)
            self._projects.clear()
            logger.info("All Ghidra projects closed")

    def decompile(self, file_path: str, function_address: str | None = None) -> str:
        """
        Decompile a function or the entire file.

        Args:
            file_path: Path to the binary
            function_address: Address of function to decompile (optional)

        Returns:
            Decompiled C code
        """
        self._ensure_jvm_started()

        self._ensure_jvm_started()

        # [PERFORMANCE BOTTLENECK]
        # Ghidra/JPype requires single-threaded access to the JVM bridge via this lock.
        # This serializes all decompilation requests.
        # DO NOT REMOVE this lock without implementing a multi-process worker pool architecture.
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
                        except Exception as e:  # Catch all exceptions when parsing address
                            logger.debug("parse address/symbol %s: %s", function_address, e)

                    if not addr:
                        raise ValueError(f"Invalid address or symbol: {function_address}")

                    func = flat_api.getFunctionAt(addr)
                    if not func:
                        # Try to find nearest function
                        func = flat_api.getFunctionBefore(addr)
                        if not func:
                            raise ValueError(f"No function found at or near {function_address}")

                    res = decompiler.decompileFunction(func, 60, monitor)
                    if not res.decompileCompleted():
                        raise DecompilationError(f"Decompilation failed: {res.getErrorMessage()}")

                    return res.getDecompiledFunction().getC()
                else:
                    raise NotImplementedError(
                        "Full file decompilation not supported. Please specify a function."
                    )

            except Exception as e:
                logger.error(f"Ghidra decompilation failed: {e}")
                # Invalidate cache on error
                with self._project_lock:
                    if file_path in self._projects:
                        del self._projects[file_path]
                raise

    async def decompile_async(self, file_path: str, function_address: str | None = None) -> str:
        """Execute decompilation asynchronously."""
        return await asyncio.to_thread(self.decompile, file_path, function_address)


# Global instance
ghidra_manager = GhidraManager()


def get_ghidra_manager() -> GhidraManager:
    """Get the global GhidraManager instance."""
    return ghidra_manager
