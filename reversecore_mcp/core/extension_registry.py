"""
Central registry and auto-discovery for Reversecore MCP extension plugins.

This module provides ``ExtensionRegistry`` — a singleton that:
  1. Discovers and registers R2 / Ghidra extension plugins (three strategies).
  2. Exposes hook runners called by the analysis pipeline.
  3. Collects additional MCP tools from extensions for dynamic registration.

Discovery Strategies
--------------------
  A. Python entry_points (pip-installable third-party packages):
       [project.entry-points."reversecore_mcp.r2_extensions"]
       my_ext = "mypkg.extensions:MyR2Ext"

  B. Local directory scan (for personal / team scripts):
       REVERSECORE_PLUGIN_DIRS=/home/user/.reversecore/plugins,/opt/team-plugins

  C. Explicit class specification via environment variable:
       REVERSECORE_R2_EXTENSIONS=mypkg.ext:MyR2Ext,mypkg.ext2:AnotherExt
       REVERSECORE_GHIDRA_EXTENSIONS=mypkg.ghidra_ext:MyGhidraExt

Usage in server.py
------------------
    from reversecore_mcp.core.extension_registry import get_extension_registry

    registry = get_extension_registry()
    registry.discover_all()

    for tool_fn in registry.get_all_extension_tools():
        mcp.tool(tool_fn)

Usage in pipeline hooks (r2_analysis.py)
-----------------------------------------
    from reversecore_mcp.core.extension_registry import get_extension_registry

    registry = get_extension_registry()
    file_path, command = await registry.run_r2_pre_hooks(file_path, command)
    # ... execute r2 ...
    result_obj = R2CommandResult(file_path=fp, command=cmd, raw_output=raw)
    result_obj = await registry.run_r2_post_hooks(result_obj)
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reversecore_mcp.core.extension import (
    GhidraAnalysisContext,
    GhidraExtensionPoint,
    R2CommandResult,
    R2ExtensionPoint,
)
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Entry-point group names used for pip-installable plugins
_R2_ENTRY_GROUP = "reversecore_mcp.r2_extensions"
_GHIDRA_ENTRY_GROUP = "reversecore_mcp.ghidra_extensions"

# Environment variables for explicit class lists
_ENV_R2_EXTENSIONS = "REVERSECORE_R2_EXTENSIONS"
_ENV_GHIDRA_EXTENSIONS = "REVERSECORE_GHIDRA_EXTENSIONS"
_ENV_PLUGIN_DIRS = "REVERSECORE_PLUGIN_DIRS"


class ExtensionRegistry:
    """
    Central registry for R2 and Ghidra extension plugins.

    This is normally used as a process-wide singleton via
    ``get_extension_registry()``.  Tests may instantiate it directly.
    """

    def __init__(self) -> None:
        self._r2_extensions: list[R2ExtensionPoint] = []
        self._ghidra_extensions: list[GhidraExtensionPoint] = []
        self._discovered: bool = False

    # =========================================================================
    # Registration
    # =========================================================================

    def register_r2(self, ext: R2ExtensionPoint) -> None:
        """Register a single R2 extension and sort by priority."""
        if any(e.name == ext.name for e in self._r2_extensions):
            logger.warning("R2 extension '%s' already registered — skipping", ext.name)
            return
        self._r2_extensions.append(ext)
        self._r2_extensions.sort(key=lambda e: e.priority)

        # Expand the r2 command allowlist if needed
        if ext.r2_command_allowlist:
            self._expand_r2_allowlist(ext.r2_command_allowlist)

        logger.info("✅ R2 extension registered: %s (priority=%d)", ext.name, ext.priority)

    def register_ghidra(self, ext: GhidraExtensionPoint) -> None:
        """Register a single Ghidra extension and sort by priority."""
        if any(e.name == ext.name for e in self._ghidra_extensions):
            logger.warning("Ghidra extension '%s' already registered — skipping", ext.name)
            return
        self._ghidra_extensions.append(ext)
        self._ghidra_extensions.sort(key=lambda e: e.priority)
        logger.info("✅ Ghidra extension registered: %s (priority=%d)", ext.name, ext.priority)

    # =========================================================================
    # Discovery
    # =========================================================================

    def discover_all(self) -> None:
        """
        Run all three discovery strategies and register found extensions.

        Safe to call multiple times (subsequent calls are no-ops unless
        ``reset()`` was called in between).
        """
        if self._discovered:
            return
        self._discovered = True

        logger.info("🔍 Discovering extension plugins...")
        self._discover_from_entry_points()
        self._discover_from_plugin_dirs()
        self._discover_from_env_vars()

        r2_count = len(self._r2_extensions)
        g_count = len(self._ghidra_extensions)
        logger.info("Plugin discovery complete — R2: %d, Ghidra: %d", r2_count, g_count)

    def _discover_from_entry_points(self) -> None:
        """Strategy A: Discover plugins via Python package entry_points."""
        try:
            from importlib.metadata import entry_points
        except ImportError:
            # Python < 3.9 fallback
            try:
                from importlib_metadata import entry_points  # type: ignore[no-redef]
            except ImportError:
                logger.debug("importlib.metadata not available — skipping entry_points discovery")
                return

        # R2 extensions
        for ep in entry_points(group=_R2_ENTRY_GROUP):
            try:
                cls = ep.load()
                if inspect.isclass(cls) and issubclass(cls, R2ExtensionPoint):
                    self.register_r2(cls())
                    logger.info("Loaded R2 extension via entry_points: %s", ep.name)
                else:
                    logger.warning(
                        "Entry point '%s' does not resolve to an R2ExtensionPoint subclass",
                        ep.name,
                    )
            except Exception as exc:
                logger.error("Failed to load R2 entry_point '%s': %s", ep.name, exc)

        # Ghidra extensions
        for ep in entry_points(group=_GHIDRA_ENTRY_GROUP):
            try:
                cls = ep.load()
                if inspect.isclass(cls) and issubclass(cls, GhidraExtensionPoint):
                    self.register_ghidra(cls())
                    logger.info("Loaded Ghidra extension via entry_points: %s", ep.name)
                else:
                    logger.warning(
                        "Entry point '%s' does not resolve to a GhidraExtensionPoint subclass",
                        ep.name,
                    )
            except Exception as exc:
                logger.error("Failed to load Ghidra entry_point '%s': %s", ep.name, exc)

    def _discover_from_plugin_dirs(self) -> None:
        """Strategy B: Scan directories for .py files containing extension classes."""
        raw = os.environ.get(_ENV_PLUGIN_DIRS, "").strip()
        if not raw:
            return

        dirs = [Path(d.strip()) for d in raw.split(",") if d.strip()]
        for directory in dirs:
            if not directory.is_dir():
                logger.warning("Plugin dir '%s' does not exist — skipping", directory)
                continue
            logger.info("Scanning plugin dir: %s", directory)
            for py_file in sorted(directory.glob("*.py")):
                self._load_from_file(py_file)

    def _load_from_file(self, py_file: Path) -> None:
        """Dynamically import *py_file* and register any extension classes found."""
        module_name = f"_reversecore_ext_{py_file.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                return
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            logger.error("Failed to load plugin file '%s': %s", py_file, exc)
            return

        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module_name:
                continue  # Skip imported classes
            if issubclass(obj, R2ExtensionPoint) and obj is not R2ExtensionPoint:
                try:
                    self.register_r2(obj())
                    logger.info("Loaded R2 extension from file: %s::%s", py_file.name, _name)
                except Exception as exc:
                    logger.error("Failed to instantiate %s: %s", _name, exc)
            elif issubclass(obj, GhidraExtensionPoint) and obj is not GhidraExtensionPoint:
                try:
                    self.register_ghidra(obj())
                    logger.info("Loaded Ghidra extension from file: %s::%s", py_file.name, _name)
                except Exception as exc:
                    logger.error("Failed to instantiate %s: %s", _name, exc)

    def _discover_from_env_vars(self) -> None:
        """Strategy C: Load extension classes from REVERSECORE_*_EXTENSIONS env vars."""
        r2_spec = os.environ.get(_ENV_R2_EXTENSIONS, "").strip()
        ghidra_spec = os.environ.get(_ENV_GHIDRA_EXTENSIONS, "").strip()

        for spec in filter(None, r2_spec.split(",")):
            cls = self._load_class(spec.strip())
            if cls and issubclass(cls, R2ExtensionPoint):
                try:
                    self.register_r2(cls())
                except Exception as exc:
                    logger.error("Failed to instantiate R2 extension '%s': %s", spec, exc)
            elif cls:
                logger.warning("'%s' is not an R2ExtensionPoint subclass — skipping", spec)

        for spec in filter(None, ghidra_spec.split(",")):
            cls = self._load_class(spec.strip())
            if cls and issubclass(cls, GhidraExtensionPoint):
                try:
                    self.register_ghidra(cls())
                except Exception as exc:
                    logger.error("Failed to instantiate Ghidra extension '%s': %s", spec, exc)
            elif cls:
                logger.warning("'%s' is not a GhidraExtensionPoint subclass — skipping", spec)

    @staticmethod
    def _load_class(dotted: str) -> type | None:
        """
        Import a class from a ``"module.path:ClassName"`` or
        ``"module.path.ClassName"`` dotted string.
        """
        try:
            if ":" in dotted:
                module_path, cls_name = dotted.rsplit(":", 1)
            elif "." in dotted:
                module_path, cls_name = dotted.rsplit(".", 1)
            else:
                logger.warning("Cannot parse extension spec '%s'", dotted)
                return None
            module = importlib.import_module(module_path)
            return getattr(module, cls_name)
        except Exception as exc:
            logger.error("Failed to load class '%s': %s", dotted, exc)
            return None

    # =========================================================================
    # Hook runners (called by analysis pipeline)
    # =========================================================================

    async def run_r2_pre_hooks(self, file_path: str, command: str) -> tuple[str, str]:
        """
        Chain all R2 ``on_before_r2_command`` hooks.

        Args:
            file_path: Validated binary path.
            command:   Validated r2 command.

        Returns:
            Tuple of (possibly modified file_path, command).
        """
        if not self._r2_extensions:
            return file_path, command
        for ext in self._r2_extensions:
            try:
                file_path, command = await ext.on_before_r2_command(file_path, command)
            except Exception as exc:
                logger.error("R2 pre-hook error in extension '%s': %s", ext.name, exc)
        return file_path, command

    async def run_r2_post_hooks(self, result: R2CommandResult) -> R2CommandResult:
        """
        Chain all R2 ``on_after_r2_command`` hooks.

        Args:
            result: Execution result container.

        Returns:
            Possibly enriched result.
        """
        if not self._r2_extensions:
            return result
        for ext in self._r2_extensions:
            try:
                result = await ext.on_after_r2_command(result)
            except Exception as exc:
                logger.error("R2 post-hook error in extension '%s': %s", ext.name, exc)
        return result

    async def run_r2_session_open_hooks(self, file_path: str, r2pipe_instance: Any) -> None:
        """Call ``on_session_open`` on all R2 extensions."""
        for ext in self._r2_extensions:
            try:
                await ext.on_session_open(file_path, r2pipe_instance)
            except Exception as exc:
                logger.error("R2 session-open hook error in '%s': %s", ext.name, exc)

    async def run_r2_session_close_hooks(self, file_path: str) -> None:
        """Call ``on_session_close`` on all R2 extensions."""
        for ext in self._r2_extensions:
            try:
                await ext.on_session_close(file_path)
            except Exception as exc:
                logger.debug("R2 session-close hook error in '%s': %s", ext.name, exc)

    async def run_ghidra_decompile_hooks(self, ctx: GhidraAnalysisContext, code: str) -> str:
        """
        Chain all Ghidra ``on_after_decompile`` hooks.

        Args:
            ctx:  Analysis context.
            code: Raw decompiled code from Ghidra.

        Returns:
            Possibly transformed code string.
        """
        if not self._ghidra_extensions:
            return code
        for ext in self._ghidra_extensions:
            try:
                code = await ext.on_after_decompile(ctx, code)
            except Exception as exc:
                logger.error("Ghidra decompile hook error in '%s': %s", ext.name, exc)
        return code

    async def run_ghidra_function_hooks(
        self, ctx: GhidraAnalysisContext, functions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Chain all Ghidra ``on_after_function_analysis`` hooks."""
        if not self._ghidra_extensions:
            return functions
        for ext in self._ghidra_extensions:
            try:
                functions = await ext.on_after_function_analysis(ctx, functions)
            except Exception as exc:
                logger.error("Ghidra function hook error in '%s': %s", ext.name, exc)
        return functions

    # =========================================================================
    # Tool collection
    # =========================================================================

    def get_all_extension_tools(self) -> list[Callable]:
        """
        Collect all MCP tool functions contributed by registered extensions.

        Returns:
            Flat list of tool callables, ready for ``mcp.tool()`` registration.
        """
        tools: list[Callable] = []
        for ext in self._r2_extensions + self._ghidra_extensions:  # type: ignore[operator]
            try:
                tools.extend(ext.get_mcp_tools())
            except Exception as exc:
                logger.error("get_mcp_tools() error in extension '%s': %s", ext.name, exc)
        return tools

    def get_ghidra_startup_scripts(self) -> list[str]:
        """Collect all headless scripts from Ghidra extensions."""
        scripts: list[str] = []
        for ext in self._ghidra_extensions:
            try:
                scripts.extend(ext.get_headless_scripts())
            except Exception as exc:
                logger.error("get_headless_scripts() error in extension '%s': %s", ext.name, exc)
        return scripts

    def get_r2_startup_commands(self, file_path: str) -> list[str]:
        """Collect all r2 startup commands from R2 extensions."""
        commands: list[str] = []
        for ext in self._r2_extensions:
            try:
                commands.extend(ext.get_r2_startup_commands())
            except Exception as exc:
                logger.error("get_r2_startup_commands() error in extension '%s': %s", ext.name, exc)
        return commands

    # =========================================================================
    # Introspection
    # =========================================================================

    def list_extensions(self) -> dict[str, list[str]]:
        """Return a summary of all registered extensions by category."""
        return {
            "r2": [e.name for e in self._r2_extensions],
            "ghidra": [e.name for e in self._ghidra_extensions],
        }

    @property
    def r2_extensions(self) -> list[R2ExtensionPoint]:
        return list(self._r2_extensions)

    @property
    def ghidra_extensions(self) -> list[GhidraExtensionPoint]:
        return list(self._ghidra_extensions)

    def reset(self) -> None:
        """Clear all registered extensions (mainly used in tests)."""
        self._r2_extensions.clear()
        self._ghidra_extensions.clear()
        self._discovered = False

    # =========================================================================
    # Private helpers
    # =========================================================================

    @staticmethod
    def _expand_r2_allowlist(commands: list[str]) -> None:
        """
        Dynamically add commands to the r2 command allowlist in command_spec.

        This allows extensions to permit additional r2 commands without
        modifying the core ``command_spec.py`` file.
        """
        try:
            from reversecore_mcp.core import command_spec

            existing = getattr(command_spec, "ALLOWED_R2_COMMANDS", set())
            new_cmds = set(commands) - existing
            if new_cmds:
                command_spec.ALLOWED_R2_COMMANDS = existing | new_cmds  # type: ignore[attr-defined]
                logger.info("R2 allowlist expanded with: %s", new_cmds)
        except Exception as exc:
            logger.warning("Could not expand r2 allowlist: %s", exc)


# =============================================================================
# Singleton access
# =============================================================================

_registry: ExtensionRegistry | None = None


def get_extension_registry() -> ExtensionRegistry:
    """
    Return the process-wide ExtensionRegistry singleton.

    Thread-safe for read access; call ``discover_all()`` once at startup.
    """
    global _registry
    if _registry is None:
        _registry = ExtensionRegistry()
    return _registry


def reset_extension_registry() -> None:
    """Reset the singleton (used in tests)."""
    global _registry
    if _registry is not None:
        _registry.reset()
    _registry = None
