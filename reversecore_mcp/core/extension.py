"""
Extension point interfaces for Radare2 and Ghidra plugin extensibility.

This module defines the contracts that external (or internal) plugins must
implement to hook into the Radare2 and Ghidra analysis pipelines.

Architecture:
    R2ExtensionPoint       — hooks into r2 command execution pipeline
    GhidraExtensionPoint   — hooks into Ghidra decompile / analysis pipeline
    R2CommandResult        — immutable result container passed through r2 hooks
    GhidraAnalysisContext  — mutable context passed through Ghidra hooks

Registration:
    Plugins are discovered via ExtensionRegistry (extension_registry.py).
    Three discovery strategies are supported:
      1. Python entry_points  (pip-installable packages)
      2. Local directory scan (REVERSECORE_PLUGIN_DIRS env var)
      3. Explicit class list  (REVERSECORE_R2_EXTENSIONS / REVERSECORE_GHIDRA_EXTENSIONS)

Example (pip package):
    # pyproject.toml
    [project.entry-points."reversecore_mcp.r2_extensions"]
    my_ext = "my_package.ext:MyR2Extension"

Example (local file, ~/.reversecore/plugins/my_ext.py):
    from reversecore_mcp.core.extension import R2ExtensionPoint, R2CommandResult

    class MyExt(R2ExtensionPoint):
        name = "my_ext"

        async def on_after_r2_command(self, result):
            result.metadata["custom"] = "value"
            return result

        def get_mcp_tools(self):
            return [my_mcp_tool_fn]
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


# =============================================================================
# Data Containers
# =============================================================================


@dataclass
class R2CommandResult:
    """
    Container for a radare2 command execution result.

    Passed through the post-hook chain. Extensions may mutate ``metadata``
    or replace ``parsed`` to enrich the final ToolResult returned to the AI.

    Attributes:
        file_path:    Validated absolute path of the binary being analysed.
        command:      The r2 command that was executed (after validation).
        raw_output:   Raw string output from radare2.
        parsed:       Optional structured data (dict / list) replacing raw_output
                      in the final ToolResult. Extensions may populate this.
        metadata:     Arbitrary key-value pairs attached by extensions.
                      Merged into the ToolResult ``success()`` call.
    """

    file_path: str
    command: str
    raw_output: str
    parsed: dict[str, Any] | list[Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GhidraAnalysisContext:
    """
    Context object passed through the Ghidra hook chain.

    Attributes:
        file_path:       Validated absolute path of the binary.
        function_address: Address / symbol name of the function being analysed.
        program:         Ghidra ``Program`` object (None if Ghidra unavailable).
        flat_api:        Ghidra ``FlatProgramAPI`` object (None if unavailable).
        metadata:        Arbitrary key-value pairs for cross-hook communication.
    """

    file_path: str
    function_address: str
    program: Any | None = None
    flat_api: Any | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# R2 Extension Point
# =============================================================================


class R2ExtensionPoint:
    """
    Abstract base class for Radare2 analysis pipeline extensions.

    Subclasses may override any subset of the hook methods. Unoverridden
    methods are no-ops and add negligible overhead.

    Class Attributes:
        name (str):                      Unique extension identifier (required).
        priority (int):                  Lower value = executed first (default 100).
        r2_command_allowlist (list[str]): Additional r2 commands this extension
                                          permits. These bypass the built-in
                                          ``validate_r2_command`` whitelist.
                                          Use with caution.
    """

    #: Must be overridden in subclasses.
    name: str = ""

    #: Execution order among registered extensions (lower = earlier).
    priority: int = 100

    #: Extra r2 commands this extension is permitted to run.
    #: Example: ["agfj", "pdg"] — only add commands you specifically need.
    r2_command_allowlist: list[str] = []

    # ── Lifecycle hooks ───────────────────────────────────────────────────────

    async def on_session_open(self, file_path: str, r2pipe_instance: Any) -> None:
        """
        Called when a new r2 session is opened for *file_path*.

        Use this to run one-time setup commands (e.g. loading custom scripts,
        setting radare2 config variables).

        Args:
            file_path:       Path to the binary file.
            r2pipe_instance: Live r2pipe.open() object.
        """

    async def on_session_close(self, file_path: str) -> None:
        """
        Called when an r2 session for *file_path* is about to be closed.

        Args:
            file_path: Path to the binary file.
        """

    # ── Command pipeline hooks ────────────────────────────────────────────────

    async def on_before_r2_command(self, file_path: str, command: str) -> tuple[str, str]:
        """
        Called before an r2 command is executed.

        Extensions may modify or replace the *file_path* and/or *command*.
        The modified values are passed to subsequent hooks and eventually
        to the r2 execution engine.

        Args:
            file_path: Validated path to the binary.
            command:   Validated r2 command string.

        Returns:
            Tuple of (file_path, command) — possibly modified.
        """
        return file_path, command

    async def on_after_r2_command(self, result: R2CommandResult) -> R2CommandResult:
        """
        Called after an r2 command finishes.

        Extensions may enrich ``result.metadata`` or replace ``result.parsed``
        with structured data derived from ``result.raw_output``.

        Args:
            result: Execution result container.

        Returns:
            Possibly modified ``R2CommandResult``.
        """
        return result

    # ── Tool registration ─────────────────────────────────────────────────────

    def get_mcp_tools(self) -> list[Callable]:
        """
        Return a list of additional MCP tool functions to register.

        Each function must be compatible with FastMCP ``@server.tool()``
        (i.e., an ``async def`` returning ``ToolResult``).

        Returns:
            List of tool callables (may be empty).
        """
        return []

    def get_r2_startup_commands(self) -> list[str]:
        """
        Return r2 commands to execute on every new session open.

        These run AFTER ``on_session_open()`` and are a simpler alternative
        for extensions that only need to configure r2 settings.

        Returns:
            List of r2 command strings (may be empty).
        """
        return []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate that subclasses declare a ``name`` attribute."""
        super().__init_subclass__(**kwargs)
        # Only enforce on concrete (non-abstract) subclasses
        if not getattr(cls, "__abstractmethods__", None) and not cls.name:
            raise TypeError(f"{cls.__name__} must define a non-empty class attribute 'name'.")


# =============================================================================
# Ghidra Extension Point
# =============================================================================


class GhidraExtensionPoint:
    """
    Abstract base class for Ghidra analysis pipeline extensions.

    Hooks into decompilation and function analysis phases. Extensions
    can inject Ghidra headless scripts, post-process decompiled code,
    or enrich function metadata.

    Class Attributes:
        name (str):     Unique extension identifier (required).
        priority (int): Lower value = executed first (default 100).
    """

    name: str = ""
    priority: int = 100

    # ── Project lifecycle ─────────────────────────────────────────────────────

    async def on_project_open(self, ctx: GhidraAnalysisContext) -> None:
        """
        Called after a Ghidra project is opened/loaded.

        Args:
            ctx: Analysis context with program and flat_api populated.
        """

    async def on_before_analysis(self, ctx: GhidraAnalysisContext) -> GhidraAnalysisContext:
        """
        Called before Ghidra runs function analysis.

        Args:
            ctx: Analysis context.

        Returns:
            Possibly modified context.
        """
        return ctx

    # ── Output hooks ──────────────────────────────────────────────────────────

    async def on_after_decompile(self, ctx: GhidraAnalysisContext, decompiled_code: str) -> str:
        """
        Called after Ghidra produces decompiled C code for a function.

        Extensions may post-process the code (e.g. rename variables,
        add type annotations, strip noise).

        Args:
            ctx:             Analysis context.
            decompiled_code: Raw decompiled C code string from Ghidra.

        Returns:
            Possibly modified decompiled code string.
        """
        return decompiled_code

    async def on_after_function_analysis(
        self, ctx: GhidraAnalysisContext, functions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Called after a function list is produced.

        Args:
            ctx:       Analysis context.
            functions: List of function metadata dicts.

        Returns:
            Possibly modified list of function metadata.
        """
        return functions

    # ── Tool & script injection ────────────────────────────────────────────────

    def get_headless_scripts(self) -> list[str]:
        """
        Return absolute paths to Ghidra headless scripts to run during analysis.

        Scripts may be Python (.py) or Java (.java/.class) Ghidra scripts.
        They are executed AFTER the default Ghidra analysis pass.

        Returns:
            List of absolute path strings (may be empty).
        """
        return []

    def get_mcp_tools(self) -> list[Callable]:
        """
        Return a list of additional MCP tool functions to register.

        Returns:
            List of tool callables (may be empty).
        """
        return []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Validate that subclasses declare a ``name`` attribute."""
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "__abstractmethods__", None) and not cls.name:
            raise TypeError(f"{cls.__name__} must define a non-empty class attribute 'name'.")
