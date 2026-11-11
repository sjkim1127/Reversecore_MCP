"""Dynamic analysis tools package.

Provides safe, container- and OS-level execution tracing and process memory
dumping tools for binary analysis and Fission pre-processing:
- trace_execution: Traces subprocess execution, file activity, syscalls, and crashes
- dump_process_memory: Dumps virtual memory segments for dynamic unpacking inspection
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class DynamicToolsPlugin(Plugin):
    """Plugin for runtime dynamic analysis and memory dumping tools."""

    @property
    def name(self) -> str:
        return "dynamic_tools"

    @property
    def description(self) -> str:
        return (
            "Runtime dynamic analysis tools including sandbox execution tracing and memory dumping."
        )

    def register(self, mcp_server: Any) -> None:
        """Register dynamic analysis tools."""
        from reversecore_mcp.tools.dynamic.memory_dumper import dump_process_memory
        from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution

        mcp_server.tool(trace_execution)
        mcp_server.tool(dump_process_memory)

        logger.info(f"Registered {self.name} plugin with 2 dynamic analysis tools")


__all__ = ["DynamicToolsPlugin"]
