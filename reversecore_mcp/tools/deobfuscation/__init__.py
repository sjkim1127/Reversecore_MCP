"""Deobfuscation tools package.

Provides automated stack string recovery, emulation-based string decryption,
API hash resolution, and dead code/opaque predicate elimination.
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import (
    deobfuscate_strings,
    eliminate_dead_code,
    resolve_api_hashes,
    run_deobfuscation_pipeline,
)

logger = get_logger(__name__)


class DeobfuscationToolsPlugin(Plugin):
    """Unified plugin for all deobfuscation tools."""

    @property
    def name(self) -> str:
        return "deobfuscation_tools"

    @property
    def description(self) -> str:
        return (
            "AI-assisted automated deobfuscation tools including stack string recovery, "
            "emulated loop string decryption, API hash resolution, and dead code elimination."
        )

    def register(self, mcp_server: Any) -> None:
        """Register all deobfuscation tools with the FastMCP server."""
        mcp_server.tool(deobfuscate_strings)
        mcp_server.tool(resolve_api_hashes)
        mcp_server.tool(eliminate_dead_code)
        mcp_server.tool(run_deobfuscation_pipeline)

        logger.info(f"Registered {self.name} plugin with 4 deobfuscation tools")


__all__ = [
    "DeobfuscationToolsPlugin",
    "deobfuscate_strings",
    "resolve_api_hashes",
    "eliminate_dead_code",
    "run_deobfuscation_pipeline",
]
