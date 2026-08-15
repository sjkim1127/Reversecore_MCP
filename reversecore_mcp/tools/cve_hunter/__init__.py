"""CVE Hunter Tools Plugin for Reversecore_MCP."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import (
    cve_fuzz_target,
    cve_minimize_poc,
    cve_synthesize_harness,
    cve_triage_crash,
    hunt_cve_vulnerabilities,
)

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = get_logger(__name__)


class CVEHunterToolsPlugin(Plugin):
    """Plugin providing automated C/C++ CVE hunting, fuzzing, and triage tools."""

    @property
    def name(self) -> str:
        return "cve_hunter_tools"

    @property
    def description(self) -> str:
        return "Automated C/C++ CVE hunting, LibFuzzer harness synthesis, ASan triage, and PoC minimization tools."

    def register(self, server: FastMCP) -> None:
        """Register CVE hunter tools with the FastMCP server."""
        server.tool()(cve_synthesize_harness)
        server.tool()(cve_fuzz_target)
        server.tool()(cve_triage_crash)
        server.tool()(cve_minimize_poc)
        server.tool()(hunt_cve_vulnerabilities)
        logger.info("Registered cve_hunter_tools plugin with 5 CVE discovery tools")


__all__ = [
    "CVEHunterToolsPlugin",
    "cve_fuzz_target",
    "cve_minimize_poc",
    "cve_synthesize_harness",
    "cve_triage_crash",
    "hunt_cve_vulnerabilities",
]
