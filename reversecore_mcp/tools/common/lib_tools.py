"""Library-backed MCP tools that emit structured ToolResult payloads.

This module acts as a facade that imports and exposes tools from specialized modules:
- ioc_tools: IOC extraction using regex
- yara_tools: YARA scanning
- capstone_tools: Capstone disassembly
- lief_tools: LIEF binary parsing
"""

# Import all tools from specialized modules
from reversecore_mcp.tools.malware.ioc_tools import _IOC_IPV4_PATTERN, extract_iocs
from reversecore_mcp.tools.analysis.lief_tools import _format_lief_output, parse_binary_with_lief
from reversecore_mcp.tools.malware.yara_tools import _format_yara_match, run_yara

# Re-export all tools so existing imports continue to work
__all__ = [
    "extract_iocs",
    "run_yara",
    "parse_binary_with_lief",
    "register_lib_tools",
    # Internal symbols for backward compatibility (used by tests)
    "_IOC_IPV4_PATTERN",
    "_format_yara_match",
    "_format_lief_output",
]


from typing import Any

from reversecore_mcp.core.plugin import Plugin


class LibToolsPlugin(Plugin):
    """Plugin for library-backed tools (YARA, LIEF, IOCs)."""

    @property
    def name(self) -> str:
        return "lib_tools"

    @property
    def description(self) -> str:
        return "Library-backed tools for YARA scanning, binary parsing, and IOC extraction."

    def register(self, mcp_server: Any) -> None:
        """Register library tools."""
        mcp_server.tool(run_yara)
        mcp_server.tool(parse_binary_with_lief)
        mcp_server.tool(extract_iocs)
