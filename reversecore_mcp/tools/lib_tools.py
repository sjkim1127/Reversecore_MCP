"""Library-backed MCP tools that emit structured ToolResult payloads.

This module acts as a facade that imports and exposes tools from specialized modules:
- ioc_tools: IOC extraction using regex
- yara_tools: YARA scanning
- capstone_tools: Capstone disassembly
- lief_tools: LIEF binary parsing
"""

from fastmcp import FastMCP

# Import all tools from specialized modules
from reversecore_mcp.tools.ioc_tools import extract_iocs, _IOC_IPV4_PATTERN
from reversecore_mcp.tools.yara_tools import run_yara, _format_yara_match
from reversecore_mcp.tools.capstone_tools import disassemble_with_capstone
from reversecore_mcp.tools.lief_tools import parse_binary_with_lief, _format_lief_output

# Re-export all tools so existing imports continue to work
__all__ = [
    "extract_iocs",
    "run_yara",
    "disassemble_with_capstone",
    "parse_binary_with_lief",
    "register_lib_tools",
    # Internal symbols for backward compatibility (used by tests)
    "_IOC_IPV4_PATTERN",
    "_format_yara_match",
    "_format_lief_output",
]


def register_lib_tools(mcp: FastMCP) -> None:
    """
    Register all library tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_yara)
    mcp.tool(disassemble_with_capstone)
    mcp.tool(parse_binary_with_lief)
    mcp.tool(extract_iocs)
