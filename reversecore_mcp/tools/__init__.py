"""
Tool definitions for Reversecore_MCP.

This package contains tool modules that wrap reverse engineering CLI tools
and libraries, making them accessible to AI agents through the MCP protocol.
"""

# Backward compatibility re-exports for legacy imports
# These allow tests and other code to use `from reversecore_mcp.tools import X` syntax

# Analysis tools
from reversecore_mcp.tools.analysis import static_analysis
from reversecore_mcp.tools.analysis import diff_tools
from reversecore_mcp.tools.analysis import signature_tools
from reversecore_mcp.tools.analysis import lief_tools

# Common tools
from reversecore_mcp.tools.common import file_operations
from reversecore_mcp.tools.common import lib_tools

# Radare2 tools
from reversecore_mcp.tools.radare2 import r2_analysis

# Ghidra tools
from reversecore_mcp.tools.ghidra import decompilation

__all__ = [
    "static_analysis",
    "diff_tools",
    "signature_tools",
    "lief_tools",
    "file_operations",
    "lib_tools",
    "r2_analysis",
    "decompilation",
]
