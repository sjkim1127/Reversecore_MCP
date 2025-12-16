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

# Malware tools - backward compatibility aliases
from reversecore_mcp.tools.malware import dormant_detector
from reversecore_mcp.tools.malware import adaptive_vaccine
from reversecore_mcp.tools.malware import vulnerability_hunter

# Legacy aliases for renamed modules
ghost_trace = dormant_detector  # ghost_trace was renamed to dormant_detector

# Report tools - backward compatibility
from reversecore_mcp.tools.report import report_tools
from reversecore_mcp.tools.report import report_mcp_tools

__all__ = [
    "static_analysis",
    "diff_tools",
    "signature_tools",
    "lief_tools",
    "file_operations",
    "lib_tools",
    "r2_analysis",
    "decompilation",
    # Malware tools
    "dormant_detector",
    "adaptive_vaccine",
    "vulnerability_hunter",
    "ghost_trace",  # Legacy alias
    # Report tools
    "report_tools",
    "report_mcp_tools",
]
