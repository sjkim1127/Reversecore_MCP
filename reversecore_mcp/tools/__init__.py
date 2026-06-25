"""
Tool definitions for Reversecore_MCP.

This package contains tool modules that wrap reverse engineering CLI tools
and libraries, making them accessible to AI agents through the MCP protocol.
"""

# Analysis tools
from reversecore_mcp.tools.analysis import (
    diff_tools,
    emulation_tools,
    lief_tools,
    signature_tools,
    source_auditor,
    static_analysis,
)

# Common tools
from reversecore_mcp.tools.common import file_operations, patch_explainer

# Forensics tools
from reversecore_mcp.tools.forensics import artifact, disk, memory, network

# Ghidra tools
from reversecore_mcp.tools.ghidra import decompilation

# Malware tools
from reversecore_mcp.tools.malware import (
    adaptive_vaccine,
    dormant_detector,
    ioc_tools,
    vulnerability_hunter,
    yara_tools,
)

# Radare2 tools
from reversecore_mcp.tools.radare2 import r2_analysis

# Report tools
from reversecore_mcp.tools.report import report_mcp_tools, report_tools

__all__ = [
    # Analysis tools
    "static_analysis",
    "diff_tools",
    "signature_tools",
    "lief_tools",
    "emulation_tools",
    "source_auditor",
    # Common tools
    "file_operations",
    "patch_explainer",
    # Forensics tools
    "memory",
    "disk",
    "network",
    "artifact",
    # Radare2 tools
    "r2_analysis",
    # Ghidra tools
    "decompilation",
    # Malware tools
    "dormant_detector",
    "adaptive_vaccine",
    "vulnerability_hunter",
    "ioc_tools",
    "yara_tools",
    # Report tools
    "report_tools",
    "report_mcp_tools",
]

# NOTE: Legacy alias 'ghost_trace' was removed in v1.0.0
# Use 'dormant_detector' directly
