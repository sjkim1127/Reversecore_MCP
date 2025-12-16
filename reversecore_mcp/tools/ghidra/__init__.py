"""Ghidra tools package."""
from reversecore_mcp.tools.ghidra.ghidra_tools import GhidraToolsPlugin
from reversecore_mcp.tools.ghidra import decompilation

# Backward compatibility re-exports for legacy imports
# These modules have been moved but are re-exported for backward compatibility
from reversecore_mcp.tools.analysis import diff_tools
from reversecore_mcp.tools.analysis import signature_tools
from reversecore_mcp.tools.analysis import static_analysis
from reversecore_mcp.tools.analysis import lief_tools
from reversecore_mcp.tools.common import lib_tools
from reversecore_mcp.tools.radare2 import r2_analysis

__all__ = [
    "GhidraToolsPlugin",
    "decompilation",
    # Backward compatibility
    "diff_tools",
    "signature_tools",
    "static_analysis",
    "lief_tools",
    "lib_tools",
    "r2_analysis",
]
