"""Radare2 tools package."""
from reversecore_mcp.tools.radare2.radare2_mcp_tools import Radare2ToolsPlugin
from reversecore_mcp.tools.radare2 import r2_analysis

# Backward compatibility re-exports for legacy imports
from reversecore_mcp.tools.analysis import static_analysis

__all__ = [
    "Radare2ToolsPlugin",
    "r2_analysis",
    # Backward compatibility
    "static_analysis",
]
