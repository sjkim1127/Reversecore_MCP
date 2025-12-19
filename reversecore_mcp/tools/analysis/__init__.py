"""Static analysis tools package.

Provides a unified AnalysisToolsPlugin that registers all analysis-related tools.
"""

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class AnalysisToolsPlugin(Plugin):
    """Unified plugin for all static analysis tools."""

    @property
    def name(self) -> str:
        return "analysis_tools"

    @property
    def description(self) -> str:
        return "Unified static analysis tools including diffing, LIEF parsing, signature generation, and string extraction."

    def register(self, mcp_server: Any) -> None:
        """Register all analysis tools."""
        # Import tool functions from submodules
        from reversecore_mcp.tools.analysis.die_tools import (
            detect_packer,
            detect_packer_deep,
        )
        from reversecore_mcp.tools.analysis.diff_tools import (
            analyze_variant_changes,
            diff_binaries,
            match_libraries,
        )
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
        from reversecore_mcp.tools.analysis.signature_tools import (
            generate_signature,
            generate_yara_rule,
        )
        from reversecore_mcp.tools.analysis.static_analysis import (
            extract_rtti_info,
            run_binwalk,
            run_binwalk_extract,
            run_strings,
            scan_for_versions,
        )

        # Register all tools
        mcp_server.tool(diff_binaries)
        mcp_server.tool(analyze_variant_changes)
        mcp_server.tool(match_libraries)
        mcp_server.tool(parse_binary_with_lief)
        mcp_server.tool(generate_signature)
        mcp_server.tool(generate_yara_rule)
        mcp_server.tool(run_strings)
        mcp_server.tool(run_binwalk)
        mcp_server.tool(run_binwalk_extract)
        mcp_server.tool(scan_for_versions)
        mcp_server.tool(extract_rtti_info)
        mcp_server.tool(detect_packer)
        mcp_server.tool(detect_packer_deep)

        logger.info(f"Registered {self.name} plugin with 13 analysis tools (unified)")


__all__ = ["AnalysisToolsPlugin"]
