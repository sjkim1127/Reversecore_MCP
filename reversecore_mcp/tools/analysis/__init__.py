"""Static analysis tools package.

Provides a unified AnalysisToolsPlugin that registers all analysis-related tools
while keeping resource-facing modules lazy. This lets the base wheel import the
server without requiring optional analysis dependencies such as LIEF.
"""

from importlib import import_module
from types import ModuleType
from typing import Any, Final

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.plugin import Plugin

logger = get_logger(__name__)


class _LazyModule(ModuleType):
    """Module proxy that imports its target on first attribute access."""

    def __init__(self, module_path: str) -> None:
        super().__init__(module_path)
        self._module_path = module_path

    def _load(self) -> ModuleType:
        module = import_module(self._module_path)
        globals()[self._module_path.rsplit(".", 1)[-1]] = module
        return module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._load(), name)


# ``reversecore_mcp.resources`` imports these modules at server import time.
# Keep them as proxies so optional analysis extras are only required when the
# corresponding resource is actually used.
_LAZY_RESOURCE_MODULES: Final[dict[str, str]] = {
    "capa_tools": "reversecore_mcp.tools.analysis.capa_tools",
    "die_tools": "reversecore_mcp.tools.analysis.die_tools",
    "lief_tools": "reversecore_mcp.tools.analysis.lief_tools",
    "static_analysis": "reversecore_mcp.tools.analysis.static_analysis",
}

for _name, _module_path in _LAZY_RESOURCE_MODULES.items():
    globals()[_name] = _LazyModule(_module_path)


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
        from reversecore_mcp.tools.analysis.advanced_yara import (
            generate_advanced_yara_rule,
        )
        from reversecore_mcp.tools.analysis.capa_tools import (
            run_capa,
            run_capa_quick,
        )
        from reversecore_mcp.tools.analysis.crash_triage import triage_crash
        from reversecore_mcp.tools.analysis.die_tools import (
            detect_packer,
            detect_packer_deep,
        )
        from reversecore_mcp.tools.analysis.diff_tools import (
            analyze_variant_changes,
            diff_binaries,
            match_libraries,
            patch_diff_1day,
        )
        from reversecore_mcp.tools.analysis.emulation_tools import emulate_binary
        from reversecore_mcp.tools.analysis.fuzz_tools import generate_fuzzing_harness
        from reversecore_mcp.tools.analysis.fuzzing_campaign import run_fuzzing_campaign
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
        from reversecore_mcp.tools.analysis.patch_vuln_inference import (
            analyze_patch_diff_auto,
        )
        from reversecore_mcp.tools.analysis.signature_tools import (
            generate_enhanced_yara_rule,
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
        from reversecore_mcp.tools.analysis.symbolic_analysis import (
            verify_path_and_get_args_tool,
        )
        from reversecore_mcp.tools.analysis.taint_analysis import taint_trace
        from reversecore_mcp.tools.analysis.vt_lookup import vt_lookup

        # Register all tools
        mcp_server.tool(generate_advanced_yara_rule)
        mcp_server.tool(diff_binaries)
        mcp_server.tool(analyze_variant_changes)
        mcp_server.tool(match_libraries)
        mcp_server.tool(patch_diff_1day)
        mcp_server.tool(parse_binary_with_lief)
        mcp_server.tool(generate_signature)
        mcp_server.tool(generate_yara_rule)
        mcp_server.tool(generate_enhanced_yara_rule)
        mcp_server.tool(run_strings)
        mcp_server.tool(run_binwalk)
        mcp_server.tool(run_binwalk_extract)
        mcp_server.tool(scan_for_versions)
        mcp_server.tool(extract_rtti_info)
        mcp_server.tool(detect_packer)
        mcp_server.tool(detect_packer_deep)
        mcp_server.tool(run_capa)
        mcp_server.tool(run_capa_quick)
        mcp_server.tool(emulate_binary)
        mcp_server.tool(generate_fuzzing_harness)
        mcp_server.tool(run_fuzzing_campaign)
        mcp_server.tool(triage_crash)
        mcp_server.tool(name="verify_path_and_get_args")(verify_path_and_get_args_tool)
        mcp_server.tool(analyze_patch_diff_auto)
        mcp_server.tool(taint_trace)
        mcp_server.tool(vt_lookup)

        logger.info(f"Registered {self.name} plugin with 27 analysis tools (unified)")


__all__ = ["AnalysisToolsPlugin", *_LAZY_RESOURCE_MODULES]
