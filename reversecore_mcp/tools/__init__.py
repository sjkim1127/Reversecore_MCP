"""Tool definitions for Reversecore_MCP.

Tool modules are exposed lazily so importing :mod:`reversecore_mcp.tools` does
not require every optional reverse-engineering dependency to be installed.
Individual plugins can still fail gracefully during registration when an
optional dependency is unavailable.
"""

from importlib import import_module
from types import ModuleType
from typing import Final

_LAZY_MODULES: Final[dict[str, str]] = {
    # Analysis tools
    "cache_tools": "reversecore_mcp.tools.analysis.cache_tools",
    "crash_triage": "reversecore_mcp.tools.analysis.crash_triage",
    "diff_tools": "reversecore_mcp.tools.analysis.diff_tools",
    "emulation_tools": "reversecore_mcp.tools.analysis.emulation_tools",
    "lief_tools": "reversecore_mcp.tools.analysis.lief_tools",
    "signature_tools": "reversecore_mcp.tools.analysis.signature_tools",
    "source_auditor": "reversecore_mcp.tools.analysis.source_auditor",
    "static_analysis": "reversecore_mcp.tools.analysis.static_analysis",
    # Common tools
    "file_operations": "reversecore_mcp.tools.common.file_operations",
    "patch_explainer": "reversecore_mcp.tools.common.patch_explainer",
    # Forensics tools
    "artifact": "reversecore_mcp.tools.forensics.artifact",
    "disk": "reversecore_mcp.tools.forensics.disk",
    "memory": "reversecore_mcp.tools.forensics.memory",
    "network": "reversecore_mcp.tools.forensics.network",
    # Malware tools
    "adaptive_vaccine": "reversecore_mcp.tools.malware.adaptive_vaccine",
    "dormant_detector": "reversecore_mcp.tools.malware.dormant_detector",
    "ioc_tools": "reversecore_mcp.tools.malware.ioc_tools",
    "vulnerability_hunter": "reversecore_mcp.tools.malware.vulnerability_hunter",
    "yara_tools": "reversecore_mcp.tools.malware.yara_tools",
    # Radare2 tools
    "r2_analysis": "reversecore_mcp.tools.radare2.r2_analysis",
    # Report tools
    "report_mcp_tools": "reversecore_mcp.tools.report.report_mcp_tools",
    "report_tools": "reversecore_mcp.tools.report.report_tools",
}

__all__ = list(_LAZY_MODULES)


def __getattr__(name: str) -> ModuleType:
    """Load a compatibility module export only when it is requested."""
    try:
        module_path = _LAZY_MODULES[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = import_module(module_path)
    globals()[name] = module
    return module


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
