"""Tool definitions for Reversecore_MCP.

Tool modules are exposed lazily so importing :mod:`reversecore_mcp.tools` does
not require every optional reverse-engineering dependency to be installed.
Individual plugins can still fail gracefully during registration when an
optional dependency is unavailable.
"""

from __future__ import annotations

import sys
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
    "vt_lookup": "reversecore_mcp.tools.analysis.vt_lookup",
    # Common tools
    "file_operations": "reversecore_mcp.tools.common.file_operations",
    "patch_explainer": "reversecore_mcp.tools.common.patch_explainer",
    # Deobfuscation tools
    "deobfuscation_tools": "reversecore_mcp.tools.deobfuscation",
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

# Historical alias modules exposed stable ``__all__`` values. Preserve those
# contracts even when the current implementation module does not define one.
_LEGACY_EXPORTS: Final[dict[str, tuple[str, ...]]] = {
    "patch_explainer": (
        "explain_patch",
        "_generate_explanation",
        "_generate_diff_snippet",
    ),
    "report_tools": ("ReportTools",),
}

__all__ = list(_LAZY_MODULES)


class _LegacyModuleAlias(ModuleType):
    """Lazy ``sys.modules`` alias for a historical flat tool-module path."""

    def __init__(
        self,
        name: str,
        target_path: str,
        exports: tuple[str, ...] = (),
    ) -> None:
        super().__init__(name)
        super().__setattr__("_target_path", target_path)
        super().__setattr__("__all__", list(exports))

    def _load(self) -> ModuleType:
        module = import_module(self._target_path)
        sys.modules[self.__name__] = module

        parent_name, attribute = self.__name__.rsplit(".", 1)
        parent = sys.modules.get(parent_name)
        if parent is not None:
            setattr(parent, attribute, module)
        return module

    def __getattr__(self, name: str):
        return getattr(self._load(), name)


# Older integrations import and patch flat paths such as
# ``reversecore_mcp.tools.static_analysis`` and ``...tools.r2_analysis``. These
# modules now live in category packages. Registering aliases up front prevents
# third-party meta-path finders from trying to resolve non-existent physical
# modules while preserving lazy imports and optional dependency isolation.
#
# Implementation note: ``importlib.import_module(legacy_path)`` reads directly
# from ``sys.modules``, so both the legacy and the canonical key must point to
# the *same object* for ``is``-identity checks to pass.  We therefore try to
# eagerly import the canonical module and register it under both keys; if the
# canonical import fails (optional dependency missing) we fall back to a lazy
# proxy that replaces itself on first attribute access.
for _legacy_name, _target_path in _LAZY_MODULES.items():
    _legacy_path = f"{__name__}.{_legacy_name}"
    if _legacy_path in sys.modules:
        # Already registered — ensure it matches the canonical if loaded.
        if _target_path in sys.modules:
            sys.modules[_legacy_path] = sys.modules[_target_path]
        # else: leave the existing entry as-is
    else:
        try:
            _canonical_mod = import_module(_target_path)
            sys.modules[_legacy_path] = _canonical_mod
        except ImportError:
            # Optional dependency unavailable — use lazy proxy.
            sys.modules[_legacy_path] = _LegacyModuleAlias(
                _legacy_path,
                _target_path,
                _LEGACY_EXPORTS.get(_legacy_name, ()),
            )


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
