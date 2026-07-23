from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    ("legacy_path", "target_path"),
    [
        (
            "reversecore_mcp.tools.static_analysis",
            "reversecore_mcp.tools.analysis.static_analysis",
        ),
        (
            "reversecore_mcp.tools.r2_analysis",
            "reversecore_mcp.tools.radare2.r2_analysis",
        ),
        (
            "reversecore_mcp.tools.file_operations",
            "reversecore_mcp.tools.common.file_operations",
        ),
    ],
)
def test_legacy_tool_module_aliases_resolve_to_current_modules(
    legacy_path: str, target_path: str
) -> None:
    assert importlib.import_module(legacy_path) is importlib.import_module(target_path)
