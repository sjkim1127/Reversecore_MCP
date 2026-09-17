"""Unit tests for backward compatibility aliases in reversecore_mcp.tools."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent


def test_patch_explainer_alias_file_execution():
    """Verify reversecore_mcp/tools/patch_explainer.py file executes and re-exports symbols."""
    path = ROOT / "reversecore_mcp" / "tools" / "patch_explainer.py"
    spec = importlib.util.spec_from_file_location(
        "reversecore_mcp.tools.patch_explainer", str(path)
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert hasattr(mod, "explain_patch")
    assert hasattr(mod, "_generate_explanation")
    assert hasattr(mod, "_generate_diff_snippet")
    assert "explain_patch" in mod.__all__


def test_report_tools_alias_file_execution():
    """Verify reversecore_mcp/tools/report_tools.py file executes and re-exports symbols."""
    path = ROOT / "reversecore_mcp" / "tools" / "report_tools.py"
    spec = importlib.util.spec_from_file_location("reversecore_mcp.tools.report_tools", str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert hasattr(mod, "ReportTools")
    assert "ReportTools" in mod.__all__
