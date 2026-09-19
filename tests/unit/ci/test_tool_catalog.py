"""Unit tests for tool catalog generation and profile benchmark tooling."""

from __future__ import annotations

import pytest

from scripts.benchmark_profiles import (
    EXPECTED_PROFILE_TOOL_COUNTS,
    PROFILES,
    render_markdown_report,
)
from scripts.generate_tool_catalog import (
    PLUGIN_METADATA,
    RESOURCE_TEMPLATES,
    collect_tool_registry,
    render_tools_markdown,
    update_readme_tool_counts,
)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_collect_tool_registry():
    """Verify tool catalog collects all registered FastMCP tools and plugins."""
    catalog = await collect_tool_registry()

    assert catalog["total_tools"] >= 151
    assert len(catalog["all_tools"]) == catalog["total_tools"]

    # Verify all expected plugins are populated
    for plugin_name in PLUGIN_METADATA:
        assert plugin_name in catalog["plugin_tools"]
        assert len(catalog["plugin_tools"][plugin_name]) > 0

    # Ensure every tool has required metadata
    for tool in catalog["all_tools"]:
        assert tool["name"]
        assert tool["description"]
        assert tool["plugin"] in PLUGIN_METADATA
        assert "full" in tool["profiles"]


@pytest.mark.unit
def test_render_tools_markdown():
    """Verify generated catalog markdown structure and contents."""
    mock_catalog = {
        "total_tools": 151,
        "all_tools": [],
        "plugin_tools": {
            "analysis_tools": [
                {
                    "name": "parse_binary_with_lief",
                    "description": "Parse binary headers.",
                    "param_summary": "`file_path` (string, req)",
                    "profiles": ["full", "static"],
                }
            ]
        },
        "profiles": {},
    }

    markdown = render_tools_markdown(mock_catalog)

    assert "# Reversecore MCP Tool Catalog (151 Tools)" in markdown
    assert "## 🧭 Tool Profiles Overview" in markdown
    assert "## 📦 Plugin Summary" in markdown
    assert "## 🛠️ Complete Tool Reference" in markdown
    assert "parse_binary_with_lief" in markdown
    assert "reversecore://guide" in markdown
    assert len(RESOURCE_TEMPLATES) == 11


@pytest.mark.unit
def test_update_readme_tool_counts():
    """Verify regex tool count synchronization across README sections."""
    sample_readme = """
- [Tool Catalog (120 Tools)](#tool-catalog-120-tools)
Reversecore MCP is a server that wraps **120 analysis tools** into a single interface.
│          120 registered tools · Fully async          │
## Tool Catalog (120 Tools)
Complete documentation for all 120 registered tools
├── tools/                         # MCP tool implementations (120 tools)
"""

    updated = update_readme_tool_counts(sample_readme, 151)

    assert "[Tool Catalog (151 Tools)](#tool-catalog-151-tools)" in updated
    assert "wraps **151 analysis tools**" in updated
    assert "151 registered tools · Fully async" in updated
    assert "## Tool Catalog (151 Tools)" in updated
    assert "Complete documentation for all 151 registered tools" in updated
    assert "MCP tool implementations (151 tools)" in updated
    assert "120" not in updated


@pytest.mark.unit
def test_profile_benchmark_expectations():
    """Verify profile benchmark profiles and expected counts."""
    assert "full" in PROFILES
    assert "static" in PROFILES
    assert "malware" in PROFILES
    assert "forensics" in PROFILES
    assert "vuln-research" in PROFILES

    assert EXPECTED_PROFILE_TOOL_COUNTS["full"] == 151
    assert EXPECTED_PROFILE_TOOL_COUNTS["static"] == 97
    assert EXPECTED_PROFILE_TOOL_COUNTS["malware"] == 65
    assert EXPECTED_PROFILE_TOOL_COUNTS["forensics"] == 57
    assert EXPECTED_PROFILE_TOOL_COUNTS["vuln-research"] == 103


@pytest.mark.unit
def test_render_benchmark_markdown_report():
    """Verify markdown benchmark report generation."""
    sample_results = [
        {
            "profile": "full",
            "tool_count": 151,
            "schema_bytes": 115000,
            "schema_kb": 112.3,
            "cold_start_ms": 650.0,
            "rc_modules": 130,
            "rss_mb": 180.0,
            "schema_reduction_pct": 0.0,
            "token_estimate": 28750,
            "tokens_saved": 0,
        },
        {
            "profile": "static",
            "tool_count": 97,
            "schema_bytes": 66000,
            "schema_kb": 64.5,
            "cold_start_ms": 550.0,
            "rc_modules": 120,
            "rss_mb": 175.0,
            "schema_reduction_pct": 42.6,
            "token_estimate": 16500,
            "tokens_saved": 12250,
        },
    ]

    report = render_markdown_report(sample_results)

    assert "# Reversecore MCP Tool Profile Footprint & Benchmark" in report
    assert "`full`" in report
    assert "`static`" in report
    assert "151" in report
    assert "97" in report
    assert "-42.6%" in report
