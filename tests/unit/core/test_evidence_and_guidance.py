"""Unit tests for Retained Evidence Cache, inspect_analysis_view, and Guidance Tools."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.evidence_cache import EvidenceCache, get_evidence_cache
from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.tools.common.evidence_view_tools import inspect_analysis_view
from reversecore_mcp.tools.common.guidance_tools import (
    read_guidance_section,
    search_guidance,
)


def test_evidence_cache_store_and_query_view():
    """Verify EvidenceCache stores facets, paginates slices, and applies filters."""
    cache = EvidenceCache(max_records=10)
    ev_id = cache.store(
        tool_name="Radare2_list_strings",
        target_path="/workspace/sample.bin",
        facets={
            "strings": [
                "https://c2.evil.example/beacon",
                "http://update.evil.example/payload",
                "/etc/passwd",
                "C:\\Windows\\System32\\cmd.exe",
                "normal_string_1",
            ],
            "pseudocode": 'int main() {\n  printf("hello");\n  return 0;\n}',
        },
        summary={"total_strings": 5},
    )

    assert ev_id.startswith("ev_")

    # 1. Paginate primary facet ('strings')
    view1 = cache.query_view(ev_id, offset=0, limit=2)
    assert view1 is not None
    assert view1["selected_facet"] == "strings"
    assert view1["total_items"] == 5
    assert view1["returned_items"] == 2
    assert view1["has_more"] is True
    assert view1["next_offset"] == 2

    # 2. Filter by substring
    view_filtered = cache.query_view(ev_id, facet="strings", filter_query="evil.example")
    assert view_filtered is not None
    assert view_filtered["total_items"] == 2
    assert all("evil.example" in s for s in view_filtered["items"])

    # 3. Query string-typed facet ('pseudocode' auto-splits into numbered lines)
    view_code = cache.query_view(ev_id, facet="pseudocode", offset=0, limit=10)
    assert view_code is not None
    assert view_code["total_items"] == 4
    assert view_code["items"][0]["line_number"] == 1
    assert "int main()" in view_code["items"][0]["text"]


def test_evidence_cache_lru_eviction():
    """Verify EvidenceCache evicts oldest records beyond max_records."""
    cache = EvidenceCache(max_records=8)
    ids = [cache.store("test_tool", f"/path/{i}", {"items": [i]}) for i in range(12)]
    # First 4 should be evicted
    assert cache.get(ids[0]) is None
    assert cache.get(ids[-1]) is not None
    assert len(cache.list_records(limit=50)) == 8


@pytest.mark.asyncio
async def test_inspect_analysis_view_tool():
    """Verify inspect_analysis_view MCP tool handles valid IDs, 'list', and unknown IDs."""
    cache = get_evidence_cache()
    ev_id = cache.store(
        tool_name="test_producer",
        target_path="/workspace/app.exe",
        facets={"functions": ["main.init", "main.runServer", "crypto.Decrypt"]},
        summary={"count": 3},
    )

    # Query valid evidence_id
    res = await inspect_analysis_view(evidence_id=ev_id, facet="functions", filter_query="main.")
    assert isinstance(res, ToolSuccess)
    assert res.data["total_items"] == 2
    assert "main.runServer" in res.data["items"]

    # List retained evidence records
    res_list = await inspect_analysis_view(evidence_id="list")
    assert isinstance(res_list, ToolSuccess)
    assert res_list.data["total_retained"] >= 1
    retained_ids = [r["evidence_id"] for r in res_list.data["records"]]
    assert ev_id in retained_ids

    # Unknown evidence_id
    res_missing = await inspect_analysis_view(evidence_id="ev_nonexistent00")
    assert isinstance(res_missing, ToolError)
    assert res_missing.error_code == "EVIDENCE_NOT_FOUND"


@pytest.mark.asyncio
async def test_search_and_read_guidance():
    """Verify on-demand guidance search and section retrieval."""
    # Search for Go/Rust guidance
    res_search = await search_guidance(query="go rust gopclntab")
    assert isinstance(res_search, ToolSuccess)
    assert res_search.data["total_matches"] >= 1
    top_locator = res_search.data["results"][0]["locator"]
    assert "go-rust" in top_locator or "playbook:" in top_locator

    # Read exact playbook section
    res_read = await read_guidance_section(
        locator="playbook:go-rust-reversing#gopclntab-and-crates"
    )
    assert isinstance(res_read, ToolSuccess)
    assert "gopclntab" in res_read.data["content"]
    assert len(res_read.data["related_locators"]) >= 1

    # Read by prefix
    res_prefix = await read_guidance_section(locator="playbook:electron-asar")
    assert isinstance(res_prefix, ToolSuccess)
    assert "Electron" in res_prefix.data["content"]

    # Unknown guidance locator
    res_err = await read_guidance_section(locator="nonexistent:guide#nothing")
    assert isinstance(res_err, ToolError)
    assert res_err.error_code == "GUIDANCE_NOT_FOUND"


def test_skill_and_plugin_packaging_manifests():
    """Verify SKILL.md, .agents/skills, .claude-plugin, and .codex-plugin manifests exist and are valid."""
    repo_root = Path(__file__).resolve().parents[3]

    root_skill = repo_root / "SKILL.md"
    agent_skill = repo_root / ".agents" / "skills" / "reversecore-mcp" / "SKILL.md"
    claude_plugin = repo_root / ".claude-plugin" / "plugin.json"
    codex_plugin = repo_root / ".codex-plugin" / "plugin.json"
    codex_mcp = repo_root / ".codex-plugin" / "mcp.json"

    assert root_skill.is_file()
    assert "name: reversecore-mcp" in root_skill.read_text(encoding="utf-8")
    assert agent_skill.is_file()

    claude_data = json.loads(claude_plugin.read_text(encoding="utf-8"))
    assert claude_data["name"] == "reversecore-mcp"
    assert "reversecore" in claude_data["mcpServers"]

    codex_data = json.loads(codex_plugin.read_text(encoding="utf-8"))
    assert codex_data["name"] == "reversecore-mcp"
    assert codex_mcp.is_file()
