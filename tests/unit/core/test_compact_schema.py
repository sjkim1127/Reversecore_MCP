"""Unit tests for FastMCP Compact Schema Profile."""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from reversecore_mcp.core.compact_schema import (
    compact_json_schema,
    compact_tool_description,
    setup_compact_schema_mode,
)


@pytest.mark.unit
def test_compact_tool_description_strips_args_and_returns():
    docstring = """
    Analyze a binary file for threats and vulnerabilities.

    Use this tool before running deeper static analysis.

    Args:
        file_path: Path to the binary file to analyze.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult containing analysis data or error.

    Raises:
        ValidationError: If file_path is invalid.

    Example:
        >>> result = analyze_binary("sample.exe")
    """
    compacted = compact_tool_description(docstring)
    assert "Analyze a binary file for threats and vulnerabilities." in compacted
    assert "Use this tool before running deeper static analysis." in compacted
    assert "Args:" not in compacted
    assert "file_path:" not in compacted
    assert "Returns:" not in compacted
    assert "Example:" not in compacted


@pytest.mark.unit
def test_compact_tool_description_length_limit():
    very_long = "This is a detailed reverse engineering analysis tool. " * 20
    compacted = compact_tool_description(very_long, max_length=100)
    assert len(compacted) <= 100
    assert compacted.endswith("...") or compacted.endswith(".")


@pytest.mark.unit
def test_compact_tool_description_empty_or_none():
    assert compact_tool_description("") == ""
    assert compact_tool_description(None) == ""
    assert compact_tool_description("   ") == ""


@pytest.mark.unit
def test_compact_json_schema_strips_annotations_and_depth():
    schema = {
        "title": "ComplexToolInput",
        "description": "Full schema description",
        "type": "object",
        "examples": [{"a": 1}],
        "properties": {
            "file_path": {
                "title": "FilePath",
                "type": "string",
                "examples": ["/path/to/bin"],
            },
            "nested": {
                "type": "object",
                "properties": {
                    "level2": {
                        "type": "object",
                        "properties": {
                            "level3": {
                                "type": "string",
                            }
                        },
                    }
                },
            },
        },
    }

    # Depth clamped at 1
    compacted = compact_json_schema(schema, max_depth=1)
    assert "title" not in compacted
    assert "examples" not in compacted
    assert "file_path" in compacted["properties"]
    assert "title" not in compacted["properties"]["file_path"]
    assert "examples" not in compacted["properties"]["file_path"]
    # nested properties beyond depth 1 are pruned/clamped
    assert "properties" not in compacted["properties"]["nested"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_setup_compact_schema_mode():
    mcp = FastMCP("test_compact_server")

    @mcp.tool(
        description=(
            "Sample tool for testing schema compaction. Detailed paragraph.\n\n"
            "Args:\n"
            "    file_path: The target file path.\n\n"
            "Returns:\n"
            "    Success message."
        )
    )
    def sample_tool(file_path: str, options: str = "default") -> str:
        return f"OK: {file_path}"

    # In full mode, list_tools returns full descriptions
    tools_before = await mcp.list_tools()
    assert "Args:" in (tools_before[0].description or "")

    # Activate compact mode
    setup_compact_schema_mode(mcp, profile="compact")

    tools_after = await mcp.list_tools()
    assert len(tools_after) == 1
    assert "Sample tool for testing schema compaction." in (tools_after[0].description or "")
    assert "Args:" not in (tools_after[0].description or "")
