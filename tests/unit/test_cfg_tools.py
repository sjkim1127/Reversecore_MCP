"""Unit tests for CFG visualization tools."""

import json
import subprocess

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools import cli_tools
from reversecore_mcp.tools import r2_analysis


def test_radare2_json_to_mermaid_basic():
    """Test basic JSON to Mermaid conversion."""
    test_json = json.dumps([{
        "blocks": [
            {
                "offset": 4194304,
                "ops": [
                    {"opcode": "push rbp"},
                    {"opcode": "mov rbp, rsp"}
                ],
                "jump": 4194320,
                "fail": 4194312
            }
        ]
    }])
    
    result = r2_analysis._radare2_json_to_mermaid(test_json)
    
    assert "graph TD" in result
    assert "N_0x400000" in result
    assert "push rbp" in result
    assert "-->|True|" in result
    assert "-.->|False|" in result


def test_radare2_json_to_mermaid_empty():
    """Test Mermaid conversion with empty data."""
    test_json = json.dumps([])
    
    result = r2_analysis._radare2_json_to_mermaid(test_json)
    
    assert "Error[No graph data found]" in result


def test_radare2_json_to_mermaid_invalid_json():
    """Test Mermaid conversion with invalid JSON."""
    result = r2_analysis._radare2_json_to_mermaid("invalid json{]")
    
    assert "Error[Parse Error:" in result


def test_radare2_json_to_mermaid_long_block():
    """Test that long blocks are truncated."""
    ops = [{"opcode": f"instruction_{i}"} for i in range(10)]
    test_json = json.dumps([{"blocks": [{"offset": 0x1000, "ops": ops}]}])
    
    result = r2_analysis._radare2_json_to_mermaid(test_json)
    
    # Should only show first 5 instructions + "..."
    assert "..." in result
    assert "instruction_0" in result
    assert "instruction_4" in result
    assert "instruction_9" not in result


@pytest.mark.asyncio
async def test_generate_function_graph_validation_error(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test generate_function_graph with invalid parameters."""
    # Test invalid format
    result = await cli_tools.generate_function_graph(
        file_path=str(workspace_dir / "test.bin"),
        function_address="main",
        format="invalid_format"
    )
    
    assert result.status == "error"
    assert "VALIDATION_ERROR" in result.error_code or "Invalid format" in result.message


@pytest.mark.asyncio
async def test_generate_function_graph_json_format(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test generate_function_graph with JSON output format."""
    from pathlib import Path
    
    # Create test binary
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        # Return mock radare2 JSON output
        mock_output = json.dumps([{
            "blocks": [
                {
                    "offset": 0x1000,
                    "ops": [{"opcode": "nop"}],
                    "jump": 0x1004
                }
            ]
        }])
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.generate_function_graph(
        file_path=str(test_file),
        function_address="main",
        format="json"
    )
    
    assert result.status == "success"
    assert "blocks" in result.data


@pytest.mark.asyncio
async def test_generate_function_graph_mermaid_format(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test generate_function_graph with Mermaid output format."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        mock_output = json.dumps([{
            "blocks": [
                {
                    "offset": 0x1000,
                    "ops": [{"opcode": "push rbp"}, {"opcode": "mov rbp, rsp"}],
                    "jump": 0x1010
                }
            ]
        }])
        return (mock_output, len(mock_output))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.generate_function_graph(
        file_path=str(test_file),
        function_address="0x1000",
        format="mermaid"
    )
    
    assert result.status == "success"
    assert "graph TD" in result.data
    assert "push rbp" in result.data
    assert result.metadata.get("format") == "mermaid"


@pytest.mark.asyncio
async def test_generate_function_graph_invalid_address(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test generate_function_graph with invalid function address."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    # Test with shell injection attempt
    result = await cli_tools.generate_function_graph(
        file_path=str(test_file),
        function_address="main; rm -rf /",
        format="json"
    )
    
    assert result.status == "error"
    assert "VALIDATION_ERROR" in result.error_code


@pytest.mark.asyncio
async def test_generate_function_graph_dot_format(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Test generate_function_graph with DOT output format."""
    test_file = workspace_dir / "test.bin"
    test_file.write_bytes(b"\x00" * 100)
    
    async def mock_exec(cmd, **kw):
        # Return mock DOT output
        mock_dot = "digraph G {\\n  node_1000 -> node_1010;\\n}"
        return (mock_dot, len(mock_dot))
    
    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", mock_exec)
    
    result = await cli_tools.generate_function_graph(
        file_path=str(test_file),
        function_address="main",
        format="dot"
    )
    
    assert result.status == "success"
    assert "digraph" in result.data or result.metadata.get("format") == "dot"
