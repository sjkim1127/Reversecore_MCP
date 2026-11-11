"""Unit tests for Dynamic Analysis tools (trace_execution & dump_process_memory)."""

from __future__ import annotations

import os

import pytest

from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.tools.dynamic.memory_dumper import dump_process_memory
from reversecore_mcp.tools.dynamic.sandbox_tracer import trace_execution


@pytest.fixture
def mock_exec_binary(workspace_dir):
    """Create a minimal runnable shell script acting as an executable binary."""
    sample = workspace_dir / "target_prog.sh"
    content = (
        "#!/bin/sh\n"
        "echo 'HELLO DYNAMIC SANDBOX'\n"
        "if [ \"$1\" = 'drop' ]; then\n"
        "  echo 'dropped payload' > dropped.txt\n"
        "fi\n"
        "if [ \"$1\" = 'hang' ]; then\n"
        "  sleep 10\n"
        "fi\n"
        "exit 0\n"
    )
    sample.write_text(content)
    sample.chmod(0o755)
    return sample


@pytest.mark.asyncio
async def test_trace_execution_basic(mock_exec_binary, patched_workspace_config):
    """Test standard trace execution capturing stdout and exit code."""
    res = await trace_execution(str(mock_exec_binary), timeout=5)
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert data["exit_code"] == 0
    assert "HELLO DYNAMIC SANDBOX" in data["stdout"]
    assert data["timed_out"] is False
    assert data["execution_duration_ms"] >= 0


@pytest.mark.asyncio
async def test_trace_execution_file_activity(mock_exec_binary, patched_workspace_config):
    """Test trace execution detects created files in workspace."""
    res = await trace_execution(str(mock_exec_binary), arguments=["drop"], timeout=5)
    assert res.status == "success"
    data = res.data
    assert "created_files" in data["file_activity"]
    # Check dropped.txt was detected
    created = [os.path.basename(f) for f in data["file_activity"]["created_files"]]
    assert "dropped.txt" in created
    assert any("dropped" in a for a in data["anomalies"])


@pytest.mark.asyncio
async def test_trace_execution_timeout(mock_exec_binary, patched_workspace_config):
    """Test trace execution handles timeouts properly."""
    res = await trace_execution(str(mock_exec_binary), arguments=["hang"], timeout=1)
    assert res.status == "success"
    data = res.data
    assert data["timed_out"] is True
    assert any("timed out" in a.lower() for a in data["anomalies"])


@pytest.mark.asyncio
async def test_trace_execution_invalid_path(patched_workspace_config):
    """Test trace execution fails with non-existent file."""
    res = await trace_execution("/non/existent/target.bin")
    assert res.status == "error"
    assert res.error is not None


@pytest.mark.asyncio
async def test_dump_process_memory_basic(mock_exec_binary, patched_workspace_config):
    """Test dump_process_memory spawns, inspects, and creates dump segments."""
    res = await dump_process_memory(
        str(mock_exec_binary), wait_ms=50, filter_permissions="all", timeout=5
    )
    assert isinstance(res, ToolResult)
    assert res.status == "success"
    data = res.data
    assert data["status"] == "success"
    assert "dumped_files" in data
    assert len(data["dumped_files"]) > 0
    assert data["fission_pipeline_ready"] is True
    first_dump = data["dumped_files"][0]
    assert "file_path" in first_dump
    assert "entropy" in first_dump
    assert "sha256" in first_dump


@pytest.mark.asyncio
async def test_dump_process_memory_invalid_path(patched_workspace_config):
    """Test dump_process_memory error handling for invalid path."""
    res = await dump_process_memory("/non/existent/target.bin")
    assert res.status == "error"
