"""Additional unit tests for tools.cli_tools using mocks."""

import subprocess

import pytest

from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.tools import cli_tools
from reversecore_mcp.tools import file_operations, static_analysis, r2_analysis
from reversecore_mcp.core import command_spec


def _create_workspace_file(workspace_dir, name: str, data: str | bytes = "stub"):
    path = workspace_dir / name
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data)
    return path


@pytest.mark.asyncio
async def test_run_file_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")
    
    async def mock_exec(cmd, **kw):
        return ("ELF 64-bit", 20)
    
    monkeypatch.setattr(
        file_operations,
        "execute_subprocess_async",
        mock_exec,
    )
    out = await cli_tools.run_file(str(mocked_path))
    assert out.status == "success" and "ELF" in out.data


@pytest.mark.asyncio
async def test_run_file_tool_not_found(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    async def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("file")

    monkeypatch.setattr(file_operations, "execute_subprocess_async", raise_not_found)
    out = await cli_tools.run_file(str(mocked_path))
    assert out.status == "error" and out.error_code == "TOOL_NOT_FOUND"


@pytest.mark.asyncio
async def test_run_strings_timeout(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    async def raise_timeout(cmd, **kw):
        raise ExecutionTimeoutError(1)

    monkeypatch.setattr(static_analysis, "execute_subprocess_async", raise_timeout)
    out = await cli_tools.run_strings(str(mocked_path))
    assert out.status == "error" and out.error_code == "TIMEOUT"


@pytest.mark.asyncio
async def test_run_strings_called_process_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "x")

    async def raise_cpe(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="bad")

    monkeypatch.setattr(static_analysis, "execute_subprocess_async", raise_cpe)
    out = await cli_tools.run_strings(str(mocked_path))
    assert out.status == "error" and out.error_code == "INTERNAL_ERROR"


@pytest.mark.asyncio
async def test_run_binwalk_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "fw.bin")
    
    async def mock_exec(cmd, **kw):
        return ("BINWALK OK", 50)
    
    monkeypatch.setattr(
        static_analysis,
        "execute_subprocess_async",
        mock_exec,
    )
    out = await cli_tools.run_binwalk(str(mocked_path))
    assert out.status == "success" and "BINWALK" in out.data


@pytest.mark.asyncio
async def test_run_binwalk_called_process_error(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "fw.bin")

    async def raise_cpe(cmd, **kw):
        raise subprocess.CalledProcessError(2, cmd, output="", stderr="bad arg")

    monkeypatch.setattr(static_analysis, "execute_subprocess_async", raise_cpe)
    out = await cli_tools.run_binwalk(str(mocked_path))
    assert out.status == "error" and out.error_code == "INTERNAL_ERROR"


@pytest.mark.asyncio
async def test_run_radare2_success(monkeypatch, workspace_dir, patched_workspace_config):
    mocked_path = _create_workspace_file(workspace_dir, "a.out")
    monkeypatch.setattr(command_spec, "validate_r2_command", lambda s: s)
    
    async def mock_exec(cmd, **kw):
        return ("r2 out", 10)
    
    monkeypatch.setattr(
        r2_analysis,
        "execute_subprocess_async",
        mock_exec,
    )
    out = await cli_tools.run_radare2(str(mocked_path), "i")
    assert out.status == "success" and out.data == "r2 out"


@pytest.mark.asyncio
async def test_run_radare2_tool_not_found(
    monkeypatch,
    workspace_dir,
    patched_workspace_config,
):
    mocked_path = _create_workspace_file(workspace_dir, "a.out")
    monkeypatch.setattr(command_spec, "validate_r2_command", lambda s: s)

    async def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("r2")

    monkeypatch.setattr(r2_analysis, "execute_subprocess_async", raise_not_found)
    out = await cli_tools.run_radare2(str(mocked_path), "i")
    assert out.status == "error" and out.error_code == "TOOL_NOT_FOUND"
