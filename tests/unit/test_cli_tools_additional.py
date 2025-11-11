"""
Additional unit tests for tools.cli_tools using mocks.
"""

import subprocess
import pytest

from reversecore_mcp.tools import cli_tools
from reversecore_mcp.core.exceptions import ToolNotFoundError, ExecutionTimeoutError


class Dummy:
    pass


def test_run_file_success(monkeypatch, tmp_path):
    # Mock validator to return path
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "x"))
    # Mock executor to return output
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", lambda cmd, **kw: ("ELF 64-bit", 20))
    out = cli_tools.run_file(str(tmp_path / "x"))
    assert "ELF" in out


def test_run_file_tool_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "x"))
    def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("file")
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_not_found)
    out = cli_tools.run_file(str(tmp_path / "x"))
    assert "Error" in out and "not found" in out.lower()


def test_run_strings_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "x"))
    def raise_timeout(cmd, **kw):
        raise ExecutionTimeoutError(1)
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_timeout)
    out = cli_tools.run_strings(str(tmp_path / "x"))
    assert "Error" in out and "timed out" in out.lower()


def test_run_strings_called_process_error(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "x"))
    def raise_cpe(cmd, **kw):
        e = subprocess.CalledProcessError(1, cmd, output="", stderr="bad")
        raise e
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_cpe)
    out = cli_tools.run_strings(str(tmp_path / "x"))
    assert "exit code" in out.lower()
