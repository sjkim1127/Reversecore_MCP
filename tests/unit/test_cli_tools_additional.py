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
    # New Result type format includes "Error:" and error details
    assert "Error" in out and ("non-zero exit status" in out.lower() or "unexpected error" in out.lower())


def test_run_binwalk_success(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "fw.bin"))
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", lambda cmd, **kw: ("BINWALK OK", 50))
    out = cli_tools.run_binwalk(str(tmp_path / "fw.bin"))
    assert "BINWALK" in out


def test_run_binwalk_called_process_error(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "fw.bin"))
    def raise_cpe(cmd, **kw):
        raise subprocess.CalledProcessError(2, cmd, output="", stderr="bad arg")
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_cpe)
    out = cli_tools.run_binwalk(str(tmp_path / "fw.bin"))
    # New Result type format includes "Error:" and error details
    assert "Error" in out and ("non-zero exit status" in out.lower() or "unexpected error" in out.lower())


def test_run_radare2_success(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "a.out"))
    monkeypatch.setattr(cli_tools, "validate_r2_command", lambda s, allow_write=False: None)
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", lambda cmd, **kw: ("r2 out", 10))
    out = cli_tools.run_radare2(str(tmp_path / "a.out"), "i")
    assert isinstance(out, str)


def test_run_radare2_tool_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "a.out"))
    monkeypatch.setattr(cli_tools, "validate_r2_command", lambda s, allow_write=False: None)
    def raise_not_found(cmd, **kw):
        raise ToolNotFoundError("r2")
    monkeypatch.setattr(cli_tools, "execute_subprocess_streaming", raise_not_found)
    out = cli_tools.run_radare2(str(tmp_path / "a.out"), "i")
    assert "not found" in out.lower()
