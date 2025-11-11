"""
More unit tests for tools.cli_tools covering additional branches.
"""

import pytest

from reversecore_mcp.tools import cli_tools
from reversecore_mcp.core.exceptions import ValidationError


def test_run_radare2_invalid_command_sanitization(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_tools, "validate_file_path", lambda p, read_only=False: str(tmp_path / "a.out"))
    def _sanitize(cmd):
        raise ValueError("invalid")
    monkeypatch.setattr(cli_tools, "sanitize_command_string", lambda s: _sanitize(s))
    out = cli_tools.run_radare2(str(tmp_path / "a.out"), "bad")
    assert "error" in out.lower()


def test_run_strings_validation_error(monkeypatch, tmp_path):
    def _raise(_p, read_only=False):
        raise ValidationError("Outside workspace")
    monkeypatch.setattr(cli_tools, "validate_file_path", _raise)
    out = cli_tools.run_strings(str(tmp_path / "x"))
    assert "error" in out.lower() and "outside" in out.lower()
