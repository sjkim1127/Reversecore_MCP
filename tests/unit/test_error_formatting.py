"""
Unit tests for core.error_formatting utilities.
"""

import os
import json
import pytest

from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import ValidationError, ExecutionTimeoutError


def test_format_error_plain_without_hint(monkeypatch):
    monkeypatch.delenv("STRUCTURED_ERRORS", raising=False)
    err = ValidationError("Invalid file path", details={"path": "/bad"})
    text = format_error(err, tool_name="run_test")
    assert isinstance(text, str)
    assert "Invalid file path" in text


def test_format_error_plain_with_hint(monkeypatch):
    monkeypatch.delenv("STRUCTURED_ERRORS", raising=False)
    err = ValidationError("Outside workspace", details={"path": "/etc/passwd"})
    hint = get_validation_hint(err)
    text = format_error(err, tool_name="run_test", hint=hint)
    assert "Hint" in text or "hint" in text.lower()


def test_format_error_structured_json(monkeypatch):
    monkeypatch.setenv("STRUCTURED_ERRORS", "true")
    # Reload settings to pick up new environment variable
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    err = ExecutionTimeoutError(timeout_seconds=5)
    data = format_error(err, tool_name="run_test")
    # Should be a dict
    assert isinstance(data, dict)
    assert data["error_type"].upper().find("TIMEOUT") >= 0
    assert data.get("details", {}).get("tool_name") == "run_test"


def test_get_validation_hint_defaults():
    # Unknown error falls back to generic hint
    hint = get_validation_hint(ValueError("something"))
    assert isinstance(hint, str)
    assert len(hint) > 0


def test_get_validation_hint_workspace_error():
    """Test hint for workspace-related errors."""
    hint = get_validation_hint(ValueError("file is outside the workspace"))
    assert "workspace" in hint.lower()
    assert "REVERSECORE_WORKSPACE" in hint


def test_get_validation_hint_directory_error():
    """Test hint for directory path errors."""
    hint = get_validation_hint(ValueError("path does not point to a file"))
    assert "directory" in hint.lower()
    assert "file path" in hint.lower()


def test_get_validation_hint_invalid_path_error():
    """Test hint for invalid path errors."""
    hint = get_validation_hint(ValueError("invalid file path provided"))
    assert "file path" in hint.lower() or "invalid" in hint.lower()


def test_format_error_generic_exception(monkeypatch):
    """Test formatting of generic (non-Reversecore) exceptions."""
    monkeypatch.delenv("STRUCTURED_ERRORS", raising=False)
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    err = RuntimeError("Something went wrong")
    text = format_error(err)
    assert isinstance(text, str)
    assert "Something went wrong" in text


def test_format_error_structured_with_hint(monkeypatch):
    """Test structured error formatting with hint."""
    monkeypatch.setenv("STRUCTURED_ERRORS", "true")
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    err = ValidationError("Invalid parameter")
    data = format_error(err, hint="Check the parameter value")
    assert isinstance(data, dict)
    assert data["hint"] == "Check the parameter value"


def test_format_error_with_tool_name_attribute(monkeypatch):
    """Test formatting error that has tool_name attribute."""
    monkeypatch.delenv("STRUCTURED_ERRORS", raising=False)
    from reversecore_mcp.core.config import reload_settings
    from reversecore_mcp.core.exceptions import ToolNotFoundError
    reload_settings()
    
    err = ToolNotFoundError(tool_name="radare2")
    text = format_error(err)
    assert isinstance(text, str)


def test_format_error_with_timeout_attributes(monkeypatch):
    """Test formatting error with timeout attributes."""
    monkeypatch.setenv("STRUCTURED_ERRORS", "true")
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    err = ExecutionTimeoutError(timeout_seconds=60)
    data = format_error(err)
    assert isinstance(data, dict)
    assert "timeout_seconds" in data["details"]
    assert data["details"]["timeout_seconds"] == 60


def test_format_error_with_size_attributes(monkeypatch):
    """Test formatting error with size attributes."""
    monkeypatch.setenv("STRUCTURED_ERRORS", "true")
    from reversecore_mcp.core.config import reload_settings
    from reversecore_mcp.core.exceptions import OutputLimitExceededError
    reload_settings()
    
    err = OutputLimitExceededError(max_size=1000000, actual_size=2000000)
    data = format_error(err)
    assert isinstance(data, dict)
    assert "max_size" in data["details"]
    assert "actual_size" in data["details"]


def test_format_error_generic_structured(monkeypatch):
    """Test formatting generic exception in structured mode."""
    monkeypatch.setenv("STRUCTURED_ERRORS", "true")
    from reversecore_mcp.core.config import reload_settings
    reload_settings()
    
    err = KeyError("missing_key")
    data = format_error(err)
    assert isinstance(data, dict)
    assert data["error_code"] == "RCMCP-E000"
    assert data["error_type"] == "SYSTEM_ERROR"
    assert "exception_type" in data["details"]
    assert data["details"]["exception_type"] == "KeyError"
