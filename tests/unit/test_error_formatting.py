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
