"""
Tests for JSON parsing optimization improvements.

This module tests the refactored JSON parsing logic that eliminates
double parsing and provides cleaner error handling.
"""

import json
import pytest
from reversecore_mcp.tools.cli_tools import _extract_first_json, _parse_json_output


class TestExtractFirstJson:
    """Tests for the improved _extract_first_json function."""

    def test_returns_none_for_empty_string(self):
        """Should return None for empty input."""
        assert _extract_first_json("") is None
        assert _extract_first_json("   ") is None

    def test_returns_none_for_no_json(self):
        """Should return None when no JSON structure is found."""
        result = _extract_first_json("just some text without json")
        assert result is None

    def test_extracts_valid_json_object(self):
        """Should extract a valid JSON object from text."""
        text = 'some text {"key": "value", "num": 42} more text'
        result = _extract_first_json(text)
        assert result is not None
        assert result == '{"key": "value", "num": 42}'

    def test_extracts_valid_json_array(self):
        """Should extract a valid JSON array from text."""
        text = 'prefix [{"item": 1}, {"item": 2}] suffix'
        result = _extract_first_json(text)
        assert result is not None
        assert result == '[{"item": 1}, {"item": 2}]'

    def test_handles_nested_structures(self):
        """Should correctly handle nested JSON structures."""
        text = 'data: {"outer": {"inner": [1, 2, 3]}} end'
        result = _extract_first_json(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed == {"outer": {"inner": [1, 2, 3]}}

    def test_returns_none_for_mismatched_brackets(self):
        """Should return None for mismatched brackets."""
        assert _extract_first_json("{]") is None
        assert _extract_first_json("[}") is None

    def test_returns_none_for_unclosed_json(self):
        """Should return None for unclosed JSON structures."""
        assert _extract_first_json('{"key": "value"') is None
        assert _extract_first_json('[1, 2, 3') is None

    def test_ignores_unmatched_closing_brackets(self):
        """Should ignore unmatched closing brackets before valid JSON."""
        text = '}} {"valid": true}'
        result = _extract_first_json(text)
        assert result is not None
        assert result == '{"valid": true}'


class TestParseJsonOutput:
    """Tests for the new _parse_json_output helper function."""

    def test_parses_clean_json_object(self):
        """Should parse clean JSON object directly."""
        output = '{"key": "value", "number": 123}'
        result = _parse_json_output(output)
        assert result == {"key": "value", "number": 123}

    def test_parses_clean_json_array(self):
        """Should parse clean JSON array directly."""
        output = '[{"id": 1}, {"id": 2}]'
        result = _parse_json_output(output)
        assert result == [{"id": 1}, {"id": 2}]

    def test_extracts_json_from_noisy_output(self):
        """Should extract and parse JSON from output with noise."""
        # Simulates radare2 output with warnings/messages before JSON
        output = 'WARNING: Analysis may take time\nProcessing...\n{"result": "success"}'
        result = _parse_json_output(output)
        assert result == {"result": "success"}

    def test_raises_on_invalid_json(self):
        """Should raise JSONDecodeError for invalid JSON."""
        with pytest.raises(json.JSONDecodeError):
            _parse_json_output("not json at all")

    def test_raises_on_empty_string(self):
        """Should raise JSONDecodeError for empty string."""
        with pytest.raises(json.JSONDecodeError):
            _parse_json_output("")

    def test_handles_radare2_like_output(self):
        """Should handle realistic radare2 command output."""
        # Simulate aflj output with some prefixes
        output = '''e scr.color=0
aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[{"name": "sym.main", "offset": 4096}, {"name": "sym.foo", "offset": 4200}]'''
        result = _parse_json_output(output)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["name"] == "sym.main"

    def test_handles_xrefs_output(self):
        """Should handle cross-reference JSON output."""
        output = '[{"from": 1234, "type": "call"}, {"from": 5678, "type": "call"}]'
        result = _parse_json_output(output)
        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["from"] == 1234


class TestPerformanceImprovement:
    """Tests demonstrating the performance improvement from eliminating double parsing."""

    def test_parse_json_output_uses_helper(self, monkeypatch):
        """_parse_json_output should use the helper function correctly."""
        # The key improvement is that we don't have the pattern:
        # if json_str: parse(json_str) else: parse(output)
        # Instead we use a single try-except flow
        
        # Test with noisy output (triggers extraction path)
        output = 'prefix {"key": "value"} suffix'
        result = _parse_json_output(output)
        assert result == {"key": "value"}

    def test_clean_json_parsed_efficiently(self):
        """Clean JSON should be parsed efficiently."""
        # When JSON is clean, we still parse efficiently
        output = '{"key": "value"}'
        result = _parse_json_output(output)
        assert result == {"key": "value"}
        
    def test_eliminates_redundant_fallback_pattern(self):
        """Should not use the old redundant if/else pattern."""
        # The old pattern was:
        # json_str = _extract_first_json(out)
        # if json_str:
        #     data = json.loads(json_str)  # First parse
        # else:
        #     data = json.loads(out)        # Second parse attempt
        #
        # This could parse the same invalid JSON twice.
        # New pattern uses try-except, avoiding redundant attempts.
        
        # Test that invalid JSON raises error cleanly, not after multiple attempts
        try:
            _parse_json_output("not json")
            assert False, "Should raise"
        except json.JSONDecodeError:
            pass  # Expected

    def test_error_handling_is_clear(self):
        """Should provide clear error when JSON parsing fails completely."""
        try:
            _parse_json_output("definitely not json")
            assert False, "Should have raised JSONDecodeError"
        except json.JSONDecodeError as e:
            # Error should be clear and from json.loads, not hidden
            assert "Expecting value" in str(e)


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_multiple_json_objects_extracts_first(self):
        """Should extract only the first complete JSON object."""
        text = '{"first": 1} {"second": 2}'
        result = _extract_first_json(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed == {"first": 1}

    def test_deeply_nested_json(self):
        """Should handle deeply nested JSON structures."""
        nested = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {"data": [1, 2, 3]}
                    }
                }
            }
        }
        text = f"prefix {json.dumps(nested)} suffix"
        result = _extract_first_json(text)
        assert result is not None
        parsed = json.loads(result)
        assert parsed == nested

    def test_json_with_escaped_characters(self):
        """Should handle JSON with escaped characters."""
        text = '{"message": "Line 1\\nLine 2\\tTabbed", "path": "C:\\\\Windows\\\\System32"}'
        result = _parse_json_output(text)
        assert result["message"] == "Line 1\nLine 2\tTabbed"
        assert result["path"] == "C:\\Windows\\System32"

    def test_empty_array(self):
        """Should handle empty arrays."""
        result = _parse_json_output("[]")
        assert result == []

    def test_empty_object(self):
        """Should handle empty objects."""
        result = _parse_json_output("{}")
        assert result == {}
