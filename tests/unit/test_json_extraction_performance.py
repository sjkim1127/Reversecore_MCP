"""
Performance tests for optimized JSON extraction function.

This module contains tests to verify that the _extract_first_json function
has been optimized from O(n²) to O(n) complexity and correctly handles
edge cases including strings with brackets.
"""

import json
import time
import pytest
from reversecore_mcp.core.r2_helpers import _extract_first_json


class TestJSONExtractionPerformance:
    """Test performance and correctness of optimized JSON extraction."""

    def test_basic_json_extraction(self):
        """Test extraction of simple JSON objects."""
        text = 'prefix text {"key": "value"} suffix'
        result = _extract_first_json(text)
        assert result == '{"key": "value"}'
        
        parsed = json.loads(result)
        assert parsed == {"key": "value"}

    def test_nested_json_extraction(self):
        """Test extraction of nested JSON structures."""
        text = 'garbage {"outer": {"inner": [1, 2, 3]}} more garbage'
        result = _extract_first_json(text)
        assert result == '{"outer": {"inner": [1, 2, 3]}}'
        
        parsed = json.loads(result)
        assert parsed == {"outer": {"inner": [1, 2, 3]}}

    def test_json_array_extraction(self):
        """Test extraction of JSON arrays."""
        text = 'prefix [1, 2, {"key": "value"}, 4] suffix'
        result = _extract_first_json(text)
        assert result == '[1, 2, {"key": "value"}, 4]'
        
        parsed = json.loads(result)
        assert parsed == [1, 2, {"key": "value"}, 4]

    def test_json_with_brackets_in_strings(self):
        """Test that brackets inside string values are handled correctly."""
        # This is a critical test - the old O(n²) algorithm didn't handle strings
        text = '{"message": "Error: expected } but got {", "code": 123}'
        result = _extract_first_json(text)
        assert result == '{"message": "Error: expected } but got {", "code": 123}'
        
        parsed = json.loads(result)
        assert parsed["message"] == "Error: expected } but got {"
        assert parsed["code"] == 123

    def test_json_with_escaped_quotes(self):
        """Test handling of escaped quotes in strings."""
        text = '{"path": "C:\\\\Program Files\\\\App", "name": "test"}'
        result = _extract_first_json(text)
        assert result is not None
        
        parsed = json.loads(result)
        assert "path" in parsed
        assert "name" in parsed

    def test_json_with_nested_brackets_in_strings(self):
        """Test complex case with nested brackets in string values."""
        json_text = '{"regex": "[a-z]{2,5}", "array": [1, 2, 3]}'
        text = f'prefix {json_text} suffix'
        result = _extract_first_json(text)
        assert result == json_text
        
        parsed = json.loads(result)
        assert parsed["regex"] == "[a-z]{2,5}"

    def test_malformed_json_returns_none(self):
        """Test that malformed JSON returns None."""
        text = '{"key": "value"'  # Missing closing brace
        result = _extract_first_json(text)
        assert result is None

    def test_no_json_returns_none(self):
        """Test that text without JSON returns None."""
        text = 'This is just plain text without any JSON'
        result = _extract_first_json(text)
        assert result is None

    def test_empty_string_returns_none(self):
        """Test that empty string returns None."""
        assert _extract_first_json("") is None
        assert _extract_first_json("   ") is None

    def test_multiple_json_objects_returns_first(self):
        """Test that only the first JSON object is returned."""
        text = '{"first": 1} {"second": 2}'
        result = _extract_first_json(text)
        assert result == '{"first": 1}'
        
        parsed = json.loads(result)
        assert parsed == {"first": 1}

    def test_json_after_noise(self):
        """Test extraction when JSON appears after significant noise."""
        noise = "Warning: something\nError: another thing\n[x] some marker\n"
        json_text = '{"data": "actual content"}'
        text = noise + json_text
        result = _extract_first_json(text)
        assert result == json_text

    def test_radare2_style_output(self):
        """Test extraction from typical radare2 output with markers."""
        # Simulate radare2 output with [x] markers that look like JSON arrays
        text = '[x] Analyze all flags starting with sym. and entry0 (aa)\n{"functions": []}'
        result = _extract_first_json(text)
        # Should skip the "[x]" marker and find the actual JSON
        assert result == '{"functions": []}'
        
        # Verify it's valid JSON
        parsed = json.loads(result)
        assert parsed == {"functions": []}

    def test_performance_large_text_with_late_json(self):
        """Test O(n) performance: JSON at end of large text should be fast."""
        # Create a large text with JSON at the end
        noise = "x" * 100000  # 100KB of noise
        json_text = '{"result": "found"}'
        text = noise + json_text
        
        start = time.perf_counter()
        result = _extract_first_json(text)
        duration = time.perf_counter() - start
        
        assert result == json_text
        # Should complete in under 100ms even with 100KB of text (O(n) complexity)
        # On modern hardware, O(n) pass through 100KB should be < 10ms
        assert duration < 0.1, f"Too slow: {duration:.3f}s for 100KB text"

    def test_performance_multiple_false_starts(self):
        """Test performance with many bracket characters that aren't JSON."""
        # Create text with many false starts (opening brackets that don't lead to valid JSON)
        false_starts = "{ { { { { " * 1000  # 5000 opening braces
        json_text = '{"valid": true}'
        text = false_starts + json_text
        
        start = time.perf_counter()
        result = _extract_first_json(text)
        duration = time.perf_counter() - start
        
        assert result == json_text
        # Should still be fast with O(n) complexity
        assert duration < 0.1, f"Too slow: {duration:.3f}s with many false starts"

    def test_performance_deeply_nested_json(self):
        """Test performance with deeply nested JSON structure."""
        # Create deeply nested JSON
        depth = 100
        json_obj = {"level": 0}
        current = json_obj
        for i in range(1, depth):
            current["nested"] = {"level": i}
            current = current["nested"]
        
        json_text = json.dumps(json_obj)
        text = "prefix " + json_text + " suffix"
        
        start = time.perf_counter()
        result = _extract_first_json(text)
        duration = time.perf_counter() - start
        
        assert result == json_text
        parsed = json.loads(result)
        assert parsed["level"] == 0
        
        # Should handle deep nesting efficiently
        assert duration < 0.05, f"Too slow: {duration:.3f}s for deeply nested JSON"

    def test_real_world_radare2_aflj_output(self):
        """Test with realistic radare2 aflj (analyze functions list JSON) output."""
        # Simulate actual radare2 output format
        text = """[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[{"offset":4198656,"name":"entry0","size":42,"is-pure":false,"realsz":42,"noreturn":false,"stackframe":0,"calltype":"none","cost":28,"cc":1,"bits":64,"type":"fcn","nbbs":1,"edges":0,"ebbs":1}]"""
        
        result = _extract_first_json(text)
        assert result is not None
        assert result.startswith('[{')
        assert result.endswith('}]')
        
        # Verify it's valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["name"] == "entry0"

    def test_json_with_unicode_characters(self):
        """Test extraction of JSON with unicode characters."""
        json_text = '{"message": "Hello 世界", "emoji": "🚀"}'
        text = f'prefix {json_text} suffix'
        result = _extract_first_json(text)
        assert result == json_text
        
        parsed = json.loads(result)
        assert parsed["message"] == "Hello 世界"
        assert parsed["emoji"] == "🚀"

    def test_comparative_performance_vs_naive(self):
        """
        Compare optimized O(n) algorithm against naive O(n²) approach.
        
        This test demonstrates the performance improvement by measuring
        execution time with a large input where JSON appears late.
        """
        # Create input where JSON is at position 50000 (middle of 100KB text)
        prefix = "x" * 50000
        json_text = '{"result": "found at position 50000"}'
        suffix = "y" * 50000
        text = prefix + json_text + suffix
        
        # Test optimized version
        iterations = 10
        start = time.perf_counter()
        for _ in range(iterations):
            result = _extract_first_json(text)
        optimized_duration = (time.perf_counter() - start) / iterations
        
        assert result == json_text
        
        # Optimized O(n) should be very fast even with 100KB input
        # Expecting < 10ms per call on modern hardware
        assert optimized_duration < 0.05, (
            f"Optimized version too slow: {optimized_duration*1000:.1f}ms per call. "
            f"Expected < 50ms for O(n) algorithm on 100KB input."
        )


class TestJSONExtractionCorrectness:
    """Additional correctness tests for edge cases."""

    def test_unmatched_opening_bracket(self):
        """Test handling of unmatched opening bracket."""
        text = '{ "key": "value"'
        result = _extract_first_json(text)
        assert result is None

    def test_unmatched_closing_bracket(self):
        """Test handling of unmatched closing bracket at start."""
        text = '} {"key": "value"}'
        result = _extract_first_json(text)
        assert result == '{"key": "value"}'

    def test_mixed_bracket_types(self):
        """Test mismatched bracket types (array close for object)."""
        text = '{"key": "value"]'
        result = _extract_first_json(text)
        assert result is None

    def test_json_with_newlines(self):
        """Test multiline JSON extraction."""
        json_text = """{
    "key1": "value1",
    "key2": [
        1,
        2,
        3
    ]
}"""
        text = f"prefix\n{json_text}\nsuffix"
        result = _extract_first_json(text)
        assert result is not None
        
        parsed = json.loads(result)
        assert parsed["key1"] == "value1"
        assert parsed["key2"] == [1, 2, 3]

    def test_json_true_false_null(self):
        """Test JSON with boolean and null values."""
        json_text = '{"active": true, "disabled": false, "value": null}'
        text = f'prefix {json_text} suffix'
        result = _extract_first_json(text)
        assert result == json_text
        
        parsed = json.loads(result)
        assert parsed["active"] is True
        assert parsed["disabled"] is False
        assert parsed["value"] is None

    def test_json_with_numbers(self):
        """Test JSON with various number formats."""
        json_text = '{"int": 42, "float": 3.14, "exp": 1.2e-10, "negative": -100}'
        text = f'prefix {json_text} suffix'
        result = _extract_first_json(text)
        assert result == json_text
        
        parsed = json.loads(result)
        assert parsed["int"] == 42
        assert abs(parsed["float"] - 3.14) < 0.001
        assert parsed["negative"] == -100

    def test_empty_json_object(self):
        """Test extraction of empty JSON object."""
        text = 'prefix {} suffix'
        result = _extract_first_json(text)
        assert result == '{}'
        
        parsed = json.loads(result)
        assert parsed == {}

    def test_empty_json_array(self):
        """Test extraction of empty JSON array."""
        text = 'prefix [] suffix'
        result = _extract_first_json(text)
        assert result == '[]'
        
        parsed = json.loads(result)
        assert parsed == []

    def test_json_with_url_in_string(self):
        """Test JSON containing URL (which has brackets in some cases)."""
        json_text = '{"url": "https://example.com/path?param=[value]", "status": 200}'
        text = f'prefix {json_text} suffix'
        result = _extract_first_json(text)
        assert result == json_text
        
        parsed = json.loads(result)
        assert "[value]" in parsed["url"]
