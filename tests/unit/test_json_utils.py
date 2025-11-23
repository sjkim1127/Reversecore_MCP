"""Tests for high-performance JSON utilities."""

import time
import pytest
from reversecore_mcp.core import json_utils

# Test configuration constants
MAX_EXPECTED_SERIALIZATION_TIME = 1.0  # seconds for 100 iterations of test data


class TestJSONUtils:
    """Test json_utils module functionality."""

    def test_loads_string(self):
        """Test loads() with string input."""
        json_str = '{"key": "value", "number": 42}'
        result = json_utils.loads(json_str)
        assert result == {"key": "value", "number": 42}

    def test_loads_bytes(self):
        """Test loads() with bytes input."""
        json_bytes = b'{"key": "value", "number": 42}'
        result = json_utils.loads(json_bytes)
        assert result == {"key": "value", "number": 42}

    def test_dumps_simple(self):
        """Test dumps() with simple object."""
        obj = {"key": "value", "number": 42}
        result = json_utils.dumps(obj)
        # Parse back to verify
        parsed = json_utils.loads(result)
        assert parsed == obj

    def test_dumps_with_indent(self):
        """Test dumps() with indentation."""
        obj = {"key": "value", "nested": {"a": 1, "b": 2}}
        result = json_utils.dumps(obj, indent=2)
        assert isinstance(result, str)
        # Should contain newlines for formatting
        assert '\n' in result
        # Parse back to verify
        parsed = json_utils.loads(result)
        assert parsed == obj

    def test_dumps_list(self):
        """Test dumps() with list."""
        obj = [1, 2, 3, "four", {"five": 5}]
        result = json_utils.dumps(obj)
        parsed = json_utils.loads(result)
        assert parsed == obj

    def test_loads_complex(self):
        """Test loads() with complex nested structure."""
        json_str = '''
        {
            "string": "value",
            "number": 123,
            "float": 45.67,
            "bool": true,
            "null": null,
            "array": [1, 2, 3],
            "nested": {
                "key": "nested_value"
            }
        }
        '''
        result = json_utils.loads(json_str)
        assert result["string"] == "value"
        assert result["number"] == 123
        assert result["float"] == 45.67
        assert result["bool"] is True
        assert result["null"] is None
        assert result["array"] == [1, 2, 3]
        assert result["nested"]["key"] == "nested_value"

    def test_round_trip(self):
        """Test that dumps -> loads preserves data."""
        original = {
            "text": "Hello, World!",
            "numbers": [1, 2, 3, 4, 5],
            "nested": {
                "a": 1,
                "b": 2,
                "c": [{"x": 10}, {"y": 20}]
            }
        }
        json_str = json_utils.dumps(original)
        parsed = json_utils.loads(json_str)
        assert parsed == original

    def test_is_orjson_available(self):
        """Test is_orjson_available() returns bool."""
        result = json_utils.is_orjson_available()
        assert isinstance(result, bool)
        # Just verify it returns something, actual value depends on installation

    def test_unicode_handling(self):
        """Test Unicode string handling."""
        obj = {"text": "Hello 世界 🌍", "emoji": "🚀"}
        json_str = json_utils.dumps(obj)
        parsed = json_utils.loads(json_str)
        assert parsed == obj

    def test_empty_objects(self):
        """Test empty dict and list."""
        assert json_utils.loads("{}") == {}
        assert json_utils.loads("[]") == []
        assert json_utils.dumps({}) == "{}"
        assert json_utils.dumps([]) == "[]"

    def test_performance_note(self):
        """Verify performance characteristics (documentation test)."""
        # This test documents the expected performance benefit
        # When orjson is available: 3-5x faster than stdlib json
        # When not available: fallback to stdlib json (same performance)
        
        obj = {"data": list(range(1000)), "nested": [{"key": i} for i in range(100)]}
        
        # Warm up
        for _ in range(10):
            json_utils.dumps(obj)
        
        # Time the operation
        start = time.time()
        for _ in range(100):
            json_utils.dumps(obj)
        duration = time.time() - start
        
        # Should complete in reasonable time (sanity check)
        assert duration < MAX_EXPECTED_SERIALIZATION_TIME, \
            f"JSON serialization too slow: {duration}s (max: {MAX_EXPECTED_SERIALIZATION_TIME}s)"
        
        # Log whether we're using orjson or fallback
        print(f"\nUsing orjson: {json_utils.is_orjson_available()}")
        print(f"Serialization time for 100 iterations: {duration:.3f}s")

    def test_json_decode_error_import(self):
        """Test that JSONDecodeError is properly exposed."""
        # Verify JSONDecodeError is accessible
        assert hasattr(json_utils, 'JSONDecodeError')
        assert json_utils.JSONDecodeError is not None
        
    def test_invalid_json_raises_error(self):
        """Test that invalid JSON raises JSONDecodeError."""
        with pytest.raises(json_utils.JSONDecodeError):
            json_utils.loads("invalid json {]")
    
    def test_dumps_none(self):
        """Test dumps() with None value."""
        result = json_utils.dumps(None)
        assert result == "null"
        assert json_utils.loads(result) is None
    
    def test_dumps_boolean_values(self):
        """Test dumps() with boolean values."""
        assert json_utils.loads(json_utils.dumps(True)) is True
        assert json_utils.loads(json_utils.dumps(False)) is False
    
    def test_dumps_numeric_types(self):
        """Test dumps() with various numeric types."""
        result = json_utils.dumps({"int": 42, "float": 3.14, "negative": -10})
        parsed = json_utils.loads(result)
        assert parsed["int"] == 42
        assert abs(parsed["float"] - 3.14) < 0.001
        assert parsed["negative"] == -10
    
    def test_large_nested_structure(self):
        """Test with large nested data structure."""
        large_obj = {
            "level1": {
                "level2": {
                    "level3": {
                        "data": list(range(100)),
                        "strings": [f"item_{i}" for i in range(50)]
                    }
                }
            }
        }
        json_str = json_utils.dumps(large_obj)
        parsed = json_utils.loads(json_str)
        assert parsed == large_obj
    
    def test_special_characters_in_strings(self):
        """Test handling of special characters."""
        obj = {
            "newline": "line1\nline2",
            "tab": "col1\tcol2",
            "quote": 'He said "hello"',
            "backslash": "path\\to\\file"
        }
        json_str = json_utils.dumps(obj)
        parsed = json_utils.loads(json_str)
        assert parsed == obj
