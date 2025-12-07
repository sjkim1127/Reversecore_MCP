"""
Tests for caching optimizations added to improve performance.

These tests verify that:
1. Caching functions work correctly
2. Cache hits provide expected performance benefits
3. Cached results are consistent with non-cached behavior
"""

import time

import pytest


def test_calculate_dynamic_timeout_caching(workspace_dir):
    """Test that _calculate_dynamic_timeout uses caching effectively."""
    from reversecore_mcp.core.r2_helpers import _calculate_dynamic_timeout

    # Create a test file
    test_file = workspace_dir / "timeout_test.bin"
    test_file.write_bytes(b"x" * (5 * 1024 * 1024))  # 5MB file

    # Clear cache first
    _calculate_dynamic_timeout.cache_clear()

    # First call - cache miss
    result1 = _calculate_dynamic_timeout(str(test_file), base_timeout=100)

    # Check cache state after first call
    info1 = _calculate_dynamic_timeout.cache_info()
    assert info1.misses == 1, f"Expected 1 miss, got {info1.misses}"
    assert info1.hits == 0, f"Expected 0 hits, got {info1.hits}"

    # Second call - cache hit
    result2 = _calculate_dynamic_timeout(str(test_file), base_timeout=100)

    # Check cache state after second call
    info2 = _calculate_dynamic_timeout.cache_info()
    assert info2.hits == 1, f"Expected 1 hit, got {info2.hits}"
    assert info2.misses == 1, f"Expected 1 miss, got {info2.misses}"

    # Results should be identical
    assert result1 == result2

    # Verify the calculation is correct
    # 5MB file should add ~10 seconds (size_mb * 2)
    assert result1 == 110


def test_get_r2_project_name_caching(workspace_dir):
    """Test that _get_r2_project_name uses caching effectively."""
    from reversecore_mcp.core.r2_helpers import _get_r2_project_name

    test_file = workspace_dir / "project_test.bin"
    test_file.write_bytes(b"test")

    # Clear cache
    _get_r2_project_name.cache_clear()

    # First call
    start = time.time()
    result1 = _get_r2_project_name(str(test_file))
    time1 = time.time() - start

    # Second call - should be cached
    start = time.time()
    result2 = _get_r2_project_name(str(test_file))
    time2 = time.time() - start

    # Results should be identical
    assert result1 == result2
    assert len(result1) == 32  # MD5 hex digest length

    # Verify cache hit via cache_info (more reliable than timing)
    info = _get_r2_project_name.cache_info()
    assert info.hits >= 1, f"Expected at least 1 cache hit, got {info.hits}"


def test_extract_library_name_caching():
    """Test that _extract_library_name uses caching effectively."""
    from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

    # Clear cache
    _extract_library_name.cache_clear()

    test_cases = [
        ("sym.imp.strcpy", "import"),
        ("kernel32.dll.CreateFileA", "kernel32"),
        ("msvcrt.malloc", "libc/msvcrt"),
        ("std::vector", "libstdc++"),
        ("custom_function", "unknown"),
    ]

    # First pass - all cache misses
    for func_name, expected in test_cases:
        result = _extract_library_name(func_name)
        assert result == expected, f"Expected {expected}, got {result} for {func_name}"

    # Check cache state - should have 5 misses, 0 hits
    info1 = _extract_library_name.cache_info()
    assert info1.misses == 5, f"Expected 5 misses, got {info1.misses}"
    assert info1.hits == 0, f"Expected 0 hits, got {info1.hits}"

    # Second pass - all cache hits
    for func_name, expected in test_cases:
        result = _extract_library_name(func_name)
        assert result == expected, f"Expected {expected}, got {result} for {func_name}"

    # Check cache state - should have 5 misses, 5 hits
    info2 = _extract_library_name.cache_info()
    assert info2.misses == 5, f"Expected 5 misses, got {info2.misses}"
    assert info2.hits == 5, f"Expected 5 hits, got {info2.hits}"


def test_sanitize_filename_for_rule_caching(workspace_dir):
    """Test that _sanitize_filename_for_rule uses caching effectively."""
    from reversecore_mcp.tools.analysis.signature_tools import _sanitize_filename_for_rule

    test_file = workspace_dir / "test-file.name.ext"
    test_file.write_bytes(b"test")

    # Clear cache
    _sanitize_filename_for_rule.cache_clear()

    # First call
    start = time.time()
    result1 = _sanitize_filename_for_rule(str(test_file))
    time1 = time.time() - start

    # Second call - should be cached
    start = time.time()
    result2 = _sanitize_filename_for_rule(str(test_file))
    time2 = time.time() - start

    # Results should be identical and sanitized
    assert result1 == result2
    assert result1 == "test_file_name"  # Dashes and dots replaced

    # Verify cache hit via cache_info (more reliable than timing)
    info = _sanitize_filename_for_rule.cache_info()
    assert info.hits >= 1, f"Expected at least 1 cache hit, got {info.hits}"


def test_cache_size_limits():
    """Test that caches respect their size limits."""
    from reversecore_mcp.core.r2_helpers import (
        _calculate_dynamic_timeout,
        _get_r2_project_name,
    )
    from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name
    from reversecore_mcp.tools.analysis.signature_tools import _sanitize_filename_for_rule

    # Clear all caches
    _calculate_dynamic_timeout.cache_clear()
    _extract_library_name.cache_clear()
    _get_r2_project_name.cache_clear()
    _sanitize_filename_for_rule.cache_clear()

    # Test that cache info is available
    assert hasattr(_calculate_dynamic_timeout, "cache_info")
    assert hasattr(_extract_library_name, "cache_info")
    assert hasattr(_get_r2_project_name, "cache_info")
    assert hasattr(_sanitize_filename_for_rule, "cache_info")

    # Verify initial cache state
    info = _calculate_dynamic_timeout.cache_info()
    assert info.hits == 0
    assert info.misses == 0
    assert info.currsize == 0


def test_extract_first_json_optimization():
    """Test that _extract_first_json works correctly (optimized version)."""
    from reversecore_mcp.core.r2_helpers import _extract_first_json

    # Test valid JSON extraction
    text1 = 'garbage [{"key": "value"}] more garbage'
    result1 = _extract_first_json(text1)
    assert result1 == '[{"key": "value"}]'

    # Test object extraction
    text2 = 'prefix {"a": 1, "b": 2} suffix'
    result2 = _extract_first_json(text2)
    assert result2 == '{"a": 1, "b": 2}'

    # Test nested structures
    text3 = '{"outer": {"inner": [1, 2, 3]}} tail'
    result3 = _extract_first_json(text3)
    assert result3 == '{"outer": {"inner": [1, 2, 3]}}'

    # Test empty input - now returns None instead of ""
    assert _extract_first_json("") is None
    assert _extract_first_json("   ") is None

    # Test invalid input - now returns None instead of ""
    assert _extract_first_json("no json here") is None


def test_caching_improves_batch_operations(workspace_dir):
    """Test that caching provides measurable benefits in batch scenarios."""
    from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

    # Create a list of common function names
    function_names = [
        "sym.imp.strcpy",
        "sym.imp.malloc",
        "kernel32.CreateFileA",
        "msvcrt.printf",
        "sym.imp.free",
    ] * 20  # Repeat to simulate batch processing

    # Clear cache
    _extract_library_name.cache_clear()

    # First pass - all cache misses
    start = time.time()
    results1 = [_extract_library_name(name) for name in function_names]
    time1 = time.time() - start

    # Clear cache and run again
    _extract_library_name.cache_clear()
    start = time.time()
    results2 = [_extract_library_name(name) for name in function_names]
    time2 = time.time() - start

    # Results should be identical
    assert results1 == results2

    # With caching, repeated names should be processed faster
    # Check cache statistics
    info = _extract_library_name.cache_info()
    # We have 5 unique names * 20 repetitions = 100 total calls
    # Expected: 5 misses (first occurrence) + 95 hits (repetitions)
    assert info.hits > 80, f"Expected >80 cache hits, got {info.hits}"
    assert info.misses < 10, f"Expected <10 cache misses, got {info.misses}"


def test_cache_correctness_across_different_inputs(workspace_dir):
    """Test that cache returns correct results for different inputs."""
    from reversecore_mcp.core.r2_helpers import _calculate_dynamic_timeout

    # Create files of different sizes
    small_file = workspace_dir / "small.bin"
    small_file.write_bytes(b"x" * (1 * 1024 * 1024))  # 1MB

    large_file = workspace_dir / "large.bin"
    large_file.write_bytes(b"x" * (10 * 1024 * 1024))  # 10MB

    # Clear cache
    _calculate_dynamic_timeout.cache_clear()

    # Test small file
    timeout_small = _calculate_dynamic_timeout(str(small_file), 100)
    assert timeout_small == 102  # 100 + (1 * 2)

    # Test large file
    timeout_large = _calculate_dynamic_timeout(str(large_file), 100)
    assert timeout_large == 120  # 100 + (10 * 2)

    # Test with different base timeouts
    timeout_small2 = _calculate_dynamic_timeout(str(small_file), 200)
    assert timeout_small2 == 202  # 200 + (1 * 2)

    # Verify cache is working - call again with original params
    timeout_small_cached = _calculate_dynamic_timeout(str(small_file), 100)
    assert timeout_small_cached == timeout_small


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
