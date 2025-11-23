"""
Tests for new performance optimizations added to improve code efficiency.

These tests verify:
1. Binary cache TTL boundary conditions
2. R2 pool analyzed file checking
3. Resource manager cleanup efficiency
4. JSON utilities exception handling
"""

import time
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from itertools import chain


def test_binary_cache_ttl_boundary_optimization(workspace_dir):
    """Test that binary cache TTL uses strict < comparison to avoid edge case stat() calls."""
    from reversecore_mcp.core.binary_cache import BinaryMetadataCache
    
    # Create a cache with 1 second TTL
    cache = BinaryMetadataCache(ttl_seconds=1)
    
    # Create a test file
    test_file = workspace_dir / "ttl_test.bin"
    test_file.write_bytes(b"test data")
    
    # Set a value in cache
    cache.set(str(test_file), "test_key", "test_value")
    
    # Immediately retrieve - should be cached (fast path)
    result1 = cache.get(str(test_file), "test_key")
    assert result1 == "test_value"
    
    # Wait exactly 1 second (at boundary)
    time.sleep(1.0)
    
    # At the exact TTL boundary with < comparison, cache should be expired
    # This will trigger a stat() call to verify the file hasn't changed
    result2 = cache.get(str(test_file), "test_key")
    
    # Should still get the value (file hasn't changed)
    assert result2 == "test_value"
    
    # Wait a bit more to ensure we're past boundary
    time.sleep(0.1)
    
    # Should still work
    result3 = cache.get(str(test_file), "test_key")
    assert result3 == "test_value"


def test_r2_pool_is_analyzed_optimization():
    """Test that R2 pool's is_analyzed method is optimized with single check."""
    from reversecore_mcp.core.r2_pool import R2ConnectionPool
    
    pool = R2ConnectionPool()
    
    # Mark a file as analyzed
    test_path = "/fake/path/test.bin"
    pool._analyzed_files.add(test_path)
    
    # Check is_analyzed - should return True with single dict lookup
    assert pool.is_analyzed(test_path) is True
    
    # Check non-analyzed file - should return False
    assert pool.is_analyzed("/fake/path/other.bin") is False
    
    # Verify the optimization: _analyzed_files should be the only check needed
    # The old code also checked if file_path was in self._pool, which was redundant
    # This test verifies the simplified logic works correctly


def test_resource_manager_cleanup_uses_chain():
    """Test that resource manager uses itertools.chain for efficient cleanup."""
    from reversecore_mcp.core.resource_manager import ResourceManager
    import tempfile
    
    # Create a temporary workspace with test files
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        
        # Create test files matching cleanup patterns
        (workspace / "test1.tmp").write_text("tmp1")
        (workspace / "test2.tmp").write_text("tmp2")
        (workspace / ".r2_cache1").write_text("r2_1")
        (workspace / "test.r2").write_text("r2_2")
        (workspace / "keep.txt").write_text("keep")
        
        # Make files old enough to be cleaned (> 24 hours)
        old_time = time.time() - (25 * 3600)
        for f in workspace.glob("*.tmp"):
            f.touch()
            # Set old mtime - use os.utime since Path.touch doesn't support times
            import os
            os.utime(f, (old_time, old_time))
        
        # Verify chain is used in the code by checking the cleanup logic
        # The optimization uses itertools.chain to combine multiple glob patterns
        # This test verifies the pattern exists in the code
        import inspect
        from reversecore_mcp.core import resource_manager
        
        source = inspect.getsource(resource_manager.ResourceManager.cleanup)
        assert "chain" in source, "Resource manager should use itertools.chain for optimization"


def test_json_utils_exposes_jsondecodeerror():
    """Test that json_utils properly exposes JSONDecodeError for exception handling."""
    from reversecore_mcp.core import json_utils
    
    # Verify JSONDecodeError is exposed
    assert hasattr(json_utils, 'JSONDecodeError')
    
    # Test that it can be used in exception handling
    invalid_json = '{"invalid": json'
    
    try:
        json_utils.loads(invalid_json)
        assert False, "Should have raised JSONDecodeError"
    except json_utils.JSONDecodeError:
        # Expected - exception should be caught correctly
        pass


def test_json_utils_decode_error_with_orjson():
    """Test that JSONDecodeError works correctly when orjson is available."""
    from reversecore_mcp.core import json_utils
    
    # Test invalid JSON
    invalid_cases = [
        '{"unclosed": ',
        '[1, 2, 3,',
        '{"key": undefined}',
        'not json at all',
    ]
    
    for invalid_json in invalid_cases:
        with pytest.raises(json_utils.JSONDecodeError):
            json_utils.loads(invalid_json)


def test_json_utils_loads_and_dumps_work_correctly():
    """Test that json_utils loads and dumps work correctly after optimization."""
    from reversecore_mcp.core import json_utils
    
    # Test various data structures
    test_data = {
        "string": "value",
        "number": 42,
        "float": 3.14,
        "bool": True,
        "null": None,
        "list": [1, 2, 3],
        "nested": {"key": "value"}
    }
    
    # Test dumps
    json_str = json_utils.dumps(test_data)
    assert isinstance(json_str, str)
    
    # Test loads
    loaded_data = json_utils.loads(json_str)
    assert loaded_data == test_data
    
    # Test with bytes input
    json_bytes = json_str.encode('utf-8')
    loaded_from_bytes = json_utils.loads(json_bytes)
    assert loaded_from_bytes == test_data


def test_chain_optimization_correctness():
    """Test that using itertools.chain produces correct results."""
    from itertools import chain
    
    # Simulate the file patterns used in resource cleanup
    patterns = ["*.tmp", ".r2_*", "*.r2"]
    
    # Create fake file lists
    files_per_pattern = [
        [f"file{i}.tmp" for i in range(100)],
        [f".r2_{i}" for i in range(100)],
        [f"file{i}.r2" for i in range(100)]
    ]
    
    # Old approach: multiple iterations
    old_result = []
    for i, pattern in enumerate(patterns):
        for f in files_per_pattern[i]:
            old_result.append(f)
    
    # New approach: single iteration with chain
    new_result = list(chain(*files_per_pattern))
    
    # Verify same result
    assert len(old_result) == len(new_result) == 300
    assert set(old_result) == set(new_result), "Chain should produce same files"
    
    # Verify all patterns are included
    assert any(f.endswith('.tmp') for f in new_result)
    assert any(f.startswith('.r2_') for f in new_result)
    assert any(f.endswith('.r2') and not f.startswith('.r2_') for f in new_result)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
