"""
Performance tests to validate optimization improvements.

These tests ensure that optimizations don't introduce regressions
and provide baseline measurements for key operations.
"""

import sys
import time
from unittest.mock import MagicMock

import pytest


def test_yara_result_processing_with_many_matches(
    workspace_dir,
    read_only_dir,
    patched_workspace_config,
):
    """Test that YARA result processing handles many matches efficiently."""
    # This test validates that the optimized YARA processing doesn't regress
    # We're testing the code path, not actual YARA functionality
    # The optimization reduces getattr calls and improves type checking

    # Create a mock match with many string instances
    mock_instance = MagicMock()
    mock_instance.offset = 0x1000
    mock_instance.matched_data = b"test_data"

    mock_string = MagicMock()
    mock_string.identifier = "$test"
    mock_string.instances = [mock_instance] * 50  # 50 instances

    mock_match = MagicMock()
    mock_match.rule = "TestRule"
    mock_match.namespace = "default"
    mock_match.tags = ["test"]
    mock_match.meta = {"author": "test"}
    mock_match.strings = [mock_string] * 10  # 10 string patterns, each with 50 instances

    # This creates 500 total string matches to process
    mock_matches = [mock_match] * 5  # 5 matches = 2500 total instances

    binary = workspace_dir / "perf.bin"
    binary.write_bytes(b"data")
    rule_file = read_only_dir / "perf.yar"
    rule_file.write_text("rule perf { condition: true }")

    import sys

    mock_yara_module = MagicMock()
    sys.modules["yara"] = mock_yara_module
    mock_yara_module.compile.return_value.match.return_value = mock_matches

    try:
        from reversecore_mcp.tools.common.lib_tools import run_yara

        start_time = time.time()
        result = run_yara(str(binary), str(rule_file))
        elapsed = time.time() - start_time

        # Should complete in under 1 second even with 2500 instances
        assert elapsed < 1.0, f"YARA processing took too long: {elapsed}s"
        assert result.status == "success"
        assert result.data["match_count"] == len(mock_matches)
        assert result.data["matches"][0]["rule"] == "TestRule"
    finally:
        if "yara" in sys.modules:
            del sys.modules["yara"]


def test_file_path_validation_string_conversion_optimization(workspace_config):
    """Test that file path validation optimizes string conversions."""
    from reversecore_mcp.core.security import validate_file_path

    test_file = workspace_config.workspace / "perf_test.bin"
    test_file.write_text("test")

    start_time = time.time()
    for _ in range(100):
        result = validate_file_path(str(test_file), config=workspace_config)
    elapsed = time.time() - start_time

    # Should complete 100 validations in under 0.1 seconds
    assert elapsed < 0.1, f"File validation took too long: {elapsed}s"
    assert result == test_file.resolve()


def test_lief_output_formatting_no_redundant_slicing():
    """Test that LIEF output formatting doesn't perform redundant list slicing."""
    from reversecore_mcp.tools.common.lib_tools import _format_lief_output

    # Create a large result with many sections and functions
    result = {
        "format": "pe",
        "entry_point": "0x1000",
        "sections": [
            {
                "name": f".section{i}",
                "virtual_address": hex(0x1000 + i * 0x1000),
                "size": 0x1000,
            }
            for i in range(100)
        ],
        "imported_functions": [f"func_{i}" for i in range(200)],
        "exported_functions": [f"export_{i}" for i in range(150)],
    }

    # Test text formatting (which limits output)
    start_time = time.time()
    for _ in range(100):
        output = _format_lief_output(result, "text")
    elapsed = time.time() - start_time

    # Should complete 100 iterations in under 0.1 seconds
    assert elapsed < 0.1, f"LIEF formatting took too long: {elapsed}s"

    # Verify output is correct and limited
    lines = output.split("\n")
    assert "Format: pe" in output
    assert "Entry Point: 0x1000" in output

    # Should have sections (header + max 20 items)
    section_lines = [l for l in lines if ".section" in l]
    assert len(section_lines) == 20, "Should limit to 20 sections"

    # Should have imported functions (header + max 20 items)
    import_lines = [l for l in lines if "func_" in l]
    assert len(import_lines) == 20, "Should limit to 20 functions"


def test_subprocess_polling_adaptive_backoff():
    """Test that subprocess polling uses adaptive backoff correctly."""
    from reversecore_mcp.core.exceptions import ExecutionTimeoutError
    from reversecore_mcp.core.execution import execute_subprocess_streaming

    # Test a command that completes quickly
    start_time = time.time()
    output, bytes_read = execute_subprocess_streaming(
        [sys.executable, "-c", "print('test')"],
        max_output_size=1000,
        timeout=5,
    )
    elapsed = time.time() - start_time

    # Quick command should complete almost immediately
    assert elapsed < 0.5, f"Simple command took too long: {elapsed}s"
    assert "test" in output.strip()

    # Test that timeout works
    with pytest.raises(ExecutionTimeoutError) as exc_info:
        execute_subprocess_streaming(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            max_output_size=1000,
            timeout=1,
        )
    assert "timed out" in str(exc_info.value).lower()


def test_ioc_extraction_with_precompiled_patterns():
    """Test that IOC extraction uses pre-compiled patterns for better performance."""
    from reversecore_mcp.tools.common.lib_tools import extract_iocs

    # Create a large text with many IOCs
    test_text = "\n".join(
        [
            f"Server at 192.168.{i}.{j} running http://example{i}{j}.com and admin{i}{j}@test.com"
            for i in range(10)
            for j in range(10)
        ]
    )

    # Test performance - should complete quickly with pre-compiled patterns
    start_time = time.time()
    for _ in range(10):
        result = extract_iocs(test_text)
    elapsed = time.time() - start_time

    # 10 iterations should complete in under 0.5 seconds with pre-compiled patterns
    assert elapsed < 0.5, f"IOC extraction took too long: {elapsed}s"
    assert result.status == "success"
    # ioc_count is in metadata, not data
    assert result.metadata["ioc_count"] > 0


def test_regex_pattern_reuse_performance():
    """Test that pre-compiled regex patterns are at least as fast as inline compilation."""
    import re

    # Import the pre-compiled pattern for comparison
    from reversecore_mcp.tools.common.lib_tools import _IOC_IPV4_PATTERN

    # Simulate the old approach (compiling each time)
    text = "Test 192.168.1.1 and http://example.com and test@email.com " * 1000

    start_time = time.time()
    for _ in range(100):
        # Old approach - compile each time (using same pattern as production)
        ip_pattern = re.compile(_IOC_IPV4_PATTERN.pattern)
        ip_pattern.findall(text)
    old_elapsed = time.time() - start_time

    # New approach - use pre-compiled pattern
    start_time = time.time()
    for _ in range(100):
        _IOC_IPV4_PATTERN.findall(text)
    new_elapsed = time.time() - start_time

    # Pre-compiled should be at least as fast (not slower)
    # Note: Actual performance gain depends on Python version and system
    assert new_elapsed <= old_elapsed * 1.1, (
        f"Pre-compiled pattern is slower: {new_elapsed}s vs {old_elapsed}s"
    )


def test_islice_vs_list_slicing_performance():
    """Test that islice provides memory and performance benefits over list slicing."""
    from itertools import islice

    # Create a large iterable
    large_iterable = (x for x in range(100000))

    # Test islice approach (new)
    start_time = time.time()
    result = list(islice(large_iterable, 100))
    islice_elapsed = time.time() - start_time

    # Test list conversion approach (old)
    large_iterable = (x for x in range(100000))
    start_time = time.time()
    result = list(large_iterable)[:100]
    list_elapsed = time.time() - start_time

    # islice should be significantly faster (at least 10x)
    assert islice_elapsed < list_elapsed / 10, (
        f"islice not significantly faster: {islice_elapsed}s vs {list_elapsed}s"
    )
    assert len(result) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
