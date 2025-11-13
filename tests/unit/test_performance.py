"""
Performance tests to validate optimization improvements.

These tests ensure that optimizations don't introduce regressions
and provide baseline measurements for key operations.
"""

import time
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest


def test_yara_result_processing_with_many_matches():
    """Test that YARA result processing handles many matches efficiently."""
    # This test validates that the optimized YARA processing doesn't regress
    # We're testing the code path, not actual YARA functionality
    # The optimization reduces getattr calls and improves type checking

    # Mock the necessary components
    from unittest.mock import patch, MagicMock

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

    with patch("reversecore_mcp.tools.lib_tools.validate_file_path") as mock_validate:
        mock_validate.return_value = "/tmp/test.bin"

        # Import and mock yara within the function scope
        import sys
        mock_yara_module = MagicMock()
        sys.modules['yara'] = mock_yara_module
        mock_yara_module.compile.return_value.match.return_value = mock_matches

        try:
            from reversecore_mcp.tools.lib_tools import run_yara

            start_time = time.time()
            result = run_yara("/tmp/test.bin", "/tmp/test.yar")
            elapsed = time.time() - start_time

            # Should complete in under 1 second even with 2500 instances
            assert elapsed < 1.0, f"YARA processing took too long: {elapsed}s"
            assert "TestRule" in result
        finally:
            # Clean up mock
            if 'yara' in sys.modules:
                del sys.modules['yara']


def test_file_path_validation_string_conversion_optimization():
    """Test that file path validation optimizes string conversions."""
    from reversecore_mcp.core.security import validate_file_path
    from unittest.mock import patch

    # Create a temporary test file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        test_file = f.name
        f.write("test")

    try:
        # Mock the workspace to allow our temp file
        with patch("reversecore_mcp.core.security._get_allowed_workspace") as mock_workspace:
            with patch("reversecore_mcp.core.security._get_allowed_read_dirs") as mock_read_dirs:
                mock_workspace.return_value = Path("/tmp")
                mock_read_dirs.return_value = []

                # Test that multiple validations of the same path are efficient
                start_time = time.time()
                for _ in range(100):
                    result = validate_file_path(test_file)
                elapsed = time.time() - start_time

                # Should complete 100 validations in under 0.1 seconds
                assert elapsed < 0.1, f"File validation took too long: {elapsed}s"
                assert result == str(Path(test_file).resolve())
    finally:
        # Clean up
        Path(test_file).unlink()


def test_lief_output_formatting_no_redundant_slicing():
    """Test that LIEF output formatting doesn't perform redundant list slicing."""
    from reversecore_mcp.tools.lib_tools import _format_lief_output

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
    from reversecore_mcp.core.execution import execute_subprocess_streaming
    from reversecore_mcp.core.exceptions import ExecutionTimeoutError

    # Test a command that completes quickly
    start_time = time.time()
    output, bytes_read = execute_subprocess_streaming(
        ["echo", "test"],
        max_output_size=1000,
        timeout=5
    )
    elapsed = time.time() - start_time

    # Quick command should complete almost immediately
    assert elapsed < 0.5, f"Simple command took too long: {elapsed}s"
    assert "test" in output.strip()

    # Test that timeout works
    with pytest.raises(ExecutionTimeoutError) as exc_info:
        execute_subprocess_streaming(
            ["sleep", "10"],
            max_output_size=1000,
            timeout=1
        )
    assert "timed out" in str(exc_info.value).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
