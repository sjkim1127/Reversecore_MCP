"""
Tests for performance optimizations implemented in the codebase.

This test suite validates that the optimizations work correctly and
provides benchmarks to prevent performance regressions.
"""

import asyncio
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestJSONOptimization:
    """Test that json_utils is used instead of standard json."""

    def test_json_utils_imports_in_report_tools(self):
        """Verify report_tools.py uses optimized JSON."""
        with open("reversecore_mcp/tools/report_tools.py") as f:
            content = f.read()
            # Should import json_utils
            assert "from reversecore_mcp.core import json_utils as json" in content
            # Should not import standard json directly as "import json"
            # (except in comments)
            lines = [
                line for line in content.split("\n") if not line.strip().startswith("#")
            ]
            non_comment_content = "\n".join(lines)
            assert "import json\n" not in non_comment_content

    def test_json_utils_imports_in_report_mcp_tools(self):
        """Verify report_mcp_tools.py uses optimized JSON."""
        with open("reversecore_mcp/tools/report_mcp_tools.py") as f:
            content = f.read()
            # Should import json_utils
            assert "from reversecore_mcp.core import json_utils as json" in content

    def test_json_utils_performance(self):
        """Benchmark json_utils vs standard json."""
        from reversecore_mcp.core import json_utils

        # Create a large test object
        test_data = {
            "analysis": {
                "iocs": [
                    {
                        "type": "ipv4",
                        "value": f"192.168.{i}.{j}",
                        "confidence": 0.95,
                        "metadata": {"source": "network_traffic", "count": i * j},
                    }
                    for i in range(10)
                    for j in range(10)
                ],
                "functions": [
                    {
                        "name": f"func_{i}",
                        "address": hex(0x1000 + i * 0x100),
                        "size": 256 + i,
                    }
                    for i in range(100)
                ],
                "strings": [f"String_{i}_test_data_here" for i in range(500)],
            }
        }

        # Benchmark dumps
        start = time.time()
        for _ in range(100):
            json_str = json_utils.dumps(test_data)
        dumps_time = time.time() - start

        # Benchmark loads
        start = time.time()
        for _ in range(100):
            json_utils.loads(json_str)
        loads_time = time.time() - start

        # Should complete reasonably fast
        assert dumps_time < 1.0, f"JSON dumps too slow: {dumps_time}s"
        assert loads_time < 1.0, f"JSON loads too slow: {loads_time}s"


class TestAsyncSubprocessOptimization:
    """Test that async subprocess execution is used."""

    def test_r2_analysis_uses_async_subprocess(self):
        """Verify r2_analysis.py uses async subprocess for image generation."""
        with open("reversecore_mcp/tools/r2_analysis.py") as f:
            content = f.read()

            # Should use execute_subprocess_async
            assert "await execute_subprocess_async(" in content

            # Should not have synchronous subprocess.run for dot command
            # Check the specific context around line 589
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "dot" in line and "-Tpng" in line:
                    # Check surrounding context (5 lines before and after)
                    context = "\n".join(lines[max(0, i - 5) : i + 5])
                    # Should use async version
                    if "subprocess.run" in context:
                        assert (
                            "await execute_subprocess_async" in context
                        ), f"Found subprocess.run near line {i+1} without async alternative"

    @pytest.mark.asyncio
    async def test_async_subprocess_execution(self):
        """Test that execute_subprocess_async works correctly."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        # Test a simple command
        output, bytes_read = await execute_subprocess_async(
            ["echo", "test"], max_output_size=1000, timeout=5
        )

        assert "test" in output
        assert bytes_read > 0


class TestBufferedIOOptimization:
    """Test that buffered I/O is used for large files."""

    def test_ioc_tools_uses_buffered_io(self):
        """Verify ioc_tools.py uses buffered I/O."""
        with open("reversecore_mcp/tools/ioc_tools.py") as f:
            content = f.read()

            # Should specify buffering parameter
            assert "buffering=8192" in content

    def test_buffered_reading_performance(self):
        """Benchmark buffered vs unbuffered reading."""
        # Create a test file with substantial content
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            temp_path = f.name
            # Write 5MB of text
            test_data = "test line with some content\n" * 200000
            f.write(test_data)

        try:
            # Buffered reading
            start = time.time()
            with open(temp_path, encoding="utf-8", buffering=8192) as f:
                content1 = f.read()
            buffered_time = time.time() - start

            # Default buffering
            start = time.time()
            with open(temp_path, encoding="utf-8") as f:
                content2 = f.read()
            default_time = time.time() - start

            # Verify content is the same
            assert content1 == content2

            # Buffered should be at least as fast (usually faster on large files)
            # Note: On some systems, default buffering may already be optimal
            assert buffered_time <= default_time * 1.5, (
                f"Buffered reading is significantly slower: "
                f"{buffered_time}s vs {default_time}s"
            )

        finally:
            os.unlink(temp_path)


class TestResourceManagerOptimization:
    """Test that resource manager uses efficient cleanup."""

    def test_resource_manager_uses_itertools_chain(self):
        """Verify resource_manager.py uses itertools.chain."""
        with open("reversecore_mcp/core/resource_manager.py") as f:
            content = f.read()

            # Should import and use itertools.chain
            assert "from itertools import chain" in content
            assert "chain(" in content

    @pytest.mark.asyncio
    async def test_resource_cleanup_efficiency(self, tmp_path):
        """Test that resource cleanup is efficient with many files."""
        from reversecore_mcp.core.resource_manager import ResourceManager

        # Create many temp files
        for i in range(100):
            (tmp_path / f"test_{i}.tmp").touch()
            (tmp_path / f".r2_{i}").touch()

        # Override workspace
        with patch("reversecore_mcp.core.config.get_config") as mock_config:
            mock_config.return_value.workspace = tmp_path

            # Create resource manager
            rm = ResourceManager(cleanup_interval=1)

            # Manually trigger cleanup
            start = time.time()
            await rm.cleanup()
            cleanup_time = time.time() - start

            # Should complete quickly even with many files
            assert cleanup_time < 1.0, f"Cleanup too slow: {cleanup_time}s"


class TestPrecompiledRegexPatterns:
    """Test that regex patterns are pre-compiled."""

    def test_ghost_trace_precompiled_patterns(self):
        """Verify ghost_trace.py uses pre-compiled patterns."""
        with open("reversecore_mcp/tools/ghost_trace.py") as f:
            content = f.read()

            # Should have module-level compiled patterns
            assert "_JSON_ARRAY_PATTERN = re.compile(" in content
            assert "_HEX_ADDRESS_PATTERN = re.compile(" in content

    def test_decompilation_precompiled_patterns(self):
        """Verify decompilation.py uses pre-compiled patterns."""
        with open("reversecore_mcp/tools/decompilation.py") as f:
            content = f.read()

            # Should have module-level compiled patterns
            assert "_FUNCTION_ADDRESS_PATTERN = re.compile(" in content

    def test_precompiled_pattern_performance(self):
        """Benchmark pre-compiled vs inline regex compilation."""
        import re

        # Create test data
        test_text = "\n".join([f"192.168.1.{i}" for i in range(1000)])

        # Pre-compiled pattern
        PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

        start = time.time()
        for _ in range(100):
            PATTERN.findall(test_text)
        precompiled_time = time.time() - start

        # Inline compilation (old approach)
        start = time.time()
        for _ in range(100):
            re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").findall(test_text)
        inline_time = time.time() - start

        # Pre-compiled should be faster
        assert precompiled_time < inline_time, (
            f"Pre-compiled not faster: {precompiled_time}s vs {inline_time}s"
        )


class TestPerformanceDocumentation:
    """Test that performance documentation exists and is complete."""

    def test_performance_guide_exists(self):
        """Verify PERFORMANCE.md exists."""
        assert Path("docs/PERFORMANCE.md").exists()

    def test_performance_guide_completeness(self):
        """Verify PERFORMANCE.md covers key topics."""
        with open("docs/PERFORMANCE.md") as f:
            content = f.read()

            # Should document key optimizations
            assert "JSON Performance" in content
            assert "Async Subprocess" in content
            assert "Buffered File I/O" in content
            assert "Pre-compiled Regex" in content
            assert "Resource Cleanup" in content

            # Should have examples
            assert "```python" in content

            # Should have benchmarking section
            assert "Benchmarking" in content or "Performance Tests" in content


# Integration test for overall performance
class TestEndToEndPerformance:
    """Integration tests for overall system performance."""

    @pytest.mark.asyncio
    async def test_multiple_concurrent_operations(self):
        """Test that async operations can run concurrently."""
        from reversecore_mcp.core.execution import execute_subprocess_async

        # Run multiple operations concurrently
        start = time.time()
        results = await asyncio.gather(
            execute_subprocess_async(["echo", "test1"], max_output_size=1000, timeout=5),
            execute_subprocess_async(["echo", "test2"], max_output_size=1000, timeout=5),
            execute_subprocess_async(["echo", "test3"], max_output_size=1000, timeout=5),
        )
        concurrent_time = time.time() - start

        # Verify results
        assert len(results) == 3
        assert all("test" in result[0] for result in results)

        # Should complete faster than sequential execution would take
        # (each echo is ~instant, but scheduling overhead exists)
        assert concurrent_time < 1.0, f"Concurrent execution too slow: {concurrent_time}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
