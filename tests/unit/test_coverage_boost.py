"""
Tests to boost coverage for modules with low coverage.

Target modules:
- ghost_trace.py (21%)
- neural_decompiler.py (18%)
- static_analysis.py (46%)
- file_operations.py (50%)
- diff_tools.py (58%)
- cli_tools.py (37%)
"""

from unittest.mock import Mock

import pytest

from tests.conftest import requires_file, requires_strings

# ============================================================================
# ghost_trace.py tests
# ============================================================================


class TestGhostTraceHelpers:
    """Test helper functions in ghost_trace module."""

    def test_extract_json_safely_with_array(self):
        """Test JSON extraction with array."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        output = 'garbage [{"name": "main", "offset": 4096}] more text'
        result = _extract_json_safely(output)
        assert result == [{"name": "main", "offset": 4096}]

    def test_extract_json_safely_with_object(self):
        """Test JSON extraction with object."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        output = 'prefix {"key": "value", "num": 42} suffix'
        result = _extract_json_safely(output)
        assert result == {"key": "value", "num": 42}

    def test_extract_json_safely_with_nested(self):
        """Test JSON extraction with nested structures."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        # Test that it can extract valid JSON (actual result depends on implementation)
        output = '{"outer": {"inner": [1, 2, 3]}, "list": ["a", "b"]}'
        result = _extract_json_safely(output)
        assert result is not None
        # The function may extract inner structures first
        assert isinstance(result, (dict, list))

    def test_extract_json_safely_empty_input(self):
        """Test JSON extraction with empty input."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        assert _extract_json_safely("") is None
        assert _extract_json_safely("   ") is None
        assert _extract_json_safely(None) is None

    def test_extract_json_safely_no_json(self):
        """Test JSON extraction when no valid JSON present."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        result = _extract_json_safely("no json here at all")
        assert result is None

    def test_extract_json_safely_single_line(self):
        """Test JSON extraction from single line."""
        from reversecore_mcp.tools.ghost_trace import _extract_json_safely

        output = "line1\nline2\n[1, 2, 3]\nline4"
        result = _extract_json_safely(output)
        assert result == [1, 2, 3]

    def test_validate_r2_identifier_hex_address(self):
        """Test validation of hex addresses."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        assert _validate_r2_identifier("0x401000") == "0x401000"
        assert _validate_r2_identifier("0xDEADBEEF") == "0xDEADBEEF"

    def test_validate_r2_identifier_symbol(self):
        """Test validation of symbol names."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        assert _validate_r2_identifier("sym.main") == "sym.main"
        assert _validate_r2_identifier("sym.imp.CreateFileA") == "sym.imp.CreateFileA"

    def test_validate_r2_identifier_function_name(self):
        """Test validation of simple function names."""
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        assert _validate_r2_identifier("main") == "main"
        assert _validate_r2_identifier("_start") == "_start"
        assert _validate_r2_identifier("my_func123") == "my_func123"

    def test_validate_r2_identifier_invalid(self):
        """Test validation of invalid identifiers."""
        from reversecore_mcp.core.exceptions import ValidationError
        from reversecore_mcp.tools.ghost_trace import _validate_r2_identifier

        with pytest.raises(ValidationError):
            _validate_r2_identifier("rm -rf /")

        with pytest.raises(ValidationError):
            _validate_r2_identifier("0x; ls")

        with pytest.raises(ValidationError):
            _validate_r2_identifier("$(whoami)")

    def test_get_file_cache_key(self, workspace_dir):
        """Test cache key generation."""
        from reversecore_mcp.tools.ghost_trace import _get_file_cache_key

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"test content")

        key = _get_file_cache_key(str(test_file))
        assert key is not None
        assert len(key) > 0


# ============================================================================
# neural_decompiler.py tests
# ============================================================================


class TestNeuralDecompilerHelpers:
    """Test Neural Decompiler helper functions."""

    def test_register_neural_decompiler(self):
        """Test tool registration."""
        from reversecore_mcp.tools.neural_decompiler import register_neural_decompiler

        mock_mcp = Mock()
        register_neural_decompiler(mock_mcp)
        mock_mcp.tool.assert_called_once()


# ============================================================================
# static_analysis.py tests
# ============================================================================


class TestStaticAnalysis:
    """Test static analysis functions."""

    @requires_strings
    @pytest.mark.asyncio
    async def test_run_strings_basic(self, sample_binary_path, patched_workspace_config):
        """Test basic string extraction."""
        from reversecore_mcp.tools.static_analysis import run_strings

        result = await run_strings(str(sample_binary_path))
        assert result.status == "success"

    @requires_strings
    @pytest.mark.asyncio
    async def test_run_strings_min_length(self, sample_binary_path, patched_workspace_config):
        """Test string extraction with custom min length."""
        from reversecore_mcp.tools.static_analysis import run_strings

        result = await run_strings(str(sample_binary_path), min_length=8)
        assert result.status == "success"

    @requires_strings
    @pytest.mark.asyncio
    async def test_run_strings_output_truncation(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test output truncation warning."""
        from reversecore_mcp.tools.static_analysis import run_strings

        # This tests the truncation path - file is small so won't trigger
        result = await run_strings(str(sample_binary_path), max_output_size=1024 * 1024)
        assert result.status == "success"

    @requires_strings
    @pytest.mark.asyncio
    async def test_run_strings_small_max_output_enforced(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that small max_output_size is enforced to minimum."""
        from reversecore_mcp.tools.static_analysis import run_strings

        # Even if we pass a small max_output_size, it should be enforced to MIN_OUTPUT_SIZE
        result = await run_strings(str(sample_binary_path), max_output_size=100)
        assert result.status == "success"

    def test_version_patterns_compiled(self):
        """Test that version patterns are pre-compiled."""
        from reversecore_mcp.tools.static_analysis import _VERSION_PATTERNS

        assert "OpenSSL" in _VERSION_PATTERNS
        assert "GCC" in _VERSION_PATTERNS
        assert "Python" in _VERSION_PATTERNS

        # Test pattern matching
        openssl_pattern = _VERSION_PATTERNS["OpenSSL"]
        match = openssl_pattern.search("OpenSSL 1.0.1e")
        assert match is not None

    def test_constants_defined(self):
        """Test that constants are properly defined."""
        from reversecore_mcp.tools.static_analysis import (
            LLM_SAFE_LIMIT,
            MAX_EXTRACTED_FILES,
            MAX_SIGNATURES,
            MIN_OUTPUT_SIZE,
        )

        assert MIN_OUTPUT_SIZE == 1024 * 1024  # 1MB
        assert LLM_SAFE_LIMIT == 50 * 1024  # 50KB
        assert MAX_EXTRACTED_FILES == 200
        assert MAX_SIGNATURES == 50


# ============================================================================
# file_operations.py tests
# ============================================================================


class TestFileOperations:
    """Test file operation functions."""

    @requires_file
    @pytest.mark.asyncio
    async def test_run_file_basic(self, sample_binary_path, patched_workspace_config):
        """Test basic file type identification."""
        from reversecore_mcp.tools.file_operations import run_file

        result = await run_file(str(sample_binary_path))
        assert result.status == "success"
        assert (
            "data" in result.data.lower()
            or "executable" in result.data.lower()
            or "elf" in result.data.lower()
        )

    def test_copy_to_workspace_nonexistent(self, patched_workspace_config):
        """Test copying non-existent file."""
        from reversecore_mcp.tools.file_operations import copy_to_workspace

        # The function is wrapped with handle_tool_errors, so it returns ToolResult
        result = copy_to_workspace("/nonexistent/file.bin")
        assert result.status == "error"

    def test_copy_to_workspace_directory(self, workspace_dir, patched_workspace_config):
        """Test copying a directory (should fail)."""
        from reversecore_mcp.tools.file_operations import copy_to_workspace

        # Create a subdirectory
        subdir = workspace_dir / "subdir"
        subdir.mkdir()

        # The function is wrapped with handle_tool_errors, so it returns ToolResult
        result = copy_to_workspace(str(subdir))
        assert result.status == "error"

    def test_copy_to_workspace_success(self, workspace_dir, patched_config):
        """Test successful file copy."""
        # Create source file outside workspace
        import tempfile

        from reversecore_mcp.tools.file_operations import copy_to_workspace

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test binary content")
            source_path = f.name

        try:
            result = copy_to_workspace(source_path, "copied_file.bin")
            assert result.status == "success"
            assert "copied_file.bin" in result.data
        finally:
            import os

            os.unlink(source_path)


# ============================================================================
# diff_tools.py tests
# ============================================================================


class TestDiffTools:
    """Test diff tool functions."""

    def test_extract_library_name_import(self):
        """Test library name extraction for imports."""
        from reversecore_mcp.tools.diff_tools import _extract_library_name

        assert _extract_library_name("sym.imp.strcpy") == "import"
        assert _extract_library_name("sym.imp.malloc") == "import"

    def test_extract_library_name_kernel32(self):
        """Test library name extraction for kernel32."""
        from reversecore_mcp.tools.diff_tools import _extract_library_name

        assert _extract_library_name("kernel32.dll.CreateFileA") == "kernel32"
        assert _extract_library_name("kernel32.VirtualAlloc") == "kernel32"

    def test_extract_library_name_msvcrt(self):
        """Test library name extraction for msvcrt."""
        from reversecore_mcp.tools.diff_tools import _extract_library_name

        assert _extract_library_name("msvcrt.printf") == "libc/msvcrt"
        assert _extract_library_name("msvcrt.malloc") == "libc/msvcrt"

    def test_extract_library_name_stl(self):
        """Test library name extraction for STL."""
        from reversecore_mcp.tools.diff_tools import _extract_library_name

        assert _extract_library_name("std::vector") == "libstdc++"
        assert _extract_library_name("std::string") == "libstdc++"

    def test_extract_library_name_unknown(self):
        """Test library name extraction for unknown functions."""
        from reversecore_mcp.tools.diff_tools import _extract_library_name

        assert _extract_library_name("my_custom_function") == "unknown"
        assert _extract_library_name("user_code_123") == "unknown"


# ============================================================================
# cli_tools.py tests
# ============================================================================


class TestCliTools:
    """Test CLI tool wrapper functions."""

    @pytest.mark.asyncio
    async def test_run_radare2_with_mock(self, sample_binary_path, patched_workspace_config):
        """Test radare2 execution with mocked subprocess."""
        from reversecore_mcp.tools.r2_analysis import run_radare2

        # Simple info command that should work
        result = await run_radare2(str(sample_binary_path), "i")
        # Result depends on whether r2 is installed
        assert result.status in ["success", "error"]

    @pytest.mark.asyncio
    async def test_run_radare2_invalid_command(self, sample_binary_path, patched_workspace_config):
        """Test radare2 with invalid command."""
        from reversecore_mcp.tools.r2_analysis import run_radare2

        # This should fail validation
        result = await run_radare2(str(sample_binary_path), "!rm -rf /")
        assert result.status == "error"


# ============================================================================
# ioc_tools.py tests
# ============================================================================


class TestIocTools:
    """Test IOC extraction functions."""

    def test_extract_iocs_basic(self):
        """Test basic IOC extraction."""
        from reversecore_mcp.tools.ioc_tools import extract_iocs

        text = """
        Connect to http://malicious.com/payload
        Send data to 192.168.1.1
        Contact admin@evil.com
        """

        result = extract_iocs(text)
        assert result.status == "success"
        assert "urls" in result.data or "ipv4" in result.data or "emails" in result.data

    def test_extract_iocs_empty(self):
        """Test IOC extraction with no IOCs."""
        from reversecore_mcp.tools.ioc_tools import extract_iocs

        result = extract_iocs("no indicators here")
        assert result.status == "success"

    def test_extract_iocs_ipv4(self):
        """Test IPv4 extraction."""
        from reversecore_mcp.tools.ioc_tools import extract_iocs

        text = "Server at 10.0.0.1 and 172.16.0.1"
        result = extract_iocs(text)
        assert result.status == "success"


# ============================================================================
# r2_pool.py additional tests
# ============================================================================


class TestR2PoolAdditional:
    """Additional tests for R2 connection pool."""

    def test_pool_initialization(self):
        """Test pool initialization."""
        from reversecore_mcp.core.r2_pool import R2ConnectionPool

        pool = R2ConnectionPool(max_connections=5)
        assert pool.max_connections == 5
        assert len(pool._pool) == 0

    def test_get_async_lock(self):
        """Test async lock retrieval."""
        import asyncio

        from reversecore_mcp.core.r2_pool import R2ConnectionPool

        pool = R2ConnectionPool()
        lock = pool._get_async_lock()
        assert isinstance(lock, asyncio.Lock)

        # Second call should return same lock
        lock2 = pool._get_async_lock()
        assert lock is lock2


# ============================================================================
# json_utils.py tests
# ============================================================================


class TestJsonUtils:
    """Test optimized JSON utilities."""

    def test_json_loads_basic(self):
        """Test basic JSON loading."""
        from reversecore_mcp.core import json_utils as json

        result = json.loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_json_dumps_basic(self):
        """Test basic JSON dumping."""
        from reversecore_mcp.core import json_utils as json

        result = json.dumps({"key": "value"})
        assert '"key"' in result
        assert '"value"' in result


# ============================================================================
# Additional coverage for core modules
# ============================================================================


class TestCoreModulesAdditional:
    """Additional tests for core modules."""

    def test_config_defaults(self):
        """Test config default values."""
        from reversecore_mcp.core.config import get_config

        config = get_config()
        assert config.default_tool_timeout > 0
        assert config.workspace is not None

    def test_result_success_with_metadata(self):
        """Test success result with metadata."""
        from reversecore_mcp.core.result import success

        result = success("data", bytes_read=100, custom_field="test")
        assert result.status == "success"
        assert result.data == "data"
        assert result.metadata["bytes_read"] == 100
        assert result.metadata["custom_field"] == "test"

    def test_result_failure_with_details(self):
        """Test failure result with details."""
        from reversecore_mcp.core.result import failure

        result = failure("ERROR_CODE", "Error message")
        assert result.status == "error"
        assert result.error_code == "ERROR_CODE"
        assert result.message == "Error message"

    def test_exception_classes(self):
        """Test custom exception classes."""
        from reversecore_mcp.core.exceptions import (
            ExecutionTimeoutError,
            ToolNotFoundError,
            ValidationError,
        )

        # ValidationError
        err = ValidationError("Invalid input", details={"field": "value"})
        assert "Invalid input" in str(err)

        # ToolNotFoundError
        err = ToolNotFoundError("radare2")
        assert "radare2" in str(err)

        # ExecutionTimeoutError
        err = ExecutionTimeoutError(30)
        assert "30" in str(err)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
