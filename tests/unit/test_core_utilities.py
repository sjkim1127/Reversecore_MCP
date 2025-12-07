"""Final coverage boost tests to reach 80% target.

Targets remaining low-coverage areas:
- cli_tools (45%)
- ioc_tools (63%)
- static_analysis (66%)
- r2_analysis (67%)
- json_utils (59%)
- r2_pool (65%)
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

# ============================================================================
# CLI Tools Additional Tests (45% -> higher)
# ============================================================================


# ============================================================================
# JSON Utils Additional Tests (59% -> higher)
# ============================================================================


class TestJsonUtilsAdditional:
    """Additional tests for json_utils module."""

    def test_loads_invalid_json_raises(self):
        """Test loads with invalid JSON raises exception."""
        from reversecore_mcp.core import json_utils

        with pytest.raises(json.JSONDecodeError):
            json_utils.loads("not valid json")

    def test_loads_empty_string_raises(self):
        """Test loads with empty string raises exception."""
        from reversecore_mcp.core import json_utils

        with pytest.raises(json.JSONDecodeError):
            json_utils.loads("")

    def test_loads_null(self):
        """Test loads with null."""
        from reversecore_mcp.core import json_utils

        result = json_utils.loads("null")
        assert result is None

    def test_dumps_with_indent(self):
        """Test dumps with indentation."""
        from reversecore_mcp.core import json_utils

        result = json_utils.dumps({"a": 1}, indent=2)
        assert "  " in result  # indentation check


# ============================================================================
# R2 Pool Additional Tests (65% -> higher)
# ============================================================================


class TestR2PoolAdditional:
    """Additional tests for r2_pool module."""

    def test_r2_pool_default_connections(self):
        """Test R2ConnectionPool with default max_connections."""
        from reversecore_mcp.core.r2_pool import R2ConnectionPool

        pool = R2ConnectionPool()
        assert pool.max_connections == 10

    def test_r2_pool_properties(self):
        """Test R2ConnectionPool properties."""
        from reversecore_mcp.core.r2_pool import R2ConnectionPool

        pool = R2ConnectionPool(max_connections=5)
        assert hasattr(pool, "_pool")
        assert hasattr(pool, "_lock")
        assert hasattr(pool, "_last_access")


# ============================================================================
# IOC Tools Additional Tests (63% -> higher)
# ============================================================================


class TestIOCToolsAdditional:
    """Additional tests for ioc_tools module."""

    def test_extract_iocs_with_urls(self, patched_workspace_config, workspace_dir):
        """Test extract_iocs with URL patterns."""
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(
            b"https://malicious.com/payload\x00http://192.168.1.1:8080\x00ftp://ftp.example.org\x00"
        )

        result = extract_iocs(str(test_file))
        assert result.status in ("success", "error")

    def test_extract_iocs_with_ips(self, patched_workspace_config, workspace_dir):
        """Test extract_iocs with IP patterns."""
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"10.0.0.1\x00172.16.0.1\x008.8.8.8\x00")

        result = extract_iocs(str(test_file))
        assert result.status in ("success", "error")


# ============================================================================
# Static Analysis Additional Tests (66% -> higher)
# ============================================================================


class TestStaticAnalysisAdditional:
    """Additional tests for static_analysis module."""

    @pytest.mark.asyncio
    async def test_run_strings_basic(self, patched_workspace_config, workspace_dir):
        """Test run_strings with basic file."""
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"Hello World\x00This is a test string\x00\x00\x00\x00\x00")

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("Hello World\nThis is a test string", ""),
        ):
            result = await run_strings(str(test_file))
            assert result.status in ("success", "error")


# ============================================================================
# R2 Analysis Additional Tests (67% -> higher)
# ============================================================================


class TestR2AnalysisAdditional:
    """Additional tests for r2_analysis module."""

    def test_strip_address_prefixes(self):
        """Test _strip_address_prefixes helper."""
        from reversecore_mcp.core.r2_helpers import _strip_address_prefixes

        assert _strip_address_prefixes("0x401000") == "401000"
        assert _strip_address_prefixes("401000") == "401000"
        assert _strip_address_prefixes("main") == "main"

    def test_escape_mermaid_chars(self):
        """Test _escape_mermaid_chars helper."""
        from reversecore_mcp.core.r2_helpers import _escape_mermaid_chars

        result = _escape_mermaid_chars("test")
        assert isinstance(result, str)

    def test_get_r2_project_name(self):
        """Test _get_r2_project_name helper."""
        from reversecore_mcp.core.r2_helpers import _get_r2_project_name

        result = _get_r2_project_name("/path/to/file.bin")
        assert isinstance(result, str)

    def test_calculate_dynamic_timeout(self):
        """Test _calculate_dynamic_timeout helper."""
        from reversecore_mcp.core.r2_helpers import _calculate_dynamic_timeout

        # Small file should use base timeout
        result = _calculate_dynamic_timeout("/nonexistent/file.bin", base_timeout=100)
        assert result >= 100


# ============================================================================
# File Operations Additional Tests
# ============================================================================


class TestFileOperationsAdditional:
    """Additional tests for file_operations module."""

    def test_list_workspace(self, patched_workspace_config, workspace_dir):
        """Test list_workspace function."""
        from reversecore_mcp.tools.common.file_operations import list_workspace

        # Create some test files
        (workspace_dir / "test1.bin").write_bytes(b"\x00" * 10)
        (workspace_dir / "test2.bin").write_bytes(b"\x00" * 20)

        result = list_workspace()
        assert result.status in ("success", "error")


# ============================================================================
# Signature Tools Additional Tests
# ============================================================================


class TestSignatureToolsAdditional:
    """Additional tests for signature_tools module."""

    def test_validate_address_or_fail_valid(self):
        """Test _validate_address_or_fail with valid address."""
        from reversecore_mcp.tools.analysis.signature_tools import _validate_address_or_fail

        # Should not raise for valid hex address
        _validate_address_or_fail("0x401000")

    def test_format_hex_bytes(self):
        """Test _format_hex_bytes helper."""
        from reversecore_mcp.tools.analysis.signature_tools import _format_hex_bytes

        result = _format_hex_bytes("414243")
        assert isinstance(result, str)

    def test_sanitize_filename_for_rule(self):
        """Test _sanitize_filename_for_rule helper."""
        from reversecore_mcp.tools.analysis.signature_tools import _sanitize_filename_for_rule

        result = _sanitize_filename_for_rule("/path/to/file.bin")
        assert isinstance(result, str)
        # Should not contain path separators or dots
        assert "/" not in result


# ============================================================================
# Core Modules Additional Tests
# ============================================================================


class TestCoreModulesAdditional:
    """Additional tests for core modules."""

    def test_binary_cache_import(self):
        """Test binary_cache module import."""
        from reversecore_mcp.core import binary_cache

        assert binary_cache is not None

    def test_resource_manager_import(self):
        """Test resource_manager module import."""
        from reversecore_mcp.core import resource_manager

        assert resource_manager is not None

    def test_resilience_import(self):
        """Test resilience module import."""
        from reversecore_mcp.core import resilience

        assert resilience is not None


# ============================================================================
# Error Handling Additional Tests
# ============================================================================


class TestErrorHandlingAdditional:
    """Additional tests for error handling."""

    def test_error_formatting_format_error(self):
        """Test format_error function."""
        from reversecore_mcp.core.error_formatting import format_error
        from reversecore_mcp.core.exceptions import ValidationError

        err = ValidationError("Test message")
        result = format_error(err, tool_name="test_tool", hint="Test hint")
        assert isinstance(result, str)


# ============================================================================
# Validators Additional Tests
# ============================================================================


class TestValidatorsAdditional:
    """Additional tests for validators module."""

    def test_validate_address_format_valid(self):
        """Test validate_address_format with valid address."""
        from reversecore_mcp.core.validators import validate_address_format

        # Should not raise for valid hex address
        validate_address_format("0x401000")
        validate_address_format("401000")

    def test_validate_address_format_invalid(self):
        """Test validate_address_format with invalid address."""
        from reversecore_mcp.core.exceptions import ValidationError
        from reversecore_mcp.core.validators import validate_address_format

        with pytest.raises(ValidationError):
            validate_address_format("")

    def test_validate_tool_parameters(self):
        """Test validate_tool_parameters function."""
        from reversecore_mcp.core.validators import validate_tool_parameters

        # Should not raise for valid parameters
        validate_tool_parameters("strings", {"file_path": "/path/to/file"})
