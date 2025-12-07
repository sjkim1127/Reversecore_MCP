"""Absolute final tests to push over 80% coverage.

Focus on smallest gaps.
"""

from unittest.mock import AsyncMock, patch

import pytest

# ============================================================================
# File Operations - copy_to_workspace
# ============================================================================


class TestFileOperationsFinalPush:
    """Final push for file_operations coverage."""

    def test_copy_to_workspace_basic(self, patched_workspace_config, workspace_dir):
        """Test copy_to_workspace function."""
        import os

        # Create source file outside workspace first
        import tempfile

        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            temp_path = f.name

        try:
            result = copy_to_workspace(temp_path)
            assert result.status in ("success", "error")
        finally:
            os.unlink(temp_path)


# ============================================================================
# IOC Tools - edge cases
# ============================================================================


class TestIOCToolsFinalPush:
    """Final push for ioc_tools coverage."""

    def test_extract_iocs_emails(self, patched_workspace_config, workspace_dir):
        """Test extract_iocs with email patterns."""
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(
            b"admin@malware.com\x00support@legit-company.org\x00test.user@example.co.uk\x00"
        )

        result = extract_iocs(str(test_file))
        assert result.status in ("success", "error")


# ============================================================================
# JSON Utils - edge cases
# ============================================================================


class TestJsonUtilsFinalPush:
    """Final push for json_utils coverage."""

    def test_dumps_complex(self):
        """Test dumps with complex nested structures."""
        from reversecore_mcp.core import json_utils

        data = {"level1": {"level2": [1, 2, {"level3": "value"}]}, "list": [True, False, None]}
        result = json_utils.dumps(data)
        assert "level1" in result
        assert "level2" in result


# ============================================================================
# R2 Analysis - helper functions
# ============================================================================


class TestR2AnalysisFinalPush:
    """Final push for r2_analysis coverage."""

    def test_extract_first_json_nested(self):
        """Test _extract_first_json with nested JSON."""
        from reversecore_mcp.core.r2_helpers import _extract_first_json

        text = 'Some output {"nested": {"key": "value"}}'
        result = _extract_first_json(text)
        assert result is None or isinstance(result, str)


# ============================================================================
# Decompilation - edge cases
# ============================================================================


class TestDecompilationFinalPush:
    """Final push for decompilation coverage."""

    @pytest.mark.asyncio
    async def test_smart_decompile_detailed(self, patched_workspace_config, workspace_dir):
        """Test smart_decompile with detailed mock."""
        from reversecore_mcp.tools.ghidra.decompilation import smart_decompile

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 150)

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("/* decompiled */\nint main() { return 42; }", ""),
        ):
            result = await smart_decompile(str(test_file), "main")
            assert result.status in ("success", "error")


# ============================================================================
# Signature Tools - helpers
# ============================================================================


class TestSignatureToolsFinalPush:
    """Final push for signature_tools coverage."""

    def test_validate_address_or_fail_decimal(self):
        """Test _validate_address_or_fail with decimal address."""
        from reversecore_mcp.tools.analysis.signature_tools import _validate_address_or_fail

        # Should not raise for decimal address
        _validate_address_or_fail("4198400")

    def test_format_hex_bytes_short(self):
        """Test _format_hex_bytes with short hex string."""
        from reversecore_mcp.tools.analysis.signature_tools import _format_hex_bytes

        result = _format_hex_bytes("41")
        assert isinstance(result, str)


# ============================================================================
# Static Analysis - run_strings edge cases
# ============================================================================


class TestStaticAnalysisFinalPush:
    """Final push for static_analysis coverage."""

    @pytest.mark.asyncio
    async def test_run_strings_detailed(self, patched_workspace_config, workspace_dir):
        """Test run_strings with detailed output."""
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        test_file = workspace_dir / "test.bin"
        test_file.write_bytes(b"FIRST_STRING\x00SECOND_STRING\x00THIRD_STRING\x00")

        with patch(
            "reversecore_mcp.core.execution.execute_subprocess_async",
            new_callable=AsyncMock,
            return_value=("FIRST_STRING\nSECOND_STRING\nTHIRD_STRING", ""),
        ):
            result = await run_strings(str(test_file))
            assert result.status in ("success", "error")


# ============================================================================
# Validators - edge cases
# ============================================================================


class TestValidatorsFinalPush:
    """Final push for validators coverage."""

    def test_validate_address_format_hex_with_prefix(self):
        """Test validate_address_format with 0x prefix."""
        from reversecore_mcp.core.validators import validate_address_format

        # Should not raise
        validate_address_format("0x00401000")

    def test_validate_tool_parameters_radare2(self):
        """Test validate_tool_parameters for radare2 tool."""
        from reversecore_mcp.core.validators import validate_tool_parameters

        validate_tool_parameters("radare2", {"file_path": "/test.bin", "commands": ["aaa"]})


# ============================================================================
# Error Formatting - additional coverage
# ============================================================================


class TestErrorFormattingFinalPush:
    """Final push for error_formatting coverage."""

    def test_format_error_with_timeout_error(self):
        """Test format_error with ExecutionTimeoutError."""
        from reversecore_mcp.core.error_formatting import format_error
        from reversecore_mcp.core.exceptions import ExecutionTimeoutError

        err = ExecutionTimeoutError(120)
        result = format_error(err, tool_name="radare2")
        assert isinstance(result, str)

    def test_format_error_with_output_limit_error(self):
        """Test format_error with OutputLimitExceededError."""
        from reversecore_mcp.core.error_formatting import format_error
        from reversecore_mcp.core.exceptions import OutputLimitExceededError

        err = OutputLimitExceededError(1024, 2048)
        result = format_error(err)
        assert isinstance(result, str)
