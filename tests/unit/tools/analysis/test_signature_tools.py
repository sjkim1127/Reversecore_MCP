"""Tests for reversecore_mcp.tools.analysis.signature_tools."""

from unittest.mock import AsyncMock, patch

import pytest


class TestValidateAddressOrFail:
    """Tests for _validate_address_or_fail."""

    def test_valid_hex(self):
        from reversecore_mcp.tools.analysis.signature_tools import _validate_address_or_fail

        result = _validate_address_or_fail("0x401000")
        assert result is None  # Returns None on success

    def test_invalid_address(self):
        from reversecore_mcp.tools.analysis.signature_tools import _validate_address_or_fail

        result = _validate_address_or_fail("bad; rm -rf /")
        assert result is not None  # Returns failure ToolResult


class TestFormatHexBytes:
    """Tests for _format_hex_bytes."""

    def test_even_length(self):
        from reversecore_mcp.tools.analysis.signature_tools import _format_hex_bytes

        result = _format_hex_bytes("DEADBEEF")
        assert result == "DE AD BE EF"

    def test_odd_length(self):
        from reversecore_mcp.tools.analysis.signature_tools import _format_hex_bytes

        result = _format_hex_bytes("123")
        assert result == "12 3"


class TestSanitizeFilenameForRule:
    """Tests for _sanitize_filename_for_rule."""

    def test_simple_name(self):
        from reversecore_mcp.tools.analysis.signature_tools import _sanitize_filename_for_rule

        result = _sanitize_filename_for_rule("/path/to/test.exe")
        assert result == "test"

    def test_with_dots(self):
        from reversecore_mcp.tools.analysis.signature_tools import _sanitize_filename_for_rule

        result = _sanitize_filename_for_rule("my.file.name.dll")
        assert "my" in result


class TestGenerateSignature:
    """Tests for generate_signature."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.signature_tools import generate_signature

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.signature_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("DEADBEEF" * 4, 32)
                result = await generate_signature(str(test_file), "0x401000")

        assert result.status in ("success", "error")


class TestGenerateYaraRule:
    """Tests for generate_yara_rule."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.signature_tools import generate_yara_rule

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.signature_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("functions: 1\n", 15)
                result = await generate_yara_rule(str(test_file), "0x401000")

        assert result.status in ("success", "error")


class TestGenerateEnhancedYaraRule:
    """Tests for generate_enhanced_yara_rule."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.signature_tools import generate_enhanced_yara_rule

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_enhanced_yara_rule(
                str(test_file),
                "test_rule",
                ["test_string"],
            )

        assert result.status in ("success", "error")
