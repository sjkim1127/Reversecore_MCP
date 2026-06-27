"""Tests for reversecore_mcp.tools.analysis.signature_tools."""

from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.tools.analysis.signature_tools import (
    _format_hex_bytes,
    _sanitize_filename_for_rule,
    _validate_address_or_fail,
    generate_enhanced_yara_rule,
    generate_signature,
    generate_yara_rule,
)


class TestValidateAddressOrFail:
    """Tests for _validate_address_or_fail."""

    def test_valid_hex(self):
        result = _validate_address_or_fail("0x401000")
        assert result is None  # Returns None on success

    def test_invalid_address(self):
        result = _validate_address_or_fail("bad; rm -rf /")
        assert result is not None  # Returns failure ToolResult
        assert result.status == "error"


class TestFormatHexBytes:
    """Tests for _format_hex_bytes."""

    def test_even_length(self):
        result = _format_hex_bytes("DEADBEEF")
        assert result == "DE AD BE EF"

    def test_odd_length(self):
        result = _format_hex_bytes("123")
        assert result == "12 3"


class TestSanitizeFilenameForRule:
    """Tests for _sanitize_filename_for_rule."""

    def test_simple_name(self):
        result = _sanitize_filename_for_rule("/path/to/test.exe")
        assert result == "test"

    def test_with_dots(self):
        result = _sanitize_filename_for_rule("my.file.name.dll")
        assert result == "my_file_name"


class TestGenerateSignature:
    """Tests for generate_signature."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            mock_r2.return_value = ("4883ec20", 8)
            result = await generate_signature(str(test_file), "0x401000", length=4)

        assert result.status == "success"
        assert "suspicious_test_x401000" in result.data
        assert result.metadata["hex_bytes"] == "48 83 ec 20"

    @pytest.mark.asyncio
    async def test_all_zeros_fallback(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec,
        ):
            # First attempt returns all zeros, with analysis_level="-n"
            # Second attempt returns a valid code block or zeros again
            mock_r2.return_value = ("00000000", 4)
            mock_exec.return_value = ("00000000", 4)
            result = await generate_signature(str(test_file), "0x401000")

        assert result.status == "error"
        assert result.error_code == "SIGNATURE_ERROR"

    @pytest.mark.asyncio
    async def test_invalid_address(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)
        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_signature(str(test_file), "invalid_address!")
        assert result.status == "error"
        assert "address" in result.message

    @pytest.mark.asyncio
    async def test_invalid_hex_bytes(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            mock_r2.return_value = ("invalid hex chars here", 0)
            result = await generate_signature(str(test_file), "0x401000")

        assert result.status == "error"
        assert "Failed to extract valid hex bytes" in result.message


class TestGenerateYaraRule:
    """Tests for generate_yara_rule."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            mock_r2.return_value = ("5589e55d", 4)
            result = await generate_yara_rule(str(test_file), "0x401000", rule_name="my_rule")

        assert result.status == "success"
        assert "rule my_rule" in result.data

    @pytest.mark.asyncio
    async def test_invalid_rule_name(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)
        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_yara_rule(str(test_file), "0x401000", rule_name="123_invalid")
        assert result.status == "error"
        assert "rule_name must start with a letter" in result.message

    @pytest.mark.asyncio
    async def test_smart_offset_search_failure(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            # Mock return value for p8 16 => all zeros to trigger smart offset
            # Then aflj returns list of functions
            mock_r2.side_effect = [
                ("00" * 20, 20),
                ('[{"offset": 4198400, "size": 100, "name": "sym.main"}]', 50),
            ]
            result = await generate_yara_rule(str(test_file), "0x401000", rule_name="smart_rule")

        assert result.status == "error"
        # Ensure we check the hint field for suggestion alternatives
        assert "Suggested alternative" in result.hint
        assert "sym.main" in result.hint

    @pytest.mark.asyncio
    async def test_smart_offset_search_corrupt_json(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with (
            patch(
                "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
                return_value=test_file,
            ),
            patch(
                "reversecore_mcp.tools.analysis.signature_tools._execute_r2_command",
                new_callable=AsyncMock,
            ) as mock_r2,
        ):
            mock_r2.side_effect = [
                ("00" * 20, 20),
                ("corrupt json here", 18),
            ]
            result = await generate_yara_rule(str(test_file), "0x401000", rule_name="smart_rule")

        assert result.status == "error"
        assert "contains invalid bytes" in result.message


class TestGenerateEnhancedYaraRule:
    """Tests for generate_enhanced_yara_rule."""

    @pytest.mark.asyncio
    async def test_success_pe(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_enhanced_yara_rule(
                str(test_file),
                "enhanced_pe_rule",
                strings=["malware_string_1", "malware_string_2"],
                imports=["CreateProcessA", "VirtualAlloc"],
                file_type="PE",
                min_filesize=1000,
                max_filesize=100000,
                section_names=[".text", ".rsrc"],
                entry_point_pattern="55 89 e5",
                tags=["apt", "trojan"],
            )

        assert result.status == "success"
        assert "rule enhanced_pe_rule : apt trojan" in result.data
        assert 'import "pe"' in result.data
        assert "uint16(0) == 0x5A4D" in result.data
        assert "filesize > 1000" in result.data
        assert "filesize < 100000" in result.data
        assert "pe.sections" in result.data
        assert "$ep at pe.entry_point" in result.data

    @pytest.mark.asyncio
    async def test_success_elf(self, tmp_path):
        test_file = tmp_path / "test.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_enhanced_yara_rule(
                str(test_file),
                "enhanced_elf_rule",
                strings=["elf_malware_str"],
                file_type="ELF",
                section_names=[".text"],
                entry_point_pattern="31 c0 c3",
            )

        assert result.status == "success"
        assert 'import "elf"' in result.data
        assert "uint32(0) == 0x464C457F" in result.data
        assert "$ep at elf.entry_point" in result.data

    @pytest.mark.asyncio
    async def test_invalid_rule_name(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)
        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_enhanced_yara_rule(str(test_file), "123_invalid", ["string"])
        assert result.status == "error"
        assert "rule_name must start with a letter" in result.message

    @pytest.mark.asyncio
    async def test_empty_strings(self, tmp_path):
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)
        with patch(
            "reversecore_mcp.tools.analysis.signature_tools.validate_file_path",
            return_value=test_file,
        ):
            result = await generate_enhanced_yara_rule(str(test_file), "valid_name", [])
        assert result.status == "error"
        assert "At least one string is required" in result.message
