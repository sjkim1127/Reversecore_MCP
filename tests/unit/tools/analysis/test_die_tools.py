"""Unit tests for die_tools module."""

import pytest
from unittest.mock import patch, AsyncMock

from reversecore_mcp.core.result import ToolSuccess, ToolError


class TestDieAvailability:
    """Tests for DIE availability check."""

    def test_is_die_available_when_installed(self):
        """Test when diec is installed."""
        with patch("shutil.which", return_value="/usr/bin/diec"):
            from reversecore_mcp.tools.analysis.die_tools import _is_die_available

            assert _is_die_available() is True

    def test_is_die_available_when_not_installed(self):
        """Test when diec is not installed."""
        with patch("shutil.which", return_value=None):
            from reversecore_mcp.tools.analysis.die_tools import _is_die_available

            assert _is_die_available() is False


class TestParseDieOutput:
    """Tests for DIE output parsing."""

    def test_parse_pe32_output(self):
        """Test parsing PE32 output."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        output = """PE32
Compiler: Microsoft Visual C/C++(2019 v.16.0)
Linker: Microsoft Linker(14.26.28805)"""
        result = _parse_die_output(output)
        assert result["file_type"] == "PE32"
        assert result["arch"] == "x86"
        assert "Microsoft Visual C" in result["compiler"]
        assert "Microsoft Linker" in result["linker"]

    def test_parse_pe64_output(self):
        """Test parsing PE64 output."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        output = """PE64
Compiler: GCC(10.2.0)
Packer: UPX(3.96)"""
        result = _parse_die_output(output)
        assert result["file_type"] == "PE64"
        assert result["arch"] == "x64"
        assert result["packer"] == "UPX(3.96)"

    def test_parse_with_protector(self):
        """Test parsing with protector detection."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        output = """PE32
Protector: Themida(3.0.0)"""
        result = _parse_die_output(output)
        assert result["protector"] == "Themida(3.0.0)"

    def test_parse_elf_output(self):
        """Test parsing ELF output."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        output = """ELF64
Compiler: GCC(9.3.0)"""
        result = _parse_die_output(output)
        assert result["file_type"] == "ELF64"
        assert result["arch"] == "x64"

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        result = _parse_die_output("")
        assert result["file_type"] is None
        assert result["detections"] == []

    def test_raw_output_preserved(self):
        """Test that raw output is preserved."""
        from reversecore_mcp.tools.analysis.die_tools import _parse_die_output

        output = "PE32\nCompiler: Test"
        result = _parse_die_output(output)
        assert result["raw_output"] == output


class TestDetectPacker:
    """Tests for detect_packer tool."""

    @pytest.mark.asyncio
    async def test_detect_packer_die_not_installed(self):
        """Test when DIE is not installed."""
        from reversecore_mcp.tools.analysis.die_tools import detect_packer

        with patch(
            "reversecore_mcp.tools.analysis.die_tools._is_die_available",
            return_value=False,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.die_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                result = await detect_packer("/path/to/file.exe")
                assert isinstance(result, ToolError)
                assert "not installed" in result.message.lower()

    @pytest.mark.asyncio
    async def test_detect_packer_success(self):
        """Test successful packer detection."""
        from reversecore_mcp.tools.analysis.die_tools import detect_packer

        mock_output = """PE32
Compiler: Microsoft Visual C/C++(2019)
Packer: UPX(3.96)"""

        with patch(
            "reversecore_mcp.tools.analysis.die_tools._is_die_available",
            return_value=True,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.die_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                with patch(
                    "reversecore_mcp.tools.analysis.die_tools.execute_subprocess_async",
                    new_callable=AsyncMock,
                    return_value=(mock_output, ""),
                ):
                    result = await detect_packer("/path/to/file.exe")
                    assert isinstance(result, ToolSuccess)
                    assert result.data["file_type"] == "PE32"
                    assert result.data["packer"] == "UPX(3.96)"

    @pytest.mark.asyncio
    async def test_detect_packer_no_packer(self):
        """Test detection with no packer."""
        from reversecore_mcp.tools.analysis.die_tools import detect_packer

        mock_output = """PE64
Compiler: Microsoft Visual C/C++(2022)"""

        with patch(
            "reversecore_mcp.tools.analysis.die_tools._is_die_available",
            return_value=True,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.die_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                with patch(
                    "reversecore_mcp.tools.analysis.die_tools.execute_subprocess_async",
                    new_callable=AsyncMock,
                    return_value=(mock_output, ""),
                ):
                    result = await detect_packer("/path/to/file.exe")
                    assert isinstance(result, ToolSuccess)


class TestDetectPackerDeep:
    """Tests for detect_packer_deep tool."""

    @pytest.mark.asyncio
    async def test_detect_packer_deep_success(self):
        """Test deep scan success."""
        from reversecore_mcp.tools.analysis.die_tools import detect_packer_deep

        mock_output = """PE32
Compiler: Borland Delphi
Protector: VMProtect(3.5)"""

        with patch(
            "reversecore_mcp.tools.analysis.die_tools._is_die_available",
            return_value=True,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.die_tools.validate_file_path",
                return_value="/path/to/file.exe",
            ):
                with patch(
                    "reversecore_mcp.tools.analysis.die_tools.execute_subprocess_async",
                    new_callable=AsyncMock,
                    return_value=(mock_output, ""),
                ):
                    result = await detect_packer_deep("/path/to/file.exe")
                    assert isinstance(result, ToolSuccess)
