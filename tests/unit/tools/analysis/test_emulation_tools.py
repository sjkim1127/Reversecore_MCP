"""Unit tests for the emulation_tools module."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.analysis.emulation_tools import _detect_binary_type, emulate_binary


class TestDetectBinaryType:
    """Tests for _detect_binary_type helper function."""

    @patch("lief.parse")
    def test_detect_elf_x86_64(self, mock_lief_parse):
        """Test detecting ELF x86-64 binary."""
        mock_binary = MagicMock()
        mock_binary.format = MagicMock()
        mock_binary.format.__str__.return_type = "FORMAT.ELF"
        mock_binary.format = "FORMAT.ELF"
        mock_binary.header = MagicMock()
        mock_binary.header.machine = "ARCH_x86_64"
        mock_lief_parse.return_value = mock_binary

        ostype, archtype = _detect_binary_type(Path("/app/workspace/sample.elf"))
        assert ostype == "linux"
        assert archtype == "x86_64"

    @patch("lief.parse")
    def test_detect_pe_x86(self, mock_lief_parse):
        """Test detecting PE x86 binary."""
        mock_binary = MagicMock()
        mock_binary.format = "FORMAT.PE"
        mock_binary.header = MagicMock()
        mock_binary.header.machine = "ARCH_i386"
        mock_lief_parse.return_value = mock_binary

        ostype, archtype = _detect_binary_type(Path("/app/workspace/sample.exe"))
        assert ostype == "windows"
        assert archtype == "x86"

    @patch("lief.parse", side_effect=Exception("LIEF error"))
    def test_detect_fallback_pe(self, mock_lief_parse):
        """Test fallback detection for PE binary via magic bytes."""
        with patch("builtins.open", MagicMock()) as mock_file_open:
            mock_file = MagicMock()
            mock_file.read.return_value = b"MZ\x90\x00"
            mock_file_open.return_value.__enter__.return_value = mock_file

            ostype, archtype = _detect_binary_type(Path("/app/workspace/sample.exe"))
            assert ostype == "windows"


class TestEmulateBinary:
    """Tests for emulate_binary tool."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.emulation_tools.validate_file_path")
    async def test_emulate_binary_invalid_address(self, mock_validate_file_path):
        """Test that ValidationError is raised for invalid hex/int addresses."""
        mock_validate_file_path.return_value = Path("/app/workspace/sample.elf")

        # Invalid start address
        result = await emulate_binary("sample.elf", start_address="invalid_addr")
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code

        # Invalid end address
        result = await emulate_binary("sample.elf", end_address="invalid_addr")
        assert result.status == "error"
        assert "VALIDATION_ERROR" in result.error_code

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.emulation_tools.validate_file_path")
    async def test_emulate_binary_qiling_not_installed(self, mock_validate_file_path):
        """Test emulation fails gracefully when Qiling is not installed."""
        mock_validate_file_path.return_value = Path("/app/workspace/sample.elf")

        with patch.dict("sys.modules", {"qiling": None}):
            result = await emulate_binary("sample.elf")
            assert result.status == "error"
            assert result.error_code == "EMULATION_ERROR"
            assert "Qiling framework is not installed" in result.message

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.emulation_tools.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.emulation_tools._detect_binary_type")
    async def test_emulate_binary_success(self, mock_detect, mock_validate_file_path):
        """Test successful emulation with mocked Qiling engine."""
        mock_validate_file_path.return_value = Path("/app/workspace/sample.elf")
        mock_detect.return_value = ("linux", "x86_64")

        # Mock Qiling class and its registers/stack/run APIs
        mock_ql = MagicMock()
        mock_ql.arch = MagicMock()
        mock_ql.arch.regs = MagicMock()
        mock_ql.arch.regs.read.side_effect = lambda reg: 0x1234 if reg == "rax" else 0

        mock_ql_class = MagicMock()
        mock_ql_class.return_value = mock_ql

        mock_qiling_module = MagicMock()
        mock_qiling_module.Qiling = mock_ql_class

        mock_qiling_const_module = MagicMock()
        mock_qiling_const_module.QL_VERBOSE = MagicMock()

        # Patch sys.modules to mock imports of qiling
        with patch.dict(
            sys.modules, {"qiling": mock_qiling_module, "qiling.const": mock_qiling_const_module}
        ):
            result = await emulate_binary(
                "sample.elf",
                registers={"rax": 10},
                stack_inputs=[1, 2],
                mock_files={"/etc/config": "test_content"},
                timeout=5,
            )

            assert result.status == "success"
            assert result.data["ostype"] == "linux"
            assert result.data["archtype"] == "x86_64"
            assert result.data["final_registers"]["rax"] == "0x1234"

            # Check that Qiling was instantiated and run
            mock_ql_class.assert_called_once()
            mock_ql.run.assert_called_once_with(begin=None, end=None, timeout=5000)
            mock_ql.arch.regs.write.assert_called_with("rax", 10)
            mock_ql.arch.stack_push.assert_any_call(1)
            mock_ql.arch.stack_push.assert_any_call(2)
