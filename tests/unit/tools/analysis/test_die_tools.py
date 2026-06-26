"""Unit tests for die_tools module."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import lief
import pytest

import reversecore_mcp.tools.analysis.die_tools as die_tools
from reversecore_mcp.tools.analysis.die_tools import (
    _analyze_binary_with_lief,
    detect_packer,
    detect_packer_deep,
)


# Custom isinstance mock to handle C++ extension class checks on mocks
def mock_isinstance(obj, class_info):
    if hasattr(obj, "_mock_class") and obj._mock_class == class_info:
        return True
    import builtins

    return builtins.isinstance(obj, class_info)


# Apply the mock to the die_tools module namespace
die_tools.isinstance = mock_isinstance


class TestAnalyzeBinaryWithLief:
    """Tests for _analyze_binary_with_lief function."""

    @patch("lief.parse")
    def test_analyze_pe_amd64(self, mock_parse):
        """Test analyzing an AMD64 PE binary with LIEF."""
        mock_binary = MagicMock()
        mock_binary._mock_class = lief.PE.Binary
        mock_binary.header.machine = "AMD64"

        mock_section = MagicMock()
        mock_section.name = ".upx0"
        mock_section.entropy = 7.9
        mock_section.size = 1000
        mock_binary.sections = [mock_section]

        mock_parse.return_value = mock_binary

        result = _analyze_binary_with_lief(Path("dummy_path"))

        assert result["file_type"] == "PE32+"
        assert result["arch"] == "x64"
        assert len(result["high_entropy_sections"]) == 1
        assert result["high_entropy_sections"][0]["name"] == ".upx0"
        assert result["high_entropy_sections"][0]["entropy"] == 7.9
        assert result["suspicious_sections"] == [".upx0"]
        assert result["packer_from_sections"] == "UPX"

    @patch("lief.parse")
    def test_analyze_elf_x64(self, mock_parse):
        """Test analyzing an x64 ELF binary with LIEF."""
        mock_binary = MagicMock()
        mock_binary._mock_class = lief.ELF.Binary
        mock_binary.header.identity_class = "ELF64"
        mock_binary.header.machine_type = "X86_64"

        mock_section = MagicMock()
        mock_section.name = ".text"
        mock_section.entropy = 5.0
        mock_section.size = 2000
        mock_binary.sections = [mock_section]

        mock_parse.return_value = mock_binary

        result = _analyze_binary_with_lief(Path("dummy_path"))

        assert result["file_type"] == "ELF64"
        assert result["arch"] == "x64"
        assert len(result["high_entropy_sections"]) == 0
        assert result["suspicious_sections"] == []
        assert result["packer_from_sections"] is None

    @patch("lief.parse")
    def test_analyze_macho_arm64(self, mock_parse):
        """Test analyzing an ARM64 MachO binary with LIEF."""
        mock_binary = MagicMock()
        mock_binary._mock_class = lief.MachO.Binary
        mock_binary.header.cpu_type = "ARM64"
        mock_binary.sections = []

        mock_parse.return_value = mock_binary

        result = _analyze_binary_with_lief(Path("dummy_path"))

        assert result["file_type"] == "Mach-O"
        assert result["arch"] == "arm64"

    @patch("lief.parse")
    def test_analyze_parse_none(self, mock_parse):
        """Test analyzing when lief.parse returns None."""
        mock_parse.return_value = None
        result = _analyze_binary_with_lief(Path("dummy_path"))
        assert result["file_type"] is None
        assert result["arch"] is None

    @patch("lief.parse")
    def test_analyze_exception(self, mock_parse):
        """Test that exception during lief parsing is handled gracefully."""
        mock_parse.side_effect = Exception("LIEF failed")
        result = _analyze_binary_with_lief(Path("dummy_path"))
        assert result["file_type"] is None
        assert result["arch"] is None


class TestDetectPacker:
    """Tests for detect_packer tool."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.die_tools.validate_file_path")
    async def test_detect_packer_read_error(self, mock_validate):
        """Test when the file cannot be read."""
        mock_path = MagicMock(spec=Path)
        mock_path.read_bytes.side_effect = OSError("Read failed")
        mock_validate.return_value = mock_path

        result = await detect_packer("dummy_path")
        assert result.status == "error"
        assert "Cannot read file" in result.message

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.die_tools._analyze_binary_with_lief")
    @patch("reversecore_mcp.tools.analysis.die_tools.validate_file_path")
    async def test_detect_packer_success_packed(self, mock_validate, mock_analyze):
        """Test detect_packer success with a packed binary (UPX)."""
        mock_path = MagicMock(spec=Path)
        # Mock file contents with "UPX!" signature
        mock_path.read_bytes.return_value = b"Some random bytes UPX! more bytes"
        mock_validate.return_value = mock_path

        mock_analyze.return_value = {
            "file_type": "PE32+",
            "arch": "x64",
            "high_entropy_sections": [{"name": ".upx0", "entropy": 7.9, "size": 500}],
            "suspicious_sections": [".upx0"],
            "packer_from_sections": "UPX",
        }

        result = await detect_packer("dummy_path")
        assert result.status == "success"

        assert result.data["file_type"] == "PE32+"
        assert result.data["arch"] == "x64"
        assert result.data["packer"] == "UPX"
        assert result.data["is_packed"] is True
        assert any(d["value"] == "UPX" for d in result.data["detections"])

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.die_tools._analyze_binary_with_lief")
    @patch("reversecore_mcp.tools.analysis.die_tools.validate_file_path")
    async def test_detect_packer_success_non_packed(self, mock_validate, mock_analyze):
        """Test detect_packer success with a non-packed binary."""
        mock_path = MagicMock(spec=Path)
        # Mock file contents with GCC string
        mock_path.read_bytes.return_value = (
            b"Some compiler string GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
        )
        mock_validate.return_value = mock_path

        mock_analyze.return_value = {
            "file_type": "ELF64",
            "arch": "x64",
            "high_entropy_sections": [],
            "suspicious_sections": [],
            "packer_from_sections": None,
        }

        result = await detect_packer("dummy_path")
        assert result.status == "success"

        assert result.data["file_type"] == "ELF64"
        assert result.data["arch"] == "x64"
        assert result.data["packer"] is None
        assert result.data["compiler"] == "GCC"
        assert result.data["is_packed"] is False


class TestDetectPackerDeep:
    """Tests for detect_packer_deep tool."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.die_tools._analyze_binary_with_lief")
    @patch("reversecore_mcp.tools.analysis.die_tools.validate_file_path")
    async def test_detect_packer_deep_success(self, mock_validate, mock_analyze):
        """Test detect_packer_deep success."""
        mock_path = MagicMock(spec=Path)
        mock_path.read_bytes.return_value = b"VMProtect is here and also rustc compiler"
        mock_validate.return_value = mock_path

        mock_analyze.return_value = {
            "file_type": "PE32",
            "arch": "x86",
            "high_entropy_sections": [{"name": ".vmp0", "entropy": 7.8, "size": 1000}],
            "suspicious_sections": [".vmp0"],
            "packer_from_sections": "VMProtect",
        }

        result = await detect_packer_deep("dummy_path")
        assert result.status == "success"

        assert result.data["file_type"] == "PE32"
        assert result.data["arch"] == "x86"
        assert "VMProtect" in result.data["packers"]
        assert "Rust" in result.data["compilers"]
        assert result.metadata["is_packed"] is True
        assert len(result.data["high_entropy_sections"]) == 1
