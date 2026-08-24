"""Unit tests for die_tools module."""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import lief
import pytest

import reversecore_mcp.tools.analysis.die_tools as die_tools
from reversecore_mcp.tools.analysis.die_tools import (
    _analyze_binary_with_lief,
    _pure_python_elf_fallback,
    _pure_python_header_fallback,
    _pure_python_pe_fallback,
    _run_diec_cli_if_available,
    calculate_block_entropy,
    calculate_shannon_entropy,
    compute_packing_heuristic_score,
    detect_packer,
    detect_packer_deep,
    detect_section_anomalies,
    get_entropy_category,
    inspect_binary_overlay,
    is_standard_section_name,
)

FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "synthetic_packers"


# Custom isinstance mock to handle C++ extension class checks on mocks
def mock_isinstance(obj, class_info):
    if hasattr(obj, "_mock_class") and obj._mock_class == class_info:
        return True
    import builtins

    return builtins.isinstance(obj, class_info)


# Apply the mock to the die_tools module namespace
die_tools.isinstance = mock_isinstance


# ============================================================================
# 1. Native Shannon Entropy Tests
# ============================================================================


class TestShannonEntropyEngine:
    """Tests for native Shannon entropy calculation."""

    def test_empty_bytes(self):
        assert calculate_shannon_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        assert calculate_shannon_entropy(b"\x00" * 1000) == 0.0
        assert calculate_shannon_entropy(b"A" * 500) == 0.0

    def test_two_equal_bytes(self):
        data = b"\x00\xff" * 500
        # -2 * (0.5 * log2(0.5)) = 1.0
        assert pytest.approx(calculate_shannon_entropy(data), 0.01) == 1.0

    def test_maximum_entropy(self):
        # 256 unique bytes equally distributed -> 8.0 bits/byte
        data = bytes(range(256)) * 100
        assert pytest.approx(calculate_shannon_entropy(data), 0.01) == 8.0

    def test_typical_text_entropy(self):
        text = b"The quick brown fox jumps over the lazy dog. 1234567890" * 10
        ent = calculate_shannon_entropy(text)
        assert 4.0 <= ent <= 5.0

    def test_entropy_categories(self):
        assert get_entropy_category(0.0) == "low"
        assert get_entropy_category(3.99) == "low"
        assert get_entropy_category(4.0) == "normal"
        assert get_entropy_category(6.79) == "normal"
        assert get_entropy_category(6.8) == "compressed"
        assert get_entropy_category(7.49) == "compressed"
        assert get_entropy_category(7.5) == "packed_or_encrypted"
        assert get_entropy_category(8.0) == "packed_or_encrypted"

    def test_calculate_block_entropy_empty(self):
        assert calculate_block_entropy(b"") == []
        assert calculate_block_entropy(b"test", block_size=0) == []

    def test_calculate_block_entropy_blocks(self):
        data = (b"\x00" * 4096) + bytes(range(256)) * 16
        blocks = calculate_block_entropy(data, block_size=4096)
        assert len(blocks) == 2
        assert blocks[0]["offset"] == 0
        assert blocks[0]["size"] == 4096
        assert blocks[0]["entropy"] == 0.0
        assert blocks[0]["category"] == "low"
        assert blocks[1]["offset"] == 4096
        assert pytest.approx(blocks[1]["entropy"], 0.01) == 8.0
        assert blocks[1]["category"] == "packed_or_encrypted"


# ============================================================================
# 2. Section Anomaly Detection Tests
# ============================================================================


class TestSectionAnomalyDetection:
    """Tests for section anomaly and W+X violation heuristics."""

    def test_standard_section_names(self):
        assert is_standard_section_name(".text", "PE") is True
        assert is_standard_section_name(".data", "PE") is True
        assert is_standard_section_name(".rodata", "ELF") is True
        assert is_standard_section_name("__text", "Mach-O") is True
        assert is_standard_section_name(".upx0", "PE") is False
        assert is_standard_section_name("", "PE") is False

    def test_empty_sections_list(self):
        assert detect_section_anomalies([], entrypoint=0x1000, file_size=1000) == []

    def test_wx_violation_detection(self):
        sections = [
            {
                "name": ".text",
                "virtual_address": "0x1000",
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
                "is_writable": True,
                "is_executable": True,
            }
        ]
        anomalies = detect_section_anomalies(sections, format_type="PE")
        assert any(
            a["anomaly"] == "writable_and_executable" and a["severity"] == "critical"
            for a in anomalies
        )

    def test_zero_raw_size_anomaly(self):
        sections = [
            {
                "name": "UPX0",
                "virtual_address": "0x1000",
                "virtual_size": 0x10000,
                "raw_size": 0,
                "is_writable": True,
                "is_executable": False,
            }
        ]
        anomalies = detect_section_anomalies(sections, format_type="PE")
        assert any(a["anomaly"] == "zero_raw_size" and a["severity"] == "high" for a in anomalies)

    def test_known_packer_section_anomaly(self):
        sections = [
            {
                "name": ".vmp0",
                "virtual_address": "0x1000",
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
            }
        ]
        anomalies = detect_section_anomalies(sections, format_type="PE")
        assert any(
            a["anomaly"] == "known_packer_section" and a["severity"] == "high" for a in anomalies
        )

    def test_entrypoint_in_last_section(self):
        sections = [
            {
                "name": ".text",
                "virtual_address": "0x1000",
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
            },
            {
                "name": ".stub",
                "virtual_address": "0x2000",
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
                "entropy": 7.8,
            },
        ]
        anomalies = detect_section_anomalies(sections, entrypoint=0x2500, format_type="PE")
        assert any(a["anomaly"] == "entrypoint_in_last_section" for a in anomalies)
        assert any(a["anomaly"] == "entrypoint_in_high_entropy_section" for a in anomalies)

    def test_entrypoint_outside_sections(self):
        sections = [
            {
                "name": ".text",
                "virtual_address": "0x1000",
                "virtual_size": 0x1000,
                "raw_size": 0x1000,
            }
        ]
        anomalies = detect_section_anomalies(sections, entrypoint=0x9000, format_type="PE")
        assert any(
            a["anomaly"] == "entrypoint_outside_sections" and a["severity"] == "critical"
            for a in anomalies
        )

    def test_elf_null_section_skipped(self):
        sections = [
            {
                "name": "",
                "virtual_address": "0x0",
                "virtual_size": 0,
                "raw_size": 0,
            },
            {
                "name": ".text",
                "virtual_address": "0x401000",
                "virtual_size": 0x100,
                "raw_size": 0x100,
                "is_executable": True,
            },
        ]
        anomalies = detect_section_anomalies(sections, entrypoint=0x401050, format_type="ELF64")
        assert not any(a["anomaly"] == "empty_section_name" for a in anomalies)


# ============================================================================
# 3. Binary Overlay Inspection Tests
# ============================================================================


class TestBinaryOverlayInspection:
    """Tests for binary overlay detection and payload magic classification."""

    def test_empty_data(self):
        res = inspect_binary_overlay(None, b"")
        assert res["has_overlay"] is False

    def test_no_overlay(self):
        data = b"MZ" + b"\x00" * 1022
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is False
        assert res["size"] == 0

    def test_null_alignment_padding_ignored(self):
        data = b"MZ" + b"\x00" * 1024 + b"\x00" * 16
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is False

    def test_pyinstaller_overlay_detection(self):
        data = (
            b"MZ"
            + b"\x00" * 1022
            + b"MEI\x0c\x0b\x0a\x0b\x0e_MEIPASS\x00pyimod01_os_path\x00base_library.zip"
        )
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is True
        assert res["payload_type"] == "PyInstaller_Archive"

    def test_zip_overlay_detection(self):
        data = b"MZ" + b"\x00" * 1022 + b"PK\x03\x04" + b"\x00" * 100
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is True
        assert res["payload_type"] == "ZIP_Archive"

    def test_7z_overlay_detection(self):
        data = b"MZ" + b"\x00" * 1022 + b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is True
        assert res["payload_type"] == "7z_Archive"

    def test_authenticode_overlay_detection(self):
        cert = struct.pack("<IHH", 256, 0x0200, 0x0002) + (b"\xaa" * 248)
        data = b"MZ" + b"\x00" * 1022 + cert
        res = inspect_binary_overlay(
            None,
            data,
            {
                "physical_extent": 1024,
                "security_directory": {"offset": 1024, "size": 256},
            },
        )
        assert res["has_overlay"] is True
        assert res["payload_type"] == "Authenticode_Signature"

    def test_high_entropy_blob_overlay(self):
        high_ent = bytes(range(256)) * 4
        data = b"MZ" + b"\x00" * 1022 + high_ent
        res = inspect_binary_overlay(None, data, {"physical_extent": 1024})
        assert res["has_overlay"] is True
        assert res["payload_type"] == "Encrypted_or_Compressed_Blob"


# ============================================================================
# 4. Pure Python Header Fallbacks Tests
# ============================================================================


class TestPurePythonHeaderFallbacks:
    """Tests for zero-dependency pure Python PE and ELF header fallback parsers."""

    def test_pe_fallback_invalid_data(self):
        assert _pure_python_pe_fallback(b"") is None
        assert _pure_python_pe_fallback(b"MZ" + b"\x00" * 10) is None
        assert _pure_python_pe_fallback(b"NOT_A_PE_FILE" * 10) is None

    def test_elf_fallback_invalid_data(self):
        assert _pure_python_elf_fallback(b"") is None
        assert _pure_python_elf_fallback(b"\x7fELF" + b"\x00" * 10) is None
        assert _pure_python_elf_fallback(b"NOT_AN_ELF" * 10) is None

    def test_pure_python_header_fallback_dispatcher(self):
        assert _pure_python_header_fallback(b"") is None
        assert _pure_python_header_fallback(b"RAW_DATA") is None


# ============================================================================
# 5. Multi-Factor Heuristic Scoring Tests
# ============================================================================


class TestHeuristicScoringEngine:
    """Tests for multi-factor packing confidence calculation."""

    def test_clean_binary_suppression(self):
        score = compute_packing_heuristic_score(
            overall_entropy=4.8,
            high_entropy_sections=[],
            section_anomalies=[],
            overlay_info={"has_overlay": False},
            found_packers=[],
            found_compilers=["MSVC"],
            suspicious_sections=[],
        )
        assert score["is_packed"] is False
        assert score["packing_confidence"] <= 0.1
        assert score["packer_category"] == "none"

    def test_commercial_packer_scoring(self):
        score = compute_packing_heuristic_score(
            overall_entropy=7.8,
            high_entropy_sections=[{"name": ".vmp0", "entropy": 7.9}],
            section_anomalies=[{"anomaly": "known_packer_section", "severity": "high"}],
            overlay_info={"has_overlay": False},
            found_packers=["VMProtect"],
            found_compilers=[],
            suspicious_sections=[".vmp0"],
        )
        assert score["is_packed"] is True
        assert score["packing_confidence"] >= 0.8
        assert score["packer_category"] == "commercial"

    def test_compressor_scoring(self):
        score = compute_packing_heuristic_score(
            overall_entropy=7.6,
            high_entropy_sections=[{"name": "UPX1", "entropy": 7.9}],
            section_anomalies=[
                {"anomaly": "zero_raw_size", "severity": "high"},
                {"anomaly": "writable_and_executable", "severity": "critical"},
            ],
            overlay_info={"has_overlay": False},
            found_packers=["UPX"],
            found_compilers=[],
            suspicious_sections=["UPX0", "UPX1"],
        )
        assert score["is_packed"] is True
        assert score["packing_confidence"] >= 0.9
        assert score["packer_category"] == "compressor"

    def test_pyinstaller_bundle_scoring(self):
        score = compute_packing_heuristic_score(
            overall_entropy=7.4,
            high_entropy_sections=[],
            section_anomalies=[],
            overlay_info={"has_overlay": True, "payload_type": "PyInstaller_Archive"},
            found_packers=["PyInstaller"],
            found_compilers=[],
            suspicious_sections=[],
        )
        assert score["is_packed"] is True
        assert score["packer_category"] == "bundle_installer"


# ============================================================================
# 6. Real Synthetic Fixtures End-to-End Tests
# ============================================================================


class TestSyntheticPackerFixtures:
    """End-to-end tests validating detection on synthetic packer fixtures."""

    @pytest.fixture(autouse=True)
    def bypass_path_validation(self):
        """Bypass workspace path validation so fixture files are always accessible
        regardless of REVERSECORE_WORKSPACE set by other tests in the full suite."""
        with patch(
            "reversecore_mcp.tools.analysis.die_tools.validate_file_path",
            side_effect=lambda p, **kw: Path(p),
        ):
            yield

    @pytest.mark.asyncio
    async def test_synthetic_upx(self):
        upx_path = FIXTURES_DIR / "synthetic_upx.exe"
        if not upx_path.exists():
            pytest.skip("synthetic_upx.exe fixture not generated")

        res = await detect_packer(str(upx_path))
        assert res.status == "success"
        assert res.data["is_packed"] is True
        assert res.data["packer"] == "UPX"
        assert res.data["packer_category"] == "compressor"
        assert res.data["packing_confidence"] >= 0.8

        deep_res = await detect_packer_deep(str(upx_path))
        assert deep_res.status == "success"
        assert "UPX" in deep_res.data["packers"]

    @pytest.mark.asyncio
    async def test_synthetic_vmprotect(self):
        vmp_path = FIXTURES_DIR / "synthetic_vmprotect.exe"
        if not vmp_path.exists():
            pytest.skip("synthetic_vmprotect.exe fixture not generated")

        res = await detect_packer(str(vmp_path))
        assert res.status == "success"
        assert res.data["is_packed"] is True
        assert res.data["packer"] == "VMProtect"
        assert res.data["packer_category"] == "commercial"

    @pytest.mark.asyncio
    async def test_synthetic_confuserex(self):
        confuser_path = FIXTURES_DIR / "synthetic_confuserex.exe"
        if not confuser_path.exists():
            pytest.skip("synthetic_confuserex.exe fixture not generated")

        res = await detect_packer(str(confuser_path))
        assert res.status == "success"
        assert res.data["is_packed"] is True
        assert res.data["packer"] == "ConfuserEx"
        assert res.data["packer_category"] == "commercial"

    @pytest.mark.asyncio
    async def test_synthetic_pyinstaller(self):
        pyinst_path = FIXTURES_DIR / "synthetic_pyinstaller.exe"
        if not pyinst_path.exists():
            pytest.skip("synthetic_pyinstaller.exe fixture not generated")

        res = await detect_packer(str(pyinst_path))
        assert res.status == "success"
        assert res.data["is_packed"] is True
        assert res.data["packer"] == "PyInstaller"
        assert res.data["packer_category"] == "bundle_installer"
        assert res.data["overlay"]["has_overlay"] is True
        assert res.data["overlay"]["payload_type"] == "PyInstaller_Archive"

    @pytest.mark.asyncio
    async def test_synthetic_authenticode_clean(self):
        auth_path = FIXTURES_DIR / "synthetic_authenticode.exe"
        if not auth_path.exists():
            pytest.skip("synthetic_authenticode.exe fixture not generated")

        res = await detect_packer(str(auth_path))
        assert res.status == "success"
        assert res.data["is_packed"] is False
        assert res.data["overlay"]["has_overlay"] is True
        assert res.data["overlay"]["payload_type"] == "Authenticode_Signature"

    @pytest.mark.asyncio
    async def test_synthetic_clean_pe_zero_fp(self):
        clean_pe = FIXTURES_DIR / "synthetic_clean_pe.exe"
        if not clean_pe.exists():
            pytest.skip("synthetic_clean_pe.exe fixture not generated")

        res = await detect_packer(str(clean_pe))
        assert res.status == "success"
        assert res.data["is_packed"] is False
        assert res.data["packer"] is None
        assert res.data["packing_confidence"] <= 0.1
        assert res.data["compiler"] == "MSVC"

    @pytest.mark.asyncio
    async def test_synthetic_clean_elf_zero_fp(self):
        clean_elf = FIXTURES_DIR / "synthetic_clean_elf"
        if not clean_elf.exists():
            pytest.skip("synthetic_clean_elf fixture not generated")

        res = await detect_packer(str(clean_elf))
        assert res.status == "success"
        assert res.data["is_packed"] is False
        assert res.data["packer"] is None
        assert res.data["packing_confidence"] <= 0.1
        assert res.data["compiler"] == "GCC"


# ============================================================================
# 7. Legacy Mock Tests (Backwards Compatibility)
# ============================================================================


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
        mock_path.read_bytes.return_value = b"Some random bytes UPX! more bytes"
        mock_validate.return_value = mock_path

        mock_analyze.return_value = {
            "file_type": "PE32+",
            "arch": "x64",
            "entry_point": "0x1000",
            "high_entropy_sections": [{"name": ".upx0", "entropy": 7.9, "size": 500}],
            "suspicious_sections": [".upx0"],
            "packer_from_sections": "UPX",
            "sections": [],
            "physical_extent": 0,
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
        mock_path.read_bytes.return_value = (
            b"Some compiler string GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
        )
        mock_validate.return_value = mock_path

        mock_analyze.return_value = {
            "file_type": "ELF64",
            "arch": "x64",
            "entry_point": "0x401000",
            "high_entropy_sections": [],
            "suspicious_sections": [],
            "packer_from_sections": None,
            "sections": [],
            "physical_extent": 0,
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
            "entry_point": "0x1000",
            "high_entropy_sections": [{"name": ".vmp0", "entropy": 7.8, "size": 1000}],
            "suspicious_sections": [".vmp0"],
            "packer_from_sections": "VMProtect",
            "sections": [],
            "physical_extent": 0,
        }

        result = await detect_packer_deep("dummy_path")
        assert result.status == "success"

        assert result.data["file_type"] == "PE32"
        assert result.data["arch"] == "x86"
        assert "VMProtect" in result.data["packers"]
        assert "Rust" in result.data["compilers"]
        assert result.metadata["is_packed"] is True
        assert len(result.data["high_entropy_sections"]) == 1


class TestDiecCliIntegration:
    """Tests for optional diec CLI wrapper."""

    @patch("shutil.which", return_value="/usr/bin/diec")
    @patch("subprocess.run")
    def test_diec_cli_success(self, mock_run, mock_which):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"detects": [{"type": "Packer", "name": "UPX (3.96)"}]}'
        mock_run.return_value = mock_proc

        res = _run_diec_cli_if_available(Path("dummy"))
        assert res is not None
        assert res["detects"][0]["name"] == "UPX (3.96)"

    @patch("shutil.which", return_value=None)
    def test_diec_cli_not_found(self, mock_which):
        assert _run_diec_cli_if_available(Path("dummy")) is None
