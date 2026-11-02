"""Tests for reversecore_mcp.tools.analysis.lief_tools."""

import concurrent.futures
from concurrent.futures.process import BrokenProcessPool
from unittest.mock import MagicMock, patch

import lief
import pytest

# Import _extract_mitigations and trigger the compatibility aliases first
from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

try:
    _extract_mitigations(None)
except Exception:
    pass

# Now only define mock fallback classes if they are STILL missing
if not hasattr(lief.ELF, "SEGMENT_TYPES"):

    class SEGMENT_TYPES:
        GNU_RELRO = 1

    lief.ELF.SEGMENT_TYPES = SEGMENT_TYPES

if not hasattr(lief.ELF, "DYNAMIC_TAGS"):

    class DYNAMIC_TAGS:
        FLAGS = 2
        FLAGS_1 = 3
        BIND_NOW = 4

    lief.ELF.DYNAMIC_TAGS = DYNAMIC_TAGS

if not hasattr(lief.ELF, "DYNAMIC_FLAGS"):

    class DYNAMIC_FLAGS:
        BIND_NOW = 3
        NOW = 5

    lief.ELF.DYNAMIC_FLAGS = DYNAMIC_FLAGS

if not hasattr(lief.PE, "DLL_CHARACTERISTICS"):

    class DLL_CHARACTERISTICS:
        NX_COMPAT = 4
        DYNAMIC_BASE = 5
        GUARD_CF = 6

    lief.PE.DLL_CHARACTERISTICS = DLL_CHARACTERISTICS

if not hasattr(lief.PE, "LoadConfigurationV1"):

    class LoadConfigurationV1:
        pass

    lief.PE.LoadConfigurationV1 = LoadConfigurationV1


@pytest.fixture(autouse=True)
def reset_lief_state():
    """Reset LIEF cache and shared pool before and after every test."""
    from reversecore_mcp.tools.analysis.lief_tools import _lief_cache, _reset_lief_pool

    _lief_cache.clear()
    _reset_lief_pool(shutdown_old=False)
    yield
    _lief_cache.clear()
    _reset_lief_pool(shutdown_old=False)


class TestExtractSections:
    """Tests for _extract_sections."""

    def test_no_sections(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_sections

        binary = MagicMock()
        binary.sections = None
        result = _extract_sections(binary)
        assert result == []

    def test_with_sections(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_sections

        binary = MagicMock()
        section = MagicMock()
        section.name = ".text"
        section.virtual_address = 4096
        section.size = 512
        section.characteristics = 0x60000020
        binary.sections = [section]
        result = _extract_sections(binary)
        assert len(result) == 1
        assert result[0]["name"] == ".text"


class TestExtractMitigations:
    """Tests for _extract_mitigations."""

    def test_extract_mitigations_elf_all_mitigations(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = True
        binary.is_pie = True

        # Canary check
        sym = MagicMock()
        sym.name = "__stack_chk_fail"
        binary.imported_symbols = [sym]

        # RELRO check
        segment = MagicMock()
        segment.type = lief.ELF.SEGMENT_TYPES.GNU_RELRO
        binary.segments = [segment]

        # Bind Now check - Case A: DynamicEntryFlags
        binary.has.return_value = True
        flags_mock = MagicMock(spec=lief.ELF.DynamicEntryFlags)
        flags_mock.flags = [lief.ELF.DYNAMIC_FLAGS.BIND_NOW]
        binary.get.return_value = flags_mock

        result = _extract_mitigations(binary)
        assert result["nx"] is True
        assert result["pie"] is True
        assert result["canary"] is True
        assert result["relro"] == "Full"

    def test_extract_mitigations_elf_partial_relro_flags_variant_b(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []

        segment = MagicMock()
        segment.type = lief.ELF.SEGMENT_TYPES.GNU_RELRO
        binary.segments = [segment]

        # Bind Now check - Case B: type(flags).__name__ == "DynamicEntryFlags"
        binary.has.return_value = True

        class DynamicEntryFlags:
            def __contains__(self, item):
                return item == lief.ELF.DYNAMIC_FLAGS.BIND_NOW

        binary.get.return_value = DynamicEntryFlags()

        result = _extract_mitigations(binary)
        assert result["relro"] == "Full"

    def test_extract_mitigations_elf_partial_relro_flags_variant_c(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []

        segment = MagicMock()
        segment.type = lief.ELF.SEGMENT_TYPES.GNU_RELRO
        binary.segments = [segment]

        # Bind Now check - Case C: list
        binary.has.return_value = True
        binary.get.return_value = [lief.ELF.DYNAMIC_FLAGS.BIND_NOW]

        result = _extract_mitigations(binary)
        assert result["relro"] == "Full"

    def test_extract_mitigations_elf_no_mitigations(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []
        binary.segments = []
        binary.has.return_value = False

        result = _extract_mitigations(binary)
        assert result["nx"] is False
        assert result["pie"] is False
        assert result["canary"] is False
        assert result["relro"] == "None"

    def test_extract_mitigations_elf_flags_1_now_full_relro(self):
        """PT_GNU_RELRO + DT_FLAGS_1 with NOW flag classifies as Full RELRO."""
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = True
        binary.is_pie = True
        binary.imported_symbols = []

        # GNU_RELRO segment present
        segment = MagicMock()
        segment.type = getattr(
            lief.ELF, "SEGMENT_TYPES", getattr(getattr(lief.ELF, "Segment", None), "TYPE", None)
        ).GNU_RELRO
        binary.segments = [segment]

        tag_enum = getattr(
            lief.ELF, "DYNAMIC_TAGS", getattr(getattr(lief.ELF, "DynamicEntry", None), "TAG", None)
        )
        flag_enum = getattr(
            lief.ELF,
            "DYNAMIC_FLAGS",
            getattr(getattr(lief.ELF, "DynamicEntryFlags", None), "FLAG", None),
        )
        flags_1_tag = getattr(tag_enum, "FLAGS_1", None)
        now_flag = getattr(flag_enum, "NOW", None)

        def mock_has(tag):
            return tag == flags_1_tag

        binary.has.side_effect = mock_has

        flags_1_mock = MagicMock()
        flags_1_mock.flags = [now_flag]
        flags_1_mock.has.return_value = True
        flags_1_mock.value = 1
        binary.get.return_value = flags_1_mock

        result = _extract_mitigations(binary)
        assert result["relro"] == "Full"

    def test_extract_mitigations_elf_dt_bind_now_tag_full_relro(self):
        """PT_GNU_RELRO + standalone DT_BIND_NOW tag classifies as Full RELRO."""
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []

        segment = MagicMock()
        segment.type = getattr(
            lief.ELF, "SEGMENT_TYPES", getattr(getattr(lief.ELF, "Segment", None), "TYPE", None)
        ).GNU_RELRO
        binary.segments = [segment]

        tag_enum = getattr(
            lief.ELF, "DYNAMIC_TAGS", getattr(getattr(lief.ELF, "DynamicEntry", None), "TAG", None)
        )
        bind_now_tag = getattr(tag_enum, "BIND_NOW", None)

        def mock_has(tag):
            return tag == bind_now_tag

        binary.has.side_effect = mock_has

        result = _extract_mitigations(binary)
        assert result["relro"] == "Full"

    def test_extract_mitigations_elf_gnu_relro_without_eager_binding_partial(self):
        """PT_GNU_RELRO present without any eager-binding flags classifies as Partial RELRO."""
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []

        segment = MagicMock()
        segment.type = getattr(
            lief.ELF, "SEGMENT_TYPES", getattr(getattr(lief.ELF, "Segment", None), "TYPE", None)
        ).GNU_RELRO
        binary.segments = [segment]
        binary.has.return_value = False
        binary.dynamic_entries = []

        result = _extract_mitigations(binary)
        assert result["relro"] == "Partial"

    def test_extract_mitigations_elf_now_flags_without_gnu_relro_none(self):
        """No PT_GNU_RELRO must result in relro='None' regardless of BIND_NOW flags."""
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []
        # No segments (no GNU_RELRO)
        binary.segments = []

        tag_enum = getattr(
            lief.ELF, "DYNAMIC_TAGS", getattr(getattr(lief.ELF, "DynamicEntry", None), "TAG", None)
        )
        bind_now_tag = getattr(tag_enum, "BIND_NOW", None)
        binary.has.side_effect = lambda t: t == bind_now_tag

        result = _extract_mitigations(binary)
        assert result["relro"] == "None"

    def test_extract_mitigations_pe_all_mitigations(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_opt_header = True
        binary.optional_header.dll_characteristics_lists = [
            lief.PE.DLL_CHARACTERISTICS.NX_COMPAT,
            lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE,
            lief.PE.DLL_CHARACTERISTICS.GUARD_CF,
        ]

        binary.has_load_config = True
        load_config = MagicMock(spec=lief.PE.LoadConfigurationV1)
        load_config.se_handler_table = 0x1234
        load_config.se_handler_count = 2
        load_config.security_cookie = 0x5678
        binary.load_configuration = load_config

        result = _extract_mitigations(binary)
        assert result["nx"] is True
        assert result["pie"] is True
        assert result["cfg"] is True
        assert result["safeseh"] is True
        assert result["canary"] is True
        assert result["dynamic_base"] is True

    def test_extract_mitigations_pe_no_mitigations(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_opt_header = True
        binary.optional_header.dll_characteristics_lists = []
        binary.has_load_config = False

        result = _extract_mitigations(binary)
        assert result["nx"] is False
        assert result["pie"] is False
        assert result["cfg"] is False
        assert result["safeseh"] is False
        assert result["canary"] is False

    def test_extract_mitigations_pe_exception_handling(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.PE.Binary)
        binary.has_opt_header = True
        binary.optional_header.dll_characteristics_lists = []

        # Accessing has_load_config raises exception
        type(binary).has_load_config = property(
            MagicMock(side_effect=RuntimeError("PE parse error"))
        )

        # Should not crash and return default/empty mitigations
        result = _extract_mitigations(binary)
        assert result["nx"] is False

    def test_extract_mitigations_general_exception_handled(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        with patch("builtins.isinstance", side_effect=TypeError("mock error")):
            result = _extract_mitigations(None)
            assert result["nx"] is False

    def test_extract_mitigations_elf_partial_relro_only(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []

        segment = MagicMock()
        segment.type = lief.ELF.SEGMENT_TYPES.GNU_RELRO
        binary.segments = [segment]

        # No BIND_NOW
        binary.has.return_value = False

        result = _extract_mitigations(binary)
        assert result["relro"] == "Partial"

    def test_extract_mitigations_elf_flags_exception(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.has_nx = False
        binary.is_pie = False
        binary.imported_symbols = []
        binary.segments = []

        # Raising exception on has()
        binary.has.side_effect = RuntimeError("Mock has error")

        result = _extract_mitigations(binary)
        # Should not crash
        assert result["relro"] == "None"


class TestExtractSymbols:
    """Tests for _extract_symbols."""

    def test_no_imports_exports(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_symbols

        binary = MagicMock()
        binary.imported_functions = []
        binary.exported_functions = []
        binary.imports = []
        binary.exports = []
        result = _extract_symbols(binary)
        assert "imported_functions" not in result
        assert "exported_functions" not in result
        assert "imports" not in result
        assert "exports" not in result

    def test_with_imports(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_symbols

        binary = MagicMock()

        # Mock imported/exported functions as objects with __str__ defined
        f1 = MagicMock()
        f1.__str__.return_value = "printf"
        f2 = MagicMock()
        f2.__str__.return_value = "malloc"

        binary.imported_functions = [f1, f2]
        binary.exported_functions = []
        result = _extract_symbols(binary)
        assert len(result["imported_functions"]) == 2
        assert "printf" in result["imported_functions"]

    def test_pe_imports_exports(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_symbols

        binary = MagicMock()
        binary.imported_functions = []
        binary.exported_functions = []

        # Mock imports
        imp1 = MagicMock()
        imp1.name = "kernel32.dll"
        f1 = MagicMock()
        f1.__str__.return_value = "CreateFileW"
        imp1.entries = [f1]
        binary.imports = [imp1]

        # Mock exports
        exp1 = MagicMock()
        exp1.name = "MyExportedFunction"
        exp1.address = 0x1000
        binary.exports = [exp1]

        result = _extract_symbols(binary)
        assert "imports" in result
        assert result["imports"][0]["name"] == "kernel32.dll"
        assert result["imports"][0]["functions"] == ["CreateFileW"]
        assert "exports" in result
        assert result["exports"][0]["name"] == "MyExportedFunction"
        assert result["exports"][0]["address"] == "0x1000"


class TestFormatLiefOutput:
    """Tests for _format_lief_output."""

    def test_json_format(self):
        from reversecore_mcp.tools.analysis.lief_tools import _format_lief_output

        result = _format_lief_output({"key": "value"}, "json")
        assert '"key": "value"' in result

    def test_text_format(self):
        from reversecore_mcp.tools.analysis.lief_tools import _format_lief_output

        result = _format_lief_output({"format": "PE"}, "text")
        assert "Format: PE" in result

    def test_format_lief_output_all_sections_and_limits(self):
        from reversecore_mcp.tools.analysis.lief_tools import _format_lief_output

        mock_data = {
            "format": "elf",
            "entry_point": "0x400000",
            "mitigations": {
                "nx": True,
                "pie": False,
                "canary": True,
            },
            "sections": [
                {
                    "name": f".sec{i}",
                    "virtual_address": hex(0x1000 + i * 0x100),
                    "size": 100,
                }
                for i in range(25)
            ],
            "imported_functions": [f"imp_func_{i}" for i in range(25)],
            "exported_functions": [f"exp_func_{i}" for i in range(25)],
        }

        output = _format_lief_output(mock_data, "text")

        assert "Format: elf" in output
        assert "Entry Point: 0x400000" in output
        assert "NX: True" in output
        assert "PIE: False" in output
        assert "CANARY: True" in output

        # Sections count should be reported as 25, but only 20 printed
        assert "Sections (25):" in output
        assert ".sec0: VA=0x1000, Size=100" in output
        assert ".sec19: VA=0x2300, Size=100" in output
        assert ".sec20" not in output

        # Imports limit check (only 20 printed)
        assert "Imported Functions (25):" in output
        assert "imp_func_0" in output
        assert "imp_func_19" in output
        assert "imp_func_20" not in output

        # Exports limit check (only 20 printed)
        assert "Exported Functions (25):" in output
        assert "exp_func_0" in output
        assert "exp_func_19" in output
        assert "exp_func_20" not in output


class TestParseBinaryWithLief:
    """Tests for parse_binary_with_lief."""

    def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_result = {
            "format": "PE",
            "architecture": "AMD64",
            "sections": [],
            "imports": [],
            "exports": [],
        }

        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "success"

    def test_text_format(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_result = {"format": "PE"}

        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file), format="text")

        assert result.status == "success"

    def test_file_size_exceeds_max_allowed(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "large_test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("reversecore_mcp.tools.analysis.lief_tools.get_config") as mock_get_config:
                # Set max allowed file size to 50 bytes (smaller than the file)
                mock_get_config.return_value.lief_max_file_size = 50
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "FILE_TOO_LARGE"

    def test_file_size_headers_only_mode(self, tmp_path):
        """Files > 500MB (and <= lief_max_file_size) parse in headers_only mode without OOM."""
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        mock_path = MagicMock()
        mock_path.stat.return_value.st_size = 600 * 1024 * 1024  # 600MB
        mock_path.stat.return_value.st_mtime_ns = 12345
        mock_path.exists.return_value = True

        mock_result = {
            "format": "pe",
            "entry_point": "0x401000",
            "sections": [{"name": ".text", "virtual_address": "0x1000", "size": 4096}],
            "mitigations": {"nx": True, "pie": False},
        }
        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=mock_path,
        ):
            with patch("reversecore_mcp.tools.analysis.lief_tools.get_config") as mock_get_config:
                mock_get_config.return_value.lief_max_file_size = 1000 * 1024 * 1024
                with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                    result = parse_binary_with_lief(str(mock_path))

        assert result.status == "success"
        assert result.data["_diagnostics"]["parse_mode"] == "headers_only (file > 500MB)"
        assert result.metadata["parse_mode"] == "headers_only (file > 500MB)"
        assert result.metadata["partial_analysis"] is True
        assert result.metadata["file_size_mb"] == 600.0
        assert "_warning" in result.data
        assert "headers only" in result.data["_warning"]

    def test_large_file_boundaries_and_rejection(self, tmp_path):
        """Test boundaries across <=100MB, 100-500MB, 500MB-max, and >lief_max_file_size rejection."""
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        mock_path = MagicMock()
        mock_path.stat.return_value.st_mtime_ns = 99999
        mock_path.exists.return_value = True

        mock_result = {"format": "pe", "entry_point": "0x1000"}
        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=mock_path,
        ):
            with patch("reversecore_mcp.tools.analysis.lief_tools.get_config") as mock_get_config:
                # 1. Configured limit: 800MB
                mock_get_config.return_value.lief_max_file_size = 800 * 1024 * 1024

                # File at 900MB exceeds configured limit -> rejected
                mock_path.stat.return_value.st_size = 900 * 1024 * 1024
                res_rejected = parse_binary_with_lief(str(mock_path))
                assert res_rejected.status == "error"
                assert res_rejected.error_code == "FILE_TOO_LARGE"

                # File at 501MB within configured limit -> headers_only mode
                with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                    mock_path.stat.return_value.st_size = 501 * 1024 * 1024
                    res_headers = parse_binary_with_lief(str(mock_path))
                    assert res_headers.status == "success"
                    assert "headers_only" in res_headers.metadata["parse_mode"]
                    assert res_headers.metadata["partial_analysis"] is True

                # File at 50MB (<= 100MB) -> full_detail mode
                with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                    mock_path.stat.return_value.st_size = 50 * 1024 * 1024
                    res_full = parse_binary_with_lief(str(mock_path))
                    assert res_full.status == "success"
                    assert res_full.metadata["parse_mode"] == "full_detail"
                    assert res_full.metadata["partial_analysis"] is False

    def test_file_size_warning_truncated(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        mock_path = MagicMock()
        mock_path.stat.return_value.st_size = 120 * 1024 * 1024  # 120MB (exceeds warning threshold)
        mock_path.exists.return_value = True

        mock_result = {"format": "PE"}
        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=mock_path,
        ):
            with patch("reversecore_mcp.tools.analysis.lief_tools.get_config") as mock_get_config:
                mock_get_config.return_value.lief_max_file_size = 1000 * 1024 * 1024
                with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                    result = parse_binary_with_lief(str(mock_path))

        assert result.status == "success"
        # We need to make sure the warning is in result.data
        assert "_warning" in result.data
        assert "truncated" in result.data["_warning"]

    def test_concurrent_futures_timeout(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError("Timeout")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "TIMEOUT"

    def test_concurrent_futures_broken_pool(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = BrokenProcessPool("Broken pool")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "CRASH_DETECTED"

    def test_concurrent_futures_general_exception(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("Other error")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor.__enter__ = MagicMock(return_value=mock_executor)
        mock_executor.__exit__ = MagicMock(return_value=False)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "LIEF_ERROR"

    def test_executor_setup_failure(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            # ProcessPoolExecutor raises error on initialization
            with patch(
                "concurrent.futures.ProcessPoolExecutor",
                side_effect=RuntimeError("executor init failed"),
            ):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "EXECUTION_ERROR"

    def test_timeout_terminates_processes(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError("Timeout")

        mock_process = MagicMock()
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor._processes = {1234: mock_process}

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "TIMEOUT"
        mock_process.terminate.assert_called_once()
        mock_process.join.assert_called_once_with(timeout=1.0)
        mock_executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_shutdown_on_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import (
            _cleanup_lief_pool,
            _reset_lief_pool,
            parse_binary_with_lief,
        )

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_result = {"format": "PE"}
        mock_future = MagicMock()
        mock_future.result.return_value = mock_result
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result1 = parse_binary_with_lief(str(test_file))
                # Second call should hit the cache without invoking submit again
                result2 = parse_binary_with_lief(str(test_file))

        assert result1.status == "success"
        assert result2.status == "success"
        assert mock_executor.submit.call_count == 1

        # Test clean shutdown
        _cleanup_lief_pool()
        _reset_lief_pool()

    def test_shutdown_on_broken_pool(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = BrokenProcessPool("Broken pool")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "CRASH_DETECTED"
        mock_executor.shutdown.assert_called_once_with(wait=False)

    def test_shutdown_on_other_exceptions(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("Other error")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "LIEF_ERROR"
        mock_executor.shutdown.assert_called_once_with(wait=False)


class TestRunLiefInProcess:
    """Tests for _run_lief_in_process."""

    def test_run_lief_in_process_success_elf(self):
        from reversecore_mcp.tools.analysis.lief_tools import _run_lief_in_process

        binary = MagicMock(spec=lief.ELF.Binary)
        binary.format = MagicMock()
        binary.format.__str__.return_value = "elf"
        binary.entrypoint = 0x400000

        # Section mock
        sec = MagicMock()
        sec.name = ".text"
        sec.virtual_address = 0x401000
        sec.size = 1024
        binary.sections = [sec]

        # Mitigations mock (ELF)
        binary.has_nx = True
        binary.is_pie = False
        binary.imported_symbols = []
        binary.segments = []
        binary.has.return_value = False

        with patch("lief.parse", return_value=binary):
            res = _run_lief_in_process(
                "dummy_path.elf", max_imports=10, max_exports=10, max_sections=1
            )

        assert res["format"] == "elf"
        assert res["entry_point"] == "0x400000"
        assert len(res["sections"]) == 1
        assert res["sections"][0]["name"] == ".text"
        assert res["mitigations"]["nx"] is True

    def test_run_lief_in_process_lief_parse_exception(self):
        from reversecore_mcp.tools.analysis.lief_tools import _run_lief_in_process

        with patch("lief.parse", side_effect=Exception("Corrupt file")):
            with pytest.raises(RuntimeError) as exc_info:
                _run_lief_in_process(
                    "dummy_path.exe", max_imports=10, max_exports=10, max_sections=10
                )

        assert "LIEF parse failed" in str(exc_info.value)

    def test_run_lief_in_process_unsupported_format(self):
        from reversecore_mcp.tools.analysis.lief_tools import _run_lief_in_process

        with patch("lief.parse", return_value=None):
            with pytest.raises(ValueError) as exc_info:
                _run_lief_in_process(
                    "dummy_path.exe", max_imports=10, max_exports=10, max_sections=10
                )

        assert "Unsupported binary format" in str(exc_info.value)


class TestLiefToolsExtraCoverage:
    """Extra tests to cover exception handlers and achieve 100% statement coverage."""

    def test_extract_mitigations_pe_load_config_v1_exception(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_mitigations

        # Mock lief.PE
        class BadPE:
            class Binary:
                pass

            class DLL_CHARACTERISTICS:
                pass

            LoadConfiguration = "exists"

            def __setattr__(self, name, value):
                if name == "LoadConfigurationV1":
                    raise RuntimeError("Cannot assign LoadConfigurationV1")
                self.__dict__[name] = value

        mock_lief_pe = BadPE()
        binary = MagicMock(spec=lief.PE.Binary)
        binary.optional_header.dll_characteristics = 0

        # Patch sys.modules['lief']
        mock_lief = MagicMock()
        mock_lief.PE = mock_lief_pe
        mock_lief.ELF = lief.ELF  # keep ELF

        with patch.dict("sys.modules", {"lief": mock_lief}):
            mitigations = _extract_mitigations(binary)

        # Should fall back gracefully and succeed
        assert mitigations is not None

    def test_concurrent_futures_timeout_terminate_fails(self, tmp_path):
        from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError("Timeout")

        # mock a process whose terminate() raises Exception
        mock_process = MagicMock()
        mock_process.terminate.side_effect = Exception("Failed to terminate process")
        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future
        mock_executor._processes = {1234: mock_process}

        with patch(
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path",
            return_value=test_file,
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file))

        assert result.status == "error"
        assert result.error_code == "TIMEOUT"
        mock_process.terminate.assert_called_once()
        mock_executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)


class TestLIEFResultCache:
    """Unit tests for _LIEFResultCache."""

    def test_cache_set_and_get(self):
        from reversecore_mcp.tools.analysis.lief_tools import _LIEFResultCache

        cache = _LIEFResultCache(maxsize=2)
        key1 = ("/path/to/bin1", 1000, 500)
        data1 = {"format": "ELF", "sections": []}

        assert cache.get(key1) is None
        cache.set(key1, data1)
        assert cache.get(key1) == data1
        assert len(cache) == 1

    def test_cache_lru_eviction(self):
        from reversecore_mcp.tools.analysis.lief_tools import _LIEFResultCache

        cache = _LIEFResultCache(maxsize=2)
        k1 = ("/bin1", 1, 10)
        k2 = ("/bin2", 2, 20)
        k3 = ("/bin3", 3, 30)

        cache.set(k1, {"id": 1})
        cache.set(k2, {"id": 2})

        # Access k1 to make k2 the least recently used
        assert cache.get(k1) == {"id": 1}

        # Add k3, which should evict k2
        cache.set(k3, {"id": 3})

        assert cache.get(k1) == {"id": 1}
        assert cache.get(k2) is None
        assert cache.get(k3) == {"id": 3}
        assert len(cache) == 2

    def test_cache_clear(self):
        from reversecore_mcp.tools.analysis.lief_tools import _LIEFResultCache

        cache = _LIEFResultCache(maxsize=5)
        cache.set(("/bin1", 1, 10), {"data": "test"})
        assert len(cache) == 1
        cache.clear()
        assert len(cache) == 0
        assert cache.get(("/bin1", 1, 10)) is None
