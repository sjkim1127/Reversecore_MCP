"""Tests for reversecore_mcp.tools.analysis.lief_tools."""

from unittest.mock import MagicMock, patch


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


class TestExtractSymbols:
    """Tests for _extract_symbols."""

    def test_no_imports_exports(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_symbols

        binary = MagicMock()
        binary.imported_functions = []
        binary.exported_functions = []
        result = _extract_symbols(binary)
        assert "imported_functions" not in result
        assert "exported_functions" not in result

    def test_with_imports(self):
        from reversecore_mcp.tools.analysis.lief_tools import _extract_symbols

        binary = MagicMock()
        binary.imported_functions = ["printf", "malloc"]
        binary.exported_functions = []
        result = _extract_symbols(binary)
        assert len(result["imported_functions"]) == 2
        assert "printf" in result["imported_functions"]


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
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path", return_value=test_file
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
            "reversecore_mcp.tools.analysis.lief_tools.validate_file_path", return_value=test_file
        ):
            with patch("concurrent.futures.ProcessPoolExecutor", return_value=mock_executor):
                result = parse_binary_with_lief(str(test_file), format="text")

        assert result.status == "success"
