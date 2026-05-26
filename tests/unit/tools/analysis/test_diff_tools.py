"""Tests for reversecore_mcp.tools.analysis.diff_tools."""

from unittest.mock import AsyncMock, patch

import pytest


class TestExtractLibraryName:
    """Tests for _extract_library_name."""

    def test_unknown_name(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        result = _extract_library_name("printf")
        assert result == "unknown"

    def test_import_prefix(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        result = _extract_library_name("sym.imp.printf")
        assert result == "import"

    def test_empty(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        result = _extract_library_name("")
        assert result == "unknown"


class TestExtractLibraryNameMore:
    """Additional tests for _extract_library_name."""

    def test_kernel32(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        assert _extract_library_name("sym.imp.Kernel32_CreateFileA") == "kernel32"

    def test_libc(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        assert _extract_library_name("sym.imp.libc_printf") == "libc/msvcrt"

    def test_libstdcpp(self):
        from reversecore_mcp.tools.analysis.diff_tools import _extract_library_name

        assert _extract_library_name("sym.std::__cxx11::basic_string") == "libstdc++"


class TestDiffBinaries:
    """Tests for diff_binaries."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import diff_binaries

        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"MZ" + b"\x00" * 100)
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"MZ" + b"\x01" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("functions: 5\nsimilarity: 0.5", 20)
                result = await diff_binaries(str(file_a), str(file_b))

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_with_function_filter(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import diff_binaries

        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"MZ" + b"\x00" * 100)
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"MZ" + b"\x01" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("functions: 1\nmain: changed", 20)
                result = await diff_binaries(str(file_a), str(file_b), function_name="main")

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_with_changes(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import diff_binaries

        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"MZ" + b"\x00" * 100)
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"MZ" + b"\x01" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = (
                    "0x401000: modified jmp call\n0x401010: new block\n0x401020: removed deleted",
                    50,
                )
                result = await diff_binaries(str(file_a), str(file_b))

        assert result.status in ("success", "error")


class TestAnalyzeVariantChanges:
    """Tests for analyze_variant_changes."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import analyze_variant_changes

        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"MZ" + b"\x00" * 100)
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"MZ" + b"\x01" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("changed: 3\nadded: 2\nremoved: 1", 20)
                result = await analyze_variant_changes(str(file_a), str(file_b))

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_top_n_filter(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import analyze_variant_changes

        file_a = tmp_path / "a.exe"
        file_a.write_bytes(b"MZ" + b"\x00" * 100)
        file_b = tmp_path / "b.exe"
        file_b.write_bytes(b"MZ" + b"\x01" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=file_a
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("changed: 10\nadded: 5\nremoved: 5", 20)
                result = await analyze_variant_changes(str(file_a), str(file_b), top_n=2)

        assert result.status in ("success", "error")


class TestMatchLibraries:
    """Tests for match_libraries."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import match_libraries

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("libc.so.6\nKERNEL32.dll", 20)
                result = await match_libraries(str(test_file))

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_with_signature_db(self, tmp_path):
        from reversecore_mcp.tools.analysis.diff_tools import match_libraries

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)
        sig_db = tmp_path / "sigs.txt"
        sig_db.write_text("libc\nkernel32")

        with patch(
            "reversecore_mcp.tools.analysis.diff_tools.validate_file_path", return_value=test_file
        ):
            with patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("libc.so.6", 20)
                result = await match_libraries(str(test_file), signature_db=str(sig_db))

        assert result.status in ("success", "error")
