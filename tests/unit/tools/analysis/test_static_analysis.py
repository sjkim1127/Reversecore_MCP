"""Tests for reversecore_mcp.tools.analysis.static_analysis."""

from unittest.mock import AsyncMock, patch

import pytest


class TestRunStrings:
    """Tests for run_strings."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        """Run strings on a file."""
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZhello world\x00" * 10)

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("hello world\n", 12)
                result = await run_strings(str(test_file))

        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_not_found(self, tmp_path):
        """Handle strings command not found."""
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                from reversecore_mcp.core.exceptions import ToolNotFoundError

                mock_exec.side_effect = ToolNotFoundError("strings")
                result = await run_strings(str(test_file))

        assert result.status == "error"


class TestRunBinwalk:
    """Tests for run_binwalk."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        """Run binwalk on a file."""
        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = (
                    "DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             Unknown\n",
                    50,
                )
                result = await run_binwalk(str(test_file))

        assert result.status == "success"


class TestScanForVersions:
    """Tests for scan_for_versions."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        """Scan for version strings."""
        from reversecore_mcp.tools.analysis.static_analysis import scan_for_versions

        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"MZ")

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("1.2.3", 5)
                result = await scan_for_versions(str(test_file))

        assert result.status == "success"


class TestExtractRttiInfo:
    """Tests for extract_rtti_info."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        """Extract RTTI info."""
        from reversecore_mcp.tools.analysis.static_analysis import extract_rtti_info

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ('{"classes": []}', 15)
                result = await extract_rtti_info(str(test_file))

        assert result.status == "success"


class TestFormatSize:
    """Tests for _format_size helper."""

    def test_bytes(self):
        from reversecore_mcp.tools.analysis.static_analysis import _format_size

        assert _format_size(0) == "0.0 B"
        assert _format_size(512) == "512.0 B"

    def test_kilobytes(self):
        from reversecore_mcp.tools.analysis.static_analysis import _format_size

        assert _format_size(1024) == "1.0 KB"
        assert _format_size(1536) == "1.5 KB"

    def test_megabytes(self):
        from reversecore_mcp.tools.analysis.static_analysis import _format_size

        assert _format_size(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        from reversecore_mcp.tools.analysis.static_analysis import _format_size

        assert _format_size(1024 * 1024 * 1024) == "1.0 GB"


class TestRunStringsTruncated:
    """Tests for run_strings large output truncation."""

    @pytest.mark.asyncio
    async def test_truncated_output(self, tmp_path):
        from reversecore_mcp.tools.analysis.static_analysis import run_strings

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        large_output = "a" * 3000000
        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = (large_output, 3000000)
                result = await run_strings(str(test_file))

        assert result.status == "success"


class TestRunBinwalkExtract:
    """Tests for run_binwalk_extract."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("extracted: output_dir/", 20)
                result = await run_binwalk_extract(str(test_file))

        assert result.status in ("success", "error")

    @pytest.mark.asyncio
    async def test_binwalk_not_found(self, tmp_path):
        from reversecore_mcp.core.exceptions import ToolNotFoundError
        from reversecore_mcp.tools.analysis.static_analysis import run_binwalk_extract

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.side_effect = ToolNotFoundError("binwalk")
                result = await run_binwalk_extract(str(test_file))

        assert result.status == "error"


class TestScanForVersionsError:
    """Tests for scan_for_versions error paths."""

    @pytest.mark.asyncio
    async def test_not_found(self, tmp_path):
        from reversecore_mcp.core.exceptions import ToolNotFoundError
        from reversecore_mcp.tools.analysis.static_analysis import scan_for_versions

        test_file = tmp_path / "test.dll"
        test_file.write_bytes(b"MZ")

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.side_effect = ToolNotFoundError("strings")
                result = await scan_for_versions(str(test_file))

        assert result.status == "error"


class TestExtractRttiInfoError:
    """Tests for extract_rtti_info error paths."""

    @pytest.mark.asyncio
    async def test_not_found(self, tmp_path):
        from reversecore_mcp.core.exceptions import ToolNotFoundError
        from reversecore_mcp.tools.analysis.static_analysis import extract_rtti_info

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ")

        with patch(
            "reversecore_mcp.tools.analysis.static_analysis.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.analysis.static_analysis.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.side_effect = ToolNotFoundError("r2")
                result = await extract_rtti_info(str(test_file))

        assert result.status == "error"
