"""Tests for reversecore_mcp.tools.common.file_operations."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestRunFile:
    """Tests for run_file function."""

    @pytest.mark.asyncio
    async def test_success(self, tmp_path):
        """Run file command on a valid file."""
        from reversecore_mcp.tools.common.file_operations import run_file

        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        with patch(
            "reversecore_mcp.tools.common.file_operations.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.common.file_operations.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("ASCII text", 11)
                result = await run_file(str(test_file))

        assert result.status == "success"
        assert "ASCII text" in str(result.data)

    @pytest.mark.asyncio
    async def test_executable_detection(self, tmp_path):
        """Detect executable file type."""
        from reversecore_mcp.tools.common.file_operations import run_file

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.common.file_operations.validate_file_path",
            return_value=test_file,
        ):
            with patch(
                "reversecore_mcp.tools.common.file_operations.execute_subprocess_async",
                new_callable=AsyncMock,
            ) as mock_exec:
                mock_exec.return_value = ("PE32 executable", 102)
                result = await run_file(str(test_file))

        assert result.status == "success"


class TestCopyToWorkspace:
    """Tests for copy_to_workspace function."""

    def test_success(self, tmp_path):
        """Copy a file to workspace."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        source = tmp_path / "source.txt"
        source.write_text("hello")

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = copy_to_workspace(str(source))

        assert result.status == "success"
        assert (workspace / "source.txt").exists()

    def test_destination_name(self, tmp_path):
        """Copy with custom destination name."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        source = tmp_path / "source.txt"
        source.write_text("hello")

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = copy_to_workspace(str(source), destination_name="dest.txt")

        assert result.status == "success"
        assert (workspace / "dest.txt").exists()

    def test_destination_nested(self, tmp_path):
        """Copy to a nested destination path."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        source = tmp_path / "source.txt"
        source.write_text("hello")

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = copy_to_workspace(str(source), destination_name="session_A/dest.txt")

        assert result.status == "success"
        assert (workspace / "session_A" / "dest.txt").exists()

    def test_destination_traversal_blocked(self, tmp_path):
        """Copy to a traversal path should be blocked."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        source = tmp_path / "source.txt"
        source.write_text("hello")

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = copy_to_workspace(str(source), destination_name="../outside.txt")

        assert result.status == "error"
        assert "traverses outside workspace" in result.message

    def test_nonexistent_source(self):
        """Raise ValidationError for nonexistent source."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        result = copy_to_workspace("/nonexistent/file.txt")
        assert result.status == "error"

    def test_source_is_directory(self, tmp_path):
        """Raise ValidationError when source is a directory."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        result = copy_to_workspace(str(tmp_path))
        assert result.status == "error"

    def test_file_exists_error(self, tmp_path):
        """Raise ValidationError when destination already exists."""
        from reversecore_mcp.tools.common.file_operations import copy_to_workspace

        source = tmp_path / "source.txt"
        source.write_text("hello")

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "source.txt").write_text("existing")

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = copy_to_workspace(str(source))

        assert result.status == "error"


class TestListWorkspace:
    """Tests for list_workspace function."""

    def test_empty_workspace(self, tmp_path):
        """List empty workspace."""
        from reversecore_mcp.tools.common.file_operations import list_workspace

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = list_workspace()

        assert result.status == "success"

    def test_with_files(self, tmp_path):
        """List workspace with files."""
        from reversecore_mcp.tools.common.file_operations import list_workspace

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "test.exe").write_bytes(b"MZ")
        (workspace / "test.bin").write_bytes(b"\x00\x01")

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = list_workspace()

        assert result.status == "success"


class TestScanWorkspace:
    """Tests for scan_workspace."""

    @pytest.mark.asyncio
    async def test_empty(self, tmp_path):
        from reversecore_mcp.tools.common.file_operations import scan_workspace

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = await scan_workspace()

        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_with_files(self, tmp_path):
        from reversecore_mcp.tools.common.file_operations import scan_workspace

        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "test.exe").write_bytes(b"MZ" + b"\x00" * 100)

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            with patch(
                "reversecore_mcp.tools.common.file_operations.run_file", new_callable=AsyncMock
            ) as mock_run_file:
                mock_run_file.return_value.status = "success"
                mock_run_file.return_value.data = "PE32 executable"
                with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
                    mock_to_thread.return_value.status = "success"
                    mock_to_thread.return_value.data = '{"format": "PE"}'
                    result = await scan_workspace()

        assert result.status in ("success", "error")


class TestCreateDirectory:
    """Tests for create_directory function."""

    def test_success_relative(self, tmp_path):
        from reversecore_mcp.tools.common.file_operations import create_directory

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = create_directory("session_B/nested")

        assert result.status == "success"
        assert (workspace / "session_B" / "nested").is_dir()

    def test_success_absolute(self, tmp_path):
        from reversecore_mcp.tools.common.file_operations import create_directory

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = create_directory(str(workspace / "session_C"))

        assert result.status == "success"
        assert (workspace / "session_C").is_dir()

    def test_traversal_blocked(self, tmp_path):
        from reversecore_mcp.tools.common.file_operations import create_directory

        workspace = tmp_path / "workspace"
        workspace.mkdir()

        with patch("reversecore_mcp.tools.common.file_operations.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.workspace = workspace
            mock_get_config.return_value = mock_config
            result = create_directory("../../outside_dir")

        assert result.status == "error"
        assert "traverses outside workspace" in result.message
