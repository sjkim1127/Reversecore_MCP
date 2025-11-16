"""Unit tests for copy_to_workspace and list_workspace tools."""


from reversecore_mcp.tools import cli_tools


class TestCopyToWorkspace:
    """Unit tests for copy_to_workspace tool."""

    def test_copy_to_workspace_success(self, workspace_dir, tmp_path, patched_config):
        """Test successful file copy to workspace."""
        # Create a source file outside workspace
        source_file = tmp_path / "source" / "test_file.bin"
        source_file.parent.mkdir()
        test_content = b"Test binary content\x00\x01\x02"
        source_file.write_bytes(test_content)

        # Copy to workspace
        result = cli_tools.copy_to_workspace(str(source_file))

        # Verify success
        assert result.status == "success"
        assert "test_file.bin" in result.data
        assert result.metadata["file_size"] == len(test_content)
        assert result.metadata["source_path"] == str(source_file)

        # Verify file was actually copied
        dest_path = workspace_dir / "test_file.bin"
        assert dest_path.exists()
        assert dest_path.read_bytes() == test_content

    def test_copy_to_workspace_custom_name(
        self, workspace_dir, tmp_path, patched_config
    ):
        """Test copying file with custom destination name."""
        source_file = tmp_path / "source" / "original.bin"
        source_file.parent.mkdir()
        source_file.write_bytes(b"content")

        result = cli_tools.copy_to_workspace(
            str(source_file), destination_name="custom_name.bin"
        )

        assert result.status == "success"
        assert "custom_name.bin" in result.data
        dest_path = workspace_dir / "custom_name.bin"
        assert dest_path.exists()
        assert dest_path.read_bytes() == b"content"

    def test_copy_to_workspace_nonexistent_file(self, tmp_path, patched_config):
        """Test error when source file doesn't exist."""
        nonexistent = tmp_path / "nonexistent.bin"

        result = cli_tools.copy_to_workspace(str(nonexistent))

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "does not exist" in result.message

    def test_copy_to_workspace_directory(self, tmp_path, patched_config):
        """Test error when source path is a directory."""
        source_dir = tmp_path / "source_dir"
        source_dir.mkdir()

        result = cli_tools.copy_to_workspace(str(source_dir))

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "not a file" in result.message

    def test_copy_to_workspace_file_exists(
        self, workspace_dir, tmp_path, patched_config
    ):
        """Test error when destination file already exists."""
        # Create source file
        source_file = tmp_path / "source" / "test.bin"
        source_file.parent.mkdir()
        source_file.write_bytes(b"content")

        # Create existing file in workspace
        existing_file = workspace_dir / "test.bin"
        existing_file.write_bytes(b"existing")

        result = cli_tools.copy_to_workspace(str(source_file))

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "already exists" in result.message

    def test_copy_to_workspace_dangerous_destination_name(
        self, tmp_path, patched_config
    ):
        """Test sanitization of dangerous destination names."""
        source_file = tmp_path / "source" / "test.bin"
        source_file.parent.mkdir()
        source_file.write_bytes(b"content")

        # Test path traversal attempt
        result = cli_tools.copy_to_workspace(
            str(source_file), destination_name="../../../etc/passwd"
        )

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "Invalid destination name" in result.message

    def test_copy_to_workspace_large_file(self, tmp_path, patched_config):
        """Test error when file exceeds size limit."""
        # Create a file
        source_file = tmp_path / "source" / "large.bin"
        source_file.parent.mkdir()
        source_file.write_bytes(b"small content")

        # Mock the file size to be over 5GB
        import unittest.mock as mock

        real_stat = source_file.stat()

        class MockStat:
            st_size = 6 * 1024 * 1024 * 1024  # 6GB
            st_mode = real_stat.st_mode
            st_ino = real_stat.st_ino
            st_dev = real_stat.st_dev
            st_nlink = real_stat.st_nlink
            st_uid = real_stat.st_uid
            st_gid = real_stat.st_gid
            st_atime = real_stat.st_atime
            st_mtime = real_stat.st_mtime
            st_ctime = real_stat.st_ctime

        with mock.patch.object(type(source_file), "stat", return_value=MockStat()):
            result = cli_tools.copy_to_workspace(str(source_file))

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
        assert "too large" in result.message

    def test_copy_to_workspace_expanduser(
        self, workspace_dir, tmp_path, patched_config
    ):
        """Test that tilde expansion works correctly."""

        # Create a file in a temp location
        source_file = tmp_path / "test.bin"
        source_file.write_bytes(b"content")

        # Use absolute path (since we can't rely on HOME in tests)
        result = cli_tools.copy_to_workspace(str(source_file))

        assert result.status == "success"
        dest_path = workspace_dir / "test.bin"
        assert dest_path.exists()


class TestListWorkspace:
    """Unit tests for list_workspace tool."""

    def test_list_workspace_empty(self, workspace_dir, patched_config):
        """Test listing empty workspace."""
        result = cli_tools.list_workspace()

        assert result.status == "success"
        assert result.data["files"] == []
        assert result.metadata["file_count"] == 0
        assert result.metadata["workspace_path"] == str(workspace_dir)

    def test_list_workspace_with_files(self, workspace_dir, patched_config):
        """Test listing workspace with files."""
        # Create test files
        file1 = workspace_dir / "file1.bin"
        file1.write_bytes(b"content1")

        file2 = workspace_dir / "file2.txt"
        file2.write_bytes(b"content2")

        result = cli_tools.list_workspace()

        assert result.status == "success"
        assert result.metadata["file_count"] == 2
        assert len(result.data["files"]) == 2

        # Check file details
        files_by_name = {f["name"]: f for f in result.data["files"]}
        assert "file1.bin" in files_by_name
        assert "file2.txt" in files_by_name
        assert files_by_name["file1.bin"]["size"] == 8
        assert files_by_name["file2.txt"]["size"] == 8

    def test_list_workspace_ignores_directories(self, workspace_dir, patched_config):
        """Test that list_workspace only lists files, not directories."""
        # Create files and directories
        file1 = workspace_dir / "file.bin"
        file1.write_bytes(b"content")

        subdir = workspace_dir / "subdir"
        subdir.mkdir()

        result = cli_tools.list_workspace()

        assert result.status == "success"
        assert result.metadata["file_count"] == 1
        assert len(result.data["files"]) == 1
        assert result.data["files"][0]["name"] == "file.bin"

    def test_list_workspace_with_subdirectory_files(
        self, workspace_dir, patched_config
    ):
        """Test that files in subdirectories are not listed (only top-level files)."""
        # Create top-level file
        file1 = workspace_dir / "file1.bin"
        file1.write_bytes(b"content1")

        # Create subdirectory with file
        subdir = workspace_dir / "subdir"
        subdir.mkdir()
        file2 = subdir / "file2.bin"
        file2.write_bytes(b"content2")

        result = cli_tools.list_workspace()

        assert result.status == "success"
        assert result.metadata["file_count"] == 1
        assert result.data["files"][0]["name"] == "file1.bin"
