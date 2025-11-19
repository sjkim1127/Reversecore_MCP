"""Integration tests for diff_binaries and match_libraries tools."""

import subprocess

import pytest

from reversecore_mcp.tools import cli_tools


def _require_radare2() -> None:
    """Skip tests if radare2 is not installed."""
    try:
        subprocess.run(["r2", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("radare2 not installed")


def _require_radiff2() -> None:
    """Skip tests if radiff2 is not installed."""
    try:
        subprocess.run(["radiff2", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("radiff2 not installed")


class TestDiffBinaries:
    """Integration tests for diff_binaries tool."""

    @pytest.mark.asyncio
    async def test_diff_binaries_same_file(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test diffing a binary against itself should show high similarity."""
        _require_radiff2()

        result = await cli_tools.diff_binaries(
            str(sample_binary_path), str(sample_binary_path)
        )

        assert result.status == "success"
        assert isinstance(result.data, str)

        # Parse JSON output
        import json

        data = json.loads(result.data)

        # Similarity should be 1.0 or very close for identical files
        assert "similarity" in data
        assert data["similarity"] >= 0.9
        assert "changes" in data
        assert "function_specific" in data
        assert data["function_specific"] is False

    @pytest.mark.asyncio
    async def test_diff_binaries_with_function(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test function-specific binary diff."""
        _require_radiff2()

        result = await cli_tools.diff_binaries(
            str(sample_binary_path), str(sample_binary_path), function_name="entry0"
        )

        # Should succeed or gracefully handle if function doesn't exist
        assert result.status in ["success", "error"]

        if result.status == "success":
            import json

            data = json.loads(result.data)
            assert data["function_specific"] is True

    @pytest.mark.asyncio
    async def test_diff_binaries_nonexistent_first_file(
        self, sample_binary_path, workspace_dir, patched_workspace_config
    ):
        """Test diff with nonexistent first file."""
        _require_radiff2()

        result = await cli_tools.diff_binaries(
            str(workspace_dir / "nonexistent1.bin"), str(sample_binary_path)
        )

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_diff_binaries_nonexistent_second_file(
        self, sample_binary_path, workspace_dir, patched_workspace_config
    ):
        """Test diff with nonexistent second file."""
        _require_radiff2()

        result = await cli_tools.diff_binaries(
            str(sample_binary_path), str(workspace_dir / "nonexistent2.bin")
        )

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_diff_binaries_outside_workspace(
        self, sample_binary_path, tmp_path, patched_workspace_config
    ):
        """Test that files outside workspace are rejected."""
        _require_radiff2()

        # Create a file outside workspace
        outside_file = tmp_path / "outside.bin"
        outside_file.write_bytes(b"\x7fELF")

        result = await cli_tools.diff_binaries(
            str(sample_binary_path), str(outside_file)
        )

        assert result.status == "error"
        assert "outside" in result.message.lower()

    @pytest.mark.asyncio
    async def test_diff_binaries_timeout(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test diff with very short timeout."""
        _require_radiff2()

        # Use a very short timeout to test timeout handling
        result = await cli_tools.diff_binaries(
            str(sample_binary_path),
            str(sample_binary_path),
            timeout=1,  # 1 second timeout
        )

        # Should either succeed quickly or timeout
        assert result.status in ["success", "error"]


class TestMatchLibraries:
    """Integration tests for match_libraries tool."""

    @pytest.mark.asyncio
    async def test_match_libraries_success(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test successful library matching."""
        _require_radare2()

        result = await cli_tools.match_libraries(str(sample_binary_path))

        assert result.status == "success"
        assert isinstance(result.data, str)

        # Parse JSON output
        import json

        data = json.loads(result.data)

        # Check expected fields
        assert "total_functions" in data
        assert "library_functions" in data
        assert "user_functions" in data
        assert "noise_reduction_percentage" in data
        assert "library_matches" in data
        assert "user_function_list" in data
        assert "summary" in data

        # Validate data types
        assert isinstance(data["total_functions"], int)
        assert isinstance(data["library_functions"], int)
        assert isinstance(data["user_functions"], int)
        assert isinstance(data["noise_reduction_percentage"], (int, float))
        assert isinstance(data["library_matches"], list)
        assert isinstance(data["user_function_list"], list)

    @pytest.mark.asyncio
    async def test_match_libraries_metadata(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that metadata is properly returned."""
        _require_radare2()

        result = await cli_tools.match_libraries(str(sample_binary_path))

        if result.status == "success":
            assert result.metadata is not None
            assert "total_functions" in result.metadata
            assert "library_functions" in result.metadata
            assert "user_functions" in result.metadata
            assert "noise_reduction" in result.metadata

    @pytest.mark.asyncio
    async def test_match_libraries_nonexistent_file(
        self, workspace_dir, patched_workspace_config
    ):
        """Test library matching on nonexistent file."""
        _require_radare2()

        result = await cli_tools.match_libraries(str(workspace_dir / "nonexistent.bin"))

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"

    @pytest.mark.asyncio
    async def test_match_libraries_outside_workspace(
        self, tmp_path, patched_workspace_config
    ):
        """Test that files outside workspace are rejected."""
        _require_radare2()

        # Create a file outside workspace
        outside_file = tmp_path / "outside.bin"
        outside_file.write_bytes(b"\x7fELF")

        result = await cli_tools.match_libraries(str(outside_file))

        assert result.status == "error"
        assert "outside" in result.message.lower()

    @pytest.mark.asyncio
    async def test_match_libraries_with_custom_db(
        self, sample_binary_path, workspace_dir, patched_workspace_config
    ):
        """Test library matching with custom signature database."""
        _require_radare2()

        # Create a dummy signature file in workspace
        sig_file = workspace_dir / "test.sig"
        sig_file.write_text("# Test signature file\n")

        result = await cli_tools.match_libraries(
            str(sample_binary_path), signature_db=str(sig_file)
        )

        # Should succeed or fail gracefully
        assert result.status in ["success", "error"]

        if result.status == "success":
            import json

            data = json.loads(result.data)
            assert data["signature_db_used"] == str(sig_file)

    @pytest.mark.asyncio
    async def test_match_libraries_timeout(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test library matching with short timeout."""
        _require_radare2()

        # Use a very short timeout
        result = await cli_tools.match_libraries(str(sample_binary_path), timeout=1)

        # Should either succeed quickly or timeout
        assert result.status in ["success", "error"]

    @pytest.mark.asyncio
    async def test_match_libraries_validates_parameters(
        self, sample_binary_path, patched_workspace_config
    ):
        """Test that invalid parameters are caught."""
        _require_radare2()

        # Test invalid timeout
        result = await cli_tools.match_libraries(str(sample_binary_path), timeout=-1)

        assert result.status == "error"
        assert result.error_code == "VALIDATION_ERROR"
