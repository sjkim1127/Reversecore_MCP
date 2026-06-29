"""Unit tests for disk forensics tools (disk.py).

Tests cover happy path with mocked Sleuth Kit subprocess calls
and edge cases: missing binary, non-existent image, unsupported filesystem.
"""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.tools.forensics.disk import (
    disk_analyze_mft,
    disk_hash_verify,
    disk_list_files,
    disk_list_partition,
    disk_recover_deleted,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_image(workspace_dir, patched_workspace_config):
    """Create a fake disk image file inside the allowed workspace."""
    img = workspace_dir / "disk.img"
    img.write_bytes(b"\x00" * 4096)
    return str(img)


@pytest.fixture()
def mock_tsk_available():
    """Patch _check_tsk_available to return True."""
    with patch("reversecore_mcp.tools.forensics.disk._check_tsk_available", return_value=True):
        yield


@pytest.fixture()
def mock_tsk_unavailable():
    """Patch _check_tsk_available to return False."""
    with patch("reversecore_mcp.tools.forensics.disk._check_tsk_available", return_value=False):
        yield


# ── disk_list_partition ────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_partition_success(tmp_image, mock_tsk_available):
    """Happy path: mmls parses partition table."""
    mmls_output = (
        "DOS Partition Table\n"
        "Offset Sector: 0\n"
        "Units are in 512-byte sectors\n"
        "\n"
        "     Slot      Start        End          Length       Description\n"
        "000: Meta 0000000000 0000000000 0000000001 Primary Table (#0)\n"
        "001: ---  0000000001 0000002047 0000002047 Unallocated\n"
        "002: 000  0000002048 0020971519 0020969472 Linux (0x83)\n"
    )

    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=(mmls_output, "", 0),
    ):
        result = await disk_list_partition(tmp_image)

    assert result.status == "success"
    assert "partitions" in result.data
    assert result.data["partition_count"] >= 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_partition_no_tsk(tmp_image, mock_tsk_unavailable):
    """Edge case: Sleuth Kit not installed."""
    result = await disk_list_partition(tmp_image)
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_partition_invalid_image():
    """Edge case: Image file does not exist."""
    result = await disk_list_partition("/nonexistent/disk.img")
    assert result.status == "error"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_partition_tsk_error(tmp_image, mock_tsk_available):
    """Edge case: mmls returns non-zero with no output."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("", "Invalid image format", 1),
    ):
        result = await disk_list_partition(tmp_image)

    assert result.status == "error"
    assert result.error_code == "TSK_ERROR"


# ── disk_list_files ────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_files_success(tmp_image, mock_tsk_available):
    """Happy path: fls lists live and deleted files."""
    fls_output = (
        "r/r 10:    passwd\nr/r 11:    shadow\n* r/r 12:   deleted_secret.txt\nd/d 13:    home\n"
    )

    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=(fls_output, "", 0),
    ):
        result = await disk_list_files(tmp_image, include_deleted=True)

    assert result.status == "success"
    assert result.data["total_count"] == 4
    assert result.data["deleted_count"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_files_no_tsk(tmp_image, mock_tsk_unavailable):
    """Edge case: Sleuth Kit not installed."""
    result = await disk_list_files(tmp_image)
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_files_tsk_error(tmp_image, mock_tsk_available):
    """Edge case: fls returns error (wrong filesystem)."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("", "Cannot determine filesystem type", 1),
    ):
        result = await disk_list_files(tmp_image)

    assert result.status == "error"
    assert result.error_code == "TSK_ERROR"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_files_empty(tmp_image, mock_tsk_available):
    """Edge case: Empty filesystem returns 0 files."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("", "", 0),
    ):
        result = await disk_list_files(tmp_image)

    assert result.status == "success"
    assert result.data["total_count"] == 0


# ── disk_recover_deleted ───────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_success(tmp_image, mock_tsk_available, workspace_dir):
    """Happy path: icat recovers deleted file content."""
    recovered_content = b"This is recovered content from deleted file"
    mock_result = MagicMock()
    mock_result.stdout = recovered_content
    mock_result.stderr = b""
    mock_result.returncode = 0

    output_path = str(workspace_dir / "recovered.txt")

    with patch("subprocess.run", return_value=mock_result):
        result = await disk_recover_deleted(tmp_image, inode="42", output_path=output_path)

    assert result.status == "success"
    assert result.data["recovered_bytes"] == len(recovered_content)
    assert result.data["sha256"] == hashlib.sha256(recovered_content).hexdigest()
    assert Path(output_path).exists()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_no_tsk(tmp_image, mock_tsk_unavailable, workspace_dir):
    """Edge case: Sleuth Kit not installed."""
    result = await disk_recover_deleted(tmp_image, "42", str(workspace_dir / "out.bin"))
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_icat_fails(tmp_image, mock_tsk_available, workspace_dir):
    """Edge case: icat returns failure (inode overwritten)."""
    mock_result = MagicMock()
    mock_result.stdout = b""
    mock_result.stderr = b"inode 42 not found"
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        result = await disk_recover_deleted(tmp_image, "42", str(workspace_dir / "out.bin"))

    assert result.status == "error"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_empty_inode(tmp_image, mock_tsk_available, workspace_dir):
    """Edge case: icat returns empty output (fully overwritten blocks)."""
    mock_result = MagicMock()
    mock_result.stdout = b""
    mock_result.stderr = b""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = await disk_recover_deleted(tmp_image, "42", str(workspace_dir / "out_empty.bin"))

    assert result.status == "error"
    assert result.error_code == "EMPTY_INODE"


# ── disk_analyze_mft ───────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_analyze_mft_success(tmp_image, mock_tsk_available):
    """Happy path: MFT analysis returns file entries."""
    mft_output = (
        "0|/Windows/System32/cmd.exe|100|-rwxr-xr-x|0|0|348160|1620000000|1620000100|1620000200|1620000300\n"
        "0|/Users/victim/malware.exe|200|-rwxr-xr-x|0|0|102400|1620001000|1620001100|1620001200|1620001300\n"
    )

    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=(mft_output, "", 0),
    ):
        result = await disk_analyze_mft(tmp_image)

    assert result.status == "success"
    assert result.data["entry_count"] == 2
    assert result.data["mft_entries"][0]["path"] == "/Windows/System32/cmd.exe"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_analyze_mft_no_tsk(tmp_image, mock_tsk_unavailable):
    """Edge case: Sleuth Kit not installed."""
    result = await disk_analyze_mft(tmp_image)
    assert result.status == "error"
    assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_analyze_mft_non_ntfs(tmp_image, mock_tsk_available):
    """Edge case: Non-NTFS filesystem fails MFT analysis."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("", "Not an NTFS filesystem", 1),
    ):
        result = await disk_analyze_mft(tmp_image)

    assert result.status == "error"
    assert result.error_code == "TSK_ERROR"


# ── disk_hash_verify ───────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_hash_verify_match(workspace_dir, patched_workspace_config):
    """Happy path: computed hash matches expected hash."""
    img = workspace_dir / "hash_match.img"
    img.write_bytes(b"test content for hashing")
    expected = hashlib.sha256(b"test content for hashing").hexdigest()

    result = await disk_hash_verify(str(img), expected_hash=expected)
    assert result.status == "success"
    assert result.data["verified"] is True
    assert result.data["status"] == "MATCH"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_hash_verify_mismatch(workspace_dir, patched_workspace_config):
    """Edge case: computed hash does not match expected (tampered image)."""
    img = workspace_dir / "hash_mismatch.img"
    img.write_bytes(b"tampered content")

    result = await disk_hash_verify(str(img), expected_hash="deadbeef" * 8)
    assert result.status == "success"
    assert result.data["verified"] is False
    assert result.data["status"] == "MISMATCH"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_hash_verify_no_expected(workspace_dir, patched_workspace_config):
    """Happy path: compute hash without expected value."""
    img = workspace_dir / "hash_noexpected.img"
    img.write_bytes(b"any content")

    result = await disk_hash_verify(str(img))
    assert result.status == "success"
    assert result.data["verified"] is True
    assert len(result.data["computed_hash"]) == 64  # SHA256


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_hash_verify_invalid_algorithm(workspace_dir, patched_workspace_config):
    """Edge case: unsupported hash algorithm is rejected."""
    img = workspace_dir / "hash_algo.img"
    img.write_bytes(b"content")

    result = await disk_hash_verify(str(img), algorithm="blake2b")
    assert result.status == "error"
    assert result.error_code == "INVALID_ALGORITHM"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_hash_verify_md5(workspace_dir, patched_workspace_config):
    """Happy path: MD5 hash computation."""
    img = workspace_dir / "hash_md5.img"
    img.write_bytes(b"md5 test")
    expected = hashlib.md5(b"md5 test").hexdigest()  # noqa: S324

    result = await disk_hash_verify(str(img), expected_hash=expected, algorithm="md5")
    assert result.status == "success"
    assert result.data["verified"] is True


@pytest.mark.unit
def test_disk_check_tsk_available_real():
    """Test _check_tsk_available returns True on success and False on missing binary."""
    from reversecore_mcp.tools.forensics.disk import _check_tsk_available

    with patch("shutil.which", return_value="/usr/bin/fls"):
        assert _check_tsk_available() is True

    with patch("shutil.which", return_value=None):
        assert _check_tsk_available() is False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_run_tsk_real():
    """Test _run_tsk directly runs subprocess and returns output."""
    from reversecore_mcp.tools.forensics.disk import _run_tsk

    mock_res = MagicMock()
    mock_res.stdout = "out"
    mock_res.stderr = "err"
    mock_res.returncode = 0
    with patch("subprocess.run", return_value=mock_res):
        stdout, stderr, rc = await _run_tsk(["fls"])
        assert stdout == "out"
        assert stderr == "err"
        assert rc == 0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_run_tsk_uncovered():
    """Test _run_tsk with empty command or missing executable."""
    from reversecore_mcp.tools.forensics.disk import _run_tsk

    # 1. empty cmd
    out, err, code = await _run_tsk([])
    assert code == -1
    assert "Empty command" in err

    # 2. missing exe
    with patch("shutil.which", return_value=None):
        out, err, code = await _run_tsk(["fls"])
        assert code == -1
        assert "not found in PATH" in err


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_icat_missing(tmp_image, workspace_dir):
    """Test disk_recover_deleted when icat executable is missing."""
    from reversecore_mcp.tools.forensics.disk import disk_recover_deleted

    out_file = str(workspace_dir / "recovered.bin")
    with patch("shutil.which", return_value=None):
        result = await disk_recover_deleted(tmp_image, "123", out_file)
        assert result.status == "error"
        assert result.error_code == "DEPENDENCY_MISSING"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_list_files_options(tmp_image, mock_tsk_available):
    """Happy path: disk_list_files with offset, recursive, and custom directory."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("d/d 42:\tsubdir", "", 0),
    ) as mock_run:
        result = await disk_list_files(tmp_image, offset=2048, recursive=True, directory="/subdir")
        # Verify custom args are passed to cmd
        called_args = mock_run.call_args[0][0]
        assert "-o" in called_args
        assert "2048" in called_args
        assert "-r" in called_args
        assert "/subdir" in called_args

    assert result.status == "success"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_recover_deleted_offset(tmp_image, mock_tsk_available, workspace_dir):
    """Happy path: disk_recover_deleted with offset parameter."""
    mock_result = MagicMock()
    mock_result.stdout = b"recovered content"
    mock_result.stderr = b""
    mock_result.returncode = 0

    output = str(workspace_dir / "recovered_offset.bin")
    with patch("subprocess.run", return_value=mock_result) as mock_sub:
        result = await disk_recover_deleted(tmp_image, "123", output, offset=2048)
        called_args = mock_sub.call_args[0][0]
        assert "-o" in called_args
        assert "2048" in called_args

    assert result.status == "success"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_analyze_mft_offset(tmp_image, mock_tsk_available):
    """Happy path: disk_analyze_mft with offset parameter."""
    with patch(
        "reversecore_mcp.tools.forensics.disk._run_tsk",
        return_value=("", "", 0),
    ) as mock_run:
        await disk_analyze_mft(tmp_image, offset=2048)
        called_args = mock_run.call_args[0][0]
        assert "-o" in called_args
        assert "2048" in called_args


@pytest.mark.unit
@pytest.mark.asyncio
async def test_disk_extract_file_success(tmp_image, mock_tsk_available, workspace_dir):
    """Happy path: disk_extract_file calls disk_recover_deleted internally."""
    from reversecore_mcp.tools.forensics.disk import disk_extract_file

    mock_result = MagicMock()
    mock_result.stdout = b"live file data"
    mock_result.stderr = b""
    mock_result.returncode = 0

    output = str(workspace_dir / "extracted.bin")
    with patch("subprocess.run", return_value=mock_result):
        result = await disk_extract_file(tmp_image, "500", output)

    assert result.status == "success"
    assert result.data["recovered_bytes"] == len(b"live file data")
