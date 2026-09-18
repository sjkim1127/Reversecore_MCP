"""Unit tests for fetch_test_binaries.py security hardening and safe extraction."""

import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.fetch_test_binaries import (
    fetch_binaries,
    safe_extract_tar,
    verify_sha256,
)


@pytest.fixture
def temp_extract_dir(tmp_path: Path) -> Path:
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()
    return extract_dir


def _create_tar_bytes(members_data: list[tuple[str, bytes, int | None, str | None]]) -> bytes:
    """Helper to create an in-memory tar archive.

    members_data is list of (name, content_bytes, type_flag, linkname).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for item in members_data:
            name, content, type_flag, linkname = item
            ti = tarfile.TarInfo(name=name)
            if type_flag is not None:
                ti.type = type_flag
            if linkname is not None:
                ti.linkname = linkname
            if ti.isreg() or type_flag is None:
                ti.size = len(content)
                tar.addfile(ti, io.BytesIO(content))
            else:
                tar.addfile(ti)
    buf.seek(0)
    return buf.getvalue()


class TestSafeExtractTar:
    """Test safe extraction and traversal defense."""

    def test_safe_extraction_valid(self, temp_extract_dir: Path):
        """Valid files within archive should extract without error."""
        tar_bytes = _create_tar_bytes(
            [
                ("sample.bin", b"\x7fELFtest", None, None),
                ("subdir/nested.bin", b"testdata", None, None),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            safe_extract_tar(tar, temp_extract_dir)

        assert (temp_extract_dir / "sample.bin").is_file()
        assert (temp_extract_dir / "sample.bin").read_bytes() == b"\x7fELFtest"
        assert (temp_extract_dir / "subdir" / "nested.bin").is_file()

    def test_rejection_path_traversal_dotdot(self, temp_extract_dir: Path):
        """Archives containing '..' path traversal components must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("../escaped.txt", b"evil", None, None),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Dangerous path traversal"):
                safe_extract_tar(tar, temp_extract_dir)

    def test_rejection_absolute_path(self, temp_extract_dir: Path):
        """Archives containing absolute path entries must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("/tmp/evil.txt", b"evil", None, None),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Dangerous path traversal"):
                safe_extract_tar(tar, temp_extract_dir)

    def test_rejection_external_symlink(self, temp_extract_dir: Path):
        """Symlinks pointing outside the extraction directory must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("symlink_evil", b"", tarfile.SYMTYPE, "../../etc/passwd"),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Symlink points outside target directory"):
                safe_extract_tar(tar, temp_extract_dir)

    def test_rejection_absolute_symlink(self, temp_extract_dir: Path):
        """Absolute symlinks must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("symlink_abs", b"", tarfile.SYMTYPE, "/etc/shadow"),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Absolute symlinks not permitted"):
                safe_extract_tar(tar, temp_extract_dir)

    def test_rejection_external_hardlink(self, temp_extract_dir: Path):
        """Hardlinks pointing outside the extraction directory must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("hardlink_evil", b"", tarfile.LNKTYPE, "../secret"),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Hardlink points outside target directory"):
                safe_extract_tar(tar, temp_extract_dir)

    def test_rejection_device_file(self, temp_extract_dir: Path):
        """Device node entries must be rejected."""
        tar_bytes = _create_tar_bytes(
            [
                ("dev_entry", b"", tarfile.CHRTYPE, None),
            ]
        )
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
            with pytest.raises(ValueError, match="Special device entries not permitted"):
                safe_extract_tar(tar, temp_extract_dir)


class TestVerifySha256:
    """Test SHA256 checksum verification."""

    def test_verify_empty_expected_hash(self, tmp_path: Path):
        """Empty expected hash should return True (skipped)."""
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"data")
        assert verify_sha256(file_path, "") is True

    def test_verify_matching_hash(self, tmp_path: Path):
        """Matching SHA256 should return True."""
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"hello world")
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert verify_sha256(file_path, expected) is True

    def test_verify_mismatch_hash(self, tmp_path: Path):
        """Mismatched SHA256 should return False."""
        file_path = tmp_path / "test.txt"
        file_path.write_bytes(b"hello world")
        assert (
            verify_sha256(
                file_path, "0000000000000000000000000000000000000000000000000000000000000000"
            )
            is False
        )


class TestFetchBinariesExecution:
    """Test fetch_binaries safety boundaries and fallback behavior."""

    def test_remote_url_without_sha256_triggers_safe_fallback(self, tmp_path: Path):
        """A remote URL without EXPECTED_SHA256 must trigger safe fallback."""
        with (
            patch("scripts.fetch_test_binaries.WORKSPACE_DIR", tmp_path),
            patch("scripts.fetch_test_binaries.BINARIES_DIR", tmp_path / "binaries"),
            patch(
                "scripts.fetch_test_binaries.TEST_BINARIES_URL",
                "https://example.com/binaries.tar.gz",
            ),
            patch("scripts.fetch_test_binaries.EXPECTED_SHA256", ""),
            patch("scripts.fetch_test_binaries.create_minimal_fallback_binaries") as mock_fallback,
        ):
            fetch_binaries()
            mock_fallback.assert_called_once()
