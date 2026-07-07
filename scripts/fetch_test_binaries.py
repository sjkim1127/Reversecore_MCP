#!/usr/bin/env python3
"""
On-Demand Test Binary Fetcher for Reversecore_MCP
Downloads and extracts pre-compiled multi-architecture test binaries.
Falls back to generating minimal mock binaries if the download fails.
"""

import hashlib
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path

# Configuration
TEST_BINARIES_URL = os.environ.get(
    "TEST_BINARIES_URL",
    "https://github.com/reversecore/Reversecore_MCP/releases/download/v1.0-testbin/reversecore_test_binaries_v1.tar.gz",  # Mock URL
)
EXPECTED_SHA256 = os.environ.get(
    "TEST_BINARIES_SHA256", ""
)  # If empty, skips strict check for the mock
WORKSPACE_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "workspace"
BINARIES_DIR = WORKSPACE_DIR / "binaries"


def verify_sha256(file_path: Path, expected_hash: str) -> bool:
    """Verify the SHA256 checksum of a file."""
    if not expected_hash:
        return True

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest() == expected_hash


def create_minimal_fallback_binaries():
    """Create minimal ELF/PE binaries as a fallback if download fails."""
    print("⚠️  Creating minimal fallback binaries...")
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    # Minimal ELF (x86_64)
    elf_path = BINARIES_DIR / "hello_x64"
    with open(elf_path, "wb") as f:
        # Minimal viable ELF header
        f.write(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00"
        )

    # Minimal PIE ELF
    pie_path = BINARIES_DIR / "pie_x64"
    with open(pie_path, "wb") as f:
        f.write(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00"
        )

    # Copy for stripped variant
    shutil.copy(elf_path, BINARIES_DIR / "hello_x64_stripped")

    # Empty binary for loop test
    with open(BINARIES_DIR / "loop_x64", "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00")

    print("✅ Fallback binaries created.")


def fetch_binaries():
    """Download, verify, and extract binaries."""
    print("========================================")
    print("Fetching Test Binaries")
    print("========================================")

    # Ensure workspace exists
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    archive_path = WORKSPACE_DIR / "test_binaries.tar.gz"

    print(f"Downloading from {TEST_BINARIES_URL}...")
    try:
        urllib.request.urlretrieve(TEST_BINARIES_URL, archive_path)
        print("Download successful.")

        if EXPECTED_SHA256:
            print(f"Verifying SHA256: {EXPECTED_SHA256}...")
            if not verify_sha256(archive_path, EXPECTED_SHA256):
                print("❌ SHA256 verification failed!")
                raise ValueError("Checksum mismatch")
            print("✅ Checksum verified.")

        print("Extracting archive...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=BINARIES_DIR)
        print("✅ Extraction complete.")

        # Cleanup archive
        archive_path.unlink()

    except Exception as e:
        print(f"⚠️  Download or extraction failed: {e}")
        if archive_path.exists():
            archive_path.unlink()

        create_minimal_fallback_binaries()


if __name__ == "__main__":
    fetch_binaries()
