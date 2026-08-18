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

    import subprocess

    if shutil.which("gcc"):
        print("🔧 gcc found, compiling real test binaries on the fly...")
        c_src = BINARIES_DIR / "hello.c"
        c_src.write_text("""
#include <stdio.h>
int fib(int n) {
    if (n <= 1) return n;
    return fib(n-1) + fib(n-2);
}
int main() {
    printf("Hello from real test binary\\n");
    return fib(10);
}
""")
        hello_path = BINARIES_DIR / "hello_x64"
        subprocess.run(["gcc", "-o", str(hello_path), str(c_src)], capture_output=True)
        stripped_path = BINARIES_DIR / "hello_x64_stripped"
        shutil.copy2(hello_path, stripped_path)
        subprocess.run(["strip", str(stripped_path)], capture_output=True)

        pie_path = BINARIES_DIR / "pie_x64"
        subprocess.run(
            ["gcc", "-fPIE", "-pie", "-o", str(pie_path), str(c_src)],
            capture_output=True,
        )

        vuln_c = BINARIES_DIR / "vuln.c"
        vuln_c.write_text("""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void vuln_function(char *str) {
    char buffer[16];
    strcpy(buffer, str);
}
int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "backdoor") == 0) {
            system("ls");
        } else {
            vuln_function(argv[1]);
        }
    }
    return 0;
}
""")
        vuln_path = BINARIES_DIR / "vuln_x64"
        subprocess.run(["gcc", "-o", str(vuln_path), str(vuln_c)], capture_output=True)
        vuln_stripped_path = BINARIES_DIR / "vuln_x64_stripped"
        shutil.copy2(vuln_path, vuln_stripped_path)
        subprocess.run(["strip", str(vuln_stripped_path)], capture_output=True)

        with open(BINARIES_DIR / "loop_x64", "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")
        print("✅ Compilation complete.")
        return

    # Minimal ELF (x86_64)
    print("⚠️  gcc not found, falling back to 24-byte zero files...")
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

    hello_bin = BINARIES_DIR / "hello_x64"
    if hello_bin.exists() and os.path.getsize(hello_bin) > 100:
        print("✅ Real test binaries already exist. Skipping fetch/generation.")
        return

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
