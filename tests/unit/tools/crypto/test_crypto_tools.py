"""Unit tests for cryptographic analysis and dynamic key extraction tools."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from reversecore_mcp.tools.crypto.dynamic_extractor import (
    HOOKED_CRYPTO_APIS,
    extract_crypto_keys_dynamic,
)
from reversecore_mcp.tools.crypto.scanner import (
    AES_SBOX,
    STANDARD_B64_ALPHABET,
    scan_crypto_constants,
)


def _parse_payload(result) -> dict:
    """Extract ToolResult data payload."""
    assert result.status == "success", f"Unexpected error: {result}"
    return result.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_crypto_constants_aes_chacha_sha_tea(
    workspace_dir: Path, patched_workspace_config
) -> None:
    """Verify scan_crypto_constants detects AES S-Box, ChaCha20, TEA delta, and Base64."""
    sample = workspace_dir / "crypto_sample.bin"
    tea_delta_le = b"\xb9\x79\x37\x9e"
    sha256_k_le = b"\x98\x2f\x8a\x42\x91\x44\x37\x71\xcf\xfb\xc0\xb5\xa5\xdb\xb5\xe9"

    blob = (
        b"\x00" * 64
        + AES_SBOX
        + b"\x00" * 32
        + b"expand 32-byte k"
        + b"\x00" * 16
        + tea_delta_le
        + b"\x00" * 16
        + sha256_k_le
        + b"\x00" * 16
        + STANDARD_B64_ALPHABET
        + b"\x00" * 32
    )
    sample.write_bytes(blob)

    result = await scan_crypto_constants(str(sample))
    data = _parse_payload(result)

    algos = set(data["algorithms_detected"])
    assert "AES" in algos
    assert "ChaCha20 / Salsa20" in algos
    assert "TEA / XTEA" in algos
    assert "SHA-256" in algos
    assert "Base64" in algos
    assert data["total_matches"] >= 5

    aes_match = next(m for m in data["matches"] if m["name"] == "AES_SBOX")
    assert aes_match["file_offset"] == 64
    assert aes_match["confidence"] == "high"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_crypto_constants_custom_base64(
    workspace_dir: Path, patched_workspace_config
) -> None:
    """Verify detection of custom shuffled 64-character Base64 alphabets."""
    # Reverse the standard Base64 alphabet dynamically to avoid high-entropy literals
    custom_alphabet = STANDARD_B64_ALPHABET[::-1]
    assert len(custom_alphabet) == 64
    sample = workspace_dir / "custom_b64.bin"
    sample.write_bytes(b"\x00" * 32 + custom_alphabet + b"\x00" * 32)

    result = await scan_crypto_constants(str(sample), include_custom_base64=True)
    data = _parse_payload(result)

    assert "Base64-Custom" in data["algorithms_detected"]
    custom_match = next(m for m in data["matches"] if m["name"] == "BASE64_CUSTOM_ALPHABET")
    assert custom_match["file_offset"] == 32
    assert custom_match["preview"] == custom_alphabet.decode("ascii")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_crypto_constants_clean_file(
    workspace_dir: Path, patched_workspace_config
) -> None:
    """Verify clean non-crypto file yields zero matches."""
    clean = workspace_dir / "clean.txt"
    clean.write_text("Hello, this is a benign configuration file without crypto tables.")

    result = await scan_crypto_constants(str(clean))
    data = _parse_payload(result)

    assert data["total_matches"] == 0
    assert data["algorithms_detected"] == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_extract_crypto_keys_dynamic_compile_only(
    workspace_dir: Path, patched_workspace_config
) -> None:
    """Verify compile_only mode generates source and compiles crypto hook library."""
    result = await extract_crypto_keys_dynamic(compile_only=True)
    data = _parse_payload(result)

    assert data["hooked_apis"] == HOOKED_CRYPTO_APIS
    assert Path(data["c_source_path"]).exists()
    if shutil.which("clang") or shutil.which("gcc"):
        assert data["compiler_available"] is True
        assert Path(data["library_path"]).exists()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_extract_crypto_keys_dynamic_interception(
    workspace_dir: Path, patched_workspace_config
) -> None:
    """Verify runtime interception of EVP_EncryptInit_ex and AES_set_encrypt_key."""
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        pytest.skip("No C compiler (clang/gcc) available for dynamic hook test")

    import platform

    is_darwin = platform.system() == "Darwin"
    ext = ".dylib" if is_darwin else ".so"
    dummy_c = workspace_dir / "dummy_crypto.c"
    dummy_lib = workspace_dir / f"libdummy_crypto{ext}"
    dummy_c.write_text(
        r"""
int EVP_EncryptInit_ex(void* ctx, const void* type, void* impl, const unsigned char* key, const unsigned char* iv) {
    (void)ctx; (void)type; (void)impl; (void)key; (void)iv;
    return 1;
}
int AES_set_encrypt_key(const unsigned char* userKey, const int bits, void* key) {
    (void)userKey; (void)bits; (void)key;
    return 0;
}
""",
        encoding="utf-8",
    )

    lib_flags = ["-dynamiclib"] if is_darwin else ["-shared", "-fPIC"]
    comp_lib = subprocess.run(
        [compiler, *lib_flags, "-o", str(dummy_lib), str(dummy_c)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if comp_lib.returncode != 0:
        pytest.skip(f"Could not compile dummy crypto library: {comp_lib.stderr}")

    test_c = workspace_dir / "target_crypto.c"
    test_bin = workspace_dir / "target_crypto"
    test_c.write_text(
        r"""
#include <stddef.h>

extern int EVP_EncryptInit_ex(void* ctx, const void* type, void* impl, const unsigned char* key, const unsigned char* iv);
extern int AES_set_encrypt_key(const unsigned char* userKey, const int bits, void* key);

int main(void) {
    unsigned char key[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    unsigned char iv[16] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    unsigned char sched[256] = {0};

    EVP_EncryptInit_ex(NULL, NULL, NULL, key, iv);
    AES_set_encrypt_key(key, 128, sched);
    return 0;
}
""",
        encoding="utf-8",
    )

    rpath_flag = f"-Wl,-rpath,{workspace_dir}"
    extra_link = ["-Wl,-flat_namespace"] if is_darwin else []
    comp = subprocess.run(
        [
            compiler,
            "-O0",
            "-o",
            str(test_bin),
            str(test_c),
            str(dummy_lib),
            rpath_flag,
            *extra_link,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if comp.returncode != 0:
        pytest.skip(f"Could not compile test binary: {comp.stderr}")

    result = await extract_crypto_keys_dynamic(file_path=str(test_bin), timeout=10)
    data = _parse_payload(result)

    assert data["exit_code"] == 0
    assert data["total_events"] >= 2
    assert data["unique_keys_count"] >= 1

    expected_prefix = "".join(f"{i * 0x11:02x}" for i in range(16))
    assert any(k["key_hex"].startswith(expected_prefix) for k in data["unique_keys"])
