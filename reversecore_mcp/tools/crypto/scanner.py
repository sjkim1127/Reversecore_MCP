"""Static cryptographic constant and algorithm scanner (FindCrypt-style).

Scans binary executables and firmware blobs for known cryptographic lookup tables,
initialization vectors, round constants, and custom Base64 substitution alphabets.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# ==============================================================================
# Cryptographic Constants & Signatures
# ==============================================================================

# AES Forward S-Box (256 bytes)
AES_SBOX = bytes(
    [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5C,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]
)

# AES Inverse S-Box (256 bytes)
AES_INV_SBOX = bytes(
    [
        0x52,
        0x09,
        0x6A,
        0xD5,
        0x30,
        0x36,
        0xA5,
        0x38,
        0xBF,
        0x40,
        0xA3,
        0x9E,
        0x81,
        0xF3,
        0xD7,
        0xFB,
        0x7C,
        0xE3,
        0x39,
        0x82,
        0x9B,
        0x2F,
        0xFF,
        0x87,
        0x34,
        0x8E,
        0x43,
        0x44,
        0xC4,
        0xDE,
        0xE9,
        0xCB,
        0x54,
        0x7B,
        0x94,
        0x32,
        0xA6,
        0xC2,
        0x23,
        0x3D,
        0xEE,
        0x4C,
        0x95,
        0x0B,
        0x42,
        0xFA,
        0xC3,
        0x4E,
        0x08,
        0x2E,
        0xA1,
        0x66,
        0x28,
        0xD9,
        0x24,
        0xB2,
        0x76,
        0x5B,
        0xA2,
        0x49,
        0x6D,
        0x8B,
        0xD1,
        0x25,
        0x72,
        0xF8,
        0xF6,
        0x64,
        0x86,
        0x68,
        0x98,
        0x16,
        0xD4,
        0xA4,
        0x5C,
        0xCC,
        0x5D,
        0x65,
        0xB6,
        0x92,
        0x6C,
        0x70,
        0x48,
        0x50,
        0xFD,
        0xED,
        0xB9,
        0xDA,
        0x5E,
        0x15,
        0x46,
        0x57,
        0xA7,
        0x8D,
        0x9D,
        0x84,
        0x90,
        0xD8,
        0xAB,
        0x00,
        0x8C,
        0xBC,
        0xD3,
        0x0A,
        0xF7,
        0xE4,
        0x58,
        0x05,
        0xB8,
        0xB3,
        0x45,
        0x06,
        0xD0,
        0x2C,
        0x1E,
        0x8F,
        0xCA,
        0x3F,
        0x0F,
        0x02,
        0xC1,
        0xAF,
        0xBD,
        0x03,
        0x01,
        0x13,
        0x8A,
        0x6B,
        0x3A,
        0x91,
        0x11,
        0x41,
        0x4F,
        0x67,
        0xDC,
        0xEA,
        0x97,
        0xF2,
        0xCF,
        0xCE,
        0xF0,
        0xB4,
        0xE6,
        0x73,
        0x96,
        0xAC,
        0x74,
        0x22,
        0xE7,
        0xAD,
        0x35,
        0x85,
        0xE2,
        0xF9,
        0x37,
        0xE8,
        0x1C,
        0x75,
        0xDF,
        0x6E,
        0x47,
        0xF1,
        0x1A,
        0x71,
        0x1D,
        0x29,
        0xC5,
        0x89,
        0x6F,
        0xB7,
        0x62,
        0x0E,
        0xAA,
        0x18,
        0xBE,
        0x1B,
        0xFC,
        0x56,
        0x3E,
        0x4B,
        0xC6,
        0xD2,
        0x79,
        0x20,
        0x9A,
        0xDB,
        0xC0,
        0xFE,
        0x78,
        0xCD,
        0x5A,
        0xF4,
        0x1F,
        0xDD,
        0xA8,
        0x33,
        0x88,
        0x07,
        0xC7,
        0x31,
        0xB1,
        0x12,
        0x10,
        0x59,
        0x27,
        0x80,
        0xEC,
        0x5F,
        0x60,
        0x51,
        0x7F,
        0xA9,
        0x19,
        0xB5,
        0x4A,
        0x0D,
        0x2D,
        0xE5,
        0x7A,
        0x9F,
        0x93,
        0xC9,
        0x9C,
        0xEF,
        0xA0,
        0xE0,
        0x3B,
        0x4D,
        0xAE,
        0x2A,
        0xF5,
        0xB0,
        0xC8,
        0xEB,
        0xBB,
        0x3C,
        0x83,
        0x53,
        0x99,
        0x61,
        0x17,
        0x2B,
        0x04,
        0x7E,
        0xBA,
        0x77,
        0xD6,
        0x26,
        0xE1,
        0x69,
        0x14,
        0x63,
        0x55,
        0x21,
        0x0C,
        0x7D,
    ]
)

# SM4 S-Box prefix (first 16 bytes)
SM4_SBOX_PREFIX = bytes(
    [
        0xD6,
        0x90,
        0xE9,
        0xFE,
        0xCC,
        0xE1,
        0x3D,
        0xB7,
        0x16,
        0xB6,
        0x14,
        0xC2,
        0x28,
        0xFB,
        0x2C,
        0x05,
    ]
)

# RC4 initial identity permutation (0x00..0xFF)
RC4_IDENTITY_TABLE = bytes(range(256))

STANDARD_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
URLSAFE_B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_PRINTABLE_SET = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_!@#$%^&*."
)


def _pack_u32_words(words: list[int], endian: str) -> bytes:
    """Pack a list of 32-bit unsigned integers in little ('<') or big ('>') endian."""
    fmt = f"{endian}{len(words)}I"
    return struct.pack(fmt, *words)


def _build_signature_catalog() -> list[dict[str, Any]]:
    """Build the catalog of static cryptographic signatures (LE and BE variants)."""
    sigs: list[dict[str, Any]] = [
        {
            "name": "AES_SBOX",
            "algorithm": "AES",
            "category": "symmetric_cipher",
            "confidence": "high",
            "pattern": AES_SBOX,
            "description": "AES (Rijndael) Forward S-Box (256 bytes)",
        },
        {
            "name": "AES_INV_SBOX",
            "algorithm": "AES",
            "category": "symmetric_cipher",
            "confidence": "high",
            "pattern": AES_INV_SBOX,
            "description": "AES (Rijndael) Inverse S-Box (256 bytes)",
        },
        {
            "name": "CHACHA20_SALSA20_32B",
            "algorithm": "ChaCha20 / Salsa20",
            "category": "stream_cipher",
            "confidence": "high",
            "pattern": b"expand 32-byte k",
            "description": "ChaCha20 / Salsa20 256-bit key constant ('expand 32-byte k')",
        },
        {
            "name": "CHACHA20_SALSA20_16B",
            "algorithm": "ChaCha20 / Salsa20",
            "category": "stream_cipher",
            "confidence": "high",
            "pattern": b"expand 16-byte k",
            "description": "ChaCha20 / Salsa20 128-bit key constant ('expand 16-byte k')",
        },
        {
            "name": "SM4_SBOX",
            "algorithm": "SM4",
            "category": "symmetric_cipher",
            "confidence": "high",
            "pattern": SM4_SBOX_PREFIX,
            "description": "SM4 block cipher S-Box prefix (16 bytes)",
        },
        {
            "name": "RC4_IDENTITY_SBOX",
            "algorithm": "RC4",
            "category": "stream_cipher",
            "confidence": "medium",
            "pattern": RC4_IDENTITY_TABLE,
            "description": "Static 256-byte identity permutation table (0x00..0xFF, common in RC4 KSA)",
        },
        {
            "name": "BASE64_STANDARD",
            "algorithm": "Base64",
            "category": "encoding",
            "confidence": "high",
            "pattern": STANDARD_B64_ALPHABET,
            "description": "Standard Base64 encoding alphabet",
        },
        {
            "name": "BASE64_URLSAFE",
            "algorithm": "Base64-URL",
            "category": "encoding",
            "confidence": "high",
            "pattern": URLSAFE_B64_ALPHABET,
            "description": "URL-safe Base64 encoding alphabet",
        },
    ]

    # 32-bit word table signatures (generate both Little-Endian and Big-Endian)
    word_tables: list[dict[str, Any]] = [
        {
            "name": "AES_TE0_TABLE",
            "algorithm": "AES",
            "category": "symmetric_cipher",
            "confidence": "high",
            "words": [0xC66363A5, 0xF87C7C84, 0xEE777799, 0xF67B7B8D],
            "description": "AES Te0 T-table prefix (4x32-bit words)",
        },
        {
            "name": "CRC32_IEEE_TABLE",
            "algorithm": "CRC32",
            "category": "checksum",
            "confidence": "high",
            "words": [0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA],
            "description": "CRC32 IEEE 802.3 lookup table prefix",
        },
        {
            "name": "CRC32C_CASTAGNOLI_POLY",
            "algorithm": "CRC32C",
            "category": "checksum",
            "confidence": "medium",
            "words": [0x82F63B78],
            "description": "CRC32C (Castagnoli) reversed polynomial 0x82F63B78",
        },
        {
            "name": "CRC32_IEEE_POLY",
            "algorithm": "CRC32",
            "category": "checksum",
            "confidence": "medium",
            "words": [0xEDB88320],
            "description": "CRC32 IEEE 802.3 reversed polynomial 0xEDB88320",
        },
        {
            "name": "SHA256_K_TABLE",
            "algorithm": "SHA-256",
            "category": "hash",
            "confidence": "high",
            "words": [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5],
            "description": "SHA-256 round constants K[0..3]",
        },
        {
            "name": "SHA256_H0_INIT",
            "algorithm": "SHA-256",
            "category": "hash",
            "confidence": "high",
            "words": [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A],
            "description": "SHA-256 initial hash values H0[0..3]",
        },
        {
            "name": "MD5_T_TABLE",
            "algorithm": "MD5",
            "category": "hash",
            "confidence": "high",
            "words": [0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE],
            "description": "MD5 sine-derived T-table constants T[0..3]",
        },
        {
            "name": "MD5_INIT_STATE",
            "algorithm": "MD5",
            "category": "hash",
            "confidence": "high",
            "words": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            "description": "MD5 / SHA-1 initial state A,B,C,D (0x67452301...)",
        },
        {
            "name": "SHA1_K_CONSTANTS",
            "algorithm": "SHA-1",
            "category": "hash",
            "confidence": "high",
            "words": [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
            "description": "SHA-1 round constants K[0..3]",
        },
        {
            "name": "TEA_XTEA_DELTA",
            "algorithm": "TEA / XTEA",
            "category": "symmetric_cipher",
            "confidence": "medium",
            "words": [0x9E3779B9],
            "description": "TEA / XTEA golden-ratio delta constant (0x9E3779B9)",
        },
        {
            "name": "TEA_DECRYPT_SUM",
            "algorithm": "TEA / XTEA",
            "category": "symmetric_cipher",
            "confidence": "medium",
            "words": [0xC6EF3720],
            "description": "TEA 32-round decryption initial sum (0xC6EF3720)",
        },
        {
            "name": "BLOWFISH_P_ARRAY",
            "algorithm": "Blowfish",
            "category": "symmetric_cipher",
            "confidence": "high",
            "words": [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344],
            "description": "Blowfish initial P-array constants (pi hex digits)",
        },
    ]

    for tbl in word_tables:
        for endian, label in (("<", "LE"), (">", "BE")):
            sigs.append(
                {
                    "name": f"{tbl['name']}_{label}",
                    "algorithm": tbl["algorithm"],
                    "category": tbl["category"],
                    "confidence": tbl["confidence"],
                    "pattern": _pack_u32_words(tbl["words"], endian),
                    "description": f"{tbl['description']} ({label})",
                }
            )

    return sigs


CRYPTO_SIGNATURES = _build_signature_catalog()


def _extract_lief_sections(file_path: Path) -> list[dict[str, Any]]:
    """Best-effort extraction of binary sections via LIEF for offset->VA/section mapping."""
    try:
        import lief  # type: ignore[import-untyped]

        binary = lief.parse(str(file_path))
        if binary is None:
            return []
        imagebase = getattr(binary, "imagebase", 0) or 0
        sections: list[dict[str, Any]] = []
        for sec in getattr(binary, "sections", []):
            offset = getattr(sec, "offset", 0) or 0
            size = getattr(sec, "size", 0) or 0
            va = getattr(sec, "virtual_address", 0) or 0
            if size > 0:
                sections.append(
                    {
                        "name": getattr(sec, "name", "") or "unknown",
                        "offset": offset,
                        "end": offset + size,
                        "va": va + imagebase if va < imagebase else va,
                    }
                )
        return sections
    except Exception:
        return []


def _map_offset_to_section(
    file_offset: int, sections: list[dict[str, Any]]
) -> tuple[str | None, str | None]:
    """Map a file offset to (section_name, hex_virtual_address) if section bounds match."""
    for sec in sections:
        if sec["offset"] <= file_offset < sec["end"]:
            va = sec["va"] + (file_offset - sec["offset"])
            return sec["name"], hex(va)
    return None, None


def _detect_custom_base64_alphabets(data: bytes, max_candidates: int = 10) -> list[dict[str, Any]]:
    """Detect non-standard 64-byte Base64 substitution alphabets.

    Finds contiguous 64-byte ASCII sequences made of unique Base64-like characters
    that contain alphanumeric coverage (>= 50 alphanumeric chars) and differ from
    standard and URL-safe Base64 tables.
    """
    candidates: list[dict[str, Any]] = []
    n = len(data)
    if n < 64:
        return candidates

    i = 0
    while i <= n - 64 and len(candidates) < max_candidates:
        chunk = data[i : i + 64]
        # Fast filter: all bytes must be in printable Base64 character set and unique
        if all(b in _B64_PRINTABLE_SET for b in chunk) and len(set(chunk)) == 64:
            if chunk not in (STANDARD_B64_ALPHABET, URLSAFE_B64_ALPHABET):
                alnum_count = sum(
                    1 for b in chunk if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122)
                )
                # Standard Base64 has 62 alphanumeric chars + 2 symbols
                if alnum_count >= 58:
                    candidates.append(
                        {
                            "name": "BASE64_CUSTOM_ALPHABET",
                            "algorithm": "Base64-Custom",
                            "category": "encoding",
                            "confidence": "medium",
                            "file_offset": i,
                            "file_offset_hex": hex(i),
                            "length": 64,
                            "preview": chunk.decode("ascii", errors="replace"),
                            "description": "Potential custom 64-character Base64 substitution alphabet",
                        }
                    )
                    i += 64
                    continue
        i += 1

    return candidates


@log_execution(tool_name="scan_crypto_constants")
@track_metrics("scan_crypto_constants")
@handle_tool_errors
async def scan_crypto_constants(
    file_path: str,
    include_custom_base64: bool = True,
    max_matches: int = 200,
) -> ToolResult:
    """Scan a binary file for cryptographic constants, S-Boxes, and encoding tables.

    Detects AES S-Box/InvS-Box/Te0 tables, ChaCha20/Salsa20 key constants, RC4
    identity tables, TEA/XTEA deltas, CRC32 polynomials/tables, SHA-1/SHA-256/MD5
    constants, Blowfish/SM4 tables, and standard or custom Base64 alphabets.

    Args:
        file_path: Path to the target binary or firmware file inside the workspace.
        include_custom_base64: If True, scan for custom 64-byte Base64 substitution tables.
        max_matches: Maximum number of matches to return to bound response size.

    Returns:
        ToolResult containing detected cryptographic algorithms, file offsets,
        virtual addresses (when parsable via LIEF), and confidence ratings.

    Example:
        >>> result = await scan_crypto_constants("/app/workspace/sample.bin")
        >>> print(result.status)
        'success'
    """
    validated_path = validate_file_path(file_path)
    data = validated_path.read_bytes()
    file_size = len(data)
    sections = _extract_lief_sections(validated_path)

    findings: list[dict[str, Any]] = []
    truncated = False

    for sig in CRYPTO_SIGNATURES:
        pattern = sig["pattern"]
        start = 0
        while True:
            idx = data.find(pattern, start)
            if idx == -1:
                break
            if len(findings) >= max_matches:
                truncated = True
                break
            sec_name, va_hex = _map_offset_to_section(idx, sections)
            findings.append(
                {
                    "name": sig["name"],
                    "algorithm": sig["algorithm"],
                    "category": sig["category"],
                    "confidence": sig["confidence"],
                    "file_offset": idx,
                    "file_offset_hex": hex(idx),
                    "virtual_address": va_hex,
                    "section": sec_name,
                    "length": len(pattern),
                    "description": sig["description"],
                }
            )
            start = idx + len(pattern)
        if truncated:
            break

    if include_custom_base64 and not truncated:
        remaining = max(0, max_matches - len(findings))
        if remaining > 0:
            custom_b64 = _detect_custom_base64_alphabets(data, max_candidates=min(remaining, 10))
            for item in custom_b64:
                sec_name, va_hex = _map_offset_to_section(item["file_offset"], sections)
                item["virtual_address"] = va_hex
                item["section"] = sec_name
                findings.append(item)

    # Sort findings deterministically by file offset
    findings.sort(key=lambda x: x["file_offset"])

    algorithms_detected = sorted({f["algorithm"] for f in findings})
    high_conf_algos = sorted({f["algorithm"] for f in findings if f["confidence"] == "high"})

    payload: dict[str, Any] = {
        "file_path": str(validated_path),
        "file_size": file_size,
        "total_matches": len(findings),
        "truncated": truncated,
        "algorithms_detected": algorithms_detected,
        "high_confidence_algorithms": high_conf_algos,
        "matches": findings,
    }

    if findings:
        msg = (
            f"Detected {len(findings)} cryptographic constant match(es) across "
            f"{len(algorithms_detected)} algorithm(s): {', '.join(algorithms_detected)}."
        )
    else:
        msg = f"No known cryptographic constants or tables detected in '{validated_path.name}'."

    return success(data=payload, message=msg)
