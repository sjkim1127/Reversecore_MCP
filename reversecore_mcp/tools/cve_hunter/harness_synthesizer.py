"""Harness and Dictionary Synthesizer for C/C++ target parsing and fuzzing."""

from __future__ import annotations

import re
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Common file format magic bytes and chunk signatures
KNOWN_MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "image": [
        b"\x89PNG\r\n\x1a\n",  # PNG
        b"\xff\xd8\xff",  # JPEG
        b"GIF87a",  # GIF87
        b"GIF89a",  # GIF89
        b"RIFF",  # WEBP / WAV / AVI
        b"BM",  # BMP
        b"\x00\x00\x01\x00",  # ICO
    ],
    "archive": [
        b"PK\x03\x04",  # ZIP
        b"\x1f\x8b\x08",  # GZIP
        b"BZh",  # BZIP2
        b"7z\xbc\xaf\x27\x1c",  # 7Z
        b"Rar!\x1a\x07\x00",  # RAR
        b"\xfd7zXZ\x00",  # XZ
        b"ustar",  # TAR
    ],
    "document": [
        b"%PDF-",  # PDF
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE2 / MS Office legacy
        b"{\\rtf",  # RTF
        b"SQLite format 3\x00",  # SQLite
    ],
    "executable": [
        b"MZ",  # PE
        b"\x7fELF",  # ELF
        b"\xca\xfe\xba\xbe",  # Mach-O Fat / Java Class
        b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit
        b"\xce\xfa\xed\xfe",  # Mach-O 32-bit
    ],
    "media": [
        b"\x1a\x45\xdf\xa3",  # Matroska / WebM
        b"OggS",  # OGG
        b"fLaC",  # FLAC
        b"ID3",  # MP3 ID3
        b"\x00\x00\x00 ftyp",  # MP4
    ],
}

# Regex to detect C/C++ parser function signatures: int parse_xxx(const uint8_t *data, size_t size, ...)
_FUNC_SIGNATURE_PATTERN = re.compile(
    r"^\s*(?:extern\s+[\"']C[\"']\s+)?(?:static\s+|inline\s+)?([A-Za-z0-9_]+(?:\s*\*+)?)\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def extract_format_tokens_from_sample(sample_bytes: bytes, max_tokens: int = 50) -> list[str]:
    """Extract format tokens, ASCII headers, and magic tags from a sample input.

    Args:
        sample_bytes: Raw binary content of a valid sample file.
        max_tokens: Maximum number of distinct tokens to extract.

    Returns:
        List of formatted dictionary entries (e.g. '"PNG"' or '"\\x89PNG"').
    """
    tokens: set[str] = set()

    # 1. Check known magic headers
    for _category, magics in KNOWN_MAGIC_SIGNATURES.items():
        for m in magics:
            if sample_bytes.startswith(m) or m in sample_bytes[:128]:
                escaped = "".join(f"\\x{b:02x}" if b < 32 or b > 126 else chr(b) for b in m)
                tokens.add(f'"{escaped}"')

    # 2. Extract 4-byte chunk identifiers (e.g. IHDR, IDAT, IEND, moov, trak)
    chunk_pattern = re.compile(rb"[A-Za-z0-9_]{4}")
    for match in chunk_pattern.finditer(sample_bytes[:4096]):
        chunk = match.group(0).decode("ascii", errors="ignore")
        if chunk.isalnum():
            tokens.add(f'"{chunk}"')

    # 3. Extract printable ASCII strings (length between 3 and 16)
    ascii_pattern = re.compile(rb"[A-Za-z0-9_\-\.\:\/]{3,16}")
    for match in ascii_pattern.finditer(sample_bytes[:4096]):
        val = match.group(0).decode("ascii", errors="ignore")
        if val:
            tokens.add(f'"{val}"')

    return sorted(tokens)[:max_tokens]


def build_afl_dictionary(tokens: list[str]) -> str:
    """Construct an AFL/LibFuzzer dictionary string from token entries.

    Args:
        tokens: List of token strings.

    Returns:
        AFL-compatible .dict file content.
    """
    lines = [
        "# AFL++ / LibFuzzer dictionary auto-synthesized by Reversecore_MCP",
        "# Use with: -dict=<file.dict> or -dict=fuzz.dict",
    ]
    for i, tok in enumerate(tokens):
        cleaned = tok if tok.startswith('"') and tok.endswith('"') else f'"{tok}"'
        lines.append(f"token_{i} = {cleaned}")
    return "\n".join(lines) + "\n"


def parse_header_for_parser_functions(header_content: str) -> list[dict[str, Any]]:
    """Parse a C/C++ header to locate candidate parser/decoder entry points.

    Args:
        header_content: Content of a C/C++ header file.

    Returns:
        List of identified candidate parser function dictionaries.
    """
    candidates: list[dict[str, Any]] = []

    for match in _FUNC_SIGNATURE_PATTERN.finditer(header_content):
        return_type = match.group(1).strip()
        func_name = match.group(2).strip()
        params_str = match.group(3).strip()

        # Score function based on parser keywords in name and parameters
        score = 0
        name_lower = func_name.lower()
        if any(
            kw in name_lower
            for kw in ["parse", "decode", "read", "load", "unpack", "process", "open", "decompress"]
        ):
            score += 40
        if any(
            kw in name_lower
            for kw in ["buffer", "data", "stream", "chunk", "packet", "msg", "file"]
        ):
            score += 20

        # Check parameter list for (data, size) or (buffer, len)
        params_lower = params_str.lower()
        has_buffer_param = any(
            t in params_lower for t in ["char *", "uint8_t *", "void *", "unsigned char *", "char*"]
        )
        has_size_param = any(
            t in params_lower
            for t in ["size_t", "int size", "int len", "unsigned int", "uint32_t", "size"]
        )

        if has_buffer_param and has_size_param:
            score += 40
        elif has_buffer_param or has_size_param:
            score += 20

        if score >= 40:
            candidates.append(
                {
                    "function_name": func_name,
                    "return_type": return_type,
                    "parameters": params_str,
                    "confidence_score": min(score, 100),
                }
            )

    candidates.sort(key=lambda x: x["confidence_score"], reverse=True)
    return candidates


def generate_libfuzzer_harness(
    header_include: str,
    target_function: str,
    parameters: str,
    extra_cflags: list[str] | None = None,
) -> str:
    """Generate a clean, standalone LibFuzzer C++ harness.

    Args:
        header_include: Include directive or header path (e.g. '#include "parser.h"').
        target_function: Name of the C/C++ function to fuzz.
        parameters: Parameter signature string of target function.
        extra_cflags: Optional compiler flags to document in comments.

    Returns:
        Complete C/C++ LibFuzzer harness source code string.
    """
    include_stmt = (
        header_include if header_include.startswith("#") else f'#include "{header_include}"'
    )
    cflags_comment = (
        " ".join(extra_cflags) if extra_cflags else "-fsanitize=fuzzer,address,undefined -g -O1"
    )

    # Analyze parameters to construct suitable invocation
    call_args: list[str] = []

    for raw_p in parameters.split(","):
        p = raw_p.strip()
        if not p or p == "void":
            continue
        p_lower = p.lower()
        if any(t in p_lower for t in ["char *", "uint8_t *", "void *", "unsigned char *", "char*"]):
            if "const" in p_lower or "char *" in p_lower or "uint8_t *" in p_lower:
                call_args.append("(const uint8_t *)Data")
            else:
                call_args.append("(uint8_t *)Data")
        elif any(
            t in p_lower
            for t in ["size_t", "int size", "int len", "unsigned int", "uint32_t", "length", "size"]
        ):
            call_args.append("Size")
        elif "int *" in p_lower or "size_t *" in p_lower:
            call_args.append("NULL")
        elif any(t in p_lower for t in ["int", "long", "flags"]):
            call_args.append("0")
        else:
            call_args.append("NULL")

    if not call_args:
        call_args = ["(const uint8_t *)Data", "Size"]

    args_str = ", ".join(call_args)

    harness_code = f"""/*
 * Auto-Generated LibFuzzer Harness by Reversecore_MCP
 * Compile with: clang++ {cflags_comment} -o fuzzer_target harness.cc -L. -l<target_lib>
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {{
#endif

{include_stmt}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size < 4 || Size > 10 * 1024 * 1024) {{
        return 0; // Ignore empty or excessively large inputs
    }}

    // Target parser entry point invocation
    {target_function}({args_str});

    return 0;
}}

#ifdef __cplusplus
}}
#endif
"""
    return harness_code


async def synthesize_fuzz_harness_impl(
    header_or_binary_path: str,
    sample_file_path: str | None = None,
    target_function: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Synthesize LibFuzzer/AFL++ harness and dictionary for a C/C++ target.

    Args:
        header_or_binary_path: Path to target header (.h) or binary in workspace.
        sample_file_path: Optional path to a valid sample file to extract dictionary tokens.
        target_function: Optional explicit target function name.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult containing harness source code, candidate functions, and dictionary content.
    """
    try:
        target_path = validate_file_path(header_or_binary_path)
    except Exception as e:
        return failure("INVALID_PATH", f"Validation error on target path: {e}")

    if not target_path.exists():
        return failure("FILE_NOT_FOUND", f"Target path does not exist: {header_or_binary_path}")

    # Step 1: Parse header or disassemble binary for candidate functions
    candidate_funcs: list[dict[str, Any]] = []
    header_content = ""

    if target_path.suffix.lower() in [".h", ".hpp", ".c", ".cpp", ".cc"]:
        try:
            header_content = target_path.read_text(errors="ignore")
            candidate_funcs = parse_header_for_parser_functions(header_content)
        except Exception as e:
            logger.warning(f"Failed to read header file: {e}")

    selected_func_name = target_function
    selected_params = "const uint8_t *data, size_t size"

    if not selected_func_name:
        if candidate_funcs:
            top = candidate_funcs[0]
            selected_func_name = top["function_name"]
            selected_params = top["parameters"]
        else:
            selected_func_name = "target_parse_function"

    # Step 2: Extract dictionary tokens from sample file if provided
    tokens: list[str] = []
    if sample_file_path:
        try:
            sample_path = validate_file_path(sample_file_path)
            if sample_path.exists():
                sample_bytes = sample_path.read_bytes()
                tokens = extract_format_tokens_from_sample(sample_bytes)
        except Exception as e:
            logger.debug(f"Sample parsing skipped: {e}")

    dict_content = build_afl_dictionary(tokens) if tokens else "# No dictionary tokens extracted\n"

    # Step 3: Generate C++ LibFuzzer Harness
    header_include = target_path.name if target_path.suffix in [".h", ".hpp"] else "target.h"
    harness_code = generate_libfuzzer_harness(
        header_include=header_include,
        target_function=selected_func_name,
        parameters=selected_params,
    )

    result_data = {
        "target_file": str(target_path),
        "selected_target_function": selected_func_name,
        "candidate_functions": candidate_funcs,
        "harness_source_code": harness_code,
        "dictionary_content": dict_content,
        "dictionary_token_count": len(tokens),
        "summary": f"Synthesized LibFuzzer harness for function '{selected_func_name}' with {len(tokens)} dictionary tokens.",
    }

    return success(result_data)
