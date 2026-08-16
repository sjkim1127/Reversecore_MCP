"""
Stack String & Emulation-Based String Decryption Engine.

Recovers dynamically constructed stack strings (byte-by-byte or dword-by-dword local variables)
and extracts decrypted strings from obfuscated loops (XOR, additive, rolling ciphers) via
micro-emulation and disassembly heuristics.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout, parse_json_output
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

_STACK_STORE_BYTE_PATTERN = re.compile(
    r"mov\s+(?:byte\s+)?(?:ptr\s+)?\[\s*(?:r|e)?(?:bp|sp)\s*([+-]\s*0x[0-9a-fA-F]+|[+-]\s*\d+)\s*\]\s*,\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)
_STACK_STORE_DWORD_PATTERN = re.compile(
    r"mov\s+(?:dword\s+)?(?:ptr\s+)?\[\s*(?:r|e)?(?:bp|sp)\s*([+-]\s*0x[0-9a-fA-F]+|[+-]\s*\d+)\s*\]\s*,\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)
_STACK_STORE_QWORD_PATTERN = re.compile(
    r"mov\s+(?:qword\s+)?(?:ptr\s+)?\[\s*(?:r|e)?(?:bp|sp)\s*([+-]\s*0x[0-9a-fA-F]+|[+-]\s*\d+)\s*\]\s*,\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)

_PRINTABLE_ASCII_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
_PRINTABLE_WIDE_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


async def _run_r2_command(file_path: str | Path, command: str, timeout: int = 30) -> str:
    """Execute a radare2 command using async execution."""
    from reversecore_mcp.core.execution import execute_subprocess_async

    cmd = ["radare2", "-q", "-0", "-c", f"e scr.color=0; {command}", str(file_path)]
    stdout, _ = await execute_subprocess_async(cmd, timeout=timeout)
    return stdout


def _parse_offset(offset_str: str) -> int:
    """Parse stack offset string like '- 0x20' or '+16' into an integer."""
    clean = offset_str.replace(" ", "")
    if clean.startswith("+"):
        val_str = clean[1:]
        return int(val_str, 16) if val_str.startswith("0x") else int(val_str)
    elif clean.startswith("-"):
        val_str = clean[1:]
        return -(int(val_str, 16) if val_str.startswith("0x") else int(val_str))
    else:
        return int(clean, 16) if clean.startswith("0x") else int(clean)


def _parse_val(val_str: str) -> int:
    """Parse integer value from hex or decimal string."""
    clean = val_str.strip()
    return int(clean, 16) if clean.startswith("0x") else int(clean)


def _extract_printable_strings(raw_bytes: bytes, min_len: int = 4) -> list[dict[str, str]]:
    """Extract ASCII and UTF-16LE printable strings from raw bytes buffer."""
    results: list[dict[str, str]] = []

    # ASCII matches
    for m in _PRINTABLE_ASCII_PATTERN.finditer(raw_bytes):
        s = m.group(0).decode("latin-1", errors="ignore").strip()
        if len(s) >= min_len:
            results.append({"type": "ascii", "string": s})

    # Wide matches
    for m in _PRINTABLE_WIDE_PATTERN.finditer(raw_bytes):
        try:
            s = m.group(0).decode("utf-16le", errors="ignore").strip()
            if len(s) >= min_len:
                results.append({"type": "utf-16le", "string": s})
        except Exception:
            pass

    return results


@track_metrics(tool_name="deobfuscate_strings")
async def deobfuscate_strings_impl(
    file_path: str,
    function_address: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Deobfuscate stack strings and emulated loop strings in a binary.

    Args:
        file_path: Path to the target binary file.
        function_address: Optional function address/name to limit scope (e.g. '0x140001000' or 'main').
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult containing recovered stack strings and emulated loop strings.
    """
    safe_path = validate_file_path(file_path)
    if not safe_path.exists() or not safe_path.is_file():
        return failure("INVALID_PATH", f"Target file does not exist: {file_path}")

    calc_timeout = calculate_dynamic_timeout(safe_path, base_timeout=timeout or 60)

    recovered_strings: list[dict[str, Any]] = []
    seen_strings: set[str] = set()

    # Step 1: Query functions from radare2
    if function_address:
        functions = [{"offset": function_address, "name": str(function_address)}]
    else:
        afl_output = await _run_r2_command(safe_path, "aa; aflj", timeout=calc_timeout)
        functions = parse_json_output(afl_output) or []

    func_limit = min(len(functions), 100) if functions else 0

    for i in range(func_limit):
        f = functions[i]
        f_offset = f.get("offset")
        f_name = f.get("name", "func")
        if f_offset is None:
            continue

        pdf_cmd = f"pdfj @ {f_offset}"
        pdf_output = await _run_r2_command(safe_path, pdf_cmd, timeout=min(calc_timeout, 10))
        pdf_data = parse_json_output(pdf_output)
        if not pdf_data or not isinstance(pdf_data, dict):
            continue

        ops = pdf_data.get("ops", [])
        if not ops:
            continue

        # --- Sub-Engine A: Stack String Scanner ---
        # Map stack offset -> byte value
        stack_bytes: dict[int, int] = {}
        has_loop = False

        for op in ops:
            disasm = op.get("disasm", "")
            op_type = op.get("type", "")

            if op_type in ("cjmp", "jmp") and op.get("jump", 0) <= op.get("offset", 0):
                has_loop = True

            # Check byte stores
            m_byte = _STACK_STORE_BYTE_PATTERN.search(disasm)
            if m_byte:
                try:
                    off = _parse_offset(m_byte.group(1))
                    val = _parse_val(m_byte.group(2)) & 0xFF
                    stack_bytes[off] = val
                except (ValueError, IndexError):
                    pass
                continue

            # Check dword stores
            m_dword = _STACK_STORE_DWORD_PATTERN.search(disasm)
            if m_dword:
                try:
                    off = _parse_offset(m_dword.group(1))
                    val = _parse_val(m_dword.group(2)) & 0xFFFFFFFF
                    for b_idx in range(4):
                        stack_bytes[off + b_idx] = (val >> (b_idx * 8)) & 0xFF
                except (ValueError, IndexError):
                    pass
                continue

            # Check qword stores
            m_qword = _STACK_STORE_QWORD_PATTERN.search(disasm)
            if m_qword:
                try:
                    off = _parse_offset(m_qword.group(1))
                    val = _parse_val(m_qword.group(2)) & 0xFFFFFFFFFFFFFFFF
                    for b_idx in range(8):
                        stack_bytes[off + b_idx] = (val >> (b_idx * 8)) & 0xFF
                except (ValueError, IndexError):
                    pass
                continue

        # Reconstruct contiguous chunks from stack_bytes
        if len(stack_bytes) >= 4:
            sorted_offsets = sorted(stack_bytes.keys())
            # Group consecutive offsets
            chunks: list[bytearray] = []
            curr_chunk = bytearray()
            last_off = None

            for off in sorted_offsets:
                b = stack_bytes[off]
                if last_off is None or off == last_off + 1:
                    curr_chunk.append(b)
                else:
                    if len(curr_chunk) >= 4:
                        chunks.append(curr_chunk)
                    curr_chunk = bytearray([b])
                last_off = off

            if len(curr_chunk) >= 4:
                chunks.append(curr_chunk)

            for chunk in chunks:
                extracted = _extract_printable_strings(bytes(chunk))
                for item in extracted:
                    s_val = item["string"]
                    if s_val not in seen_strings:
                        seen_strings.add(s_val)
                        recovered_strings.append(
                            {
                                "address": (
                                    hex(f_offset) if isinstance(f_offset, int) else str(f_offset)
                                ),
                                "function": f_name,
                                "type": "stack_string",
                                "encoding": item["type"],
                                "string": s_val,
                                "confidence": 0.95,
                            }
                        )

        # --- Sub-Engine B: Emulated Loop String Extraction ---
        # If loop was found with arithmetic/XOR, run short ESIL emulation step
        if has_loop:
            try:
                # Step up to 500 instructions from function start and inspect memory
                esil_cmd = f"aei; aeim; aeip; aes 500 @ {f_offset}; psj @ rbp-128"
                await _run_r2_command(safe_path, esil_cmd, timeout=min(calc_timeout, 5))
                # Also inspect stack buffer using 'pxj'
                px_cmd = "pxj 128 @ esp"
                px_output = await _run_r2_command(safe_path, px_cmd, timeout=min(calc_timeout, 5))
                px_bytes = parse_json_output(px_output)
                if px_bytes and isinstance(px_bytes, list):
                    raw_stack = bytes(px_bytes)
                    emul_strings = _extract_printable_strings(raw_stack)
                    for item in emul_strings:
                        s_val = item["string"]
                        if s_val not in seen_strings:
                            seen_strings.add(s_val)
                            recovered_strings.append(
                                {
                                    "address": (
                                        hex(f_offset)
                                        if isinstance(f_offset, int)
                                        else str(f_offset)
                                    ),
                                    "function": f_name,
                                    "type": "emulated_loop",
                                    "encoding": item["type"],
                                    "string": s_val,
                                    "confidence": 0.88,
                                }
                            )
            except Exception as e:
                logger.debug(f"ESIL emulation loop scan: {e}")

    result_payload = {
        "file_path": str(safe_path),
        "total_strings_recovered": len(recovered_strings),
        "recovered_strings": recovered_strings,
        "summary": f"Recovered {len(recovered_strings)} deobfuscated strings (stack strings and emulated loops).",
    }

    return success(result_payload)
