"""
Malware API Hash Resolver & PEB Walking Analyzer.

Detects dynamic API resolution patterns (PEB/TEB walking, Export Directory iteration)
and maps 32-bit constant values to known Windows API exports using precomputed hash tables
(ROR13, CRC32, MurmurHash3, FNV-1a, DJB2, SDBM).
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout, parse_json_output
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.deobfuscation.data.hash_algorithms import (
    SUPPORTED_ALGORITHMS,
    get_api_hash_db,
)

logger = get_logger(__name__)

# PEB / TEB traversal and Export Directory scanning regex patterns
_PEB_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"fs:\s*\[\s*0x30\s*\]", re.IGNORECASE), "x86 PEB Access (fs:[0x30])"),
    (re.compile(r"fs:\s*\[\s*0x18\s*\]", re.IGNORECASE), "x86 TEB Access (fs:[0x18])"),
    (re.compile(r"gs:\s*\[\s*0x60\s*\]", re.IGNORECASE), "x64 PEB Access (gs:[0x60])"),
    (re.compile(r"gs:\s*\[\s*0x30\s*\]", re.IGNORECASE), "x64 TEB Access (gs:[0x30])"),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x0?c\]", re.IGNORECASE),
        "PEB_LDR_DATA / InLoadOrderModuleList (0x0C)",
    ),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x14\]", re.IGNORECASE),
        "InMemoryOrderModuleList (0x14)",
    ),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x1c\]", re.IGNORECASE),
        "InInitializationOrderModuleList (0x1C)",
    ),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x3c\]", re.IGNORECASE),
        "e_lfanew / PE Header Offset (0x3C)",
    ),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x78\]", re.IGNORECASE),
        "Export Directory DataDirectory[0] (0x78)",
    ),
    (
        re.compile(r"\[[a-z0-9_]+\s*\+\s*0x88\]", re.IGNORECASE),
        "x64 Export Directory (0x88)",
    ),
]

# Immediate constant extraction pattern (32-bit hex constants)
_HEX_IMM_PATTERN = re.compile(r"\b0x([0-9a-fA-F]{5,8})\b")
_INT_IMM_PATTERN = re.compile(r"\b([1-9][0-9]{7,9})\b")


async def _run_r2_command(file_path: str | Path, command: str, timeout: int = 30) -> str:
    """Execute a radare2 command using async execution."""
    from reversecore_mcp.core.execution import execute_subprocess_async

    cmd = ["radare2", "-q", "-0", "-c", f"e scr.color=0; {command}", str(file_path)]
    stdout, stderr, code = await execute_subprocess_async(cmd, timeout=timeout)
    if code != 0 and not stdout:
        logger.warning(f"radare2 exited with code {code}: {stderr}")
    return stdout


@log_execution(tool_name="resolve_api_hashes")
@track_metrics(tool_name="resolve_api_hashes")
async def resolve_api_hashes_impl(
    file_path: str,
    algorithm: str | None = "auto",
    custom_hashes: dict[str, str] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Resolve obfuscated API hashes in a binary file against standard and custom hash databases.

    Args:
        file_path: Path to the binary file to analyze.
        algorithm: Specific hash algorithm ('ror13', 'crc32', 'djb2', 'fnv1a', etc.) or 'auto'.
        custom_hashes: Optional dictionary mapping hash strings (hex/dec) to API names.
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult containing detected PEB walking patterns and resolved API symbols.
    """
    safe_path = validate_file_path(file_path)
    if not safe_path.exists() or not safe_path.is_file():
        return failure("INVALID_PATH", f"Target file does not exist: {file_path}")

    calc_timeout = calculate_dynamic_timeout(safe_path, base_timeout=timeout or 45)
    db = get_api_hash_db()
    custom_hash_map: dict[int, dict[str, str]] = {}

    # Register user-supplied custom hashes if provided
    if custom_hashes and isinstance(custom_hashes, dict):
        for h_str, api_symbol in custom_hashes.items():
            try:
                h_val = int(str(h_str), 16) if str(h_str).startswith("0x") else int(str(h_str))
                dll_part = "custom.dll"
                api_part = api_symbol
                if "!" in api_symbol:
                    dll_part, api_part = api_symbol.split("!", 1)
                custom_hash_map[h_val] = {
                    "api_name": api_part,
                    "dll": dll_part,
                    "algorithm": "custom",
                    "full_symbol": f"{dll_part}!{api_part}",
                    "signature": f"{api_part}()",
                }
            except (ValueError, TypeError):
                continue

    algo_filter = None
    if algorithm and algorithm.lower() != "auto" and algorithm.lower() in SUPPORTED_ALGORITHMS:
        algo_filter = algorithm.lower()

    # Step 1: Scan disassembly for instructions and functions
    # Using 'pdfj' or 'pdrj' on all functions or scanning opcodes with 'pI'
    r2_cmd = "aa; aflj"
    afl_output = await _run_r2_command(safe_path, r2_cmd, timeout=calc_timeout)
    functions = parse_json_output(afl_output)
    if not isinstance(functions, list):
        functions = []

    peb_walking_indicators: list[dict[str, Any]] = []
    scanned_constants: set[int] = set()
    constant_locations: dict[int, list[str]] = {}

    # Step 2: Iterate over functions (or entrypoint) to extract instructions & immediate values
    func_limit = min(len(functions), 150) if functions else 0

    for i in range(func_limit):
        f = functions[i]
        offset = f.get("offset")
        if offset is None:
            continue

        pdf_output = await _run_r2_command(
            safe_path, f"pdfj @ {offset}", timeout=min(calc_timeout, 10)
        )
        pdf_data = parse_json_output(pdf_output)
        if not pdf_data or not isinstance(pdf_data, dict):
            continue

        ops = pdf_data.get("ops", [])
        for op in ops:
            disasm = op.get("disasm", "")
            op_addr = hex(op.get("offset", 0))

            # Check for PEB / TEB traversal patterns
            for pat, desc in _PEB_PATTERNS:
                if pat.search(disasm):
                    peb_walking_indicators.append(
                        {
                            "address": op_addr,
                            "instruction": disasm,
                            "pattern": desc,
                            "function": f.get("name", "unknown"),
                        }
                    )

            # Check for immediate 32-bit constants in opcode
            # Look at disasm string for hex immediates
            for match in _HEX_IMM_PATTERN.finditer(disasm):
                try:
                    val = int(match.group(0), 16)
                    if 0x10000 <= val <= 0xFFFFFFFF:
                        scanned_constants.add(val)
                        constant_locations.setdefault(val, []).append(f"{op_addr}: {disasm}")
                except ValueError:
                    pass

            for match in _INT_IMM_PATTERN.finditer(disasm):
                try:
                    val = int(match.group(0))
                    if 0x10000 <= val <= 0xFFFFFFFF:
                        scanned_constants.add(val)
                        constant_locations.setdefault(val, []).append(f"{op_addr}: {disasm}")
                except ValueError:
                    pass

    # Step 3: Also scan raw binary data for DWORDs if few instructions were found
    if len(scanned_constants) < 20:
        try:
            raw_bytes = safe_path.read_bytes()
            # Scan in 4-byte steps
            for offset in range(0, min(len(raw_bytes) - 4, 1024 * 1024), 4):
                val = struct.unpack("<I", raw_bytes[offset : offset + 4])[0]
                if 0x10000 <= val <= 0xFFFFFFFF:
                    matches = db.lookup(val, algorithm=algo_filter)
                    if matches or val in custom_hash_map:
                        scanned_constants.add(val)
                        constant_locations.setdefault(val, []).append(f"raw_offset: 0x{offset:x}")
        except Exception as e:
            logger.debug(f"Raw scanning fallback encountered error: {e}")

    # Step 4: Resolve scanned constants against Database
    resolved_apis: list[dict[str, Any]] = []
    seen_resolutions: set[tuple[int, str, str]] = set()

    for val in scanned_constants:
        matches = list(db.lookup(val, algorithm=algo_filter))
        if val in custom_hash_map:
            matches.append(custom_hash_map[val])

        for m in matches:
            key = (val, m["algorithm"], m["full_symbol"])
            if key in seen_resolutions:
                continue
            seen_resolutions.add(key)

            locs = constant_locations.get(val, [])
            resolved_apis.append(
                {
                    "hash_hex": f"0x{val:08x}",
                    "hash_dec": val,
                    "algorithm": m["algorithm"],
                    "dll": m["dll"],
                    "api_name": m["api_name"],
                    "full_symbol": m["full_symbol"],
                    "signature": m["signature"],
                    "occurrences": len(locs),
                    "locations": locs[:5],
                    "confidence": (0.95 if pe_has_peb_indicators(peb_walking_indicators) else 0.85),
                }
            )

    # Sort resolved APIs by occurrences descending
    resolved_apis.sort(key=lambda x: x["occurrences"], reverse=True)

    result_payload = {
        "file_path": str(safe_path),
        "peb_walking_detected": len(peb_walking_indicators) > 0,
        "peb_walking_indicators": peb_walking_indicators[:20],
        "total_constants_scanned": len(scanned_constants),
        "total_resolved_apis": len(resolved_apis),
        "resolved_apis": resolved_apis,
        "summary": f"Scanned {len(scanned_constants)} constants; resolved {len(resolved_apis)} API hashes with {len(peb_walking_indicators)} PEB traversal indicators.",
    }

    return success(result_payload)


def pe_has_peb_indicators(indicators: list[dict[str, Any]]) -> bool:
    """Return True if any PEB or TEB indicators are detected."""
    return len(indicators) > 0
