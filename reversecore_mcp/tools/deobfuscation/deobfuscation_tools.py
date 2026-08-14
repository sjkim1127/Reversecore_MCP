"""
Deobfuscation MCP Tools.

Exposes FastMCP tools for automated string deobfuscation, API hash resolution,
opaque predicate dead code elimination, and unified deobfuscation pipelining.
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.tools.deobfuscation.api_hash_resolver import (
    resolve_api_hashes_impl,
)
from reversecore_mcp.tools.deobfuscation.dead_code_eliminator import (
    eliminate_dead_code_impl,
)
from reversecore_mcp.tools.deobfuscation.deobfuscation_pipeline import (
    run_deobfuscation_pipeline_impl,
)
from reversecore_mcp.tools.deobfuscation.string_decryptor import (
    deobfuscate_strings_impl,
)


@handle_tool_errors
async def deobfuscate_strings(
    file_path: str,
    function_address: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Recover dynamically constructed stack strings and emulated loop strings in a binary.

    Scans function basic blocks for stack stores (byte/word/dword constants) and
    micro-emulates tight loops (XOR/additive/rolling ciphers) to capture decrypted strings.

    Args:
        file_path: Path to the binary file in the workspace.
        function_address: Optional function offset or symbol (e.g. '0x140001000' or 'main').
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with recovered string list, encoding types, and function offsets.
    """
    return await deobfuscate_strings_impl(
        file_path, function_address=function_address, timeout=timeout
    )


@handle_tool_errors
async def resolve_api_hashes(
    file_path: str,
    algorithm: str | None = "auto",
    custom_hashes: dict[str, str] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Detect dynamic PEB/TEB walking and resolve 32-bit API hashes to Windows export symbols.

    Matches constants found in instructions or data sections against precomputed hash tables
    (ROR13, CRC32, MurmurHash3, FNV-1a, DJB2, SDBM) for standard Windows libraries (ntdll,
    kernel32, user32, advapi32, ws2_32, wininet, winhttp, etc.).

    Args:
        file_path: Path to the binary file to analyze.
        algorithm: Hash algorithm name ('ror13', 'crc32', 'djb2', 'fnv1a', etc.) or 'auto'.
        custom_hashes: Optional custom mapping of hash strings (e.g. '0x7c0dfcaa') to API names.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with PEB traversal indicators and list of resolved Windows APIs.
    """
    return await resolve_api_hashes_impl(
        file_path,
        algorithm=algorithm,
        custom_hashes=custom_hashes,
        timeout=timeout,
    )


@handle_tool_errors
async def eliminate_dead_code(
    file_path: str,
    function_address: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Analyze opaque predicates and identify unreachable basic blocks in a function CFG.

    Detects algebraic/constant opaque predicates (e.g. zero-flag tests, constant comparisons,
    redundant jumps) and computes effective reachable blocks to simplify control flow analysis.

    Args:
        file_path: Path to the binary file to analyze.
        function_address: Optional target function address or name (e.g. '0x140001000').
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with detected opaque predicates and simplified CFG statistics.
    """
    return await eliminate_dead_code_impl(
        file_path,
        function_address=function_address,
        timeout=timeout,
    )


@handle_tool_errors
async def run_deobfuscation_pipeline(
    file_path: str,
    options: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Run all deobfuscation engines concurrently and assemble a unified intelligence report.

    Executes stack string recovery, emulated loop decryption, API hash resolution, and
    opaque predicate dead code elimination, producing a comprehensive report with threat tags
    and detected malware capabilities.

    Args:
        file_path: Path to the binary file to analyze.
        options: Optional configuration dictionary (e.g. {'algorithm': 'ror13', 'function_address': 'main'}).
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult containing the complete deobfuscation analysis report and severity score.
    """
    return await run_deobfuscation_pipeline_impl(file_path, options=options, timeout=timeout)
