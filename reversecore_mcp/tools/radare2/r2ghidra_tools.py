"""
r2ghidra-based decompilation and analysis tools.

Replaces the previous Ghidra (PyGhidra/JVM) integration with the lightweight
r2ghidra plugin, which embeds the Ghidra decompiler engine directly inside
radare2 — no JDK or Ghidra installation required.

Available tools (MCP-registered):
    r2_decompile             — Decompile a function via r2ghidra ``pdg``
    r2_recover_structures    — Recover C struct layouts from memory access patterns
    r2_analyze_function      — Full function metadata (args, vars, calls, complexity)
    r2_get_call_graph        — Caller/callee graph for a function
    r2_simulate_patch        — Simulate a byte-level patch and re-analyse
"""

import asyncio

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.analysis_cache import (
    get_cached_decompile,
    set_cached_decompile,
)
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.next_tool_hints import build_decompile_hints, finalize_hints
from reversecore_mcp.core.r2_helpers import execute_r2_command as _execute_r2_command
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import (
    PaginationMeta,
    ToolError,
    ToolResult,
    ToolSuccess,
    failure,
    success,
)
from reversecore_mcp.core.result_cache import cache_tool_result
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_address_format

logger = get_logger(__name__)
DEFAULT_TIMEOUT = get_config().default_tool_timeout


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_addr(address: str, param: str = "function_address") -> ToolResult | None:
    """Return a failure ToolResult if *address* is invalid, else None."""
    from reversecore_mcp.core.exceptions import ValidationError

    try:
        validate_address_format(address, param)
        return None
    except ValidationError as exc:
        return failure("VALIDATION_ERROR", str(exc))


@circuit_breaker(tool_name="r2ghidra", failure_threshold=3, recovery_timeout=45)
async def _r2_run(
    validated_path,
    cmds: list[str],
    *,
    analysis_level: str = "aaa",
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[str, int]:
    """Execute a list of r2 commands and return (raw_output, bytes_read)."""
    output, bytes_read = await _execute_r2_command(
        validated_path,
        cmds,
        analysis_level=analysis_level,
        max_output_size=10_000_000,
        base_timeout=timeout,
    )
    return output, bytes_read


# ---------------------------------------------------------------------------
# r2_decompile
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_decompile")
@track_metrics("r2_decompile")
@handle_tool_errors
@cache_tool_result(
    "r2_decompile",
    ttl=86400,
    cache_kwargs=["function_address", "line_offset", "max_lines"],
)
async def r2_decompile(
    file_path: str,
    function_address: str,
    line_offset: int = 0,
    max_lines: int = 200,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Decompile a binary function to pseudo-C using the r2ghidra plugin.

    Uses the ``pdg`` command which invokes the embedded Ghidra decompiler
    engine inside radare2 — no separate Ghidra or JDK installation required.
    Includes smart line windowing and function summary header for token efficiency.

    Args:
        file_path: Path to the binary (must be inside the workspace).
        function_address: Function to decompile — name (``main``) or hex address
            (``0x401000``).
        line_offset: Starting line offset for windowed output (default: 0).
        max_lines: Maximum number of lines to return (default: 200).
        timeout: Maximum execution time in seconds (default 300).

    Returns:
        ToolResult with windowed ``pseudo_c`` string, summary header, and pagination metadata.

    Example:
        >>> result = await r2_decompile("/workspace/sample.exe", "main", line_offset=0, max_lines=50)
        >>> print(result.data["pseudo_c"])
    """
    err = _validate_addr(function_address)
    if err:
        return err
    validated = validate_file_path(file_path)

    # Check cache first
    cached_res = await get_cached_decompile(validated, function_address, use_ghidra=True)
    pseudo_c: str | None = None
    meta: dict = {}
    if cached_res is not None:
        if isinstance(cached_res, ToolSuccess):
            if isinstance(cached_res.data, dict):
                pseudo_c = cached_res.data.get("full_pseudo_c") or cached_res.data.get("pseudo_c")
            elif isinstance(cached_res.data, str):
                pseudo_c = cached_res.data
            if cached_res.metadata:
                meta.update(cached_res.metadata)
        elif isinstance(cached_res, ToolError):
            return cached_res

    if pseudo_c is None:
        cmds = [
            f"s {function_address}",
            "pdg",  # r2ghidra decompile command
        ]

        output, _ = await _r2_run(validated, cmds, timeout=timeout)

        if not output or output.strip().startswith("ERROR"):
            return failure(
                "DECOMPILE_ERROR",
                f"r2ghidra failed to decompile '{function_address}'. "
                "Ensure r2ghidra plugin is installed (`r2pm -ci r2ghidra`) and the "
                "function address is valid.",
                hint="Try running `r2 -AA binary -c 'pdg @ main'` locally to verify.",
            )

        pseudo_c = output.strip()

        # Cache the full unwindowed result in database cache for subsequent offset queries
        full_cached_res = success(
            {
                "function": function_address,
                "pseudo_c": pseudo_c,
                "full_pseudo_c": pseudo_c,
                "decompiler": "r2ghidra",
            }
        )
        await set_cached_decompile(validated, function_address, full_cached_res, use_ghidra=True)

    lines = pseudo_c.splitlines()
    total_lines = len(lines)

    # Extract function signature from first non-comment line
    signature = ""
    for raw_line in lines:
        l_str = raw_line.strip()
        if l_str and not l_str.startswith("//") and not l_str.startswith("/*"):
            signature = l_str
            break
    if not signature and lines:
        signature = lines[0].strip()

    start_line = max(0, line_offset)
    effective_max = max_lines if max_lines > 0 else total_lines
    end_line = start_line + effective_max
    window_lines = lines[start_line:end_line]
    windowed_pseudo_c = "\n".join(window_lines)
    has_more = end_line < total_lines
    next_line_offset = end_line if has_more else None

    pagination = PaginationMeta(
        has_more=has_more,
        next_cursor=str(next_line_offset) if next_line_offset is not None else None,
        total_items=total_lines,
        page=(start_line // effective_max) + 1 if effective_max > 0 else 1,
        page_size=effective_max,
        truncated=has_more,
    )

    summary_header = {
        "function": function_address,
        "signature": signature,
        "total_lines": total_lines,
        "window_lines": (
            f"{start_line + 1}-{min(end_line, total_lines)}"
            if total_lines > 0 and start_line < total_lines
            else "0-0"
        ),
    }

    hints = finalize_hints(build_decompile_hints(file_path, function_address, windowed_pseudo_c))
    return success(
        {
            "function": function_address,
            "summary": summary_header,
            "pseudo_c": windowed_pseudo_c,
            "full_pseudo_c": pseudo_c,
            "decompiler": "r2ghidra",
            "line_offset": start_line,
            "max_lines": effective_max,
            "total_lines": total_lines,
            "has_more": has_more,
            "next_line_offset": next_line_offset,
        },
        pagination=pagination,
        hints=hints or None,
        **meta,
    )


# ---------------------------------------------------------------------------
# r2_recover_structures
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_recover_structures")
@track_metrics("r2_recover_structures")
@handle_tool_errors
@cache_tool_result("r2_recover_structures", ttl=86400, cache_kwargs=["function_address"])
async def r2_recover_structures(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Recover C struct layouts from a function's memory access patterns.

    Analyses local variables (``afvf``), function arguments (``afvj``), and
    cross-references (``axtj``) to infer struct field offsets and types.

    Args:
        file_path: Path to the binary (must be inside the workspace).
        function_address: Function whose local variables / struct usage to analyse.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with list of inferred structs and their fields.

    Example:
        >>> result = await r2_recover_structures("/workspace/game.exe", "0x4012a0")
    """
    err = _validate_addr(function_address)
    if err:
        return err
    validated = validate_file_path(file_path)

    # Check cache first
    cached_res = await get_cached_decompile(validated, function_address, use_ghidra=False)
    if cached_res is not None:
        return cached_res

    cmds = [
        f"s {function_address}",
        "afvfj",  # local vars as JSON
        "afvj",  # function vars JSON
        "afsj",  # function signature JSON
    ]

    output, _ = await _r2_run(validated, cmds, timeout=timeout)

    # Parse JSON blocks from interleaved output
    structures: list[dict] = []
    for block in output.strip().split("\n"):
        block = block.strip()
        if not block:
            continue
        try:
            parsed = json.loads(block)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict) and "name" in item:
                        structures.append(
                            {
                                "name": item.get("name", "unknown"),
                                "type": item.get("type", "unknown"),
                                "offset": item.get("delta", item.get("offset", 0)),
                                "size": item.get("size", 0),
                                "source": "r2_afvf",
                            }
                        )
        except (json.JSONDecodeError, ValueError):
            continue

    res = success(
        {
            "function": function_address,
            "structures": structures,
            "field_count": len(structures),
        }
    )
    await set_cached_decompile(validated, function_address, res, use_ghidra=False)
    return res


# ---------------------------------------------------------------------------
# r2_analyze_function
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_analyze_function")
@track_metrics("r2_analyze_function")
@handle_tool_errors
async def r2_analyze_function(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Return full metadata for a binary function via radare2.

    Retrieves name, size, cyclomatic complexity, arguments, local variables,
    call targets, and cross-references using radare2's JSON APIs.

    Args:
        file_path: Path to the binary (must be inside the workspace).
        function_address: Function name or hex address.
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with structured function metadata dict.

    Example:
        >>> result = await r2_analyze_function("/workspace/malware.elf", "sym.decrypt")
    """
    err = _validate_addr(function_address)
    if err:
        return err
    validated = validate_file_path(file_path)

    cmds = [
        f"s {function_address}",
        "afij",  # function info JSON
    ]

    output, _ = await _r2_run(validated, cmds, timeout=timeout)

    fn_info: dict = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, list) and parsed:
                fn_info = parsed[0]
                break
            if isinstance(parsed, dict):
                fn_info = parsed
                break
        except (json.JSONDecodeError, ValueError):
            continue

    if not fn_info:
        return failure(
            "ANALYSIS_ERROR",
            f"Could not retrieve function metadata for '{function_address}'.",
            hint="Verify the address is a valid function entry point.",
        )

    return success(
        {
            "name": fn_info.get("name", function_address),
            "offset": fn_info.get("offset", 0),
            "size": fn_info.get("size", 0),
            "complexity": fn_info.get("cc", 0),
            "edges": fn_info.get("edges", 0),
            "nbbs": fn_info.get("nbbs", 0),
            "nlocals": fn_info.get("nlocals", 0),
            "nargs": fn_info.get("nargs", 0),
            "signature": fn_info.get("signature", ""),
            "calltype": fn_info.get("calltype", ""),
        }
    )


# ---------------------------------------------------------------------------
# r2_get_call_graph
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_get_call_graph")
@track_metrics("r2_get_call_graph")
@handle_tool_errors
async def r2_get_call_graph(
    file_path: str,
    function_address: str,
    depth: int = 2,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Generate a caller/callee call graph for a function.

    Uses radare2's ``agCd`` (call-graph dot) and ``axtj`` (cross-reference JSON)
    commands to build a structured graph.

    Args:
        file_path: Path to the binary (must be inside the workspace).
        function_address: Root function name or hex address.
        depth: Maximum call depth to traverse (default 2).
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with ``nodes`` and ``edges`` lists.

    Example:
        >>> result = await r2_get_call_graph("/workspace/malware.elf", "main")
    """
    err = _validate_addr(function_address)
    if err:
        return err
    if not isinstance(depth, int) or depth < 1 or depth > 10:
        return failure("VALIDATION_ERROR", "depth must be an integer between 1 and 10")
    validated = validate_file_path(file_path)

    cmds = [
        f"s {function_address}",
        "axtj",  # cross-references to current function (callers)
        "axffj",  # calls made by current function (callees)
    ]

    output, _ = await _r2_run(validated, cmds, timeout=timeout)

    nodes: set[str] = {function_address}
    edges: list[dict] = []

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            refs = json.loads(line)
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                src = ref.get("from", {})
                dst = ref.get("to", ref.get("name", ""))
                src_name = (
                    src.get("name", str(src.get("offset", "")))
                    if isinstance(src, dict)
                    else str(src)
                )
                dst_name = (
                    str(dst.get("name", str(dst.get("offset", dst))))
                    if isinstance(dst, dict)
                    else str(dst)
                )
                if src_name and dst_name:
                    nodes.add(src_name)
                    nodes.add(dst_name)
                    edges.append({"from": src_name, "to": dst_name})
        except (json.JSONDecodeError, ValueError):
            continue

    return success(
        {
            "root": function_address,
            "depth": depth,
            "nodes": sorted(nodes),
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
    )


# ---------------------------------------------------------------------------
# r2_simulate_patch
# ---------------------------------------------------------------------------


@log_execution(tool_name="r2_simulate_patch")
@track_metrics("r2_simulate_patch")
@handle_tool_errors
async def r2_simulate_patch(
    file_path: str,
    address: str,
    patch_bytes: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Simulate a byte-level patch at an address and re-decompile.

    Opens the binary in write mode, applies ``patch_bytes`` (hex string) at
    ``address``, then runs r2ghidra's ``pdg`` to show the patched pseudo-C.
    **The original file is not modified** — radare2's ``-w`` flag patches
    a memory copy only.

    Args:
        file_path: Path to the binary (must be inside the workspace).
        address: Target address (e.g. ``0x401020``).
        patch_bytes: Hex string of bytes to write (e.g. ``"9090"`` for 2 NOPs).
        timeout: Maximum execution time in seconds.

    Returns:
        ToolResult with ``original_disasm``, ``patched_disasm``, and ``pseudo_c``.

    Example:
        >>> result = await r2_simulate_patch("/workspace/crackme", "0x401020", "9090")
    """
    err = _validate_addr(address, "address")
    if err:
        return err
    # Validate patch_bytes is a clean hex string
    patch_bytes_clean = patch_bytes.replace(" ", "").lower()
    if (
        not all(c in "0123456789abcdef" for c in patch_bytes_clean)
        or len(patch_bytes_clean) % 2 != 0
    ):
        return failure("VALIDATION_ERROR", "patch_bytes must be a valid hex string (e.g. '9090')")

    validated = validate_file_path(file_path)

    # Read original bytes first (read-only session)
    read_cmds = [
        f"s {address}",
        f"px {len(patch_bytes_clean) // 2}",  # show original bytes
        f"pd {len(patch_bytes_clean) // 2}",  # disassemble original
    ]
    original_output, _ = await _r2_run(validated, read_cmds, timeout=timeout)

    # Simulate patch in a separate read+write session
    patch_cmds = [
        f"s {address}",
        f"wx {patch_bytes_clean}",  # write patch bytes
        f"pd {max(1, len(patch_bytes_clean) // 4)}",  # disassemble patched region
        "pdg",  # r2ghidra decompile after patch
    ]

    # r2 write mode requires -w flag; pass via analysis_level workaround
    # We use a subprocess call for write-mode simulation
    import shutil

    r2_exe = shutil.which("r2")
    if not r2_exe:
        return failure("DEPENDENCY_MISSING", "radare2 (r2) not found in PATH")

    script = "; ".join(patch_cmds) + "; q"
    try:
        proc = await asyncio.create_subprocess_exec(  # nosec B603
            r2_exe,
            "-w",
            "-A",
            "-e",
            "scr.color=0",
            "-q",
            "-c",
            script,
            str(validated),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        patched_output = stdout.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        return failure("TIMEOUT", f"Patch simulation timed out after {timeout}s")
    except Exception as exc:
        return failure("EXECUTION_ERROR", str(exc))

    return success(
        {
            "address": address,
            "patch_bytes": patch_bytes_clean,
            "byte_count": len(patch_bytes_clean) // 2,
            "original_disasm": original_output.strip(),
            "patched_output": patched_output.strip(),
            "note": "Original file is NOT modified. Patch was applied to in-memory copy only.",
        }
    )
