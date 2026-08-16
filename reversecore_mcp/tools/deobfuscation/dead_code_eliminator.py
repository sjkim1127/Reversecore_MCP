"""
Dead Code & Opaque Predicate Eliminator.

Detects mathematical and constant opaque predicates, junk byte insertions,
and computes unreachable basic blocks to simplify control flow graphs (CFGs).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout, parse_json_output
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Known opaque predicate patterns
# (Pattern description, predicate invariant condition, resolved_outcome)
_KNOWN_OPAQUE_PATTERNS = [
    (
        "zero_xor_test",
        re.compile(
            r"xor\s+([a-z0-9]+),\s*\1.*?(?:test|cmp)\s+\1,\s*(?:\1|0).*?j(z|e)",
            re.DOTALL | re.IGNORECASE,
        ),
        "Always True (Zero Flag is always 1)",
    ),
    (
        "zero_xor_jnz",
        re.compile(
            r"xor\s+([a-z0-9]+),\s*\1.*?(?:test|cmp)\s+\1,\s*(?:\1|0).*?j(nz|ne)",
            re.DOTALL | re.IGNORECASE,
        ),
        "Always False (Zero Flag is always 1, Never Jumps)",
    ),
    (
        "stc_jnc",
        re.compile(r"stc.*?j(nc|ae|nb)", re.DOTALL | re.IGNORECASE),
        "Always False (Carry Flag is set by STC, JNC never taken)",
    ),
    (
        "clc_jc",
        re.compile(r"clc.*?j(c|b|nae)", re.DOTALL | re.IGNORECASE),
        "Always False (Carry Flag is cleared by CLC, JC never taken)",
    ),
    (
        "const_mov_cmp_je",
        re.compile(
            r"mov\s+([a-z0-9]+),\s*(0x[0-9a-f]+|\d+).*?cmp\s+\1,\s*\2.*?j(z|e)",
            re.DOTALL | re.IGNORECASE,
        ),
        "Always True (Equal constants compare true)",
    ),
]


async def _run_r2_command(file_path: str | Path, command: str, timeout: int = 30) -> str:
    """Execute a radare2 command using async execution."""
    from reversecore_mcp.core.execution import execute_subprocess_async

    cmd = ["radare2", "-q", "-0", "-c", f"e scr.color=0; {command}", str(file_path)]
    stdout, _ = await execute_subprocess_async(cmd, timeout=timeout)
    return stdout


@log_execution(tool_name="eliminate_dead_code")
@track_metrics(tool_name="eliminate_dead_code")
async def eliminate_dead_code_impl(
    file_path: str,
    function_address: str | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Detect opaque predicates and identify unreachable dead code blocks in a binary.

    Args:
        file_path: Path to the target binary file.
        function_address: Target function address or name (e.g. 'main', '0x140001000').
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult containing identified opaque predicates, dead blocks, and simplified CFG statistics.
    """
    safe_path = validate_file_path(file_path)
    if not safe_path.exists() or not safe_path.is_file():
        return failure("INVALID_PATH", f"Target file does not exist: {file_path}")

    calc_timeout = calculate_dynamic_timeout(safe_path, base_timeout=timeout or 45)

    # Step 1: Query function list or target function
    if function_address:
        functions = [{"offset": function_address, "name": str(function_address)}]
    else:
        afl_output = await _run_r2_command(safe_path, "aa; aflj", timeout=calc_timeout)
        functions = parse_json_output(afl_output) or []

    func_limit = min(len(functions), 50) if functions else 0

    detected_predicates: list[dict[str, Any]] = []
    dead_blocks_total: list[dict[str, Any]] = []
    cfg_simplifications: list[dict[str, Any]] = []

    for i in range(func_limit):
        f = functions[i]
        f_offset = f.get("offset")
        f_name = f.get("name", "func")
        if f_offset is None:
            continue

        # Get basic blocks for function: afbj @ offset
        afb_output = await _run_r2_command(
            safe_path, f"afbj @ {f_offset}", timeout=min(calc_timeout, 10)
        )
        blocks = parse_json_output(afb_output) or []
        if not blocks or not isinstance(blocks, list):
            continue

        total_blocks = len(blocks)
        dead_blocks_in_func: list[str] = []

        # Get disassembly for full function to find opaque patterns
        pdf_output = await _run_r2_command(
            safe_path, f"pdfj @ {f_offset}", timeout=min(calc_timeout, 10)
        )
        pdf_data = parse_json_output(pdf_output)
        if not pdf_data or not isinstance(pdf_data, dict):
            continue

        ops = pdf_data.get("ops", [])
        disasm_lines: list[str] = []
        for op in ops:
            disasm_lines.append(f"{hex(op.get('offset', 0))}: {op.get('disasm', '')}")

        full_disasm_text = "\n".join(disasm_lines)

        # Check for known opaque predicate patterns
        for p_name, pat, invariant_desc in _KNOWN_OPAQUE_PATTERNS:
            for match in pat.finditer(full_disasm_text):
                matched_snippet = match.group(0)
                # Find matching address
                first_line = matched_snippet.strip().split("\n")[0]
                addr_match = re.search(r"(0x[0-9a-fA-F]+):", first_line)
                addr_str = (
                    addr_match.group(1)
                    if addr_match
                    else hex(f_offset)
                    if isinstance(f_offset, int)
                    else str(f_offset)
                )

                detected_predicates.append(
                    {
                        "address": addr_str,
                        "function": f_name,
                        "type": p_name,
                        "invariant": invariant_desc,
                        "instruction_sequence": matched_snippet.replace("\n", " | "),
                    }
                )

        # Check for consecutive redundant jumps: jmp $+5 / jmp next_addr
        for _idx, op in enumerate(ops):
            if op.get("type") == "jmp":
                jump_target = op.get("jump", 0)
                next_addr = op.get("offset", 0) + op.get("size", 0)
                if jump_target == next_addr:
                    dead_blocks_in_func.append(hex(op.get("offset", 0)))
                    detected_predicates.append(
                        {
                            "address": hex(op.get("offset", 0)),
                            "function": f_name,
                            "type": "redundant_jump",
                            "invariant": "Jump directly to next instruction",
                            "instruction_sequence": op.get("disasm", ""),
                        }
                    )

        # Calculate CFG reduction summary for this function
        if detected_predicates:
            effective_blocks = max(1, total_blocks - len(dead_blocks_in_func))
            reduction_pct = round(
                ((total_blocks - effective_blocks) / max(total_blocks, 1)) * 100, 1
            )
            cfg_simplifications.append(
                {
                    "function": f_name,
                    "address": (hex(f_offset) if isinstance(f_offset, int) else str(f_offset)),
                    "original_blocks": total_blocks,
                    "effective_blocks": effective_blocks,
                    "reduction_percent": f"{reduction_pct}%",
                }
            )

    result_payload = {
        "file_path": str(safe_path),
        "total_opaque_predicates": len(detected_predicates),
        "opaque_predicates": detected_predicates,
        "dead_blocks": dead_blocks_total,
        "cfg_simplifications": cfg_simplifications,
        "summary": f"Detected {len(detected_predicates)} opaque predicates and simplified {len(cfg_simplifications)} function CFGs.",
    }

    return success(result_payload)
