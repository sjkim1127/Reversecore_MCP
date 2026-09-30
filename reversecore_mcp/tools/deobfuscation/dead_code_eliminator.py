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
MAX_LINEAR_SWEEP_SIZE = 1024 * 1024

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


def _coerce_address(value: Any) -> int | None:
    """Parse a Radare2 address value from JSON."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None

    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 16)
        except ValueError:
            return None


def _get_address(item: dict[str, Any], *keys: str) -> int | None:
    """Read an address from Radare2's ``offset`` or ``addr`` fields."""
    for key in keys:
        address = _coerce_address(item.get(key))
        if address is not None:
            return address
    return None


def _format_address(address: int | None, fallback: Any = None) -> str | None:
    """Format an address as hexadecimal, preserving symbolic fallbacks."""
    if address is not None:
        return hex(address)
    if fallback is None:
        return None
    return str(fallback)


def _find_unreachable_blocks(
    blocks: list[Any], function_entry: Any, function_name: str
) -> tuple[list[dict[str, Any]], str | None, int]:
    """Return basic blocks not reachable through Radare2's CFG edges."""
    blocks_by_address: dict[int, dict[str, Any]] = {}
    for block in blocks:
        if not isinstance(block, dict):
            continue
        address = _get_address(block, "offset", "addr")
        if address is not None:
            blocks_by_address.setdefault(address, block)

    if not blocks_by_address:
        return [], _format_address(_coerce_address(function_entry), function_entry), 0

    entry_address = _coerce_address(function_entry)
    if entry_address not in blocks_by_address:
        entry_address = min(blocks_by_address)

    successors: dict[int, set[int]] = {address: set() for address in blocks_by_address}
    predecessors: dict[int, set[int]] = {address: set() for address in blocks_by_address}
    for address, block in blocks_by_address.items():
        for edge_name in ("jump", "fail"):
            target = _coerce_address(block.get(edge_name))
            if target in blocks_by_address:
                successors[address].add(target)
                predecessors[target].add(address)

    reachable = {entry_address}
    pending = [entry_address]
    while pending:
        current = pending.pop()
        for target in successors[current] - reachable:
            reachable.add(target)
            pending.append(target)

    dead_blocks = []
    for address in sorted(blocks_by_address.keys() - reachable):
        block = blocks_by_address[address]
        outgoing = sorted(successors[address])
        incoming = sorted(predecessors[address])
        dead_blocks.append(
            {
                "function": function_name,
                "address": hex(address),
                "type": "unreachable_basic_block",
                "reason": "No path from the function entry reaches this basic block.",
                "size": block.get("size"),
                "evidence": {
                    "entry_address": hex(entry_address),
                    "incoming_edges": [hex(source) for source in incoming],
                    "outgoing_edges": [hex(target) for target in outgoing],
                },
            }
        )

    return dead_blocks, hex(entry_address), len(blocks_by_address)


def _find_unreachable_linear_blocks(
    blocks: list[Any],
    linear_ops: list[Any],
    known_dead_blocks: list[dict[str, Any]],
    function_entry: Any,
    function_name: str,
) -> list[dict[str, Any]]:
    """Find code decoded linearly but omitted from the reachable CFG."""
    dead_block_addresses = {
        address
        for dead_block in known_dead_blocks
        if (address := _coerce_address(dead_block.get("address"))) is not None
    }
    reachable_instruction_addresses: set[int] = set()
    reachable_ranges: list[tuple[int, int]] = []
    dead_ranges: list[tuple[int, int]] = []

    for block in blocks:
        if not isinstance(block, dict):
            continue
        address = _get_address(block, "offset", "addr")
        size = block.get("size")
        if address is None:
            continue

        is_known_dead = address in dead_block_addresses
        if isinstance(size, int) and size > 0:
            block_range = (address, address + size)
            (dead_ranges if is_known_dead else reachable_ranges).append(block_range)
        if is_known_dead:
            continue

        instructions = block.get("instrs")
        if isinstance(instructions, list):
            reachable_instruction_addresses.update(
                instruction_address
                for instruction in instructions
                if (instruction_address := _coerce_address(instruction)) is not None
            )

    def is_reachable(address: int) -> bool:
        return address in reachable_instruction_addresses or any(
            start <= address < end for start, end in reachable_ranges
        )

    decoded_ops = []
    for op in linear_ops:
        if not isinstance(op, dict):
            continue
        address = _get_address(op, "offset", "addr")
        size = op.get("size")
        if address is None or not isinstance(size, int) or size <= 0:
            continue
        decoded_ops.append((address, op))
    decoded_ops.sort(key=lambda item: item[0])

    dead_ops = [
        (address, op)
        for address, op in decoded_ops
        if not is_reachable(address)
        and address not in dead_block_addresses
        and not any(start <= address < end for start, end in dead_ranges)
    ]
    if not dead_ops:
        return []

    branch_targets = {
        target
        for _address, op in decoded_ops
        for target in (_coerce_address(op.get("jump")), _coerce_address(op.get("fail")))
        if target is not None
    }
    terminators = {"jmp", "ujmp", "ijmp", "cjmp", "rcjmp", "ret", "trap"}
    dead_blocks: list[dict[str, Any]] = []
    current: list[tuple[int, dict[str, Any]]] = []

    def flush_current() -> None:
        if not current:
            return
        first_address = current[0][0]
        size = sum(op["size"] for _address, op in current)
        instruction_evidence = [
            {
                "address": hex(address),
                "size": op["size"],
                "type": op.get("type"),
                "instruction": op.get("disasm", ""),
            }
            for address, op in current
        ]
        incoming_edges = []
        for source_address, source_op in decoded_ops:
            for edge_name in ("jump", "fail"):
                if _coerce_address(source_op.get(edge_name)) == first_address:
                    incoming_edges.append(
                        {
                            "source_address": hex(source_address),
                            "edge": edge_name,
                            "source_reachable": is_reachable(source_address),
                        }
                    )

        dead_blocks.append(
            {
                "function": function_name,
                "address": hex(first_address),
                "type": "unreachable_basic_block",
                "reason": (
                    "Linear disassembly found this block within the function, but no "
                    "reachable CFG block contains its instructions."
                ),
                "size": size,
                "evidence": {
                    "entry_address": _format_address(
                        _coerce_address(function_entry), function_entry
                    ),
                    "incoming_edges": incoming_edges,
                    "instructions": instruction_evidence,
                },
            }
        )
        current.clear()

    for address, op in dead_ops:
        if current:
            previous_address, previous_op = current[-1]
            previous_end = previous_address + previous_op["size"]
            if (
                address != previous_end
                or address in branch_targets
                or previous_op.get("type") in terminators
            ):
                flush_current()

        current.append((address, op))
        if op.get("type") in terminators:
            flush_current()

    flush_current()
    return dead_blocks


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
        target_function_output = await _run_r2_command(
            safe_path,
            f"af @ {function_address}; afij @ {function_address}",
            timeout=min(calc_timeout, 10),
        )
        target_function = parse_json_output(target_function_output)
        if isinstance(target_function, list) and target_function:
            functions = target_function
        elif isinstance(target_function, dict) and target_function:
            functions = [target_function]
        else:
            functions = [{"offset": function_address, "name": str(function_address)}]
    else:
        afl_output = await _run_r2_command(safe_path, "aa; aflj", timeout=calc_timeout)
        functions = parse_json_output(afl_output) or []

    func_limit = min(len(functions), 50) if functions else 0

    opaque_predicates: list[dict[str, Any]] = []
    dead_blocks_total: list[dict[str, Any]] = []
    redundant_jumps_total: list[dict[str, Any]] = []
    cfg_simplifications: list[dict[str, Any]] = []
    linear_sweep_skipped_functions: list[dict[str, Any]] = []

    for i in range(func_limit):
        f = functions[i]
        f_offset: Any = f.get("offset")
        if f_offset is None:
            f_offset = f.get("addr")
        f_name = f.get("name", "func")
        if f_offset is None:
            continue

        # Radare2 runs in a fresh process for every command, so analyze the
        # requested function before querying its CFG.
        afb_output = await _run_r2_command(
            safe_path,
            f"af @ {f_offset}; afbj @ {f_offset}",
            timeout=min(calc_timeout, 10),
        )
        blocks = parse_json_output(afb_output) or []
        if not blocks or not isinstance(blocks, list):
            linear_sweep_skipped_functions.append(
                {"function": f_name, "reason": "Radare2 returned no basic blocks."}
            )
            continue

        dead_blocks_in_func, normalized_entry, total_blocks = _find_unreachable_blocks(
            blocks, f_offset, f_name
        )
        dead_blocks_total.extend(dead_blocks_in_func)

        function_size = _coerce_address(f.get("size"))
        linear_ops: list[Any] = []
        if function_size is None or function_size <= 0:
            linear_sweep_skipped_functions.append(
                {
                    "function": f_name,
                    "reason": "Radare2 did not report a function size.",
                }
            )
        elif function_size > MAX_LINEAR_SWEEP_SIZE:
            linear_sweep_skipped_functions.append(
                {
                    "function": f_name,
                    "size": function_size,
                    "reason": f"Function exceeds the {MAX_LINEAR_SWEEP_SIZE}-byte linear sweep limit.",
                }
            )
        else:
            linear_output = await _run_r2_command(
                safe_path,
                f"pDj {function_size} @ {f_offset}",
                timeout=min(calc_timeout, 10),
            )
            parsed_linear_ops = parse_json_output(linear_output)
            if isinstance(parsed_linear_ops, list):
                linear_ops = parsed_linear_ops
            else:
                linear_sweep_skipped_functions.append(
                    {
                        "function": f_name,
                        "reason": "Radare2 linear disassembly returned no instruction list.",
                    }
                )

        linear_dead_blocks = _find_unreachable_linear_blocks(
            blocks, linear_ops, dead_blocks_in_func, f_offset, f_name
        )
        dead_blocks_in_func.extend(linear_dead_blocks)
        dead_blocks_total.extend(linear_dead_blocks)
        total_blocks += len(linear_dead_blocks)

        # Get disassembly for full function to find opaque patterns
        pdf_output = await _run_r2_command(
            safe_path,
            f"af @ {f_offset}; pdfj @ {f_offset}",
            timeout=min(calc_timeout, 10),
        )
        pdf_data = parse_json_output(pdf_output)
        ops = pdf_data.get("ops", []) if isinstance(pdf_data, dict) else []
        if not isinstance(ops, list):
            ops = []

        disasm_lines: list[str] = []
        for op in ops:
            if not isinstance(op, dict):
                continue
            op_address = _get_address(op, "offset", "addr")
            address_text = _format_address(op_address, "0x0")
            disasm_lines.append(f"{address_text}: {op.get('disasm', '')}")

        full_disasm_text = "\n".join(disasm_lines)
        opaque_predicates_in_func: list[dict[str, Any]] = []
        redundant_jumps_in_func: list[dict[str, Any]] = []

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
                    else _format_address(_coerce_address(f_offset), f_offset)
                )

                opaque_predicates_in_func.append(
                    {
                        "address": addr_str,
                        "function": f_name,
                        "type": p_name,
                        "invariant": invariant_desc,
                        "instruction_sequence": matched_snippet.replace("\n", " | "),
                    }
                )

        # Check for consecutive redundant jumps: jmp $+5 / jmp next_addr
        for op in ops:
            if not isinstance(op, dict):
                continue
            op_address = _get_address(op, "offset", "addr")
            jump_target = _coerce_address(op.get("jump"))
            op_size = op.get("size")
            if (
                op.get("type") == "jmp"
                and op_address is not None
                and isinstance(op_size, int)
                and jump_target == op_address + op_size
            ):
                redundant_jumps_in_func.append(
                    {
                        "address": hex(op_address),
                        "function": f_name,
                        "type": "redundant_jump",
                        "reason": "Unconditional jump targets the next instruction.",
                        "evidence": {
                            "instruction": op.get("disasm", ""),
                            "instruction_size": op_size,
                            "jump_target": hex(jump_target),
                        },
                    }
                )

        opaque_predicates.extend(opaque_predicates_in_func)
        redundant_jumps_total.extend(redundant_jumps_in_func)

        if dead_blocks_in_func or opaque_predicates_in_func or redundant_jumps_in_func:
            effective_blocks = max(1, total_blocks - len(dead_blocks_in_func))
            reduction_pct = round(
                ((total_blocks - effective_blocks) / max(total_blocks, 1)) * 100, 1
            )
            cfg_simplifications.append(
                {
                    "function": f_name,
                    "address": normalized_entry,
                    "original_blocks": total_blocks,
                    "effective_blocks": effective_blocks,
                    "unreachable_blocks": len(dead_blocks_in_func),
                    "opaque_predicates": len(opaque_predicates_in_func),
                    "redundant_jumps": len(redundant_jumps_in_func),
                    "reduction_percent": f"{reduction_pct}%",
                }
            )

    total_opaque_predicates = len(opaque_predicates)
    total_dead_blocks = len(dead_blocks_total)
    total_redundant_jumps = len(redundant_jumps_total)
    summary_counts = {
        "opaque_predicates": total_opaque_predicates,
        "dead_blocks": total_dead_blocks,
        "redundant_jumps": total_redundant_jumps,
    }

    summary = (
        f"Detected {total_opaque_predicates} opaque predicates, {total_dead_blocks} "
        f"unreachable dead blocks, and {total_redundant_jumps} redundant jumps across "
        f"{len(cfg_simplifications)} function CFGs."
    )
    if linear_sweep_skipped_functions:
        summary += (
            f" Linear unreachable-block scanning was skipped for "
            f"{len(linear_sweep_skipped_functions)} function(s)."
        )

    result_payload = {
        "file_path": str(safe_path),
        "total_opaque_predicates": total_opaque_predicates,
        "total_dead_blocks": total_dead_blocks,
        "total_redundant_jumps": total_redundant_jumps,
        "opaque_predicates": opaque_predicates,
        "dead_blocks": dead_blocks_total,
        "redundant_jumps": redundant_jumps_total,
        "cfg_simplifications": cfg_simplifications,
        "summary_counts": summary_counts,
        "analysis_complete": not linear_sweep_skipped_functions,
        "linear_sweep_skipped_functions": linear_sweep_skipped_functions,
        "summary": summary,
    }

    return success(result_payload)
