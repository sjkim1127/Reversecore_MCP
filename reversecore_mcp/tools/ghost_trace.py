"""
Ghost Trace: Hybrid Reverse Engineering Tool.

This tool combines static analysis and partial emulation to detect hidden malicious behaviors
(Logic Bombs, Dormant Malware) that are often missed by traditional dynamic analysis.
"""

import os
import re
from pathlib import Path
from typing import Any

from async_lru import alru_cache
from fastmcp import Context, FastMCP

from reversecore_mcp.core import json_utils as json  # Use optimized JSON (3-5x faster)
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# OPTIMIZATION: Pre-compile regex patterns used in hot paths
_JSON_ARRAY_PATTERN = re.compile(r"\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]", re.DOTALL)
_JSON_OBJECT_PATTERN = re.compile(r"\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}", re.DOTALL)
_NESTED_JSON_PATTERN = re.compile(r"\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}", re.DOTALL)
_HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
_SYMBOL_PATTERN = re.compile(r"^sym\.[a-zA-Z0-9_\.]+$")
_FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_REG_PATTERN = re.compile(r"^[a-z0-9]+$")
_VALUE_PATTERN = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")


def _extract_json_safely(output: str) -> Any | None:
    """Extract JSON from radare2 output with multiple fallback strategies."""
    if not output or not output.strip():
        return None

    # Strategy 1: Try to find JSON array/object with proper nesting
    # OPTIMIZATION: Use pre-compiled patterns (faster)
    json_patterns = [
        (_JSON_ARRAY_PATTERN, "array"),  # Nested arrays
        (_JSON_OBJECT_PATTERN, "object"),  # Nested objects
    ]

    for pattern, pattern_type in json_patterns:
        matches = pattern.findall(output)
        # Try from last to first (radare2 usually puts command output at the end)
        for match in reversed(matches):
            try:
                parsed = json.loads(match)
                logger.debug(f"Successfully parsed {pattern_type} JSON")
                return parsed
            except json.JSONDecodeError:
                continue

    # Strategy 2: Try line-by-line from the end
    lines = output.strip().split("\n")
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        # Check if line looks like JSON
        if (line.startswith("[") and line.endswith("]")) or (
            line.startswith("{") and line.endswith("}")
        ):
            try:
                parsed = json.loads(line)
                logger.debug("Successfully parsed single-line JSON")
                return parsed
            except json.JSONDecodeError:
                continue

    logger.warning("Failed to extract valid JSON from radare2 output")
    return None


def _validate_r2_identifier(identifier: str) -> str:
    """Validate and sanitize radare2 function/address identifier."""
    # OPTIMIZATION: Use pre-compiled patterns (faster)
    # Allow: hex addresses (0x...), symbols (sym.*), function names
    if (_HEX_ADDRESS_PATTERN.match(identifier) or 
        _SYMBOL_PATTERN.match(identifier) or 
        _FUNCTION_NAME_PATTERN.match(identifier)):
        return identifier

    raise ValidationError(
        f"Invalid radare2 identifier: '{identifier}'. "
        "Must be hex address (0x...) or valid symbol name."
    )


def register_ghost_trace(mcp: FastMCP) -> None:
    """Register the Ghost Trace tool with the FastMCP server."""
    mcp.tool(ghost_trace)


def _get_file_cache_key(file_path: str) -> str:
    """Generate a cache key based on file path and modification time.

    This ensures cache invalidation when the file is modified.
    """
    try:
        stat = os.stat(file_path)
        return f"{file_path}:{stat.st_mtime}:{stat.st_size}"
    except OSError:
        # If file doesn't exist or can't be accessed, use path only
        return file_path


@alru_cache(maxsize=64, ttl=300)  # Cache for 5 minutes, max 64 entries
async def _run_r2_cmd_cached(
    cache_key: str, file_path: str, cmd: str, timeout: int | None = None
) -> str:
    """Cached helper to run a single radare2 command.

    The cache_key includes file modification time for automatic invalidation.
    Uses dynamic timeout based on file size if timeout is not specified.
    """
    # Calculate dynamic timeout if not provided
    effective_timeout = (
        timeout if timeout else calculate_dynamic_timeout(file_path, base_timeout=30)
    )
    full_cmd = ["radare2", "-q", "-c", cmd, str(file_path)]
    output, _ = await execute_subprocess_async(full_cmd, timeout=effective_timeout)
    return output


async def _run_r2_cmd(
    file_path: str, cmd: str, timeout: int | None = None, use_cache: bool = True
) -> str:
    """Helper to run a single radare2 command with optional caching.

    Args:
        file_path: Path to the binary file
        cmd: Radare2 command to execute
        timeout: Command timeout in seconds (uses dynamic timeout if None)
        use_cache: Whether to use caching (default: True)

    Returns:
        Command output as string
    """
    # Calculate dynamic timeout based on file size
    effective_timeout = (
        timeout if timeout else calculate_dynamic_timeout(file_path, base_timeout=30)
    )

    if use_cache:
        cache_key = _get_file_cache_key(file_path)
        return await _run_r2_cmd_cached(cache_key, file_path, cmd, effective_timeout)

    # Direct execution without caching (for commands with side effects)
    full_cmd = ["radare2", "-q", "-c", cmd, str(file_path)]
    output, _ = await execute_subprocess_async(full_cmd, timeout=effective_timeout)
    return output


@log_execution(tool_name="ghost_trace")
@track_metrics("ghost_trace")
@handle_tool_errors
async def ghost_trace(
    file_path: str,
    focus_function: str | None = None,
    hypothesis: dict[str, Any] | None = None,
    timeout: int = 300,
    ctx: Context = None,
) -> ToolResult:
    """
    Detect hidden malicious behaviors using "Ghost Trace" (Static + Emulation).

    This tool performs a hybrid analysis:
    1. **Scan**: Finds "Orphan Functions" (not called by main) and "Suspicious Logic" (magic value checks).
    2. **Hypothesize**: (Optional) If `hypothesis` is provided, it sets up emulation conditions.
    3. **Emulate**: (Optional) If `focus_function` is provided, it emulates that specific function
       to verify the hypothesis (e.g., "If register eax=0x1234, does it call system()?").

    Args:
        file_path: Path to the binary.
        focus_function: (Optional) Name or address of a specific function to emulate.
        hypothesis: (Optional) Dictionary defining emulation parameters:
                    {
                        "registers": {"eax": "0x1234", "zf": "1"},
                        "args": ["arg1", "arg2"],
                        "max_steps": 100
                    }
        timeout: Execution timeout.

    Returns:
        ToolResult containing suspicious candidates or emulation results.
    """
    validated_path = validate_file_path(file_path)

    # 1. If focus_function is provided, run emulation (Verification Phase)
    if focus_function and hypothesis:
        if ctx:
            await ctx.info(f"👻 Ghost Trace: Emulating {focus_function} with hypothesis...")
        return await _verify_hypothesis_with_emulation(
            validated_path, focus_function, hypothesis, timeout
        )

    # 2. Otherwise, run full scan (Discovery Phase)
    if ctx:
        await ctx.info("👻 Ghost Trace: Scanning for suspicious logic...")

    # Run analysis
    # We chain commands: aaa (analyze), aflj (list functions json)
    # Note: 'aaa' can be slow on large binaries. Use 'aa' for faster but less complete analysis.
    # For large binaries (>5MB), use lighter analysis
    file_size = os.path.getsize(validated_path)
    analysis_cmd = "aa" if file_size > 5_000_000 else "aaa"

    cmd = f"{analysis_cmd}; aflj"
    output = await _run_r2_cmd(validated_path, cmd, timeout=timeout, use_cache=False)

    # Debug logging for troubleshooting
    logger.debug(f"r2 output length: {len(output)}, first 500 chars: {output[:500]}")

    # Parse functions with safe JSON extraction
    functions = _extract_json_safely(output)

    # Handle failed JSON extraction (not empty list which is valid)
    if functions is None:
        logger.warning(f"Could not extract JSON from r2 output. Output preview: {output[:300]}...")
        # Try a fallback: run aflj separately with more time
        fallback_output = await _run_r2_cmd(validated_path, "aflj", timeout=60, use_cache=False)
        functions = _extract_json_safely(fallback_output)

        # If still None after fallback, return error
        if functions is None:
            logger.error(
                f"Failed to parse JSON after fallback. Fallback output: {fallback_output[:200]}..."
            )
            return failure(
                "PARSE_ERROR",
                "Failed to parse function list from radare2. "
                "Output may be corrupted or analysis failed.",
                hint="Try increasing timeout or using a simpler analysis mode.",
            )

    # Validate that functions is a list (empty list is valid for stripped binaries)
    if not isinstance(functions, list):
        logger.error(
            f"Invalid function list format (type: {type(functions)}). Output preview: {output[:200]}..."
        )
        return failure(
            "PARSE_ERROR",
            "Failed to parse function list from radare2. "
            "Output may be corrupted or analysis failed.",
            hint="Try increasing timeout or using a simpler analysis mode.",
        )

    if not functions:
        logger.info("No functions found in binary (possibly stripped or small)")

    # Find orphans and suspicious logic
    orphans = []
    suspicious_logic = []

    # We need xrefs to find orphans. 'aflj' doesn't give xrefs count reliably in all versions.
    # We'll do a quick pass.
    # Actually, 'aflj' has 'noreturn', 'stack', etc.
    # Let's use a heuristic: if name is not 'main' and not 'entry' and not exported,
    # and we can't easily see xrefs (we'd need 'ax' for all, which is slow).

    # Better approach for orphans:
    # 1. Get all functions.
    # 2. Get entry points (ie).
    # 3. For a subset of "interesting" functions (large size, specific strings), check xrefs.

    # For this MVP, let's focus on "Suspicious Logic" (Magic Values) in ALL functions.
    # We'll search for 'cmp' instructions with immediate values.

    # Search for magic value checks: '/m' command in r2 finds "magic" signatures, but we want code logic.
    # We'll search for instructions like 'cmp reg, 0x...'
    # cmd: "aaa; /aj cmp,0x" (search for 'cmp' instructions with '0x' operand)
    # This is a bit raw.

    # Let's implement `find_orphan_functions` and `identify_conditional_paths` properly.

    if ctx:
        await ctx.report_progress(30, 100)
        await ctx.info("👻 Ghost Trace: Identifying orphan functions...")

    orphans = await _find_orphan_functions(validated_path, functions)

    if ctx:
        await ctx.report_progress(60, 100)
        await ctx.info("👻 Ghost Trace: Analyzing conditional logic...")

    suspicious_logic = await _identify_conditional_paths(
        validated_path, functions[:20], ctx
    )  # Limit to top 20 for speed in MVP

    if ctx:
        await ctx.report_progress(100, 100)

    return success(
        {
            "scan_type": "discovery",
            "orphan_functions": orphans,
            "suspicious_logic": suspicious_logic,
            "description": "Found potential logic bombs. Use 'focus_function' and 'hypothesis' to verify.",
        }
    )


def _functions_to_tuple(functions: list[dict[str, Any]]) -> tuple:
    """Convert functions list to hashable tuple for caching."""
    return tuple(
        (
            f.get("name", ""),
            f.get("offset", 0),
            f.get("size", 0),
            tuple(f.get("codexrefs", []) or []),
        )
        for f in functions
    )


@alru_cache(maxsize=32, ttl=300)
async def _find_orphan_functions_cached(
    file_path_str: str, functions_tuple: tuple
) -> tuple[dict[str, Any], ...]:
    """Cached implementation of orphan function detection."""
    orphans = []

    for func_data in functions_tuple:
        name, offset, size, codexrefs = func_data

        if name.startswith("sym.imp"):  # Skip imports
            continue
        if "main" in name or "entry" in name:
            continue

        # Check refs - only care about non-trivial functions
        if not codexrefs and size > 50:
            orphans.append(
                {
                    "name": name,
                    "address": hex(offset),
                    "size": size,
                    "reason": "No code cross-references found (potential dormant code)",
                }
            )

    return tuple(orphans)


async def _find_orphan_functions(
    file_path: Path, functions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Identify functions with no direct XREFs (potential dead code/backdoors).

    Uses caching to avoid recomputing orphan analysis for the same functions.
    """
    # Convert to hashable format for caching
    functions_tuple = _functions_to_tuple(functions)
    result = await _find_orphan_functions_cached(str(file_path), functions_tuple)
    return list(result)


async def _identify_conditional_paths(
    file_path: Path, functions: list[dict[str, Any]], ctx: Context = None
) -> list[dict[str, Any]]:
    """Identify functions with suspicious conditional logic (Magic Values)."""
    suspicious = []

    # Batch process functions for better performance
    # Build a single command chain to analyze multiple functions
    batch_size = 10
    total_functions = len(functions)
    for i in range(0, total_functions, batch_size):
        if ctx:
            await ctx.report_progress(60 + int((i / total_functions) * 30), 100)

        batch = functions[i : i + batch_size]

        # Create batch command
        cmds = []
        for func in batch:
            addr = func.get("offset")
            if addr:
                cmds.append(f"pdfj @ {addr}")

        if not cmds:
            continue

        # Execute batch command
        batch_cmd = "; ".join(cmds)
        try:
            out = await _run_r2_cmd(file_path, batch_cmd, timeout=60)

            # Parse each function's output
            # Note: with multiple pdfj, output contains multiple JSON objects
            # We need to split them carefully
            # OPTIMIZATION: Use pre-compiled pattern (faster)
            json_outputs = _NESTED_JSON_PATTERN.findall(out)

            for func, json_str in zip(batch, json_outputs, strict=False):
                try:
                    func_data = json.loads(json_str)
                    ops = func_data.get("ops", [])
                    name = func.get("name")

                    for op in ops:
                        disasm = op.get("disasm", "")
                        # Heuristic: cmp [reg], 0x[large_value]
                        if "cmp" in disasm and "0x" in disasm:
                            # Check if value is "magic" (not small loop counter)
                            # Simple check: length of hex string > 4 (e.g. 0x12)
                            args = disasm.split(",")
                            if len(args) > 1:
                                val = args[1].strip()
                                if val.startswith("0x") and len(val) > 4:
                                    suspicious.append(
                                        {
                                            "function": name,
                                            "address": hex(op.get("offset", 0)),
                                            "instruction": disasm,
                                            "reason": "Magic value comparison detected (potential logic bomb trigger)",
                                        }
                                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse function disassembly: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Failed to analyze batch: {e}")
            continue

    return suspicious


async def _verify_hypothesis_with_emulation(
    file_path: Path, function_name: str, hypothesis: dict[str, Any], timeout: int
) -> ToolResult:
    """
    Verify a hypothesis using partial emulation (ESIL).

    Hypothesis format:
    {
        "registers": {"eax": "0xCAFEBABE"},
        "max_steps": 100
    }
    """
    # Validate function name to prevent command injection
    try:
        validated_func = _validate_r2_identifier(function_name)
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))

    # Construct ESIL script
    # 1. Initialize ESIL (aei)
    # 2. Initialize Stack (aeim)
    # 3. Seek to function (s <func>)
    # 4. Set registers (aer <reg>=<val>)
    # 5. Step (aes) and trace

    regs = hypothesis.get("registers", {})
    max_steps = min(hypothesis.get("max_steps", 50), 1000)  # Cap at 1000 for safety

    cmds = [
        "aaa",  # Analyze
        "aei",  # Init ESIL
        "aeim",  # Init Stack
        f"s {validated_func}",  # Seek to function (validated)
    ]

    # Set registers (validate register names and values)
    for reg, val in regs.items():
        # OPTIMIZATION: Use pre-compiled pattern (faster)
        if not _REG_PATTERN.match(reg.lower()):
            logger.warning(f"Skipping invalid register name: {reg}")
            continue
        # OPTIMIZATION: Use pre-compiled pattern (faster)
        if not _VALUE_PATTERN.match(str(val)):
            logger.warning(f"Skipping invalid register value: {val}")
            continue
        cmds.append(f"aer {reg}={val}")

    # Step and record
    # We'll use a loop in r2 or just run 'aes' N times and print registers
    # 'aes <steps>' runs N steps.
    # We want to see if it reaches a certain state or calls a function.
    # For this MVP, we'll run steps and return the final register state and visited addresses.

    # Run N steps and print disassembly of current instruction
    # 'aes <max_steps>; aerj' (run steps, then print registers json)
    cmds.append(f"aes {max_steps}")
    cmds.append("aerj")  # Get registers

    full_cmd = "; ".join(cmds)
    output = await _run_r2_cmd(file_path, full_cmd, timeout=timeout)

    # Parse result (last json is registers) with safe extraction
    final_regs = _extract_json_safely(output)

    if final_regs is None:
        logger.error(f"Failed to parse emulation results. Output: {output[:500]}")
        return failure(
            "EMULATION_ERROR",
            "Emulation completed but failed to parse register state. "
            "The function may have crashed or radare2 output was corrupted.",
        )

    return success(
        {
            "status": "emulation_complete",
            "steps_executed": max_steps,
            "final_registers": final_regs,
            "hypothesis_verification": "Check final_registers to see if expected state was reached.",
            "raw_output_preview": output[:200] + "..." if len(output) > 200 else output,
        }
    )


# Plugin import at bottom to avoid circular imports
from reversecore_mcp.core.plugin import Plugin  # noqa: E402


class GhostTracePlugin(Plugin):
    """Plugin for Ghost Trace tool."""

    @property
    def name(self) -> str:
        return "ghost_trace"

    @property
    def description(self) -> str:
        return "Hybrid reverse engineering tool (Static + Emulation) for detecting hidden malicious behaviors."

    def register(self, mcp_server: Any) -> None:
        """Register Ghost Trace tool."""
        mcp_server.tool(ghost_trace)
