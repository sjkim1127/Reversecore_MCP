"""
Neural Decompiler: AI-Simulated Code Refinement Tool.

This tool transforms raw Ghidra decompilation output into "human-like" natural code
using advanced heuristics and pattern matching to restore developer intent.

Supports fallback to radare2 when Ghidra is not available.
"""

import re

from fastmcp import Context, FastMCP

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.ghidra import (
    decompile_function_with_ghidra,
    ensure_ghidra_available,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# OPTIMIZATION: Pre-compile regex patterns used in hot paths for variable renaming
# These patterns match API calls and extract the assigned variable name
_API_PATTERNS = [
    (re.compile(r"(\w+)\s*=\s*socket\("), "sock_fd"),
    (re.compile(r"(\w+)\s*=\s*fopen\("), "file_handle"),
    (re.compile(r"(\w+)\s*=\s*recv\("), "bytes_received"),
    (re.compile(r"(\w+)\s*=\s*send\("), "bytes_sent"),
    (re.compile(r"(\w+)\s*=\s*malloc\("), "heap_ptr"),
    (re.compile(r"(\w+)\s*=\s*calloc\("), "heap_ptr"),
    (re.compile(r"(\w+)\s*=\s*realloc\("), "heap_ptr"),
    (re.compile(r"(\w+)\s*=\s*CreateFile\w*\("), "file_handle"),
    (re.compile(r"(\w+)\s*=\s*CreateThread\("), "thread_handle"),
    (re.compile(r"(\w+)\s*=\s*connect\("), "conn_result"),
    (re.compile(r"(\w+)\s*=\s*accept\("), "client_sock"),
    (re.compile(r"(\w+)\s*=\s*RegOpenKey\w*\("), "reg_key"),
    (re.compile(r"(\w+)\s*=\s*RegCreateKey\w*\("), "reg_key"),
    (re.compile(r"(\w+)\s*=\s*GetProcAddress\("), "proc_addr"),
    (re.compile(r"(\w+)\s*=\s*LoadLibrary\w*\("), "lib_handle"),
]


def register_neural_decompiler(mcp: FastMCP) -> None:
    """Register the Neural Decompiler tool with the FastMCP server."""
    mcp.tool(neural_decompile)


@log_execution(tool_name="neural_decompile")
@track_metrics("neural_decompile")
@handle_tool_errors
async def neural_decompile(
    file_path: str,
    function_address: str,
    timeout: int = 300,
    use_ghidra: bool = True,
    ctx: Context = None,
) -> ToolResult:
    """
    Decompile a function and refine it into "human-like" code using the Neural Decompiler.

    This tool:
    1.  Decompiles the function using Ghidra (preferred) or radare2 (fallback).
    2.  Refines the code by renaming variables based on API usage (e.g., `socket` -> `sock_fd`).
    3.  Infers structures and adds semantic comments.

    Args:
        file_path: Path to the binary.
        function_address: Address or name of the function.
        timeout: Execution timeout.
        use_ghidra: Use Ghidra decompiler if available (default True), fallback to radare2.
        ctx: FastMCP Context (auto-injected).

    Returns:
        ToolResult containing the refined "Neural" code.
    """
    validated_path = validate_file_path(file_path)

    if ctx:
        await ctx.info(f"🧠 Neural Decompiler: Analyzing {function_address}...")

    raw_code = None
    metadata = {}
    decompiler_used = None
    fallback_note = ""

    # Try Ghidra first if requested
    if use_ghidra:
        if ensure_ghidra_available():
            try:
                if ctx:
                    await ctx.info("🧠 Using Ghidra decompiler...")
                raw_code, metadata = decompile_function_with_ghidra(
                    validated_path, function_address, timeout
                )
                decompiler_used = "ghidra"
            except Exception as e:
                logger.warning(f"Ghidra decompilation failed: {e}. Falling back to radare2")
                fallback_note = f" (Ghidra failed: {str(e)[:50]}..., fell back to radare2)"
                # Continue to radare2 fallback
        else:
            logger.info("Ghidra not available, using radare2")
            fallback_note = " (Ghidra not available, using radare2)"

    # Fallback to radare2 if Ghidra failed or not available
    if raw_code is None:
        try:
            if ctx:
                await ctx.info("🧠 Using radare2 decompiler (pdc)...")

            from reversecore_mcp.core.r2_helpers import execute_r2_command as _execute_r2_command

            r2_cmds = [f"pdc @ {function_address}"]
            output, bytes_read = await _execute_r2_command(
                validated_path,
                r2_cmds,
                analysis_level="aaa",
                max_output_size=10_000_000,
                base_timeout=timeout,
            )

            if not output or output.strip() == "":
                return failure(
                    error_code="DECOMPILATION_FAILED",
                    message=f"No decompilation output for address: {function_address}",
                    hint="Verify the address exists and points to a valid function. "
                    "Try analyzing with 'afl' first.",
                )

            raw_code = output
            metadata = {
                "function_address": function_address,
                "bytes_read": bytes_read,
            }
            decompiler_used = "radare2"

        except Exception as e:
            return failure(
                error_code="DECOMPILATION_FAILED",
                message=f"Both Ghidra and radare2 decompilation failed: {str(e)}",
                hint="Ensure the binary is valid and the function address exists. "
                "Check that radare2 is installed and working.",
            )

    if ctx:
        await ctx.info("🧠 Neural Decompiler: Refining code structure and semantics...")

    # Refine Code (The "Neural" Magic)
    refined_code = _refine_code(raw_code)

    # Build description
    description = f"Decompiled with {decompiler_used}{fallback_note}"

    return success(
        {
            "original_code": raw_code,
            "original_code_snippet": (raw_code[:200] + "..." if len(raw_code) > 200 else raw_code),
            "neural_code": refined_code,
            "metadata": metadata,
            "decompiler": decompiler_used,
            "description": description,
            "refinement_stats": {
                "renamed_vars": refined_code.count("/* Renamed from"),
                "inferred_structs": refined_code.count("->"),
                "comments_added": refined_code.count("// Magic:") + refined_code.count("/* Magic"),
            },
        }
    )


def _refine_code(code: str) -> str:
    """
    Apply heuristic patterns to refine C code.

    Transforms:
    - API-based variable renaming
    - Structure inference from pointer arithmetic
    - Magic value annotation
    """
    lines = code.split("\n")
    refined_lines = []

    # Variable mapping: old_name -> new_name
    var_map = {}

    # API counters for unique naming
    api_counters = {}

    # 1. First Pass: Analyze API usage to build variable map (using pre-compiled patterns)
    for line in lines:
        for pattern, base_name in _API_PATTERNS:
            if match := pattern.search(line):
                var_name = match.group(1)

                # Generate unique name if multiple variables use same API
                count = api_counters.get(base_name, 0) + 1
                api_counters[base_name] = count

                # Only add suffix if there's more than one
                unique_name = f"{base_name}_{count}" if count > 1 else base_name
                var_map[var_name] = unique_name
                break  # Stop after first match per line

    # 2. Second Pass: Apply transformations
    # OPTIMIZATION: Compile patterns lazily only when needed
    var_patterns = {}  # Cache for compiled patterns
    
    for line in lines:
        new_line = line

        # Apply variable renaming (compile patterns on first use)
        for old, new in var_map.items():
            # OPTIMIZATION: Lazy compilation - only compile if variable not already compiled
            if old not in var_patterns:
                var_patterns[old] = re.compile(r"\b" + re.escape(old) + r"\b")
            
            pattern = var_patterns[old]

            # Check if variable exists in line before attempting replacement
            if pattern.search(new_line):
                # Add comment on first definition
                if f"{old} =" in new_line or f"{old};" in new_line:
                    new_line = pattern.sub(new, new_line)
                    new_line += f" /* Renamed from {old} */"
                else:
                    new_line = pattern.sub(new, new_line)

        # Structure Inference: *(ptr + 4) -> ptr->field_4
        # Regex: \*\((int|long|void)\s*\*\)\s*\((\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\)
        # Simplified: *(type *)(var + offset)
        def struct_replacer(match):
            # type = match.group(1) # unused for now
            var = match.group(1)
            offset = match.group(2)
            return f"{var}->field_{offset}"

        new_line = re.sub(
            r"\*\(\w+\s*\*\)\s*\(([\w\d_]+)\s*\+\s*(0x[\da-fA-F]+|\d+)\)",
            struct_replacer,
            new_line,
        )

        # Magic Value Annotation
        # Find hex constants > 0x1000
        def magic_replacer(match):
            val_str = match.group(0)
            try:
                val = int(val_str, 16)
                if val > 0x1000:
                    return f"{val_str} /* Magic Value */"
            except (ValueError, TypeError):
                pass
            return val_str

        # Avoid replacing inside comments or if already commented
        if "//" not in new_line and "/*" not in new_line:
            new_line = re.sub(r"0x[\da-fA-F]+", magic_replacer, new_line)

        refined_lines.append(new_line)

    # 3. Final pass: Add type hints if possible (bonus)
    # For example, if a variable is consistently used as integer, we could add a comment
    # This is a simple heuristic and could be expanded

    return "\n".join(refined_lines)


from typing import Any

from reversecore_mcp.core.plugin import Plugin


class NeuralDecompilerPlugin(Plugin):
    """Plugin for Neural Decompiler tool."""

    @property
    def name(self) -> str:
        return "neural_decompiler"

    @property
    def description(self) -> str:
        return "AI-Simulated Code Refinement Tool for transforming raw decompilation into human-like code."

    def register(self, mcp_server: Any) -> None:
        """Register Neural Decompiler tool."""
        mcp_server.tool(neural_decompile)
