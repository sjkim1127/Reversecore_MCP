"""
Neural Decompiler: AI-Simulated Code Refinement Tool.

This tool transforms raw Ghidra decompilation output into "human-like" natural code
using advanced heuristics and pattern matching to restore developer intent.
"""

import re

from fastmcp import FastMCP, Context
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core import ghidra_helper

logger = get_logger(__name__)


def register_neural_decompiler(mcp: FastMCP) -> None:
    """Register the Neural Decompiler tool with the FastMCP server."""
    mcp.tool(neural_decompile)


@log_execution(tool_name="neural_decompile")
async def neural_decompile(
    file_path: str,
    function_address: str,
    timeout: int = 300,
    ctx: Context = None,
) -> ToolResult:
    """
    Decompile a function and refine it into "human-like" code using the Neural Decompiler.

    This tool:
    1.  Decompiles the function using Ghidra.
    2.  Refines the code by renaming variables based on API usage (e.g., `socket` -> `sock_fd`).
    3.  Infers structures and adds semantic comments.

    Args:
        file_path: Path to the binary.
        function_address: Address or name of the function.
        timeout: Execution timeout.

    Returns:
        ToolResult containing the refined "Neural" code.
    """
    validated_path = validate_file_path(file_path)

    if ctx:
        await ctx.info(f"🧠 Neural Decompiler: Analyzing {function_address}...")

    try:
        raw_code, metadata = ghidra_helper.decompile_function_with_ghidra(
            validated_path, function_address, timeout
        )
    except Exception as e:
        return failure(
            error_code="GHIDRA_DECOMPILATION_FAILED",
            message=f"Ghidra decompilation failed:{str(e)}",
            hint="Ensure Ghidra is properly installed and JAVA_HOME is set correctly",
        )

    if ctx:
        await ctx.info("🧠 Neural Decompiler: Refining code structure and semantics...")

    # 2. Refine Code (The "Neural" Magic)
    refined_code = _refine_code(raw_code)

    return success(
        {
            "ghidra_code": raw_code,  # Full original code for comparison
            "original_code_snippet": raw_code[:200] + "...",
            "neural_code": refined_code,
            "metadata": metadata,
            "refinement_stats": {
                "renamed_vars": refined_code.count("/* Renamed from"),
                "inferred_structs": refined_code.count("->"),
                "comments_added": refined_code.count("// Magic:"),
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

    # Extended API patterns with meaningful names
    api_patterns = [
        (r"(\w+)\s*=\s*socket\(", "sock_fd"),
        (r"(\w+)\s*=\s*fopen\(", "file_handle"),
        (r"(\w+)\s*=\s*recv\(", "bytes_received"),
        (r"(\w+)\s*=\s*send\(", "bytes_sent"),
        (r"(\w+)\s*=\s*malloc\(", "heap_ptr"),
        (r"(\w+)\s*=\s*calloc\(", "heap_ptr"),
        (r"(\w+)\s*=\s*realloc\(", "heap_ptr"),
        (r"(\w+)\s*=\s*CreateFile\w*\(", "file_handle"),
        (r"(\w+)\s*=\s*CreateThread\(", "thread_handle"),
        (r"(\w+)\s*=\s*connect\(", "conn_result"),
        (r"(\w+)\s*=\s*accept\(", "client_sock"),
        (r"(\w+)\s*=\s*RegOpenKey\w*\(", "reg_key"),
        (r"(\w+)\s*=\s*RegCreateKey\w*\(", "reg_key"),
        (r"(\w+)\s*=\s*GetProcAddress\(", "proc_addr"),
        (r"(\w+)\s*=\s*LoadLibrary\w*\(", "lib_handle"),
    ]

    # 1. First Pass: Analyze API usage to build variable map
    for line in lines:
        for pattern, base_name in api_patterns:
            if match := re.search(pattern, line):
                var_name = match.group(1)

                # Generate unique name if multiple variables use same API
                count = api_counters.get(base_name, 0) + 1
                api_counters[base_name] = count

                # Only add suffix if there's more than one
                unique_name = f"{base_name}_{count}" if count > 1 else base_name
                var_map[var_name] = unique_name
                break  # Stop after first match per line

    # 2. Second Pass: Apply transformations
    for line in lines:
        new_line = line

        # Apply variable renaming
        for old, new in var_map.items():
            # Use word boundary to avoid partial matches
            if re.search(r"\b" + re.escape(old) + r"\b", new_line):
                # Add comment on first definition
                if f"{old} =" in new_line or f"{old};" in new_line:
                    new_line = re.sub(r"\b" + re.escape(old) + r"\b", new, new_line)
                    new_line += f" /* Renamed from {old} */"
                else:
                    new_line = re.sub(r"\b" + re.escape(old) + r"\b", new, new_line)

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
