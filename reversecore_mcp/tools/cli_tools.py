"""CLI tool wrappers that return structured ToolResult payloads.

This module acts as a facade that imports and exposes tools from specialized modules:
- file_operations: File management and workspace operations
- static_analysis: String extraction and version scanning
- r2_analysis: Radare2-based analysis tools
- decompilation: Decompilation and structure recovery
- signature_tools: YARA rule and signature generation
- diff_tools: Binary diffing and library matching

It also contains AI-powered tools and symbolic execution tools that remain here.
"""

import asyncio
from fastmcp import FastMCP, Context

# Import all tools from specialized modules
from reversecore_mcp.tools.file_operations import (
    run_file,
    copy_to_workspace,
    list_workspace,
    scan_workspace,
)

from reversecore_mcp.tools.static_analysis import (
    run_strings,
    run_binwalk,
    scan_for_versions,
    extract_rtti_info,
)

from reversecore_mcp.tools.r2_analysis import (
    run_radare2,
    generate_function_graph,
    analyze_xrefs,
    trace_execution_path,
)

from reversecore_mcp.tools.decompilation import (
    smart_decompile,
    get_pseudo_code,
    recover_structures,
    emulate_machine_code,
)

from reversecore_mcp.tools.signature_tools import (
    generate_yara_rule,
    generate_signature,
)

from reversecore_mcp.tools.diff_tools import (
    diff_binaries,
    analyze_variant_changes,
    match_libraries,
)

# Import remaining dependencies for local tools
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# Re-export all tools so existing imports continue to work
__all__ = [
    # File operations
    "run_file",
    "copy_to_workspace",
    "list_workspace",
    "scan_workspace",
    # Static analysis
    "run_strings",
    "run_binwalk",
    "scan_for_versions",
    "extract_rtti_info",
    # R2 analysis
    "run_radare2",
    "generate_function_graph",
    "analyze_xrefs",
    "trace_execution_path",
    # Decompilation
    "smart_decompile",
    "get_pseudo_code",
    "recover_structures",
    "emulate_machine_code",
    # Signature tools
    "generate_yara_rule",
    "generate_signature",
    # Diff tools
    "diff_binaries",
    "analyze_variant_changes",
    "match_libraries",
    # Local tools (AI + symbolic execution)
    "solve_path_constraints",
    "analyze_with_ai",
    "suggest_function_name",
    # Registration function
    "register_cli_tools",
]


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    # File operations
    mcp.tool(run_file)
    mcp.tool(copy_to_workspace)
    mcp.tool(list_workspace)
    mcp.tool(scan_workspace)

    # Static analysis
    mcp.tool(run_strings)
    mcp.tool(run_binwalk)
    mcp.tool(scan_for_versions)
    mcp.tool(extract_rtti_info)

    # R2 analysis
    mcp.tool(run_radare2)
    mcp.tool(generate_function_graph)
    mcp.tool(analyze_xrefs)
    mcp.tool(trace_execution_path)

    # Decompilation
    mcp.tool(emulate_machine_code)
    mcp.tool(get_pseudo_code)
    mcp.tool(smart_decompile)
    mcp.tool(recover_structures)

    # Signature tools
    mcp.tool(generate_yara_rule)
    mcp.tool(generate_signature)

    # Diff tools
    mcp.tool(diff_binaries)
    mcp.tool(analyze_variant_changes)
    mcp.tool(match_libraries)

    # Local tools
    mcp.tool(solve_path_constraints)
    # AI-powered tools (using LLM sampling)
    mcp.tool(analyze_with_ai)
    mcp.tool(suggest_function_name)


# ============================================================================
# Local Tools (Symbolic Execution + AI-Powered)
# ============================================================================


def _resolve_address(proj, addr_str):
    """Helper to resolve address string to integer using angr project."""
    if not addr_str:
        return None

    # Try hex
    if addr_str.startswith("0x"):
        try:
            return int(addr_str, 16)
        except ValueError:
            pass

    # Try symbol
    try:
        sym = proj.loader.main_object.get_symbol(addr_str)
        if sym:
            return sym.rebased_addr
    except Exception:
        pass

    # Try integer
    try:
        return int(addr_str)
    except ValueError:
        pass

    return None


@log_execution(tool_name="solve_path_constraints")
@track_metrics("solve_path_constraints")
@handle_tool_errors
async def solve_path_constraints(
    file_path: str,
    start_address: str,
    target_address: str,
    avoid_address: str = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Find an execution path from start to target address using symbolic execution.

    This tool uses the 'angr' binary analysis framework to mathematically prove
    reachability and generate inputs that trigger specific code paths.

    **Use Cases:**
    - **CTF Challenges**: Find the input that reaches the "Win" function
    - **Exploit Development**: Generate input to reach a vulnerable buffer overflow
    - **Bug Triage**: Verify if a crash is reachable from the entry point

    Args:
        file_path: Path to the binary file
        start_address: Address to start symbolic execution (e.g., 'main', '0x401000')
        target_address: Address to reach (e.g., 'sym.win', '0x401050')
        avoid_address: Optional address to avoid (e.g., 'sym.fail', '0x401060')
        timeout: Execution timeout in seconds (default: 300)

    Returns:
        ToolResult with the solution (input) that satisfies the path constraints.
    """
    # 1. Validate parameters
    validate_tool_parameters(
        "solve_path_constraints",
        {"start_address": start_address, "target_address": target_address},
    )
    validated_path = validate_file_path(file_path)

    # 2. Run angr in a separate thread (it's CPU bound and blocking)
    def run_angr_solve():
        try:
            import angr
        except ImportError:
            return {"found": False, "error": "angr or claripy not installed"}

        # Create project
        try:
            proj = angr.Project(str(validated_path), auto_load_libs=False)
        except Exception as e:
            return {"found": False, "error": f"Failed to load binary with angr: {e}"}

        # Resolve addresses if they are symbols
        start_addr = _resolve_address(proj, start_address)
        target_addr = _resolve_address(proj, target_address)
        avoid_addr = _resolve_address(proj, avoid_address) if avoid_address else None

        if start_addr is None:
            return {
                "found": False,
                "error": f"Could not resolve start address: {start_address}",
            }
        if target_addr is None:
            return {
                "found": False,
                "error": f"Could not resolve target address: {target_address}",
            }

        # Create simulation state
        try:
            state = proj.factory.blank_state(addr=start_addr)
        except Exception as e:
            return {"found": False, "error": f"Failed to create state: {e}"}

        # Create simulation manager
        simgr = proj.factory.simulation_manager(state)

        # Define exploration technique
        find_args = {"find": target_addr}
        if avoid_addr:
            find_args["avoid"] = avoid_addr

        # Explore
        try:
            simgr.explore(**find_args)
        except Exception as e:
            return {"found": False, "error": f"Exploration failed: {e}"}

        if simgr.found:
            found_state = simgr.found[0]
            # Generate input (stdin)
            # This is a simplification; often we need to constrain stdin specifically
            # But for blank_state, we might check what was read.
            # For now, let's return the stdin if it was constrained, or just the state info.

            try:
                solution = found_state.posix.dumps(0)  # Dump stdin
                return {
                    "found": True,
                    "input_hex": solution.hex(),
                    "input_str": str(solution),  # Best effort string representation
                    "stdout": found_state.posix.dumps(1).decode(errors="ignore"),
                }
            except Exception:
                return {
                    "found": True,
                    "input_hex": "",
                    "input_str": "Error dumping input",
                    "stdout": "",
                }
        else:
            return {"found": False, "reason": "No path found to target"}

    try:
        # Run with timeout
        result = await asyncio.to_thread(run_angr_solve)

        if result.get("error"):
            return failure("SYMBOLIC_EXECUTION_ERROR", result["error"])

        if result["found"]:
            return success(
                result,
                format="json",
                description=f"Found path from {start_address} to {target_address}. Input: {result.get('input_hex')}",
            )
        else:
            return failure(
                "PATH_NOT_FOUND",
                f"No execution path found from {start_address} to {target_address}",
                hint="Check if the target is actually reachable or if constraints are too strict.",
            )

    except Exception as e:
        return failure(
            "SYMBOLIC_EXECUTION_ERROR",
            f"Angr execution failed: {str(e)}",
            hint="Symbolic execution is complex. Ensure addresses are correct and the binary is compatible.",
        )


# ============================================================================
# AI-Powered Tools (Using LLM Sampling)
# ============================================================================


@log_execution(tool_name="analyze_with_ai")
@track_metrics("analyze_with_ai")
@handle_tool_errors
async def analyze_with_ai(
    file_path: str,
    question: str,
    ctx: Context = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Ask AI to analyze specific aspects of a binary.

    This tool leverages LLM sampling to get AI's opinion on ambiguous data.
    Use this when automated analysis produces unclear results and you need
    AI interpretation.

    **Use Cases:**
    - Identifying obfuscation techniques: "Is this function obfuscated?"
    - Naming suggestions: "What would be a good name for this function?"
    - Pattern recognition: "Does this look like malware behavior?"

    Args:
        file_path: Path to the binary file
        question: Question to ask AI about the binary
        ctx: FastMCP Context for AI sampling (auto-injected)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with AI's analysis
    """
    validated_path = validate_file_path(file_path)

    if not ctx:
        return failure(
            "NO_CONTEXT",
            "AI sampling requires Context parameter",
            hint="This tool needs to be called from an MCP client that supports sampling",
        )

    try:
        # 1. Get basic info about the file
        file_info_result = await run_file(str(validated_path))
        file_info = (
            file_info_result.content[0].text if file_info_result.content else "Unknown"
        )

        # 2. Get strings sample
        strings_result = await run_strings(str(validated_path), max_output_size=100_000)
        strings_sample = (
            strings_result.content[0].text if strings_result.content else ""
        )[
            :5000
        ]  # First 5KB

        # 3. Ask AI via sampling
        prompt = f"""You are a reverse engineering expert analyzing a binary file.

File: {validated_path.name}
Type: {file_info}

Sample strings from the binary:
```
{strings_sample}
```

Question: {question}

Please provide a concise, technical analysis based on the available information.
"""

        response = await ctx.sample(
            messages=[{"role": "user", "content": prompt}], max_tokens=500
        )

        ai_analysis = (
            response.content.text
            if hasattr(response.content, "text")
            else str(response.content)
        )

        return success(
            ai_analysis,
            question=question,
            file=validated_path.name,
            description=f"AI analysis completed for: {question}",
        )

    except Exception as e:
        return failure(
            "AI_SAMPLING_ERROR",
            f"AI sampling failed: {str(e)}",
            hint="Ensure the MCP client supports sampling feature",
        )


@log_execution(tool_name="suggest_function_name")
@track_metrics("suggest_function_name")
@handle_tool_errors
async def suggest_function_name(
    file_path: str,
    function_address: str,
    ctx: Context = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Use AI to suggest a meaningful name for a function based on its code.

    This tool decompiles a function and asks AI to suggest a descriptive name
    based on the logic and patterns in the code.

    Args:
        file_path: Path to the binary file
        function_address: Function address to analyze
        ctx: FastMCP Context for AI sampling (auto-injected)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with suggested function name and reasoning
    """
    validated_path = validate_file_path(file_path)

    if not ctx:
        return failure(
            "NO_CONTEXT",
            "AI sampling requires Context parameter",
            hint="This tool needs to be called from an MCP client that supports sampling",
        )

    try:
        # 1. Decompile the function
        decompile_result = await smart_decompile(
            str(validated_path), function_address, use_ghidra=True
        )

        if decompile_result.is_error:
            return decompile_result

        code = (
            decompile_result.content[0].text
            if decompile_result.content
            else decompile_result.data
        )

        # 2. Ask AI for name suggestion
        prompt = f"""You are a reverse engineering expert. Analyze this decompiled function and suggest a descriptive function name.

Decompiled code:
```c
{code[:2000]}  // Showing first 2000 chars
```

Based on the code logic, suggest:
1. A concise function name (e.g., decrypt_config, send_http_request)
2. Brief reasoning (1 sentence)

Format your response as:
Name: <function_name>
Reason: <why this name>
"""

        response = await ctx.sample(
            messages=[{"role": "user", "content": prompt}], max_tokens=150
        )

        ai_suggestion = (
            response.content.text
            if hasattr(response.content, "text")
            else str(response.content)
        )

        return success(
            ai_suggestion,
            function_address=function_address,
            description=f"AI suggested name for function @ {function_address}",
        )

    except Exception as e:
        return failure(
            "NAMING_SUGGESTION_ERROR",
            f"Failed to suggest function name: {str(e)}",
            hint="Ensure the function can be decompiled and client supports sampling",
        )
