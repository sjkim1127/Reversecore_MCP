"""Radare2-based analysis tools for binary analysis, cross-references, and execution tracing."""

import os
import re
from typing import Any

from async_lru import alru_cache
from fastmcp import Context

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async  # For test compatibility
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import (
    build_r2_cmd as _build_r2_cmd,
)

# Import shared R2 helper functions from core (avoids circular dependencies)
from reversecore_mcp.core.r2_helpers import (
    calculate_dynamic_timeout,
    remove_analysis_commands,
)
from reversecore_mcp.core.r2_helpers import (
    escape_mermaid_chars as _escape_mermaid_chars,
)
from reversecore_mcp.core.r2_helpers import (
    execute_r2_command as _execute_r2_command,
)
from reversecore_mcp.core.r2_helpers import (
    parse_json_output as _parse_json_output,
)
from reversecore_mcp.core.r2_helpers import (
    strip_address_prefixes as _strip_address_prefixes,
)
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import (
    _ADDRESS_PATTERN,  # OPTIMIZATION: Import pre-compiled pattern instead of duplicating
    validate_tool_parameters,
)

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@circuit_breaker("run_radare2", failure_threshold=5, recovery_timeout=60)
@handle_tool_errors
async def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context = None,
) -> ToolResult:
    """Execute vetted radare2 commands for binary triage."""

    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    validated_path = validate_file_path(file_path)
    validated_command = validate_r2_command(r2_command)

    # Adaptive analysis logic based on command type and file size
    # Use 'aa' for basic commands, 'aaa' for analysis-heavy commands on small files
    analysis_level = "aa"

    # Simple information commands don't need analysis
    simple_commands = ["i", "iI", "iz", "izj", "il", "is", "isj", "ie", "it", "iS", "iSj"]
    if validated_command in simple_commands or validated_command.startswith("i "):
        analysis_level = "-n"

    # Function listing commands (afl, aflj) benefit from deeper analysis
    # but only if file is small enough
    function_commands = ["afl", "aflj", "afll", "afllj", "pdf", "pdr"]
    if any(cmd in validated_command for cmd in function_commands):
        try:
            file_size_mb = os.path.getsize(validated_path) / (1024 * 1024)
            if file_size_mb < 10:  # For files under 10MB, use deeper analysis
                analysis_level = "aaa"
        except OSError:
            pass

    # If user explicitly requested analysis, handle it via caching
    if "aaa" in validated_command or "aa" in validated_command:
        # Remove explicit analysis commands as they are handled by _build_r2_cmd
        validated_command = remove_analysis_commands(validated_command)

    # Use helper function to execute radare2 command
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            [validated_command],
            analysis_level=analysis_level,
            max_output_size=max_output_size,
            base_timeout=timeout,
        )
        return success(output, bytes_read=bytes_read, analysis_level=analysis_level)
    except Exception as e:
        # Log error to client if context is available
        if ctx:
            await ctx.error(f"radare2 command '{validated_command}' failed: {str(e)}")
        raise


# Plugin import at bottom to avoid circular imports
from reversecore_mcp.core.plugin import Plugin  # noqa: E402


class R2AnalysisPlugin(Plugin):
    """Plugin for Radare2 analysis tools."""

    @property
    def name(self) -> str:
        return "r2_analysis"

    @property
    def description(self) -> str:
        return "Radare2-based analysis tools for binary analysis, cross-references, and execution tracing."

    def register(self, mcp_server: Any) -> None:
        """Register R2 analysis tools."""
        mcp_server.tool(run_radare2)
        mcp_server.tool(trace_execution_path)
        mcp_server.tool(generate_function_graph)
        mcp_server.tool(analyze_xrefs)


# Dangerous sink APIs for prioritized path tracing
_DANGEROUS_SINKS = frozenset(
    {
        # Command execution
        "system",
        "execve",
        "execl",
        "execlp",
        "execle",
        "execv",
        "execvp",
        "execvpe",
        "popen",
        "_popen",
        "ShellExecute",
        "ShellExecuteEx",
        "CreateProcess",
        "WinExec",
        "spawn",
        "fork",
        # Memory corruption
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "scanf",
        "memcpy",
        "memmove",
        "strncpy",
        # File operations
        "fopen",
        "open",
        "CreateFile",
        "DeleteFile",
        "WriteFile",
        # Network
        "connect",
        "send",
        "recv",
        "socket",
        "bind",
        "listen",
        # Registry (Windows)
        "RegSetValue",
        "RegCreateKey",
        "RegDeleteKey",
    }
)

# OPTIMIZATION: Pre-define translation table for faster function name cleaning
# Use empty second argument to delete characters
_FUNC_NAME_CLEAN_TABLE = str.maketrans("", "", "_")


@log_execution(tool_name="trace_execution_path")
@track_metrics("trace_execution_path")
@handle_tool_errors
async def trace_execution_path(
    file_path: str,
    target_function: str,
    max_depth: int = 2,
    max_paths: int = 5,
    timeout: int | None = None,
    prioritize_sinks: bool = True,
) -> ToolResult:
    """
    Trace function calls backwards from a target function (Sink) to find potential execution paths.

    This tool helps identify "Exploit Paths" by finding which functions call a dangerous
    target function (like 'system', 'strcpy', 'execve'). It performs a recursive
    cross-reference analysis (backtrace) to map out how execution reaches the target.

    **Use Cases:**
    - **Vulnerability Analysis**: Check if user input (main/recv) reaches 'system'
    - **Reachability Analysis**: Verify if a vulnerable function is actually called
    - **Taint Analysis Helper**: Provide the path for AI to perform manual taint checking

    **Performance Optimizations (v3.0):**
    - Reduced default depth (3→2) for faster analysis
    - Sink-aware pruning: prioritizes paths through dangerous APIs
    - Dynamic timeout based on file size

    Args:
        file_path: Path to the binary file
        target_function: Name or address of the target function (e.g., 'sym.imp.system', '0x401000')
        max_depth: Maximum depth of backtrace (default: 2, reduce for speed)
        max_paths: Maximum number of paths to return (default: 5)
        timeout: Execution timeout in seconds (uses dynamic timeout if None)
        prioritize_sinks: Prioritize paths through dangerous sink APIs (default: True)

    Returns:
        ToolResult with a list of execution paths (call chains).
    """
    validated_path = validate_file_path(file_path)

    # Calculate dynamic timeout based on file size
    effective_timeout = (
        timeout if timeout else calculate_dynamic_timeout(str(validated_path), base_timeout=30)
    )

    # Helper to check if a function name is a dangerous sink
    def is_dangerous_sink(func_name: str) -> bool:
        """Check if function name matches any dangerous sink API."""
        if not func_name:
            return False
        # OPTIMIZATION: Use str.translate() for faster prefix removal
        # Remove common prefixes first
        clean_name = func_name.replace("sym.imp.", "").replace("sym.", "")
        # Then remove underscores using translate (faster than replace)
        clean_name = clean_name.translate(_FUNC_NAME_CLEAN_TABLE)
        return any(sink in clean_name.lower() for sink in _DANGEROUS_SINKS)

    # Helper to get address of a function name
    async def get_address(func_name):
        # OPTIMIZATION: Batch both symbol and function lookups in one r2 call
        # This eliminates the overhead of a second subprocess call when the symbol
        # isn't found in the first lookup (common for stripped binaries)
        cmd = _build_r2_cmd(str(validated_path), ["isj", "aflj"], "aaa")
        out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

        # Parse output: radare2 outputs one JSON per command line
        # We expect 2 lines: first from isj (symbols), second from aflj (functions)
        lines = [line.strip() for line in out.strip().split("\n") if line.strip()]

        # Validate we have at least one line with potential JSON
        if not lines:
            return None

        # Try symbols first (isj output)
        # Use robust parsing that handles both JSON arrays and error messages
        if len(lines) >= 1:
            try:
                symbols = _parse_json_output(lines[0])
                # Validate it's a list (not an error dict or string)
                if isinstance(symbols, list):
                    for sym in symbols:
                        if isinstance(sym, dict):
                            if sym.get("name") == func_name or sym.get("realname") == func_name:
                                return sym.get("vaddr")
            except (json.JSONDecodeError, TypeError, IndexError):
                # First line wasn't valid JSON or wasn't in expected format
                # This is OK - fall through to try functions
                pass

        # If not found in symbols, try functions (aflj output)
        if len(lines) >= 2:
            try:
                funcs = _parse_json_output(lines[1])
                # Validate it's a list (not an error dict or string)
                if isinstance(funcs, list):
                    for f in funcs:
                        if isinstance(f, dict) and f.get("name") == func_name:
                            return f.get("offset")
            except (json.JSONDecodeError, TypeError, IndexError):
                # Second line wasn't valid JSON or wasn't in expected format
                # This is OK - just means function not found
                pass

        return None

    # Resolve target address
    target_addr = target_function
    if not target_function.startswith("0x"):
        addr = await get_address(target_function)
        if addr:
            target_addr = hex(addr)
        else:
            # If we can't resolve it, try using it directly if it looks like a symbol
            pass

    paths = []
    visited = set()

    async def recursive_backtrace(current_addr, current_path, depth):
        if depth >= max_depth or len(paths) >= max_paths:
            return

        # OPTIMIZATION: Pre-compute addresses in current path to avoid repeated list comprehensions
        current_path_addrs = {p["addr"] for p in current_path}

        if current_addr in visited and current_addr not in current_path_addrs:
            # Allow revisiting if it's a different path, but prevent cycles in current path
            pass
        elif current_addr in current_path_addrs:
            return  # Cycle detected

        # Get xrefs TO this address
        cmd = _build_r2_cmd(str(validated_path), [f"axtj @ {current_addr}"], "aaa")
        out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

        try:
            xrefs = _parse_json_output(out)
        except (json.JSONDecodeError, TypeError):
            xrefs = []

        if not xrefs:
            # End of chain (root caller found or no xrefs)
            if len(current_path) > 1:
                paths.append(current_path)
            return

        # OPTIMIZATION v3.0: Prioritize xrefs through dangerous sink APIs
        # This implements "Sink-aware pruning" - explore high-value paths first
        if prioritize_sinks and len(xrefs) > 1:
            xrefs = sorted(
                xrefs,
                key=lambda x: (
                    # Priority 1: main/entry functions (complete paths)
                    -2
                    if any(k in x.get("fcn_name", "").lower() for k in ["main", "entry"])
                    # Priority 2: Dangerous sink APIs
                    else -1
                    if is_dangerous_sink(x.get("fcn_name", ""))
                    # Priority 3: Everything else
                    else 0
                ),
            )

        for xref in xrefs:
            if len(paths) >= max_paths:
                break

            caller_addr = hex(xref.get("fcn_addr", 0))
            caller_name = xref.get("fcn_name", "unknown")
            type_ref = xref.get("type", "call")

            if type_ref not in ["call", "jump"]:
                continue

            new_node = {"addr": caller_addr, "name": caller_name, "type": type_ref}

            # If we reached main or entry, this is a complete path
            if "main" in caller_name or "entry" in caller_name:
                paths.append(current_path + [new_node])
            else:
                await recursive_backtrace(caller_addr, current_path + [new_node], depth + 1)

    # Start trace
    root_node = {"addr": target_addr, "name": target_function, "type": "target"}
    await recursive_backtrace(target_addr, [root_node], 0)

    # Format results
    # OPTIMIZATION: Use list comprehension with generator expression in join
    # This reduces memory by avoiding intermediate list creation in the join
    formatted_paths = [" -> ".join(f"{n['name']} ({n['addr']})" for n in p[::-1]) for p in paths]

    return success(
        {"paths": formatted_paths, "raw_paths": paths},
        path_count=len(paths),
        target=target_function,
        description=f"Found {len(paths)} execution paths to {target_function}",
    )


def _radare2_json_to_mermaid(json_str: str) -> str:
    """
    Convert Radare2 'agfj' JSON output to Mermaid Flowchart syntax.
    Optimized for LLM context efficiency.

    Args:
        json_str: JSON output from radare2 agfj command

    Returns:
        Mermaid flowchart syntax string
    """
    try:
        graph_data = json.loads(json_str)
        if not graph_data:
            return "graph TD;\n    Error[No graph data found]"

        # agfj returns list format for function graph
        blocks = (
            graph_data[0].get("blocks", [])
            if isinstance(graph_data, list)
            else graph_data.get("blocks", [])
        )

        mermaid_lines = ["graph TD"]

        for block in blocks:
            # 1. Generate node ID from offset
            node_id = f"N_{hex(block.get('offset', 0))}"

            # 2. Generate node label from assembly opcodes
            ops = block.get("ops", [])
            # OPTIMIZATION: Use enumerate with early break to avoid processing all ops
            # For token efficiency, we limit to 5 instructions per block
            op_codes = []
            has_more = False
            for i, op in enumerate(ops):
                if i < 5:
                    op_codes.append(op.get("opcode", ""))
                elif i == 5:
                    has_more = True
                    break

            if has_more:
                op_codes.append("...")

            # Escape Mermaid special characters using optimized function
            label_content = _escape_mermaid_chars("\\n".join(op_codes))

            # Define node
            mermaid_lines.append(f'    {node_id}["{label_content}"]')

            # 3. Create edges
            # True branch (jump)
            if "jump" in block:
                target_id = f"N_{hex(block['jump'])}"
                mermaid_lines.append(f"    {node_id} -->|True| {target_id}")

            # False branch (fail)
            if "fail" in block:
                target_id = f"N_{hex(block['fail'])}"
                mermaid_lines.append(f"    {node_id} -.->|False| {target_id}")

        return "\n".join(mermaid_lines)

    except Exception as e:
        return f"graph TD;\n    Error[Parse Error: {str(e)}]"


@alru_cache(maxsize=32)
@log_execution(tool_name="generate_function_graph")
@track_metrics("generate_function_graph")
@handle_tool_errors
async def _generate_function_graph_impl(
    file_path: str,
    function_address: str,
    format: str = "mermaid",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Internal implementation of generate_function_graph with caching.
    """
    # 1. Parameter validation
    validate_tool_parameters(
        "generate_function_graph",
        {"function_address": function_address, "format": format},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    from reversecore_mcp.core.exceptions import ValidationError
    from reversecore_mcp.core.validators import validate_address_format

    try:
        validate_address_format(function_address, "function_address")
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))

    # 3. Build radare2 command
    r2_cmd_str = f"agfj @ {function_address}"

    # 4. Execute subprocess asynchronously using helper
    # Large graphs need higher output limit
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_cmd_str],
        analysis_level="aaa",
        max_output_size=50_000_000,
        base_timeout=timeout,
    )

    # Add timestamp for cache visibility
    import time

    timestamp = time.time()

    # 5. Format conversion and return
    if format.lower() == "json":
        return success(output, bytes_read=bytes_read, format="json", timestamp=timestamp)

    elif format.lower() == "mermaid":
        mermaid_code = _radare2_json_to_mermaid(output)
        return success(
            mermaid_code,
            bytes_read=bytes_read,
            format="mermaid",
            description="Render this using Mermaid to see the control flow.",
            timestamp=timestamp,
        )

    elif format.lower() == "dot":
        # For DOT format, call radare2 with agfd command
        # NOTE: This is a separate call from agfj above, but this is optimal because:
        # - DOT format requires a different command (agfd vs agfj)
        # - Batching both would waste resources since we only need one format
        # - DOT format is rarely used (mermaid and json are preferred)
        dot_cmd_str = f"agfd @ {function_address}"

        dot_output, dot_bytes = await _execute_r2_command(
            validated_path,
            [dot_cmd_str],
            analysis_level="aaa",
            max_output_size=50_000_000,
            base_timeout=timeout,
        )
        return success(dot_output, bytes_read=dot_bytes, format="dot")

    return failure("INVALID_FORMAT", f"Unsupported format: {format}")


async def generate_function_graph(
    file_path: str,
    function_address: str,
    format: str = "mermaid",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Generate a Control Flow Graph (CFG) for a specific function.

    This tool uses radare2 to analyze the function structure and returns
    a visualization code (Mermaid by default) or PNG image that helps AI understand
    the code flow without reading thousands of lines of assembly.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address (e.g., 'main', '0x140001000', 'sym.foo')
        format: Output format ('mermaid', 'json', 'dot', or 'png'). Default is 'mermaid'.
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with CFG visualization, JSON data, or PNG image
    """
    import time

    from fastmcp.utilities.types import Image

    # If PNG format requested, generate DOT first then convert
    if format.lower() == "png":
        # Get DOT format first
        result = await _generate_function_graph_impl(file_path, function_address, "dot", timeout)

        if result.is_error:
            return result

        # Convert DOT to PNG using graphviz
        try:
            import subprocess
            import tempfile
            from pathlib import Path as PathlibPath

            # Get DOT content from result
            dot_content = result.content[0].text if result.content else ""

            # Create temp files
            with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as dot_file:
                dot_file.write(dot_content)
                dot_path = dot_file.name

            png_path = dot_path.replace(".dot", ".png")

            try:
                # Use async subprocess execution to avoid blocking the event loop
                # This allows concurrent operations and better resource utilization
                await execute_subprocess_async(
                    ["dot", "-Tpng", dot_path, "-o", png_path],
                    max_output_size=1_000_000,  # 1MB for error messages
                    timeout=30,
                )

                # Read PNG file
                png_data = PathlibPath(png_path).read_bytes()

                # Return Image object
                return Image(data=png_data, mime_type="image/png")

            finally:
                # Cleanup temp files
                try:
                    PathlibPath(dot_path).unlink()
                    if PathlibPath(png_path).exists():
                        PathlibPath(png_path).unlink()
                except (OSError, FileNotFoundError):
                    pass

        except Exception as e:
            return failure(
                "IMAGE_GENERATION_ERROR",
                f"Failed to generate PNG image: {str(e)}",
                hint="Ensure graphviz is installed in the container",
            )

    # For other formats, use existing implementation
    result = await _generate_function_graph_impl(file_path, function_address, format, timeout)

    # Check for cache hit
    if result.status == "success" and result.metadata:
        ts = result.metadata.get("timestamp")
        if ts and (time.time() - ts > 1.0):
            result.metadata["cache_hit"] = True
            # Update description to indicate cached result
            # Note: ToolSuccess has 'data' field, not 'content'

    return result


@log_execution(tool_name="analyze_xrefs")
@track_metrics("analyze_xrefs")
@handle_tool_errors
async def analyze_xrefs(
    file_path: str,
    address: str,
    xref_type: str = "all",
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context = None,
) -> ToolResult:
    """
    Analyze cross-references (xrefs) for a specific address using radare2.

    Cross-references show the relationships between code blocks - who calls this
    function (callers) and what it calls (callees). This is essential for:
    - Understanding program flow
    - Tracing data dependencies
    - Identifying attack surfaces
    - Reverse engineering malware C&C

    **xref_type Options:**
    - **"to"**: Show who references this address (callers/jumps TO here)
    - **"from"**: Show what this address references (calls/jumps FROM here)
    - **"all"**: Show both directions (complete relationship map)

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function or address to analyze (e.g., 'main', '0x401000', 'sym.decrypt')
        xref_type: Type of cross-references to show: 'all', 'to', 'from' (default: 'all')
        timeout: Execution timeout in seconds (default: 300)
        ctx: FastMCP Context for progress reporting (auto-injected)

    Returns:
        ToolResult with structured JSON containing xrefs data:
        {
            "address": "main",
            "xref_type": "all",
            "xrefs_to": [{"from": "0x401050", "type": "call", "fcn_name": "entry0"}],
            "xrefs_from": [{"addr": "0x401100", "type": "call", "fcn_name": "printf"}],
            "summary": "2 reference(s) TO this address (callers), 1 reference(s) FROM this address (callees)",
            "total_refs_to": 2,
            "total_refs_from": 1
        }

    Example:
        # Find who calls the suspicious 'decrypt' function
        analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")

        # Find what APIs a malware function uses
        analyze_xrefs("/app/workspace/malware.exe", "0x401000", "from")

        # Get complete relationship map
        analyze_xrefs("/app/workspace/malware.exe", "main", "all")
    """
    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if xref_type not in ["all", "to", "from"]:
        return failure(
            "VALIDATION_ERROR",
            f"Invalid xref_type: {xref_type}",
            hint="Valid options are: 'all', 'to', 'from'",
        )

    # 2. Validate address format
    # OPTIMIZATION: Use pre-compiled pattern from validators module
    if not _ADDRESS_PATTERN.match(
        _strip_address_prefixes(address),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, and prefixes like '0x', 'sym.', 'fcn.'",
        )

    # 3. Build radare2 commands to get xrefs
    # axj = analyze xrefs in JSON format
    commands = []

    if xref_type in ["all", "to"]:
        # axtj = xrefs TO this address (callers)
        commands.append(f"axtj @ {address}")

    if xref_type in ["all", "from"]:
        # axfj = xrefs FROM this address (callees)
        commands.append(f"axfj @ {address}")

    # Build command string
    r2_commands_str = "; ".join(commands)

    if ctx:
        await ctx.report_progress(10, 100)
        await ctx.info(f"Analyzing xrefs for {address}...")

    # 4. Execute analysis using helper
    # Use 'aa' (basic analysis) as default to prevent timeouts on large/obfuscated binaries
    # 'aaa' is much slower but more accurate - only use for small files

    analysis_level = "aa"
    try:
        file_size_mb = os.path.getsize(validated_path) / (1024 * 1024)
        if file_size_mb < 5:
            analysis_level = "aaa"  # Full analysis for small files (<5MB)
        if ctx and file_size_mb > 5:
            await ctx.info(f"Large file ({file_size_mb:.1f}MB) detected, using basic analysis...")
    except OSError:
        pass

    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_commands_str],
        analysis_level=analysis_level,
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    if ctx:
        await ctx.report_progress(90, 100)

    # 5. Parse JSON output
    try:
        # Output may contain multiple JSON arrays if both "to" and "from" were requested
        # Split by lines and parse each JSON array
        lines = [line.strip() for line in output.strip().split("\n") if line.strip()]

        xrefs_to = []
        xrefs_from = []

        for line in lines:
            # Robust JSON extraction from line
            try:
                refs = _parse_json_output(line)
                if isinstance(refs, list) and refs:  # OPTIMIZATION: Direct bool check instead of len() comparison
                    # Determine if this is "to" or "from" based on field names
                    first_ref = refs[0]
                    if "from" in first_ref:
                        # This is xrefs TO (callers)
                        xrefs_to = refs
                    elif "addr" in first_ref or "fcn_addr" in first_ref:
                        # This is xrefs FROM (callees)
                        xrefs_from = refs
            except json.JSONDecodeError:
                # Skip lines that don't contain valid JSON
                continue

        # 6. Format results
        result = {
            "address": address,
            "xref_type": xref_type,
            "xrefs_to": xrefs_to,
            "xrefs_from": xrefs_from,
            "total_refs_to": len(xrefs_to),
            "total_refs_from": len(xrefs_from),
        }

        # Add human-readable summary
        summary_parts = []
        if xrefs_to:
            summary_parts.append(f"{len(xrefs_to)} reference(s) TO this address (callers)")
        if xrefs_from:
            summary_parts.append(f"{len(xrefs_from)} reference(s) FROM this address (callees)")

        if not summary_parts:
            summary = "No cross-references found"
        else:
            summary = ", ".join(summary_parts)

        result["summary"] = summary

        # 7. Return structured result
        return success(
            result,
            bytes_read=bytes_read,
            address=address,
            xref_type=xref_type,
            total_refs=len(xrefs_to) + len(xrefs_from),
            description=f"Cross-reference analysis for {address}: {summary}",
        )

    except Exception as e:
        return failure(
            "XREF_ANALYSIS_ERROR",
            f"Failed to parse cross-reference data: {str(e)}",
            hint="The address may not exist or the binary may not have been analyzed. Try running 'afl' first to see available functions.",
        )
