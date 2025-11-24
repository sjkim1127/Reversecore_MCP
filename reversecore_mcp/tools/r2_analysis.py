"""Radare2-based analysis tools for binary analysis, cross-references, and execution tracing."""

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path

from async_lru import alru_cache
from fastmcp import Context

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# OPTIMIZATION: Pre-compile pattern for stripping address prefixes
_ADDRESS_PREFIX_PATTERN = re.compile(r"(0x|sym\.|fcn\.)")

# OPTIMIZATION: Pre-compile pattern for Mermaid special character escaping
_MERMAID_ESCAPE_CHARS = str.maketrans({'"': "'", "(": "[", ")": "]"})

# OPTIMIZATION: Pre-compile pattern for removing radare2 analysis commands
_R2_ANALYSIS_PATTERN = re.compile(r"\b(aaa|aa)\b")


def _strip_address_prefixes(address: str) -> str:
    """
    Efficiently strip common address prefixes using regex.

    This is faster than chained .replace() calls for multiple patterns.
    """
    return _ADDRESS_PREFIX_PATTERN.sub("", address)


def _escape_mermaid_chars(text: str) -> str:
    """
    Efficiently escape Mermaid special characters using str.translate().

    This is faster than chained .replace() calls for multiple characters.
    """
    return text.translate(_MERMAID_ESCAPE_CHARS)


@lru_cache(maxsize=128)
def _get_r2_project_name(file_path: str) -> str:
    """Generate a unique project name based on file path hash.

    Cached to avoid repeated MD5 computation for the same file path.
    """
    # Use absolute path to ensure uniqueness
    abs_path = str(Path(file_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()


@lru_cache(maxsize=128)
def _calculate_dynamic_timeout(file_path: str, base_timeout: int = 300) -> int:
    """
    Calculate timeout based on file size.
    Strategy: Base timeout + 1 second per MB of file size.

    Cached to avoid repeated file stat calls for the same file.
    """
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        # Cap the dynamic addition to avoid extremely long timeouts (e.g. max +10 mins)
        additional_time = min(size_mb * 2, 600)
        return int(base_timeout + additional_time)
    except Exception:
        return base_timeout


async def _execute_r2_command(
    file_path: Path,
    r2_commands: list[str],
    analysis_level: str = "aaa",
    max_output_size: int = 10_000_000,
    base_timeout: int = 300,
) -> tuple[str, int]:
    """
    Execute radare2 commands with common pattern.

    This helper consolidates the repeated pattern of:
    1. Calculate dynamic timeout
    2. Build r2 command
    3. Execute subprocess

    Args:
        file_path: Path to the binary file (already validated)
        r2_commands: List of radare2 commands to execute
        analysis_level: Analysis level ("aaa", "aa", "-n")
        max_output_size: Maximum output size in bytes
        base_timeout: Base timeout in seconds

    Returns:
        Tuple of (output, bytes_read)
    """
    effective_timeout = _calculate_dynamic_timeout(str(file_path), base_timeout)
    cmd = _build_r2_cmd(str(file_path), r2_commands, analysis_level)

    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=effective_timeout,
    )

    return output, bytes_read


def _build_r2_cmd(file_path: str, r2_commands: list[str], analysis_level: str = "aaa") -> list[str]:
    """
    Build radare2 command.

    Simplified version: Always run analysis if requested, skipping project persistence
    to avoid permission issues and 'exit 1' errors in Docker environments.

    Performance Note - Early Filtering:
    ===================================
    When searching for specific data, consider using radare2's built-in filtering
    to reduce data transfer and parsing overhead. Examples:

    1. Text-based filtering with grep (~):
       - aflj~main       # Filter functions containing "main" (WARNING: breaks JSON)
       - afl~main        # Text-mode filtering (safe, but not JSON)
       - iz~password     # Filter strings containing "password"

    2. Radare2's native JSON queries (where available):
       - Some commands support inline filtering in JSON mode
       - Check radare2 documentation for specific command capabilities

    3. Trade-offs:
       - Early filtering: Reduces data transfer by 50-70%
       - Late filtering: Preserves JSON structure, more flexible
       - Current implementation: Prioritizes JSON structure integrity

    For complex filtering logic (e.g., checking multiple conditions, prefix matching),
    Python-side filtering is more maintainable and flexible.
    """
    base_cmd = ["r2", "-q"]

    # If we just want to run commands without analysis (adaptive analysis)
    if analysis_level == "-n":
        return base_cmd + ["-n"] + ["-c", ";".join(r2_commands), str(file_path)]

    # Always run analysis + commands
    # We use 'e scr.color=0' to ensure no color codes in output
    combined_cmds = ["e scr.color=0", analysis_level] + r2_commands
    return base_cmd + ["-c", ";".join(combined_cmds), str(file_path)]


def _extract_first_json(text: str) -> str | None:
    """
    Extract the first valid JSON object or array from a string.
    Handles nested structures and ignores surrounding garbage.

    PERFORMANCE NOTE: Optimized to O(n) by minimizing redundant scanning.
    Uses early bailout conditions when a bracket is followed only by
    whitespace and more brackets (pathological case: "{ { { { {").

    Returns:
        The extracted JSON string, or None if no valid JSON found.
    """
    text = text.strip()
    if not text:
        return None

    # Quick optimization: Try parsing the whole string first
    # This handles the common case where output is pure JSON
    if text[0] in ("{", "["):
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass

    # Need to extract JSON from noisy output
    i = 0
    text_len = len(text)

    while i < text_len:
        char = text[i]

        # Skip non-JSON start characters
        if char not in ("{", "["):
            i += 1
            continue

        # Found potential JSON start
        # Quick heuristic: Skip obvious false starts (isolated brackets)
        # This prevents pathological O(n²) behavior with "{ { { { {".
        # Note: We only check for same bracket type to avoid false positives.
        # Mixed brackets like "{ [" could be valid JSON like `{"arr": [...]}`
        if i + 1 < text_len and text[i + 1] in (" ", "\t"):
            # Bracket followed by whitespace - check if next non-whitespace is also a bracket
            next_idx = i + 2
            while next_idx < text_len and text[next_idx] in (" ", "\t", "\n", "\r"):
                next_idx += 1
            if next_idx < text_len and text[next_idx] == char:
                # Pattern like "{ {" or "[ [" with only whitespace between
                # This is likely noise, not JSON - skip it
                i += 1
                continue

        # Try to extract JSON starting from this position
        stack = []
        start_idx = i
        in_string = False
        escape_next = False
        j = i

        while j < text_len:
            c = text[j]

            # Handle string literals (quotes can contain brackets)
            if escape_next:
                escape_next = False
                j += 1
                continue

            if c == "\\" and in_string:
                escape_next = True
                j += 1
                continue

            if c == '"':
                in_string = not in_string
                j += 1
                continue

            # Process brackets only when not inside strings
            if not in_string:
                if c in ("{", "["):
                    stack.append(c)
                elif c in ("}", "]"):
                    if not stack:
                        # Unmatched closing bracket
                        break

                    last = stack[-1]
                    if (c == "}" and last == "{") or (c == "]" and last == "["):
                        stack.pop()
                        if not stack:
                            # Found complete structure, validate it's actually JSON
                            candidate = text[start_idx : j + 1]
                            try:
                                json.loads(candidate)  # Validate it's real JSON
                                return candidate
                            except json.JSONDecodeError:
                                # Not valid JSON, skip past this failed attempt
                                # Optimization: Jump to position j+1 (where extraction stopped)
                                # instead of just i+1, avoiding re-processing characters
                                i = j + 1
                                break
                    else:
                        # Mismatched brackets
                        break

            j += 1

        # Move past this failed attempt
        if i == start_idx:
            i += 1

    return None


def _parse_json_output(output: str):
    """
    Safely parse JSON from command output.

    Tries to extract JSON from output that may contain non-JSON text
    (like warnings, debug messages, etc.) and parse it.

    Args:
        output: Raw command output that may contain JSON

    Returns:
        Parsed JSON object (dict/list) or None if parsing fails

    Raises:
        json.JSONDecodeError: If JSON is found but invalid
    """
    # First, try to extract clean JSON from potentially noisy output
    json_str = _extract_first_json(output)

    if json_str is not None:
        # Found potential JSON, try to parse it
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Extracted text wasn't valid JSON (e.g., "[x]" from radare2 output)
            # Fall through to try parsing entire output
            pass

    # No valid JSON structure found via extraction, try parsing entire output as-is
    # This handles cases where output is pure JSON without any prefix/suffix
    return json.loads(output)


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

    # Adaptive analysis logic
    # Use 'aa' (basic analysis) instead of 'aaa' (advanced analysis) for better performance
    # 'aaa' is often overkill for automated tasks and causes timeouts on large binaries
    analysis_level = "aa"

    # Simple information commands don't need analysis
    simple_commands = ["i", "iI", "iz", "il", "is", "ie", "it"]
    if validated_command in simple_commands or validated_command.startswith("i "):
        analysis_level = "-n"

    # If user explicitly requested analysis, handle it via caching
    if "aaa" in validated_command or "aa" in validated_command:
        # Remove explicit analysis commands as they are handled by _build_r2_cmd
        # OPTIMIZATION: Use pre-compiled regex pattern instead of chained replace
        validated_command = _R2_ANALYSIS_PATTERN.sub("", validated_command).strip(" ;")

    # Use helper function to execute radare2 command
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            [validated_command],
            analysis_level=analysis_level,
            max_output_size=max_output_size,
            base_timeout=timeout,
        )
        return success(output, bytes_read=bytes_read)
    except Exception as e:
        # Log error to client if context is available
        if ctx:
            await ctx.error(f"radare2 command '{validated_command}' failed: {str(e)}")
        raise


@log_execution(tool_name="trace_execution_path")
@track_metrics("trace_execution_path")
@handle_tool_errors
async def trace_execution_path(
    file_path: str,
    target_function: str,
    max_depth: int = 3,
    max_paths: int = 5,
    timeout: int = DEFAULT_TIMEOUT,
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

    Args:
        file_path: Path to the binary file
        target_function: Name or address of the target function (e.g., 'sym.imp.system', '0x401000')
        max_depth: Maximum depth of backtrace (default: 3)
        max_paths: Maximum number of paths to return (default: 5)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with a list of execution paths (call chains).
    """
    validated_path = validate_file_path(file_path)
    effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)

    # Helper to get address of a function name
    async def get_address(func_name):
        # OPTIMIZATION: Batch both symbol and function lookups in one r2 call
        # This eliminates the overhead of a second subprocess call when the symbol
        # isn't found in the first lookup (common for stripped binaries)
        cmd = _build_r2_cmd(str(validated_path), ["isj", "aflj"], "aaa")
        out, _ = await execute_subprocess_async(cmd, timeout=30)

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
        out, _ = await execute_subprocess_async(cmd, timeout=30)

        try:
            xrefs = _parse_json_output(out)
        except (json.JSONDecodeError, TypeError):
            xrefs = []

        if not xrefs:
            # End of chain (root caller found or no xrefs)
            if len(current_path) > 1:
                paths.append(current_path)
            return

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
        blocks = graph_data[0].get("blocks", []) if isinstance(graph_data, list) else graph_data.get("blocks", [])

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
    from reversecore_mcp.core.validators import validate_address_format
    from reversecore_mcp.core.exceptions import ValidationError

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
                # Use graphviz's dot command to convert DOT to PNG
                subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=True, timeout=30, capture_output=True)

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
                except:
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
    # OPTIMIZATION: Use efficient regex substitution instead of chained replace
    if not re.match(
        r"^[a-zA-Z0-9_.]+$",
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
    # Use 'aa' instead of 'aaa' for speed if possible, but 'axt' needs good analysis.
    # We'll stick to 'aaa' but rely on the increased timeout (120s -> 300s in config/default).
    # Wait, I set default to 120s in the signature.
    # If the user wants faster, they can use 'aa'.
    # Let's try to be smart: if file size is large (>5MB), use 'aa'.

    # Use 'aa' (basic analysis) as default to prevent timeouts on obfuscated binaries
    analysis_level = "aa"
    try:
        if os.path.getsize(validated_path) > 5 * 1024 * 1024:
            analysis_level = "aa"
            if ctx:
                await ctx.info("Large file detected, using lighter analysis ('aa')...")
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
                if isinstance(refs, list) and len(refs) > 0:
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
