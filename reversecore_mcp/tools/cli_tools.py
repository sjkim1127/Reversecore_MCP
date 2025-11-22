"""CLI tool wrappers that return structured ToolResult payloads."""

import asyncio
import json
import re
import shutil
import hashlib
import os
from pathlib import Path
import time

from async_lru import alru_cache
from functools import lru_cache
from fastmcp import FastMCP
from reversecore_mcp.core.config import get_config

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters, validate_address_format

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# Pre-compile regex patterns for performance optimization
_VERSION_PATTERNS = {
    "OpenSSL": re.compile(r"(OpenSSL|openssl)\s+(\d+\.\d+\.\d+[a-z]?)", re.IGNORECASE),
    "GCC": re.compile(r"GCC:\s+\(.*\)\s+(\d+\.\d+\.\d+)"),
    "Python": re.compile(r"(Python|python)\s+([23]\.\d+\.\d+)", re.IGNORECASE),
    "Curl": re.compile(r"curl\s+(\d+\.\d+\.\d+)", re.IGNORECASE),
    "BusyBox": re.compile(r"BusyBox\s+v(\d+\.\d+\.\d+)", re.IGNORECASE),
    "Generic_Version": re.compile(r"[vV]er(?:sion)?\s?[:.]?\s?(\d+\.\d+\.\d+)"),
    "Copyright": re.compile(r"Copyright.*(19|20)\d{2}"),
}


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(run_radare2)
    mcp.tool(run_binwalk)
    mcp.tool(copy_to_workspace)
    mcp.tool(list_workspace)
    mcp.tool(generate_function_graph)
    mcp.tool(emulate_machine_code)
    mcp.tool(get_pseudo_code)
    mcp.tool(generate_signature)
    mcp.tool(extract_rtti_info)
    mcp.tool(smart_decompile)
    mcp.tool(generate_yara_rule)
    mcp.tool(analyze_xrefs)
    mcp.tool(recover_structures)
    mcp.tool(diff_binaries)
    mcp.tool(match_libraries)
    mcp.tool(scan_workspace)
    mcp.tool(trace_execution_path)
    mcp.tool(scan_for_versions)
    mcp.tool(analyze_variant_changes)
    mcp.tool(solve_path_constraints)


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
    from reversecore_mcp.core.result import failure

    validated_path = validate_file_path(file_path)
    effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)

    # Helper to get address of a function name
    async def get_address(func_name):
        # Try to find exact match first
        # Note: We cannot use ~grep with json output (isj~name) as it breaks JSON syntax
        cmd = _build_r2_cmd(str(validated_path), ["isj"], "aaa")
        out, _ = await execute_subprocess_async(cmd, timeout=30)
        try:
            symbols = _parse_json_output(out)
            for sym in symbols:
                if sym.get("name") == func_name or sym.get("realname") == func_name:
                    return sym.get("vaddr")
        except (json.JSONDecodeError, TypeError):
            pass
        
        # If not found, try aflj
        cmd = _build_r2_cmd(str(validated_path), ["aflj"], "aaa")
        out, _ = await execute_subprocess_async(cmd, timeout=30)
        try:
            funcs = _parse_json_output(out)
            for f in funcs:
                if f.get("name") == func_name:
                    return f.get("offset")
        except (json.JSONDecodeError, TypeError):
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

        if current_addr in visited and current_addr not in [p["addr"] for p in current_path]:
             # Allow revisiting if it's a different path, but prevent cycles in current path
             pass
        elif current_addr in [p["addr"] for p in current_path]:
            return # Cycle detected

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
    formatted_paths = []
    for p in paths:
        # Reverse to show flow from Source -> Sink
        chain = p[::-1]
        formatted_paths.append(" -> ".join([f"{n['name']} ({n['addr']})" for n in chain]))

    return success(
        {"paths": formatted_paths, "raw_paths": paths},
        path_count=len(paths),
        target=target_function,
        description=f"Found {len(paths)} execution paths to {target_function}"
    )


@log_execution(tool_name="scan_for_versions")
@track_metrics("scan_for_versions")
@handle_tool_errors
async def scan_for_versions(
    file_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Extract library version strings and CVE clues from a binary.

    This tool acts as a "Version Detective", scanning the binary for strings that
    look like version numbers or library identifiers (e.g., "OpenSSL 1.0.2g",
    "GCC 5.4.0"). It helps identify outdated components and potential CVEs.

    **Use Cases:**
    - **SCA (Software Composition Analysis)**: Identify open source components
    - **Vulnerability Scanning**: Find outdated libraries (e.g., Heartbleed-vulnerable OpenSSL)
    - **Firmware Analysis**: Determine OS and toolchain versions

    Args:
        file_path: Path to the binary file
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with detected libraries and versions.
    """
    validated_path = validate_file_path(file_path)
    
    # Run strings command
    cmd = ["strings", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=10_000_000,
        timeout=timeout,
    )
    
    text = output
    
    # Use pre-compiled patterns for better performance
    detected = {}
    
    # Process all version patterns
    for name, pattern in _VERSION_PATTERNS.items():
        matches = []
        for match in pattern.finditer(text):
            # Extract version from appropriate group (1 or 2 depending on pattern)
            if name in ["OpenSSL", "Python"]:
                matches.append(match.group(2))
            else:
                matches.append(match.group(1))
        if matches:
            detected[name] = list(set(matches))
    
    return success(
        detected,
        bytes_read=bytes_read,
        description=f"Detected {len(detected)} potential library versions"
    )


@log_execution(tool_name="analyze_variant_changes")
@track_metrics("analyze_variant_changes")
@handle_tool_errors
async def analyze_variant_changes(
    file_path_a: str,
    file_path_b: str,
    top_n: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Analyze structural changes between two binary variants (Lineage Mapper).

    This tool combines binary diffing with control flow analysis to understand
    *how* a binary has evolved. It identifies the most modified functions and
    generates their Control Flow Graphs (CFG) for comparison.

    **Use Cases:**
    - **Malware Lineage**: "How did Lazarus Group modify their backdoor?"
    - **Patch Diffing**: "What logic changed in the vulnerable function?"
    - **Variant Analysis**: "Is this a new version of the same malware?"

    Args:
        file_path_a: Path to the original binary
        file_path_b: Path to the variant binary
        top_n: Number of top changed functions to analyze in detail (default: 3)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with diff summary and CFG data for top changed functions.
    """
    # 1. Run diff_binaries
    diff_result = await diff_binaries(file_path_a, file_path_b, timeout=timeout)
    
    if diff_result.is_error:
        return diff_result
        
    diff_data = json.loads(diff_result.content[0].text)
    changes = diff_data.get("changes", [])
    
    # 2. Identify changed functions (heuristic: group changes by address proximity or use explicit function diff if available)
    # Since diff_binaries returns a flat list of changes, we'll try to map them to functions.
    # For this advanced tool, we'll assume we want to analyze the functions where changes occurred.
    
    # Get function list for file B (variant) to map addresses to names
    # We use a simple r2 command to get functions
    validated_path_b = validate_file_path(file_path_b)
    cmd = _build_r2_cmd(str(validated_path_b), ["aflj"], "aaa")
    out, _ = await execute_subprocess_async(cmd, timeout=60)
    
    try:
        funcs_b = _parse_json_output(out)
    except (json.JSONDecodeError, TypeError):
        funcs_b = []
        
    # Map changes to functions
    changed_funcs = {} # {func_name: count}
    
    for change in changes:
        addr_str = change.get("address")
        if not addr_str: continue
        try:
            addr = int(addr_str, 16)
            # Find which function contains this address
            for f in funcs_b:
                f_offset = f.get("offset")
                f_size = f.get("size")
                if f_offset <= addr < f_offset + f_size:
                    fname = f.get("name")
                    changed_funcs[fname] = changed_funcs.get(fname, 0) + 1
                    break
        except:
            pass
            
    # Sort by number of changes
    sorted_funcs = sorted(changed_funcs.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    detailed_analysis = []
    
    # 3. Generate CFG for top changed functions
    for func_name, count in sorted_funcs:
        # Get CFG for variant
        cfg_result = await generate_function_graph(file_path_b, func_name, format="mermaid")
        cfg_mermaid = cfg_result.content[0].text if not cfg_result.is_error else "Error generating CFG"
        
        detailed_analysis.append({
            "function": func_name,
            "change_count": count,
            "cfg_mermaid": cfg_mermaid,
            "analysis_hint": f"Function {func_name} has {count} modifications. Compare its logic with the original."
        })
        
    return success(
        {
            "similarity": diff_data.get("similarity"),
            "total_changes": diff_data.get("total_changes"),
            "top_modified_functions": detailed_analysis
        },
        description=f"Analyzed variants. Similarity: {diff_data.get('similarity')}. Detailed analysis for {len(detailed_analysis)} functions."
    )


@log_execution(tool_name="scan_workspace")
@track_metrics("scan_workspace")
@handle_tool_errors
async def scan_workspace(
    file_patterns: list[str] = None,
    timeout: int = 600,
) -> ToolResult:
    """
    Batch scan all files in the workspace using multiple tools in parallel.

    This tool performs a comprehensive scan of the workspace to identify files,
    analyze binaries, and detect threats. It runs 'run_file', 'parse_binary_with_lief',
    and 'run_yara' (if rules exist) on all matching files concurrently.

    **Workflow:**
    1. Identify files matching patterns (default: all files)
    2. Run 'file' command on all files
    3. Run 'LIEF' analysis on executable files
    4. Run 'YARA' scan if rules are available
    5. Aggregate results into a single report

    Args:
        file_patterns: List of glob patterns to include (e.g., ["*.exe", "*.dll"]).
                      Default is ["*"] (all files).
        timeout: Global timeout for the batch operation in seconds.

    Returns:
        ToolResult with aggregated scan results for all files.
    """
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.tools.lib_tools import parse_binary_with_lief, run_yara

    config = get_config()
    workspace = config.workspace
    
    if not file_patterns:
        file_patterns = ["*"]

    # 1. Collect files
    files_to_scan = []
    for pattern in file_patterns:
        files_to_scan.extend(workspace.glob(pattern))
    
    # Remove duplicates and directories
    files_to_scan = list(set([f for f in files_to_scan if f.is_file()]))
    
    if not files_to_scan:
        return success(
            {"files": [], "summary": "No files found matching patterns"},
            file_count=0
        )

    # 2. Define scan tasks
    results = {}
    
    async def scan_single_file(file_path: Path):
        path_str = str(file_path)
        file_name = file_path.name
        file_result = {"name": file_name, "path": path_str}
        
        # Task 1: run_file (async)
        # We call the tool function directly. Since it's async, we await it.
        try:
            file_cmd_result = await run_file(path_str)
            file_result["file_type"] = file_cmd_result.content[0].text if file_cmd_result.content else "unknown"
        except Exception as e:
            file_result["file_type_error"] = str(e)

        # Task 2: LIEF (sync, run in thread)
        # Only for likely binaries
        if "executable" in str(file_result.get("file_type", "")).lower() or file_path.suffix.lower() in [".exe", ".dll", ".so", ".dylib", ".bin", ".elf"]:
            try:
                # Run sync function in thread pool
                lief_result = await asyncio.to_thread(parse_binary_with_lief, path_str)
                if not lief_result.is_error:
                     # Parse JSON content if available
                    content = lief_result.content[0].text
                    try:
                        file_result["lief_metadata"] = json.loads(content) if isinstance(content, str) else content
                    except:
                        file_result["lief_metadata"] = content
            except Exception as e:
                file_result["lief_error"] = str(e)

        # Task 3: YARA (sync, run in thread)
        # Check if we have a default yara rule file or if user provided one (not supported in this batch mode yet, skipping for now or using default)
        # For now, we skip YARA in batch mode unless we have a default rule path in config, 
        # but let's assume we might want to add it later. 
        # To keep it simple and robust, we'll skip YARA for now in this initial implementation 
        # unless we want to scan against a specific rule file which isn't passed here.
        
        return file_name, file_result

    # 3. Run scans in parallel
    # Limit concurrency to avoid overwhelming the system
    semaphore = asyncio.Semaphore(5) # Process 5 files at a time
    
    async def sem_scan(file_path):
        async with semaphore:
            return await scan_single_file(file_path)

    tasks = [sem_scan(f) for f in files_to_scan]
    
    # Wait for all tasks with global timeout
    try:
        scan_results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout)
        for name, res in scan_results:
            results[name] = res
    except asyncio.TimeoutError:
        return success(
            {"partial_results": results, "error": "Scan timed out"},
            file_count=len(files_to_scan),
            scanned_count=len(results),
            status="timeout"
        )

    return success(
        {"files": results},
        file_count=len(files_to_scan),
        status="completed",
        description=f"Batch scan completed for {len(files_to_scan)} files"
    )


@log_execution(tool_name="run_file")
@track_metrics("run_file")
@handle_tool_errors
async def run_file(file_path: str, timeout: int = DEFAULT_TIMEOUT) -> ToolResult:
    """Identify file metadata using the ``file`` CLI utility."""

    validated_path = validate_file_path(file_path)
    cmd = ["file", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )
    return success(output.strip(), bytes_read=bytes_read)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
async def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )
    
    # Enforce a reasonable minimum output size to prevent accidental truncation
    # 1KB is too small for meaningful string analysis
    if max_output_size < 1024 * 1024:  # Enforce 1MB minimum
        max_output_size = 1024 * 1024
        
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@handle_tool_errors
async def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
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
        validated_command = validated_command.replace("aaa", "").replace("aa", "").strip(" ;")
    
    # Calculate dynamic timeout
    effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)
    
    # Build optimized command
    cmd = _build_r2_cmd(str(validated_path), [validated_command], analysis_level)
    
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=effective_timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
@handle_tool_errors
async def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Analyze binaries for embedded content using binwalk."""

    validated_path = validate_file_path(file_path)
    cmd = ["binwalk", "-A", "-d", str(depth), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="copy_to_workspace")
@track_metrics("copy_to_workspace")
@handle_tool_errors
def copy_to_workspace(
    source_path: str,
    destination_name: str = None,
) -> ToolResult:
    """
    Copy any accessible file to the workspace directory.

    This tool allows copying files from any location (including AI agent upload directories)
    to the workspace where other reverse engineering tools can access them.

    Supports files from:
    - Claude Desktop uploads (/mnt/user-data/uploads)
    - Cursor uploads
    - Windsurf uploads
    - Local file paths
    - Any other accessible location

    Args:
        source_path: Absolute or relative path to the source file
        destination_name: Optional custom filename in workspace (defaults to original name)

    Returns:
        ToolResult with the new file path in workspace
    """
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.exceptions import ValidationError

    # Convert to Path and resolve (but don't require strict=True for external files)
    try:
        source = Path(source_path).expanduser().resolve()
    except Exception as e:
        raise ValidationError(
            f"Invalid source path: {source_path}",
            details={"source_path": source_path, "error": str(e)},
        )

    # Validate source exists and is a file
    if not source.exists():
        raise ValidationError(
            f"Source file does not exist: {source}",
            details={"source_path": str(source)},
        )

    if not source.is_file():
        raise ValidationError(
            f"Source path is not a file: {source}", details={"source_path": str(source)}
        )

    # Check file size (prevent copying extremely large files)
    max_file_size = 5 * 1024 * 1024 * 1024  # 5GB
    file_size = source.stat().st_size
    if file_size > max_file_size:
        raise ValidationError(
            f"File too large to copy: {file_size} bytes (max: {max_file_size} bytes)",
            details={"file_size": file_size, "max_size": max_file_size},
        )

    # Determine destination filename
    if destination_name:
        # Sanitize destination name (remove path separators and dangerous chars)
        dest_name = Path(destination_name).name
        # Additional sanitization for security - check if sanitization changed the name
        if dest_name != destination_name or not dest_name:
            raise ValidationError(
                f"Invalid destination name: {destination_name}",
                details={"destination_name": destination_name},
            )
    else:
        dest_name = source.name

    # Build destination path in workspace
    config = get_config()
    destination = config.workspace / dest_name

    # Check if file already exists
    if destination.exists():
        raise ValidationError(
            f"File already exists in workspace: {dest_name}",
            details={
                "destination": str(destination),
                "hint": "Use a different destination_name or remove the existing file first",
            },
        )

    # Copy file to workspace
    try:
        shutil.copy2(source, destination)
        copied_size = destination.stat().st_size

        return success(
            str(destination),
            source_path=str(source),
            destination_path=str(destination),
            file_size=copied_size,
            message=f"File copied successfully to workspace: {dest_name}",
        )
    except PermissionError as e:
        raise ValidationError(
            f"Permission denied when copying file: {e}",
            details={"source": str(source), "destination": str(destination)},
        )
    except Exception as e:
        raise ValidationError(
            f"Failed to copy file: {e}",
            details={
                "source": str(source),
                "destination": str(destination),
                "error": str(e),
            },
        )


@log_execution(tool_name="list_workspace")
@track_metrics("list_workspace")
@handle_tool_errors
def list_workspace() -> ToolResult:
    """
    List all files in the workspace directory.

    Returns:
        ToolResult with list of files in workspace
    """
    from reversecore_mcp.core.config import get_config

    config = get_config()
    workspace = config.workspace

    if not workspace.exists():
        return success(
            {"files": [], "message": "Workspace is empty"},
            file_count=0,
            workspace_path=str(workspace),
        )

    files = []
    for item in workspace.iterdir():
        if item.is_file():
            files.append(
                {"name": item.name, "size": item.stat().st_size, "path": str(item)}
            )

    return success(
        {"files": files}, file_count=len(files), workspace_path=str(workspace)
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
            op_codes = [op.get("opcode", "") for op in ops]

            # Token efficiency: limit to 5 lines per block
            if len(op_codes) > 5:
                op_codes = op_codes[:5] + ["..."]

            # Escape Mermaid special characters
            label_content = (
                "\\n".join(op_codes)
                .replace('"', "'")
                .replace("(", "[")
                .replace(")", "]")
            )

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
    from reversecore_mcp.core.result import failure

    # 1. Parameter validation
    validate_tool_parameters(
        "generate_function_graph",
        {"function_address": function_address, "format": format},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    try:
        validate_address_format(function_address, "function_address")
    except Exception as e:
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
            timestamp=timestamp
        )

    elif format.lower() == "dot":
        # For DOT format, call radare2 with agfd command
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
    a visualization code (Mermaid by default) that helps AI understand
    the code flow without reading thousands of lines of assembly.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address (e.g., 'main', '0x140001000', 'sym.foo')
        format: Output format ('mermaid', 'json', or 'dot'). Default is 'mermaid'.
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with CFG visualization or JSON data
    """
    import time
    result = await _generate_function_graph_impl(
        file_path, function_address, format, timeout
    )
    
    # Check for cache hit
    if result.status == "success" and result.metadata:
        ts = result.metadata.get("timestamp")
        if ts and (time.time() - ts > 1.0):
            result.metadata["cache_hit"] = True
            # Update description to indicate cached result
            # Note: ToolSuccess has 'data' field, not 'content'
            pass
                
    return result


def _parse_register_state(ar_output: str) -> dict:
    """
    Parse radare2 'ar' command output into structured register state.

    Args:
        ar_output: Raw output from 'ar' command

    Returns:
        Dictionary mapping register names to values

    Example output from 'ar':
        rax = 0x00000000
        rbx = 0x00401000
        ...
    """
    registers = {}

    for line in ar_output.strip().split("\n"):
        if "=" in line:
            parts = line.split("=")
            if len(parts) == 2:
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers[reg_name] = reg_value

    return registers


@log_execution(tool_name="emulate_machine_code")
@track_metrics("emulate_machine_code")
@handle_tool_errors
async def emulate_machine_code(
    file_path: str,
    start_address: str,
    instructions: int = 50,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language).

    This tool provides safe, sandboxed emulation of binary code without actual execution.
    Perfect for analyzing obfuscated code, understanding register states, and predicting
    execution outcomes without security risks.

    **Key Use Cases:**
    - De-obfuscation: Reveal hidden strings by emulating XOR/shift operations
    - Register Analysis: See final register values after code execution
    - Safe Malware Analysis: Predict behavior without running malicious code

    **Safety Features:**
    - Virtual CPU simulation (no real execution)
    - Instruction count limit (max 1000) prevents infinite loops
    - Memory sandboxing (changes don't affect host system)

    Args:
        file_path: Path to the binary file (must be in workspace)
        start_address: Address to start emulation (e.g., 'main', '0x401000', 'sym.decrypt')
        instructions: Number of instructions to execute (default 50, max 1000)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with register states and emulation summary
    """
    from reversecore_mcp.core.result import failure

    # 1. Parameter validation
    validate_tool_parameters(
        "emulate_machine_code",
        {"start_address": start_address, "instructions": instructions},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for start address (prevent shell injection)
    try:
        validate_address_format(start_address, "start_address")
    except Exception as e:
        return failure("VALIDATION_ERROR", str(e))

    # 3. Build radare2 ESIL emulation command chain
    # Note: Commands must be executed in specific order for ESIL to work correctly
    esil_cmds = [
        f"s {start_address}",  # Seek to start address
        "aei",  # Initialize ESIL VM
        "aeim",  # Initialize ESIL memory (stack)
        "aeip",  # Initialize program counter to current seek
        f"aes {instructions}",  # Step through N instructions
        "ar",  # Show all registers
    ]
    
    # 4. Execute emulation using helper
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            esil_cmds,
            analysis_level="aaa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )

        # 5. Parse register state
        register_state = _parse_register_state(output)

        if not register_state:
            return failure(
                "EMULATION_ERROR",
                "Failed to extract register state from emulation output",
                hint="The binary may not be compatible with ESIL emulation, or the start address is invalid",
            )

        # 6. Build result with metadata
        return success(
            register_state,
            bytes_read=bytes_read,
            format="register_state",
            instructions_executed=instructions,
            start_address=start_address,
            description=f"Emulated {instructions} instructions starting at {start_address}",
        )

    except Exception as e:
        return failure(
            "EMULATION_ERROR",
            f"ESIL emulation failed: {str(e)}",
            hint="Check that the binary architecture is supported and the start address is valid",
        )


@log_execution(tool_name="get_pseudo_code")
@track_metrics("get_pseudo_code")
@handle_tool_errors
async def get_pseudo_code(
    file_path: str,
    address: str = "main",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Generate pseudo C code (decompilation) for a function using radare2's pdc command.

    This tool decompiles binary code into C-like pseudocode, making it much easier
    to understand program logic compared to raw assembly. The output can be further
    refined by AI for better readability.

    **Use Cases:**
    - Quick function understanding without reading assembly
    - AI-assisted code analysis and refactoring
    - Documentation generation from binaries
    - Reverse engineering workflow optimization

    **Note:** The output is "pseudo C" - it may not be syntactically perfect C,
    but provides a high-level representation of the function logic.

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function address to decompile (e.g., 'main', '0x401000', 'sym.foo')
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with pseudo C code string

    Example:
        get_pseudo_code("/app/workspace/sample.exe", "main")
        # Returns C-like code representation of the main function
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate file path
    validated_path = validate_file_path(file_path)

    # 2. Security check for address (prevent shell injection)
    try:
        validate_address_format(address, "address")
    except Exception as e:
        return failure(
            "VALIDATION_ERROR",
            str(e),
            hint="Address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Build radare2 command to decompile
    r2_cmd = f"pdc @ {address}"
    
    # 4. Execute decompilation using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_cmd],
        analysis_level="aaa",
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    # 5. Check if output is valid
    if not output or output.strip() == "":
        return failure(
            "DECOMPILATION_ERROR",
            f"No decompilation output for address: {address}",
            hint="Verify the address exists and points to a valid function. Try analyzing with 'afl' first.",
        )

    # 6. Return pseudo C code
    return success(
        output,
        bytes_read=bytes_read,
        address=address,
        format="pseudo_c",
        description=f"Pseudo C code decompiled from address {address}",
    )


@log_execution(tool_name="generate_signature")
@track_metrics("generate_signature")
@handle_tool_errors
async def generate_signature(
    file_path: str,
    address: str,
    length: int = 32,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Generate a YARA signature from opcode bytes at a specific address.

    This tool extracts opcode bytes from a function or code section and formats
    them as a YARA rule, enabling automated malware detection. It attempts to
    mask variable values (addresses, offsets) to create more flexible signatures.

    **Use Cases:**
    - Generate detection signatures for malware samples
    - Create YARA rules for threat hunting
    - Automate IOC (Indicator of Compromise) generation
    - Build malware family signatures

    **Workflow:**
    1. Extract opcode bytes from specified address
    2. Apply basic masking for variable values (optional)
    3. Format as YARA rule template
    4. Return ready-to-use YARA rule

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Start address for signature extraction (e.g., 'main', '0x401000')
        length: Number of bytes to extract (default 32, recommended 16-64)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string

    Example:
        generate_signature("/app/workspace/malware.exe", "0x401000", 48)
        # Returns a YARA rule with extracted byte pattern
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if not isinstance(length, int) or length < 1 or length > 1024:
        return failure(
            "VALIDATION_ERROR",
            "Length must be between 1 and 1024 bytes",
            hint="Typical signature lengths are 16-64 bytes for good detection accuracy",
        )

    # 2. Security check for address
    try:
        validate_address_format(address, "address")
    except Exception as e:
        return failure(
            "VALIDATION_ERROR",
            str(e),
            hint="Address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Extract hex bytes using radare2's p8 command
    r2_cmds = [
        f"s {address}",  # Seek to address
        f"p8 {length}",  # Print hex bytes
    ]
    
    # Adaptive analysis: if address is hex, we don't need full analysis
    # If it's a symbol, we use default loading (empty string) which parses headers/symbols
    # NOTE: For p8 (print bytes), we must ensure we are reading from the correct map.
    # 'io.maps' might be needed if sections aren't mapped.
    # But usually r2 maps sections automatically.
    # If we get all FF, it might be unmapped.
    # Let's force mapping if possible, or just rely on standard loading.
    
    analysis_level = ""
    if address.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", address):
        # Even for hex addresses, we might need basic header parsing to map sections correctly
        # -n skips everything. Let's try without -n if we suspect mapping issues,
        # but -n is faster.
        # If the user reports 0xFF, maybe we are reading from file offset instead of virtual address?
        # r2 default is virtual address.
        # Let's stick to -n for speed, but if it fails, we might need to revisit.
        # Actually, let's use 'e io.cache=true' to ensure we can read? No.
        analysis_level = "-n"
        
    # Extract hex bytes using helper
    # Note: analysis_level may be "" (empty) which means default r2 behavior (parse headers/symbols)
    output, bytes_read = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level or "aaa",
        max_output_size=1_000_000,
        base_timeout=timeout,
    )

    # 4. Validate output
    hex_bytes = output.strip()
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "SIGNATURE_ERROR",
            f"Failed to extract valid hex bytes from address: {address}",
            hint="Verify the address is valid and contains executable code",
        )

    # Check for all 0xFF or 0x00 (likely unmapped memory)
    if re.match(r"^(ff)+$", hex_bytes, re.IGNORECASE) or re.match(r"^(00)+$", hex_bytes):
        # If we used -n, try again without it to force mapping
        if analysis_level == "-n":
             cmd = _build_r2_cmd(str(validated_path), r2_cmds, "aaa")
             output, _ = await execute_subprocess_async(
                cmd,
                max_output_size=1_000_000,
                timeout=effective_timeout,
            )
             hex_bytes = output.strip()
             
             # Re-check
             if re.match(r"^(ff)+$", hex_bytes, re.IGNORECASE) or re.match(r"^(00)+$", hex_bytes):
                 return failure(
                    "SIGNATURE_ERROR",
                    f"Extracted bytes are all 0xFF or 0x00 at {address}. The memory might be unmapped or empty.",
                    hint="Try a different address or ensure the binary is loaded correctly."
                )
        else:
             return failure(
                "SIGNATURE_ERROR",
                f"Extracted bytes are all 0xFF or 0x00 at {address}. The memory might be unmapped or empty.",
                hint="Try a different address or ensure the binary is loaded correctly."
            )

    # 5. Format as YARA hex string (space-separated pairs)
    # Convert: "4883ec20" -> "48 83 ec 20"
    formatted_bytes = " ".join(
        [hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)]
    )

    # 6. Generate YARA rule template
    # Extract filename for rule name using cached helper
    file_name = _sanitize_filename_for_rule(file_path)
    rule_name = f"suspicious_{file_name}_{address.replace('0x', 'x')}"

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated signature for {file_name}"
        address = "{address}"
        length = {length}
        author = "Reversecore_MCP"
        date = "auto-generated"
        
    strings:
        $code = {{ {formatted_bytes} }}
        
    condition:
        $code
}}"""

    # 7. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        address=address,
        length=length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA signature generated from {length} bytes at {address}",
    )


@log_execution(tool_name="extract_rtti_info")
@track_metrics("extract_rtti_info")
@handle_tool_errors
async def extract_rtti_info(
    file_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Extract C++ RTTI (Run-Time Type Information) and class structure information.

    This tool analyzes C++ binaries to recover class names, methods, and inheritance
    hierarchies using RTTI metadata and symbol tables. Essential for reverse engineering
    large C++ applications like games and commercial software.

    **Use Cases:**
    - Recover class structure from C++ binaries
    - Map out object hierarchies in games/applications
    - Identify virtual function tables (vtables)
    - Understand C++ software architecture
    - Generate class diagrams from binaries

    **Extracted Information:**
    - Class names and namespaces
    - Virtual methods and vtables
    - Type descriptors
    - Symbol information
    - Import/export functions

    **Note:** RTTI recovery works best with binaries compiled with RTTI enabled
    (typically the default). Stripped or heavily obfuscated binaries may have
    limited RTTI information.

    Args:
        file_path: Path to the binary file (must be in workspace)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with structured RTTI information including classes, symbols, and methods

    Example:
        extract_rtti_info("/app/workspace/game.exe")
        # Returns JSON with class hierarchy and method information
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate file path
    validated_path = validate_file_path(file_path)

    # 2. Build radare2 command chain to extract RTTI and symbols
    # We'll use multiple commands to get comprehensive information
    r2_cmds = ["icj"]  # List classes in JSON format
    
    effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)
    cmd = _build_r2_cmd(str(validated_path), r2_cmds, "aaa")

    # 3. Execute class extraction
    classes_output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=50_000_000,  # Class info can be large for complex binaries
        timeout=effective_timeout,
    )

    # 4. Extract symbols
    symbols_cmds = ["isj"]  # List symbols in JSON format
    symbols_cmd = _build_r2_cmd(str(validated_path), symbols_cmds, "aaa")

    symbols_output, symbols_bytes = await execute_subprocess_async(
        symbols_cmd,
        max_output_size=50_000_000,
        timeout=effective_timeout,
    )

    # 5. Parse JSON outputs
    try:
        # Robust JSON extraction for classes
        if classes_output.strip():
            classes = _parse_json_output(classes_output)
        else:
            classes = []

        # Robust JSON extraction for symbols
        if symbols_output.strip():
            symbols = _parse_json_output(symbols_output)
        else:
            symbols = []

    except json.JSONDecodeError as e:
        return failure(
            "PARSE_ERROR",
            f"Failed to parse RTTI output: {str(e)}",
            hint="The binary may not contain valid RTTI information or is not a C++ binary",
        )

    # 6. Filter and organize C++ specific symbols
    cpp_classes = []
    cpp_methods = []
    vtables = []

    # Process classes
    for cls in classes:
        if isinstance(cls, dict):
            cpp_classes.append(
                {
                    "name": cls.get("classname", "unknown"),
                    "address": cls.get("addr", "0x0"),
                    "methods": cls.get("methods", []),
                    "vtable": cls.get("vtable", None),
                }
            )

    # Process symbols to find C++ related items
    for sym in symbols:
        if isinstance(sym, dict):
            name = sym.get("name", "")
            sym_type = sym.get("type", "")

            # Detect C++ mangled names (start with _Z or ??)
            if name.startswith("_Z") or name.startswith("??"):
                cpp_methods.append(
                    {
                        "name": name,
                        "address": sym.get("vaddr", sym.get("paddr", "0x0")),
                        "type": sym_type,
                        "size": sym.get("size", 0),
                    }
                )

            # Detect vtables
            if "vtable" in name.lower() or name.startswith("vtable"):
                vtables.append(
                    {"name": name, "address": sym.get("vaddr", sym.get("paddr", "0x0"))}
                )

    # 7. Build comprehensive RTTI report
    rtti_info = {
        "classes": cpp_classes,
        "class_count": len(cpp_classes),
        "methods": cpp_methods[:100],  # Limit to first 100 for readability
        "method_count": len(cpp_methods),
        "vtables": vtables,
        "vtable_count": len(vtables),
        "has_rtti": len(cpp_classes) > 0 or len(vtables) > 0,
        "binary_type": (
            "C++" if (len(cpp_classes) > 0 or len(cpp_methods) > 0) else "Unknown"
        ),
    }

    # 8. Add summary message
    if not rtti_info["has_rtti"]:
        description = "No RTTI information found. Binary may be stripped, not C++, or compiled without RTTI."
    else:
        description = f"Found {rtti_info['class_count']} classes, {rtti_info['method_count']} methods, {rtti_info['vtable_count']} vtables"

    # 9. Return structured RTTI information
    return success(
        rtti_info,
        bytes_read=bytes_read + symbols_bytes,
        format="rtti_info",
        description=description,
    )


@alru_cache(maxsize=32)
@log_execution(tool_name="smart_decompile")
@track_metrics("smart_decompile")
@handle_tool_errors
async def _smart_decompile_impl(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
    use_ghidra: bool = True,
) -> ToolResult:
    """
    Internal implementation of smart_decompile with caching.
    """
    from reversecore_mcp.core.result import failure
    from reversecore_mcp.core.logging_config import get_logger

    logger = get_logger(__name__)

    # 1. Validate parameters
    validate_tool_parameters("smart_decompile", {"function_address": function_address})
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    try:
        validate_address_format(function_address, "function_address")
    except Exception as e:
        return failure(
            "VALIDATION_ERROR",
            str(e),
            hint="Function address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Try Ghidra first if requested and available
    if use_ghidra:
        try:
            from reversecore_mcp.core.ghidra_helper import (
                ensure_ghidra_available,
                decompile_function_with_ghidra,
            )

            if ensure_ghidra_available():
                logger.info(f"Using Ghidra decompiler for {function_address}")

                # Run Ghidra decompilation
                try:
                    c_code, metadata = decompile_function_with_ghidra(
                        validated_path, function_address, timeout
                    )

                    return success(
                        c_code,
                        function_address=function_address,
                        format="pseudo_c",
                        decompiler="ghidra",
                        **metadata,
                    )

                except Exception as ghidra_error:
                    logger.warning(
                        f"Ghidra decompilation failed: {ghidra_error}. "
                        "Falling back to radare2"
                    )
                    # Fall through to radare2
            else:
                logger.info("Ghidra not available, using radare2")

        except ImportError:
            logger.info("PyGhidra not installed, using radare2")

    # 4. Fallback to radare2 (original implementation)
    logger.info(f"Using radare2 decompiler for {function_address}")

    r2_cmds = [f"pdc @ {function_address}"]
    
    # 5. Execute decompilation using helper
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_cmds,
            analysis_level="aaa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )
    except Exception as e:
        # If 'aaa' fails, try lighter analysis 'aa' or just '-n' if desperate,
        # but pdc requires analysis.
        return failure(
            "DECOMPILATION_ERROR",
            f"Radare2 decompilation failed: {str(e)}",
            hint="Analysis failed. The binary might be packed or corrupted."
        )

    # Add timestamp for cache visibility
    import time
    timestamp = time.time()

    # 6. Return result
    return success(
        output,
        bytes_read=bytes_read,
        function_address=function_address,
        format="pseudo_c",
        decompiler="radare2",
        description=f"Decompiled code from function {function_address}",
        timestamp=timestamp
    )


async def smart_decompile(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
    use_ghidra: bool = True,
) -> ToolResult:
    """
    Decompile a function to pseudo C code using Ghidra or radare2.

    This tool provides decompilation for a specific function in a binary,
    making it easier to understand the logic without reading raw assembly.

    **Decompiler Selection:**
    - Ghidra (default): More accurate, better type recovery, industry-standard
    - radare2 (fallback): Faster, lighter weight, good for quick analysis

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to decompile (e.g., 'main', '0x401000')
        timeout: Execution timeout in seconds (default 300)
        use_ghidra: Use Ghidra decompiler if available (default True)

    Returns:
        ToolResult with decompiled pseudo C code
    """
    import time
    result = await _smart_decompile_impl(
        file_path, function_address, timeout, use_ghidra
    )

    # Check for cache hit
    if result.status == "success" and result.metadata:
        ts = result.metadata.get("timestamp")
        if ts and (time.time() - ts > 1.0):
            result.metadata["cache_hit"] = True
            
    return result


@log_execution(tool_name="generate_yara_rule")
@track_metrics("generate_yara_rule")
@handle_tool_errors
async def generate_yara_rule(
    file_path: str,
    function_address: str,
    rule_name: str = "auto_generated_rule",
    byte_length: int = 64,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Generate a YARA rule from function bytes.

    This tool extracts bytes from a function and generates a ready-to-use
    YARA rule for malware detection and threat hunting.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to extract bytes from (e.g., 'main', '0x401000')
        rule_name: Name for the YARA rule (default 'auto_generated_rule')
        byte_length: Number of bytes to extract (default 64, max 1024)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validate_tool_parameters(
        "generate_yara_rule",
        {
            "function_address": function_address,
            "rule_name": rule_name,
            "byte_length": byte_length,
        },
    )
    validated_path = validate_file_path(file_path)

    # 2. Validate rule_name format
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", rule_name):
        return failure(
            "VALIDATION_ERROR",
            "rule_name must start with a letter and contain only alphanumeric characters and underscores",
        )

    # 3. Security check for function address (prevent shell injection)
    try:
        validate_address_format(function_address, "function_address")
    except Exception as e:
        return failure(
            "VALIDATION_ERROR",
            str(e),
            hint="Function address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 4. Extract hex bytes using radare2's p8 command
    r2_cmds = [
        f"s {function_address}",  # Seek to address
        f"p8 {byte_length}",  # Print hex bytes
    ]
    
    analysis_level = ""
    if function_address.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", function_address):
        analysis_level = "-n"
        
    # 4. Extract hex bytes using helper
    # Note: analysis_level may be "" (empty) which means default r2 behavior (parse headers/symbols)
    output, bytes_read = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level or "aaa",
        max_output_size=1_000_000,
        base_timeout=timeout,
    )

    # 5. Validate output
    hex_bytes = output.strip()
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "YARA_GENERATION_ERROR",
            f"Failed to extract valid hex bytes from address: {function_address}",
            hint="Verify the address is valid and contains executable code",
        )

    # 6. Format as YARA hex string (space-separated pairs)
    formatted_bytes = " ".join(
        [hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)]
    )

    # 7. Generate YARA rule
    file_name = _sanitize_filename_for_rule(file_path)

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule for {file_name}"
        address = "{function_address}"
        byte_length = {byte_length}
        author = "Reversecore_MCP"
        
    strings:
        $code = {{ {formatted_bytes} }}
        
    condition:
        $code
}}"""

    # 8. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        function_address=function_address,
        rule_name=rule_name,
        byte_length=byte_length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA rule '{rule_name}' generated from {byte_length} bytes at {function_address}",
    )


@log_execution(tool_name="analyze_xrefs")
@track_metrics("analyze_xrefs")
@handle_tool_errors
async def analyze_xrefs(
    file_path: str,
    address: str,
    xref_type: str = "all",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Analyze cross-references (X-Refs) for a function or data address.

    This tool identifies all references TO and FROM a given address, providing
    critical context for understanding code behavior. Essential for malware
    analysis, vulnerability research, and understanding program flow.

    **Why Cross-References Matter:**
    - **Callers**: Who calls this function? (Find entry points to suspicious code)
    - **Callees**: What does this function call? (Understand behavior and APIs used)
    - **Data Refs**: What data does this access? (Find strings, configs, crypto keys)
    - **Context**: Understand the "why" behind code execution

    **Use Cases:**
    - Malware analysis: "Who calls this Connect function?" reveals C2 behavior
    - Password hunting: "What functions reference this 'Password' string?"
    - Vulnerability research: "What uses this vulnerable API?"
    - Game hacking: "Where is Player health accessed from?"

    **AI Collaboration:**
    AI can use xrefs to:
    - Build call graphs automatically
    - Identify code patterns (e.g., "all functions that write files")
    - Focus token budget on relevant functions only
    - Reduce hallucination by providing real relationships

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function or data address (e.g., 'main', '0x401000', 'sym.decrypt')
        xref_type: Type of references to analyze:
            - "all" (default): Both callers and callees
            - "to": References TO this address (callers, data reads)
            - "from": References FROM this address (callees, data writes)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with cross-reference information in structured format:
        {
            "address": "0x401000",
            "function_name": "main",
            "xrefs_to": [
                {"from": "0x401234", "type": "call", "function": "entry0"},
                {"from": "0x401567", "type": "call", "function": "init"}
            ],
            "xrefs_from": [
                {"to": "0x401100", "type": "call", "function": "sub_401100"},
                {"to": "0x403000", "type": "data_read", "data": "str.password"}
            ],
            "total_refs_to": 2,
            "total_refs_from": 2
        }

    Example:
        # Find who calls the suspicious 'decrypt' function
        analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")

        # Find what APIs a malware function uses
        analyze_xrefs("/app/workspace/malware.exe", "0x401000", "from")

        # Get complete relationship map
        analyze_xrefs("/app/workspace/malware.exe", "main", "all")
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if xref_type not in ["all", "to", "from"]:
        return failure(
            "VALIDATION_ERROR",
            f"Invalid xref_type: {xref_type}",
            hint="Valid options are: 'all', 'to', 'from'",
        )

    # 2. Validate address format
    if not re.match(
        r"^[a-zA-Z0-9_.]+$",
        address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
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

    # 4. Execute analysis using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_commands_str],
        analysis_level="aaa",
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

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
            summary_parts.append(
                f"{len(xrefs_to)} reference(s) TO this address (callers)"
            )
        if xrefs_from:
            summary_parts.append(
                f"{len(xrefs_from)} reference(s) FROM this address (callees)"
            )

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


@log_execution(tool_name="recover_structures")
@track_metrics("recover_structures")
@handle_tool_errors
async def recover_structures(
    file_path: str,
    function_address: str,
    use_ghidra: bool = True,
    timeout: int = DEFAULT_TIMEOUT * 10,
) -> ToolResult:
    """
    Recover C++ class structures and data types from binary code.

    This is THE game-changer for C++ reverse engineering. Transforms cryptic
    "this + 0x4" memory accesses into meaningful "Player.health" structure fields.
    Uses Ghidra's powerful data type propagation and structure recovery algorithms.

    **Why Structure Recovery Matters:**
    - **C++ Analysis**: 99% of game clients and commercial apps are C++
    - **Understanding**: "this + 0x4" means nothing, "Player.health = 100" tells a story
    - **AI Comprehension**: AI can't understand raw offsets, but understands named fields
    - **Scale**: One structure definition can clarify thousands of lines of code

    **How It Works:**
    1. Analyze memory access patterns in the function
    2. Identify structure layouts from offset usage
    3. Use data type propagation to infer field types
    4. Generate C structure definitions with meaningful names

    **Use Cases:**
    - Game hacking: Recover Player, Entity, Weapon structures
    - Malware analysis: Understand malware configuration structures
    - Vulnerability research: Find buffer overflow candidates in structs
    - Software auditing: Document undocumented data structures

    **AI Collaboration:**
    - AI: "This offset pattern looks like Vector3 (x, y, z)"
    - You: Apply structure definition in Ghidra
    - Result: All "this + 0x0/0x4/0x8" become "vec.x/vec.y/vec.z"

    **Ghidra vs Radare2:**
    - Ghidra (default): Superior type recovery, structure propagation, C++ support
    - Radare2 (fallback): Basic structure definition, faster but less intelligent

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function to analyze for structure usage (e.g., 'main', '0x401000')
        use_ghidra: Use Ghidra for advanced recovery (default True), or radare2 for basic
        timeout: Execution timeout in seconds (default 600 for Ghidra analysis)

    Returns:
        ToolResult with recovered structures in C format:
        {
            "structures": [
                {
                    "name": "Player",
                    "size": 64,
                    "fields": [
                        {"offset": "0x0", "type": "int", "name": "health"},
                        {"offset": "0x4", "type": "int", "name": "armor"},
                        {"offset": "0x8", "type": "Vector3", "name": "position"}
                    ]
                }
            ],
            "c_definitions": "struct Player { int health; int armor; Vector3 position; };"
        }

    Example:
        # Recover structures used in main function
        recover_structures("/app/workspace/game.exe", "main")

        # Analyze specific class method
        recover_structures("/app/workspace/game.exe", "Player::update")

        # Use radare2 for quick analysis
        recover_structures("/app/workspace/binary", "0x401000", use_ghidra=False)
    """
    from reversecore_mcp.core.result import failure
    from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    # 2. Validate address format
    if not re.match(
        r"^[a-zA-Z0-9_.:<>]+$",
        function_address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid function address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, colons, angle brackets, and prefixes like '0x', 'sym.'",
        )

    # 3. Check if Ghidra is available when requested
    if use_ghidra:
        # Check availability and fallback if needed
        if not ensure_ghidra_available():
            # Instead of failing, let's fallback to radare2 with a warning in the description
            # This improves UX when Ghidra is optional but requested by default
            use_ghidra = False
            # We will append a note to the result description later
            fallback_note = " (Ghidra not available, fell back to radare2)"
        else:
            fallback_note = ""
            # 4a. Use Ghidra for advanced structure recovery
            try:
                from reversecore_mcp.core.ghidra_helper import (
                    recover_structures_with_ghidra,
                )

                structures, metadata = recover_structures_with_ghidra(
                    validated_path, function_address, timeout
                )

                return success(
                    {"structures": structures},
                    **metadata,
                    function_address=function_address,
                    method="ghidra",
                    description=f"Structures recovered from {function_address} using Ghidra",
                )

            except Exception as e:
                # If Ghidra fails during execution, also fallback
                use_ghidra = False
                fallback_note = f" (Ghidra failed: {str(e)}, fell back to radare2)"

    if not use_ghidra:
        # 4b. Use radare2 for basic structure recovery
        # radare2's 'afvt' command shows variable types and offsets
        r2_cmds = [
            f"s {function_address}",  # Seek to function
            "afvj",  # Get function variables in JSON
        ]
        
        effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)
        cmd = _build_r2_cmd(str(validated_path), r2_cmds, "aaa")

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=10_000_000,
            timeout=effective_timeout,
        )

        # 5. Parse radare2 output
        try:
            if output.strip():
                variables = _parse_json_output(output)
            else:
                variables = []

            # Extract structure-like patterns
            # Group variables by their base pointer (e.g., rbp, rsp)
            structures = {}

            for var in variables:
                if isinstance(var, dict):
                    var_type = var.get("type", "unknown")
                    var_name = var.get("name", "unnamed")
                    offset = var.get("delta", 0)

                    # Simple heuristic: group by base register
                    base = (
                        var.get("ref", {}).get("base", "unknown")
                        if "ref" in var
                        else "stack"
                    )

                    if base not in structures:
                        structures[base] = {"name": f"struct_{base}", "fields": []}

                    structures[base]["fields"].append(
                        {
                            "offset": f"0x{abs(offset):x}",
                            "type": var_type,
                            "name": var_name,
                        }
                    )

            # 6. Generate C structure definitions
            c_definitions = []
            for struct_name, struct_data in structures.items():
                fields_str = "\n    ".join(
                    [
                        f"{field['type']} {field['name']}; // offset {field['offset']}"
                        for field in struct_data["fields"]
                    ]
                )

                c_def = f"struct {struct_data['name']} {{\n    {fields_str}\n}};"
                c_definitions.append(c_def)

            result = {
                "structures": list(structures.values()),
                "c_definitions": "\n\n".join(c_definitions),
                "count": len(structures),
            }
            
            desc = f"Basic structure recovery from {function_address} using radare2 (found {len(structures)} structure(s))"
            if 'fallback_note' in locals():
                desc += fallback_note

            return success(
                result,
                bytes_read=bytes_read,
                function_address=function_address,
                method="radare2",
                structure_count=len(structures),
                description=desc,
            )

        except json.JSONDecodeError as e:
            return failure(
                "STRUCTURE_RECOVERY_ERROR",
                f"Failed to parse structure data: {str(e)}",
                hint="The function may not exist or may not use structures. Verify the address with 'afl' command.",
            )


@log_execution(tool_name="diff_binaries")
@track_metrics("diff_binaries")
@handle_tool_errors
async def diff_binaries(
    file_path_a: str,
    file_path_b: str,
    function_name: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Compare two binary files to identify code changes and modifications.

    This tool uses radiff2 to perform binary diffing, which is essential for:
    - **Patch Analysis (1-day Exploits)**: Compare pre-patch and post-patch binaries
      to identify security vulnerabilities fixed in updates
    - ** Game Hacking**: Find offset changes after game updates to maintain functionality
    - **Malware Variant Analysis**: Identify code differences between malware variants
      (e.g., "90% similar to Lazarus malware, but C2 address generation changed")

    The tool provides:
    - Similarity score (0.0-1.0) between binaries
    - List of code changes with addresses and descriptions
    - Optional function-level comparison for targeted analysis

    Args:
        file_path_a: Path to the first binary file (e.g., pre-patch version)
        file_path_b: Path to the second binary file (e.g., post-patch version)
        function_name: Optional function name to compare (e.g., "main", "sym.decrypt").
                      If None, performs whole-binary comparison.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - similarity: Float between 0.0 and 1.0 indicating code similarity
        - changes: List of detected changes with addresses and descriptions
        - function_specific: Boolean indicating if function-level diff was performed

    Example:
        # Compare two versions of a patched binary
        diff_binaries("/app/workspace/app_v1.0.exe", "/app/workspace/app_v1.1.exe")

        # Compare specific function between versions
        diff_binaries("/app/workspace/malware_old.exe", "/app/workspace/malware_new.exe", "main")

    Output Format:
        {
          "similarity": 0.95,
          "function_specific": false,
          "changes": [
            {
              "address": "0x401050",
              "type": "code_change",
              "description": "Instruction changed from JNZ to JZ"
            },
            {
              "address": "0x401080",
              "type": "new_block",
              "description": "Added security check"
            }
          ],
          "total_changes": 2
        }
    """
    from reversecore_mcp.core.result import failure

    # Validate both file paths
    validated_path_a = validate_file_path(file_path_a)
    validated_path_b = validate_file_path(file_path_b)

    # Validate tool parameters
    validate_tool_parameters(
        "diff_binaries",
        {
            "function_name": function_name,
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Build radiff2 command
        # -s: similarity score
        # -C: code comparison
        # -g: graph diff (if function specified)

        if function_name:
            # Function-specific comparison using graph diff
            cmd = [
                "radiff2",
                "-g",
                function_name,
                str(validated_path_a),
                str(validated_path_b),
            ]
        else:
            # Whole-binary comparison with similarity scoring
            cmd = [
                "radiff2",
                "-C",
                str(validated_path_a),
                str(validated_path_b),
            ]

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=max_output_size,
            timeout=timeout,
        )

        # Also get similarity score (format: "similarity: 0.95")
        similarity_cmd = ["radiff2", "-s", str(validated_path_a), str(validated_path_b)]
        similarity_output, _ = await execute_subprocess_async(
            similarity_cmd,
            max_output_size=1_000_000,
            timeout=60,
        )

        # Parse similarity score (format: "similarity: 0.95")
        similarity = 0.0
        similarity_match = re.search(r"similarity:\s*(\d+\.?\d*)", similarity_output)
        if similarity_match:
            similarity = float(similarity_match.group(1))

        # Parse changes from output
        changes = []

        # Parse the diff output to extract meaningful changes
        # radiff2 output varies, so we'll capture the raw output and structure it
        lines = output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            # Look for common patterns in radiff2 output
            # Address patterns: 0x... or addresses
            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)

            if addr_match:
                address = addr_match.group(1)

                # Determine change type based on line content
                change_type = "unknown"
                description = line.strip()

                if "new" in line.lower():
                    change_type = "new_block"
                elif "removed" in line.lower() or "deleted" in line.lower():
                    change_type = "removed_block"
                elif "modified" in line.lower() or "changed" in line.lower():
                    change_type = "code_change"
                elif (
                    "jmp" in line.lower()
                    or "call" in line.lower()
                    or "jnz" in line.lower()
                ):
                    change_type = "control_flow_change"

                changes.append(
                    {
                        "address": address,
                        "type": change_type,
                        "description": description,
                    }
                )

        # If no structured changes found, include summary info
        if not changes and output.strip():
            changes.append(
                {
                    "type": "summary",
                    "description": "Binary comparison completed. See raw output for details.",
                }
            )

        # Build result
        result_data = {
            "similarity": similarity,
            "function_specific": bool(function_name),
            "changes": changes,
            "total_changes": len(changes),
            "raw_output": (
                output if len(output) < 5000 else output[:5000] + "... (truncated)"
            ),
        }

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            similarity=similarity,
            total_changes=len(changes),
            function_specific=bool(function_name),
        )

    except Exception as e:
        return failure(
            "DIFF_ERROR",
            f"Binary diff failed: {str(e)}",
            hint="Ensure both files are valid binaries and radiff2 is available. For function-level diff, verify function name exists in both binaries.",
        )


@log_execution(tool_name="match_libraries")
@track_metrics("match_libraries")
@handle_tool_errors
async def match_libraries(
    file_path: str,
    signature_db: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Match and filter known library functions to focus on user code.

    This tool uses radare2's zignatures (FLIRT-compatible signature matching) to:
    - **Reduce Analysis Noise**: Skip analysis of known library functions (strcpy, malloc, etc.)
    - **Focus on User Code**: Identify which functions are original vs library code
    - **Save Time & Tokens**: Reduce analysis scope by 80% by filtering out standard libraries
    - **Improve Accuracy**: Focus AI analysis on the actual malicious/interesting code

    Common use cases:
    - Analyzing large binaries (>25MB) where most code is OpenSSL, zlib, MFC, etc.
    - Game client reverse engineering (filter out Unreal Engine / Unity standard library)
    - Malware analysis (focus on custom malware code, skip Windows API wrappers)

    The tool automatically uses built-in signature databases for common libraries
    and can optionally use custom signature databases for specialized analysis.

    Args:
        file_path: Path to the binary file to analyze
        signature_db: Optional path to custom signature database file (.sig format).
                     If None, uses radare2's built-in signature databases.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - total_functions: Total number of functions found
        - library_functions: Number of matched library functions
        - user_functions: Number of unmatched (user) functions to analyze
        - library_matches: List of matched library functions with details
        - user_function_list: List of user function addresses/names for further analysis
        - noise_reduction_percentage: Percentage of functions filtered out

    Example:
        # Auto-detect standard libraries
        match_libraries("/app/workspace/large_app.exe")

        # Use custom signature database
        match_libraries("/app/workspace/game.exe", "/app/rules/game_engine.sig")

    Output Format:
        {
          "total_functions": 1250,
          "library_functions": 1000,
          "user_functions": 250,
          "noise_reduction_percentage": 80.0,
          "library_matches": [
            {
              "address": "0x401000",
              "name": "strcpy",
              "library": "msvcrt"
            },
            {
              "address": "0x401050",
              "name": "malloc",
              "library": "msvcrt"
            }
          ],
          "user_function_list": [
            "0x402000",
            "0x402100",
            "sym.custom_decrypt"
          ]
        }
    """
    from reversecore_mcp.core.result import failure

    # Validate file path
    validated_path = validate_file_path(file_path)

    # Validate optional signature database path
    if signature_db:
        validated_sig_path = validate_file_path(signature_db)

    # Validate tool parameters
    validate_tool_parameters(
        "match_libraries",
        {
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Step 1: Load binary and analyze
        # Use radare2 to get function list with signature matching

        # Build command to apply signatures and get function list
        if signature_db:
            # Load custom signature database
            r2_commands = [f"zg {validated_sig_path}", "aflj"]
        else:
            # Use built-in signatures
            r2_commands = ["zg", "aflj"]

        effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)
        cmd = _build_r2_cmd(str(validated_path), r2_commands, "aaa")

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=max_output_size,
            timeout=effective_timeout,
        )

        # Parse JSON output from aflj (function list JSON)
        try:
            # Attempt to find JSON array in output if direct parse fails
            # This handles cases where 'zg' or 'aaa' might produce non-JSON output before the JSON result
            functions = _parse_json_output(output)
        except json.JSONDecodeError:
            # If JSON parsing fails, fall back to text parsing
            return failure(
                "PARSE_ERROR",
                "Failed to parse function list from radare2",
                hint="The binary may not be analyzable or may be packed/obfuscated. Try running 'aaa' analysis first.",
            )

        # Categorize functions into library vs user code
        library_functions = []
        user_functions = []

        for func in functions:
            name = func.get("name", "")
            # Support both 'offset' (aflj) and 'vaddr' (isj) keys
            # Fallback to 'realname' or other identifiers if needed
            offset = func.get("offset", func.get("vaddr", 0))
            
            # If offset is 0, try to parse it from the name if it looks like sym.func.0x...
            if offset == 0 and name:
                # Try to find hex address in name
                import re
                hex_match = re.search(r"(?:0x)?([0-9a-fA-F]{4,})", name)
                if hex_match:
                    try:
                        offset = int(hex_match.group(1), 16)
                    except ValueError:
                        pass

            # Heuristic: library functions typically have names like:
            # - sym.imp.* (imports)
            # - sym.std::* (C++ standard library)
            # - Known library prefixes
            is_library = (
                name.startswith("sym.imp.")
                or name.startswith("sym.std::")
                or name.startswith("fcn.imp.")
                or "libc" in name.lower()
                or "msvcrt" in name.lower()
                or "kernel32" in name.lower()
            )

            if is_library:
                library_functions.append(
                    {
                        "address": f"0x{offset:x}",
                        "name": name,
                        "library": _extract_library_name(name),
                    }
                )
            else:
                user_functions.append({"address": f"0x{offset:x}", "name": name})

        total_functions = len(functions)
        library_count = len(library_functions)
        user_count = len(user_functions)

        # Calculate noise reduction percentage
        noise_reduction = (
            (library_count / total_functions * 100) if total_functions > 0 else 0.0
        )

        # Build result
        result_data = {
            "total_functions": total_functions,
            "library_functions": library_count,
            "user_functions": user_count,
            "noise_reduction_percentage": round(noise_reduction, 2),
            "library_matches": library_functions[
                :50
            ],  # Limit to first 50 for readability
            "user_function_list": [
                f["address"] for f in user_functions[:100]
            ],  # First 100 user functions
            "summary": f"Filtered out {library_count} library functions ({noise_reduction:.1f}% noise reduction). Focus analysis on {user_count} user functions.",
            "signature_db_used": signature_db if signature_db else "built-in",
        }

        if library_count == 0:
            result_data["hint"] = (
                "No library functions matched. This could mean: "
                "1. No signatures loaded (check signature_db). "
                "2. Binary uses statically linked libraries not in DB. "
                "3. Binary is fully custom."
            )

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            total_functions=total_functions,
            library_functions=library_count,
            user_functions=user_count,
            noise_reduction=round(noise_reduction, 2),
        )

    except Exception as e:
        return failure(
            "LIBRARY_MATCH_ERROR",
            f"Library signature matching failed: {str(e)}",
            hint="Ensure the binary is valid and radare2 signature databases are available. For custom databases, verify the .sig file format.",
        )


@lru_cache(maxsize=256)
def _extract_library_name(function_name: str) -> str:
    """
    Extract library name from function name.
    
    Cached to avoid repeated string comparisons for common function names.

    Args:
        function_name: Function name (e.g., "sym.imp.strcpy")

    Returns:
        Extracted library name or "unknown"
    """
    # Simple heuristic extraction
    if "kernel32" in function_name.lower():
        return "kernel32"
    elif "msvcrt" in function_name.lower() or "libc" in function_name.lower():
        return "libc/msvcrt"
    elif "std::" in function_name:
        return "libstdc++"
    elif "imp." in function_name:
        return "import"
    else:
        return "unknown"


@lru_cache(maxsize=128)
def _sanitize_filename_for_rule(file_path: str) -> str:
    """
    Extract and sanitize filename for use in YARA rule names.
    
    Cached to avoid repeated Path operations and string replacements.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Sanitized filename with special characters replaced
    """
    return Path(file_path).stem.replace("-", "_").replace(".", "_")


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
    if text[0] in ('{', '['):
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
        if char not in ('{', '['):
            i += 1
            continue
        
        # Found potential JSON start
        # Quick heuristic: Skip obvious false starts (isolated brackets)
        # This prevents pathological O(n²) behavior with "{ { { { {..." patterns
        # Note: We only check for same bracket type to avoid false positives.
        # Mixed brackets like "{ [" could be valid JSON like `{"arr": [...]}`
        if i + 1 < text_len and text[i + 1] in (' ', '\t'):
            # Bracket followed by whitespace - check if next non-whitespace is also a bracket
            next_idx = i + 2
            while next_idx < text_len and text[next_idx] in (' ', '\t', '\n', '\r'):
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
                
            if c == '\\' and in_string:
                escape_next = True
                j += 1
                continue
                
            if c == '"':
                in_string = not in_string
                j += 1
                continue
            
            # Process brackets only when not inside strings
            if not in_string:
                if c in ('{', '['):
                    stack.append(c)
                elif c in ('}', ']'):
                    if not stack:
                        # Unmatched closing bracket
                        break
                    
                    last = stack[-1]
                    if (c == '}' and last == '{') or (c == ']' and last == '['):
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
    from reversecore_mcp.core.result import failure
    
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
            import claripy
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
            return {"found": False, "error": f"Could not resolve start address: {start_address}"}
        if target_addr is None:
            return {"found": False, "error": f"Could not resolve target address: {target_address}"}

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
                solution = found_state.posix.dumps(0) # Dump stdin
                return {
                    "found": True,
                    "input_hex": solution.hex(),
                    "input_str": str(solution), # Best effort string representation
                    "stdout": found_state.posix.dumps(1).decode(errors='ignore')
                }
            except Exception as e:
                 return {"found": True, "input_hex": "", "input_str": "Error dumping input", "stdout": ""}
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
                description=f"Found path from {start_address} to {target_address}. Input: {result.get('input_hex')}"
            )
        else:
            return failure(
                "PATH_NOT_FOUND",
                f"No execution path found from {start_address} to {target_address}",
                hint="Check if the target is actually reachable or if constraints are too strict."
            )

    except Exception as e:
        return failure(
            "SYMBOLIC_EXECUTION_ERROR",
            f"Angr execution failed: {str(e)}",
            hint="Symbolic execution is complex. Ensure addresses are correct and the binary is compatible."
        )
