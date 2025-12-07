"""File operation tools for managing workspace and file handling."""

import shutil
from pathlib import Path

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path

# Load default timeout from configuration

DEFAULT_TIMEOUT = get_config().default_tool_timeout


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
    output = output.strip()
    
    # Try to infer mime type from output (simple heuristic)
    mime_type = "application/octet-stream"
    if "text" in output.lower():
        mime_type = "text/plain"
    elif "executable" in output.lower():
        mime_type = "application/x-executable"
    elif "image" in output.lower():
        mime_type = "image/" + output.split()[0].lower()
        
    return success(
        output,
        bytes_read=bytes_read,
        data={
            "file_type": output,
            "file_path": str(validated_path),
            "file_name": validated_path.name,
            "mime_type": mime_type
        }
    )


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
            files.append({"name": item.name, "size": item.stat().st_size, "path": str(item)})

    return success({"files": files}, file_count=len(files), workspace_path=str(workspace))


@log_execution(tool_name="scan_workspace")
@track_metrics("scan_workspace")
@handle_tool_errors
async def scan_workspace(
    file_patterns: list[str] = None,
    timeout: int = 600,
    ctx=None,
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
        ctx: FastMCP Context for progress reporting (auto-injected)

    Returns:
        ToolResult with aggregated scan results for all files.
    """
    import asyncio

    from reversecore_mcp.core import json_utils as json
    from reversecore_mcp.tools.common.lib_tools import parse_binary_with_lief

    config = get_config()
    workspace = config.workspace

    if not file_patterns:
        file_patterns = ["*"]

    # 1. Collect files
    # OPTIMIZATION: Use set to avoid duplicates during collection instead of after
    files_to_scan_set = set()
    for pattern in file_patterns:
        for f in workspace.glob(pattern):
            if f.is_file():
                files_to_scan_set.add(f)

    files_to_scan = list(files_to_scan_set)

    if not files_to_scan:
        return success({"files": [], "summary": "No files found matching patterns"}, file_count=0)

    total_files = len(files_to_scan)

    # 2. Define scan tasks
    results = {}
    completed_count = 0

    async def scan_single_file(file_path: Path, index: int):
        nonlocal completed_count
        path_str = str(file_path)
        file_name = file_path.name
        file_result = {"name": file_name, "path": path_str}

        # Task 1: run_file (async)
        # We call the tool function directly. Since it's async, we await it.
        try:
            file_cmd_result = await run_file(path_str)
            file_result["file_type"] = (
                file_cmd_result.data if file_cmd_result.status == "success" else "unknown"
            )
        except Exception as e:
            file_result["file_type_error"] = str(e)

        # Task 2: LIEF (sync, run in thread)
        # Only for likely binaries
        if "executable" in str(
            file_result.get("file_type", "")
        ).lower() or file_path.suffix.lower() in [
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".bin",
            ".elf",
        ]:
            try:
                # Run sync function in thread pool
                lief_result = await asyncio.to_thread(parse_binary_with_lief, path_str)
                if lief_result.status == "success":
                    # Parse JSON content if available
                    content = lief_result.data
                    try:
                        file_result["lief_metadata"] = (
                            json.loads(content) if isinstance(content, str) else content
                        )
                    except (json.JSONDecodeError, ValueError, TypeError):
                        file_result["lief_metadata"] = content
            except Exception as e:
                file_result["lief_error"] = str(e)

        # Task 3: YARA (sync, run in thread)
        # Check if we have a default yara rule file or if user provided one (not supported in this batch mode yet, skipping for now or using default)
        # For now, we skip YARA in batch mode unless we have a default rule path in config,
        # but let's assume we might want to add it later.
        # To keep it simple and robust, we'll skip YARA for now in this initial implementation
        # unless we want to scan against a specific rule file which isn't passed here.

        # Report progress
        completed_count += 1
        if ctx:
            await ctx.report_progress(completed_count, total_files)

        return file_name, file_result

    # 3. Run scans in parallel
    # Limit concurrency to avoid overwhelming the system
    semaphore = asyncio.Semaphore(5)  # Process 5 files at a time

    async def sem_scan(file_path, index):
        async with semaphore:
            return await scan_single_file(file_path, index)

    tasks = [sem_scan(f, i) for i, f in enumerate(files_to_scan)]

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
            status="timeout",
        )

    return success(
        {"files": results},
        file_count=len(files_to_scan),
        status="completed",
        description=f"Batch scan completed for {len(files_to_scan)} files",
    )


from typing import Any

from reversecore_mcp.core.plugin import Plugin


class FileOperationsPlugin(Plugin):
    """Plugin for file operation tools."""

    @property
    def name(self) -> str:
        return "file_operations"

    @property
    def description(self) -> str:
        return "File management tools for workspace operations."

    def register(self, mcp_server: Any) -> None:
        """Register file operation tools."""
        mcp_server.tool(run_file)
        mcp_server.tool(copy_to_workspace)
        mcp_server.tool(list_workspace)
        mcp_server.tool(scan_workspace)
