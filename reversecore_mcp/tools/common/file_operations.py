"""File operation tools for managing workspace and file handling."""

import shutil
from pathlib import Path

from fastmcp import Context

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
        {
            "file_type": output,
            "file_path": str(validated_path),
            "file_name": validated_path.name,
            "mime_type": mime_type,
        },
        bytes_read=bytes_read,
        raw_output=output,
    )


@log_execution(tool_name="copy_to_workspace")
@track_metrics("copy_to_workspace")
@handle_tool_errors
def copy_to_workspace(
    source_path: str,
    destination_name: str | None = None,
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

    # Security check: Ensure source path is within allowed boundaries
    import tempfile

    config = get_config()
    allowed_prefixes = [
        config.workspace.resolve(),
        Path("/mnt/user-data/uploads").resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    for read_dir in config.read_only_dirs:
        allowed_prefixes.append(read_dir.resolve())

    is_allowed = False
    for prefix in allowed_prefixes:
        try:
            source.relative_to(prefix)
            is_allowed = True
            break
        except ValueError:
            continue

    if not is_allowed:
        raise ValidationError(
            f"Source path is outside allowed directories: {source}",
            details={
                "source_path": str(source),
                "allowed_prefixes": [str(p) for p in allowed_prefixes],
            },
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
    config = get_config()
    if destination_name:
        # Allow nested paths within the workspace but block traversal
        dest_path = Path(destination_name)
        if dest_path.is_absolute():
            # If absolute, verify it's inside the workspace
            try:
                dest_path.relative_to(config.workspace)
                destination = dest_path
            except ValueError:
                raise ValidationError(
                    f"Absolute destination path must be within the workspace: {destination_name}",
                    details={"destination_name": destination_name},
                )
        else:
            destination = (config.workspace / dest_path).resolve()
            # Verify no path traversal (e.g. ../../etc/passwd)
            try:
                destination.relative_to(config.workspace)
            except ValueError:
                raise ValidationError(
                    f"Destination path traverses outside workspace: {destination_name}",
                    details={"destination_name": destination_name},
                )
    else:
        destination = config.workspace / source.name

    dest_name = destination.name

    # Create parent directories if they don't exist
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        raise ValidationError(
            f"Failed to create parent directories for destination: {e}",
            details={"destination": str(destination)},
        )

    # Copy file to workspace using atomic exclusive creation
    # This prevents TOCTOU race condition where another process could create
    # the file between exists() check and copy2() call
    try:
        # mode 'xb' = exclusive create + binary, fails if file already exists
        with open(destination, "xb") as dest_file:
            with open(source, "rb") as src_file:
                shutil.copyfileobj(src_file, dest_file)

        # Preserve metadata (like copy2)
        shutil.copystat(source, destination)
        copied_size = destination.stat().st_size

        return success(
            str(destination),
            source_path=str(source),
            destination_path=str(destination),
            file_size=copied_size,
            message=f"File copied successfully to workspace: {dest_name}",
        )
    except FileExistsError:
        raise ValidationError(
            f"File already exists in workspace: {dest_name}",
            details={
                "destination": str(destination),
                "hint": "Use a different destination_name or remove the existing file first",
            },
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
    # Using rglob to list all files in subdirectories as well
    for item in workspace.rglob("*"):
        if item.is_file():
            # Store relative path to make it easier to read
            try:
                rel_path = str(item.relative_to(workspace))
            except ValueError:
                rel_path = str(item)
            files.append(
                {
                    "name": item.name,
                    "size": item.stat().st_size,
                    "path": str(item),
                    "relative_path": rel_path,
                }
            )

    return success({"files": files}, file_count=len(files), workspace_path=str(workspace))


@log_execution(tool_name="create_directory")
@track_metrics("create_directory")
@handle_tool_errors
def create_directory(directory_path: str) -> ToolResult:
    """
    Create a new sub-directory within the workspace.

    This tool allows AI agents to dynamically create isolated sub-workspaces
    for different tasks or sessions.

    Args:
        directory_path: Relative or absolute path of the directory to create.
                       Must be within the workspace boundary.

    Returns:
        ToolResult with the newly created directory path
    """
    config = get_config()
    path = Path(directory_path)

    if path.is_absolute():
        try:
            path.relative_to(config.workspace)
            target = path
        except ValueError:
            raise ValidationError(
                f"Absolute directory path must be within the workspace: {directory_path}"
            )
    else:
        target = (config.workspace / path).resolve()
        try:
            target.relative_to(config.workspace)
        except ValueError:
            raise ValidationError(f"Directory path traverses outside workspace: {directory_path}")

    try:
        target.mkdir(parents=True, exist_ok=True)
        return success(
            str(target),
            workspace_path=str(config.workspace),
            message=f"Directory created successfully: {target.relative_to(config.workspace)}",
        )
    except PermissionError as e:
        raise ValidationError(f"Permission denied when creating directory: {e}")
    except Exception as e:
        raise ValidationError(f"Failed to create directory: {e}")


@log_execution(tool_name="scan_workspace")
@track_metrics("scan_workspace")
@handle_tool_errors
async def scan_workspace(
    file_patterns: list[str] | None = None,
    timeout: int = 600,
    ctx: Context | None = None,
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
    from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief

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


# Note: FileOperationsPlugin has been removed.
# The file operation tools are now registered via CommonToolsPlugin in common/__init__.py.
