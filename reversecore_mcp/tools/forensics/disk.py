"""Disk/filesystem forensics tools backed by Sleuth Kit CLI.

Uses ``mmls``, ``fls``, ``icat``, and ``istat`` from Sleuth Kit (installed as
system packages in the Docker base image) to avoid Python 3.14 pytsk3
compilation issues. All tools gracefully degrade if Sleuth Kit is absent.
"""

import asyncio
import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ExecutionTimeoutError, ToolNotFoundError
from reversecore_mcp.core.execution import (
    execute_subprocess_bytes_async,
    execute_subprocess_lines_async,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)
_MAX_RETURNED_ENTRIES = 10_000
_MAX_OUTPUT_LINE_BYTES = 65_536


# Sleuth Kit CLI binary names
def _check_tsk_available() -> bool:
    """Check if Sleuth Kit CLI tools are available."""
    return shutil.which("fls") is not None


@log_execution(tool_name="disk_list_partition")
@track_metrics("disk_list_partition")
@handle_tool_errors
async def disk_list_partition(image_path: str) -> ToolResult:
    """List partition layout of a disk image using Sleuth Kit mmls.

    Args:
        image_path: Path to the raw disk image file (.img, .dd, .raw, .iso).

    Returns:
        ToolResult with partition table, start/end offsets, and filesystem types.

    Example:
        >>> result = await disk_list_partition("/app/workspace/disk.img")
        >>> for part in result.data["partitions"]:
        ...     print(part["description"], part["start"])
    """
    validated = validate_file_path(image_path)

    if not _check_tsk_available():
        return failure(
            "DEPENDENCY_MISSING",
            "Sleuth Kit (mmls/fls) is not installed",
            hint="Install with: apt-get install sleuthkit",
        )

    partitions: list[dict[str, str]] = []
    raw_output: list[str] = []
    raw_output_chars = 0
    total_count = 0

    def add_partition(line: str, line_truncated: bool) -> None:
        nonlocal raw_output_chars, total_count
        if raw_output_chars < 3000:
            remaining = 3000 - raw_output_chars
            piece = (line + "\n")[:remaining]
            raw_output.append(piece)
            raw_output_chars += len(piece)
        if line_truncated:
            return
        stripped = line.strip()
        if not stripped or stripped.startswith("DOS") or stripped.startswith("Description"):
            return
        # Parse mmls output: "000: Meta 0000000000 0000000000 0000000001 ..."
        parts = stripped.split(None, 5)
        if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
            total_count += 1
            if len(partitions) < _MAX_RETURNED_ENTRIES:
                partitions.append(
                    {
                        "slot": parts[0].rstrip(":"),
                        "address": parts[1],
                        "start": parts[2],
                        "end": parts[3],
                        "length": parts[4],
                        "description": parts[5] if len(parts) > 5 else "",
                    }
                )

    output_limit = get_config().max_output_size
    (
        rc,
        stderr,
        bytes_read,
        output_limit_reached,
        line_truncated,
    ) = await execute_subprocess_lines_async(
        ["mmls", str(validated)],
        add_partition,
        max_output_size=output_limit,
        max_line_size=min(_MAX_OUTPUT_LINE_BYTES, output_limit),
        timeout=120,
    )

    if rc != 0 and bytes_read == 0 and not output_limit_reached and not line_truncated:
        return failure(
            "TSK_ERROR",
            f"mmls failed (exit {rc}): {stderr.strip()}",
            hint="Ensure the image file is a valid disk image, not a filesystem image.",
        )

    return success(
        {
            "image_path": str(validated),
            "partitions": partitions,
            "partition_count": total_count,
            "raw_output": "".join(raw_output),
            "truncated": (
                output_limit_reached or line_truncated or rc != 0 or total_count > len(partitions)
            ),
            "count_complete": not output_limit_reached and not line_truncated and rc == 0,
        }
    )


@log_execution(tool_name="disk_list_files")
@track_metrics("disk_list_files")
@handle_tool_errors
async def disk_list_files(
    image_path: str,
    directory: str = "/",
    include_deleted: bool = True,
    offset: int | None = None,
    recursive: bool = False,
    limit: int = 1000,
) -> ToolResult:
    """List all files and directories in a disk/filesystem image.

    Args:
        image_path: Path to the disk or filesystem image file.
        directory: Directory path within the image to list (default: root '/').
        include_deleted: If True, also show deleted/unallocated files (marked with '*').
        offset: Partition start offset in sectors (from disk_list_partition output).
            Leave None if image_path is a filesystem image (not a full disk image).
        recursive: If True, recursively list all subdirectories.
        limit: Maximum number of entries to return (default: 1000).

    Returns:
        ToolResult with file listing including allocation status and inode numbers.

    Example:
        >>> result = await disk_list_files("/app/workspace/disk.img", offset=2048)
        >>> deleted = [f for f in result.data["files"] if f["deleted"]]
    """
    validated = validate_file_path(image_path)

    if not _check_tsk_available():
        return failure(
            "DEPENDENCY_MISSING",
            "Sleuth Kit (fls) is not installed",
            hint="Install with: apt-get install sleuthkit",
        )

    cmd = ["fls"]
    if include_deleted:
        cmd.append("-a")  # show all (including deleted)
    if recursive:
        cmd.append("-r")  # recursive
    if offset is not None:
        cmd.extend(["-o", str(offset)])

    cmd.append(str(validated))
    if directory != "/":
        # fls takes inode number for subdirs — skip if path provided
        cmd.append(directory)

    files: list[dict[str, Any]] = []
    total_count = 0
    deleted_count = 0
    entry_limit = min(max(limit, 0), _MAX_RETURNED_ENTRIES)

    def add_file(line: str, line_truncated: bool) -> None:
        nonlocal total_count, deleted_count
        if line_truncated:
            return
        deleted = line.startswith("*")
        clean_line = line.lstrip("* ").strip()
        parts = clean_line.split(None, 2)
        if len(parts) < 3:
            return
        type_part = parts[0]
        inode_part = parts[1].rstrip(":")
        name = parts[2]
        is_dir = type_part.startswith("d")
        total_count += 1
        deleted_count += int(deleted)
        if len(files) < entry_limit:
            files.append(
                {
                    "name": name,
                    "inode": inode_part,
                    "is_directory": is_dir,
                    "deleted": deleted,
                    "type": type_part,
                }
            )

    output_limit = get_config().max_output_size
    rc, stderr, _, output_limit_reached, line_truncated = await execute_subprocess_lines_async(
        ["fls", *cmd[1:]],
        add_file,
        max_output_size=output_limit,
        max_line_size=min(_MAX_OUTPUT_LINE_BYTES, output_limit),
        timeout=180,
    )

    if rc != 0 and total_count == 0 and not output_limit_reached and not line_truncated:
        return failure(
            "TSK_ERROR",
            f"fls failed (exit {rc}): {stderr.strip()}",
            hint="Check offset with disk_list_partition or verify image integrity.",
        )

    return success(
        {
            "image_path": str(validated),
            "directory": directory,
            "files": files,
            "total_count": total_count,
            "deleted_count": deleted_count,
            "truncated": (
                output_limit_reached or line_truncated or rc != 0 or total_count > len(files)
            ),
            "count_complete": not output_limit_reached and not line_truncated and rc == 0,
        }
    )


@log_execution(tool_name="disk_recover_deleted")
@track_metrics("disk_recover_deleted")
@handle_tool_errors
async def disk_recover_deleted(
    image_path: str,
    inode: str,
    output_path: str,
    offset: int | None = None,
) -> ToolResult:
    """Recover a deleted file from a disk/filesystem image by inode number.

    Use ``disk_list_files`` with ``include_deleted=True`` first to find the
    inode number of the deleted file, then pass it to this tool.

    Args:
        image_path: Path to the disk or filesystem image file.
        inode: Inode number of the file to recover (from disk_list_files output).
        output_path: Destination path to write the recovered file.
        offset: Partition start offset in sectors (from disk_list_partition).

    Returns:
        ToolResult with recovery status, file size, and SHA256 hash of recovered data.

    Example:
        >>> result = await disk_recover_deleted(
        ...     "/app/workspace/disk.img",
        ...     inode="2437",
        ...     output_path="/app/workspace/recovered/file.exe",
        ... )
    """
    validated = validate_file_path(image_path)
    out = Path(output_path)
    workspace = get_workspace_config().workspace.resolve()
    resolved_out = (out if out.is_absolute() else (workspace / out)).resolve()
    if not resolved_out.is_relative_to(workspace):
        return failure(
            "PATH_TRAVERSAL_DETECTED",
            f"output_path '{output_path}' must reside within the workspace directory",
        )
    if resolved_out == Path(validated).resolve():
        return failure("INVALID_OUTPUT_PATH", "output_path must not overwrite the disk image")
    resolved_out.parent.mkdir(parents=True, exist_ok=True)

    if not _check_tsk_available():
        return failure(
            "DEPENDENCY_MISSING",
            "Sleuth Kit (icat) is not installed",
            hint="Install with: apt-get install sleuthkit",
        )

    cmd = ["icat"]
    if offset is not None:
        cmd.extend(["-o", str(offset)])
    cmd.extend([str(validated), inode])

    resolved_exe = shutil.which(cmd[0])
    if not resolved_exe:
        return failure("DEPENDENCY_MISSING", "Sleuth Kit (icat) is not installed")

    max_recovered_bytes = get_config().forensics_max_recovered_bytes
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{resolved_out.name}.",
        suffix=".partial",
        dir=resolved_out.parent,
    )
    os.close(fd)
    temporary_path = Path(temporary_name)
    recovered_bytes = 0
    hasher = hashlib.sha256()

    try:
        with temporary_path.open("wb") as output:

            def write_recovered_chunk(chunk: bytes) -> None:
                nonlocal recovered_bytes
                output.write(chunk)
                hasher.update(chunk)
                recovered_bytes += len(chunk)

            returncode, stderr, _, output_limit_reached = await execute_subprocess_bytes_async(
                [resolved_exe, *cmd[1:]],
                write_recovered_chunk,
                max_output_size=max_recovered_bytes,
                timeout=120,
            )
    except ToolNotFoundError:
        temporary_path.unlink(missing_ok=True)
        return failure("DEPENDENCY_MISSING", "Sleuth Kit (icat) is not installed")
    except ExecutionTimeoutError:
        temporary_path.unlink(missing_ok=True)
        return failure("RECOVERY_TIMEOUT", f"icat timed out while recovering inode {inode}")
    except asyncio.CancelledError:
        temporary_path.unlink(missing_ok=True)
        raise
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    if output_limit_reached:
        temporary_path.unlink(missing_ok=True)
        return failure(
            "RECOVERY_LIMIT_EXCEEDED",
            f"Recovered data exceeds the configured {max_recovered_bytes:,}-byte limit",
            max_recovered_bytes=max_recovered_bytes,
        )
    if returncode != 0:
        temporary_path.unlink(missing_ok=True)
        return failure(
            "RECOVERY_FAILED",
            f"icat failed for inode {inode} (exit {returncode}): {stderr.strip()}",
            hint="Verify inode number with disk_list_files or disk_analyze_mft.",
        )
    if recovered_bytes == 0:
        temporary_path.unlink(missing_ok=True)
        return failure(
            "EMPTY_INODE",
            f"Inode {inode} contains no data (may be fully overwritten)",
        )

    try:
        os.replace(temporary_path, resolved_out)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    sha256 = hasher.hexdigest()

    return success(
        {
            "image_path": str(validated),
            "inode": inode,
            "output_path": str(resolved_out),
            "recovered_bytes": recovered_bytes,
            "sha256": sha256,
            "status": "recovered",
        }
    )


@log_execution(tool_name="disk_analyze_mft")
@track_metrics("disk_analyze_mft")
@handle_tool_errors
async def disk_analyze_mft(
    image_path: str,
    offset: int | None = None,
    limit: int = 500,
) -> ToolResult:
    """Analyze the NTFS Master File Table (MFT) for file timeline and metadata.

    Provides full filesystem metadata including file creation/modification/access
    times, which is critical for establishing a forensic timeline.

    Args:
        image_path: Path to an NTFS disk or filesystem image.
        offset: Partition start offset in sectors (from disk_list_partition).
        limit: Maximum MFT entries to return (default: 500).

    Returns:
        ToolResult with MFT entries including timestamps and file metadata.

    Example:
        >>> result = await disk_analyze_mft("/app/workspace/ntfs.img")
        >>> for entry in result.data["mft_entries"]:
        ...     print(entry["name"], entry["mtime"])
    """
    validated = validate_file_path(image_path)

    if not _check_tsk_available():
        return failure(
            "DEPENDENCY_MISSING",
            "Sleuth Kit (fls/istat) is not installed",
            hint="Install with: apt-get install sleuthkit",
        )

    cmd = ["fls", "-m", "/", "-r"]
    if offset is not None:
        cmd.extend(["-o", str(offset)])
    cmd.append(str(validated))

    entries: list[dict[str, Any]] = []
    entry_count = 0
    entry_limit = min(max(limit, 0), _MAX_RETURNED_ENTRIES)

    def add_entry(line: str, line_truncated: bool) -> None:
        nonlocal entry_count
        if line_truncated:
            return
        # mactime format: "0|/path/to/file|inode|perms|uid|gid|size|atime|mtime|ctime|crtime"
        parts = line.split("|")
        if len(parts) < 11:
            return
        entry_count += 1
        if len(entries) < entry_limit:
            entries.append(
                {
                    "path": parts[1],
                    "inode": parts[2],
                    "permissions": parts[3],
                    "size": parts[6],
                    "atime": parts[7],
                    "mtime": parts[8],
                    "ctime": parts[9],
                    "crtime": parts[10],
                }
            )

    output_limit = get_config().max_output_size
    rc, stderr, _, output_limit_reached, line_truncated = await execute_subprocess_lines_async(
        ["fls", *cmd[1:]],
        add_entry,
        max_output_size=output_limit,
        max_line_size=min(_MAX_OUTPUT_LINE_BYTES, output_limit),
        timeout=300,
    )

    if rc != 0 and entry_count == 0 and not output_limit_reached and not line_truncated:
        return failure(
            "TSK_ERROR",
            f"MFT analysis failed (exit {rc}): {stderr.strip()}",
            hint="Ensure this is an NTFS partition. Use disk_list_partition to find offsets.",
        )

    return success(
        {
            "image_path": str(validated),
            "mft_entries": entries,
            "entry_count": entry_count,
            "truncated": (
                output_limit_reached or line_truncated or rc != 0 or entry_count > len(entries)
            ),
            "count_complete": not output_limit_reached and not line_truncated and rc == 0,
        }
    )


@log_execution(tool_name="disk_extract_file")
@track_metrics("disk_extract_file")
@handle_tool_errors
async def disk_extract_file(
    image_path: str,
    inode: str,
    output_path: str,
    offset: int | None = None,
) -> ToolResult:
    """Extract a live (non-deleted) file from a disk image by inode number.

    Args:
        image_path: Path to the disk or filesystem image file.
        inode: Inode number of the file to extract.
        output_path: Destination path to write the extracted file.
        offset: Partition start offset in sectors.

    Returns:
        ToolResult with extraction status, file size, and integrity hash.

    Example:
        >>> result = await disk_extract_file(
        ...     "/app/workspace/disk.img",
        ...     inode="1234",
        ...     output_path="/app/workspace/extracted/sample.bin",
        ... )
    """
    # Reuse recovery logic (icat works for both live and deleted inodes)
    return await disk_recover_deleted(image_path, inode, output_path, offset)


@log_execution(tool_name="disk_hash_verify")
@track_metrics("disk_hash_verify")
@handle_tool_errors
async def disk_hash_verify(
    image_path: str,
    expected_hash: str | None = None,
    algorithm: str = "sha256",
) -> ToolResult:
    """Compute and verify the integrity hash of a disk image or recovered file.

    Essential for forensic chain of custody — verifies that an image has not
    been tampered with since acquisition.

    Args:
        image_path: Path to the disk image or file to hash.
        expected_hash: Optional expected hash value to verify against.
        algorithm: Hash algorithm to use ('sha256', 'sha1', 'md5'). Default: 'sha256'.

    Returns:
        ToolResult with computed hash and verification status.

    Example:
        >>> result = await disk_hash_verify(
        ...     "/app/workspace/disk.img",
        ...     expected_hash="abc123...",
        ... )
        >>> print(result.data["verified"])
    """
    validated = validate_file_path(image_path)

    if algorithm not in ("sha256", "sha1", "md5"):
        return failure(
            "INVALID_ALGORITHM",
            f"Unsupported hash algorithm: {algorithm}",
            hint="Use 'sha256', 'sha1', or 'md5'.",
        )

    hash_obj = hashlib.new(algorithm)
    chunk_size = 1024 * 1024  # 1 MB chunks

    with validated.open("rb") as f:
        while chunk := f.read(chunk_size):
            hash_obj.update(chunk)

    computed = hash_obj.hexdigest()
    verified = expected_hash is None or computed.lower() == expected_hash.lower()

    return success(
        {
            "image_path": str(validated),
            "algorithm": algorithm,
            "computed_hash": computed,
            "expected_hash": expected_hash,
            "verified": verified,
            "file_size_bytes": validated.stat().st_size,
            "status": "MATCH" if verified else "MISMATCH",
        }
    )
