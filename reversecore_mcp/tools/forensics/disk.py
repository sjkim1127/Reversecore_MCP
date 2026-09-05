"""Disk/filesystem forensics tools backed by Sleuth Kit CLI.

Uses ``mmls``, ``fls``, ``icat``, and ``istat`` from Sleuth Kit (installed as
system packages in the Docker base image) to avoid Python 3.14 pytsk3
compilation issues. All tools gracefully degrade if Sleuth Kit is absent.
"""

import asyncio
import hashlib
import shutil
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)

# Sleuth Kit CLI binary names
_TSK_TOOLS = {
    "mmls": "List partition layout of disk image",
    "fls": "List files and directories in filesystem image",
    "icat": "Extract file content by inode number",
    "istat": "Display metadata for an inode",
    "fsstat": "Display filesystem statistics",
    "blkstat": "Display statistics for a data block",
    "ffind": "Find filename(s) associated with an inode",
}


def _check_tsk_available() -> bool:
    """Check if Sleuth Kit CLI tools are available."""
    return shutil.which("fls") is not None


async def _run_tsk(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a Sleuth Kit command and return (stdout, stderr, returncode)."""
    if not cmd:
        return "", "Empty command", -1
    resolved_exe = shutil.which(cmd[0])
    if not resolved_exe:
        return "", f"Executable {cmd[0]} not found in PATH", -1

    def run():
        return subprocess.run(
            [resolved_exe] + cmd[1:], capture_output=True, text=True, timeout=timeout
        )  # nosec B603

    result = await asyncio.to_thread(run)
    return result.stdout, result.stderr, result.returncode


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

    stdout, stderr, rc = await _run_tsk(["mmls", str(validated)])

    if rc != 0 and not stdout:
        return failure(
            "TSK_ERROR",
            f"mmls failed (exit {rc}): {stderr.strip()}",
            hint="Ensure the image file is a valid disk image, not a filesystem image.",
        )

    partitions = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("DOS") or line.startswith("Description"):
            continue
        # Parse mmls output: "000: Meta 0000000000 0000000000 0000000001 ..."
        parts = line.split(None, 5)
        if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
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

    return success(
        {
            "image_path": str(validated),
            "partitions": partitions,
            "partition_count": len(partitions),
            "raw_output": stdout[:3000],
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

    stdout, stderr, rc = await _run_tsk(cmd, timeout=180)

    if rc != 0 and not stdout:
        return failure(
            "TSK_ERROR",
            f"fls failed (exit {rc}): {stderr.strip()}",
            hint="Check offset with disk_list_partition or verify image integrity.",
        )

    files: list[dict[str, Any]] = []
    for line in stdout.splitlines()[:limit]:
        # fls format: "r/r 12:   filename" or "* r/r 12:   deleted_file"
        deleted = line.startswith("*")
        clean_line = line.lstrip("* ").strip()
        parts = clean_line.split(None, 2)
        if len(parts) >= 3:
            type_part = parts[0]
            inode_part = parts[1].rstrip(":")
            name = parts[2]
            is_dir = type_part.startswith("d")
            files.append(
                {
                    "name": name,
                    "inode": inode_part,
                    "is_directory": is_dir,
                    "deleted": deleted,
                    "type": type_part,
                }
            )

    deleted_files = [f for f in files if f["deleted"]]

    return success(
        {
            "image_path": str(validated),
            "directory": directory,
            "files": files,
            "total_count": len(files),
            "deleted_count": len(deleted_files),
            "truncated": len(files) >= limit,
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

    def _run_icat():
        return subprocess.run([resolved_exe] + cmd[1:], capture_output=True, timeout=120)  # nosec B603

    result = await asyncio.to_thread(_run_icat)

    if result.returncode != 0 and not result.stdout:
        return failure(
            "RECOVERY_FAILED",
            f"icat failed for inode {inode}: {result.stderr.decode(errors='replace').strip()}",
            hint="Verify inode number with disk_list_files or disk_analyze_mft.",
        )

    if not result.stdout:
        return failure(
            "EMPTY_INODE",
            f"Inode {inode} contains no data (may be fully overwritten)",
        )

    resolved_out.write_bytes(result.stdout)
    sha256 = hashlib.sha256(result.stdout).hexdigest()

    return success(
        {
            "image_path": str(validated),
            "inode": inode,
            "output_path": str(resolved_out),
            "recovered_bytes": len(result.stdout),
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

    stdout, stderr, rc = await _run_tsk(cmd, timeout=300)

    if rc != 0 and not stdout:
        return failure(
            "TSK_ERROR",
            f"MFT analysis failed (exit {rc}): {stderr.strip()}",
            hint="Ensure this is an NTFS partition. Use disk_list_partition to find offsets.",
        )

    entries: list[dict[str, Any]] = []
    for line in stdout.splitlines()[:limit]:
        # mactime format: "0|/path/to/file|inode|perms|uid|gid|size|atime|mtime|ctime|crtime"
        parts = line.split("|")
        if len(parts) >= 11:
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

    return success(
        {
            "image_path": str(validated),
            "mft_entries": entries,
            "entry_count": len(entries),
            "truncated": len(entries) >= limit,
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
