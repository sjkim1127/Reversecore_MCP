"""Static analysis tools for extracting strings, scanning for versions, and detecting embedded content."""

import asyncio
import os
import re
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async, prepare_sandbox_access
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# Output size limits
MIN_OUTPUT_SIZE = 1024 * 1024  # 1MB - minimum output size for meaningful analysis
LLM_SAFE_LIMIT = 50 * 1024  # 50KB - roughly 12-15k tokens, safe for most LLMs
MAX_EXTRACTED_FILES = 200  # Maximum files to report in extraction results
MAX_SIGNATURES = 50  # Maximum signatures to report

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

# Pre-compile RTTI detection patterns for performance optimization
# These patterns are used in extract_rtti_info to identify C++ type information
_RTTI_MAIN_PATTERN = re.compile(r"(_ZTS|_ZTI|_ZTV|\.?\?A[VUW]|class\s+\w+|struct\s+\w+)")

# Patterns for extracting class names from various RTTI formats
_RTTI_CLASS_PATTERNS = (
    re.compile(r"(?:class|struct)\s+(\w+(?:::\w+)*)"),  # class Foo, struct Bar::Baz
    re.compile(r"\.?\?AV(\w+)@@"),  # MSVC class: .?AVClassName@@
    re.compile(r"\.?\?AU(\w+)@@"),  # MSVC struct: .?AUStructName@@
    re.compile(r"_ZTS(\d+)(\w+)"),  # GCC typeinfo: _ZTS4Foo -> Foo (length prefixed)
    re.compile(
        r"(\w{2,}(?:Actor|Component|Manager|Controller|Handler|Service|Factory|Provider|Interface))"
    ),  # Common OOP patterns
    re.compile(r"(C[a-z][A-Z]\w{3,})"),  # Hungarian notation: CzCharacter, CxMonster
)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
async def run_strings(
    file_path: str,
    min_length: int = 10,  # Increased default from 4 to 10 to reduce noise and memory usage
    max_output_size: int = 2_000_000,  # Reduced default to 2MB for safety
    timeout: int = DEFAULT_TIMEOUT,
    run_async: bool = False,
    _bypass_queue: bool = False,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""
    if not _bypass_queue:
        from reversecore_mcp.core.task_queue import run_task_or_fallback

        return await run_task_or_fallback(
            "task_run_strings",
            run_strings,
            file_path,
            min_length,
            max_output_size,
            timeout,
            run_async=run_async,
            _bypass_queue=True,
        )

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )

    # Enforce strict output limits
    if max_output_size > 10_000_000:
        max_output_size = 10_000_000  # Cap at 10MB hard limit

    # Enforce a reasonable minimum output size to prevent accidental truncation
    if max_output_size < MIN_OUTPUT_SIZE:
        max_output_size = MIN_OUTPUT_SIZE

    validated_path = validate_file_path(file_path)

    # Use -n option to filter short strings at source
    cmd = ["strings", "-n", str(min_length), str(validated_path)]

    # Use execute_subprocess_async which now has robust streaming and memory limits
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )

    # Truncate output logic enhanced with file saving
    output_files = {}

    # Calculate statistics
    text_output = output
    lines = text_output.splitlines()
    count = len(lines)

    if len(output) > LLM_SAFE_LIMIT:
        # Save full output to temp file (NOT source directory)
        # This avoids: read-only mount failures, race conditions, leftover files
        import tempfile

        try:
            # Use workspace temp directory for output files for security & auto-cleanup
            workspace_tmp = get_config().workspace / "tmp"
            workspace_tmp.mkdir(exist_ok=True)

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix="_strings.txt",
                prefix=f"{validated_path.stem}_",
                dir=str(workspace_tmp),
                delete=False,  # Keep file so user can access it
                encoding="utf-8",
            ) as f:
                f.write(text_output)
                strings_path = f.name

            output_files["full_output"] = strings_path

            # Create preview
            preview_limit = min(2000, len(text_output))  # First 2000 chars
            preview_text = (
                text_output[:preview_limit] + f"\n... (truncated, full content in {strings_path})"
            )

            return success(
                preview_text,
                bytes_read=bytes_read,
                truncated=True,
                string_statistics={
                    "count": count,
                    "preview": lines[:50],  # First 50 lines list
                    "file_path": strings_path,
                    "full_size": len(text_output),
                },
            )
        except Exception as e:
            # Fallback if file write fails
            truncated_output = output[:LLM_SAFE_LIMIT]
            return success(
                truncated_output + f"\n[Error saving file: {e}]",
                bytes_read=bytes_read,
                truncated=True,
            )

    return success(
        output,
        bytes_read=bytes_read,
        string_statistics={
            "count": count,
            "preview": lines[:50],
            "full_size": len(text_output),
        },
    )


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


@log_execution(tool_name="run_binwalk_extract")
@track_metrics("run_binwalk_extract")
@handle_tool_errors
async def run_binwalk_extract(
    file_path: str,
    output_dir: str | None = None,
    matryoshka: bool = True,
    depth: int = 8,
    max_output_size: int = 50_000_000,
    timeout: int = 600,
) -> ToolResult:
    """
    Extract embedded files and file systems from a binary using binwalk.

    This tool performs deep extraction of embedded content, including:
    - Compressed archives (gzip, bzip2, lzma, xz)
    - File systems (squashfs, cramfs, jffs2, ubifs)
    - Firmware images and bootloaders
    - Nested/matryoshka content (files within files)

    **Use Cases:**
    - **Firmware Analysis**: Extract file systems from router/IoT firmware
    - **Malware Unpacking**: Extract payloads from packed/embedded malware
    - **Forensics**: Recover embedded files from disk images
    - **CTF Challenges**: Extract hidden data from challenge files

    Args:
        file_path: Path to the binary file to extract
        output_dir: Directory to extract files to (default: creates temp dir)
        matryoshka: Enable recursive extraction (files within files)
        depth: Maximum extraction depth for nested content (default: 8)
        max_output_size: Maximum output size in bytes
        timeout: Extraction timeout in seconds (default: 600 for large files)

    Returns:
        ToolResult with extraction summary including:
        - extracted_files: List of extracted files with paths and types
        - output_directory: Path to extraction output
        - total_size: Total size of extracted content
        - extraction_depth: Maximum depth reached during extraction

    Example:
        >>> result = await run_binwalk_extract("/path/to/firmware.bin")
        >>> print(result.data["extracted_files"])
        [{"path": "squashfs-root/etc/passwd", "type": "ASCII text", "size": 1234}, ...]
    """
    validated_path = validate_file_path(file_path)
    settings = get_config()

    # Create output directory if not specified
    is_temp_dir = False
    if output_dir is None:
        # The sandbox grants write access only to workspace/.cache.
        cache_dir = settings.workspace.resolve() / ".cache"
        if cache_dir.is_symlink():
            return failure(
                "INVALID_WORKSPACE", "Workspace cache directory must not be a symbolic link"
            )
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_dir.resolve().relative_to(settings.workspace.resolve())
        temp_dir = tempfile.mkdtemp(prefix="binwalk_extract_", dir=str(cache_dir))
        prepare_sandbox_access(Path(temp_dir))
        extraction_dir = temp_dir
        is_temp_dir = True
    else:
        # Resolve output directory path (may not exist yet)
        from reversecore_mcp.core.exceptions import ValidationError

        output_path = Path(output_dir).expanduser().resolve()
        # Verify output directory resolves to be within workspace
        workspace = get_config().workspace.resolve()
        try:
            output_path.relative_to(workspace)
        except ValueError:
            raise ValidationError(
                f"Output directory must be inside the workspace: {workspace}",
                details={"output_dir": output_dir, "workspace": str(workspace)},
            )
        extraction_dir = str(output_path)
        os.makedirs(extraction_dir, exist_ok=True)

    # Build binwalk extraction command
    cmd = ["binwalk", "-e"]  # -e for extraction

    if matryoshka:
        cmd.append("-M")  # Matryoshka/recursive extraction

    cmd.extend(["-d", str(depth)])  # Extraction depth
    cmd.extend(["-C", str(extraction_dir)])  # Output directory
    cmd.append(str(validated_path))

    try:
        # Poll filesystem output while Binwalk is still running. The stdout
        # capture cap below is separate from these on-disk extraction budgets.
        extraction_task = asyncio.create_task(
            execute_subprocess_async(
                cmd,
                max_output_size=max_output_size,
                timeout=timeout,
                kill_process_group=True,
            )
        )
        try:
            while not extraction_task.done():
                await asyncio.sleep(0.1)
                if extraction_task.done():
                    break
                total_size, total_files, exceeded = await asyncio.to_thread(
                    _measure_extraction_tree,
                    Path(extraction_dir),
                    settings.binwalk_max_extracted_bytes,
                    settings.binwalk_max_extracted_files,
                )
                if exceeded:
                    extraction_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await extraction_task
                    if is_temp_dir:
                        shutil.rmtree(extraction_dir, ignore_errors=True)
                    return failure(
                        "RESOURCE_LIMIT",
                        "Binwalk extraction stopped after exceeding its configured output budget "
                        f"({settings.binwalk_max_extracted_bytes} bytes, "
                        f"{settings.binwalk_max_extracted_files} files).",
                        partial_bytes=total_size,
                        partial_files=total_files,
                    )

            output, bytes_read = await extraction_task
            total_size, total_files, exceeded = await asyncio.to_thread(
                _measure_extraction_tree,
                Path(extraction_dir),
                settings.binwalk_max_extracted_bytes,
                settings.binwalk_max_extracted_files,
            )
            if exceeded:
                if is_temp_dir:
                    shutil.rmtree(extraction_dir, ignore_errors=True)
                return failure(
                    "RESOURCE_LIMIT",
                    "Binwalk extraction stopped after exceeding its configured output budget "
                    f"({settings.binwalk_max_extracted_bytes} bytes, "
                    f"{settings.binwalk_max_extracted_files} files).",
                    partial_bytes=total_size,
                    partial_files=total_files,
                )
        finally:
            if not extraction_task.done():
                extraction_task.cancel()
                with suppress(asyncio.CancelledError):
                    await extraction_task

        # Gather extraction results
        extracted_files: list[dict[str, Any]] = []
        total_size = 0
        max_depth_found = 0

        # Walk the extraction directory to catalog results
        extraction_path = Path(extraction_dir)
        if extraction_path.exists():
            for root, _dirs, files in os.walk(extraction_path):
                # Calculate depth from extraction root
                rel_path = Path(root).relative_to(extraction_path)
                current_depth = len(rel_path.parts)
                max_depth_found = max(max_depth_found, current_depth)

                for filename in files:
                    file_full_path = Path(root) / filename
                    try:
                        if file_full_path.is_symlink():
                            continue
                        file_size = file_full_path.stat(follow_symlinks=False).st_size
                        total_size += file_size

                        # Try to determine file type
                        file_type = "unknown"
                        try:
                            # Use 'file' command for type detection
                            type_cmd = ["file", "-b", str(file_full_path)]
                            type_output, _ = await execute_subprocess_async(
                                type_cmd, timeout=5, max_output_size=1024
                            )
                            file_type = type_output.strip()[:100]  # Limit type string length
                        except (OSError, TimeoutError):
                            # file command failed or timed out, use default "unknown"
                            file_type = "unknown"

                        extracted_files.append(
                            {
                                "path": str(file_full_path.relative_to(extraction_path)),
                                "type": file_type,
                                "size": file_size,
                            }
                        )
                    except (OSError, ValueError):
                        continue

        # Sort by size (largest first) and limit entries
        extracted_files.sort(key=lambda x: int(x["size"]), reverse=True)
        truncated = len(extracted_files) > MAX_EXTRACTED_FILES
        extracted_files = extracted_files[:MAX_EXTRACTED_FILES]

        # Parse binwalk output for additional info
        signatures_found = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith("DECIMAL") and not line.startswith("-"):
                # Extract signature type from binwalk output.
                # maxsplit=2 means parts[2] already holds the full remainder,
                # so we avoid the " ".join(parts[2:]) re-join cost.
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    try:
                        offset = int(parts[0])
                        sig_type = parts[2]
                        signatures_found.append({"offset": offset, "type": sig_type[:100]})
                    except (ValueError, IndexError):
                        continue

        return success(
            {
                "output_directory": str(extraction_dir),
                "extracted_files": extracted_files,
                "total_files": len(extracted_files)
                + (100 if truncated else 0),  # Estimate if truncated
                "total_size": total_size,
                "total_size_human": _format_size(total_size),
                "extraction_depth": max_depth_found,
                "signatures_found": signatures_found[:MAX_SIGNATURES],
                "binwalk_output": output[:5000] if len(output) > 5000 else output,
                "truncated": truncated,
            },
            bytes_read=bytes_read,
            description=f"Extracted {len(extracted_files)} files ({_format_size(total_size)}) to {extraction_dir}",
        )
    except asyncio.CancelledError:
        if is_temp_dir and os.path.exists(extraction_dir):
            shutil.rmtree(extraction_dir, ignore_errors=True)
        raise
    except Exception:
        if is_temp_dir and os.path.exists(extraction_dir):
            shutil.rmtree(extraction_dir, ignore_errors=True)
        raise


def _format_size(size_bytes: int | float) -> str:
    """Format byte size to human-readable string."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _measure_extraction_tree(root: Path, max_bytes: int, max_files: int) -> tuple[int, int, bool]:
    """Measure extracted entries without following symlinks or walking past the limits."""
    total_size = 0
    total_files = 0
    pending = [root]

    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            continue

        with entries:
            for entry in entries:
                try:
                    total_files += 1
                    if total_files > max_files:
                        return total_size, total_files, True
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                        continue

                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat(follow_symlinks=False).st_size
                    if total_files > max_files or total_size > max_bytes:
                        return total_size, total_files, True
                except OSError:
                    continue

    return total_size, total_files, False


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
        description=f"Detected {len(detected)} potential library versions",
    )


@log_execution(tool_name="extract_rtti_info")
@track_metrics("extract_rtti_info")
@handle_tool_errors
async def extract_rtti_info(
    file_path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Extract RTTI (Run-Time Type Information) from C++ binaries.

    RTTI provides class names and inheritance hierarchies in C++ binaries,
    which is invaluable for understanding object-oriented malware and game clients.

    Args:
        file_path: Path to the binary file
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with extracted class names and type information
    """
    validated_path = validate_file_path(file_path)

    # Use strings with C++ demangling to extract RTTI
    # Look for typeinfo names which start with _ZTS (type string)
    cmd = ["strings", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=10_000_000,
        timeout=timeout,
    )

    # Use pre-compiled module-level patterns for better performance
    # These patterns are compiled once at module load time, avoiding the overhead
    # of regex compilation on each function call

    rtti_strings = []
    class_names = set()

    for line in output.splitlines():
        line_stripped = line.strip()
        if _RTTI_MAIN_PATTERN.search(line_stripped):
            rtti_strings.append(line_stripped)

            # Try all patterns to extract class names
            for pattern in _RTTI_CLASS_PATTERNS:
                matches = pattern.findall(line_stripped)
                for match in matches:
                    # Handle tuple results from patterns with groups
                    if isinstance(match, tuple):
                        class_name = match[-1]  # Take the last group (usually the name)
                    else:
                        class_name = match

                    # Filter out noise (too short, all caps, numbers only)
                    if (
                        len(class_name) > 2
                        and not class_name.isupper()
                        and not class_name.isdigit()
                    ):
                        class_names.add(class_name)

    return success(
        {
            "rtti_strings": rtti_strings[:200],  # Limit to first 200
            "class_names": sorted(class_names),  # sorted() accepts any iterable
            "total_rtti_entries": len(rtti_strings),
            "total_classes": len(class_names),
        },
        bytes_read=bytes_read,
        description=f"Extracted {len(class_names)} C++ class names from RTTI",
    )


# Note: StaticAnalysisPlugin has been removed.
# The static analysis tools are now registered via AnalysisToolsPlugin in analysis/__init__.py.
