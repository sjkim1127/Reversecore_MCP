"""Static analysis tools for extracting strings, scanning for versions, and detecting embedded content."""

import re

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

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

    # Truncate output for LLM consumption if too large
    # 50KB is roughly 12-15k tokens, which is a safe limit for most models
    LLM_SAFE_LIMIT = 50 * 1024

    if len(output) > LLM_SAFE_LIMIT:
        truncated_output = output[:LLM_SAFE_LIMIT]
        warning_msg = (
            f"\n\n[WARNING] Output truncated! Total size: {len(output)} bytes. "
            f"Showing first {LLM_SAFE_LIMIT} bytes.\n"
            "To analyze the full content, consider using 'grep' or processing the file directly."
        )
        return success(
            truncated_output + warning_msg, bytes_read=bytes_read, truncated=True
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


@log_execution(tool_name="run_binwalk_extract")
@track_metrics("run_binwalk_extract")
@handle_tool_errors
async def run_binwalk_extract(
    file_path: str,
    output_dir: str = None,
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
    import os
    import tempfile
    from pathlib import Path

    validated_path = validate_file_path(file_path)
    
    # Create output directory if not specified
    if output_dir is None:
        # Create temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="binwalk_extract_")
        extraction_dir = temp_dir
    else:
        # Validate output directory path
        extraction_dir = validate_file_path(output_dir, must_exist=False)
        os.makedirs(extraction_dir, exist_ok=True)
    
    # Build binwalk extraction command
    cmd = ["binwalk", "-e"]  # -e for extraction
    
    if matryoshka:
        cmd.append("-M")  # Matryoshka/recursive extraction
    
    cmd.extend(["-d", str(depth)])  # Extraction depth
    cmd.extend(["-C", str(extraction_dir)])  # Output directory
    cmd.append(str(validated_path))
    
    # Run extraction
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    
    # Gather extraction results
    extracted_files = []
    total_size = 0
    max_depth_found = 0
    
    # Walk the extraction directory to catalog results
    extraction_path = Path(extraction_dir)
    if extraction_path.exists():
        for root, dirs, files in os.walk(extraction_path):
            # Calculate depth from extraction root
            rel_path = Path(root).relative_to(extraction_path)
            current_depth = len(rel_path.parts)
            max_depth_found = max(max_depth_found, current_depth)
            
            for filename in files:
                file_full_path = Path(root) / filename
                try:
                    file_size = file_full_path.stat().st_size
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
                    
                    extracted_files.append({
                        "path": str(file_full_path.relative_to(extraction_path)),
                        "type": file_type,
                        "size": file_size,
                    })
                except (OSError, ValueError):
                    continue
    
    # Sort by size (largest first) and limit to first 200 entries
    extracted_files.sort(key=lambda x: x["size"], reverse=True)
    truncated = len(extracted_files) > 200
    extracted_files = extracted_files[:200]
    
    # Parse binwalk output for additional info
    signatures_found = []
    for line in output.split("\n"):
        line = line.strip()
        if line and not line.startswith("DECIMAL") and not line.startswith("-"):
            # Extract signature type from binwalk output
            parts = line.split()
            if len(parts) >= 3:
                try:
                    offset = int(parts[0])
                    sig_type = " ".join(parts[2:])
                    signatures_found.append({
                        "offset": offset,
                        "type": sig_type[:100]
                    })
                except (ValueError, IndexError):
                    continue
    
    return success(
        {
            "output_directory": str(extraction_dir),
            "extracted_files": extracted_files,
            "total_files": len(extracted_files) + (100 if truncated else 0),  # Estimate if truncated
            "total_size": total_size,
            "total_size_human": _format_size(total_size),
            "extraction_depth": max_depth_found,
            "signatures_found": signatures_found[:50],  # Limit signatures
            "binwalk_output": output[:5000] if len(output) > 5000 else output,
            "truncated": truncated,
        },
        bytes_read=bytes_read,
        description=f"Extracted {len(extracted_files)} files ({_format_size(total_size)}) to {extraction_dir}",
    )


def _format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


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

    # Extract potential RTTI strings
    rtti_pattern = re.compile(r"(_ZTS|_ZTI|class\s+\w+|struct\s+\w+)")
    class_pattern = re.compile(r"(?:class|struct)\s+(\w+(?:::\w+)*)")

    rtti_strings = []
    class_names = set()

    for line in output.split("\n"):
        if rtti_pattern.search(line):
            rtti_strings.append(line.strip())
            # Try to extract class names
            class_match = class_pattern.search(line)
            if class_match:
                class_names.add(class_match.group(1))

    return success(
        {
            "rtti_strings": rtti_strings[:100],  # Limit to first 100
            "class_names": sorted(list(class_names)),
            "total_rtti_entries": len(rtti_strings),
            "total_classes": len(class_names),
        },
        bytes_read=bytes_read,
        description=f"Extracted {len(class_names)} C++ class names from RTTI",
    )
