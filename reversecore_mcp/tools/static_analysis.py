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
        return success(truncated_output + warning_msg, bytes_read=bytes_read, truncated=True)

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

    return success(detected, bytes_read=bytes_read, description=f"Detected {len(detected)} potential library versions")


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
