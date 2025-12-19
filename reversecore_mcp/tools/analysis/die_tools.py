"""
Detect It Easy (DIE) integration for packer/compiler detection.

Provides tools to identify binary file characteristics using the DIE CLI (diec).
"""

import shutil

from reversecore_mcp.core.decorators import tool_error_handler
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


def _is_die_available() -> bool:
    """Check if Detect It Easy CLI (diec) is available."""
    return shutil.which("diec") is not None


def _parse_die_output(output: str) -> dict:
    """
    Parse DIE output into structured data.

    DIE output format example:
    PE32
    Compiler: Microsoft Visual C/C++(2019 v.16.0-4)[-]
    Linker: Microsoft Linker(14.26.28805)[EXE32,console]
    Packer: UPX(3.96)[NRV,brute]
    """
    result = {
        "file_type": None,
        "arch": None,
        "compiler": None,
        "linker": None,
        "packer": None,
        "protector": None,
        "installer": None,
        "sfx": None,
        "overlay": False,
        "raw_output": output,
        "detections": [],
    }

    lines = output.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # First line is usually the file type
        if result["file_type"] is None and ":" not in line:
            result["file_type"] = line
            # Extract architecture from file type
            if "PE32+" in line or "PE64" in line or "ELF64" in line:
                result["arch"] = "x64"
            elif "PE32" in line or "ELF32" in line:
                result["arch"] = "x86"
            elif "Mach-O" in line:
                result["arch"] = "arm64" if "arm64" in line.lower() else "x64"
            continue

        # Parse key: value lines
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key == "compiler":
                result["compiler"] = value
            elif key == "linker":
                result["linker"] = value
            elif key == "packer":
                result["packer"] = value
            elif key == "protector":
                result["protector"] = value
            elif key == "installer":
                result["installer"] = value
            elif key == "sfx":
                result["sfx"] = value
            elif "overlay" in key:
                result["overlay"] = True

            result["detections"].append({"type": key, "value": value})

    return result


@tool_error_handler
async def detect_packer(file_path: str) -> ToolResult:
    """
    Detect packer, compiler, and protector using Detect It Easy (DIE).

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ToolResult with detection information including:
        - file_type: PE32, PE64, ELF, Mach-O, etc.
        - compiler: Detected compiler and version
        - linker: Detected linker information
        - packer: Detected packer (UPX, ASPack, etc.)
        - protector: Detected protector (Themida, VMProtect, etc.)
    """
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Check if DIE is available
    if not _is_die_available():
        return ToolResult.error_result(
            "Detect It Easy (diec) is not installed. "
            "Install with: apt install detect-it-easy (Linux) or brew install detect-it-easy (macOS)"
        )

    # Run DIE
    try:
        output, _ = await execute_subprocess_async(
            ["diec", str(validated_path)],
            timeout_seconds=30,
        )
    except Exception as e:
        return ToolResult.error_result(f"DIE execution failed: {e}")

    # Parse output
    result = _parse_die_output(output)

    # Determine if packed
    is_packed = result["packer"] is not None or result["protector"] is not None

    return ToolResult.success_result(
        data=result,
        message=f"Detected: {result['file_type'] or 'Unknown'}"
        + (f" | Packer: {result['packer']}" if result["packer"] else "")
        + (f" | Compiler: {result['compiler']}" if result["compiler"] else ""),
        metadata={
            "is_packed": is_packed,
            "detection_count": len(result["detections"]),
        },
    )


@tool_error_handler
async def detect_packer_deep(file_path: str) -> ToolResult:
    """
    Deep scan with DIE for more thorough detection.

    Uses additional DIE options for deeper analysis.

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ToolResult with detailed detection information
    """
    validated_path = validate_file_path(file_path)

    if not _is_die_available():
        return ToolResult.error_result("Detect It Easy (diec) is not installed.")

    try:
        # Use deep scan option
        output, _ = await execute_subprocess_async(
            ["diec", "-d", str(validated_path)],
            timeout_seconds=60,
        )
    except Exception as e:
        return ToolResult.error_result(f"DIE deep scan failed: {e}")

    result = _parse_die_output(output)

    return ToolResult.success_result(
        data=result,
        message=f"Deep scan complete: {len(result['detections'])} detections",
        metadata={"scan_type": "deep"},
    )
