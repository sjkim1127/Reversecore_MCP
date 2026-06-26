"""
Detect It Easy (DIE) integration for packer/compiler detection.

Provides tools to identify binary file characteristics using the DIE CLI (diec).
When DIE is not available, detect_packer_deep falls back to a strings-based
heuristic approach for basic packer/compiler identification.
"""

import shutil

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Known packer/protector signature strings for heuristic fallback detection
_PACKER_SIGNATURES: list[tuple[str, str]] = [
    # (pattern, label)
    (r"UPX[0-9!]", "UPX"),
    (r"MPRESS", "MPRESS"),
    (r"PEC2", "PEC2"),
    (r"ASPack", "ASPack"),
    (r"Themida", "Themida"),
    (r"VMProtect", "VMProtect"),
    (r"Enigma", "Enigma Protector"),
    (r"ExeStealth", "ExeStealth"),
    (r"NsPack", "NsPack"),
    (r"PECompact", "PECompact"),
    (r"FSG ", "FSG"),
    (r"PETITE", "Petite"),
    (r"BeRoEXEPacker", "BeRo"),
    (r"kkrunchy", "kkrunchy"),
]

_COMPILER_SIGNATURES: list[tuple[str, str]] = [
    (r"GCC:.*?\d+\.\d+\.\d+", "GCC"),
    (r"Microsoft Visual C", "MSVC"),
    (r"clang version", "Clang"),
    (r"Delphi", "Delphi"),
    (r"Go build", "Go"),
    (r"rustc", "Rust"),
    (r"PyInstaller", "PyInstaller"),
    (r"\.NET Framework", ".NET"),
    (r"AutoIt", "AutoIt"),
    (r"NSIS", "NSIS"),
]


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


@log_execution()
async def detect_packer(file_path: str):
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
        return failure(
            error_code="DIE_NOT_INSTALLED",
            message="Detect It Easy (diec) is not installed. "
            "Install with: apt install detect-it-easy (Linux) or brew install detect-it-easy (macOS)",
        )

    # Run DIE
    try:
        output, _ = await execute_subprocess_async(
            ["diec", str(validated_path)],
            timeout=30,
        )
    except Exception as e:
        return failure(error_code="DIE_EXECUTION_ERROR", message=f"DIE execution failed: {e}")

    # Parse output
    result = _parse_die_output(output)

    # Determine if packed
    is_packed = result["packer"] is not None or result["protector"] is not None

    return success(
        data=result,
        message=f"Detected: {result['file_type'] or 'Unknown'}"
        + (f" | Packer: {result['packer']}" if result["packer"] else "")
        + (f" | Compiler: {result['compiler']}" if result["compiler"] else ""),
        is_packed=is_packed,
        detection_count=len(result["detections"]),
    )


@log_execution()
async def detect_packer_deep(file_path: str):
    """
    Deep scan for packer/compiler/protector detection.

    Primary: Uses DIE (Detect It Easy) ``diec -d`` for deep analysis.
    Fallback: When DIE is not installed, performs a strings-based heuristic
    scan that identifies common packer and compiler signatures embedded in
    the binary.  Results are clearly labelled with ``source`` so callers
    know which method was used.

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ToolResult with detailed detection information. Always returns
        partial results even when DIE is unavailable (via strings fallback).
        Check the ``source`` field: "diec" vs "strings_heuristic".
    """
    validated_path = validate_file_path(file_path)

    # -------------------------------------------------------------------------
    # Primary path: DIE deep scan
    # -------------------------------------------------------------------------
    if _is_die_available():
        try:
            output, _ = await execute_subprocess_async(
                ["diec", "-d", str(validated_path)],
                timeout=60,
            )
            result = _parse_die_output(output)
            return success(
                data=result,
                message=f"Deep scan complete: {len(result['detections'])} detections",
                scan_type="deep",
                source="diec",
            )
        except Exception as e:
            return failure(
                error_code="DIE_DEEP_SCAN_FAILED",
                message=f"DIE deep scan failed: {e}",
            )

    # -------------------------------------------------------------------------
    # Fallback path: strings-based heuristic when DIE is not installed
    # -------------------------------------------------------------------------
    logger.warning(
        "DIE (diec) not available — falling back to strings-based heuristic for %s",
        validated_path.name,
    )

    try:
        data = validated_path.read_bytes()
    except OSError as exc:
        return failure("FILE_READ_ERROR", f"Cannot read file: {exc}")

    # Extract printable ASCII strings from binary for pattern matching
    import re as _re

    ascii_strings = b" ".join(m.group() for m in _re.finditer(rb"[ -~]{4,}", data)).decode(
        "ascii", errors="ignore"
    )

    detections: list[dict] = []
    found_packer: str | None = None
    found_compiler: str | None = None

    for pattern, label in _PACKER_SIGNATURES:
        if _re.search(pattern, ascii_strings, _re.IGNORECASE):
            found_packer = label
            detections.append({"type": "packer", "value": label})
            break  # report first match

    for pattern, label in _COMPILER_SIGNATURES:
        m = _re.search(pattern, ascii_strings, _re.IGNORECASE)
        if m:
            found_compiler = label
            detections.append({"type": "compiler", "value": label})
            break

    result = {
        "file_type": None,
        "arch": None,
        "compiler": found_compiler,
        "linker": None,
        "packer": found_packer,
        "protector": None,
        "installer": None,
        "sfx": None,
        "overlay": False,
        "raw_output": ascii_strings[:2000],  # truncate for readability
        "detections": detections,
    }

    is_packed = found_packer is not None

    return success(
        data=result,
        message=(
            f"Strings-heuristic scan complete: {len(detections)} detection(s). "
            "Install 'diec' (Detect It Easy) for higher accuracy."
        ),
        scan_type="strings_heuristic",
        source="strings_heuristic",
        is_packed=is_packed,
        detection_count=len(detections),
        die_available=False,
    )
