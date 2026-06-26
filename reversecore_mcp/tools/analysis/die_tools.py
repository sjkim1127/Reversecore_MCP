"""
Packer and compiler detection using native Python tools (LIEF & Strings).

Provides tools to identify binary file characteristics using LIEF (for entropy
and section anomalies) and strings-based heuristics, replacing the legacy
Detect-It-Easy (diec) external dependency.
"""

import re
from pathlib import Path

import lief

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import failure, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# Known packer/protector signature strings for heuristic detection
_PACKER_SIGNATURES: list[tuple[str, str]] = [
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

# Section names known to belong to packers
_SUSPICIOUS_SECTIONS = {
    ".upx0": "UPX",
    ".upx1": "UPX",
    ".upx2": "UPX",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".vmp2": "VMProtect",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "PECompact2": "PECompact",
    ".enigma1": "Enigma Protector",
    ".enigma2": "Enigma Protector",
    ".themida": "Themida",
}


def _analyze_binary_with_lief(file_path: Path) -> dict:
    """Analyze a binary using LIEF to get format, architecture, and section entropy."""
    result = {
        "file_type": None,
        "arch": None,
        "high_entropy_sections": [],
        "suspicious_sections": [],
        "packer_from_sections": None,
    }

    try:
        binary = lief.parse(str(file_path))
        if binary is None:
            return result

        # Determine Format
        if isinstance(binary, lief.PE.Binary):
            result["file_type"] = (
                "PE32+" if binary.header.machine == lief.PE.MachineType.AMD64 else "PE32"
            )
            result["arch"] = "x64" if binary.header.machine == lief.PE.MachineType.AMD64 else "x86"
        elif isinstance(binary, lief.ELF.Binary):
            result["file_type"] = (
                "ELF64"
                if binary.header.identity_class == lief.ELF.Header.CLASS.CLASS64
                else "ELF32"
            )
            arch_type = binary.header.machine_type
            if arch_type == lief.ELF.Arch.x86_64:
                result["arch"] = "x64"
            elif arch_type == lief.ELF.Arch.i386:
                result["arch"] = "x86"
            elif arch_type == lief.ELF.Arch.AARCH64:
                result["arch"] = "arm64"
            elif arch_type == lief.ELF.Arch.ARM:
                result["arch"] = "arm"
        elif isinstance(binary, lief.MachO.Binary):
            result["file_type"] = "Mach-O"
            if binary.header.cputype == lief.MachO.CPU_TYPES.ARM64:
                result["arch"] = "arm64"
            elif binary.header.cputype == lief.MachO.CPU_TYPES.x86_64:
                result["arch"] = "x64"

        # Analyze Sections for Entropy and Names
        for section in binary.sections:
            entropy = section.entropy
            if entropy > 7.0:
                result["high_entropy_sections"].append(
                    {"name": section.name, "entropy": round(entropy, 2), "size": section.size}
                )

            # Check for suspicious section names
            name_lower = section.name.lower()
            if name_lower in _SUSPICIOUS_SECTIONS:
                result["suspicious_sections"].append(section.name)
                if not result["packer_from_sections"]:
                    result["packer_from_sections"] = _SUSPICIOUS_SECTIONS[name_lower]

    except Exception as e:
        logger.warning(f"LIEF parsing failed for {file_path.name}: {e}")

    return result


@log_execution()
async def detect_packer(file_path: str):
    """
    Detect packer, compiler, and protector using LIEF and Strings heuristics.
    (Replaces legacy Detect It Easy tool)

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ToolResult with detection information
    """
    validated_path = validate_file_path(file_path)

    try:
        data = validated_path.read_bytes()
    except OSError as exc:
        return failure("FILE_READ_ERROR", f"Cannot read file: {exc}")

    # LIEF Analysis
    lief_info = _analyze_binary_with_lief(validated_path)

    # Strings Analysis
    ascii_strings = b" ".join(m.group() for m in re.finditer(rb"[ -~]{4,}", data)).decode(
        "ascii", errors="ignore"
    )

    found_packer = lief_info["packer_from_sections"]
    found_compiler = None
    detections = []

    for pattern, label in _PACKER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            if not found_packer:
                found_packer = label
            detections.append({"type": "packer", "value": label})
            break

    for pattern, label in _COMPILER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            found_compiler = label
            detections.append({"type": "compiler", "value": label})
            break

    is_packed = found_packer is not None or len(lief_info["high_entropy_sections"]) > 0

    result = {
        "file_type": lief_info["file_type"],
        "arch": lief_info["arch"],
        "compiler": found_compiler,
        "packer": found_packer,
        "is_packed": is_packed,
        "detections": detections,
    }

    message_parts = [f"Detected: {result['file_type'] or 'Unknown'}"]
    if found_packer:
        message_parts.append(f"Packer: {found_packer}")
    elif is_packed:
        message_parts.append("Packer: Unknown (High Entropy)")
    if found_compiler:
        message_parts.append(f"Compiler: {found_compiler}")

    return success(
        data=result,
        message=" | ".join(message_parts),
        is_packed=is_packed,
        detection_count=len(detections),
    )


@log_execution()
async def detect_packer_deep(file_path: str):
    """
    Deep scan for packer/compiler/protector detection.
    Combines LIEF section entropy analysis with full strings heuristic scanning.

    Args:
        file_path: Path to the binary file to analyze

    Returns:
        ToolResult with detailed detection information.
    """
    validated_path = validate_file_path(file_path)

    try:
        data = validated_path.read_bytes()
    except OSError as exc:
        return failure("FILE_READ_ERROR", f"Cannot read file: {exc}")

    lief_info = _analyze_binary_with_lief(validated_path)
    ascii_strings = b" ".join(m.group() for m in re.finditer(rb"[ -~]{4,}", data)).decode(
        "ascii", errors="ignore"
    )

    detections = []
    found_packers = set()
    found_compilers = set()

    if lief_info["packer_from_sections"]:
        found_packers.add(lief_info["packer_from_sections"])
        detections.append({"type": "packer_section", "value": lief_info["packer_from_sections"]})

    for pattern, label in _PACKER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            found_packers.add(label)
            detections.append({"type": "packer_signature", "value": label})

    for pattern, label in _COMPILER_SIGNATURES:
        if re.search(pattern, ascii_strings, re.IGNORECASE):
            found_compilers.add(label)
            detections.append({"type": "compiler_signature", "value": label})

    is_packed = len(found_packers) > 0 or len(lief_info["high_entropy_sections"]) > 0

    result = {
        "file_type": lief_info["file_type"],
        "arch": lief_info["arch"],
        "compilers": list(found_compilers),
        "packers": list(found_packers),
        "high_entropy_sections": lief_info["high_entropy_sections"],
        "suspicious_sections": lief_info["suspicious_sections"],
        "raw_strings_sample": ascii_strings[:2000],
        "detections": detections,
    }

    return success(
        data=result,
        message=f"Deep scan complete: {len(detections)} signatures, {len(lief_info['high_entropy_sections'])} high-entropy sections found.",
        scan_type="native_deep",
        source="lief_and_strings",
        is_packed=is_packed,
        detection_count=len(detections),
    )
