"""Library-backed MCP tools that emit structured ToolResult payloads."""

import json
from typing import Any, Dict, List, Optional, Protocol

from fastmcp import FastMCP

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters


def register_lib_tools(mcp: FastMCP) -> None:
    """
    Register all library tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_yara)
    mcp.tool(disassemble_with_capstone)
    mcp.tool(parse_binary_with_lief)


class YaraStringMatchInstance(Protocol):
    """Subset of yara.StringMatchInstance used by our formatter."""

    offset: Optional[int]
    matched_data: Optional[bytes]


class YaraStringMatch(Protocol):
    """Subset of yara.StringMatch used by our formatter."""

    identifier: Optional[str]
    instances: Optional[List[YaraStringMatchInstance]]


class YaraMatch(Protocol):
    """Subset of yara.Match used by our formatter."""

    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: Optional[List[YaraStringMatch]]


def _format_yara_match(match: YaraMatch) -> Dict[str, Any]:
    """
    Format a YARA match result as a dictionary.
    
    This helper function extracts match information and formats it
    consistently. Supports both modern and legacy yara-python APIs.
    
    Args:
        match: YARA match object
        
    Returns:
        Dictionary with formatted match information
    """
    formatted_strings = []
    
    # Check if match has strings attribute
    match_strings = getattr(match, "strings", None)
    if match_strings:
        try:
            # Try modern API first (more common case)
            for sm in match_strings:
                identifier = getattr(sm, "identifier", None)
                instances = getattr(sm, "instances", None)
                if instances:
                    for inst in instances:
                        offset = getattr(inst, "offset", None)
                        matched_data = getattr(inst, "matched_data", None)
                        # Convert matched_data to string
                        if matched_data is not None:
                            data_str = (matched_data.hex() 
                                       if isinstance(matched_data, bytes) 
                                       else str(matched_data))
                        else:
                            data_str = None
                        formatted_strings.append({
                            "identifier": identifier,
                            "offset": int(offset) if offset is not None else None,
                            "matched_data": data_str,
                        })
        except (AttributeError, TypeError):
            # Fallback: older API may return tuples (offset, identifier, data)
            formatted_strings = []
            for t in match_strings:
                if isinstance(t, (list, tuple)) and len(t) >= 3:
                    off, ident, data = t[0], t[1], t[2]
                    data_str = (data.hex() 
                               if isinstance(data, bytes) 
                               else str(data))
                    formatted_strings.append({
                        "identifier": ident,
                        "offset": int(off) if off is not None else None,
                        "matched_data": data_str,
                    })
    
    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": match.tags,
        "meta": match.meta,
        "strings": formatted_strings,
    }


@log_execution(tool_name="run_yara")
@track_metrics("run_yara")
@handle_tool_errors
def run_yara(
    file_path: str,
    rule_file: str,
    timeout: int = 300,
) -> ToolResult:
    """Scan binaries against YARA rules via ``yara-python``."""

    validate_tool_parameters(
        "run_yara",
        {"rule_file": rule_file, "timeout": timeout},
    )
    validated_file = validate_file_path(file_path)
    validated_rule = validate_file_path(rule_file, read_only=True)

    try:
        import yara
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "yara-python library is not installed",
            hint="Install with: pip install yara-python",
        )

    rules = yara.compile(filepath=str(validated_rule))
    timeout_error = getattr(yara, "TimeoutError", None)
    generic_error = getattr(yara, "Error", None)

    try:
        matches = rules.match(str(validated_file), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - need to inspect yara-specific errors
        if timeout_error and isinstance(exc, timeout_error):
            return failure(
                "TIMEOUT",
                f"YARA scan timed out after {timeout} seconds",
                timeout_seconds=timeout,
                details={"error": str(exc)},
            )
        if generic_error and isinstance(exc, generic_error):
            return failure("YARA_ERROR", f"YARA error: {exc}")
        raise

    if not matches:
        return success({"matches": [], "match_count": 0})

    results = [_format_yara_match(match) for match in matches]
    return success({"matches": results, "match_count": len(matches)})


@log_execution(tool_name="disassemble_with_capstone")
@track_metrics("disassemble_with_capstone")
@handle_tool_errors
def disassemble_with_capstone(
    file_path: str,
    offset: int = 0,
    size: int = 1024,
    arch: str = "x86",
    mode: str = "64",
) -> ToolResult:
    """Disassemble binary blobs using the Capstone framework."""

    validate_tool_parameters(
        "disassemble_with_capstone",
        {"offset": offset, "size": size},
    )
    validated_path = validate_file_path(file_path)

    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_ARCH_ARM64,
            CS_ARCH_X86,
            CS_MODE_32,
            CS_MODE_64,
            CS_MODE_ARM,
            CS_MODE_THUMB,
            Cs,
        )
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "capstone library is not installed",
            hint="Install with: pip install capstone",
        )

    arch_map = {
        "x86": CS_ARCH_X86,
        "arm": CS_ARCH_ARM,
        "arm64": CS_ARCH_ARM64,
    }

    mode_map = {
        "x86": {"16": CS_MODE_32, "32": CS_MODE_32, "64": CS_MODE_64},
        "arm": {"arm": CS_MODE_ARM, "thumb": CS_MODE_THUMB},
        "arm64": {"64": CS_MODE_64},
    }

    if arch not in arch_map:
        supported = ", ".join(sorted(arch_map.keys()))
        return failure(
            "INVALID_PARAMETER",
            f"Unsupported architecture: {arch}",
            hint=f"Supported architectures: {supported}",
        )

    if arch not in mode_map or mode not in mode_map[arch]:
        supported = ", ".join(sorted(mode_map.get(arch, {}).keys()))
        return failure(
            "INVALID_PARAMETER",
            f"Unsupported mode '{mode}' for architecture '{arch}'",
            hint=f"Supported modes: {supported}",
        )

    with open(validated_path, "rb") as binary_file:
        binary_file.seek(offset)
        code = binary_file.read(size)

    if not code:
        return failure(
            "NO_DATA",
            f"No data read from file at offset {offset}",
            hint="Check the offset and file size",
        )

    disassembler = Cs(arch_map[arch], mode_map[arch][mode])
    instructions = [
        f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
        for instruction in disassembler.disasm(code, offset)
    ]

    if not instructions:
        return success("No instructions disassembled.", instruction_count=0)

    return success("\n".join(instructions), instruction_count=len(instructions))


def _extract_sections(binary: Any) -> List[Dict[str, Any]]:
    """Extract section information from binary."""
    if not hasattr(binary, "sections") or not binary.sections:
        return []
    return [
        {
            "name": section.name,
            "virtual_address": hex(section.virtual_address),
            "size": section.size,
            "entropy": round(section.entropy, 2) if hasattr(section, "entropy") else None,
        }
        for section in binary.sections
    ]


def _extract_symbols(binary: Any) -> Dict[str, Any]:
    """Extract symbol information (imports/exports) from binary."""
    symbols: Dict[str, Any] = {}

    if hasattr(binary, "imported_functions") and binary.imported_functions:
        symbols["imported_functions"] = [str(func) for func in binary.imported_functions[:100]]

    if hasattr(binary, "exported_functions") and binary.exported_functions:
        symbols["exported_functions"] = [str(func) for func in binary.exported_functions[:100]]

    # PE-specific imports/exports
    if hasattr(binary, "imports") and binary.imports:
        symbols["imports"] = [
            {
                "name": imp.name,
                "functions": [str(f) for f in imp.entries[:20]],
            }
            for imp in binary.imports[:20]
        ]

    if hasattr(binary, "exports") and binary.exports:
        symbols["exports"] = [
            {
                "name": exp.name,
                "address": hex(exp.address) if hasattr(exp, "address") else None,
            }
            for exp in binary.exports[:100]
        ]

    return symbols


def _format_lief_output(result: Dict[str, Any], format: str) -> str:
    """Format LIEF parsing result as JSON or text."""
    if format.lower() == "json":
        return json.dumps(result, indent=2)

    # Text format - optimize by using list comprehension and avoiding repeated slicing
    lines = [f"Format: {result.get('format', 'Unknown')}"]
    if result.get("entry_point"):
        lines.append(f"Entry Point: {result['entry_point']}")

    sections = result.get("sections")
    if sections:
        section_count = len(sections)
        lines.append(f"\nSections ({section_count}):")
        # Iterate directly with limit instead of slicing
        for i, section in enumerate(sections):
            if i >= 20:
                break
            lines.append(f"  - {section['name']}: VA={section['virtual_address']}, Size={section['size']}")

    imported_funcs = result.get("imported_functions")
    if imported_funcs:
        func_count = len(imported_funcs)
        lines.append(f"\nImported Functions ({func_count}):")
        for i, func in enumerate(imported_funcs):
            if i >= 20:
                break
            lines.append(f"  - {func}")

    exported_funcs = result.get("exported_functions")
    if exported_funcs:
        func_count = len(exported_funcs)
        lines.append(f"\nExported Functions ({func_count}):")
        for i, func in enumerate(exported_funcs):
            if i >= 20:
                break
            lines.append(f"  - {func}")

    return "\n".join(lines)


@log_execution(tool_name="parse_binary_with_lief")
@track_metrics("parse_binary_with_lief")
@handle_tool_errors
def parse_binary_with_lief(file_path: str, format: str = "json") -> ToolResult:
    """Parse binary metadata using LIEF and return structured results."""

    validated_path = validate_file_path(file_path)

    max_file_size = get_config().lief_max_file_size
    file_size = validated_path.stat().st_size
    if file_size > max_file_size:
        return failure(
            "FILE_TOO_LARGE",
            f"File size ({file_size} bytes) exceeds maximum allowed size ({max_file_size} bytes)",
            hint="Set LIEF_MAX_FILE_SIZE environment variable to increase limit",
        )

    try:
        import lief
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "lief library is not installed",
            hint="Install with: pip install lief",
        )

    binary = lief.parse(str(validated_path))
    if binary is None:
        return failure(
            "UNSUPPORTED_FORMAT",
            "Unsupported binary format",
            hint="LIEF supports ELF, PE, and Mach-O formats",
        )

    result_data: Dict[str, Any] = {
        "format": str(binary.format).split(".")[-1].lower(),
        "entry_point": hex(binary.entrypoint) if hasattr(binary, "entrypoint") else None,
    }

    sections = _extract_sections(binary)
    if sections:
        result_data["sections"] = sections

    symbols = _extract_symbols(binary)
    result_data.update(symbols)

    if format.lower() == "json":
        return success(result_data)

    formatted_text = _format_lief_output(result_data, format)
    return success(formatted_text)
