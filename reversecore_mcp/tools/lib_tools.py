"""
Library tool wrappers for Reversecore_MCP.

This module provides MCP tools that use Python libraries directly for
reverse engineering tasks, such as yara-python and capstone.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from fastmcp import FastMCP

from reversecore_mcp.core.config import get_settings
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_formatting import format_error, get_validation_hint
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

logger = get_logger(__name__)


def register_lib_tools(mcp: FastMCP) -> None:
    """
    Register all library tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_yara)
    mcp.tool(disassemble_with_capstone)
    mcp.tool(parse_binary_with_lief)


@track_metrics("run_yara")
def run_yara(
    file_path: str,
    rule_file: str,
    timeout: int = 300,
) -> str:
    """
    Scan a file using YARA rules.

    This tool uses yara-python to scan a file against YARA rules.
    Useful for malware detection, pattern matching, and file classification.

    Args:
        file_path: Path to the file to scan
        rule_file: Path to the YARA rule file (.yar or .yara)
        timeout: Maximum execution time in seconds (default: 300)

    Returns:
        YARA scan results in JSON format, including matched rules and
        matched strings/patterns.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate parameters
    validate_tool_parameters("run_yara", {
        "rule_file": rule_file,
        "timeout": timeout
    })
    
    start_time = time.time()
    file_name = Path(file_path).name

    logger.info(
        "Starting run_yara",
        extra={"tool_name": "run_yara", "file_name": file_name},
    )

    try:
        # Validate file paths
        # rule_file can be in read-only directories (e.g., /app/rules) or workspace
        validated_file = validate_file_path(file_path)
        validated_rule = validate_file_path(rule_file, read_only=True)

        # Import yara (will raise ImportError if not installed)
        try:
            import yara
        except ImportError:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(
                "run_yara failed - yara-python not installed",
                extra={
                    "tool_name": "run_yara",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
            )
            return format_error(
                Exception("yara-python library is not installed"),
                tool_name="run_yara",
                hint="Please install it with: pip install yara-python",
            )

        # Compile YARA rules
        try:
            rules = yara.compile(filepath=validated_rule)
        except yara.Error as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(
                "run_yara failed - rule compilation error",
                extra={
                    "tool_name": "run_yara",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
                exc_info=True,
            )
            return format_error(e, tool_name="run_yara")

        # Scan the file
        try:
            matches = rules.match(validated_file, timeout=timeout)
        except yara.TimeoutError:
            execution_time = int((time.time() - start_time) * 1000)
            logger.warning(
                "run_yara timed out",
                extra={
                    "tool_name": "run_yara",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
            )
            return format_error(
                Exception(f"YARA scan timed out after {timeout} seconds"),
                tool_name="run_yara",
            )
        except yara.Error as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(
                "run_yara scan failed",
                extra={
                    "tool_name": "run_yara",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
                exc_info=True,
            )
            return format_error(e, tool_name="run_yara")

        # Format results
        if not matches:
            execution_time = int((time.time() - start_time) * 1000)
            logger.info(
                "run_yara completed - no matches",
                extra={
                    "tool_name": "run_yara",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
            )
            return "No YARA rule matches found."

        # Pre-allocate results list with known size for better memory efficiency
        results = []
        for match in matches:
            # Build strings list supporting yara-python API:
            # match.strings is a list of StringMatch; each has .identifier and .instances
            # Each instance has .offset and .matched_data
            formatted_strings = []

            # Check if match has strings attribute first to avoid multiple getattr calls
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
                                # Optimize conditional by checking type once
                                if matched_data is not None:
                                    data_str = matched_data.hex() if isinstance(matched_data, bytes) else (matched_data if isinstance(matched_data, str) else None)
                                else:
                                    data_str = None
                                formatted_strings.append(
                                    {
                                        "identifier": identifier,
                                        "offset": int(offset) if offset is not None else None,
                                        "matched_data": data_str,
                                    }
                                )
                except (AttributeError, TypeError):
                    # Fallback: older API may return tuples (offset, identifier, data)
                    formatted_strings = []
                    for t in match_strings:
                        if isinstance(t, (list, tuple)) and len(t) >= 3:
                            off, ident, data = t[0], t[1], t[2]
                            data_str = data.hex() if isinstance(data, bytes) else (data if isinstance(data, str) else None)
                            formatted_strings.append(
                                {
                                    "identifier": ident,
                                    "offset": int(off) if off is not None else None,
                                    "matched_data": data_str,
                                }
                            )

            result = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "strings": formatted_strings,
            }
            results.append(result)

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "run_yara completed successfully",
            extra={
                "tool_name": "run_yara",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "match_count": len(matches),
            },
        )

        return json.dumps(results, indent=2)

    except (ValidationError, ValueError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else get_validation_hint(ValueError(str(e)))
        logger.warning(
            "run_yara validation failed",
            extra={
                "tool_name": "run_yara",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_yara", hint=hint)
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "run_yara unexpected error",
            extra={
                "tool_name": "run_yara",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="run_yara")


@track_metrics("disassemble_with_capstone")
def disassemble_with_capstone(
    file_path: str,
    offset: int = 0,
    size: int = 1024,
    arch: str = "x86",
    mode: str = "64",
) -> str:
    """
    Disassemble binary code using the Capstone disassembly framework.

    This tool uses the capstone library to disassemble binary code from a file.
    Supports multiple architectures and modes.

    Args:
        file_path: Path to the binary file to disassemble
        offset: Byte offset in the file to start disassembly (default: 0)
        size: Number of bytes to disassemble (default: 1024)
        arch: Architecture (x86, arm, arm64, mips, ppc, sparc, sysz, xcore) (default: x86)
        mode: Mode (16, 32, 64, arm, thumb, etc.) (default: 64)

    Returns:
        Disassembly output with addresses, bytes, and mnemonics.

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    start_time = time.time()
    file_name = Path(file_path).name

    logger.info(
        "Starting disassemble_with_capstone",
        extra={"tool_name": "disassemble_with_capstone", "file_name": file_name, "arch": arch, "mode": mode},
    )

    try:
        # Validate parameters (offset and size only, arch is validated later)
        validate_tool_parameters("disassemble_with_capstone", {
            "offset": offset,
            "size": size
        })
        
        # Validate file path
        validated_path = validate_file_path(file_path)

        # Import capstone (will raise ImportError if not installed)
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
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(
                "disassemble_with_capstone failed - capstone not installed",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
            )
            return format_error(
                Exception("capstone library is not installed"),
                tool_name="disassemble_with_capstone",
                hint="Please install it with: pip install capstone",
            )

        # Map architecture string to capstone constant
        arch_map = {
            "x86": CS_ARCH_X86,
            "arm": CS_ARCH_ARM,
            "arm64": CS_ARCH_ARM64,
        }

        if arch not in arch_map:
            supported_archs = ", ".join(sorted(arch_map.keys()))
            execution_time = int((time.time() - start_time) * 1000)
            logger.warning(
                "disassemble_with_capstone - unsupported architecture",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                    "arch": arch,
                },
            )
            return format_error(
                ValueError(f"Unsupported architecture: {arch}. Supported: {supported_archs}"),
                tool_name="disassemble_with_capstone",
            )

        # Map mode string to capstone constant
        # Mode mapping depends on architecture
        mode_map = {
            "x86": {
                "16": CS_MODE_32,  # x86-16 uses 32-bit mode constant
                "32": CS_MODE_32,
                "64": CS_MODE_64,
            },
            "arm": {
                "arm": CS_MODE_ARM,
                "thumb": CS_MODE_THUMB,
            },
            "arm64": {
                "64": CS_MODE_64,  # ARM64 is always 64-bit
            },
        }

        # Get mode constant based on architecture
        if arch not in mode_map:
            execution_time = int((time.time() - start_time) * 1000)
            logger.warning(
                "disassemble_with_capstone - invalid architecture for mode mapping",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                    "arch": arch,
                },
            )
            return format_error(
                ValueError(f"Invalid architecture for mode mapping: {arch}"),
                tool_name="disassemble_with_capstone",
            )

        arch_mode_map = mode_map[arch]
        if mode not in arch_mode_map:
            supported_modes = ", ".join(sorted(arch_mode_map.keys()))
            execution_time = int((time.time() - start_time) * 1000)
            logger.warning(
                "disassemble_with_capstone - unsupported mode",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                    "arch": arch,
                    "mode": mode,
                },
            )
            return format_error(
                ValueError(f"Unsupported mode '{mode}' for architecture '{arch}'. Supported: {supported_modes}"),
                tool_name="disassemble_with_capstone",
            )

        mode_constant = arch_mode_map[mode]

        # Read binary data from file
        with open(validated_path, "rb") as f:
            f.seek(offset)
            code = f.read(size)

        if not code:
            execution_time = int((time.time() - start_time) * 1000)
            logger.warning(
                "disassemble_with_capstone - no data read",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                    "offset": offset,
                },
            )
            return format_error(
                ValueError(f"No data read from file at offset {offset}"),
                tool_name="disassemble_with_capstone",
            )

        # Create disassembler with selected architecture and mode
        md = Cs(arch_map[arch], mode_constant)

        # Disassemble
        results = []
        for instruction in md.disasm(code, offset):
            results.append(
                f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
            )

        if not results:
            execution_time = int((time.time() - start_time) * 1000)
            logger.info(
                "disassemble_with_capstone completed - no instructions",
                extra={
                    "tool_name": "disassemble_with_capstone",
                    "file_name": file_name,
                    "execution_time_ms": execution_time,
                },
            )
            return "No instructions disassembled."

        execution_time = int((time.time() - start_time) * 1000)
        logger.info(
            "disassemble_with_capstone completed successfully",
            extra={
                "tool_name": "disassemble_with_capstone",
                "file_name": file_name,
                "execution_time_ms": execution_time,
                "instruction_count": len(results),
            },
        )

        return "\n".join(results)

    except (ValidationError, ValueError) as e:
        execution_time = int((time.time() - start_time) * 1000)
        hint = get_validation_hint(e) if isinstance(e, ValidationError) else get_validation_hint(ValueError(str(e)))
        logger.warning(
            "disassemble_with_capstone validation failed",
            extra={
                "tool_name": "disassemble_with_capstone",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="disassemble_with_capstone", hint=hint)
    except FileNotFoundError as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "disassemble_with_capstone - file not found",
            extra={
                "tool_name": "disassemble_with_capstone",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="disassemble_with_capstone")
    except Exception as e:
        execution_time = int((time.time() - start_time) * 1000)
        logger.error(
            "disassemble_with_capstone unexpected error",
            extra={
                "tool_name": "disassemble_with_capstone",
                "file_name": file_name,
                "execution_time_ms": execution_time,
            },
            exc_info=True,
        )
        return format_error(e, tool_name="disassemble_with_capstone")


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
def parse_binary_with_lief(file_path: str, format: str = "json") -> str:
    """
    Parse binary file structure using LIEF library.

    This tool uses LIEF to parse binary file formats (ELF, PE, Mach-O) and extract
    structural information such as headers, sections, symbols, and import/export tables.
    Useful for binary analysis without requiring external tools.

    Args:
        file_path: Path to the binary file to parse
        format: Output format - "json" (default) or "text"

    Returns:
        Binary structure information in JSON or text format, including:
        - File type and format
        - Headers (entry point, architecture, etc.)
        - Sections (name, virtual address, size, etc.)
        - Symbols (imports, exports, functions)
        - Import/Export tables (for PE files)

    Raises:
        Returns error message string if execution fails (never raises exceptions)
    """
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Check file size (1GB limit for safety)
    max_file_size = get_settings().lief_max_file_size
    file_size = Path(validated_path).stat().st_size
    if file_size > max_file_size:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds maximum allowed size ({max_file_size} bytes). "
            f"Set LIEF_MAX_FILE_SIZE environment variable to increase limit (current: {max_file_size} bytes)"
        )

    # Import lief (will raise ImportError if not installed)
    try:
        import lief
    except ImportError:
        raise ImportError("lief library is not installed. Please install it with: pip install lief")

    # Parse binary file
    try:
        binary = lief.parse(validated_path)
    except Exception as e:
        raise Exception(f"Failed to parse binary file: {e}")

    if binary is None:
        raise ValueError("Unsupported binary format. LIEF supports ELF, PE, and Mach-O formats.")

    # Extract information using helper functions
    result: Dict[str, Any] = {
        "format": str(binary.format).split(".")[-1].lower(),  # ELF, PE, MACHO
        "entry_point": hex(binary.entrypoint) if hasattr(binary, "entrypoint") else None,
    }

    # Add sections and symbols
    sections = _extract_sections(binary)
    if sections:
        result["sections"] = sections

    symbols = _extract_symbols(binary)
    result.update(symbols)

    # Format and return
    return _format_lief_output(result, format)
