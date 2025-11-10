"""
Library tool wrappers for Reversecore_MCP.

This module provides MCP tools that use Python libraries directly for
reverse engineering tasks, such as yara-python and capstone.
"""

from fastmcp import FastMCP

from reversecore_mcp.core.security import validate_file_path


def register_lib_tools(mcp: FastMCP) -> None:
    """
    Register all library tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_yara)
    mcp.tool(disassemble_with_capstone)


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
    try:
        # Validate file paths
        # rule_file can be in read-only directories (e.g., /app/rules) or workspace
        validated_file = validate_file_path(file_path)
        validated_rule = validate_file_path(rule_file, read_only=True)

        # Import yara (will raise ImportError if not installed)
        try:
            import yara
        except ImportError:
            return "Error: yara-python library is not installed. Please install it with: pip install yara-python"

        # Compile YARA rules
        try:
            rules = yara.compile(filepath=validated_rule)
        except yara.Error as e:
            return f"Error: Failed to compile YARA rules: {e}"

        # Scan the file
        try:
            matches = rules.match(validated_file, timeout=timeout)
        except yara.TimeoutError:
            return f"Error: YARA scan timed out after {timeout} seconds"
        except yara.Error as e:
            return f"Error: YARA scan failed: {e}"

        # Format results
        if not matches:
            return "No YARA rule matches found."

        results = []
        for match in matches:
            result = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [
                    {
                        "identifier": s.identifier,
                        "offset": s.offset,
                        "matched_data": s.matched_data.hex() if s.matched_data else None,
                    }
                    for s in match.strings
                ],
            }
            results.append(result)

        # Return formatted results
        import json

        return json.dumps(results, indent=2)

    except ValueError as e:
        return f"Error: Invalid file path - {e}"
    except Exception as e:
        return f"Error: Unexpected error - {type(e).__name__}: {e}"


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
    try:
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
            return "Error: capstone library is not installed. Please install it with: pip install capstone"

        # Map architecture string to capstone constant
        arch_map = {
            "x86": CS_ARCH_X86,
            "arm": CS_ARCH_ARM,
            "arm64": CS_ARCH_ARM64,
        }

        if arch not in arch_map:
            supported_archs = ", ".join(sorted(arch_map.keys()))
            return (
                f"Error: Unsupported architecture: {arch}. "
                f"Supported architectures: {supported_archs}"
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
            return f"Error: Invalid architecture for mode mapping: {arch}"

        arch_mode_map = mode_map[arch]
        if mode not in arch_mode_map:
            supported_modes = ", ".join(sorted(arch_mode_map.keys()))
            return (
                f"Error: Unsupported mode '{mode}' for architecture '{arch}'. "
                f"Supported modes: {supported_modes}"
            )

        mode_constant = arch_mode_map[mode]

        # Read binary data from file
        with open(validated_path, "rb") as f:
            f.seek(offset)
            code = f.read(size)

        if not code:
            return f"Error: No data read from file at offset {offset}"

        # Create disassembler with selected architecture and mode
        md = Cs(arch_map[arch], mode_constant)

        # Disassemble
        results = []
        for instruction in md.disasm(code, offset):
            results.append(
                f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
            )

        if not results:
            return "No instructions disassembled."

        return "\n".join(results)

    except ValueError as e:
        return f"Error: Invalid file path - {e}"
    except FileNotFoundError as e:
        return f"Error: File not found - {e}"
    except Exception as e:
        return f"Error: Unexpected error - {type(e).__name__}: {e}"

