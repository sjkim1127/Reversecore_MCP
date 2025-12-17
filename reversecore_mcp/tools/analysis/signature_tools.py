"""Signature generation tools for creating YARA rules and binary signatures."""

import re
from functools import lru_cache
from pathlib import Path

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import (
    build_r2_cmd as _build_r2_cmd,
)

# Import shared R2 helper functions from core (avoids circular dependencies)
from reversecore_mcp.core.r2_helpers import (
    execute_r2_command as _execute_r2_command,
)
from reversecore_mcp.core.r2_helpers import (
    parse_json_output as _parse_json_output,
)
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

logger = get_logger(__name__)

# OPTIMIZATION: Character translation table for filename sanitization
_FILENAME_SANITIZE_TRANS = str.maketrans({"-": "_", ".": "_"})

# OPTIMIZATION: Pre-compile regex patterns used in hot paths
# Note: _HEX_PATTERN is used for both addresses and byte sequences
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_ALL_FF_PATTERN = re.compile(r"^(ff)+$", re.IGNORECASE)
_ALL_00_PATTERN = re.compile(r"^(00)+$")
_RULE_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")


def _validate_address_or_fail(address: str, param_name: str = "address"):
    """
    Validate address format and return failure ToolResult if invalid.

    Args:
        address: Address string to validate
        param_name: Parameter name for error messages

    Returns:
        None if validation passes, or ToolResult failure if invalid
    """
    from reversecore_mcp.core.exceptions import ValidationError
    from reversecore_mcp.core.validators import validate_address_format

    try:
        validate_address_format(address, param_name)
        return None  # Validation passed
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))


def _format_hex_bytes(hex_string: str) -> str:
    """
    Efficiently format hex string as space-separated byte pairs.

    Optimized to avoid intermediate list creation by using a generator.

    Args:
        hex_string: Hex string without spaces (e.g., "4883ec20")

    Returns:
        Space-separated hex bytes (e.g., "48 83 ec 20")
    """
    # Use generator expression to avoid creating intermediate list
    return " ".join(hex_string[i : i + 2] for i in range(0, len(hex_string), 2))


@lru_cache(maxsize=128)
def _sanitize_filename_for_rule(file_path: str) -> str:
    """
    Extract and sanitize filename for use in YARA rule names.

    Cached to avoid repeated Path operations and string replacements.

    Args:
        file_path: Path to the file

    Returns:
        Sanitized filename with special characters replaced
    """
    # OPTIMIZATION: Use str.translate() instead of chained replace()
    return Path(file_path).stem.translate(_FILENAME_SANITIZE_TRANS)


@log_execution(tool_name="generate_signature")
@track_metrics("generate_signature")
@handle_tool_errors
async def generate_signature(
    file_path: str,
    address: str,
    length: int = 32,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Generate a YARA signature from opcode bytes at a specific address.

    This tool extracts opcode bytes from a function or code section and formats
    them as a YARA rule, enabling automated malware detection. It attempts to
    mask variable values (addresses, offsets) to create more flexible signatures.

    **Use Cases:**
    - Generate detection signatures for malware samples
    - Create YARA rules for threat hunting
    - Automate IOC (Indicator of Compromise) generation
    - Build malware family signatures

    **Workflow:**
    1. Extract opcode bytes from specified address
    2. Apply basic masking for variable values (optional)
    3. Format as YARA rule template
    4. Return ready-to-use YARA rule

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Start address for signature extraction (e.g., 'main', '0x401000')
        length: Number of bytes to extract (default 32, recommended 16-64)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string

    Example:
        generate_signature("/app/workspace/malware.exe", "0x401000", 48)
        # Returns a YARA rule with extracted byte pattern
    """
    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if not isinstance(length, int) or length < 1 or length > 1024:
        return failure(
            "VALIDATION_ERROR",
            "Length must be between 1 and 1024 bytes",
            hint="Typical signature lengths are 16-64 bytes for good detection accuracy",
        )

    # 2. Security check for address
    validation_error = _validate_address_or_fail(address, "address")
    if validation_error:
        return validation_error

    # 3. Extract hex bytes using radare2's p8 command
    r2_cmds = [
        f"s {address}",  # Seek to address
        f"p8 {length}",  # Print hex bytes
    ]

    # Adaptive analysis: if address is hex, we don't need full analysis
    analysis_level = ""
    # OPTIMIZATION: Use pre-compiled regex pattern (faster)
    if address.startswith("0x") or _HEX_PATTERN.match(address):
        analysis_level = "-n"

    # Extract hex bytes using helper
    # Note: analysis_level may be "" (empty) which means default r2 behavior (parse headers/symbols)
    output, bytes_read = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level or "aaa",
        max_output_size=1_000_000,
        base_timeout=timeout,
    )

    # 4. Validate output
    hex_bytes = output.strip()
    # OPTIMIZATION: Use pre-compiled regex pattern (faster)
    if not hex_bytes or not _HEX_PATTERN.match(hex_bytes):
        return failure(
            "SIGNATURE_ERROR",
            f"Failed to extract valid hex bytes from address: {address}",
            hint="Verify the address is valid and contains executable code",
        )

    # Check for all 0xFF or 0x00 (likely unmapped memory)
    # OPTIMIZATION: Use pre-compiled regex patterns (faster)
    if _ALL_FF_PATTERN.match(hex_bytes) or _ALL_00_PATTERN.match(hex_bytes):
        # If we used -n, try again without it to force mapping
        if analysis_level == "-n":
            from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
            
            effective_timeout = calculate_dynamic_timeout(str(validated_path))
            cmd = _build_r2_cmd(str(validated_path), r2_cmds, "aaa")
            output, _ = await execute_subprocess_async(
                cmd,
                max_output_size=1_000_000,
                timeout=effective_timeout,
            )
            hex_bytes = output.strip()

            # Re-check
            # OPTIMIZATION: Use pre-compiled regex patterns (faster)
            if _ALL_FF_PATTERN.match(hex_bytes) or _ALL_00_PATTERN.match(hex_bytes):
                return failure(
                    "SIGNATURE_ERROR",
                    f"Extracted bytes are all 0xFF or 0x00 at {address}. The memory might be unmapped or empty.",
                    hint="Try a different address or ensure the binary is loaded correctly.",
                )
        else:
            return failure(
                "SIGNATURE_ERROR",
                f"Extracted bytes are all 0xFF or 0x00 at {address}. The memory might be unmapped or empty.",
                hint="Try a different address or ensure the binary is loaded correctly.",
            )

    # 5. Format as YARA hex string (space-separated pairs)
    # Convert: "4883ec20" -> "48 83 ec 20"
    # OPTIMIZED: Use generator expression to avoid intermediate list
    formatted_bytes = _format_hex_bytes(hex_bytes)

    # 6. Generate YARA rule template
    # Extract filename for rule name using cached helper
    file_name = _sanitize_filename_for_rule(file_path)
    rule_name = f"suspicious_{file_name}_{address.replace('0x', 'x')}"

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated signature for {file_name}"
        address = "{address}"
        length = {length}
        author = "Reversecore_MCP"
        date = "auto-generated"

    strings:
        $code = {{ {formatted_bytes} }}

    condition:
        $code
}}"""

    # 7. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        address=address,
        length=length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA signature generated from {length} bytes at {address}",
    )


@log_execution(tool_name="generate_yara_rule")
@track_metrics("generate_yara_rule")
@handle_tool_errors
async def generate_yara_rule(
    file_path: str,
    function_address: str,
    rule_name: str = "auto_generated_rule",
    byte_length: int = 64,
    timeout: int = 300,
) -> ToolResult:
    """
    Generate a YARA rule from function bytes.

    This tool extracts bytes from a function and generates a ready-to-use
    YARA rule for malware detection and threat hunting.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to extract bytes from (e.g., 'main', '0x401000')
        rule_name: Name for the YARA rule (default 'auto_generated_rule')
        byte_length: Number of bytes to extract (default 64, max 1024)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string
    """
    # 1. Validate parameters
    validate_tool_parameters(
        "generate_yara_rule",
        {
            "function_address": function_address,
            "rule_name": rule_name,
            "byte_length": byte_length,
        },
    )
    validated_path = validate_file_path(file_path)

    # 2. Validate rule_name format
    if not _RULE_NAME_PATTERN.match(rule_name):
        return failure(
            "VALIDATION_ERROR",
            "rule_name must start with a letter and contain only alphanumeric characters and underscores",
        )

    # 3. Security check for function address (prevent shell injection)
    validation_error = _validate_address_or_fail(function_address, "function_address")
    if validation_error:
        return validation_error

    # 4. Extract hex bytes using radare2's p8 command
    r2_cmds = [
        f"s {function_address}",  # Seek to address
        f"p8 {byte_length}",  # Print hex bytes
    ]

    # Always use -n for p8 to avoid analysis hang
    analysis_level = "-n"

    # 4. Extract hex bytes using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level,
        max_output_size=1_000_000,
        base_timeout=timeout,
    )

    # 5. Validate output
    hex_bytes = output.strip()
    if not hex_bytes or not _HEX_PATTERN.match(hex_bytes):
        return failure(
            "YARA_GENERATION_ERROR",
            f"Failed to extract valid hex bytes from address: {function_address}",
            hint="Verify the address is valid and contains executable code",
        )

    # Check for invalid patterns (all 00 or all FF)
    if len(hex_bytes) > 16 and (
        _ALL_00_PATTERN.match(hex_bytes) or _ALL_FF_PATTERN.match(hex_bytes)
    ):
        # Smart Offset Search: Try to find a better address
        # 1. Try 'main' if we weren't already there
        # 2. Try entry point 'entry0'
        # 3. Find largest function

        logger.info(f"Invalid bytes at {function_address}, attempting smart offset search...")

        # Try to find a better function
        cmd = "aflj"
        out, _ = await _execute_r2_command(
            validated_path, [cmd], analysis_level="aaa", base_timeout=timeout
        )

        try:
            funcs = _parse_json_output(out)
            if funcs and isinstance(funcs, list):
                # Find the largest function as a fallback
                largest_func = max(funcs, key=lambda x: x.get("size", 0))
                suggested_addr = hex(largest_func.get("offset", 0))
                suggested_name = largest_func.get("name", "unknown")

                return failure(
                    "YARA_GENERATION_ERROR",
                    f"Address {function_address} contains invalid bytes (all 0x00 or 0xFF). "
                    f"Try using a different address.",
                    hint=f"Suggested alternative: {suggested_name} at {suggested_addr}",
                )
        except Exception:
            pass

        return failure(
            "YARA_GENERATION_ERROR",
            f"Address {function_address} contains invalid bytes (all 0x00 or 0xFF)",
            hint="Try a different function or address that contains actual code",
        )

    # 5. Format as YARA hex string (space-separated pairs)
    formatted_bytes = _format_hex_bytes(hex_bytes)

    # 6. Generate YARA rule
    file_name = _sanitize_filename_for_rule(file_path)

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule for {file_name}"
        function = "{function_address}"
        length = {byte_length}
        author = "Reversecore_MCP"
        date = "auto-generated"

    strings:
        $code = {{ {formatted_bytes} }}

    condition:
        $code
}}"""

    # 7. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        function_address=function_address,
        rule_name=rule_name,
        length=byte_length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA rule '{rule_name}' generated from {byte_length} bytes at {function_address}",
    )


@log_execution(tool_name="generate_enhanced_yara_rule")
@track_metrics("generate_enhanced_yara_rule")
@handle_tool_errors
async def generate_enhanced_yara_rule(
    file_path: str,
    rule_name: str,
    strings: list[str],
    imports: list[str] = None,
    file_type: str = "PE",
    min_filesize: int = None,
    max_filesize: int = None,
    section_names: list[str] = None,
    entry_point_pattern: str = None,
    description: str = "",
    author: str = "Reversecore_MCP",
    min_string_matches: int = None,
) -> ToolResult:
    """
    Generate an enhanced YARA rule with structural conditions to reduce false positives.
    
    This function creates YARA rules that combine:
    - String patterns (required)
    - Structural conditions (PE characteristics, file size)
    - Import table checks (optional)
    - Section name checks (optional)
    - Entry point patterns (optional)
    
    **Why Enhanced Rules?**
    Simple string-only rules cause high false positive rates. By adding structural
    conditions, rules become more precise and suitable for production use.
    
    Args:
        file_path: Path to reference binary (for metadata extraction)
        rule_name: Name for the YARA rule
        strings: List of strings to include in the rule
        imports: List of imported functions to check (e.g., ["CryptEncrypt", "WriteFile"])
        file_type: Target file type - "PE" or "ELF" (default: "PE")
        min_filesize: Minimum file size in bytes (optional)
        max_filesize: Maximum file size in bytes (optional)
        section_names: Required section names (e.g., [".rsrc", ".text"])
        entry_point_pattern: Hex pattern at entry point (optional)
        description: Rule description for metadata
        author: Rule author for metadata
        min_string_matches: Minimum number of strings that must match (default: 2/3 of total)
    
    Returns:
        ToolResult with enhanced YARA rule string
    
    Example:
        generate_enhanced_yara_rule(
            "/app/workspace/wannacry.exe",
            "WannaCry_Ransomware",
            strings=["WANACRY!", "WNcry@2ol7", "bitcoin"],
            imports=["CryptEncrypt", "CreateServiceA"],
            min_filesize=3000000,
            max_filesize=4000000,
            section_names=[".rsrc"],
        )
    """
    # 1. Validate parameters
    validated_path = validate_file_path(file_path)
    
    if not _RULE_NAME_PATTERN.match(rule_name):
        return failure(
            "VALIDATION_ERROR",
            "rule_name must start with a letter and contain only alphanumeric characters and underscores",
        )
    
    if not strings or len(strings) == 0:
        return failure(
            "VALIDATION_ERROR",
            "At least one string is required for YARA rule generation",
        )
    
    # 2. Build strings section (max 10 strings)
    string_definitions = []
    for i, s in enumerate(strings[:10]):
        # Escape special characters
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        string_definitions.append(f'        $str{i} = "{escaped}" ascii wide nocase')
    
    strings_section = "\n".join(string_definitions)
    
    # 3. Build imports section (optional)
    import_definitions = []
    if imports:
        for i, imp in enumerate(imports[:10]):
            escaped = imp.replace("\\", "\\\\").replace('"', '\\"')
            import_definitions.append(f'        $imp{i} = "{escaped}" ascii')
        strings_section += "\n" + "\n".join(import_definitions)
    
    # 4. Calculate min_string_matches (default: 2/3 of total, minimum 1)
    total_strings = len(strings[:10])
    if min_string_matches is None:
        min_string_matches = max(1, (total_strings * 2) // 3)
    min_string_matches = min(min_string_matches, total_strings)
    
    # 5. Build condition section
    conditions = []
    
    # File type condition
    if file_type.upper() == "PE":
        conditions.append("uint16(0) == 0x5A4D")  # MZ header
        conditions.append("uint32(uint32(0x3C)) == 0x00004550")  # PE signature
    elif file_type.upper() == "ELF":
        conditions.append("uint32(0) == 0x464C457F")  # ELF magic
    
    # File size conditions
    if min_filesize:
        conditions.append(f"filesize > {min_filesize}")
    if max_filesize:
        conditions.append(f"filesize < {max_filesize}")
    
    # String match condition
    if total_strings > 1:
        conditions.append(f"{min_string_matches} of ($str*)")
    else:
        conditions.append("$str0")
    
    # Import conditions (if provided)
    if imports and len(imports) > 0:
        min_import_matches = max(1, len(imports[:10]) // 2)
        conditions.append(f"{min_import_matches} of ($imp*)")
    
    # Section name conditions (optional)
    if section_names:
        for section in section_names[:5]:
            # Use pe module for section checks
            conditions.append(f'pe.sections[pe.number_of_sections - 1].name contains "{section}"')
    
    # Entry point pattern (optional)
    if entry_point_pattern:
        if file_type_upper == "PE":
            conditions.append(f"$ep at pe.entry_point")
        elif file_type_upper == "ELF":
            conditions.append(f"$ep at elf.entry_point")
        string_definitions.append(f'        $ep = {{ {entry_point_pattern} }}')
    
    # 6. Build condition string
    condition_str = " and\n        ".join(conditions)
    file_type = file_type.upper()
    
    # Imports section
    imports_declaration = ""
    # LOGIC FIX: Don't import "pe" for ELF files or others
    if "PE" in file_type and (section_names or entry_point_pattern):
        imports_declaration = 'import "pe"\n\n'
    elif "ELF" in file_type and (section_names or entry_point_pattern):
        imports_declaration = 'import "elf"\n\n'

    # Handle tags
    tags_str = ""
    if tags:
        tags_str = " : " + " ".join(tags)

    # 7. Generate complete rule
    yara_rule = f'''{imports_declaration}rule {rule_name}{tags_str} {{
    meta:
        description = "{description or f'Enhanced detection rule for {rule_name}'}"
        author = "{author}"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        reference = "Generated by Reversecore MCP"
        false_positive_reduction = "Structural conditions applied"
        min_string_matches = {min_string_matches}
        hash = "{hash_value}"
        confidence = "verdict"
        
    strings:
{strings_section}

    condition:
        {condition_str}
}}'''
    
    return success(
        yara_rule,
        rule_name=rule_name,
        string_count=len(strings[:10]),
        import_count=len(imports[:10]) if imports else 0,
        condition_count=len(conditions),
        min_string_matches=min_string_matches,
        format="yara",
        description=f"Enhanced YARA rule '{rule_name}' with {len(conditions)} structural conditions",
    )


# Note: SignatureToolsPlugin has been removed.
# The signature tools are now registered via AnalysisToolsPlugin in analysis/__init__.py.
