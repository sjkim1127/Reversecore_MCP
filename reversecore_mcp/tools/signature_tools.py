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
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Import helper functions from r2_analysis
from reversecore_mcp.tools.r2_analysis import _execute_r2_command, _build_r2_cmd, _parse_json_output

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

logger = get_logger(__name__)

# OPTIMIZATION: Character translation table for filename sanitization
_FILENAME_SANITIZE_TRANS = str.maketrans({"-": "_", ".": "_"})


def _validate_address_or_fail(address: str, param_name: str = "address"):
    """
    Validate address format and return failure ToolResult if invalid.

    Args:
        address: Address string to validate
        param_name: Parameter name for error messages

    Returns:
        None if validation passes, or ToolResult failure if invalid
    """
    from reversecore_mcp.core.validators import validate_address_format
    from reversecore_mcp.core.exceptions import ValidationError

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
    if address.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", address):
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
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "SIGNATURE_ERROR",
            f"Failed to extract valid hex bytes from address: {address}",
            hint="Verify the address is valid and contains executable code",
        )

    # Check for all 0xFF or 0x00 (likely unmapped memory)
    if re.match(r"^(ff)+$", hex_bytes, re.IGNORECASE) or re.match(r"^(00)+$", hex_bytes):
        # If we used -n, try again without it to force mapping
        if analysis_level == "-n":
            from reversecore_mcp.tools.r2_analysis import _calculate_dynamic_timeout

            effective_timeout = _calculate_dynamic_timeout(str(validated_path), timeout)
            cmd = _build_r2_cmd(str(validated_path), r2_cmds, "aaa")
            output, _ = await execute_subprocess_async(
                cmd,
                max_output_size=1_000_000,
                timeout=effective_timeout,
            )
            hex_bytes = output.strip()

            # Re-check
            if re.match(r"^(ff)+$", hex_bytes, re.IGNORECASE) or re.match(r"^(00)+$", hex_bytes):
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
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", rule_name):
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
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "YARA_GENERATION_ERROR",
            f"Failed to extract valid hex bytes from address: {function_address}",
            hint="Verify the address is valid and contains executable code",
        )

    # Check for invalid patterns (all 00 or all FF)
    if len(hex_bytes) > 16 and (re.match(r"^(00)+$", hex_bytes) or re.match(r"^(ff)+$", hex_bytes, re.IGNORECASE)):
        # Smart Offset Search: Try to find a better address
        # 1. Try 'main' if we weren't already there
        # 2. Try entry point 'entry0'
        # 3. Find largest function

        logger.info(f"Invalid bytes at {function_address}, attempting smart offset search...")

        # Try to find a better function
        cmd = "aflj"
        out, _ = await _execute_r2_command(validated_path, [cmd], analysis_level="aaa", base_timeout=timeout)

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
