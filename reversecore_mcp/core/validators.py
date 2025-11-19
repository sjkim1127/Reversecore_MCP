"""
Input validators for tool-specific parameters.
"""

from typing import Dict, Any
from reversecore_mcp.core.exceptions import ValidationError


def validate_tool_parameters(tool_name: str, params: Dict[str, Any]) -> None:
    """
    Validate tool-specific parameters.
    
    Args:
        tool_name: Name of the tool
        params: Parameters to validate
        
    Raises:
        ValidationError: If parameters are invalid
    """
    validators = {
        "run_strings": _validate_strings_params,
        "run_radare2": _validate_radare2_params,
        "disassemble_with_capstone": _validate_capstone_params,
        "run_yara": _validate_yara_params,
        "generate_function_graph": _validate_cfg_params,
        "emulate_machine_code": _validate_emulation_params,
        "get_pseudo_code": _validate_pseudo_code_params,
        "generate_signature": _validate_signature_params,
        "extract_rtti_info": _validate_rtti_params,
        "smart_decompile": _validate_decompile_params,
        "generate_yara_rule": _validate_yara_generation_params,
        "diff_binaries": _validate_diff_binaries_params,
        "match_libraries": _validate_match_libraries_params,
    }
    
    if tool_name in validators:
        validators[tool_name](params)


def _validate_strings_params(params: Dict[str, Any]) -> None:
    """Validate run_strings parameters."""
    min_length = params.get("min_length", 4)
    if not isinstance(min_length, int) or min_length < 1:
        raise ValidationError("min_length must be a positive integer")
    
    max_output_size = params.get("max_output_size", 10_000_000)
    if not isinstance(max_output_size, int) or max_output_size < 1:
        raise ValidationError("max_output_size must be a positive integer")


def _validate_radare2_params(params: Dict[str, Any]) -> None:
    """Validate run_radare2 parameters."""
    if "r2_command" not in params:
        raise ValidationError("r2_command is required")
    
    if not isinstance(params["r2_command"], str):
        raise ValidationError("r2_command must be a string")


def _validate_capstone_params(params: Dict[str, Any]) -> None:
    """Validate disassemble_with_capstone parameters."""
    offset = params.get("offset", 0)
    if not isinstance(offset, int) or offset < 0:
        raise ValidationError("offset must be a non-negative integer")
    
    size = params.get("size", 1024)
    if not isinstance(size, int) or size < 1:
        raise ValidationError("size must be a positive integer")
    
    # Note: Architecture validation is done by the tool function itself
    # to provide more detailed error messages


def _validate_yara_params(params: Dict[str, Any]) -> None:
    """Validate run_yara parameters."""
    if "rule_file" not in params:
        raise ValidationError("rule_file is required")
    
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")


def _validate_cfg_params(params: Dict[str, Any]) -> None:
    """Validate generate_function_graph parameters."""
    if "function_address" in params:
        if not isinstance(params["function_address"], str):
            raise ValidationError("function_address must be a string")
    
    output_format = params.get("format", "mermaid")
    allowed_formats = ["json", "mermaid", "dot"]
    if output_format not in allowed_formats:
        raise ValidationError(
            f"Invalid format '{output_format}'. Allowed: {', '.join(allowed_formats)}"
        )


def _validate_emulation_params(params: Dict[str, Any]) -> None:
    """Validate emulate_machine_code parameters."""
    if "start_address" in params:
        if not isinstance(params["start_address"], str):
            raise ValidationError("start_address must be a string")
    
    instructions = params.get("instructions", 50)
    if not isinstance(instructions, int):
        raise ValidationError("instructions must be an integer")
    
    # Critical: Prevent infinite loops and CPU exhaustion
    if instructions < 1:
        raise ValidationError("instructions must be at least 1")
    
    if instructions > 1000:
        raise ValidationError(
            "instructions cannot exceed 1000 (safety limit to prevent CPU exhaustion)"
        )


def _validate_pseudo_code_params(params: Dict[str, Any]) -> None:
    """Validate get_pseudo_code parameters."""
    if "address" in params:
        if not isinstance(params["address"], str):
            raise ValidationError("address must be a string")
    
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")


def _validate_signature_params(params: Dict[str, Any]) -> None:
    """Validate generate_signature parameters."""
    if "address" not in params:
        raise ValidationError("address is required")
    
    if not isinstance(params["address"], str):
        raise ValidationError("address must be a string")
    
    length = params.get("length", 32)
    if not isinstance(length, int) or length < 1 or length > 1024:
        raise ValidationError("length must be between 1 and 1024 bytes")
    
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")


def _validate_rtti_params(params: Dict[str, Any]) -> None:
    """Validate extract_rtti_info parameters."""
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")


def _validate_decompile_params(params: Dict[str, Any]) -> None:
    """Validate smart_decompile parameters."""
    if "function_address" in params:
        if not isinstance(params["function_address"], str):
            raise ValidationError("function_address must be a string")


def _validate_yara_generation_params(params: Dict[str, Any]) -> None:
    """Validate generate_yara_rule parameters."""
    if "function_address" in params:
        if not isinstance(params["function_address"], str):
            raise ValidationError("function_address must be a string")
    
    if "byte_length" in params:
        byte_length = params["byte_length"]
        if not isinstance(byte_length, int):
            raise ValidationError("byte_length must be a positive integer")
        if byte_length < 1:
            raise ValidationError("byte_length must be a positive integer")
        if byte_length > 1024:
            raise ValidationError("byte_length cannot exceed 1024")
    
    if "rule_name" in params:
        if not isinstance(params["rule_name"], str):
            raise ValidationError("rule_name must be a string")


def _validate_diff_binaries_params(params: Dict[str, Any]) -> None:
    """Validate diff_binaries parameters."""
    if "function_name" in params and params["function_name"] is not None:
        if not isinstance(params["function_name"], str):
            raise ValidationError("function_name must be a string")
    
    max_output_size = params.get("max_output_size", 10_000_000)
    if not isinstance(max_output_size, int) or max_output_size < 1:
        raise ValidationError("max_output_size must be a positive integer")
    
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")


def _validate_match_libraries_params(params: Dict[str, Any]) -> None:
    """Validate match_libraries parameters."""
    max_output_size = params.get("max_output_size", 10_000_000)
    if not isinstance(max_output_size, int) or max_output_size < 1:
        raise ValidationError("max_output_size must be a positive integer")
    
    timeout = params.get("timeout", 300)
    if not isinstance(timeout, int) or timeout < 1:
        raise ValidationError("timeout must be a positive integer")
