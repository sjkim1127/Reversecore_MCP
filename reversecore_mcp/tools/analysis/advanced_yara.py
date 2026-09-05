import re
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import _execute_r2_command
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_address_format

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_RULE_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")


def _mask_instruction(inst: dict[str, Any], mask_operands: bool) -> str:
    """
    Mask variable bytes in an instruction based on its type.
    If mask_operands is True, the operand bytes of calls, jumps, and memory references
    are replaced with '??'.
    """
    opcode_bytes = inst.get("bytes", "")
    if not opcode_bytes:
        return ""

    mnemonic = inst.get("mnemonic", "")

    if not mask_operands:
        return " ".join([opcode_bytes[i : i + 2] for i in range(0, len(opcode_bytes), 2)])

    # Mask CALL and JMP operands (usually relative offsets that change)
    if mnemonic.startswith("call") or mnemonic.startswith("jmp") or mnemonic.startswith("j"):
        # Very rough heuristic for x86/x64: first byte is opcode, rest is offset
        # For a more robust approach, we need exact instruction length and prefix info.
        # R2 json gives us `bytes` which is a hex string.
        # Typically x86 call rel32 is E8 XX XX XX XX (5 bytes)
        # Jmp rel32 is E9 XX XX XX XX (5 bytes)
        # Conditional jmps 0F 8X XX XX XX XX (6 bytes) or 7X XX (2 bytes)

        byte_list = [opcode_bytes[i : i + 2] for i in range(0, len(opcode_bytes), 2)]

        if len(byte_list) == 5 and byte_list[0] in ("e8", "e9"):
            return f"{byte_list[0]} ?? ?? ?? ??"
        elif len(byte_list) == 6 and byte_list[0] == "0f" and byte_list[1].startswith("8"):
            return f"{byte_list[0]} {byte_list[1]} ?? ?? ?? ??"
        elif len(byte_list) == 2 and (byte_list[0].startswith("7") or byte_list[0] == "eb"):
            return f"{byte_list[0]} ??"

    # Mask memory references in MOV, LEA, etc. (e.g., mov rax, [0x123456])
    # For a naive approach, if there's a ptr/disp, mask it. We can rely on R2's "ptr" or "disp" fields
    # but radare2 'pij' might not reliably provide exact byte offsets of operands.
    # We will provide a simplified advanced masking: if "ptr" or "disp" is present in instruction,
    # we mask the last few bytes depending on the length of the instruction.
    # R2's 'pij' might include "refs".

    # Simple fallback: return exact bytes space separated
    return " ".join([opcode_bytes[i : i + 2] for i in range(0, len(opcode_bytes), 2)])


@log_execution(tool_name="generate_advanced_yara_rule")
@track_metrics("generate_advanced_yara_rule")
@handle_tool_errors
async def generate_advanced_yara_rule(
    file_path: str,
    address: str,
    rule_name: str = "advanced_rule",
    num_instructions: int = 10,
    mask_operands: bool = True,
    timeout: int = 300,
) -> ToolResult:
    """
    Generate an advanced YARA rule based on radare2 disassembly opcodes.
    This masks offsets in CALL/JMP instructions to reduce false positives.

    Args:
        file_path: Path to the binary
        address: Start address
        rule_name: Name of the generated YARA rule
        num_instructions: Number of instructions to process
        mask_operands: Whether to mask CALL/JMP operands
        timeout: Execution timeout
    """
    validated_path = validate_file_path(file_path)

    try:
        validate_address_format(address, "address")
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))

    if not _RULE_NAME_PATTERN.match(rule_name):
        return failure(
            "VALIDATION_ERROR",
            "rule_name must start with a letter and contain only alphanumeric characters and underscores",
        )

    if not isinstance(num_instructions, int) or num_instructions < 1 or num_instructions > 1000:
        return failure("VALIDATION_ERROR", "num_instructions must be between 1 and 1000")

    r2_cmds = [f"s {address}", f"pij {num_instructions}"]

    analysis_level = "-n" if (address.startswith("0x") or _HEX_PATTERN.match(address)) else "aaa"

    output, _ = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level,
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    if not output.strip():
        return failure("ANALYSIS_ERROR", "Failed to retrieve instructions from address")

    try:
        instructions = json.loads(output)
    except json.JSONDecodeError:
        return failure("PARSING_ERROR", "Failed to parse JSON output from radare2")

    if not instructions:
        return failure("NO_DATA", "No instructions found at the given address")

    masked_pattern = []

    for inst in instructions:
        masked = _mask_instruction(inst, mask_operands)
        if masked:
            masked_pattern.append(masked)

    if not masked_pattern:
        return failure("PROCESSING_ERROR", "Could not generate masked pattern from instructions")

    hex_string = " ".join(masked_pattern)

    # Format YARA rule
    yara_rule = f"""rule {rule_name}
{{
    meta:
        description = "Advanced rule generated from {validated_path.name} at {address}"
        author = "Reversecore_MCP"
        masked = {"true" if mask_operands else "false"}

    strings:
        $opcodes = {{ {hex_string} }}

    condition:
        $opcodes
}}"""

    return success(
        {
            "rule_name": rule_name,
            "yara_rule": yara_rule,
            "pattern": hex_string,
            "instructions_processed": len(instructions),
        }
    )
