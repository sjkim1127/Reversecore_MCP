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


try:
    import capstone
    from capstone import x86

    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover
    capstone = None  # type: ignore[assignment]
    x86 = None  # type: ignore[assignment]
    _HAS_CAPSTONE = False

_cs_x86_64: Any = None
_cs_x86_32: Any = None


def _get_cs_x86_64() -> Any:
    global _cs_x86_64
    if _cs_x86_64 is None and _HAS_CAPSTONE:
        _cs_x86_64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        _cs_x86_64.detail = True
    return _cs_x86_64


def _get_cs_x86_32() -> Any:
    global _cs_x86_32
    if _cs_x86_32 is None and _HAS_CAPSTONE:
        _cs_x86_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        _cs_x86_32.detail = True
    return _cs_x86_32


def _mask_instruction(inst: dict[str, Any], mask_operands: bool) -> str:
    """
    Mask variable bytes in an instruction based on its type.
    If mask_operands is True, the operand bytes of calls, jumps, and relocatable
    memory references are replaced with '??'.
    """
    opcode_bytes = inst.get("bytes", "")
    if not opcode_bytes:
        return ""

    try:
        raw_bytes = bytes.fromhex(opcode_bytes)
    except ValueError:
        return ""

    byte_list = [opcode_bytes[i : i + 2] for i in range(0, len(opcode_bytes), 2)]
    if not byte_list:
        return ""

    if not mask_operands:
        return " ".join(byte_list)

    mnemonic = inst.get("mnemonic", "")

    # Try precise decoding with Capstone if available
    masked_via_decoder = False
    if _HAS_CAPSTONE:
        for cs in (_get_cs_x86_64(), _get_cs_x86_32()):
            if cs is None:
                continue
            try:
                insns = list(cs.disasm(raw_bytes, 0))
            except Exception:
                insns = []
            if insns and insns[0].size == len(byte_list):
                insn = insns[0]
                # 1. Branch / call targets
                if insn.mnemonic.startswith(("call", "jmp", "j")) and insn.imm_size > 0:
                    for i in range(insn.imm_offset, insn.imm_offset + insn.imm_size):
                        if 0 <= i < len(byte_list):
                            byte_list[i] = "??"
                            masked_via_decoder = True

                # 2. Memory operands (RIP-relative or absolute addresses)
                for op in insn.operands:
                    if op.type == x86.X86_OP_MEM:
                        # RIP-relative or absolute (base=0, no base register)
                        if op.mem.base == x86.X86_REG_RIP or op.mem.base == 0:
                            if insn.disp_size > 0:
                                for i in range(insn.disp_offset, insn.disp_offset + insn.disp_size):
                                    if 0 <= i < len(byte_list):
                                        byte_list[i] = "??"
                                        masked_via_decoder = True
                    elif (
                        op.type == x86.X86_OP_IMM
                        and insn.imm_size == 8
                        and insn.mnemonic.startswith("mov")
                    ):
                        # 64-bit absolute address immediate in mov
                        for i in range(insn.imm_offset, insn.imm_offset + insn.imm_size):
                            if 0 <= i < len(byte_list):
                                byte_list[i] = "??"
                                masked_via_decoder = True
                break

    # Fallback to heuristic branch masking if decoder did not mask
    if not masked_via_decoder:
        if mnemonic.startswith("call") or mnemonic.startswith("jmp") or mnemonic.startswith("j"):
            if len(byte_list) == 5 and byte_list[0] in ("e8", "e9"):
                return f"{byte_list[0]} ?? ?? ?? ??"
            elif len(byte_list) == 6 and byte_list[0] == "0f" and byte_list[1].startswith("8"):
                return f"{byte_list[0]} {byte_list[1]} ?? ?? ?? ??"
            elif len(byte_list) == 2 and (byte_list[0].startswith("7") or byte_list[0] == "eb"):
                return f"{byte_list[0]} ??"

    return " ".join(byte_list)


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
    has_normalized_operands = any("??" in piece for piece in masked_pattern)
    actual_masked = bool(mask_operands and has_normalized_operands)

    # Format YARA rule
    yara_rule = f"""rule {rule_name}
{{
    meta:
        description = "Advanced rule generated from {validated_path.name} at {address}"
        author = "Reversecore_MCP"
        masked = {"true" if actual_masked else "false"}

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
            "masked": actual_masked,
        }
    )
