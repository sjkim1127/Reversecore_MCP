"""Capstone disassembly tools for analyzing binary code."""

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters


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
            CsError,
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

    try:
        disassembler = Cs(arch_map[arch], mode_map[arch][mode])
        instructions = [
            f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}"
            for instruction in disassembler.disasm(code, offset)
        ]
    except CsError as exc:
        return failure("CAPSTONE_ERROR", f"Capstone failed: {exc}")

    if not instructions:
        return success("No instructions disassembled.", instruction_count=0)

    return success("\n".join(instructions), instruction_count=len(instructions))
