"""Assembler tool using Keystone engine for compiling assembly code into machine bytes."""

try:
    from keystone import (
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_MIPS,
        KS_ARCH_PPC,
        KS_ARCH_SPARC,
        KS_ARCH_SYSTEMZ,
        KS_ARCH_X86,
        KS_MODE_16,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_BIG_ENDIAN,
        KS_MODE_LITTLE_ENDIAN,
        KS_MODE_MIPS32,
        KS_MODE_MIPS64,
        KS_MODE_THUMB,
        KS_MODE_V8,
        Ks,
        KsError,
    )
except ImportError:
    Ks = None
    KsError = Exception
    KS_ARCH_ARM = 1
    KS_ARCH_ARM64 = 2
    KS_ARCH_MIPS = 3
    KS_ARCH_PPC = 5
    KS_ARCH_SPARC = 6
    KS_ARCH_SYSTEMZ = 7
    KS_ARCH_X86 = 4
    KS_MODE_16 = 2
    KS_MODE_32 = 4
    KS_MODE_64 = 8
    KS_MODE_ARM = 1
    KS_MODE_BIG_ENDIAN = 1073741824
    KS_MODE_LITTLE_ENDIAN = 0
    KS_MODE_MIPS32 = 4
    KS_MODE_MIPS64 = 8
    KS_MODE_THUMB = 16
    KS_MODE_V8 = 64

try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_MIPS,
        CS_ARCH_PPC,
        CS_ARCH_SPARC,
        CS_ARCH_X86,
        CS_MODE_16,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_BIG_ENDIAN,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_MIPS32,
        CS_MODE_MIPS64,
        CS_MODE_THUMB,
        Cs,
        CsError,
    )

    # CS_ARCH_ARM64 was renamed to CS_ARCH_AARCH64 in Capstone 6
    try:
        from capstone import CS_ARCH_ARM64
    except ImportError:
        from capstone import CS_ARCH_AARCH64 as CS_ARCH_ARM64

    # CS_ARCH_SYSZ was renamed to CS_ARCH_SYSTEMZ in Capstone 6
    try:
        from capstone import CS_ARCH_SYSZ
    except ImportError:
        from capstone import CS_ARCH_SYSTEMZ as CS_ARCH_SYSZ
except ImportError:
    Cs = None
    CsError = Exception
    CS_ARCH_ARM = 1
    CS_ARCH_ARM64 = 2
    CS_ARCH_MIPS = 3
    CS_ARCH_PPC = 5
    CS_ARCH_SPARC = 6
    CS_ARCH_SYSZ = 7
    CS_ARCH_X86 = 4
    CS_MODE_16 = 2
    CS_MODE_32 = 4
    CS_MODE_64 = 8
    CS_MODE_ARM = 0
    CS_MODE_BIG_ENDIAN = 2147483648
    CS_MODE_LITTLE_ENDIAN = 0
    CS_MODE_MIPS32 = 4
    CS_MODE_MIPS64 = 8
    CS_MODE_THUMB = 16

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ToolExecutionError, ValidationError
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success


def get_keystone_params(arch_str: str, mode_str: str) -> tuple[int, int]:
    """Map string representation of arch and mode to Keystone constants.

    Args:
        arch_str: Target architecture name.
        mode_str: Operating mode/width.

    Returns:
        Tuple of (KS_ARCH_*, KS_MODE_*)

    Raises:
        ValidationError: If architecture or mode is invalid.
    """
    arch_clean = arch_str.lower().strip()
    mode_clean = mode_str.lower().strip()

    if arch_clean == "x86":
        if mode_clean in ("16", "v16"):
            return KS_ARCH_X86, KS_MODE_16
        elif mode_clean in ("32", "v32"):
            return KS_ARCH_X86, KS_MODE_32
        elif mode_clean in ("64", "v64"):
            return KS_ARCH_X86, KS_MODE_64
        else:
            raise ValidationError(
                f"Invalid mode '{mode_str}' for x86. Supported: 16, 32, 64",
                details={"arch": arch_str, "mode": mode_str},
            )

    elif arch_clean == "arm":
        if mode_clean == "arm":
            return KS_ARCH_ARM, KS_MODE_ARM
        elif mode_clean == "thumb":
            return KS_ARCH_ARM, KS_MODE_THUMB
        elif mode_clean == "v8":
            return KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8
        else:
            raise ValidationError(
                f"Invalid mode '{mode_str}' for arm. Supported: arm, thumb, v8",
                details={"arch": arch_str, "mode": mode_str},
            )

    elif arch_clean == "arm64":
        ks_mode = KS_MODE_LITTLE_ENDIAN
        if "big" in mode_clean or "be" in mode_clean:
            ks_mode = KS_MODE_BIG_ENDIAN
        return KS_ARCH_ARM64, ks_mode

    elif arch_clean == "mips":
        ks_mode = KS_MODE_MIPS32
        if "64" in mode_clean:
            ks_mode = KS_MODE_MIPS64
        else:
            ks_mode = KS_MODE_MIPS32

        if "big" in mode_clean or "be" in mode_clean:
            ks_mode += KS_MODE_BIG_ENDIAN
        else:
            ks_mode += KS_MODE_LITTLE_ENDIAN
        return KS_ARCH_MIPS, ks_mode

    elif arch_clean == "sparc":
        ks_mode = KS_MODE_32
        if "64" in mode_clean:
            ks_mode = KS_MODE_64
        if "big" in mode_clean or "be" in mode_clean:
            ks_mode += KS_MODE_BIG_ENDIAN
        return KS_ARCH_SPARC, ks_mode

    elif arch_clean == "ppc":
        ks_mode = KS_MODE_64
        if "32" in mode_clean:
            ks_mode = KS_MODE_32
        if "big" in mode_clean or "be" in mode_clean:
            ks_mode += KS_MODE_BIG_ENDIAN
        return KS_ARCH_PPC, ks_mode

    elif arch_clean == "systemz":
        return KS_ARCH_SYSTEMZ, KS_MODE_32

    else:
        raise ValidationError(
            f"Unsupported architecture: '{arch_str}'. Supported: x86, arm, arm64, mips, sparc, ppc, systemz",
            details={"arch": arch_str},
        )


def get_capstone_params(arch_str: str, mode_str: str) -> tuple[int | None, int]:
    """Map string representation of arch and mode to Capstone constants.

    Args:
        arch_str: Target architecture name.
        mode_str: Operating mode/width.

    Returns:
        Tuple of (CS_ARCH_*, CS_MODE_*) or (None, 0) if unsupported.
    """
    arch_clean = arch_str.lower().strip()
    mode_clean = mode_str.lower().strip()

    if arch_clean == "x86":
        if mode_clean in ("16", "v16"):
            return CS_ARCH_X86, CS_MODE_16
        elif mode_clean in ("32", "v32"):
            return CS_ARCH_X86, CS_MODE_32
        elif mode_clean in ("64", "v64"):
            return CS_ARCH_X86, CS_MODE_64

    elif arch_clean == "arm":
        if mode_clean == "thumb":
            return CS_ARCH_ARM, CS_MODE_THUMB
        elif mode_clean == "arm":
            return CS_ARCH_ARM, CS_MODE_ARM

    elif arch_clean == "arm64":
        cs_mode = CS_MODE_ARM
        if "big" in mode_clean or "be" in mode_clean:
            cs_mode = CS_MODE_BIG_ENDIAN
        return CS_ARCH_ARM64, cs_mode

    elif arch_clean == "mips":
        cs_mode = CS_MODE_MIPS32
        if "64" in mode_clean:
            cs_mode = CS_MODE_MIPS64
        if "big" in mode_clean or "be" in mode_clean:
            cs_mode += CS_MODE_BIG_ENDIAN
        else:
            cs_mode += CS_MODE_LITTLE_ENDIAN
        return CS_ARCH_MIPS, cs_mode

    elif arch_clean == "sparc":
        cs_mode = CS_MODE_32
        if "64" in mode_clean:
            cs_mode = CS_MODE_64
        if "big" in mode_clean or "be" in mode_clean:
            cs_mode += CS_MODE_BIG_ENDIAN
        return CS_ARCH_SPARC, cs_mode

    elif arch_clean == "ppc":
        cs_mode = CS_MODE_64
        if "32" in mode_clean:
            cs_mode = CS_MODE_32
        if "big" in mode_clean or "be" in mode_clean:
            cs_mode += CS_MODE_BIG_ENDIAN
        return CS_ARCH_PPC, cs_mode

    elif arch_clean == "systemz":
        return CS_ARCH_SYSZ, CS_MODE_32

    return None, 0


@log_execution(tool_name="assemble_instructions")
@track_metrics("assemble_instructions")
@handle_tool_errors
async def assemble_instructions(
    assembly_code: str,
    arch: str = "x86",
    mode: str = "64",
    base_address: str = "0x0",
) -> ToolResult:
    """Assemble assembly instruction strings into raw machine byte values using Keystone.

    Args:
        assembly_code: The assembly instruction(s) to compile (separated by newlines or semicolons).
        arch: Target architecture (e.g., 'x86', 'arm', 'arm64', 'mips', 'sparc', 'ppc', 'systemz').
        mode: Target mode/width (e.g., '16', '32', '64' for x86; 'arm', 'thumb' for arm).
        base_address: Base address of instructions, useful for resolving relative offsets (hex or decimal string).

    Returns:
        ToolResult with the compiled hexadecimal bytes, integer byte list, instruction count,
        and Capstone-verified disassembly checking if available.

    Raises:
        ValidationError: If input parameters or assembly code syntax is invalid.
        ToolExecutionError: If Keystone compilation fails.

    Example:
        >>> result = await assemble_instructions("nop; push eax; pop ebx", arch="x86", mode="32")
        >>> print(result.status)
        'success'

    Use this when:
        - You need to assemble assembly instruction strings (like nop, jmp, or register modifications) into raw byte values,
          particularly when writing custom binary patches, crafting shellcode, or vaccine patches.

    NOT USE WHEN:
        - Do NOT use this when you need to perform deep file-based analysis or when you want to disassemble existing binaries.
          For disassembling files, prefer Radare2 or Ghidra tools.

    SEE ALSO:
        - `Ghidra_simulate_patch` for simulating patch application within Ghidra.
        - `Radare2_write_bytes` for writing raw bytes directly to a file via Radare2.
    """
    if Ks is None:
        return failure(
            "KEYSTONE_NOT_AVAILABLE",
            "Keystone engine is not installed in the python environment.",
        )

    # Validate parameters and map architecture/mode
    ks_arch, ks_mode = get_keystone_params(arch, mode)

    # Parse base address
    try:
        if base_address.lower().startswith("0x"):
            base_addr_val = int(base_address, 16)
        else:
            base_addr_val = int(base_address)
    except ValueError:
        raise ValidationError(
            f"Invalid base address value: '{base_address}'. Must be an integer or hex string.",
            details={"base_address": base_address},
        )

    # Initialize Keystone engine
    try:
        ks = Ks(ks_arch, ks_mode)
    except KsError as e:
        raise ToolExecutionError(f"Failed to initialize Keystone engine: {e}")

    # Compile assembly code
    try:
        # Replace semicolons with newlines to handle multi-line inputs properly
        cleaned_code = assembly_code.replace(";", "\n")
        encoding, count = ks.asm(cleaned_code, addr=base_addr_val)
        if encoding is None:
            raise ToolExecutionError("Keystone compilation returned empty encoding.")
    except ToolExecutionError:
        raise
    except KsError as e:
        raise ToolExecutionError(f"Keystone assembly compilation failed: {e}")
    except Exception as e:
        # Catch any other exception from ks.asm() (e.g. keystone version-specific errors)
        raise ToolExecutionError(f"Assembly compilation failed: {type(e).__name__}: {e}")

    # Format bytes
    hex_str = "".join(f"{b:02x}" for b in encoding)

    # Attempt Capstone disassembly verification if available
    verification_text = ""
    if Cs is not None:
        cs_arch, cs_mode = get_capstone_params(arch, mode)
        if cs_arch is not None:
            try:
                cs = Cs(cs_arch, cs_mode)
                disassembled = []
                for instr in cs.disasm(bytes(encoding), base_addr_val):
                    disassembled.append(f"0x{instr.address:x}: {instr.mnemonic} {instr.op_str}")
                if disassembled:
                    verification_text = "\n".join(disassembled)
                else:
                    verification_text = "Capstone warning: No instructions disassembled (invalid byte sequence or alignment)."
            except CsError as e:
                verification_text = f"Capstone warning: Disassembly verification failed: {e}"
        else:
            verification_text = f"Capstone warning: Verification not supported for {arch}/{mode}."
    else:
        verification_text = "Capstone warning: Capstone not available for disassembly verification."

    # Return structured result
    return success(
        {
            "hex": hex_str,
            "bytes": encoding,
            "instruction_count": count,
            "verification": verification_text,
        },
        arch=arch,
        mode=mode,
        base_address=hex(base_addr_val),
    )
