"""Decompilation and code recovery tools for binary analysis."""

import os
import re

from async_lru import alru_cache
from fastmcp import Context

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics

# Import shared R2 helper functions from core (avoids circular dependencies)
from reversecore_mcp.core.r2_helpers import (
    execute_r2_command as _execute_r2_command,
)
from reversecore_mcp.core.r2_helpers import (
    strip_address_prefixes as _strip_address_prefixes,
)
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

logger = get_logger(__name__)


# =============================================================================
# Helper Functions for Structure Recovery
# =============================================================================

# OPTIMIZATION: Pre-defined type size mapping at module level
# Uses exact match for common types (O(1) dict lookup) and substring match for compound types.
# Note: Types appear in both collections intentionally - _TYPE_SIZES_EXACT for exact matches,
# _TYPE_SIZES_CONTAINS for substring matching in compound types like "unsigned int".
_TYPE_SIZES_EXACT = {
    "char": 1,
    "byte": 1,
    "uint8_t": 1,
    "int8_t": 1,
    "bool": 1,
    "short": 2,
    "uint16_t": 2,
    "int16_t": 2,
    "word": 2,
    "wchar_t": 2,
    "int": 4,
    "uint32_t": 4,
    "int32_t": 4,
    "dword": 4,
    "float": 4,
    "long": 4,
    "long long": 8,
    "uint64_t": 8,
    "int64_t": 8,
    "qword": 8,
    "double": 8,
    "size_t": 8,
    "void *": 8,
    "intptr_t": 8,
}

# Types for substring match, ordered by:
# 1. Size (largest first) - ensures "uint64_t" matches before "int"
# 2. Specificity - longer/more specific types before shorter ones
# This ordering prevents "int" from matching before "uint32_t" in compound types
_TYPE_SIZES_CONTAINS = (
    # 8-byte types first (larger size takes priority)
    ("uint64_t", 8),
    ("int64_t", 8),
    ("qword", 8),
    ("double", 8),
    ("size_t", 8),
    ("intptr_t", 8),
    ("long long", 8),
    # 4-byte types
    ("uint32_t", 4),
    ("int32_t", 4),
    ("dword", 4),
    ("float", 4),
    # 2-byte types
    ("uint16_t", 2),
    ("int16_t", 2),
    ("wchar_t", 2),
    ("short", 2),
    ("word", 2),
    # 1-byte types (smallest size last)
    ("uint8_t", 1),
    ("int8_t", 1),
    ("char", 1),
    ("byte", 1),
    ("bool", 1),
)


def _estimate_type_size(type_str: str) -> int:
    """
    Estimate the size of a C/C++ type in bytes.

    Uses module-level pre-defined mappings for O(1) exact match lookup,
    falling back to substring search for compound types.

    Args:
        type_str: Type string (e.g., "int", "char *", "float")

    Returns:
        Estimated size in bytes
    """
    type_str = type_str.lower().strip()

    # Fast path: Pointer types (64-bit assumed)
    if "*" in type_str or "ptr" in type_str:
        return 8

    # Fast path: Try exact match first (O(1) lookup)
    if type_str in _TYPE_SIZES_EXACT:
        return _TYPE_SIZES_EXACT[type_str]

    # Slow path: Substring match for compound types (e.g., "unsigned int")
    for type_name, size in _TYPE_SIZES_CONTAINS:
        if type_name in type_str:
            return size

    # Default for unknown types
    return 4


def _extract_structures_from_disasm(disasm_ops: list) -> dict:
    """
    Extract structure-like patterns from disassembly.

    Analyzes memory access patterns to detect structure field accesses.
    For example: [rbx+0x4c], [rax+0x60], etc.

    Args:
        disasm_ops: List of disassembly operations from pdfj

    Returns:
        Dictionary of detected structures with fields
    """
    structures = {}

    # Pattern for memory accesses: [reg+offset] or [reg-offset]
    mem_pattern = re.compile(r"\[([a-z0-9]+)\s*([+-])\s*(0x[0-9a-f]+|[0-9]+)\]", re.IGNORECASE)

    for op in disasm_ops:
        if not isinstance(op, dict):
            continue

        opcode = op.get("opcode", "")
        disasm = op.get("disasm", "")

        # Look for memory access patterns
        matches = mem_pattern.findall(disasm)

        for reg, sign, offset_str in matches:
            # Skip stack-based accesses (usually local variables, not structures)
            if reg.lower() in ("rsp", "esp", "rbp", "ebp", "sp", "bp"):
                continue

            # Calculate offset
            try:
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                if sign == "-":
                    offset = -offset
            except ValueError:
                continue

            # Only consider positive offsets (structure fields)
            if offset < 0:
                continue

            # Infer type from instruction
            field_type = _infer_type_from_instruction(opcode, disasm)

            # Group by register (potential structure pointer)
            struct_name = f"struct_ptr_{reg}"
            if struct_name not in structures:
                structures[struct_name] = {
                    "name": struct_name,
                    "fields": [],
                    "source": "memory_access_pattern",
                }

            # Check if we already have this offset
            existing_offsets = {f["offset"] for f in structures[struct_name]["fields"]}
            offset_hex = f"0x{offset:x}"

            if offset_hex not in existing_offsets:
                structures[struct_name]["fields"].append(
                    {
                        "offset": offset_hex,
                        "type": field_type,
                        "name": f"field_{offset:x}",
                        "size": _estimate_type_size(field_type),
                    }
                )

    return structures


def _infer_type_from_instruction(opcode: str, disasm: str) -> str:
    """
    Infer the data type from the instruction.

    Args:
        opcode: Instruction opcode (e.g., "mov", "movss")
        disasm: Full disassembly string

    Returns:
        Inferred type string
    """
    opcode_lower = opcode.lower()
    disasm_lower = disasm.lower()

    # Floating point operations
    if any(x in opcode_lower for x in ("movss", "addss", "subss", "mulss", "divss", "comiss")):
        return "float"
    if any(x in opcode_lower for x in ("movsd", "addsd", "subsd", "mulsd", "divsd", "comisd")):
        return "double"
    if any(x in opcode_lower for x in ("movaps", "movups", "xmm")):
        return "float[4]"  # SSE vector

    # Size hints from operand suffixes
    if "byte" in disasm_lower or opcode_lower.endswith("b"):
        return "uint8_t"
    if "word" in disasm_lower and "dword" not in disasm_lower and "qword" not in disasm_lower:
        return "uint16_t"
    if "dword" in disasm_lower:
        return "uint32_t"
    if "qword" in disasm_lower:
        return "uint64_t"

    # Register-based inference
    if any(r in disasm_lower for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9")):
        return "uint64_t"
    if any(r in disasm_lower for r in ("eax", "ebx", "ecx", "edx", "esi", "edi")):
        return "uint32_t"
    if any(r in disasm_lower for r in ("ax", "bx", "cx", "dx")):
        return "uint16_t"
    if any(r in disasm_lower for r in ("al", "bl", "cl", "dl", "ah", "bh", "ch", "dh")):
        return "uint8_t"

    # Default
    return "uint32_t"


def _validate_address_or_fail(address: str, param_name: str = "address"):
    """
    Validate address format and return failure ToolResult if invalid.

    This helper consolidates the repeated pattern of address validation
    with try-except and failure return.

    Args:
        address: Address string to validate
        param_name: Parameter name for error messages

    Returns:
        None if validation passes, or ToolResult failure if invalid

    Raises:
        No exceptions - all validation errors are converted to ToolResult failures
    """
    from reversecore_mcp.core.validators import validate_address_format

    try:
        validate_address_format(address, param_name)
        return None  # Validation passed
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))


def _parse_register_state(ar_output: str) -> dict:
    """
    Parse radare2 'ar' command output into structured register state.

    Args:
        ar_output: Raw output from 'ar' command

    Returns:
        Dictionary mapping register names to values

    Example output from 'ar':
        rax = 0x00000000
        rbx = 0x00401000
        ...
    """
    registers = {}

    for line in ar_output.strip().split("\n"):
        if "=" in line:
            parts = line.split("=")
            if len(parts) == 2:
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers[reg_name] = reg_value

    return registers


@log_execution(tool_name="emulate_machine_code")
@track_metrics("emulate_machine_code")
@handle_tool_errors
async def emulate_machine_code(
    file_path: str,
    start_address: str,
    instructions: int = 50,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language).

    This tool provides safe, sandboxed emulation of binary code without actual execution.
    Perfect for analyzing obfuscated code, understanding register states, and predicting
    execution outcomes without security risks.

    **Key Use Cases:**
    - De-obfuscation: Reveal hidden strings by emulating XOR/shift operations
    - Register Analysis: See final register values after code execution
    - Safe Malware Analysis: Predict behavior without running malicious code

    **Safety Features:**
    - Virtual CPU simulation (no real execution)
    - Instruction count limit (max 1000) prevents infinite loops
    - Memory sandboxing (changes don't affect host system)

    Args:
        file_path: Path to the binary file (must be in workspace)
        start_address: Address to start emulation (e.g., 'main', '0x401000', 'sym.decrypt')
        instructions: Number of instructions to execute (default 50, max 1000)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with register states and emulation summary
    """
    # 1. Parameter validation
    validate_tool_parameters(
        "emulate_machine_code",
        {"start_address": start_address, "instructions": instructions},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for start address (prevent shell injection)
    validation_error = _validate_address_or_fail(start_address, "start_address")
    if validation_error:
        return validation_error

    # 3. Build radare2 ESIL emulation command chain
    # Note: Commands must be executed in specific order for ESIL to work correctly
    esil_cmds = [
        f"s {start_address}",  # Seek to start address
        "aei",  # Initialize ESIL VM
        "aeim",  # Initialize ESIL memory (stack)
        "aeip",  # Initialize program counter to current seek
        f"aes {instructions}",  # Step through N instructions
        "ar",  # Show all registers
    ]

    # 4. Execute emulation using helper
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            esil_cmds,
            analysis_level="aaa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )

        # 5. Parse register state
        register_state = _parse_register_state(output)

        if not register_state:
            return failure(
                "EMULATION_ERROR",
                "Failed to extract register state from emulation output",
                hint="The binary may not be compatible with ESIL emulation, or the start address is invalid",
            )

        # 6. Build result with metadata
        return success(
            register_state,
            bytes_read=bytes_read,
            format="register_state",
            instructions_executed=instructions,
            start_address=start_address,
            description=f"Emulated {instructions} instructions starting at {start_address}",
        )

    except Exception as e:
        return failure(
            "EMULATION_ERROR",
            f"ESIL emulation failed: {str(e)}",
            hint="Check that the binary architecture is supported and the start address is valid",
        )


@log_execution(tool_name="get_pseudo_code")
@track_metrics("get_pseudo_code")
@handle_tool_errors
async def get_pseudo_code(
    file_path: str,
    address: str = "main",
    timeout: int = 300,
) -> ToolResult:
    """
    Generate pseudo C code (decompilation) for a function using radare2's pdc command.

    This tool decompiles binary code into C-like pseudocode, making it much easier
    to understand program logic compared to raw assembly. The output can be further
    refined by AI for better readability.

    **Use Cases:**
    - Quick function understanding without reading assembly
    - AI-assisted code analysis and refactoring
    - Documentation generation from binaries
    - Reverse engineering workflow optimization

    **Note:** The output is "pseudo C" - it may not be syntactically perfect C,
    but provides a high-level representation of the function logic.

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function address to decompile (e.g., 'main', '0x401000', 'sym.foo')
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with pseudo C code string

    Example:
        get_pseudo_code("/app/workspace/sample.exe", "main")
        # Returns C-like code representation of the main function
    """
    # 1. Validate file path
    validated_path = validate_file_path(file_path)

    # 2. Security check for address (prevent shell injection)
    validation_error = _validate_address_or_fail(address, "address")
    if validation_error:
        return validation_error

    # 3. Build radare2 command to decompilation
    r2_cmd = f"pdc @ {address}"

    # 4. Determine analysis level based on file size
    # Use 'aa' (basic) for large files to prevent timeouts
    analysis_level = "aa"
    try:
        file_size_mb = os.path.getsize(validated_path) / (1024 * 1024)
        if file_size_mb < 5:
            analysis_level = "aaa"  # Full analysis for small files
    except OSError:
        pass

    # 5. Execute decompilation using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_cmd],
        analysis_level=analysis_level,
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    # 6. Check if output is valid
    if not output or output.strip() == "":
        return failure(
            "DECOMPILATION_ERROR",
            f"No decompilation output for address: {address}",
            hint="Verify the address exists and points to a valid function. Try analyzing with 'afl' first.",
        )

    # 7. Return pseudo C code
    return success(
        output,
        bytes_read=bytes_read,
        address=address,
        format="pseudo_c",
        analysis_level=analysis_level,
        description=f"Pseudo C code decompiled from address {address} (analysis: {analysis_level})",
    )


@alru_cache(maxsize=32)
@log_execution(tool_name="smart_decompile")
@track_metrics("smart_decompile")
@circuit_breaker("smart_decompile", failure_threshold=3, recovery_timeout=60)
@handle_tool_errors
async def _smart_decompile_impl(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
    use_ghidra: bool = True,
) -> ToolResult:
    """
    Internal implementation of smart_decompile with caching.
    """
    # 1. Validate parameters
    validate_tool_parameters("smart_decompile", {"function_address": function_address})
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    validation_error = _validate_address_or_fail(function_address, "function_address")
    if validation_error:
        return validation_error

    # 3. Try Ghidra first if requested and available
    if use_ghidra:
        try:
            from reversecore_mcp.core.ghidra import (
                decompile_function_with_ghidra,
                ensure_ghidra_available,
            )

            if ensure_ghidra_available():
                logger.info(f"Using Ghidra decompiler for {function_address}")

                # Run Ghidra decompilation
                try:
                    c_code, metadata = decompile_function_with_ghidra(
                        validated_path, function_address, timeout
                    )

                    return success(
                        c_code,
                        function_address=function_address,
                        format="pseudo_c",
                        decompiler="ghidra",
                        **metadata,
                    )

                except Exception as ghidra_error:
                    logger.warning(
                        f"Ghidra decompilation failed: {ghidra_error}. Falling back to radare2"
                    )
                    # Fall through to radare2
            else:
                logger.info("Ghidra not available, using radare2")

        except ImportError:
            logger.info("PyGhidra not installed, using radare2")

    # 4. Fallback to radare2 (original implementation)
    logger.info(f"Using radare2 decompiler for {function_address}")

    r2_cmds = [f"pdc @ {function_address}"]

    # 5. Execute decompilation using helper
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_cmds,
            analysis_level="aa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )
    except Exception as e:
        # If 'aaa' fails, try lighter analysis 'aa' or just '-n' if desperate,
        # but pdc requires analysis.
        return failure(
            "DECOMPILATION_ERROR",
            f"Radare2 decompilation failed: {str(e)}",
            hint="Analysis failed. The binary might be packed or corrupted.",
        )

    # Add timestamp for cache visibility
    import time

    timestamp = time.time()

    # 6. Return result
    return success(
        output,
        bytes_read=bytes_read,
        function_address=function_address,
        format="pseudo_c",
        decompiler="radare2",
        description=f"Decompiled code from function {function_address}",
        timestamp=timestamp,
    )


async def smart_decompile(
    file_path: str,
    function_address: str,
    timeout: int = DEFAULT_TIMEOUT,
    use_ghidra: bool = True,
    ctx: Context = None,
) -> ToolResult:
    """
    Decompile a function to pseudo C code using Ghidra or radare2.

    This tool provides decompilation for a specific function in a binary,
    making it easier to understand the logic without reading raw assembly.

    **Decompiler Selection:**
    - Ghidra (default): More accurate, better type recovery, industry-standard
    - radare2 (fallback): Faster, lighter weight, good for quick analysis

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to decompile (e.g., 'main', '0x401000')
        timeout: Execution timeout in seconds (default 300)
        use_ghidra: Use Ghidra decompiler if available (default True)
        ctx: FastMCP Context (auto-injected)

    Returns:
        ToolResult with decompiled pseudo C code
    """
    import time

    result = await _smart_decompile_impl(file_path, function_address, timeout, use_ghidra)

    # Check for cache hit
    if result.status == "success" and result.metadata:
        ts = result.metadata.get("timestamp")
        if ts and (time.time() - ts > 1.0):
            result.metadata["cache_hit"] = True

    return result


@log_execution(tool_name="recover_structures")
@track_metrics("recover_structures")
@handle_tool_errors
async def recover_structures(
    file_path: str,
    function_address: str,
    use_ghidra: bool = True,
    fast_mode: bool = True,
    timeout: int = DEFAULT_TIMEOUT * 5,
    ctx: Context = None,
) -> ToolResult:
    """
    Recover C++ class structures and data types from binary code.

    This is THE game-changer for C++ reverse engineering. Transforms cryptic
    "this + 0x4" memory accesses into meaningful "Player.health" structure fields.
    Uses Ghidra's powerful data type propagation and structure recovery algorithms.

    **Why Structure Recovery Matters:**
    - **C++ Analysis**: 99% of game clients and commercial apps are C++
    - **Understanding**: "this + 0x4" means nothing, "Player.health = 100" tells a story
    - **AI Comprehension**: AI can't understand raw offsets, but understands named fields
    - **Scale**: One structure definition can clarify thousands of lines of code

    **Performance Tips (for large binaries like game clients):**
    - Use `fast_mode=True` (default) to skip full binary analysis
    - Use `use_ghidra=False` for quick radare2-based analysis
    - For best results on first run, set `fast_mode=False` but expect longer wait

    **How It Works:**
    1. Analyze memory access patterns in the function
    2. Identify structure layouts from offset usage
    3. Use data type propagation to infer field types
    4. Generate C structure definitions with meaningful names

    **Use Cases:**
    - Game hacking: Recover Player, Entity, Weapon structures
    - Malware analysis: Understand malware configuration structures
    - Vulnerability research: Find buffer overflow candidates in structs
    - Software auditing: Document undocumented data structures

    **Ghidra vs Radare2:**
    - Ghidra (default): Superior type recovery, structure propagation, C++ support
    - Radare2 (fallback): Basic structure definition, faster but less intelligent

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function to analyze for structure usage (e.g., 'main', '0x401000')
        use_ghidra: Use Ghidra for advanced recovery (default True), or radare2 for basic
        fast_mode: Skip full binary analysis for faster startup (default True)
        timeout: Execution timeout in seconds (default 300 seconds)
        ctx: FastMCP Context (auto-injected)

    Returns:
        ToolResult with recovered structures in C format:
        {
            "structures": [
                {
                    "name": "Player",
                    "size": 64,
                    "fields": [
                        {"offset": "0x0", "type": "int", "name": "health"},
                        {"offset": "0x4", "type": "int", "name": "armor"},
                        {"offset": "0x8", "type": "Vector3", "name": "position"}
                    ]
                }
            ],
            "c_definitions": "struct Player { int health; int armor; Vector3 position; };"
        }

    Example:
        # Fast structure recovery (recommended for large binaries)
        recover_structures("/app/workspace/game.exe", "main")

        # More thorough analysis (slower but more accurate)
        recover_structures("/app/workspace/game.exe", "main", fast_mode=False)

        # Use radare2 for quick analysis
        recover_structures("/app/workspace/binary", "0x401000", use_ghidra=False)
    """
    from reversecore_mcp.core.ghidra import ensure_ghidra_available

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    # 2. Validate address format
    # OPTIMIZATION: Use efficient regex substitution instead of chained replace
    if not re.match(
        r"^[a-zA-Z0-9_.:<>]+$",
        _strip_address_prefixes(function_address),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid function address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, colons, angle brackets, and prefixes like '0x', 'sym.'",
        )

    # 3. Check if Ghidra is available when requested
    if use_ghidra:
        # Check availability and fallback if needed
        if not ensure_ghidra_available():
            # Instead of failing, let's fallback to radare2 with a warning in the description
            # This improves UX when Ghidra is optional but requested by default
            use_ghidra = False
            # We will append a note to the result description later
            fallback_note = " (Ghidra not available, fell back to radare2)"
        else:
            fallback_note = ""
            # 4a. Use Ghidra for advanced structure recovery
            try:
                from reversecore_mcp.core.ghidra import (
                    recover_structures_with_ghidra,
                )

                # Pass fast_mode to skip full binary analysis
                structures, metadata = recover_structures_with_ghidra(
                    validated_path, function_address, timeout, skip_full_analysis=fast_mode
                )

                mode_note = " (fast mode)" if fast_mode else " (full analysis)"
                return success(
                    {"structures": structures},
                    **metadata,
                    function_address=function_address,
                    method="ghidra",
                    fast_mode=fast_mode,
                    description=f"Structures recovered from {function_address} using Ghidra{mode_note}",
                )

            except Exception as e:
                # If Ghidra fails during execution, also fallback
                use_ghidra = False
                fallback_note = f" (Ghidra failed: {str(e)}, fell back to radare2)"

    if not use_ghidra:
        # 4b. Use radare2 for enhanced structure recovery
        # Multi-pronged approach:
        # 1. Function variables (afvj)
        # 2. Data types from binary (tj)
        # 3. Memory access patterns (axtj for structure field access)
        # 4. RTTI-based class detection

        import os

        file_size_mb = os.path.getsize(validated_path) / (1024 * 1024)

        # For structure recovery, we need deeper analysis than basic 'aa'
        # Use 'aaa' for structure recovery even on large files, but with timeout protection
        if fast_mode:
            # Fast mode: minimal analysis, may miss structures
            analysis_level = "aa"
            analysis_note = " (fast mode - may miss some structures)"
        else:
            # Full mode: thorough analysis for structure recovery
            # Even for large files, we need 'aaa' to detect types
            analysis_level = "aaa"
            analysis_note = " (full analysis)"

        # Enhanced command set for structure recovery
        r2_cmds = [
            f"s {function_address}",  # Seek to function
            "af",  # Analyze this function
            "afvj",  # Get function variables in JSON
            "afij",  # Get function info (size, type)
            "pdfj",  # Disassemble function - detect memory access patterns
        ]

        # Execute using helper
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_cmds,
            analysis_level=analysis_level,
            max_output_size=10_000_000,
            base_timeout=timeout,
        )

        # 5. Parse radare2 output - enhanced parsing
        try:
            structures = {}
            detected_classes = []
            memory_accesses = []

            # Parse multi-command output
            outputs = output.strip().split("\n")

            # Try to parse each line as JSON
            variables = []
            function_info = {}
            disasm_ops = []

            valid_json_parsed = False
            for line in outputs:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    valid_json_parsed = True
                    if isinstance(parsed, list):
                        # Could be variables (afvj) or disasm ops
                        if parsed and isinstance(parsed[0], dict):
                            if "name" in parsed[0] and "type" in parsed[0]:
                                variables = parsed
                            elif "opcode" in parsed[0]:
                                disasm_ops = parsed
                    elif isinstance(parsed, dict):
                        if "ops" in parsed:
                            disasm_ops = parsed.get("ops", [])
                        elif "name" in parsed:
                            function_info = parsed
                except json.JSONDecodeError:
                    continue

            # If we had output but failed to parse any JSON, raise error
            if output.strip() and not valid_json_parsed:
                raise json.JSONDecodeError("No valid JSON found in output", output, 0)

            # Extract structures from variables
            for var in variables:
                if isinstance(var, dict):
                    var_type = var.get("type", "unknown")
                    var_name = var.get("name", "unnamed")
                    offset = var.get("delta", 0)
                    kind = var.get("kind", "")

                    # Determine structure grouping
                    if "arg" in kind:
                        base = "args"
                    elif "var" in kind or "local" in kind:
                        base = "locals"
                    else:
                        base = (
                            var.get("ref", {}).get("base", "stack")
                            if isinstance(var.get("ref"), dict)
                            else "stack"
                        )

                    if base not in structures:
                        structures[base] = {
                            "name": f"struct_{base}",
                            "fields": [],
                            "source": "variables",
                        }

                    structures[base]["fields"].append(
                        {
                            "offset": f"0x{abs(offset):x}",
                            "type": var_type,
                            "name": var_name,
                            "size": _estimate_type_size(var_type),
                        }
                    )

            # Analyze disassembly for memory access patterns (structure field detection)
            struct_from_memory = _extract_structures_from_disasm(disasm_ops)
            for struct_name, struct_data in struct_from_memory.items():
                if struct_name not in structures:
                    structures[struct_name] = struct_data
                else:
                    # Merge fields
                    existing_offsets = {f["offset"] for f in structures[struct_name]["fields"]}
                    for field in struct_data["fields"]:
                        if field["offset"] not in existing_offsets:
                            structures[struct_name]["fields"].append(field)

            # Sort fields by offset within each structure
            for struct_data in structures.values():
                struct_data["fields"].sort(
                    key=lambda f: int(f["offset"], 16)
                    if f["offset"].startswith("0x")
                    else int(f["offset"])
                )

            # 6. Generate C structure definitions
            c_definitions = []
            for _struct_name, struct_data in structures.items():
                if not struct_data["fields"]:
                    continue

                field_strs = [
                    f"    {field['type']} {field['name']}; // offset {field['offset']}, size ~{field.get('size', '?')} bytes"
                    for field in struct_data["fields"]
                ]
                fields_str = "\n".join(field_strs)

                c_def = f"struct {struct_data['name']} {{\n{fields_str}\n}};"
                c_definitions.append(c_def)

            # Filter out empty structures
            non_empty_structures = {k: v for k, v in structures.items() if v["fields"]}

            result = {
                "structures": list(non_empty_structures.values()),
                "c_definitions": "\n\n".join(c_definitions),
                "count": len(non_empty_structures),
                "analysis_mode": "fast" if fast_mode else "full",
            }

            desc = f"Structure recovery from {function_address} using radare2{analysis_note} (found {len(non_empty_structures)} structure(s))"
            if "fallback_note" in locals():
                desc += fallback_note

            # Add hint if no structures found
            hint = None
            if len(non_empty_structures) == 0:
                hint = "No structures found. Try: 1) fast_mode=False for deeper analysis, 2) use_ghidra=True for C++ structures, 3) analyze a function that uses structures (not main/entry0)"

            return success(
                result,
                bytes_read=bytes_read,
                function_address=function_address,
                method="radare2",
                structure_count=len(non_empty_structures),
                description=desc,
                hint=hint,
            )

        except json.JSONDecodeError as e:
            return failure(
                "STRUCTURE_RECOVERY_ERROR",
                f"Failed to parse structure data: {str(e)}",
                hint="The function may not exist or may not use structures. Verify the address with 'afl' command.",
            )


from typing import Any

from reversecore_mcp.core.plugin import Plugin


class DecompilationPlugin(Plugin):
    """Plugin for decompilation and structure recovery tools."""

    @property
    def name(self) -> str:
        return "decompilation"

    @property
    def description(self) -> str:
        return "Decompilation and code recovery tools for binary analysis."

    def register(self, mcp_server: Any) -> None:
        """Register decompilation tools."""
        mcp_server.tool(emulate_machine_code)
        mcp_server.tool(get_pseudo_code)
        mcp_server.tool(smart_decompile)
        mcp_server.tool(recover_structures)
