"""Decompilation and code recovery tools for binary analysis."""

import re
from async_lru import alru_cache
from fastmcp import Context

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Import helper functions from r2_analysis
from reversecore_mcp.tools.r2_analysis import (
    _execute_r2_command,
    _strip_address_prefixes,
    _parse_json_output,
)

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

logger = get_logger(__name__)


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

    # 4. Execute decompilation using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_cmd],
        analysis_level="aaa",
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    # 5. Check if output is valid
    if not output or output.strip() == "":
        return failure(
            "DECOMPILATION_ERROR",
            f"No decompilation output for address: {address}",
            hint="Verify the address exists and points to a valid function. Try analyzing with 'afl' first.",
        )

    # 6. Return pseudo C code
    return success(
        output,
        bytes_read=bytes_read,
        address=address,
        format="pseudo_c",
        description=f"Pseudo C code decompiled from address {address}",
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
            from reversecore_mcp.core.ghidra_helper import (
                ensure_ghidra_available,
                decompile_function_with_ghidra,
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
                        f"Ghidra decompilation failed: {ghidra_error}. "
                        "Falling back to radare2"
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

    result = await _smart_decompile_impl(
        file_path, function_address, timeout, use_ghidra
    )

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
    timeout: int = DEFAULT_TIMEOUT * 10,
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

    **AI Collaboration:**
    - AI: "This offset pattern looks like Vector3 (x, y, z)"
    - You: Apply structure definition in Ghidra
    - Result: All "this + 0x0/0x4/0x8" become "vec.x/vec.y/vec.z"

    **Ghidra vs Radare2:**
    - Ghidra (default): Superior type recovery, structure propagation, C++ support
    - Radare2 (fallback): Basic structure definition, faster but less intelligent

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function to analyze for structure usage (e.g., 'main', '0x401000')
        use_ghidra: Use Ghidra for advanced recovery (default True), or radare2 for basic
        timeout: Execution timeout in seconds (default 600 for Ghidra analysis)
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
        # Recover structures used in main function
        recover_structures("/app/workspace/game.exe", "main")

        # Analyze specific class method
        recover_structures("/app/workspace/game.exe", "Player::update")

        # Use radare2 for quick analysis
        recover_structures("/app/workspace/binary", "0x401000", use_ghidra=False)
    """
    from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available

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
                from reversecore_mcp.core.ghidra_helper import (
                    recover_structures_with_ghidra,
                )

                structures, metadata = recover_structures_with_ghidra(
                    validated_path, function_address, timeout
                )

                return success(
                    {"structures": structures},
                    **metadata,
                    function_address=function_address,
                    method="ghidra",
                    description=f"Structures recovered from {function_address} using Ghidra",
                )

            except Exception as e:
                # If Ghidra fails during execution, also fallback
                use_ghidra = False
                fallback_note = f" (Ghidra failed: {str(e)}, fell back to radare2)"

    if not use_ghidra:
        # 4b. Use radare2 for basic structure recovery
        # radare2's 'afvt' command shows variable types and offsets
        r2_cmds = [
            f"s {function_address}",  # Seek to function
            "afvj",  # Get function variables in JSON
        ]

        # Execute using helper
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_cmds,
            analysis_level="aaa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )

        # 5. Parse radare2 output
        try:
            if output.strip():
                variables = _parse_json_output(output)
            else:
                variables = []

            # Extract structure-like patterns
            # Group variables by their base pointer (e.g., rbp, rsp)
            structures = {}

            for var in variables:
                if isinstance(var, dict):
                    var_type = var.get("type", "unknown")
                    var_name = var.get("name", "unnamed")
                    offset = var.get("delta", 0)

                    # Simple heuristic: group by base register
                    base = (
                        var.get("ref", {}).get("base", "unknown")
                        if "ref" in var
                        else "stack"
                    )

                    if base not in structures:
                        structures[base] = {"name": f"struct_{base}", "fields": []}

                    structures[base]["fields"].append(
                        {
                            "offset": f"0x{abs(offset):x}",
                            "type": var_type,
                            "name": var_name,
                        }
                    )

            # 6. Generate C structure definitions
            # OPTIMIZATION: Build strings more efficiently using join
            c_definitions = []
            for struct_name, struct_data in structures.items():
                # Pre-format fields more efficiently
                field_strs = [
                    f"{field['type']} {field['name']}; // offset {field['offset']}"
                    for field in struct_data["fields"]
                ]
                fields_str = "\n    ".join(field_strs)

                c_def = f"struct {struct_data['name']} {{\n    {fields_str}\n}};"
                c_definitions.append(c_def)

            result = {
                "structures": list(structures.values()),
                "c_definitions": "\n\n".join(c_definitions),
                "count": len(structures),
            }

            desc = f"Basic structure recovery from {function_address} using radare2 (found {len(structures)} structure(s))"
            if "fallback_note" in locals():
                desc += fallback_note

            return success(
                result,
                bytes_read=bytes_read,
                function_address=function_address,
                method="radare2",
                structure_count=len(structures),
                description=desc,
            )

        except json.JSONDecodeError as e:
            return failure(
                "STRUCTURE_RECOVERY_ERROR",
                f"Failed to parse structure data: {str(e)}",
                hint="The function may not exist or may not use structures. Verify the address with 'afl' command.",
            )
