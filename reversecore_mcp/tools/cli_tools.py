"""CLI tool wrappers that return structured ToolResult payloads."""

import asyncio
import json
import re
import shutil
import hashlib
import os
from pathlib import Path
from typing import Optional
import time

from async_lru import alru_cache
from functools import lru_cache
from fastmcp import FastMCP, Context
from fastmcp.utilities.types import Image
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError, ToolExecutionError
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters, validate_address_format

from reversecore_mcp.core.r2_pool import r2_pool
from reversecore_mcp.core.ghidra_manager import ghidra_manager
from reversecore_mcp.core.binary_cache import binary_cache

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout

# Pre-compile regex patterns for performance optimization
_VERSION_PATTERNS = {
    "OpenSSL": re.compile(r"(OpenSSL|openssl)\s+(\d+\.\d+\.\d+[a-z]?)", re.IGNORECASE),
    "GCC": re.compile(r"GCC:\s+\(.*\)\s+(\d+\.\d+\.\d+)"),
    "Python": re.compile(r"(Python|python)\s+([23]\.\d+\.\d+)", re.IGNORECASE),
    "Curl": re.compile(r"curl\s+(\d+\.\d+\.\d+)", re.IGNORECASE),
    "BusyBox": re.compile(r"BusyBox\s+v(\d+\.\d+\.\d+)", re.IGNORECASE),
    "Generic_Version": re.compile(r"[vV]er(?:sion)?\s?[:.]?\s?(\d+\.\d+\.\d+)"),
    "Copyright": re.compile(r"Copyright.*(19|20)\d{2}"),
}


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
    logger = get_logger(__name__)

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
            # Use GhidraManager for persistent JVM
            logger.info(f"Using Ghidra decompiler for {function_address}")
            
            c_code = await ghidra_manager.decompile_async(
                str(validated_path), function_address
            )

            return success(
                c_code,
                function_address=function_address,
                format="pseudo_c",
                decompiler="ghidra",
                description=f"Decompiled {function_address} using Ghidra (JVM reused)"
            )

        except Exception as ghidra_error:
            logger.warning(
                f"Ghidra decompilation failed: {ghidra_error}. "
                "Falling back to radare2"
            )
            # Fall through to radare2

    # 4. Fallback to radare2 (original implementation)
    logger.info(f"Using radare2 decompiler for {function_address}")

    r2_cmds = [f"pdc @ {function_address}"]
    
    # 5. Execute decompilation using helper
    try:
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_cmds,
            analysis_level="aaa",
            max_output_size=10_000_000,
            base_timeout=timeout,
        )
    except Exception as e:
        return failure(
            "DECOMPILATION_ERROR",
            f"Radare2 decompilation failed: {str(e)}",
            hint="Analysis failed. The binary might be packed or corrupted."
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
        timestamp=timestamp
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


@log_execution(tool_name="generate_yara_rule")
@track_metrics("generate_yara_rule")
@handle_tool_errors
async def generate_yara_rule(
    file_path: str,
    function_address: str,
    rule_name: str = "auto_generated_rule",
    byte_length: int = 64,
    timeout: int = DEFAULT_TIMEOUT,
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
    
    analysis_level = ""
    if function_address.startswith("0x") or re.match(r"^[0-9a-fA-F]+$", function_address):
        analysis_level = "-n"
        
    # 4. Extract hex bytes using helper
    # Note: analysis_level may be "" (empty) which means default r2 behavior (parse headers/symbols)
    output, bytes_read = await _execute_r2_command(
        validated_path,
        r2_cmds,
        analysis_level=analysis_level or "aaa",
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

    # 6. Format as YARA hex string (space-separated pairs)
    # OPTIMIZED: Use generator expression to avoid intermediate list
    formatted_bytes = _format_hex_bytes(hex_bytes)

    # 7. Generate YARA rule
    file_name = _sanitize_filename_for_rule(file_path)

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule for {file_name}"
        address = "{function_address}"
        byte_length = {byte_length}
        author = "Reversecore_MCP"
        
    strings:
        $code = {{ {formatted_bytes} }}
        
    condition:
        $code
}}"""

    # 8. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        function_address=function_address,
        rule_name=rule_name,
        byte_length=byte_length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA rule '{rule_name}' generated from {byte_length} bytes at {function_address}",
    )


@log_execution(tool_name="analyze_xrefs")
@track_metrics("analyze_xrefs")
@handle_tool_errors
async def analyze_xrefs(
    file_path: str,
    address: str,
    xref_type: str = "all",
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Analyze cross-references (X-Refs) for a function or data address.

    This tool identifies all references TO and FROM a given address, providing
    critical context for understanding code behavior. Essential for malware
    analysis, vulnerability research, and understanding program flow.

    **Why Cross-References Matter:**
    - **Callers**: Who calls this function? (Find entry points to suspicious code)
    - **Callees**: What does this function call? (Understand behavior and APIs used)
    - **Data Refs**: What data does this access? (Find strings, configs, crypto keys)
    - **Context**: Understand the "why" behind code execution

    **Use Cases:**
    - Malware analysis: "Who calls this Connect function?" reveals C2 behavior
    - Password hunting: "What functions reference this 'Password' string?"
    - Vulnerability research: "What uses this vulnerable API?"
    - Game hacking: "Where is Player health accessed from?"

    **AI Collaboration:**
    AI can use xrefs to:
    - Build call graphs automatically
    - Identify code patterns (e.g., "all functions that write files")
    - Focus token budget on relevant functions only
    - Reduce hallucination by providing real relationships

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function or data address (e.g., 'main', '0x401000', 'sym.decrypt')
        xref_type: Type of references to analyze:
            - "all" (default): Both callers and callees
            - "to": References TO this address (callers, data reads)
            - "from": References FROM this address (callees, data writes)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with cross-reference information in structured format:
        {
            "address": "0x401000",
            "function_name": "main",
            "xrefs_to": [
                {"from": "0x401234", "type": "call", "function": "entry0"},
                {"from": "0x401567", "type": "call", "function": "init"}
            ],
            "xrefs_from": [
                {"to": "0x401100", "type": "call", "function": "sub_401100"},
                {"to": "0x403000", "type": "data_read", "data": "str.password"}
            ],
            "total_refs_to": 2,
            "total_refs_from": 2
        }

    Example:
        # Find who calls the suspicious 'decrypt' function
        analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")

        # Find what APIs a malware function uses
        analyze_xrefs("/app/workspace/malware.exe", "0x401000", "from")

        # Get complete relationship map
        analyze_xrefs("/app/workspace/malware.exe", "main", "all")
    """
    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if xref_type not in ["all", "to", "from"]:
        return failure(
            "VALIDATION_ERROR",
            f"Invalid xref_type: {xref_type}",
            hint="Valid options are: 'all', 'to', 'from'",
        )

    # 2. Validate address format
    if not re.match(
        r"^[a-zA-Z0-9_.]+$",
        address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, and prefixes like '0x', 'sym.', 'fcn.'",
        )

    # 3. Build radare2 commands to get xrefs
    # axj = analyze xrefs in JSON format
    commands = []

    if xref_type in ["all", "to"]:
        # axtj = xrefs TO this address (callers)
        commands.append(f"axtj @ {address}")

    if xref_type in ["all", "from"]:
        # axfj = xrefs FROM this address (callees)
        commands.append(f"axfj @ {address}")

    # Build command string
    r2_commands_str = "; ".join(commands)

    # 4. Execute analysis using helper
    output, bytes_read = await _execute_r2_command(
        validated_path,
        [r2_commands_str],
        analysis_level="aaa",
        max_output_size=10_000_000,
        base_timeout=timeout,
    )

    # 5. Parse JSON output
    try:
        # Output may contain multiple JSON arrays if both "to" and "from" were requested
        # Split by lines and parse each JSON array
        lines = [line.strip() for line in output.strip().split("\n") if line.strip()]

        xrefs_to = []
        xrefs_from = []

        for line in lines:
            # Robust JSON extraction from line
            try:
                refs = _parse_json_output(line)
                if isinstance(refs, list) and len(refs) > 0:
                    # Determine if this is "to" or "from" based on field names
                    first_ref = refs[0]
                    if "from" in first_ref:
                        # This is xrefs TO (callers)
                        xrefs_to = refs
                    elif "addr" in first_ref or "fcn_addr" in first_ref:
                        # This is xrefs FROM (callees)
                        xrefs_from = refs
            except json.JSONDecodeError:
                # Skip lines that don't contain valid JSON
                continue

        # 6. Format results
        result = {
            "address": address,
            "xref_type": xref_type,
            "xrefs_to": xrefs_to,
            "xrefs_from": xrefs_from,
            "total_refs_to": len(xrefs_to),
            "total_refs_from": len(xrefs_from),
        }

        # Add human-readable summary
        summary_parts = []
        if xrefs_to:
            summary_parts.append(
                f"{len(xrefs_to)} reference(s) TO this address (callers)"
            )
        if xrefs_from:
            summary_parts.append(
                f"{len(xrefs_from)} reference(s) FROM this address (callees)"
            )

        if not summary_parts:
            summary = "No cross-references found"
        else:
            summary = ", ".join(summary_parts)

        result["summary"] = summary

        # 7. Return structured result
        return success(
            result,
            bytes_read=bytes_read,
            address=address,
            xref_type=xref_type,
            total_refs=len(xrefs_to) + len(xrefs_from),
            description=f"Cross-reference analysis for {address}: {summary}",
        )

    except Exception as e:
        return failure(
            "XREF_ANALYSIS_ERROR",
            f"Failed to parse cross-reference data: {str(e)}",
            hint="The address may not exist or the binary may not have been analyzed. Try running 'afl' first to see available functions.",
        )


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
    if not re.match(
        r"^[a-zA-Z0-9_.:<>]+$",
        function_address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
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
            c_definitions = []
            for struct_name, struct_data in structures.items():
                fields_str = "\n    ".join(
                    [
                        f"{field['type']} {field['name']}; // offset {field['offset']}"
                        for field in struct_data["fields"]
                    ]
                )

                c_def = f"struct {struct_data['name']} {{\n    {fields_str}\n}};"
                c_definitions.append(c_def)

            result = {
                "structures": list(structures.values()),
                "c_definitions": "\n\n".join(c_definitions),
                "count": len(structures),
            }
            
            desc = f"Basic structure recovery from {function_address} using radare2 (found {len(structures)} structure(s))"
            if 'fallback_note' in locals():
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


@log_execution(tool_name="diff_binaries")
@track_metrics("diff_binaries")
@handle_tool_errors
async def diff_binaries(
    file_path_a: str,
    file_path_b: str,
    function_name: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Compare two binary files to identify code changes and modifications.

    This tool uses radiff2 to perform binary diffing, which is essential for:
    - **Patch Analysis (1-day Exploits)**: Compare pre-patch and post-patch binaries
      to identify security vulnerabilities fixed in updates
    - ** Game Hacking**: Find offset changes after game updates to maintain functionality
    - **Malware Variant Analysis**: Identify code differences between malware variants
      (e.g., "90% similar to Lazarus malware, but C2 address generation changed")

    The tool provides:
    - Similarity score (0.0-1.0) between binaries
    - List of code changes with addresses and descriptions
    - Optional function-level comparison for targeted analysis

    Args:
        file_path_a: Path to the first binary file (e.g., pre-patch version)
        file_path_b: Path to the second binary file (e.g., post-patch version)
        function_name: Optional function name to compare (e.g., "main", "sym.decrypt").
                      If None, performs whole-binary comparison.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - similarity: Float between 0.0 and 1.0 indicating code similarity
        - changes: List of detected changes with addresses and descriptions
        - function_specific: Boolean indicating if function-level diff was performed

    Example:
        # Compare two versions of a patched binary
        diff_binaries("/app/workspace/app_v1.0.exe", "/app/workspace/app_v1.1.exe")

        # Compare specific function between versions
        diff_binaries("/app/workspace/malware_old.exe", "/app/workspace/malware_new.exe", "main")

    Output Format:
        {
          "similarity": 0.95,
          "function_specific": false,
          "changes": [
            {
              "address": "0x401050",
              "type": "code_change",
              "description": "Instruction changed from JNZ to JZ"
            },
            {
              "address": "0x401080",
              "type": "new_block",
              "description": "Added security check"
            }
          ],
          "total_changes": 2
        }
    """
    # Validate both file paths
    validated_path_a = validate_file_path(file_path_a)
    validated_path_b = validate_file_path(file_path_b)

    # Validate tool parameters
    validate_tool_parameters(
        "diff_binaries",
        {
            "function_name": function_name,
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Build radiff2 command
        # -s: similarity score
        # -C: code comparison
        # -g: graph diff (if function specified)

        if function_name:
            # Function-specific comparison using graph diff
            cmd = [
                "radiff2",
                "-g",
                function_name,
                str(validated_path_a),
                str(validated_path_b),
            ]
        else:
            # Whole-binary comparison with similarity scoring
            cmd = [
                "radiff2",
                "-C",
                str(validated_path_a),
                str(validated_path_b),
            ]

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=max_output_size,
            timeout=timeout,
        )

        # Also get similarity score (format: "similarity: 0.95")
        similarity_cmd = ["radiff2", "-s", str(validated_path_a), str(validated_path_b)]
        similarity_output, _ = await execute_subprocess_async(
            similarity_cmd,
            max_output_size=1_000_000,
            timeout=60,
        )

        # Parse similarity score (format: "similarity: 0.95")
        similarity = 0.0
        similarity_match = re.search(r"similarity:\s*(\d+\.?\d*)", similarity_output)
        if similarity_match:
            similarity = float(similarity_match.group(1))

        # Parse changes from output
        changes = []

        # Parse the diff output to extract meaningful changes
        # radiff2 output varies, so we'll capture the raw output and structure it
        lines = output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            # Look for common patterns in radiff2 output
            # Address patterns: 0x... or addresses
            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)

            if addr_match:
                address = addr_match.group(1)

                # Determine change type based on line content
                change_type = "unknown"
                description = line.strip()

                if "new" in line.lower():
                    change_type = "new_block"
                elif "removed" in line.lower() or "deleted" in line.lower():
                    change_type = "removed_block"
                elif "modified" in line.lower() or "changed" in line.lower():
                    change_type = "code_change"
                elif (
                    "jmp" in line.lower()
                    or "call" in line.lower()
                    or "jnz" in line.lower()
                ):
                    change_type = "control_flow_change"

                changes.append(
                    {
                        "address": address,
                        "type": change_type,
                        "description": description,
                    }
                )

        # If no structured changes found, include summary info
        if not changes and output.strip():
            changes.append(
                {
                    "type": "summary",
                    "description": "Binary comparison completed. See raw output for details.",
                }
            )

        # Build result
        result_data = {
            "similarity": similarity,
            "function_specific": bool(function_name),
            "changes": changes,
            "total_changes": len(changes),
            "raw_output": (
                output if len(output) < 5000 else output[:5000] + "... (truncated)"
            ),
        }

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            similarity=similarity,
            total_changes=len(changes),
            function_specific=bool(function_name),
        )

    except Exception as e:
        return failure(
            "DIFF_ERROR",
            f"Binary diff failed: {str(e)}",
            hint="Ensure both files are valid binaries and radiff2 is available. For function-level diff, verify function name exists in both binaries.",
        )


@log_execution(tool_name="match_libraries")
@track_metrics("match_libraries")
@handle_tool_errors
async def match_libraries(
    file_path: str,
    signature_db: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = DEFAULT_TIMEOUT,
    ctx: Context = None,
) -> ToolResult:
    """
    Match and filter known library functions to focus on user code.

    This tool uses radare2's zignatures (FLIRT-compatible signature matching) to:
    - **Reduce Analysis Noise**: Skip analysis of known library functions (strcpy, malloc, etc.)
    - **Focus on User Code**: Identify which functions are original vs library code
    - **Save Time & Tokens**: Reduce analysis scope by 80% by filtering out standard libraries
    - **Improve Accuracy**: Focus AI analysis on the actual malicious/interesting code

    Common use cases:
    - Analyzing large binaries (>25MB) where most code is OpenSSL, zlib, MFC, etc.
    - Game client reverse engineering (filter out Unreal Engine / Unity standard library)
    - Malware analysis (focus on custom malware code, skip Windows API wrappers)

    The tool automatically uses built-in signature databases for common libraries
    and can optionally use custom signature databases for specialized analysis.

    Args:
        file_path: Path to the binary file to analyze
        signature_db: Optional path to custom signature database file (.sig format).
                     If None, uses radare2's built-in signature databases.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - total_functions: Total number of functions found
        - library_functions: Number of matched library functions
        - user_functions: Number of unmatched (user) functions to analyze
        - library_matches: List of matched library functions with details
        - user_function_list: List of user function addresses/names for further analysis
        - noise_reduction_percentage: Percentage of functions filtered out

    Example:
        # Auto-detect standard libraries
        match_libraries("/app/workspace/large_app.exe")

        # Use custom signature database
        match_libraries("/app/workspace/game.exe", "/app/rules/game_engine.sig")

    Output Format:
        {
          "total_functions": 1250,
          "library_functions": 1000,
          "user_functions": 250,
          "noise_reduction_percentage": 80.0,
          "library_matches": [
            {
              "address": "0x401000",
              "name": "strcpy",
              "library": "msvcrt"
            },
            {
              "address": "0x401050",
              "name": "malloc",
              "library": "msvcrt"
            }
          ],
          "user_function_list": [
            "0x402000",
            "0x402100",
            "sym.custom_decrypt"
          ]
        }
    """
    # Validate file path
    validated_path = validate_file_path(file_path)

    # Validate optional signature database path
    if signature_db:
        validated_sig_path = validate_file_path(signature_db)

    # Validate tool parameters
    validate_tool_parameters(
        "match_libraries",
        {
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Step 1: Load binary and analyze
        # Use radare2 to get function list with signature matching

        # Build command to apply signatures and get function list
        if signature_db:
            # Load custom signature database
            r2_commands = [f"zg {validated_sig_path}", "aflj"]
        else:
            # Use built-in signatures
            r2_commands = ["zg", "aflj"]

        # Execute using helper
        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_commands,
            analysis_level="aaa",
            max_output_size=max_output_size,
            base_timeout=timeout,
        )

        # Parse JSON output from aflj (function list JSON)
        try:
            # Attempt to find JSON array in output if direct parse fails
            # This handles cases where 'zg' or 'aaa' might produce non-JSON output before the JSON result
            functions = _parse_json_output(output)
        except json.JSONDecodeError:
            # If JSON parsing fails, fall back to text parsing
            return failure(
                "PARSE_ERROR",
                "Failed to parse function list from radare2",
                hint="The binary may not be analyzable or may be packed/obfuscated. Try running 'aaa' analysis first.",
            )

        # Categorize functions into library vs user code
        library_functions = []
        user_functions = []

        total_functions = len(functions)
        for idx, func in enumerate(functions):
            # Report progress
            if ctx and idx % 10 == 0:  # Report every 10 functions to avoid spam
                await ctx.report_progress(idx, total_functions)
            
            name = func.get("name", "")
            # Support both 'offset' (aflj) and 'vaddr' (isj) keys
            # Fallback to 'realname' or other identifiers if needed
            offset = func.get("offset", func.get("vaddr", 0))
            
            # If offset is 0, try to parse it from the name if it looks like sym.func.0x...
            if offset == 0 and name:
                # Try to find hex address in name
                import re
                hex_match = re.search(r"(?:0x)?([0-9a-fA-F]{4,})", name)
                if hex_match:
                    try:
                        offset = int(hex_match.group(1), 16)
                    except ValueError:
                        pass

            # Heuristic: library functions typically have names like:
            # - sym.imp.* (imports)
            # - sym.std::* (C++ standard library)
            # - Known library prefixes
            is_library = (
                name.startswith("sym.imp.")
                or name.startswith("sym.std::")
                or name.startswith("fcn.imp.")
                or "libc" in name.lower()
                or "msvcrt" in name.lower()
                or "kernel32" in name.lower()
            )

            if is_library:
                library_functions.append(
                    {
                        "address": f"0x{offset:x}",
                        "name": name,
                        "library": _extract_library_name(name),
                    }
                )
            else:
                user_functions.append({"address": f"0x{offset:x}", "name": name})
        
        # Final progress report
        if ctx:
            await ctx.report_progress(total_functions, total_functions)

        total_functions = len(functions)
        library_count = len(library_functions)
        user_count = len(user_functions)

        # Calculate noise reduction percentage
        noise_reduction = (
            (library_count / total_functions * 100) if total_functions > 0 else 0.0
        )

        # Build result
        result_data = {
            "total_functions": total_functions,
            "library_functions": library_count,
            "user_functions": user_count,
            "noise_reduction_percentage": round(noise_reduction, 2),
            "library_matches": library_functions[
                :50
            ],  # Limit to first 50 for readability
            "user_function_list": [
                f["address"] for f in user_functions[:100]
            ],  # First 100 user functions
            "summary": f"Filtered out {library_count} library functions ({noise_reduction:.1f}% noise reduction). Focus analysis on {user_count} user functions.",
            "signature_db_used": signature_db if signature_db else "built-in",
        }

        if library_count == 0:
            result_data["hint"] = (
                "No library functions matched. This could mean: "
                "1. No signatures loaded (check signature_db). "
                "2. Binary uses statically linked libraries not in DB. "
                "3. Binary is fully custom."
            )

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            total_functions=total_functions,
            library_functions=library_count,
            user_functions=user_count,
            noise_reduction=round(noise_reduction, 2),
        )

    except Exception as e:
        return failure(
            "LIBRARY_MATCH_ERROR",
            f"Library signature matching failed: {str(e)}",
            hint="Ensure the binary is valid and radare2 signature databases are available. For custom databases, verify the .sig file format.",
        )


@lru_cache(maxsize=256)
def _extract_library_name(function_name: str) -> str:
    """
    Extract library name from function name.
    
    Cached to avoid repeated string comparisons for common function names.

    Args:
        function_name: Function name (e.g., "sym.imp.strcpy")

    Returns:
        Extracted library name or "unknown"
    """
    # Simple heuristic extraction
    if "kernel32" in function_name.lower():
        return "kernel32"
    elif "msvcrt" in function_name.lower() or "libc" in function_name.lower():
        return "libc/msvcrt"
    elif "std::" in function_name:
        return "libstdc++"
    elif "imp." in function_name:
        return "import"
    else:
        return "unknown"


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
    return " ".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))


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
    return Path(file_path).stem.replace("-", "_").replace(".", "_")


@lru_cache(maxsize=128)
def _get_r2_project_name(file_path: str) -> str:
    """Generate a unique project name based on file path hash.
    
    Cached to avoid repeated MD5 computation for the same file path.
    """
    # Use absolute path to ensure uniqueness
    abs_path = str(Path(file_path).resolve())
    return hashlib.md5(abs_path.encode()).hexdigest()


@lru_cache(maxsize=128)
def _calculate_dynamic_timeout(file_path: str, base_timeout: int = 300) -> int:
    """
    Calculate timeout based on file size.
    Strategy: Base timeout + 1 second per MB of file size.
    
    Cached to avoid repeated file stat calls for the same file.
    """
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        # Cap the dynamic addition to avoid extremely long timeouts (e.g. max +10 mins)
        additional_time = min(size_mb * 2, 600) 
        return int(base_timeout + additional_time)
    except Exception:
        return base_timeout


async def _execute_r2_command(
    file_path: Path,
    r2_commands: list[str],
    analysis_level: str = "aaa",
    max_output_size: int = 10_000_000,
    base_timeout: int = 300,
) -> tuple[str, int]:
    """
    Execute radare2 commands using the persistent connection pool.
    """
    logger = get_logger(__name__)
    effective_timeout = _calculate_dynamic_timeout(str(file_path), base_timeout)
    
    # Prepare commands
    cmds = []
    if analysis_level and analysis_level != "-n":
        # Check if already analyzed
        if r2_pool.is_analyzed(str(file_path)):
            # Skip 'aaa' if already analyzed
            pass
        else:
            # Run analysis and mark as analyzed
            cmds.append(analysis_level)
            # We can't easily mark it here because we haven't run it yet.
            # But we can assume if this command succeeds, it will be analyzed.
            # However, r2_pool.execute runs it.
            # We'll mark it after successful execution.
            
    cmds.extend(r2_commands)
    full_cmd = ";".join(cmds)
    
    try:
        # Execute via pool with timeout
        output = await asyncio.wait_for(
            r2_pool.execute_async(str(file_path), full_cmd),
            timeout=effective_timeout
        )
        
        # Mark analyzed if we ran analysis
        if analysis_level and analysis_level != "-n" and not r2_pool.is_analyzed(str(file_path)):
             r2_pool.mark_analyzed(str(file_path))
        
        # Handle output size limit
        if len(output) > max_output_size:
            output = output[:max_output_size] + "... (truncated)"
            
        return output, len(output)
        
    except asyncio.TimeoutError:
        raise ToolExecutionError(f"Radare2 command timed out after {effective_timeout}s")
    except Exception as e:
        logger.error(f"R2 execution failed: {e}")
        raise ToolExecutionError(f"Radare2 execution failed: {str(e)}")


def _build_r2_cmd(file_path: str, r2_commands: list[str], analysis_level: str = "aaa") -> list[str]:
    """
    Build radare2 command.
    
    Simplified version: Always run analysis if requested, skipping project persistence
    to avoid permission issues and 'exit 1' errors in Docker environments.
    
    Performance Note - Early Filtering:
    ===================================
    When searching for specific data, consider using radare2's built-in filtering
    to reduce data transfer and parsing overhead. Examples:
    
    1. Text-based filtering with grep (~):
       - aflj~main       # Filter functions containing "main" (WARNING: breaks JSON)
       - afl~main        # Text-mode filtering (safe, but not JSON)
       - iz~password     # Filter strings containing "password"
    
    2. Radare2's native JSON queries (where available):
       - Some commands support inline filtering in JSON mode
       - Check radare2 documentation for specific command capabilities
    
    3. Trade-offs:
       - Early filtering: Reduces data transfer by 50-70%
       - Late filtering: Preserves JSON structure, more flexible
       - Current implementation: Prioritizes JSON structure integrity
    
    For complex filtering logic (e.g., checking multiple conditions, prefix matching),
    Python-side filtering is more maintainable and flexible.
    """
    base_cmd = ["r2", "-q"]
    
    # If we just want to run commands without analysis (adaptive analysis)
    if analysis_level == "-n":
        return base_cmd + ["-n"] + ["-c", ";".join(r2_commands), str(file_path)]
        
    # Always run analysis + commands
    # We use 'e scr.color=0' to ensure no color codes in output
    combined_cmds = ["e scr.color=0", analysis_level] + r2_commands
    return base_cmd + ["-c", ";".join(combined_cmds), str(file_path)]



def _resolve_address(proj, addr_str):
    """Helper to resolve address string to integer using angr project."""
    if not addr_str:
        return None
    
    # Try hex
    if addr_str.startswith("0x"):
        try:
            return int(addr_str, 16)
        except ValueError:
            pass
            
    # Try symbol
    try:
        sym = proj.loader.main_object.get_symbol(addr_str)
        if sym:
            return sym.rebased_addr
    except Exception:
        pass
        
    # Try integer
    try:
        return int(addr_str)
    except ValueError:
        pass
        
    return None


def _extract_first_json(text: str) -> str | None:
    """
    Extract the first valid JSON object or array from a string.
    Handles nested structures and ignores surrounding garbage.
    
    PERFORMANCE NOTE: Optimized to O(n) by minimizing redundant scanning.
    Uses early bailout conditions when a bracket is followed only by
    whitespace and more brackets (pathological case: "{ { { { {").
    
    Returns:
        The extracted JSON string, or None if no valid JSON found.
    """
    text = text.strip()
    if not text:
        return None
    
    # Quick optimization: Try parsing the whole string first
    # This handles the common case where output is pure JSON
    if text[0] in ('{', '['):
        try:
            json.loads(text)
            return text
        except json.JSONDecodeError:
            pass
    
    # Need to extract JSON from noisy output
    i = 0
    text_len = len(text)
    
    while i < text_len:
        char = text[i]
        
        # Skip non-JSON start characters
        if char not in ('{', '['):
            i += 1
            continue
        
        # Found potential JSON start
        # Quick heuristic: Skip obvious false starts (isolated brackets)
        # This prevents pathological O(n²) behavior with "{ { { { {..." patterns
        # Note: We only check for same bracket type to avoid false positives.
        # Mixed brackets like "{ [" could be valid JSON like `{"arr": [...]}`
        if i + 1 < text_len and text[i + 1] in (' ', '\t'):
            # Bracket followed by whitespace - check if next non-whitespace is also a bracket
            next_idx = i + 2
            while next_idx < text_len and text[next_idx] in (' ', '\t', '\n', '\r'):
                next_idx += 1
            if next_idx < text_len and text[next_idx] == char:
                # Pattern like "{ {" or "[ [" with only whitespace between
                # This is likely noise, not JSON - skip it
                i += 1
                continue
        
        # Try to extract JSON starting from this position
        stack = []
        start_idx = i
        in_string = False
        escape_next = False
        j = i
        
        while j < text_len:
            c = text[j]
            
            # Handle string literals (quotes can contain brackets)
            if escape_next:
                escape_next = False
                j += 1
                continue
                
            if c == '\\' and in_string:
                escape_next = True
                j += 1
                continue
                
            if c == '"':
                in_string = not in_string
                j += 1
                continue
            
            # Process brackets only when not inside strings
            if not in_string:
                if c in ('{', '['):
                    stack.append(c)
                elif c in ('}', ']'):
                    if not stack:
                        # Unmatched closing bracket
                        break
                    
                    last = stack[-1]
                    if (c == '}' and last == '{') or (c == ']' and last == '['):
                        stack.pop()
                        if not stack:
                            # Found complete structure, validate it's actually JSON
                            candidate = text[start_idx : j + 1]
                            try:
                                json.loads(candidate)  # Validate it's real JSON
                                return candidate
                            except json.JSONDecodeError:
                                # Not valid JSON, skip past this failed attempt
                                # Optimization: Jump to position j+1 (where extraction stopped)
                                # instead of just i+1, avoiding re-processing characters
                                i = j + 1
                                break
                    else:
                        # Mismatched brackets
                        break
            
            j += 1
        
        # Move past this failed attempt
        if i == start_idx:
            i += 1
    
    return None


def _parse_json_output(output: str):
    """
    Safely parse JSON from command output.
    
    Tries to extract JSON from output that may contain non-JSON text
    (like warnings, debug messages, etc.) and parse it.
    
    Args:
        output: Raw command output that may contain JSON
        
    Returns:
        Parsed JSON object (dict/list) or None if parsing fails
        
    Raises:
        json.JSONDecodeError: If JSON is found but invalid
    """
    # First, try to extract clean JSON from potentially noisy output
    json_str = _extract_first_json(output)
    
    if json_str is not None:
        # Found potential JSON, try to parse it
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Extracted text wasn't valid JSON (e.g., "[x]" from radare2 output)
            # Fall through to try parsing entire output
            pass
    
    # No valid JSON structure found via extraction, try parsing entire output as-is
    # This handles cases where output is pure JSON without any prefix/suffix
    return json.loads(output)


def _validate_address_or_fail(address: str, param_name: str = "address") -> Optional[ToolResult]:
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
    try:
        validate_address_format(address, param_name)
        return None  # Validation passed
    except ValidationError as e:
        return failure("VALIDATION_ERROR", str(e))


@log_execution(tool_name="solve_path_constraints")
@track_metrics("solve_path_constraints")
@handle_tool_errors
async def solve_path_constraints(
    file_path: str,
    start_address: str,
    target_address: str,
    avoid_address: str = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Find an execution path from start to target address using symbolic execution.

    This tool uses the 'angr' binary analysis framework to mathematically prove
    reachability and generate inputs that trigger specific code paths.

    **Use Cases:**
    - **CTF Challenges**: Find the input that reaches the "Win" function
    - **Exploit Development**: Generate input to reach a vulnerable buffer overflow
    - **Bug Triage**: Verify if a crash is reachable from the entry point

    Args:
        file_path: Path to the binary file
        start_address: Address to start symbolic execution (e.g., 'main', '0x401000')
        target_address: Address to reach (e.g., 'sym.win', '0x401050')
        avoid_address: Optional address to avoid (e.g., 'sym.fail', '0x401060')
        timeout: Execution timeout in seconds (default: 300)

    Returns:
        ToolResult with the solution (input) that satisfies the path constraints.
    """
    # 1. Validate parameters
    validate_tool_parameters(
        "solve_path_constraints",
        {"start_address": start_address, "target_address": target_address},
    )
    validated_path = validate_file_path(file_path)

    # 2. Run angr in a separate thread (it's CPU bound and blocking)
    def run_angr_solve():
        try:
            import angr
            import claripy
        except ImportError:
            return {"found": False, "error": "angr or claripy not installed"}

        # Create project
        try:
            proj = angr.Project(str(validated_path), auto_load_libs=False)
        except Exception as e:
            return {"found": False, "error": f"Failed to load binary with angr: {e}"}

        # Resolve addresses if they are symbols
        start_addr = _resolve_address(proj, start_address)
        target_addr = _resolve_address(proj, target_address)
        avoid_addr = _resolve_address(proj, avoid_address) if avoid_address else None

        if start_addr is None:
            return {"found": False, "error": f"Could not resolve start address: {start_address}"}
        if target_addr is None:
            return {"found": False, "error": f"Could not resolve target address: {target_address}"}

        # Create simulation state
        try:
            state = proj.factory.blank_state(addr=start_addr)
        except Exception as e:
            return {"found": False, "error": f"Failed to create state: {e}"}
        
        # Create simulation manager
        simgr = proj.factory.simulation_manager(state)

        # Define exploration technique
        find_args = {"find": target_addr}
        if avoid_addr:
            find_args["avoid"] = avoid_addr

        # Explore
        try:
            simgr.explore(**find_args)
        except Exception as e:
            return {"found": False, "error": f"Exploration failed: {e}"}

        if simgr.found:
            found_state = simgr.found[0]
            # Generate input (stdin)
            # This is a simplification; often we need to constrain stdin specifically
            # But for blank_state, we might check what was read.
            # For now, let's return the stdin if it was constrained, or just the state info.
            
            try:
                solution = found_state.posix.dumps(0) # Dump stdin
                return {
                    "found": True,
                    "input_hex": solution.hex(),
                    "input_str": str(solution), # Best effort string representation
                    "stdout": found_state.posix.dumps(1).decode(errors='ignore')
                }
            except Exception as e:
                 return {"found": True, "input_hex": "", "input_str": "Error dumping input", "stdout": ""}
        else:
            return {"found": False, "reason": "No path found to target"}

    try:
        # Run with timeout
        result = await asyncio.to_thread(run_angr_solve)
        
        if result.get("error"):
             return failure("SYMBOLIC_EXECUTION_ERROR", result["error"])

        if result["found"]:
            return success(
                result,
                format="json",
                description=f"Found path from {start_address} to {target_address}. Input: {result.get('input_hex')}"
            )
        else:
            return failure(
                "PATH_NOT_FOUND",
                f"No execution path found from {start_address} to {target_address}",
                hint="Check if the target is actually reachable or if constraints are too strict."
            )

    except Exception as e:
        return failure(
            "SYMBOLIC_EXECUTION_ERROR",
            f"Angr execution failed: {str(e)}",
            hint="Symbolic execution is complex. Ensure addresses are correct and the binary is compatible."
        )


# ============================================================================
# AI-Powered Tools (Using LLM Sampling)
# ============================================================================

@log_execution(tool_name="analyze_with_ai")
@track_metrics("analyze_with_ai")
@handle_tool_errors
async def analyze_with_ai(
    file_path: str,
    question: str,
    ctx: Context = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Ask AI to analyze specific aspects of a binary.
    
    This tool leverages LLM sampling to get AI's opinion on ambiguous data.
    Use this when automated analysis produces unclear results and you need
    AI interpretation.
    
    **Use Cases:**
    - Identifying obfuscation techniques: "Is this function obfuscated?"
    - Naming suggestions: "What would be a good name for this function?"
    - Pattern recognition: "Does this look like malware behavior?"
    
    Args:
        file_path: Path to the binary file
        question: Question to ask AI about the binary
        ctx: FastMCP Context for AI sampling (auto-injected)
        timeout: Execution timeout in seconds
    
    Returns:
        ToolResult with AI's analysis
    """
    validated_path = validate_file_path(file_path)
    
    if not ctx:
        return failure(
            "NO_CONTEXT",
            "AI sampling requires Context parameter",
            hint="This tool needs to be called from an MCP client that supports sampling"
        )
    
    try:
        # 1. Get basic info about the file
        file_info_result = await run_file(str(validated_path))
        file_info = file_info_result.content[0].text if file_info_result.content else "Unknown"
        
        # 2. Get strings sample
        strings_result = await run_strings(str(validated_path), max_output_size=100_000)
        strings_sample = (strings_result.content[0].text if strings_result.content else "")[:5000]  # First 5KB
        
        # 3. Ask AI via sampling
        prompt = f"""You are a reverse engineering expert analyzing a binary file.

File: {validated_path.name}
Type: {file_info}

Sample strings from the binary:
```
{strings_sample}
```

Question: {question}

Please provide a concise, technical analysis based on the available information.
"""
        
        response = await ctx.sample(
            messages=[{
                "role": "user",
                "content": prompt
            }],
            max_tokens=500
        )
        
        ai_analysis = response.content.text if hasattr(response.content, 'text') else str(response.content)
        
        return success(
            ai_analysis,
            question=question,
            file=validated_path.name,
            description=f"AI analysis completed for: {question}"
        )
        
    except Exception as e:
        return failure(
            "AI_SAMPLING_ERROR",
            f"AI sampling failed: {str(e)}",
            hint="Ensure the MCP client supports sampling feature"
        )


@log_execution(tool_name="suggest_function_name")
@track_metrics("suggest_function_name")
@handle_tool_errors
async def suggest_function_name(
    file_path: str,
    function_address: str,
    ctx: Context = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Use AI to suggest a meaningful name for a function based on its code.
    
    This tool decompiles a function and asks AI to suggest a descriptive name
    based on the logic and patterns in the code.
    
    Args:
        file_path: Path to the binary file
        function_address: Function address to analyze
        ctx: FastMCP Context for AI sampling (auto-injected)
        timeout: Execution timeout in seconds
    
    Returns:
        ToolResult with suggested function name and reasoning
    """
    validated_path = validate_file_path(file_path)
    
    if not ctx:
        return failure(
            "NO_CONTEXT",
            "AI sampling requires Context parameter",
            hint="This tool needs to be called from an MCP client that supports sampling"
        )
    
    try:
        # 1. Decompile the function
        decompile_result = await smart_decompile(
            str(validated_path),
            function_address,
            use_ghidra=True
        )
        
        if decompile_result.is_error:
            return decompile_result
        
        code = decompile_result.content[0].text if decompile_result.content else decompile_result.data
        
        # 2. Ask AI for name suggestion
        prompt = f"""You are a reverse engineering expert. Analyze this decompiled function and suggest a descriptive function name.

Decompiled code:
```c
{code[:2000]}  // Showing first 2000 chars
```

Based on the code logic, suggest:
1. A concise function name (e.g., decrypt_config, send_http_request)
2. Brief reasoning (1 sentence)

Format your response as:
Name: <function_name>
Reason: <why this name>
"""
        
        response = await ctx.sample(
            messages=[{
                "role": "user",
                "content": prompt
            }],
            max_tokens=150
        )
        
        ai_suggestion = response.content.text if hasattr(response.content, 'text') else str(response.content)
        
        return success(
            ai_suggestion,
            function_address=function_address,
            description=f"AI suggested name for function @ {function_address}"
        )
        
    except Exception as e:
        return failure(
            "NAMING_SUGGESTION_ERROR",
            f"Failed to suggest function name: {str(e)}",
            hint="Ensure the function can be decompiled and client supports sampling"
        )
