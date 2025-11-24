"""Binary diffing and library matching tools for comparing binaries and identifying library code."""

import re
from functools import lru_cache

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters
from fastmcp import Context

# Import helper functions from r2_analysis
from reversecore_mcp.tools.r2_analysis import (
    _execute_r2_command,
    _build_r2_cmd,
    _parse_json_output,
)

# Load default timeout from configuration
DEFAULT_TIMEOUT = get_config().default_tool_timeout


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
    - **Game Hacking**: Find offset changes after game updates to maintain functionality
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


@log_execution(tool_name="analyze_variant_changes")
@track_metrics("analyze_variant_changes")
@handle_tool_errors
async def analyze_variant_changes(
    file_path_a: str,
    file_path_b: str,
    top_n: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """
    Analyze structural changes between two binary variants (Lineage Mapper).

    This tool combines binary diffing with control flow analysis to understand
    *how* a binary has evolved. It identifies the most modified functions and
    generates their Control Flow Graphs (CFG) for comparison.

    **Use Cases:**
    - **Malware Lineage**: "How did Lazarus Group modify their backdoor?"
    - **Patch Diffing**: "What logic changed in the vulnerable function?"
    - **Variant Analysis**: "Is this a new version of the same malware?"

    Args:
        file_path_a: Path to the original binary
        file_path_b: Path to the variant binary
        top_n: Number of top changed functions to analyze in detail (default: 3)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with diff summary and CFG data for top changed functions.
    """
    # Import here to avoid circular dependency
    from reversecore_mcp.tools.r2_analysis import generate_function_graph

    # 1. Run diff_binaries
    diff_result = await diff_binaries(file_path_a, file_path_b, timeout=timeout)

    if diff_result.is_error:
        return diff_result

    diff_data = json.loads(diff_result.content[0].text)
    changes = diff_data.get("changes", [])

    # 2. Identify changed functions (heuristic: group changes by address proximity or use explicit function diff if available)
    # Since diff_binaries returns a flat list of changes, we'll try to map them to functions.
    # For this advanced tool, we'll assume we want to analyze the functions where changes occurred.

    # Get function list for file B (variant) to map addresses to names
    # We use a simple r2 command to get functions
    validated_path_b = validate_file_path(file_path_b)
    cmd = _build_r2_cmd(str(validated_path_b), ["aflj"], "aaa")
    out, _ = await execute_subprocess_async(cmd, timeout=60)

    try:
        funcs_b = _parse_json_output(out)
    except (json.JSONDecodeError, TypeError):
        funcs_b = []

    # OPTIMIZATION: Pre-sort functions by offset for binary search
    # This reduces O(n*m) to O(n*log(m)) complexity
    # Further optimized to minimize redundant dict.get() calls
    sorted_funcs = []
    for f in funcs_b:
        offset = f.get("offset")
        size = f.get("size")
        name = f.get("name", "unknown")
        if offset is not None and size is not None:
            sorted_funcs.append((offset, offset + size, name))
    sorted_funcs.sort(key=lambda x: x[0])

    # Map changes to functions using binary search
    changed_funcs = {}  # {func_name: count}

    for change in changes:
        addr_str = change.get("address")
        if not addr_str:
            continue
        try:
            addr = int(addr_str, 16)
            # Binary search to find the function containing this address
            left, right = 0, len(sorted_funcs) - 1
            found_func = None

            while left <= right:
                mid = (left + right) // 2
                func_start, func_end, func_name = sorted_funcs[mid]

                if func_start <= addr < func_end:
                    found_func = func_name
                    break
                elif addr < func_start:
                    right = mid - 1
                else:
                    left = mid + 1

            if found_func:
                changed_funcs[found_func] = changed_funcs.get(found_func, 0) + 1
        except ValueError:
            # Invalid hex address format
            pass

    # Sort by number of changes
    sorted_funcs = sorted(changed_funcs.items(), key=lambda x: x[1], reverse=True)[
        :top_n
    ]

    detailed_analysis = []

    # 3. Generate CFG for top changed functions
    for func_name, count in sorted_funcs:
        # Get CFG for variant
        cfg_result = await generate_function_graph(
            file_path_b, func_name, format="mermaid"
        )
        cfg_mermaid = (
            cfg_result.content[0].text
            if not cfg_result.is_error
            else "Error generating CFG"
        )

        detailed_analysis.append(
            {
                "function": func_name,
                "change_count": count,
                "cfg_mermaid": cfg_mermaid,
                "analysis_hint": f"Function {func_name} has {count} modifications. Compare its logic with the original.",
            }
        )

    return success(
        {
            "similarity": diff_data.get("similarity"),
            "total_changes": diff_data.get("total_changes"),
            "top_modified_functions": detailed_analysis,
        },
        description=f"Analyzed variants. Similarity: {diff_data.get('similarity')}. Detailed analysis for {len(detailed_analysis)} functions.",
    )


@log_execution(tool_name="match_libraries")
@track_metrics("match_libraries")
@handle_tool_errors
async def match_libraries(
    file_path: str,
    signature_db: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = 600,
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
        timeout: Timeout in seconds (default: 600s)
        ctx: FastMCP Context (auto-injected)

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

        if ctx:
            await ctx.report_progress(10, 100)
            await ctx.info(
                "Analyzing binary and matching signatures (this may take a while)..."
            )

        # Execute using helper
        # Use 'aa' (basic analysis) instead of 'aaa' to prevent hangs
        analysis_level = "aa"

        output, bytes_read = await _execute_r2_command(
            validated_path,
            r2_commands,
            analysis_level=analysis_level,
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
