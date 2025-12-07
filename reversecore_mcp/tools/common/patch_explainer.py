"""
Semantic Patch Explainer: Analyzes differences between binaries to explain security patches.
"""

import difflib
from typing import Any

from fastmcp import Context

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.plugin import Plugin
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.ghidra import decompilation, diff_tools

logger = get_logger(__name__)


class PatchExplainerPlugin(Plugin):
    """Plugin for Semantic Patch Explainer tool."""

    @property
    def name(self) -> str:
        return "patch_explainer"

    @property
    def description(self) -> str:
        return "Analyzes binary differences to explain security patches in natural language."

    def register(self, mcp_server: Any) -> None:
        """Register Patch Explainer tool."""
        mcp_server.tool(explain_patch)


@log_execution(tool_name="explain_patch")
@track_metrics("explain_patch")
@handle_tool_errors
async def explain_patch(
    file_path_a: str,
    file_path_b: str,
    function_name: str = None,
    ctx: Context = None,
) -> ToolResult:
    """
    Analyze differences between two binaries and explain changes in natural language.

    This tool combines binary diffing with decompilation to help understand security patches.
    It identifies changed functions, decompiles them, and uses heuristics to explain
    the nature of the changes (e.g., "Added bounds check", "Replaced unsafe API").

    Args:
        file_path_a: Path to the original binary (e.g., vulnerable version).
        file_path_b: Path to the modified binary (e.g., patched version).
        function_name: Optional specific function to analyze. If None, analyzes top changes.
        ctx: FastMCP Context (auto-injected).

    Returns:
        ToolResult containing the explanation report.
    """
    path_a = validate_file_path(file_path_a)
    path_b = validate_file_path(file_path_b)

    if ctx:
        await ctx.info(f"🔍 Analyzing patch: {path_a.name} -> {path_b.name}")

    # 1. Diff Binaries
    if ctx:
        await ctx.info("📊 Diffing binaries to find changed functions...")

    diff_result = await diff_tools.diff_binaries(
        str(path_a), str(path_b), function_name=function_name
    )

    if diff_result.status != "success":
        return failure(
            error_code="DIFF_FAILED",
            message=f"Binary diff failed: {diff_result.message}",
        )

    changes = diff_result.data.get("changes", [])
    if not changes:
        return success(
            {
                "summary": "No significant code changes detected.",
                "changes": [],
            }
        )

    # Filter for code changes (ignore new/deleted functions for now, focus on modified)
    modified_funcs = []
    if function_name:
        # If specific function requested, use it
        modified_funcs.append(
            {"address": function_name, "name": function_name}
        )  # Address might be name here
    else:
        # Extract function names/addresses from changes
        # diff_binaries returns list of changes. We need to map them to functions.
        # For simplicity, let's assume we can get a list of changed function addresses/names.
        # Since diff_binaries output format might vary, let's rely on what we have.
        # If diff_binaries returns a list of changes, we might need to parse it.
        # BUT, diff_tools.diff_binaries returns a structured JSON.
        # Let's assume for this implementation we pick top 3 changed functions if not specified.
        # To do this properly, we might need a helper to map changes to functions.
        # For now, let's try to analyze the function specified or warn if none.
        pass

    # If no function specified, we need to identify WHICH functions changed.
    # diff_binaries might return raw offsets.
    # Let's use a simpler approach: If function_name is None, we ask the user to specify one
    # OR we try to find it.
    # Actually, `diff_binaries` output has "address". We can try to resolve it to a name.

    target_functions = []
    if function_name:
        target_functions.append(function_name)
    else:
        # Heuristic: Pick the first few changed addresses that look like functions
        # This is a simplification. In a real scenario, we'd map offsets to symbols.
        # For now, let's just take the first 3 unique addresses from changes.
        seen = set()
        for change in changes:
            addr = change.get("address")
            if addr and addr not in seen:
                target_functions.append(addr)
                seen.add(addr)
            if len(target_functions) >= 3:
                break

    if not target_functions:
        return success({"summary": "No changed functions identified to analyze."})

    explanations = []

    for func in target_functions:
        if ctx:
            await ctx.info(f"🧠 Analyzing function: {func}...")

        # 2. Decompile Both Versions
        # We use smart_decompile (which uses Ghidra/r2)
        # Note: We need to handle the case where function exists in both.

        # Decompile A
        res_a = await decompilation.smart_decompile(str(path_a), str(func))
        code_a = res_a.data if res_a.status == "success" else ""

        # Decompile B
        res_b = await decompilation.smart_decompile(str(path_b), str(func))
        code_b = res_b.data if res_b.status == "success" else ""

        if not code_a or not code_b:
            explanations.append(
                {"function": func, "error": "Failed to decompile one or both versions."}
            )
            continue

        # 3. Compare and Explain
        explanation = _generate_explanation(code_a, code_b)
        explanations.append(
            {
                "function": func,
                "explanation": explanation,
                "diff_snippet": _generate_diff_snippet(code_a, code_b),
            }
        )

    return success(
        {"summary": f"Analyzed {len(explanations)} function(s).", "explanations": explanations}
    )


def _generate_explanation(code_a: str, code_b: str) -> dict:
    """
    Heuristically explain changes between two code snippets.
    """
    explanation = {"summary": "Code structure changed.", "details": []}

    # Normalize code (remove whitespace changes)
    lines_a = [line.strip() for line in code_a.splitlines() if line.strip()]
    lines_b = [line.strip() for line in code_b.splitlines() if line.strip()]

    # 1. Check for Added Conditions (Security Checks)
    # Heuristic: More 'if' statements in B than A
    if_count_a = sum(1 for line in lines_a if line.startswith("if"))
    if_count_b = sum(1 for line in lines_b if line.startswith("if"))

    if if_count_b > if_count_a:
        explanation["details"].append(
            "🛡️ **Added Security Check**: New conditional logic detected (likely bounds check or validation)."
        )
        explanation["summary"] = "Security checks were added."

    # 2. Check for API Replacements
    # Common safe replacements
    replacements = [
        ("strcpy", "strncpy", "Replaced unsafe string copy with bounded copy."),
        ("sprintf", "snprintf", "Replaced unsafe format string with bounded version."),
        ("gets", "fgets", "Replaced dangerous input function."),
        ("memcpy", "memcpy_s", "Replaced memory copy with secure version."),
    ]

    code_a_str = " ".join(lines_a)
    code_b_str = " ".join(lines_b)

    for old, new, msg in replacements:
        if old in code_a_str and new in code_b_str:
            explanation["details"].append(f"🔄 **API Hardening**: {msg} (`{old}` -> `{new}`)")
            explanation["summary"] = "Unsafe APIs were replaced."

    # 3. Check for Integer Overflow Checks
    # Look for patterns like (a > MAX - b) or specific constants
    if "MAX" in code_b_str and "MAX" not in code_a_str:
        explanation["details"].append(
            "🔢 **Integer Overflow Check**: Potential overflow check added using MAX constants."
        )

    # 4. Check for Logic Removal
    if len(lines_b) < len(lines_a) * 0.8:
        explanation["details"].append(
            "✂️ **Logic Removal**: Significant portion of code was removed (dead code or feature removal)."
        )

    if not explanation["details"]:
        explanation["details"].append("ℹ️ Logic modified without obvious security patterns.")

    return explanation


def _generate_diff_snippet(code_a: str, code_b: str, context: int = 3) -> str:
    """Generate a unified diff snippet."""
    a_lines = code_a.splitlines()
    b_lines = code_b.splitlines()

    diff = difflib.unified_diff(
        a_lines, b_lines, fromfile="Original", tofile="Patched", n=context, lineterm=""
    )

    # Convert generator to string, limit length
    diff_text = "\n".join(list(diff)[:50])  # Limit to 50 lines
    return diff_text
