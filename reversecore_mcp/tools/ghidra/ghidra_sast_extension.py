"""
Ghidra SAST Extension (Source Code Auditing).

This extension hooks into the Ghidra decompilation pipeline and automatically
runs static analysis heuristics on the generated pseudo-C code to flag
potential vulnerabilities (e.g., buffer overflows, format string bugs).
"""

from __future__ import annotations

from reversecore_mcp.core.extension import GhidraAnalysisContext, GhidraExtensionPoint
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.sast.regex_scanner import RegexScanner
from reversecore_mcp.core.sast.rule_manager import rule_manager

logger = get_logger(__name__)


class GhidraSASTExtension(GhidraExtensionPoint):
    """
    Hooks into Ghidra's decompiler to automatically annotate dangerous APIs.
    """

    name = "ghidra_sast"
    priority = 150  # Run after basic decompilation

    async def on_after_decompile(self, ctx: GhidraAnalysisContext, decompiled_code: str) -> str:
        """
        Scan decompiled pseudo-C code for dangerous APIs and inject warnings
        as comments directly into the code.
        """
        logger.info(f"Running SAST scan on decompiled code for {ctx.function_address}")

        # Get C/C++ rules
        rules = rule_manager.get_rules_for_language("c")

        # Scan decompiler output (which is C code)
        scan_findings = RegexScanner().scan(decompiled_code, rules)

        if not scan_findings:
            return decompiled_code

        # Group warnings by line index (0-based)
        from collections import defaultdict

        line_to_warnings = defaultdict(list)

        for f in scan_findings:
            line_idx = f["line"] - 1  # Convert 1-based line number to 0-based index
            warning = f"// [🚨 SAST WARNING] {f['category']} (Severity: {f['severity'].upper()}): {f['message']}"
            line_to_warnings[line_idx].append(warning)

        # Apply warnings in reverse order to not mess up line indices
        lines = decompiled_code.split("\n")
        total_inserted = 0

        for line_idx in sorted(line_to_warnings.keys(), reverse=True):
            for warning in line_to_warnings[line_idx]:
                lines.insert(line_idx, warning)
                total_inserted += 1

        logger.info(f"Injected {total_inserted} SAST warnings into decompiled code.")
        ctx.metadata["sast_warnings"] = total_inserted

        return "\n".join(lines)
