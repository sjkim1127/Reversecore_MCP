"""
Ghidra SAST Extension (Source Code Auditing).

This extension hooks into the Ghidra decompilation pipeline and automatically
runs static analysis heuristics on the generated pseudo-C code to flag
potential vulnerabilities (e.g., buffer overflows, format string bugs).
"""

from __future__ import annotations

import re

from reversecore_mcp.core.extension import GhidraAnalysisContext, GhidraExtensionPoint
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Basic heuristics for fast static detection on Pseudo-C
_DANGEROUS_PATTERNS = {
    "C/C++ Memory": ["strcpy", "sprintf", "gets", "strcat", "memcpy"],
    "Command Injection": ["system", "popen", "execve", "execl"],
    "Format String": ["printf", "fprintf", "syslog"],
}


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

        findings = []
        lines = decompiled_code.split("\n")

        for i, line in enumerate(lines):
            for category, patterns in _DANGEROUS_PATTERNS.items():
                for pattern in patterns:
                    # Look for function calls: pattern(
                    if re.search(r"\b" + re.escape(pattern) + r"\s*\(", line):
                        warning = f"// [🚨 SAST WARNING] {category} risk: '{pattern}' used here"
                        # Insert comment before the line
                        findings.append((i, warning))
                        break

        # Apply warnings in reverse order to not mess up line indices
        for i, warning in sorted(findings, reverse=True):
            lines.insert(i, warning)

        if findings:
            logger.info(f"Injected {len(findings)} SAST warnings into decompiled code.")
            ctx.metadata["sast_warnings"] = len(findings)

        return "\n".join(lines)
