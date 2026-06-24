"""
Regex Scanner.

This module provides line-by-line regular expression matching against SAST rules.
It includes optimizations like precompiled regex caching and basic comment-line filtering.
"""

from __future__ import annotations

import re
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.sast.rule_manager import SASTRule

logger = get_logger(__name__)


class RegexScanner:
    """Line-by-line regex scanner for source code auditing."""

    def scan(self, code: str, rules: list[SASTRule]) -> list[dict[str, Any]]:
        """Scan code string against a list of regex-based SAST rules."""
        findings: list[dict[str, Any]] = []
        lines = code.splitlines()

        # Precompile patterns to ensure performance
        compiled_rules = []
        for rule in rules:
            # We also process AST rules as regex fallback if match_type is not regex
            pattern = rule.pattern
            # If match_type was AST, convert the pattern to a word boundary regex
            if rule.match_type == "ast":
                pattern = rf"\b{re.escape(rule.pattern)}\b"

            try:
                compiled_rules.append((rule, re.compile(pattern)))
            except Exception as e:
                logger.warning(
                    f"Failed to compile regex pattern '{pattern}' for rule {rule.id}: {e}"
                )

        for line_idx, line in enumerate(lines, start=1):
            trimmed = line.strip()

            # Simple heuristic: Skip comment lines to reduce false positives
            if (
                trimmed.startswith("//")
                or trimmed.startswith("/*")
                or trimmed.startswith("#")
                or trimmed.startswith("*")
            ):
                continue

            for rule, regex in compiled_rules:
                if regex.search(line):
                    findings.append(
                        {
                            "rule_id": rule.id,
                            "severity": rule.severity,
                            "category": rule.category,
                            "pattern": rule.pattern,
                            "message": rule.message,
                            "line": line_idx,
                            "code": trimmed,
                        }
                    )

        return findings
