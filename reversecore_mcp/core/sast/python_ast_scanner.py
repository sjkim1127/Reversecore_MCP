"""
Python AST Scanner.

This module parses Python source files into Abstract Syntax Trees (AST) and
performs precise structural checks against SAST rules to minimize false positives.
"""

from __future__ import annotations

import ast
from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.sast.rule_manager import SASTRule

logger = get_logger(__name__)


def _resolve_name(expr: ast.expr) -> str | None:
    """Recursively resolve the full name of a function call attribute (e.g., os.system)."""
    if isinstance(expr, ast.Name):
        return expr.id
    elif isinstance(expr, ast.Attribute):
        val = _resolve_name(expr.value)
        if val:
            return f"{val}.{expr.attr}"
    return None


class SASTASTVisitor(ast.NodeVisitor):
    """AST visitor that checks nodes against security rules."""

    def __init__(self, rules: list[SASTRule], code_lines: list[str]) -> None:
        self.rules = rules
        self.code_lines = code_lines
        self.findings: list[dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect all function calls in the Python AST."""
        call_name = _resolve_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        for rule in self.rules:
            if rule.match_type != "ast" or rule.language != "python":
                continue

            matched = False

            # Check general call matches
            if call_name == rule.pattern:
                # Specific checks for subprocess shell execution
                if call_name in (
                    "subprocess.Popen",
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.check_output",
                    "subprocess.check_call",
                ):
                    # Flag only if shell=True is present
                    has_shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                has_shell_true = True
                    if has_shell_true:
                        matched = True

                # Specific checks for yaml.load
                elif call_name == "yaml.load":
                    # Flag regardless of Loader since safe_load is preferred,
                    # but check if they explicitly passed SafeLoader to avoid false positives.
                    is_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            loader_name = _resolve_name(kw.value)
                            if loader_name in ("yaml.SafeLoader", "SafeLoader"):
                                is_safe_loader = True
                    if not is_safe_loader:
                        matched = True

                else:
                    # Regular name match (e.g. eval, exec, pickle.loads, os.system)
                    matched = True

            if matched:
                line_idx = node.lineno
                line_content = (
                    self.code_lines[line_idx - 1].strip()
                    if 0 < line_idx <= len(self.code_lines)
                    else ""
                )
                self.findings.append(
                    {
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "category": rule.category,
                        "pattern": rule.pattern,
                        "message": rule.message,
                        "line": line_idx,
                        "code": line_content,
                    }
                )

        self.generic_visit(node)


class PythonASTScanner:
    """Scanner that parses Python code and executes AST-based checks."""

    def scan(self, code: str, rules: list[SASTRule]) -> list[dict[str, Any]]:
        """Scan Python code string for vulnerabilities using AST visitor."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.warning(f"AST parsing failed due to SyntaxError: {e}. Falling back to regex.")
            # We return empty findings to let the caller fallback to RegexScanner
            return []

        code_lines = code.splitlines()
        visitor = SASTASTVisitor(rules, code_lines)
        visitor.visit(tree)
        return visitor.findings
