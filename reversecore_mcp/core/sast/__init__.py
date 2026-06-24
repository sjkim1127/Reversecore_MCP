"""SAST (Static Application Security Testing) Core Package."""

from reversecore_mcp.core.sast.rule_manager import SASTRule, rule_manager

__all__ = ["SASTRule", "rule_manager"]
