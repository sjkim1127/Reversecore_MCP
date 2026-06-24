"""
SAST Rule Manager.

This module is responsible for loading, parsing, and caching SAST rules from
YAML configuration files. It supports custom overrides via config settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class SASTRule:
    """Represents a single static analysis security testing (SAST) rule."""

    id: str
    language: str
    severity: str
    pattern: str
    match_type: str  # "regex" or "ast"
    category: str
    message: str


class SASTRuleManager:
    """Loads, caches, and filters security audit rules from YAML files."""

    def __init__(self) -> None:
        self._rules: list[SASTRule] = []
        self._loaded: bool = False

    def load_rules(self) -> None:
        """Load SAST rules from the configured file path or package defaults."""
        self._rules = []
        rules_path: Path | None = None

        # 1. Check custom path from settings
        try:
            config = get_config()
            if config.sast_rules_path:
                custom_path = Path(config.sast_rules_path)
                if custom_path.exists() and custom_path.is_file():
                    rules_path = custom_path
                    logger.info(f"Loading custom SAST rules from {rules_path}")
                else:
                    logger.warning(
                        f"Custom SAST rules path '{config.sast_rules_path}' not found. Falling back to defaults."
                    )
        except Exception as e:
            logger.debug(f"Error reading configuration for SAST rules: {e}")

        # 2. Fall back to package defaults
        if not rules_path:
            rules_path = Path(__file__).parent / "default_rules.yaml"
            logger.info(f"Loading default SAST rules from {rules_path}")

        try:
            with open(rules_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "rules" not in data:
                logger.warning(f"No rules found in {rules_path}")
                self._loaded = True
                return

            for item in data["rules"]:
                rule = SASTRule(
                    id=str(item.get("id", "")),
                    language=str(item.get("language", "")).lower(),
                    severity=str(item.get("severity", "medium")).lower(),
                    pattern=str(item.get("pattern", "")),
                    match_type=str(item.get("match_type", "regex")).lower(),
                    category=str(item.get("category", "General")),
                    message=str(item.get("message", "")),
                )
                if rule.id and rule.pattern:
                    self._rules.append(rule)
                else:
                    logger.warning(f"Skipping invalid SAST rule: {item}")

            logger.info(f"Successfully loaded {len(self._rules)} SAST rules.")
        except Exception as e:
            logger.error(f"Failed to load SAST rules from {rules_path}: {e}")
            # Ensure we don't crash the server, but log it

        self._loaded = True

    def get_all_rules(self) -> list[SASTRule]:
        """Return all loaded rules, loading them if not already done."""
        if not self._loaded:
            self.load_rules()
        return self._rules

    def get_rules_for_language(self, language: str) -> list[SASTRule]:
        """Return rules filtered by target programming language (case-insensitive)."""
        if not self._loaded:
            self.load_rules()

        target_lang = language.lower()
        # Normalise common variants
        if target_lang in ("c++", "cpp", "h", "hpp"):
            target_lang = "c"

        return [r for r in self._rules if r.language == target_lang]

    def reset(self) -> None:
        """Clear cached rules. Useful for testing."""
        self._rules = []
        self._loaded = False


# Global singleton instance
rule_manager = SASTRuleManager()
