"""Unit tests for auto_planning_mode prompt."""

from __future__ import annotations

from reversecore_mcp.prompts.common import DOCKER_PATH_RULE, LANGUAGE_RULE
from reversecore_mcp.prompts.planning import auto_planning_mode


class TestPlanningPrompts:
    """Tests for planning prompt generation."""

    def test_auto_planning_mode_defaults(self):
        text = auto_planning_mode()
        assert "recommend_analysis_plan" in text
        assert "malware_triage" in text
        assert "standard" in text
        assert DOCKER_PATH_RULE in text
        assert LANGUAGE_RULE in text

    def test_auto_planning_mode_custom_params(self):
        text = auto_planning_mode(
            target_file="malware.bin",
            objective="vulnerability_research",
            depth="deep",
        )
        assert "malware.bin" in text
        assert "vulnerability_research" in text
        assert "deep" in text
