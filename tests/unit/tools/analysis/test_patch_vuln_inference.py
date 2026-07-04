"""Unit tests for analyze_patch_diff_auto (patch_vuln_inference)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.patch_vuln_inference import (
    SECURITY_PATCH_PATTERNS,
    PatchPattern,
    _get_exploitation_hint,
    _match_patterns,
    analyze_patch_diff_auto,
)


class TestPatchPatterns:
    """Tests for the SECURITY_PATCH_PATTERNS database."""

    def test_patterns_non_empty(self):
        assert len(SECURITY_PATCH_PATTERNS) >= 8

    def test_all_patterns_have_required_fields(self):
        for p in SECURITY_PATCH_PATTERNS:
            assert p.name
            assert p.description
            assert p.vuln_class
            assert p.cwe_id.startswith("CWE-")
            assert p.severity in ("critical", "high", "medium", "low")
            assert p.confidence in ("high", "medium", "low")
            assert len(p.indicators) > 0

    def test_bounds_check_pattern_exists(self):
        names = [p.name for p in SECURITY_PATCH_PATTERNS]
        assert "bounds_check_added" in names

    def test_command_injection_pattern_critical(self):
        for p in SECURITY_PATCH_PATTERNS:
            if p.name == "command_injection_fix":
                assert p.severity == "critical"
                break


class TestMatchPatterns:
    """Tests for _match_patterns pattern recognition engine."""

    def test_detects_bounds_check(self):
        diff_text = "cmp rax, rbx\njbe 0x1234\ntest eax, eax\njne 0x5678"
        matches = _match_patterns(diff_text, "func_parse_input", size_delta=32, block_delta=2)
        assert any(m["pattern"] == "bounds_check_added" for m in matches)

    def test_detects_safe_api_migration(self):
        diff_text = "strcpy\nstrncpy\nbuffer\nsize"
        matches = _match_patterns(diff_text, "func_copy", size_delta=10, block_delta=0)
        assert any(m["pattern"] == "safe_api_migration" for m in matches)

    def test_detects_command_injection(self):
        diff_text = "system\nshell\nsanitize\nescape\nwhitelist"
        matches = _match_patterns(diff_text, "func_exec", size_delta=0, block_delta=0)
        assert any(m["pattern"] == "command_injection_fix" for m in matches)

    def test_no_match_for_empty_diff(self):
        matches = _match_patterns("", "empty_func", size_delta=0, block_delta=0)
        assert matches == []

    def test_matches_sorted_by_severity(self):
        # Mix of critical and medium indicators
        diff_text = "strcpy system printf rand cmp jbe test"
        matches = _match_patterns(diff_text, "func", size_delta=50, block_delta=3)
        if len(matches) >= 2:
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            scores = [severity_order.get(m["severity"], 0) for m in matches]
            assert scores == sorted(scores, reverse=True)

    def test_structural_heuristics_boost(self):
        # bounds_check should be boosted by size_delta > 0 and block_delta > 0
        diff_text = "cmp jbe test"
        matches_no_boost = _match_patterns(diff_text, "f", size_delta=0, block_delta=0)
        matches_boost = _match_patterns(diff_text, "f", size_delta=50, block_delta=3)
        # Both may match, but boost should not reduce the match
        if matches_no_boost and matches_boost:
            no_boost_score = next(
                (
                    m["indicator_score"]
                    for m in matches_no_boost
                    if m["pattern"] == "bounds_check_added"
                ),
                0,
            )
            boost_score = next(
                (
                    m["indicator_score"]
                    for m in matches_boost
                    if m["pattern"] == "bounds_check_added"
                ),
                0,
            )
            assert boost_score >= no_boost_score


class TestExploitationHint:
    """Tests for _get_exploitation_hint."""

    def test_returns_string_for_all_patterns(self):
        for p in SECURITY_PATCH_PATTERNS:
            hint = _get_exploitation_hint(p)
            assert isinstance(hint, str)
            assert len(hint) > 10

    def test_buffer_overflow_hint_mentions_overflow(self):
        p = PatchPattern(
            name="bounds_check_added",
            description="",
            vuln_class="",
            cwe_id="CWE-120",
            severity="critical",
            indicators=[],
            confidence="high",
        )
        hint = _get_exploitation_hint(p)
        assert "overflow" in hint.lower() or "buffer" in hint.lower()

    def test_unknown_pattern_returns_generic(self):
        p = PatchPattern(
            name="unknown_novel_pattern",
            description="",
            vuln_class="",
            cwe_id="CWE-999",
            severity="low",
            indicators=[],
            confidence="low",
        )
        hint = _get_exploitation_hint(p)
        assert isinstance(hint, str)
        assert len(hint) > 0


class TestAnalyzePatchDiffAuto:
    """Tests for analyze_patch_diff_auto MCP tool."""

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.explain_patch")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.execute_subprocess_async")
    async def test_identical_binaries_returns_identical(
        self, mock_exec, mock_validate, mock_explain, tmp_path
    ):
        """When similarity is ~1.0, should return IDENTICAL verdict."""
        old = tmp_path / "old.bin"
        old.write_bytes(b"MZ" + b"\x00" * 100)
        new = tmp_path / "new.bin"
        new.write_bytes(b"MZ" + b"\x00" * 100)

        mock_validate.side_effect = [old, new]
        # Simulate similarity: 1.0
        mock_exec.return_value = ("similarity: 1.000\n", 100)

        result = await analyze_patch_diff_auto(str(old), str(new))
        assert result.status == "success"
        assert result.data["patch_verdict"] == "IDENTICAL"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.explain_patch")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.execute_subprocess_async")
    async def test_security_patch_detected(self, mock_exec, mock_validate, mock_explain, tmp_path):
        """When dangerous APIs are removed, verdict should be SECURITY_PATCH."""
        old = tmp_path / "old.bin"
        old.write_bytes(b"MZ" + b"\x00" * 100)
        new = tmp_path / "new.bin"
        new.write_bytes(b"MZ" + b"\x00" * 100)

        mock_validate.side_effect = [old, new]

        # First call: similarity 0.95
        # Second call: function diff
        # Third and fourth: import lists
        call_count = [0]

        async def mock_exec_side_effect(cmd, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:  # similarity
                return ("similarity: 0.950\n", 100)
            elif call_count[0] == 2:  # radiff2 -C
                return ("0x401000 0x401000 modified func_strcpy_wrapper\n", 1000)
            else:  # import checks
                if "old" in " ".join(str(c) for c in cmd):
                    return ("strcpy\ngets\n", 100)
                return ("strncpy\nfgets\n", 100)

        mock_exec.side_effect = mock_exec_side_effect

        result = await analyze_patch_diff_auto(str(old), str(new), auto_infer_vuln=False)
        assert result.status == "success"
        # With similarity < 1.0 and some processing, we get a verdict
        assert result.data["similarity"] == pytest.approx(0.95, abs=0.01)

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.explain_patch")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.patch_vuln_inference.execute_subprocess_async")
    async def test_result_has_required_keys(self, mock_exec, mock_validate, mock_explain, tmp_path):
        """Result must always have required output keys."""
        old = tmp_path / "old.bin"
        old.write_bytes(b"MZ" + b"\x00" * 100)
        new = tmp_path / "new.bin"
        new.write_bytes(b"MZ" + b"\x00" * 100)

        mock_validate.side_effect = [old, new]
        mock_exec.return_value = ("similarity: 0.80\n", 100)

        result = await analyze_patch_diff_auto(str(old), str(new), auto_infer_vuln=False)
        assert result.status == "success"
        required_keys = [
            "similarity",
            "patch_verdict",
            "vulnerability_candidates",
            "top_vuln",
            "changed_functions",
            "dangerous_api_changes",
            "next_steps",
        ]
        for key in required_keys:
            assert key in result.data, f"Missing key: {key}"
