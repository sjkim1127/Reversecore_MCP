"""Unit tests for goal-aware tool planner subsystem."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.core.planner import (
    AnalysisObjective,
    DepthTier,
    SampleFormat,
    detect_sample_format,
    generate_analysis_plan,
    normalize_depth,
    normalize_objective,
)


class TestPlannerNormalization:
    """Tests for objective and depth normalization."""

    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            ("malware_triage", AnalysisObjective.MALWARE_TRIAGE),
            ("MALWARE", AnalysisObjective.MALWARE_TRIAGE),
            ("threat hunting", AnalysisObjective.MALWARE_TRIAGE),
            ("static_triage", AnalysisObjective.STATIC_TRIAGE),
            ("static", AnalysisObjective.STATIC_TRIAGE),
            ("fingerprint", AnalysisObjective.STATIC_TRIAGE),
            ("vulnerability_research", AnalysisObjective.VULNERABILITY_RESEARCH),
            ("vuln", AnalysisObjective.VULNERABILITY_RESEARCH),
            ("cve", AnalysisObjective.VULNERABILITY_RESEARCH),
            ("exploit", AnalysisObjective.VULNERABILITY_RESEARCH),
            ("unpacking_deobfuscation", AnalysisObjective.UNPACKING_DEOBFUSCATION),
            ("unpacking", AnalysisObjective.UNPACKING_DEOBFUSCATION),
            ("deobf", AnalysisObjective.UNPACKING_DEOBFUSCATION),
            ("incident_reconstruction", AnalysisObjective.INCIDENT_RECONSTRUCTION),
            ("incident", AnalysisObjective.INCIDENT_RECONSTRUCTION),
            ("patch_review", AnalysisObjective.PATCH_REVIEW),
            ("patch-diff", AnalysisObjective.PATCH_REVIEW),
            ("1day", AnalysisObjective.PATCH_REVIEW),
            ("forensics", AnalysisObjective.FORENSICS),
            ("forensic artifact", AnalysisObjective.FORENSICS),
            (None, AnalysisObjective.MALWARE_TRIAGE),
            ("unknown_custom_goal", AnalysisObjective.MALWARE_TRIAGE),
        ],
    )
    def test_normalize_objective(self, input_val: str | None, expected: str):
        assert normalize_objective(input_val) == expected

    @pytest.mark.parametrize(
        ("input_val", "budget", "expected"),
        [
            ("quick", None, DepthTier.QUICK),
            ("fast", None, DepthTier.QUICK),
            ("standard", None, DepthTier.STANDARD),
            ("default", None, DepthTier.STANDARD),
            ("deep", None, DepthTier.DEEP),
            ("thorough", None, DepthTier.DEEP),
            (None, None, DepthTier.STANDARD),
            ("deep", 30, DepthTier.QUICK),  # Budget overrides depth tier
            ("quick", 120, DepthTier.STANDARD),  # Budget overrides depth tier
            ("quick", 400, DepthTier.DEEP),  # Budget overrides depth tier
        ],
    )
    def test_normalize_depth(self, input_val: str | None, budget: int | None, expected: str):
        assert normalize_depth(input_val, time_budget_seconds=budget) == expected


class TestSampleFormatDetection:
    """Tests for file format detection."""

    def test_explicit_format(self):
        assert detect_sample_format(explicit_format="pe") == SampleFormat.PE
        assert detect_sample_format(explicit_format="elf") == SampleFormat.ELF
        assert detect_sample_format(explicit_format="macho") == SampleFormat.MACHO
        assert detect_sample_format(explicit_format="pcap") == SampleFormat.PCAP
        assert detect_sample_format(explicit_format="memory") == SampleFormat.MEMORY
        assert detect_sample_format(explicit_format="disk") == SampleFormat.DISK
        assert detect_sample_format(explicit_format="source") == SampleFormat.SOURCE

    def test_magic_bytes_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)

            pe_file = tmp / "sample1.bin"
            pe_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
            assert detect_sample_format(pe_file) == SampleFormat.PE

            elf_file = tmp / "sample2.bin"
            elf_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            assert detect_sample_format(elf_file) == SampleFormat.ELF

            macho_file = tmp / "sample3.bin"
            macho_file.write_bytes(
                b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x02\x00\x00\x00"
            )
            assert detect_sample_format(macho_file) == SampleFormat.MACHO

            pcap_file = tmp / "sample4.bin"
            pcap_file.write_bytes(
                b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            assert detect_sample_format(pcap_file) == SampleFormat.PCAP

    def test_extension_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            c_file = tmp / "test.c"
            c_file.write_text("int main() { return 0; }")
            assert detect_sample_format(c_file) == SampleFormat.SOURCE

            pcap_file = tmp / "test.pcap"
            pcap_file.write_bytes(b"dummy")
            assert detect_sample_format(pcap_file) == SampleFormat.PCAP

    def test_hint_detection(self):
        assert detect_sample_format(sample_hint="Windows 64-bit PE binary") == SampleFormat.PE
        assert detect_sample_format(sample_hint="Linux ELF shared library") == SampleFormat.ELF
        assert detect_sample_format(sample_hint="Network PCAP capture") == SampleFormat.PCAP
        assert detect_sample_format(sample_hint="Memory RAM dump") == SampleFormat.MEMORY
        assert detect_sample_format(sample_hint="Forensic disk image") == SampleFormat.DISK
        assert detect_sample_format(sample_hint="C/C++ source code audit") == SampleFormat.SOURCE


class TestPlanGenerationInvariants:
    """Tests verifying core invariants required by acceptance criteria."""

    @pytest.mark.parametrize(
        "obj",
        list(AnalysisObjective.ALL),
    )
    @pytest.mark.parametrize(
        "fmt",
        [
            SampleFormat.PE,
            SampleFormat.ELF,
            SampleFormat.PCAP,
            SampleFormat.MEMORY,
            SampleFormat.DISK,
            SampleFormat.SOURCE,
        ],
    )
    def test_nested_scope_invariant(self, obj: str, fmt: str):
        """Acceptance Criterion: quick, standard, and deep produce nested/consistent scopes."""
        plan_quick = generate_analysis_plan(objective=obj, file_format=fmt, depth=DepthTier.QUICK)
        plan_std = generate_analysis_plan(objective=obj, file_format=fmt, depth=DepthTier.STANDARD)
        plan_deep = generate_analysis_plan(objective=obj, file_format=fmt, depth=DepthTier.DEEP)

        tools_quick = [s.tool for s in plan_quick.primary_steps]
        tools_std = [s.tool for s in plan_std.primary_steps]
        tools_deep = [s.tool for s in plan_deep.primary_steps]

        # 1. Non-empty
        assert len(tools_quick) > 0
        assert len(tools_std) >= len(tools_quick)
        assert len(tools_deep) >= len(tools_std)

        # 2. Strict subset (nested invariant)
        assert set(tools_quick).issubset(set(tools_std))
        assert set(tools_std).issubset(set(tools_deep))

        # 3. Budget scaling
        assert plan_quick.estimated_budget_seconds < plan_std.estimated_budget_seconds
        assert plan_std.estimated_budget_seconds < plan_deep.estimated_budget_seconds

        # 4. Stop conditions & conditional branches present
        assert len(plan_quick.stop_conditions) > 0
        assert len(plan_quick.conditional_branches) > 0

    def test_different_file_types_produce_different_plans(self):
        """Acceptance Criterion: Different file types produce meaningfully different plans."""
        pe_plan = generate_analysis_plan(
            file_format="pe", objective="malware_triage", depth="standard"
        )
        pcap_plan = generate_analysis_plan(
            file_format="pcap", objective="malware_triage", depth="standard"
        )
        mem_plan = generate_analysis_plan(
            file_format="memory", objective="malware_triage", depth="standard"
        )
        src_plan = generate_analysis_plan(
            file_format="source", objective="vulnerability_research", depth="standard"
        )

        pe_tools = {s.tool for s in pe_plan.primary_steps}
        pcap_tools = {s.tool for s in pcap_plan.primary_steps}
        mem_tools = {s.tool for s in mem_plan.primary_steps}
        src_tools = {s.tool for s in src_plan.primary_steps}

        assert "pcap_analyze" in pcap_tools
        assert "pcap_analyze" not in pe_tools

        assert "memory_list_processes" in mem_tools
        assert "memory_list_processes" not in pe_tools

        assert "audit_source_code" in src_tools
        assert "audit_source_code" not in pe_tools

    def test_missing_dependencies_and_profile_filtering(self):
        """Acceptance Criterion: Missing optional dependencies are reflected in the plan."""
        # When capa is missing
        with patch("reversecore_mcp.core.planner.check_dependency") as mock_check:

            def side_effect(dep: str) -> bool:
                return dep != "capa"

            mock_check.side_effect = side_effect
            plan = generate_analysis_plan(
                file_format="pe", objective="malware_triage", depth="quick"
            )

            capa_step = next(s for s in plan.primary_steps if s.tool == "run_capa_quick")
            assert not capa_step.available
            assert "Missing required external dependency 'capa'" in (
                capa_step.missing_dependency or ""
            )
            assert capa_step.alternative_tool == "extract_iocs"
            assert any("capa" in d for d in plan.missing_dependencies)

    def test_profile_awareness(self):
        """Acceptance Criterion: Plans respect execution profiles and tool availability."""
        # Static profile excludes malware_tools (like detect_anti_analysis)
        plan_static = generate_analysis_plan(
            file_format="pe",
            objective="malware_triage",
            depth="quick",
            profile="static",
        )
        anti_step = next(
            (s for s in plan_static.primary_steps if s.tool == "detect_anti_analysis"), None
        )
        assert anti_step is not None
        # detect_anti_analysis belongs to malware_tools, which is not in static profile
        assert not anti_step.available
        assert "not included in active profile 'static'" in (anti_step.missing_dependency or "")

    def test_all_recommended_tools_exist_in_manifest(self):
        """Requirement: Planner must select strictly existing tools."""
        import json

        manifest_path = Path("tool_manifest.json")
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            manifest_tools = {t["name"] for t in manifest["tools"]}
            # recommend_analysis_plan itself is registered
            manifest_tools.add("recommend_analysis_plan")

            for obj in AnalysisObjective.ALL:
                for fmt in [
                    SampleFormat.PE,
                    SampleFormat.ELF,
                    SampleFormat.PCAP,
                    SampleFormat.MEMORY,
                    SampleFormat.DISK,
                    SampleFormat.SOURCE,
                ]:
                    plan = generate_analysis_plan(
                        objective=obj, file_format=fmt, depth=DepthTier.DEEP
                    )
                    for step in plan.primary_steps:
                        assert step.tool in manifest_tools, (
                            f"Tool '{step.tool}' is not in server manifest!"
                        )
                    for branch in plan.conditional_branches:
                        for tool in branch.recommended_tools:
                            assert tool in manifest_tools, (
                                f"Branch tool '{tool}' is not in server manifest!"
                            )
