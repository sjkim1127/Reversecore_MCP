"""Unit tests for machine-readable analysis case state management."""

from pathlib import Path

import pytest

from reversecore_mcp.core.case_state import (
    AnalysisPhase,
    CaseState,
    CaseStateManager,
    HypothesisStatus,
    SampleMetadata,
    TargetPriority,
    TargetStatus,
)
from reversecore_mcp.core.exceptions import (
    CaseNotFoundError,
    InvalidPhaseTransitionError,
    SampleHashMismatchError,
)
from reversecore_mcp.core.memory import MemoryStore


@pytest.fixture
def memory_store(tmp_path: Path):
    """Create a temporary MemoryStore instance."""
    db_file = tmp_path / "test_memory.db"
    store = MemoryStore(db_path=db_file)
    return store


@pytest.fixture
def case_manager(memory_store: MemoryStore):
    """Create a CaseStateManager with temporary MemoryStore."""
    return CaseStateManager(memory_store=memory_store)


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a fake binary sample."""
    file = tmp_path / "sample.exe"
    file.write_bytes(b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
    return file


class TestCaseStateModels:
    """Test CaseState domain objects and transitions."""

    def test_sample_metadata(self):
        meta = SampleMetadata(
            path="/test/path", sha256="abc123", name="sample.bin", size_bytes=1024
        )
        d = meta.to_dict()
        assert d["path"] == "/test/path"
        assert d["sha256"] == "abc123"

        reconstructed = SampleMetadata.from_dict(d)
        assert reconstructed.sha256 == meta.sha256
        assert reconstructed.size_bytes == 1024

    def test_phase_transitions(self):
        meta = SampleMetadata(path="/test/sample", sha256="abc")
        case = CaseState(case_id="case_001", sample=meta, phase=AnalysisPhase.INTAKE.value)

        # Transition forward: intake -> triage
        case.transition_phase(AnalysisPhase.TRIAGE)
        assert case.phase == AnalysisPhase.TRIAGE.value
        assert AnalysisPhase.INTAKE.value in case.completed_phases
        assert case.is_phase_completed(AnalysisPhase.INTAKE)

        # Transition forward skipping: triage -> deep_analysis
        case.transition_phase(AnalysisPhase.DEEP_ANALYSIS)
        assert case.phase == AnalysisPhase.DEEP_ANALYSIS.value
        assert AnalysisPhase.TRIAGE.value in case.completed_phases
        assert AnalysisPhase.HYPOTHESIS_GENERATION.value in case.completed_phases

        # Attempt invalid backward transition without force
        with pytest.raises(InvalidPhaseTransitionError) as exc_info:
            case.transition_phase(AnalysisPhase.TRIAGE, force=False)
        assert "force_phase=True" in str(exc_info.value)

        # Force backward transition
        case.transition_phase(AnalysisPhase.TRIAGE, force=True)
        assert case.phase == AnalysisPhase.TRIAGE.value

    def test_hypotheses_lifecycle(self):
        meta = SampleMetadata(path="/test/sample", sha256="abc")
        case = CaseState(case_id="case_001", sample=meta)

        hyp = case.add_hypothesis(
            title="Dormant C2 beacon triggered by registry key",
            category="c2",
            evidence_level="possible",
            rationale="Discovered hardcoded domain",
        )
        assert hyp.status == HypothesisStatus.ACTIVE.value
        assert len(case.active_hypotheses) == 1

        # Incremental update
        updated = case.update_hypothesis(
            hyp_id=hyp.id,
            evidence_refs=["0x401050: string 'beacon.example.com'"],
            rationale="Found xref in sub_401000",
        )
        assert updated is not None
        assert len(updated.evidence_refs) == 1

        # Resolve hypothesis
        resolved = case.resolve_hypothesis(
            hyp.id, verified=True, rationale="Confirmed via taint trace"
        )
        assert resolved is not None
        assert resolved.status == HypothesisStatus.VERIFIED.value
        assert resolved.evidence_level == "observed"

    def test_targets_priority_queue(self):
        meta = SampleMetadata(path="/test/sample", sha256="abc")
        case = CaseState(case_id="case_001", sample=meta)

        case.add_target("sym.func_low", priority=TargetPriority.LOW.value, reason="Helper")
        case.add_target(
            "sym.decrypt_config",
            priority=TargetPriority.CRITICAL.value,
            reason="C2 payload decryptor",
        )
        case.add_target(
            "sym.net_connect", priority=TargetPriority.HIGH.value, reason="Network callback"
        )

        # Deterministic sorting: CRITICAL, then HIGH, then LOW
        sorted_targets = case.get_sorted_targets()
        assert [t.target for t in sorted_targets] == [
            "sym.decrypt_config",
            "sym.net_connect",
            "sym.func_low",
        ]

        # Updating target
        case.update_target_status("sym.decrypt_config", TargetStatus.COMPLETED.value)
        remaining = case.get_sorted_targets(include_completed=False)
        assert [t.target for t in remaining] == ["sym.net_connect", "sym.func_low"]

    def test_blockers_and_dependencies(self):
        meta = SampleMetadata(path="/test/sample", sha256="abc")
        case = CaseState(case_id="case_001", sample=meta)

        case.add_target("sym.inject_process", priority=TargetPriority.HIGH.value)
        blocker = case.add_blocker(
            target="sym.inject_process",
            reason="Payload buffer decryption required first",
            blocked_by=["sym.decrypt_config"],
            suggested_resolution="Run taint trace from sym.decrypt_config",
        )
        assert blocker.target == "sym.inject_process"
        assert len(case.blocked) == 1

        # Target should now be marked as blocked
        tgt = [t for t in case.next_targets if t.target == "sym.inject_process"][0]
        assert tgt.status == TargetStatus.BLOCKED.value

        # Resolve blocker
        assert case.resolve_blocker("sym.inject_process") is True
        assert len(case.blocked) == 0
        assert tgt.status == TargetStatus.PENDING.value

    def test_artifacts_and_steps(self):
        meta = SampleMetadata(path="/test/sample", sha256="abc")
        case = CaseState(case_id="case_001", sample=meta)

        step = case.record_step(
            "step_1", "r2_decompile", "Decompiled main function", output_summary={"funcs": 1}
        )
        assert len(case.completed_steps) == 1
        assert step.tool_name == "r2_decompile"

        art = case.add_artifact(
            name="decompiled_main.c",
            artifact_type="disasm",
            path="/workspace/main.c",
            sha256="def456",
        )
        assert art.name == "decompiled_main.c"
        assert len(case.artifacts) == 1

    def test_serialization_roundtrip(self):
        meta = SampleMetadata(
            path="/test/sample", sha256="abc123hash", name="sample.exe", size_bytes=2048
        )
        case = CaseState(case_id="case_rt_01", sample=meta, phase=AnalysisPhase.TRIAGE.value)
        case.add_hypothesis("Hypothesis 1", category="evasion")
        case.add_target("0x401000", priority="high", reason="Entry point")
        case.record_step("s1", "file_info", "Analyzed PE header")

        d = case.to_dict()
        reconstructed = CaseState.from_dict(d)

        assert reconstructed.case_id == case.case_id
        assert reconstructed.phase == AnalysisPhase.TRIAGE.value
        assert reconstructed.sample.sha256 == "abc123hash"
        assert len(reconstructed.active_hypotheses) == 1
        assert len(reconstructed.next_targets) == 1
        assert len(reconstructed.completed_steps) == 1

        summary = reconstructed.to_summary_dict()
        assert summary["case_id"] == "case_rt_01"
        assert summary["counts"]["active_hypotheses"] == 1


class TestCaseStateManager:
    """Test CaseStateManager persistence and lifecycle."""

    @pytest.mark.asyncio
    async def test_create_and_get_case(self, case_manager: CaseStateManager, sample_file: Path):
        case = await case_manager.create_case(
            sample_path=str(sample_file),
            case_name="malware_sample",
            initial_phase="triage",
        )

        assert case.case_id.startswith("case_malware_sample_")
        assert case.phase == "triage"
        assert len(case.sample.sha256) == 64

        retrieved = await case_manager.get_case(case.case_id)
        assert retrieved is not None
        assert retrieved.case_id == case.case_id
        assert retrieved.sample.sha256 == case.sample.sha256

        by_hash = await case_manager.get_case_by_sample_hash(case.sample.sha256)
        assert by_hash is not None
        assert by_hash.case_id == case.case_id

    @pytest.mark.asyncio
    async def test_resume_case_success(self, case_manager: CaseStateManager, sample_file: Path):
        case = await case_manager.create_case(
            sample_path=str(sample_file),
            case_name="resume_test",
            initial_phase="deep_analysis",
        )
        case.add_target("sym.decrypt_payload", priority="critical", reason="Payload unpacker")
        case.add_hypothesis("Self-decrypting payload", category="unpacking")
        await case_manager.save_case(case)

        resumed = await case_manager.resume_case(case.case_id, sample_path=str(sample_file))
        assert resumed["resumed"] is True
        assert resumed["phase"] == "deep_analysis"
        assert resumed["top_target"]["target"] == "sym.decrypt_payload"
        assert len(resumed["active_hypotheses"]) == 1
        assert "sym.decrypt_payload" in resumed["guidance"]

    @pytest.mark.asyncio
    async def test_resume_case_hash_mismatch(
        self, case_manager: CaseStateManager, sample_file: Path, tmp_path: Path
    ):
        case = await case_manager.create_case(
            sample_path=str(sample_file),
            case_name="mismatch_test",
        )

        # Create another sample with different content
        other_file = tmp_path / "different.exe"
        other_file.write_bytes(b"totally different content for hash mismatch")

        with pytest.raises(SampleHashMismatchError) as exc_info:
            await case_manager.resume_case(
                case.case_id, sample_path=str(other_file), verify_hash=True
            )

        assert "Sample hash mismatch" in str(exc_info.value)
        assert exc_info.value.case_id == case.case_id

    @pytest.mark.asyncio
    async def test_resume_case_not_found(self, case_manager: CaseStateManager):
        with pytest.raises(CaseNotFoundError):
            await case_manager.resume_case("case_nonexistent_12345")

    @pytest.mark.asyncio
    async def test_list_and_delete_cases(self, case_manager: CaseStateManager, sample_file: Path):
        c1 = await case_manager.create_case(
            str(sample_file), case_name="case_1", initial_phase="intake"
        )
        c2 = await case_manager.create_case(
            str(sample_file), case_name="case_2", initial_phase="completed"
        )

        all_cases = await case_manager.list_cases()
        assert len(all_cases) >= 2

        intake_cases = await case_manager.list_cases(phase="intake")
        assert any(c["case_id"] == c1.case_id for c in intake_cases)
        assert not any(c["case_id"] == c2.case_id for c in intake_cases)

        assert await case_manager.delete_case(c1.case_id) is True
        assert await case_manager.get_case(c1.case_id) is None
