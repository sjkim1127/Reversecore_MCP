"""Unit tests for Case State MCP tools."""

from pathlib import Path

import pytest

from reversecore_mcp.core.case_state import CaseStateManager
from reversecore_mcp.core.memory import MemoryStore
from reversecore_mcp.tools.common.case_tools import (
    create_case_state,
    get_case_state,
    list_case_states,
    resume_case_state,
    update_case_state,
)


@pytest.fixture(autouse=True)
def setup_test_manager(tmp_path: Path, monkeypatch):
    """Ensure a clean temporary database is used for all tests."""
    db_file = tmp_path / "test_case_tools.db"
    store = MemoryStore(db_path=db_file)
    manager = CaseStateManager(memory_store=store)

    import reversecore_mcp.core.case_state as cs_mod

    monkeypatch.setattr(cs_mod, "_case_state_manager", manager)
    return manager


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a sample binary file."""
    f = tmp_path / "target.bin"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    return f


class TestCaseTools:
    """Tests for case state management MCP tools."""

    @pytest.mark.asyncio
    async def test_create_case_state_tool(self, sample_file: Path):
        res = await create_case_state(
            sample_path=str(sample_file),
            case_name="triage_case",
            initial_phase="triage",
            hypotheses=[
                {
                    "title": "Contains injected shellcode",
                    "category": "injection",
                    "evidence_level": "possible",
                }
            ],
            targets=[
                {
                    "target": "sym.decode",
                    "kind": "function",
                    "priority": "high",
                    "expected_next_step": "decompile",
                }
            ],
        )

        assert res.status == "success"
        payload = res.data
        assert "case" in payload
        assert payload["phase"] == "triage"
        assert len(payload["sample_hash"]) == 64
        assert res.recommended_next_tools is not None and len(res.recommended_next_tools) > 0
        assert res.recommended_next_tools[0]["tool"] == "recommend_analysis_plan"

    @pytest.mark.asyncio
    async def test_get_case_state_tool(self, sample_file: Path):
        created = await create_case_state(sample_path=str(sample_file), case_name="lookup_case")
        case_id = created.data["case_id"]

        # Get by case_id
        res1 = await get_case_state(case_id=case_id)
        assert res1.status == "success"
        assert res1.data["case_id"] == case_id

        # Get by sample_path
        res2 = await get_case_state(sample_path=str(sample_file))
        assert res2.status == "success"
        assert res2.data["case_id"] == case_id

        # Missing both arguments
        res_err = await get_case_state()
        assert res_err.status == "error"
        assert res_err.error_code == "INVALID_ARGUMENTS"

    @pytest.mark.asyncio
    async def test_update_case_state_tool(self, sample_file: Path):
        created = await create_case_state(sample_path=str(sample_file), case_name="update_case")
        case_id = created.data["case_id"]

        # Incremental update: phase, step, hypothesis, target, blocker, artifact
        res = await update_case_state(
            case_id=case_id,
            phase="deep_analysis",
            add_step={"step_id": "s1", "tool_name": "r2_decompile", "summary": "Decompiled main"},
            add_hypothesis={
                "title": "Anti-VM detected",
                "category": "evasion",
                "evidence_level": "inferred",
            },
            add_target={"target": "sym.vm_check", "kind": "function", "priority": "high"},
            add_blocker={"target": "sym.vm_check", "reason": "Requires hypervisor emulation"},
            add_artifact={
                "name": "report.json",
                "artifact_type": "report",
                "path": "/workspace/report.json",
            },
        )

        assert res.status == "success"
        case_data = res.data["case"]
        assert case_data["phase"] == "deep_analysis"
        assert case_data["counts"]["completed_steps"] == 1
        assert case_data["counts"]["active_hypotheses"] == 1
        assert case_data["counts"]["blocked"] == 1

        # Resolve blocker
        res_unblock = await update_case_state(
            case_id=case_id,
            resolve_blocker="sym.vm_check",
        )
        assert res_unblock.status == "success"
        assert res_unblock.data["case"]["counts"]["blocked"] == 0

    @pytest.mark.asyncio
    async def test_resume_case_state_tool(self, sample_file: Path):
        created = await create_case_state(sample_path=str(sample_file), case_name="resume_case")
        case_id = created.data["case_id"]

        # Add priority target to inspect
        await update_case_state(
            case_id=case_id,
            add_target={
                "target": "sym.decrypt_buffer",
                "priority": "critical",
                "expected_next_step": "decompile",
            },
        )

        res = await resume_case_state(case_id=case_id, sample_path=str(sample_file))
        assert res.status == "success"
        payload = res.data
        assert payload["resumption"]["resumed"] is True
        assert res.recommended_next_tools is not None and len(res.recommended_next_tools) > 0
        assert res.recommended_next_tools[0]["tool"] == "r2_decompile"
        assert (
            res.recommended_next_tools[0]["suggested_args"]["function_name"] == "sym.decrypt_buffer"
        )

    @pytest.mark.asyncio
    async def test_resume_hash_mismatch_tool(self, sample_file: Path, tmp_path: Path):
        created = await create_case_state(
            sample_path=str(sample_file), case_name="mismatch_tool_case"
        )
        case_id = created.data["case_id"]

        mismatch_file = tmp_path / "tampered.bin"
        mismatch_file.write_bytes(b"tampered content")

        res = await resume_case_state(
            case_id=case_id, sample_path=str(mismatch_file), verify_hash=True
        )
        assert res.status == "error"
        assert res.error_code == "SAMPLE_HASH_MISMATCH"
        assert "Case state cannot be attached to a mismatched binary" in res.message

    @pytest.mark.asyncio
    async def test_list_case_states_tool(self, sample_file: Path):
        await create_case_state(
            sample_path=str(sample_file), case_name="list_case_1", initial_phase="intake"
        )
        await create_case_state(
            sample_path=str(sample_file), case_name="list_case_2", initial_phase="triage"
        )

        res = await list_case_states()
        assert res.status == "success"
        assert res.data["total_count"] >= 2

        res_filtered = await list_case_states(phase="triage")
        assert res_filtered.status == "success"
        assert all(c["phase"] == "triage" for c in res_filtered.data["cases"])
