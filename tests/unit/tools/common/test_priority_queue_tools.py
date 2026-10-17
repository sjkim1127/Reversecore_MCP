"""Unit tests for evidence-driven priority queue MCP tools."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.case_state import (
    CaseStateManager,
    TargetStatus,
)
from reversecore_mcp.core.memory import MemoryStore
from reversecore_mcp.tools.common.case_tools import create_case_state
from reversecore_mcp.tools.common.priority_queue_tools import (
    add_priority_target,
    plan_next_analysis_targets,
    populate_case_queue_from_triage,
    resolve_target_blocker,
    update_priority_target,
)


@pytest.fixture(autouse=True)
def setup_test_manager(tmp_path: Path, monkeypatch):
    """Ensure a clean temporary database is used for all tests."""
    db_file = tmp_path / "test_pq_tools.db"
    store = MemoryStore(db_path=db_file)
    manager = CaseStateManager(memory_store=store)

    import reversecore_mcp.core.case_state as cs_mod

    monkeypatch.setattr(cs_mod, "_case_state_manager", manager)
    return manager


@pytest.fixture
def mock_binary(tmp_path: Path) -> Path:
    """Create a temporary mock binary file."""
    p = tmp_path / "target_sample.bin"
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x90" * 64)
    return p


@pytest.mark.asyncio
async def test_plan_next_analysis_targets_tool(mock_binary: Path):
    """Test plan_next_analysis_targets returns ranked plan and tool hints."""
    res = await create_case_state(
        sample_path=str(mock_binary),
        case_name="plan_test_case",
        initial_phase="triage",
    )
    assert res.status == "success"
    case_id = res.data["case_id"]

    # Add targets with different priorities
    await add_priority_target(
        case_id=case_id,
        target="sym.c2_connect",
        kind="network",
        priority="high",
        reason="C2 connection logic",
        expected_next_step="pcap_analyze + decompile",
        evidence_refs=["import:InternetOpenA"],
    )
    await add_priority_target(
        case_id=case_id,
        target="sym.anti_vm",
        kind="function",
        priority="medium",
        reason="CPUID hypervisor check",
        expected_next_step="r2_esil_simulator bypass",
    )

    plan_res = await plan_next_analysis_targets(case_id=case_id, limit=5)
    assert plan_res.status == "success"
    data = plan_res.data
    assert data["case_id"] == case_id
    assert len(data["plan_targets"]) == 2
    assert data["total_targets"] == 2
    assert data["ready_targets_count"] == 2
    assert data["blocked_targets_count"] == 0

    top_target = data["plan_targets"][0]
    assert top_target["target"] == "sym.c2_connect"
    assert top_target["is_ready"] is True
    assert "score_breakdown" in top_target
    assert len(top_target["recommended_tools"]) > 0

    assert len(plan_res.recommended_next_tools) > 0


@pytest.mark.asyncio
async def test_populate_case_queue_from_triage_tool(mock_binary: Path):
    """Test populate_case_queue_from_triage extracts and stores targets."""
    res = await create_case_state(
        sample_path=str(mock_binary),
        case_name="triage_pop_case",
        initial_phase="triage",
    )
    case_id = res.data["case_id"]

    triage_dict = {
        "imports": ["VirtualAllocEx", "CryptDecrypt"],
        "sections": [{"name": ".packed", "entropy": 7.92}],
        "strings": ["https://malware-command.test/gate.php"],
    }

    # Test with dictionary input
    pop_res = await populate_case_queue_from_triage(
        case_id=case_id,
        triage_data=triage_dict,
        max_items=10,
    )
    assert pop_res.status == "success"
    assert pop_res.data["added_count"] == 4
    assert pop_res.data["total_queue_size"] == 4

    # Test with JSON string input and deduplication (should add 0 duplicates)
    json_str = json.dumps(triage_dict)
    pop_res_2 = await populate_case_queue_from_triage(
        case_id=case_id,
        triage_data=json_str,
    )
    assert pop_res_2.status == "success"
    assert pop_res_2.data["added_count"] == 0


@pytest.mark.asyncio
async def test_update_priority_target_tool(mock_binary: Path):
    """Test update_priority_target updates status, resolves blockers, and logs findings."""
    res = await create_case_state(
        sample_path=str(mock_binary),
        case_name="update_target_case",
    )
    case_id = res.data["case_id"]

    t1_res = await add_priority_target(
        case_id=case_id,
        target="sym.find_key",
        kind="function",
        priority="high",
        reason="Search for key",
    )
    t1_id = t1_res.data["target"]["id"]

    await add_priority_target(
        case_id=case_id,
        target="sym.decrypt_database",
        kind="function",
        priority="critical",
        reason="Decrypt DB",
        blockers=["sym.find_key"],
    )

    # Initially, sym.decrypt_database is blocked
    plan1 = await plan_next_analysis_targets(case_id=case_id, include_blocked=True)
    targets_map = {t["target"]: t for t in plan1.data["plan_targets"]}
    assert targets_map["sym.decrypt_database"]["is_ready"] is False

    # Mark sym.find_key as completed
    upd_res = await update_priority_target(
        case_id=case_id,
        target=t1_id,
        status="completed",
        findings=["Found encryption key: 0xDEADBEEF"],
        reason="Successfully extracted key from .rodata",
    )
    assert upd_res.status == "success"
    assert "sym.decrypt_database" in upd_res.data["unblocked_targets"]

    # Now sym.decrypt_database is unblocked and ready
    plan2 = await plan_next_analysis_targets(case_id=case_id)
    targets_map2 = {t["target"]: t for t in plan2.data["plan_targets"]}
    assert "sym.decrypt_database" in targets_map2
    assert targets_map2["sym.decrypt_database"]["is_ready"] is True


@pytest.mark.asyncio
async def test_resolve_target_blocker_tool(mock_binary: Path):
    """Test explicit blocker resolution via resolve_target_blocker tool."""
    res = await create_case_state(
        sample_path=str(mock_binary),
        case_name="blocker_test_case",
    )
    case_id = res.data["case_id"]

    await add_priority_target(
        case_id=case_id,
        target="sym.evasive_check",
        kind="function",
        priority="medium",
        reason="Wait for sandbox bypass",
        blockers=["external_debugger_attach"],
    )

    res_blocker = await resolve_target_blocker(
        case_id=case_id,
        target="sym.evasive_check",
        resolution_note="Debugger attached successfully",
    )
    assert res_blocker.status == "success"
    assert res_blocker.data["unblocked"] is True
    assert res_blocker.data["status"] == TargetStatus.PENDING.value
