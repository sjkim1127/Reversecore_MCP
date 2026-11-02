"""Tests for the portable analyst handoff bundle (export, verify, import)."""

from __future__ import annotations

import json

import pytest

from reversecore_mcp.core import case_state as cs_mod
from reversecore_mcp.core.case_state import CaseStateManager
from reversecore_mcp.core.handoff_bundle import (
    canonical_digest,
    verify_bundle,
)
from reversecore_mcp.core.memory import MemoryStore
from reversecore_mcp.tools.common.handoff_tools import (
    export_handoff_bundle,
    import_handoff_bundle,
)
from reversecore_mcp.tools.radare2 import r2_db


def _use_fresh_stores(tmp_path, monkeypatch, tag: str) -> CaseStateManager:
    """Point case/memory/annotation stores at an empty analyst environment."""
    store = MemoryStore(db_path=tmp_path / f"{tag}_memory.db")
    manager = CaseStateManager(memory_store=store)
    monkeypatch.setattr(cs_mod, "_case_state_manager", manager)
    db_file = tmp_path / f"{tag}_annotations.db"
    monkeypatch.setenv("R2GHIDRA_DB_PATH", str(db_file))
    monkeypatch.setattr(r2_db, "_DB_PATH", db_file)
    r2_db._ensure_schema_initialized(db_file)
    return manager


@pytest.fixture
def env(workspace_dir, patched_workspace_config, patched_config, tmp_path, monkeypatch):
    sample = workspace_dir / "sample.bin"
    sample.write_bytes(b"\x7fELF" + b"\x11" * 64)
    report = workspace_dir / "report.md"
    report.write_text("# findings\n")
    manager = _use_fresh_stores(tmp_path, monkeypatch, "sender")
    return {"ws": workspace_dir, "sample": sample, "report": report, "manager": manager}


async def _populate(env) -> str:
    """Create an investigation: case with verified+active hypotheses, memory, annotations."""
    manager = env["manager"]
    store = manager.memory_store
    await store.initialize()
    sha = r2_db._sha256(env["sample"])

    session_id = await store.create_session("triage", env["sample"].name, sha)
    await store.save_memory(
        session_id,
        "finding",
        {"title": "XOR decode loop at 0x401000"},
        category="function",
        importance=8,
    )

    case = await manager.create_case(str(env["sample"]), case_name="handoff", session_id=session_id)
    case.add_hypothesis(title="Uses XOR config encryption", evidence_level="confirmed")
    case.add_hypothesis(title="Beacons to C2 over HTTPS", evidence_level="possible")
    case.active_hypotheses[0].status = "verified"
    case.add_target(target="sym.beacon", priority="high", reason="possible C2 logic")
    case.record_step("r2_decompile", "deep_analysis", "decompiled decode loop")
    await manager.save_case(case)

    r2_db._add_bookmark_sync(sha, "0x401000", "XOR decode loop", "crypto")
    r2_db._create_structure_sync(sha, "Config", '[{"name": "key", "type": "uint8_t[16]"}]')
    return case.case_id


@pytest.mark.asyncio
async def test_roundtrip_preserves_provenance_and_summary(env, tmp_path, monkeypatch):
    case_id = await _populate(env)

    exported = await export_handoff_bundle(
        str(env["sample"]), artifact_paths=[str(env["report"])], output_name="h.rchandoff.json"
    )
    assert exported.status == "success"
    assert exported.data["summary"]["established"] >= 1
    assert exported.data["summary"]["unresolved"] == 1

    receiver = _use_fresh_stores(tmp_path, monkeypatch, "receiver")
    imported = await import_handoff_bundle(
        str(env["ws"] / "h.rchandoff.json"), target_file_path=str(env["sample"])
    )
    assert imported.status == "success"
    rep = imported.data
    assert rep["integrity"] == "verified"
    assert rep["target_hash_verified"] is True
    assert rep["case_state"]["case_id"] == case_id
    assert rep["annotations"]["bookmarks"]["imported"] == 1
    assert rep["annotations"]["structures"]["imported"] == 1
    assert [a["status"] for a in rep["artifacts"]] == ["verified"]

    # Receiving analyst can tell completed work from unresolved hypotheses.
    assert any(e["kind"] == "hypothesis" for e in rep["summary"]["established"])
    assert [u["title"] for u in rep["summary"]["unresolved"]] == ["Beacons to C2 over HTTPS"]

    case = await receiver.get_case(case_id)
    assert case is not None
    levels = {h.title: (h.status, h.evidence_level) for h in case.active_hypotheses}
    assert levels["Uses XOR config encryption"] == ("verified", "confirmed")
    assert levels["Beacons to C2 over HTTPS"] == ("active", "possible")
    assert case.metadata["handoff"]["source_bundle_sha256"] == rep["bundle_sha256"]
    memories = await receiver.memory_store.get_session_memories(case.session_id)
    assert len(memories) == 1 and memories[0]["importance"] == 8


@pytest.mark.asyncio
async def test_hash_mismatch_aborts_before_anything_is_attached(env, tmp_path, monkeypatch):
    await _populate(env)
    await export_handoff_bundle(str(env["sample"]), output_name="h.rchandoff.json")

    receiver = _use_fresh_stores(tmp_path, monkeypatch, "receiver")
    other = env["ws"] / "other.bin"
    other.write_bytes(b"\x7fELF" + b"\x22" * 64)

    res = await import_handoff_bundle(
        str(env["ws"] / "h.rchandoff.json"), target_file_path=str(other)
    )
    assert res.status == "error"
    assert res.error_code == "SAMPLE_HASH_MISMATCH"
    assert await receiver.list_cases() == []
    exported = r2_db.export_annotations_sync(r2_db._sha256(env["sample"]))
    assert exported == {"bookmarks": [], "structures": [], "types": []}


@pytest.mark.asyncio
async def test_tampered_bundle_is_rejected(env, tmp_path, monkeypatch):
    await _populate(env)
    await export_handoff_bundle(str(env["sample"]), output_name="h.rchandoff.json")
    path = env["ws"] / "h.rchandoff.json"
    data = json.loads(path.read_text())
    data["sections"]["case_state"]["active_hypotheses"][1]["evidence_level"] = "confirmed"
    path.write_text(json.dumps(data))

    check = verify_bundle(data)
    assert not check["valid"]
    assert any("case_state" in p for p in check["problems"])

    _use_fresh_stores(tmp_path, monkeypatch, "receiver")
    res = await import_handoff_bundle(str(path), target_file_path=str(env["sample"]))
    assert res.status == "error"
    assert res.error_code == "HANDOFF_IMPORT_INVALID"


@pytest.mark.asyncio
async def test_missing_optional_artifact_is_reported_not_fatal(env, tmp_path, monkeypatch):
    await _populate(env)
    await export_handoff_bundle(
        str(env["sample"]), artifact_paths=[str(env["report"])], output_name="h.rchandoff.json"
    )
    env["report"].unlink()

    receiver = _use_fresh_stores(tmp_path, monkeypatch, "receiver")
    res = await import_handoff_bundle(
        str(env["ws"] / "h.rchandoff.json"), target_file_path=str(env["sample"])
    )
    assert res.status == "success"
    assert res.data["artifacts"][0]["status"] == "missing"
    assert any("artifact" in w for w in res.data["warnings"])
    assert len(await receiver.list_cases()) == 1


@pytest.mark.asyncio
async def test_existing_case_and_annotations_are_never_overwritten(env):
    case_id = await _populate(env)
    sha = r2_db._sha256(env["sample"])
    await export_handoff_bundle(str(env["sample"]), output_name="h.rchandoff.json")

    # Receiver already has its own, different bookmark at the same address.
    r2_db._add_bookmark_sync(sha, "0x401000", "my own theory", "note")
    res = await import_handoff_bundle(
        str(env["ws"] / "h.rchandoff.json"), target_file_path=str(env["sample"])
    )
    assert res.status == "success"
    assert res.data["case_state"]["case_id"] != case_id
    assert res.data["case_state"]["case_id"].startswith(f"{case_id}_imported_")
    assert any(c["kind"] == "bookmark" for c in res.data["annotations"]["conflicts"])
    kept, _ = r2_db._list_bookmarks_sync(sha, None, 10, 0)
    assert kept[0]["comment"] == "my own theory"
    assert await env["manager"].get_case(case_id) is not None


@pytest.mark.asyncio
async def test_dry_run_writes_nothing(env, tmp_path, monkeypatch):
    await _populate(env)
    await export_handoff_bundle(str(env["sample"]), output_name="h.rchandoff.json")

    receiver = _use_fresh_stores(tmp_path, monkeypatch, "receiver")
    res = await import_handoff_bundle(
        str(env["ws"] / "h.rchandoff.json"), target_file_path=str(env["sample"]), dry_run=True
    )
    assert res.status == "success"
    assert res.data["case_state"]["status"] == "would_import"
    assert await receiver.list_cases() == []


@pytest.mark.asyncio
async def test_export_refuses_case_bound_to_other_sample(env):
    case_id = await _populate(env)
    other = env["ws"] / "other.bin"
    other.write_bytes(b"\x7fELF" + b"\x33" * 64)
    res = await export_handoff_bundle(str(other), case_id=case_id)
    assert res.status == "error"
    assert res.error_code == "HANDOFF_EXPORT_ERROR"


def test_canonical_digest_is_order_independent():
    assert canonical_digest({"a": 1, "b": [1, 2]}) == canonical_digest({"b": [1, 2], "a": 1})
