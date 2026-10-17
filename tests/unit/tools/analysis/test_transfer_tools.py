"""Unit tests for cross-binary annotation transfer MCP tools."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.annotation_transfer import (
    FunctionFingerprint,
    compute_file_sha256,
)
from reversecore_mcp.tools.analysis.transfer_tools import (
    apply_transferred_annotation,
    match_functions_across_binaries,
    review_transferred_annotations,
    transfer_annotations_across_binaries,
)
from reversecore_mcp.tools.radare2 import r2_db


@pytest.fixture
def isolated_r2_db(tmp_path, monkeypatch):
    """Set up an isolated SQLite annotation database."""
    db_file = tmp_path / "test_annotations.db"
    monkeypatch.setenv("R2GHIDRA_DB_PATH", str(db_file))
    monkeypatch.setattr(r2_db, "_DB_PATH", db_file)
    r2_db._ensure_schema_initialized(db_file)
    return db_file


@pytest.mark.asyncio
async def test_match_functions_across_binaries_tool(workspace_dir, patched_workspace_config):
    bin_a = workspace_dir / "sample_v1.bin"
    bin_b = workspace_dir / "sample_v2.bin"
    bin_a.write_bytes(b"\x7fELF" + b"\x90" * 100)
    bin_b.write_bytes(b"\x7fELF" + b"\x90" * 100)

    func_a = FunctionFingerprint(
        name="main",
        address="0x401000",
        offset=0x401000,
        size=48,
        cc=2,
        nbbs=2,
        opcode_hash="hash_main",
    )
    func_b = FunctionFingerprint(
        name="main",
        address="0x501000",
        offset=0x501000,
        size=48,
        cc=2,
        nbbs=2,
        opcode_hash="hash_main",
    )

    with (
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.check_architecture_compatibility",
            return_value={"compatible": True, "reasons": []},
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.extract_functions",
            side_effect=[[func_a], [func_b]],
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine._run_radiff2_graphdiff",
            return_value=[],
        ),
    ):
        result = await match_functions_across_binaries(str(bin_a), str(bin_b))
        assert result.status == "success"
        data = result.data
        assert data["summary"]["exact"] == 1
        assert len(data["matches"]) == 1
        assert data["matches"][0]["match_state"] == "exact"
        assert data["matches"][0]["target_address"] == "0x501000"


@pytest.mark.asyncio
async def test_transfer_annotations_across_binaries_lifecycle(
    workspace_dir, isolated_r2_db, patched_workspace_config
):
    bin_src = workspace_dir / "src_binary.bin"
    bin_tgt = workspace_dir / "tgt_binary.bin"
    bin_src.write_bytes(b"\x7fELF" + b"\xaa" * 80)
    bin_tgt.write_bytes(b"\x7fELF" + b"\xbb" * 80)

    src_hash = compute_file_sha256(bin_src)

    # Pre-populate source annotations in isolated SQLite DB
    from reversecore_mcp.tools.radare2.r2_db import (
        _add_bookmark_sync,
        _create_structure_sync,
    )

    _add_bookmark_sync(src_hash, "0x401010", "Decryption loop begins", "crypto")
    _create_structure_sync(src_hash, "ConfigHeader", '[{"name": "magic", "type": "int"}]')

    func_src = FunctionFingerprint(
        name="sym.crypto_init",
        address="0x401000",
        offset=0x401000,
        size=64,
        opcode_hash="hash_exact",
    )
    func_tgt = FunctionFingerprint(
        name="sym.crypto_init",
        address="0x501000",
        offset=0x501000,
        size=64,
        opcode_hash="hash_exact",
    )

    with (
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.check_architecture_compatibility",
            return_value={"compatible": True, "reasons": []},
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.extract_functions",
            side_effect=[[func_src], [func_tgt]],
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine._run_radiff2_graphdiff",
            return_value=[],
        ),
    ):
        # 1. Execute transfer without auto-apply
        res = await transfer_annotations_across_binaries(
            str(bin_src), str(bin_tgt), auto_apply_exact=False
        )
        assert res.status == "success"
        data = res.data
        assert data["total_items_transferred"] >= 2
        assert data["breakdown"]["suggested"] >= 2

        # 2. Review transferred annotations for target binary
        review_res = await review_transferred_annotations(str(bin_tgt), status="suggested")
        assert review_res.status == "success"
        items = review_res.data["transferred_annotations"]
        assert len(items) >= 2
        transfer_id = items[0]["id"]
        assert items[0]["status"] == "suggested"

        # 3. Apply/verify the suggested annotation
        apply_res = await apply_transferred_annotation(transfer_id=transfer_id, verified=True)
        assert apply_res.status == "success"
        assert apply_res.data["status"] == "verified"
        assert apply_res.data["applied"] is True

        # Verify review now reflects updated status
        review_verified = await review_transferred_annotations(str(bin_tgt), status="verified")
        assert review_verified.status == "success"
        assert any(
            item["id"] == transfer_id for item in review_verified.data["transferred_annotations"]
        )


@pytest.mark.asyncio
async def test_rejection_of_transferred_annotation(
    workspace_dir, isolated_r2_db, patched_workspace_config
):
    bin_src = workspace_dir / "src_binary_rej.bin"
    bin_tgt = workspace_dir / "tgt_binary_rej.bin"
    bin_src.write_bytes(b"\x7fELF" + b"\x11" * 80)
    bin_tgt.write_bytes(b"\x7fELF" + b"\x22" * 80)

    src_hash = compute_file_sha256(bin_src)

    from reversecore_mcp.tools.radare2.r2_db import _add_bookmark_sync

    _add_bookmark_sync(src_hash, "0x401000", "Suspicious entrypoint", "entry")

    func_src = FunctionFingerprint(
        name="entry0",
        address="0x401000",
        offset=0x401000,
        size=32,
        opcode_hash="hash_entry",
    )
    func_tgt = FunctionFingerprint(
        name="entry0",
        address="0x501000",
        offset=0x501000,
        size=32,
        opcode_hash="hash_entry",
    )

    with (
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.check_architecture_compatibility",
            return_value={"compatible": True, "reasons": []},
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine.extract_functions",
            side_effect=[[func_src], [func_tgt]],
        ),
        patch(
            "reversecore_mcp.core.annotation_transfer.CrossBinaryTransferEngine._run_radiff2_graphdiff",
            return_value=[],
        ),
    ):
        transfer_res = await transfer_annotations_across_binaries(str(bin_src), str(bin_tgt))
        assert transfer_res.status == "success"

        review_res = await review_transferred_annotations(str(bin_tgt))
        items = review_res.data["transferred_annotations"]
        assert len(items) >= 1
        transfer_id = items[0]["id"]

        # Reject the annotation
        reject_res = await apply_transferred_annotation(transfer_id=transfer_id, verified=False)
        assert reject_res.status == "success"
        assert reject_res.data["status"] == "rejected"
        assert reject_res.data["applied"] is False
