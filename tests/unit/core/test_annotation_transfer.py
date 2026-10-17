"""Unit tests for cross-binary function matching and annotation transfer engine."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.annotation_transfer import (
    CrossBinaryTransferEngine,
    FunctionFingerprint,
    MatchState,
)


@pytest.fixture
def transfer_engine():
    return CrossBinaryTransferEngine(timeout=30)


@pytest.mark.asyncio
async def test_architecture_compatibility_matching(
    transfer_engine, workspace_dir, patched_workspace_config
):
    bin_a = workspace_dir / "sample_a.bin"
    bin_b = workspace_dir / "sample_b.bin"
    bin_a.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
    bin_b.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)

    with patch.object(
        transfer_engine,
        "_get_binary_info",
        side_effect=[
            {"arch": "x86", "bits": 64, "os": "linux"},
            {"arch": "x86", "bits": 64, "os": "linux"},
        ],
    ):
        result = await transfer_engine.check_architecture_compatibility(bin_a, bin_b)
        assert result["compatible"] is True
        assert len(result["reasons"]) == 0


@pytest.mark.asyncio
async def test_architecture_incompatibility_detected(
    transfer_engine, workspace_dir, patched_workspace_config
):
    bin_a = workspace_dir / "sample_incompat_a.bin"
    bin_b = workspace_dir / "sample_incompat_b.bin"
    bin_a.write_bytes(b"MZ" + b"\x00" * 32)
    bin_b.write_bytes(b"MZ" + b"\x00" * 32)

    with patch.object(
        transfer_engine,
        "_get_binary_info",
        side_effect=[
            {"arch": "x86", "bits": 64, "os": "windows"},
            {"arch": "arm", "bits": 32, "os": "linux"},
        ],
    ):
        result = await transfer_engine.check_architecture_compatibility(bin_a, bin_b)
        assert result["compatible"] is False
        assert any("Architecture mismatch" in r for r in result["reasons"])
        assert any("Word size mismatch" in r for r in result["reasons"])


def test_exact_opcode_hash_match(transfer_engine):
    src = FunctionFingerprint(
        name="fcn.00401000",
        address="0x401000",
        offset=0x401000,
        size=64,
        cc=2,
        nbbs=2,
        edges=2,
        opcode_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        calls=["sym.imp.malloc"],
    )
    # Rebased function in target binary at 0x501000 with identical opcodes
    tgt = FunctionFingerprint(
        name="fcn.00501000",
        address="0x501000",
        offset=0x501000,
        size=64,
        cc=2,
        nbbs=2,
        edges=2,
        opcode_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        calls=["sym.imp.malloc"],
    )

    matches = transfer_engine.match_functions([src], [tgt])
    assert len(matches) == 1
    m = matches[0]
    assert m.match_state == MatchState.EXACT
    assert m.confidence == 1.0
    assert m.target_function == "fcn.00501000"
    assert m.target_offset == 0x501000


def test_strong_structural_cfg_match(transfer_engine):
    src = FunctionFingerprint(
        name="sym.decrypt_config",
        address="0x402000",
        offset=0x402000,
        size=120,
        cc=5,
        nbbs=6,
        edges=8,
        opcode_hash="hash_a",
        calls=["sym.imp.CryptDecrypt", "sym.imp.VirtualAlloc"],
    )
    # Target binary has slightly modified code (size 128 instead of 120) but same name and CFG
    tgt = FunctionFingerprint(
        name="sym.decrypt_config",
        address="0x403000",
        offset=0x403000,
        size=128,
        cc=5,
        nbbs=6,
        edges=8,
        opcode_hash="hash_b",
        calls=["sym.imp.CryptDecrypt", "sym.imp.VirtualAlloc"],
    )

    matches = transfer_engine.match_functions([src], [tgt])
    assert len(matches) == 1
    m = matches[0]
    assert m.match_state == MatchState.STRONG_MATCH
    assert m.confidence >= 0.85
    assert m.target_function == "sym.decrypt_config"


def test_one_to_many_ambiguity_resolution(transfer_engine):
    src = FunctionFingerprint(
        name="fcn.stub",
        address="0x401000",
        offset=0x401000,
        size=16,
        cc=1,
        nbbs=1,
        edges=0,
        opcode_hash="",
        calls=[],
    )
    # Two identical stubs in target binary with indistinguishable features
    tgt1 = FunctionFingerprint(
        name="fcn.stub_1",
        address="0x501000",
        offset=0x501000,
        size=16,
        cc=1,
        nbbs=1,
        edges=0,
        opcode_hash="",
        calls=[],
    )
    tgt2 = FunctionFingerprint(
        name="fcn.stub_2",
        address="0x502000",
        offset=0x502000,
        size=16,
        cc=1,
        nbbs=1,
        edges=0,
        opcode_hash="",
        calls=[],
    )

    matches = transfer_engine.match_functions([src], [tgt1, tgt2])
    assert len(matches) == 1
    m = matches[0]
    assert m.match_state == MatchState.AMBIGUOUS
    assert m.confidence == 0.0
    assert "One-to-many ambiguity" in m.rationale


def test_many_to_one_ambiguity_resolution(transfer_engine):
    src1 = FunctionFingerprint(
        name="fcn.worker_a",
        address="0x401000",
        offset=0x401000,
        size=32,
        cc=2,
        nbbs=2,
        edges=2,
        opcode_hash="",
        calls=["sym.imp.Sleep"],
    )
    src2 = FunctionFingerprint(
        name="fcn.worker_b",
        address="0x402000",
        offset=0x402000,
        size=32,
        cc=2,
        nbbs=2,
        edges=2,
        opcode_hash="",
        calls=["sym.imp.Sleep"],
    )
    # Single target worker function
    tgt = FunctionFingerprint(
        name="fcn.worker_target",
        address="0x501000",
        offset=0x501000,
        size=32,
        cc=2,
        nbbs=2,
        edges=2,
        opcode_hash="",
        calls=["sym.imp.Sleep"],
    )

    matches = transfer_engine.match_functions([src1, src2], [tgt])
    assert len(matches) == 2
    for m in matches:
        assert m.match_state == MatchState.AMBIGUOUS
        assert m.confidence == 0.0
        assert "Many-to-one ambiguity" in m.rationale


def test_unmatched_function(transfer_engine):
    src = FunctionFingerprint(
        name="sym.complex_parser",
        address="0x401000",
        offset=0x401000,
        size=500,
        cc=25,
        nbbs=30,
        edges=45,
        opcode_hash="hash_src",
        calls=["sym.imp.xmlParseChunk", "sym.imp.zlibInflate"],
    )
    tgt = FunctionFingerprint(
        name="sym.simple_helper",
        address="0x501000",
        offset=0x501000,
        size=10,
        cc=1,
        nbbs=1,
        edges=0,
        opcode_hash="hash_tgt",
        calls=[],
    )

    matches = transfer_engine.match_functions([src], [tgt], min_confidence=0.60)
    assert len(matches) == 1
    m = matches[0]
    assert m.match_state == MatchState.UNMATCHED
    assert m.confidence == 0.0
