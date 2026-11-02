"""Unit tests for malware family similarity triage and memory fingerprinting."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reversecore_mcp.core.memory import MemoryStore
from reversecore_mcp.core.similarity_triage import (
    MatchStatus,
    SampleFingerprint,
    SignalStrength,
    SimilarityClassification,
    compare_fingerprints,
    derive_sample_fingerprint,
    query_candidate_fingerprints,
    save_fingerprint_to_memory,
    triage_sample_against_memory,
)
from reversecore_mcp.prompts.similarity_triage import similarity_triage_mode

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures" / "similarity_triage"


def load_fixture(filename: str) -> SampleFingerprint:
    path = FIXTURES_DIR / filename
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return SampleFingerprint.from_dict(data)


@pytest.fixture
def variant_a() -> SampleFingerprint:
    return load_fixture("variant_a.json")


@pytest.fixture
def variant_b() -> SampleFingerprint:
    return load_fixture("variant_b.json")


@pytest.fixture
def unrelated_sample() -> SampleFingerprint:
    return load_fixture("unrelated_sample.json")


@pytest.mark.unit
def test_signal_provenance_and_no_opaque_score(
    variant_a: SampleFingerprint, variant_b: SampleFingerprint
):
    """AC1: Similarity results explain contributing signals with tool provenance rather than an opaque score."""
    comparison = compare_fingerprints(variant_a, variant_b)

    assert comparison.classification == SimilarityClassification.STRONG_MATCH
    assert comparison.candidate_family == "Trojan.Downloader.AgentX"
    assert comparison.strong_matches_count >= 4
    assert comparison.medium_matches_count >= 1
    assert comparison.conflicting_signals_count >= 1  # different packer

    # Verify per-signal provenance
    explanations = comparison.signal_explanations
    assert len(explanations) > 0

    crc32_exp = next((e for e in explanations if e.signal_key == "algorithm:crc32"), None)
    assert crc32_exp is not None
    assert crc32_exp.status == MatchStatus.MATCH.value
    assert crc32_exp.provenance == "resolve_api_hashes"
    assert crc32_exp.strength == SignalStrength.STRONG.value

    # Verify Markdown formatting contains table with provenance
    md = comparison.format_markdown()
    assert "### Malware Family Similarity Triage:" in md
    assert "resolve_api_hashes" in md
    assert "extract_iocs" in md
    assert "run_capa" in md
    assert "generate_signature" in md
    assert "UPX" in md or "packer" in md


@pytest.mark.unit
def test_weak_indicators_cannot_produce_family_claim(
    variant_a: SampleFingerprint, unrelated_sample: SampleFingerprint
):
    """AC2 & AC3: Weak indicators cannot produce family claim; unrelated sample is not promoted."""
    comparison = compare_fingerprints(variant_a, unrelated_sample)

    # Must be classified as SUPERFICIAL_ONLY
    assert comparison.classification == SimilarityClassification.SUPERFICIAL_ONLY
    # Family attribution must be rejected (None)
    assert comparison.candidate_family is None
    assert comparison.strong_matches_count == 0
    assert comparison.medium_matches_count == 0
    assert comparison.weak_matches_count > 0

    # Summary narrative must explicitly explain rejection of family claim
    narrative = comparison.summary_narrative
    assert (
        "Superficial overlap only" in narrative or "cannot independently substantiate" in narrative
    )

    # Markdown output must clearly display superficial classification
    md = comparison.format_markdown()
    assert "SUPERFICIAL_ONLY" in md
    assert "None (Unattributed)" in md


@pytest.mark.unit
def test_different_packer_and_distinct_hashes_preserved(
    variant_a: SampleFingerprint, variant_b: SampleFingerprint
):
    """Differences such as packer type and file hashes are explicitly tracked."""
    comparison = compare_fingerprints(variant_a, variant_b)

    assert comparison.shared_file_hash is False
    packer_exp = next(
        (e for e in comparison.signal_explanations if e.signal_key == "packer_type"),
        None,
    )
    assert packer_exp is not None
    assert packer_exp.status == MatchStatus.DIFFERENT.value
    assert "UPX" in str(packer_exp.candidate_value)
    assert "None/Custom" in str(packer_exp.target_value)


@pytest.mark.unit
def test_derive_sample_fingerprint_helper():
    """Verify programmatic fingerprint derivation classifies signal strengths accurately."""
    fp = derive_sample_fingerprint(
        sample_id="test_01",
        binary_name="malware_sample.exe",
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        family_label="Redline.Stealer",
        architecture="x86_64",
        api_hashes=[{"algorithm": "Murmur3"}],
        persistence_mechanisms=["Registry Run Key"],
        c2_indicators=[".c2-command-network.org"],
        crypto_constants=["ChaCha20_State_Init"],
        function_signatures={"decrypt_config": "48895c240848896c2410"},
        capa_capabilities=["inject_thread"],
        notable_iocs=[{"type": "mutex", "value": "Redline_Global_Lock"}],
        packer_name="Themida",
        imported_apis=["ExitProcess", "LoadLibraryA", "VirtualAlloc"],
        strings=["Usage: win.exe", "Error connecting to server"],
    )

    assert fp.sample_id == "test_01"
    assert fp.family_label == "Redline.Stealer"

    sig_map = fp.get_signal_map()
    assert sig_map["api_hash_resolver:algorithm:Murmur3"].strength == SignalStrength.STRONG
    assert (
        sig_map["persistence_capability:mechanism:registry run key"].strength
        == SignalStrength.STRONG
    )
    assert sig_map["crypto_constant:constant:chacha20_state_init"].strength == SignalStrength.STRONG
    assert sig_map["generic_import:import:exitprocess"].strength == SignalStrength.WEAK
    assert sig_map["superficial_string:string:usage: win.exe"].strength == SignalStrength.WEAK


@pytest.mark.asyncio
async def test_memory_store_persistence_and_cross_session_triage(
    tmp_path: Path,
    variant_a: SampleFingerprint,
    variant_b: SampleFingerprint,
    unrelated_sample: SampleFingerprint,
):
    """AC4: Stored patterns remain portable through memory store and queryable across sessions."""
    db_path = tmp_path / "test_memory.db"
    store = MemoryStore(db_path=db_path)
    await store.initialize()

    # Session 1: Store Variant A
    sess1_id = await store.create_session(
        name="session_variant_a",
        binary_name=variant_a.binary_name,
        binary_hash=variant_a.sha256,
    )
    p1_id = await save_fingerprint_to_memory(store, sess1_id, variant_a)
    assert p1_id > 0

    # Session 2: Store Unrelated sample
    sess2_id = await store.create_session(
        name="session_unrelated",
        binary_name=unrelated_sample.binary_name,
        binary_hash=unrelated_sample.sha256,
    )
    p2_id = await save_fingerprint_to_memory(store, sess2_id, unrelated_sample)
    assert p2_id > 0

    # Query all candidate fingerprints across sessions
    candidates = await query_candidate_fingerprints(store)
    assert len(candidates) == 2
    cand_hashes = {c.sha256 for c in candidates}
    assert variant_a.sha256 in cand_hashes
    assert unrelated_sample.sha256 in cand_hashes

    # Session 3: Triage Variant B against memory store
    triage_results = await triage_sample_against_memory(
        store=store,
        target=variant_b,
        limit=5,
    )

    assert len(triage_results) == 2
    top_match = triage_results[0]
    second_match = triage_results[1]

    # Top match must be Variant A (STRONG_MATCH)
    assert top_match.candidate_binary_name == variant_a.binary_name
    assert top_match.classification == SimilarityClassification.STRONG_MATCH
    assert top_match.candidate_family == "Trojan.Downloader.AgentX"

    # Second match must be Unrelated (SUPERFICIAL_ONLY)
    assert second_match.candidate_binary_name == unrelated_sample.binary_name
    assert second_match.classification == SimilarityClassification.SUPERFICIAL_ONLY
    assert second_match.candidate_family is None


@pytest.mark.unit
def test_similarity_triage_mode_prompt_generation():
    """Verify guided prompt renders with required invariants and rules."""
    prompt_text = similarity_triage_mode(
        target_file="/app/workspace/trojan.exe",
        candidate_session_or_hash="sample_v1",
    )

    assert "/app/workspace/trojan.exe" in prompt_text
    assert "sample_v1" in prompt_text
    assert "resolve_api_hashes" in prompt_text
    assert "extract_iocs" in prompt_text
    assert "run_capa" in prompt_text
    assert "find_similar_patterns" in prompt_text
    assert "SUPERFICIAL_ONLY" in prompt_text
    assert "STRONG_MATCH" in prompt_text
