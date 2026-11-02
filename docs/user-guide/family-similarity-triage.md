# Malware Family Similarity Triage Workflow

The **Malware Family Similarity Triage Workflow** provides an analyst-centric framework for cross-session binary comparison, answering the critical threat intelligence question: **"Have I seen something structurally or behaviorally similar before?"**

Rather than relying on a single opaque similarity score or external threat intelligence feeds, this workflow extracts multi-dimensional evidence signals from local reverse engineering tools, preserves per-signal provenance, and cross-references findings against previous sessions using Reversecore's persistent memory and pattern matching subsystems.

---

## Architecture & Signal Dimensions

Each analyzed sample is fingerprinted across distinct analytical dimensions, categorized by evidence strength:

| Signal Dimension | Evidence Strength | Reused Tools | Provenance Key | Example Value |
|---|---|---|---|---|
| **API Hash Resolvers** | `STRONG` | `resolve_api_hashes` | `algorithm:<algo>` | `CRC32`, `FNV-1a`, `Murmur3` |
| **Persistence Capabilities** | `STRONG` | `run_capa`, decompilation | `mechanism:<name>` | `HKCU\Software\...\Run\UpdaterService` |
| **C2 Infrastructure** | `STRONG` | `extract_iocs` | `domain_suffix:<dom>` | `.cdn-telemetry-cache.net` |
| **Crypto Constants** | `STRONG` | `find_crypto_constants` | `constant:<name>` | `rc4_sbox_init`, ChaCha20 constants |
| **Function Bytecode Signatures** | `STRONG` | `generate_signature` | `function:<name>` | `554889e54883ec2048894df8...` |
| **Behavioral Capabilities** | `MEDIUM` | `run_capa` | `capa:<capability>` | `inject_thread`, `evade_sandbox` |
| **Notable IOCs** | `MEDIUM` | `extract_iocs` | `<type>:<value>` | `Global\AgentX_Mutex_v1` |
| **Packer & Protections** | `MEDIUM` | `detect_packer` | `packer_type` | `UPX 3.96`, `None/Custom` |
| **Generic System Imports** | `WEAK` | `parse_binary_with_lief` | `import:<api>` | `ExitProcess`, `LoadLibraryA` |
| **Superficial Strings** | `WEAK` | `extract_iocs` | `string:<snippet>` | `"Usage: ... "`, `"Windows"` |

---

## Core Invariants & Decision Rules

1. **No Opaque Similarity Scores**:
   - Similarity results must explain contributing signals with tool provenance rather than presenting an unsubstantiated percentage.
2. **Weak Indicators Cannot Produce Family Claims**:
   - Common runtime imports (`ExitProcess`, `GetProcAddress`, `malloc`) and generic strings (`Usage:`, `Windows`) carry low attribution weight.
   - If two samples share **only** weak indicators, the classification is strictly `SUPERFICIAL_ONLY` and candidate family attribution is rejected (`candidate_family = None`).
3. **Unrelated Samples Are Explicitly Separated**:
   - Benign tools or unrelated malware sharing boilerplate compiler code are not false-flagged as related variants.
4. **Preservation of Differences & Divergence**:
   - Variations (e.g. different packers, diverging architectures, updated mutex versions) are recorded alongside matching features.
5. **Memory Store Portability**:
   - Fingerprints are serialized into standard SQLite pattern records (`pattern_type="family_fingerprint"`) and are fully portable across session export bundles.
6. **No External Services**:
   - Complete offline execution without cloud APIs or third-party intelligence services.

---

## Similarity Classifications

| Classification | Criteria | Family Attribution | Narrative Meaning |
|---|---|---|---|
| `STRONG_MATCH` | $\ge 2$ strong matches (or 1 strong + $\ge 2$ medium matches) | Asserted (`candidate_family`) | Strong lineage or variant match supported by distinctive hashing, C2, crypto, or code signatures. |
| `MODERATE_MATCH` | $\ge 1$ strong match or $\ge 2$ medium matches | Probable (`candidate_family`) | Notable behavioral or structural overlap; recommended for deeper manual inspection. |
| `SUPERFICIAL_ONLY` | 0 strong matches, 0 medium matches, $\ge 1$ weak matches | **Rejected** (`None`) | Overlap limited to generic OS runtime APIs or boilerplate text; not a family match. |
| `NO_MATCH` | 0 matching signals across all dimensions | **Rejected** (`None`) | Distinct binaries with no observed structural or behavioral overlap. |

---

## Python API Usage

```python
from reversecore_mcp.core.memory import get_memory_store
from reversecore_mcp.core.similarity_triage import (
    derive_sample_fingerprint,
    compare_fingerprints,
    save_fingerprint_to_memory,
    triage_sample_against_memory,
)

# 1. Derive fingerprint from tool outputs
target_fp = derive_sample_fingerprint(
    sample_id="target_01",
    binary_name="suspect.exe",
    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    family_label="Trojan.AgentX",
    api_hashes=[{"algorithm": "CRC32"}],
    persistence_mechanisms=["HKCU\\Software\\...\\Run\\UpdaterService"],
    c2_indicators=[".cdn-telemetry-cache.net"],
    imported_apis=["ExitProcess", "LoadLibraryA"],
)

# 2. Compare against a candidate or memory store
store = get_memory_store()
await store.initialize()

# Save fingerprint to current session
await save_fingerprint_to_memory(store, session_id="session_123", fingerprint=target_fp)

# Query and rank matches against historical memory
matches = await triage_sample_against_memory(store, target_fp)
for match in matches:
    print(f"Candidate: {match.candidate_binary_name} -> {match.classification.value}")
    print(match.summary_narrative)
```

---

## Guided Prompt (`similarity_triage_mode`)

AI agents can activate the triage workflow using FastMCP prompt registration:

```python
similarity_triage_mode(
    target_file="/app/workspace/unknown_sample.exe",
    candidate_session_or_hash="trojan_downloader_v1",
)
```
