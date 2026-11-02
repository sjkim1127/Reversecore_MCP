"""Malware Family Similarity Triage and Fingerprinting Engine.

This module provides an analyst workflow and multi-signal comparison engine
for answering: "Have I seen something structurally or behaviorally similar before?"

Instead of computing a single opaque score, the engine extracts and preserves
per-signal provenance across multiple dimensions:
- API hash resolvers (resolve_api_hashes)
- Persistence mechanisms (run_capa, decompilation)
- C2 infrastructure and indicators (extract_iocs)
- Crypto constants (find_crypto_constants)
- Normalized function signatures (generate_signature)
- Behavioral capabilities (run_capa)
- Notable IOCs (mutexes, named pipes, user-agents)
- Packer and protection traits (detect_packer)
- Generic system imports (parse_binary_with_lief)
- Superficial / utility strings (extract_iocs)

Invariant guarantees:
1. Contributing signals and provenance are preserved and explicitly explained.
2. Weak indicators (generic imports, superficial strings) cannot independently
   produce a strong family claim.
3. Unrelated samples sharing common runtime APIs are classified as SUPERFICIAL_ONLY
   and rejected as family candidates.
4. Fingerprints are portable across memory store sessions and export bundles.
5. Operates purely locally without requiring external malware-family services.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from reversecore_mcp.core import json_utils
from reversecore_mcp.core.logging_config import get_logger

if TYPE_CHECKING:
    from reversecore_mcp.core.memory import MemoryStore

logger = get_logger(__name__)


class SignalStrength(str, Enum):
    """Categorization of evidence signal strength."""

    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"


class SignalType(str, Enum):
    """Supported fingerprint signal dimensions."""

    API_HASH_RESOLVER = "api_hash_resolver"
    PERSISTENCE_CAPABILITY = "persistence_capability"
    C2_COMMUNICATION = "c2_communication"
    CRYPTO_CONSTANT = "crypto_constant"
    FUNCTION_SIGNATURE = "function_signature"
    BEHAVIORAL_CAPABILITY = "behavioral_capability"
    NOTABLE_IOC = "notable_ioc"
    PACKER_PROTECTOR = "packer_protector"
    GENERIC_IMPORT = "generic_import"
    SUPERFICIAL_STRING = "superficial_string"


class MatchStatus(str, Enum):
    """Status of signal comparison between two samples."""

    MATCH = "MATCH"
    DIFFERENT = "DIFFERENT"
    UNIQUE_TO_TARGET = "UNIQUE_TO_TARGET"
    UNIQUE_TO_CANDIDATE = "UNIQUE_TO_CANDIDATE"


class SimilarityClassification(str, Enum):
    """High-level classification of sample similarity."""

    STRONG_MATCH = "STRONG_MATCH"
    MODERATE_MATCH = "MODERATE_MATCH"
    SUPERFICIAL_ONLY = "SUPERFICIAL_ONLY"
    NO_MATCH = "NO_MATCH"


# Well-known generic Windows/POSIX APIs that carry low attribution weight
GENERIC_SYSTEM_APIS = frozenset(
    {
        "exitprocess",
        "loadlibrarya",
        "loadlibraryw",
        "getprocaddress",
        "virtualalloc",
        "virtualfree",
        "closehandle",
        "getlasterror",
        "setlasterror",
        "sleep",
        "getcurrentprocess",
        "getcurrentprocessid",
        "exit",
        "abort",
        "malloc",
        "free",
        "printf",
        "memcpy",
        "memset",
        "strlen",
    }
)

# Common generic utility strings that carry low attribution weight
GENERIC_STRINGS = frozenset(
    {
        "usage",
        "help",
        "version",
        "error",
        "windows",
        "success",
        "failed",
        "file not found",
        "path not found",
        "access denied",
    }
)


@dataclass
class FingerprintSignal:
    """An individual behavioral, structural, or heuristic signal in a sample fingerprint."""

    signal_type: SignalType
    key: str
    value: Any
    strength: SignalStrength
    provenance_tool: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_type": self.signal_type.value,
            "key": self.key,
            "value": self.value,
            "strength": self.strength.value,
            "provenance_tool": self.provenance_tool,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FingerprintSignal:
        raw_type = data.get("signal_type", "superficial_string")
        signal_type = (
            SignalType(raw_type)
            if raw_type in [t.value for t in SignalType]
            else SignalType.SUPERFICIAL_STRING
        )
        raw_strength = data.get("strength", "WEAK")
        strength = (
            SignalStrength(raw_strength)
            if raw_strength in [s.value for s in SignalStrength]
            else SignalStrength.WEAK
        )
        return cls(
            signal_type=signal_type,
            key=str(data.get("key", "")),
            value=data.get("value"),
            strength=strength,
            provenance_tool=str(data.get("provenance_tool", "unknown")),
            description=str(data.get("description", "")),
        )


@dataclass
class SampleFingerprint:
    """Compact reusable fingerprint derived from multiple analysis tools."""

    sample_id: str
    binary_name: str
    sha256: str
    family_label: str | None = None
    architecture: str = "x86_64"
    signals: list[FingerprintSignal] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_signal(
        self,
        signal_type: SignalType,
        key: str,
        value: Any,
        strength: SignalStrength,
        provenance_tool: str,
        description: str = "",
    ) -> None:
        """Add a signal to the fingerprint."""
        self.signals.append(
            FingerprintSignal(
                signal_type=signal_type,
                key=key,
                value=value,
                strength=strength,
                provenance_tool=provenance_tool,
                description=description,
            )
        )

    def get_signal_map(self) -> dict[str, FingerprintSignal]:
        """Return signals keyed by signal_type:key."""
        return {f"{s.signal_type.value}:{s.key}": s for s in self.signals}

    def get_compact_signature(self) -> str:
        """Derive a normalized compact prefix for SQLite pattern matching."""
        # Index key structural signals
        components = []
        if self.family_label:
            components.append(f"fam:{self.family_label.lower()}")
        for sig in self.signals:
            if sig.strength in (SignalStrength.STRONG, SignalStrength.MEDIUM):
                val_str = str(sig.value).strip().lower()[:24]
                components.append(f"{sig.signal_type.value}:{val_str}")
        if not components:
            components.append(f"hash:{self.sha256[:12]}")
        return "|".join(components[:5])

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "binary_name": self.binary_name,
            "sha256": self.sha256,
            "family_label": self.family_label,
            "architecture": self.architecture,
            "signals": [s.to_dict() for s in self.signals],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SampleFingerprint:
        signals = [FingerprintSignal.from_dict(s) for s in data.get("signals", [])]
        return cls(
            sample_id=str(data.get("sample_id", "")),
            binary_name=str(data.get("binary_name", "unknown")),
            sha256=str(data.get("sha256", "")),
            family_label=data.get("family_label"),
            architecture=str(data.get("architecture", "unknown")),
            signals=signals,
            metadata=dict(data.get("metadata", {})),
        )

    def to_memory_pattern(self, session_id: str) -> dict[str, Any]:
        """Format as parameters for MemoryStore.save_pattern."""
        return {
            "session_id": session_id,
            "pattern_type": "family_fingerprint",
            "pattern_signature": self.get_compact_signature(),
            "description": json_utils.dumps(self.to_dict()),
        }

    @classmethod
    def from_memory_pattern(cls, pattern_row: dict[str, Any]) -> SampleFingerprint:
        """Reconstruct from MemoryStore pattern row."""
        desc = pattern_row.get("description", "{}")
        try:
            data = json_utils.loads(desc)
            if isinstance(data, dict) and "sha256" in data:
                return cls.from_dict(data)
        except Exception as e:
            logger.warning(f"Failed to deserialize fingerprint pattern: {e}")
        return cls(
            sample_id=str(pattern_row.get("id", "unknown")),
            binary_name=pattern_row.get("binary_name", "unknown"),
            sha256="",
            family_label=None,
        )


@dataclass
class SignalMatchExplanation:
    """Detailed per-signal comparison explanation with tool provenance."""

    signal_type: str
    signal_key: str
    strength: str
    status: str
    target_value: Any
    candidate_value: Any
    explanation: str
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SimilarityComparison:
    """Multi-dimensional similarity comparison between target and candidate."""

    target_sample_id: str
    target_binary_name: str
    candidate_sample_id: str
    candidate_binary_name: str
    candidate_family: str | None
    classification: SimilarityClassification
    signal_explanations: list[SignalMatchExplanation]
    strong_matches_count: int
    medium_matches_count: int
    weak_matches_count: int
    conflicting_signals_count: int
    shared_file_hash: bool
    summary_narrative: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_sample_id": self.target_sample_id,
            "target_binary_name": self.target_binary_name,
            "candidate_sample_id": self.candidate_sample_id,
            "candidate_binary_name": self.candidate_binary_name,
            "candidate_family": self.candidate_family,
            "classification": self.classification.value,
            "strong_matches_count": self.strong_matches_count,
            "medium_matches_count": self.medium_matches_count,
            "weak_matches_count": self.weak_matches_count,
            "conflicting_signals_count": self.conflicting_signals_count,
            "shared_file_hash": self.shared_file_hash,
            "summary_narrative": self.summary_narrative,
            "signal_explanations": [s.to_dict() for s in self.signal_explanations],
        }

    def format_markdown(self) -> str:
        """Format the comparison as an analyst-readable markdown report."""
        lines = [
            f"### Malware Family Similarity Triage: `{self.target_binary_name}` vs `{self.candidate_binary_name}`",
            "",
            f"- **Classification**: `{self.classification.value}`",
            f"- **Candidate Family**: `{self.candidate_family or 'None (Unattributed)'}`",
            f"- **Shared SHA-256**: `{'Yes' if self.shared_file_hash else 'No'}`",
            "- **Contributing Evidence Signals**:",
            f"  - Strong Matches: **{self.strong_matches_count}**",
            f"  - Medium Matches: **{self.medium_matches_count}**",
            f"  - Weak Matches (Generic/Superficial): **{self.weak_matches_count}**",
            f"  - Conflicting / Divergent Signals: **{self.conflicting_signals_count}**",
            "",
            "#### Analysis Summary",
            self.summary_narrative,
            "",
            "#### Signal Provenance & Explanations",
            "| Signal Type | Dimension | Strength | Match Status | Provenance Tool | Details |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for s in self.signal_explanations:
            status_badge = {
                MatchStatus.MATCH.value: "✅ MATCH",
                MatchStatus.DIFFERENT.value: "⚠️ DIFFERENT",
                MatchStatus.UNIQUE_TO_TARGET.value: "➡️ TARGET ONLY",
                MatchStatus.UNIQUE_TO_CANDIDATE.value: "⬅️ CANDIDATE ONLY",
            }.get(s.status, s.status)
            lines.append(
                f"| `{s.signal_type}` | `{s.signal_key}` | `{s.strength}` | {status_badge} | `{s.provenance}` | {s.explanation} |"
            )
        return "\n".join(lines)


def _values_match(val1: Any, val2: Any) -> bool:
    """Check if two signal values match, supporting strings, numbers, lists, or suffixes."""
    if val1 is None or val2 is None:
        return False
    if val1 == val2:
        return True

    # String comparison with normalized case
    if isinstance(val1, str) and isinstance(val2, str):
        s1 = val1.strip().lower()
        s2 = val2.strip().lower()
        if s1 == s2:
            return True
        # Domain suffix matching (e.g. .evil-corp.com)
        if (s1.startswith(".") and s2.endswith(s1)) or (s2.startswith(".") and s1.endswith(s2)):
            return True
        return False

    # List / Set overlap
    if isinstance(val1, (list, set, tuple)) and isinstance(val2, (list, set, tuple)):
        s1_set = {str(x).strip().lower() for x in val1}
        s2_set = {str(x).strip().lower() for x in val2}
        return bool(s1_set.intersection(s2_set))

    return False


def compare_fingerprints(
    target: SampleFingerprint,
    candidate: SampleFingerprint,
) -> SimilarityComparison:
    """Compare a target sample fingerprint against a candidate fingerprint.

    Evaluates structural, behavioral, and heuristic signals with per-signal
    provenance and strict invariants preventing weak-signal family claims.

    Args:
        target: Target sample fingerprint under analysis.
        candidate: Candidate sample fingerprint recalled from memory.

    Returns:
        Structured SimilarityComparison with explicit explanations.
    """
    shared_file_hash = (
        bool(target.sha256 and candidate.sha256)
        and target.sha256.lower() == candidate.sha256.lower()
    )

    explanations: list[SignalMatchExplanation] = []
    strong_matches = 0
    medium_matches = 0
    weak_matches = 0
    conflicts = 0

    target_map = target.get_signal_map()
    candidate_map = candidate.get_signal_map()
    all_keys = set(target_map.keys()).union(set(candidate_map.keys()))

    # Track narrative bullets
    narrative_points = []

    # Check architecture compatibility
    if (
        target.architecture
        and candidate.architecture
        and target.architecture != "unknown"
        and candidate.architecture != "unknown"
    ):
        if target.architecture != candidate.architecture:
            conflicts += 1
            narrative_points.append(
                f"Architecture mismatch (Target: {target.architecture}, Candidate: {candidate.architecture})"
            )
            explanations.append(
                SignalMatchExplanation(
                    signal_type="architecture",
                    signal_key="target_arch",
                    strength=SignalStrength.MEDIUM.value,
                    status=MatchStatus.DIFFERENT.value,
                    target_value=target.architecture,
                    candidate_value=candidate.architecture,
                    explanation=f"Conflicting architectures: {target.architecture} vs {candidate.architecture}",
                    provenance="binary_metadata",
                )
            )

    for composite_key in sorted(all_keys):
        in_target = composite_key in target_map
        in_candidate = composite_key in candidate_map

        if in_target and in_candidate:
            t_sig = target_map[composite_key]
            c_sig = candidate_map[composite_key]
            strength = t_sig.strength

            if _values_match(t_sig.value, c_sig.value):
                status = MatchStatus.MATCH
                if strength == SignalStrength.STRONG:
                    strong_matches += 1
                elif strength == SignalStrength.MEDIUM:
                    medium_matches += 1
                else:
                    weak_matches += 1

                explanation = f"Exact or compatible match: '{t_sig.value}'"
                provenance = (
                    f"{t_sig.provenance_tool} / {c_sig.provenance_tool}"
                    if t_sig.provenance_tool != c_sig.provenance_tool
                    else t_sig.provenance_tool
                )
                narrative_points.append(
                    f"Matching {t_sig.signal_type.value} ({t_sig.key}='{t_sig.value}') via {provenance}"
                )
            else:
                status = MatchStatus.DIFFERENT
                conflicts += 1
                explanation = (
                    f"Different values: target='{t_sig.value}' vs candidate='{c_sig.value}'"
                )
                provenance = f"{t_sig.provenance_tool} vs {c_sig.provenance_tool}"
                narrative_points.append(
                    f"Different {t_sig.signal_type.value} (Target: '{t_sig.value}', Candidate: '{c_sig.value}')"
                )

            explanations.append(
                SignalMatchExplanation(
                    signal_type=t_sig.signal_type.value,
                    signal_key=t_sig.key,
                    strength=strength.value,
                    status=status.value,
                    target_value=t_sig.value,
                    candidate_value=c_sig.value,
                    explanation=explanation,
                    provenance=provenance,
                )
            )
        elif in_target:
            t_sig = target_map[composite_key]
            explanations.append(
                SignalMatchExplanation(
                    signal_type=t_sig.signal_type.value,
                    signal_key=t_sig.key,
                    strength=t_sig.strength.value,
                    status=MatchStatus.UNIQUE_TO_TARGET.value,
                    target_value=t_sig.value,
                    candidate_value=None,
                    explanation=f"Signal present only in target sample ('{t_sig.value}')",
                    provenance=t_sig.provenance_tool,
                )
            )
        else:
            c_sig = candidate_map[composite_key]
            explanations.append(
                SignalMatchExplanation(
                    signal_type=c_sig.signal_type.value,
                    signal_key=c_sig.key,
                    strength=c_sig.strength.value,
                    status=MatchStatus.UNIQUE_TO_CANDIDATE.value,
                    target_value=None,
                    candidate_value=c_sig.value,
                    explanation=f"Signal present only in candidate sample ('{c_sig.value}')",
                    provenance=c_sig.provenance_tool,
                )
            )

    # Note file hash relationship explicitly
    if shared_file_hash:
        narrative_points.append(f"Identical file SHA-256 hash ({target.sha256})")
    else:
        narrative_points.append("No shared file hash (distinct binary samples)")

    # Strict classification rules
    # Invariant: Weak indicators (generic imports, superficial strings) cannot independently assert family candidate
    candidate_family: str | None = None

    if strong_matches >= 2 or (strong_matches >= 1 and medium_matches >= 2):
        classification = SimilarityClassification.STRONG_MATCH
        candidate_family = candidate.family_label or "Suspected_Related_Variant"
        summary_intro = (
            f"Strong family similarity detected between '{target.binary_name}' and '{candidate.binary_name}'. "
            f"Attribution supported by {strong_matches} strong distinctive signals and {medium_matches} medium signals."
        )
    elif strong_matches >= 1 or medium_matches >= 2:
        classification = SimilarityClassification.MODERATE_MATCH
        candidate_family = candidate.family_label or "Probable_Variant_Association"
        summary_intro = (
            f"Moderate behavioral/structural overlap observed between '{target.binary_name}' and '{candidate.binary_name}'. "
            f"Further analysis recommended to verify variant relationship."
        )
    elif weak_matches > 0 and strong_matches == 0 and medium_matches == 0 and conflicts >= 0:
        classification = SimilarityClassification.SUPERFICIAL_ONLY
        candidate_family = None
        summary_intro = (
            f"Superficial overlap only. Samples share {weak_matches} generic system imports or utility strings. "
            f"These common indicators cannot independently substantiate malware-family attribution or relationship."
        )
    else:
        classification = SimilarityClassification.NO_MATCH
        candidate_family = None
        summary_intro = f"No meaningful structural or behavioral similarity between '{target.binary_name}' and '{candidate.binary_name}'."

    summary_narrative = f"{summary_intro}\nKey Dimensions:\n" + "\n".join(
        f"- {p}" for p in narrative_points
    )

    return SimilarityComparison(
        target_sample_id=target.sample_id,
        target_binary_name=target.binary_name,
        candidate_sample_id=candidate.sample_id,
        candidate_binary_name=candidate.binary_name,
        candidate_family=candidate_family,
        classification=classification,
        signal_explanations=explanations,
        strong_matches_count=strong_matches,
        medium_matches_count=medium_matches,
        weak_matches_count=weak_matches,
        conflicting_signals_count=conflicts,
        shared_file_hash=shared_file_hash,
        summary_narrative=summary_narrative,
    )


def derive_sample_fingerprint(
    sample_id: str,
    binary_name: str,
    sha256: str,
    architecture: str = "x86_64",
    family_label: str | None = None,
    api_hashes: list[dict[str, Any]] | None = None,
    persistence_mechanisms: list[str] | None = None,
    c2_indicators: list[str] | None = None,
    crypto_constants: list[str] | None = None,
    function_signatures: dict[str, str] | None = None,
    capa_capabilities: list[str] | None = None,
    notable_iocs: list[dict[str, str]] | None = None,
    packer_name: str | None = None,
    imported_apis: list[str] | None = None,
    strings: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> SampleFingerprint:
    """Derive a SampleFingerprint from raw outputs of existing tools."""
    fingerprint = SampleFingerprint(
        sample_id=sample_id,
        binary_name=binary_name,
        sha256=sha256,
        family_label=family_label,
        architecture=architecture,
        metadata=metadata or {},
    )

    # 1. API Hash Resolvers (STRONG)
    if api_hashes:
        for item in api_hashes:
            algo = item.get("algorithm", "unknown")
            fingerprint.add_signal(
                signal_type=SignalType.API_HASH_RESOLVER,
                key=f"algorithm:{algo}",
                value=algo,
                strength=SignalStrength.STRONG,
                provenance_tool="resolve_api_hashes",
                description=f"API hashing algorithm: {algo}",
            )

    # 2. Persistence Capabilities (STRONG)
    if persistence_mechanisms:
        for mech in persistence_mechanisms:
            fingerprint.add_signal(
                signal_type=SignalType.PERSISTENCE_CAPABILITY,
                key=f"mechanism:{mech.lower()}",
                value=mech,
                strength=SignalStrength.STRONG,
                provenance_tool="run_capa",
                description=f"Persistence capability: {mech}",
            )

    # 3. C2 Indicators / Domain Patterns (STRONG)
    if c2_indicators:
        for ind in c2_indicators:
            # If domain or suffix
            key = f"domain_suffix:{ind}" if ind.startswith(".") else f"endpoint:{ind}"
            fingerprint.add_signal(
                signal_type=SignalType.C2_COMMUNICATION,
                key=key,
                value=ind,
                strength=SignalStrength.STRONG,
                provenance_tool="extract_iocs",
                description=f"C2 indicator or domain pattern: {ind}",
            )

    # 4. Crypto Constants (STRONG)
    if crypto_constants:
        for c in crypto_constants:
            fingerprint.add_signal(
                signal_type=SignalType.CRYPTO_CONSTANT,
                key=f"constant:{c.lower()}",
                value=c,
                strength=SignalStrength.STRONG,
                provenance_tool="find_crypto_constants",
                description=f"Cryptographic constant: {c}",
            )

    # 5. Function Signatures (STRONG)
    if function_signatures:
        for fn_name, sig in function_signatures.items():
            fingerprint.add_signal(
                signal_type=SignalType.FUNCTION_SIGNATURE,
                key=f"function:{fn_name}",
                value=sig,
                strength=SignalStrength.STRONG,
                provenance_tool="generate_signature",
                description=f"Normalized signature for function {fn_name}",
            )

    # 6. Behavioral Capabilities (MEDIUM)
    if capa_capabilities:
        for cap in capa_capabilities:
            fingerprint.add_signal(
                signal_type=SignalType.BEHAVIORAL_CAPABILITY,
                key=f"capa:{cap.lower()}",
                value=cap,
                strength=SignalStrength.MEDIUM,
                provenance_tool="run_capa",
                description=f"Capability detection: {cap}",
            )

    # 7. Notable IOCs (MEDIUM)
    if notable_iocs:
        for ioc in notable_iocs:
            ioc_type = ioc.get("type", "generic")
            ioc_val = ioc.get("value", "")
            fingerprint.add_signal(
                signal_type=SignalType.NOTABLE_IOC,
                key=f"{ioc_type}:{ioc_val}",
                value=ioc_val,
                strength=SignalStrength.MEDIUM,
                provenance_tool="extract_iocs",
                description=f"Notable {ioc_type}: {ioc_val}",
            )

    # 8. Packer / Protector (MEDIUM)
    if packer_name:
        fingerprint.add_signal(
            signal_type=SignalType.PACKER_PROTECTOR,
            key="packer_type",
            value=packer_name,
            strength=SignalStrength.MEDIUM,
            provenance_tool="detect_packer",
            description=f"Packer or protection observation: {packer_name}",
        )

    # 9. Generic Imports (WEAK)
    if imported_apis:
        for api in imported_apis:
            api_clean = api.strip().lower()
            if api_clean in GENERIC_SYSTEM_APIS:
                fingerprint.add_signal(
                    signal_type=SignalType.GENERIC_IMPORT,
                    key=f"import:{api_clean}",
                    value=api,
                    strength=SignalStrength.WEAK,
                    provenance_tool="parse_binary_with_lief",
                    description=f"Generic standard system API: {api}",
                )

    # 10. Superficial Strings (WEAK)
    if strings:
        for s in strings:
            s_clean = s.strip().lower()
            if any(generic in s_clean for generic in GENERIC_STRINGS):
                fingerprint.add_signal(
                    signal_type=SignalType.SUPERFICIAL_STRING,
                    key=f"string:{s_clean[:20]}",
                    value=s,
                    strength=SignalStrength.WEAK,
                    provenance_tool="extract_iocs",
                    description=f"Superficial utility string: {s}",
                )

    return fingerprint


async def save_fingerprint_to_memory(
    store: MemoryStore,
    session_id: str,
    fingerprint: SampleFingerprint,
) -> int:
    """Save a sample fingerprint into the MemoryStore pattern and memory subsystem.

    Args:
        store: Initialized MemoryStore instance.
        session_id: Active analysis session ID.
        fingerprint: Extracted SampleFingerprint object.

    Returns:
        Pattern database row ID.
    """
    await store.initialize()
    pattern_args = fingerprint.to_memory_pattern(session_id)
    pattern_id = await store.save_pattern(
        session_id=pattern_args["session_id"],
        pattern_type=pattern_args["pattern_type"],
        pattern_signature=pattern_args["pattern_signature"],
        description=pattern_args["description"],
    )

    # Also record as a structured memory item for retrieval
    await store.save_memory(
        session_id=session_id,
        memory_type="finding",
        content=f"SampleFingerprint for {fingerprint.binary_name} ({fingerprint.sha256[:12]}...): "
        f"{len(fingerprint.signals)} signals recorded.",
        category="family_fingerprint",
        importance=8,
    )
    logger.info(
        f"Saved fingerprint for {fingerprint.binary_name} into session {session_id} (pattern_id: {pattern_id})"
    )
    return pattern_id


async def query_candidate_fingerprints(
    store: MemoryStore,
    exclude_session: str | None = None,
    limit: int = 50,
) -> list[SampleFingerprint]:
    """Retrieve stored sample fingerprints from memory across prior sessions.

    Args:
        store: Initialized MemoryStore instance.
        exclude_session: Session ID to exclude from results.
        limit: Maximum candidates to retrieve.

    Returns:
        List of deserialized SampleFingerprint candidates.
    """
    await store.initialize()
    # Query all patterns of type 'family_fingerprint'
    pattern_rows = await store.find_similar_patterns(
        pattern_signature="",
        pattern_type="family_fingerprint",
        exclude_session=exclude_session,
        limit=limit,
    )

    candidates: list[SampleFingerprint] = []
    for row in pattern_rows:
        try:
            cand = SampleFingerprint.from_memory_pattern(row)
            if cand.sha256:
                candidates.append(cand)
        except Exception as e:
            logger.warning(f"Error parsing fingerprint from row {row.get('id')}: {e}")
    return candidates


async def triage_sample_against_memory(
    store: MemoryStore,
    target: SampleFingerprint,
    current_session_id: str | None = None,
    limit: int = 10,
) -> list[SimilarityComparison]:
    """Perform similarity triage for target sample against all candidate fingerprints in memory.

    Args:
        store: Initialized MemoryStore instance.
        target: Target sample fingerprint under analysis.
        current_session_id: Active session to exclude from matching candidates.
        limit: Maximum comparisons to return.

    Returns:
        List of SimilarityComparison objects sorted by match strength.
    """
    candidates = await query_candidate_fingerprints(
        store=store,
        exclude_session=current_session_id,
        limit=limit * 2,
    )

    comparisons: list[SimilarityComparison] = []
    for cand in candidates:
        # Avoid comparing against exact same sample unless comparing distinct sessions
        if cand.sha256 and cand.sha256.lower() == target.sha256.lower():
            # If hashes match exactly, compare to report identical sample
            pass
        comp = compare_fingerprints(target, cand)
        comparisons.append(comp)

    # Sort comparisons: STRONG_MATCH first, then MODERATE_MATCH, then SUPERFICIAL_ONLY, then NO_MATCH
    priority_order = {
        SimilarityClassification.STRONG_MATCH: 0,
        SimilarityClassification.MODERATE_MATCH: 1,
        SimilarityClassification.SUPERFICIAL_ONLY: 2,
        SimilarityClassification.NO_MATCH: 3,
    }
    comparisons.sort(
        key=lambda c: (
            priority_order.get(c.classification, 99),
            -c.strong_matches_count,
            -c.medium_matches_count,
            -c.weak_matches_count,
        )
    )

    return comparisons[:limit]
