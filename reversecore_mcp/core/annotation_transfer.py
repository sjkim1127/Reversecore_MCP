"""Cross-binary annotation and knowledge transfer engine.

Enables safe propagation of analyst annotations, bookmarks, structure definitions,
and investigation findings across related binaries or version revisions using
deterministic function identity matching.

Matches functions using:
1. Architecture compatibility verification
2. Exact normalized code/opcode hash or identical CFG signature
3. Strong structural CFG similarity (basic blocks, complexity, calls)
4. Probable similarity (moderate structural overlap or name alignment)
5. Explicit ambiguity detection (unresolved 1-to-many / many-to-one candidates)
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class MatchState(str, Enum):
    """Function identity match classification."""

    EXACT = "exact"
    STRONG_MATCH = "strong_match"
    PROBABLE = "probable"
    AMBIGUOUS = "ambiguous"
    UNMATCHED = "unmatched"


class TransferStatus(str, Enum):
    """Lifecycle status of a transferred annotation."""

    SUGGESTED = "suggested"
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


@dataclass
class FunctionFingerprint:
    """Structural and semantic fingerprint of a binary function."""

    name: str
    address: str
    offset: int
    size: int
    cc: int = 1
    nbbs: int = 1
    edges: int = 0
    opcode_hash: str = ""
    calls: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionMatch:
    """Result of matching a source function to a target function."""

    source_function: str
    target_function: str
    source_address: str
    target_address: str
    source_offset: int
    target_offset: int
    match_state: MatchState
    confidence: float
    similarity_score: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["match_state"] = self.match_state.value
        return data


@dataclass
class TransferredItem:
    """A single transferred annotation, bookmark, structure, or finding."""

    id: int | None
    source_binary_hash: str
    target_binary_hash: str
    source_function: str
    target_function: str
    source_address: str
    target_address: str
    item_type: str  # 'bookmark', 'structure', 'type', 'finding', 'hypothesis', 'analyst_note'
    name: str
    content: dict[str, Any]
    match_state: MatchState
    confidence: float
    status: TransferStatus
    source_provenance: dict[str, Any]
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["match_state"] = self.match_state.value
        data["status"] = self.status.value
        return data


def compute_file_sha256(path: Path | str) -> str:
    """Return SHA-256 hex digest of a file."""
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


class CrossBinaryTransferEngine:
    """Orchestrates cross-binary function matching and annotation transfer."""

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout

    async def check_architecture_compatibility(
        self, file_path_a: Path | str, file_path_b: Path | str
    ) -> dict[str, Any]:
        """Verify binary architectures and formats are compatible for transfer."""
        path_a = validate_file_path(str(file_path_a))
        path_b = validate_file_path(str(file_path_b))

        info_a = await self._get_binary_info(path_a)
        info_b = await self._get_binary_info(path_b)

        arch_a = info_a.get("arch", "unknown")
        bits_a = info_a.get("bits", 0)
        os_a = info_a.get("os", "unknown")

        arch_b = info_b.get("arch", "unknown")
        bits_b = info_b.get("bits", 0)
        os_b = info_b.get("os", "unknown")

        compatible = True
        reasons: list[str] = []

        if arch_a != "unknown" and arch_b != "unknown" and arch_a != arch_b:
            compatible = False
            reasons.append(f"Architecture mismatch: '{arch_a}' vs '{arch_b}'")

        if bits_a != 0 and bits_b != 0 and bits_a != bits_b:
            compatible = False
            reasons.append(f"Word size mismatch: {bits_a}-bit vs {bits_b}-bit")

        if os_a != "unknown" and os_b != "unknown" and os_a != os_b:
            reasons.append(f"Operating system difference: '{os_a}' vs '{os_b}' (warning)")

        return {
            "compatible": compatible,
            "binary_a": {
                "path": str(path_a),
                "arch": arch_a,
                "bits": bits_a,
                "os": os_a,
            },
            "binary_b": {
                "path": str(path_b),
                "arch": arch_b,
                "bits": bits_b,
                "os": os_b,
            },
            "reasons": reasons,
        }

    async def _get_binary_info(self, path: Path) -> dict[str, Any]:
        """Extract architecture and file metadata using r2."""
        if not shutil.which("r2"):
            return {"arch": "unknown", "bits": 0, "os": "unknown"}

        try:
            cmd = ["r2", "-qc", "ij", str(path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            bin_info = data.get("bin", {})
            return {
                "arch": bin_info.get("arch", "unknown"),
                "bits": bin_info.get("bits", 0),
                "os": bin_info.get("os", "unknown"),
                "bclass": bin_info.get("bclass", "unknown"),
            }
        except Exception as exc:
            logger.debug(f"Failed to get binary info via r2 for {path}: {exc}")
            return {"arch": "unknown", "bits": 0, "os": "unknown"}

    async def extract_functions(self, file_path: Path | str) -> list[FunctionFingerprint]:
        """Extract function fingerprints including CFG metrics and opcode hashes."""
        path = validate_file_path(str(file_path))
        if not shutil.which("r2"):
            logger.warning("r2 not available; cannot extract functions")
            return []

        try:
            # Analyze functions with aaa and output aflj
            cmd = ["r2", "-qc", "aaa; aflj", str(path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            out_str = stdout.decode("utf-8", errors="replace").strip()
            if not out_str:
                return []

            # Locate start of JSON array in stdout
            idx = out_str.find("[")
            if idx == -1:
                return []
            funcs_data = json.loads(out_str[idx:])

            fingerprints: list[FunctionFingerprint] = []
            for f in funcs_data:
                offset = f.get("offset")
                if offset is None:
                    continue
                name = f.get("name", f"fcn.{offset:08x}")
                size = f.get("size", 0)
                cc = f.get("cc", 1)
                nbbs = f.get("nbbs", 1)
                edges = f.get("edges", 0)
                calls = f.get("calls", [])
                if isinstance(calls, list):
                    call_names = [
                        c.get("name", str(c)) if isinstance(c, dict) else str(c) for c in calls
                    ]
                else:
                    call_names = []

                # Compute normalized opcode hash for function
                opcode_hash = await self._compute_opcode_hash(path, offset, size)

                fingerprints.append(
                    FunctionFingerprint(
                        name=name,
                        address=f"0x{offset:x}",
                        offset=offset,
                        size=size,
                        cc=cc,
                        nbbs=nbbs,
                        edges=edges,
                        opcode_hash=opcode_hash,
                        calls=call_names,
                    )
                )

            return fingerprints
        except Exception as exc:
            logger.warning(f"Failed to extract functions from {path}: {exc}")
            return []

    async def _compute_opcode_hash(self, path: Path, offset: int, size: int) -> str:
        """Read opcode bytes for function and return deterministic SHA-256."""
        if size <= 0:
            return ""
        read_len = min(size, 256)
        try:
            cmd = ["r2", "-qc", f"s {offset}; p8 {read_len}", str(path)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            hex_bytes = stdout.decode("utf-8", errors="replace").strip()
            if hex_bytes:
                return hashlib.sha256(hex_bytes.encode()).hexdigest()
        except Exception:
            pass
        return ""

    async def _run_radiff2_graphdiff(self, path_a: Path, path_b: Path) -> list[dict[str, Any]]:
        """Run radiff2 -A -C -j to obtain native function diffing if radiff2 exists."""
        if not shutil.which("radiff2"):
            return []

        try:
            cmd = ["radiff2", "-A", "-C", "-j", str(path_a), str(path_b)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            out_str = stdout.decode("utf-8", errors="replace").strip()
            if not out_str:
                return []
            idx = out_str.find("[")
            if idx != -1:
                parsed = json.loads(out_str[idx:])
                if isinstance(parsed, list):
                    return [item for item in parsed if isinstance(item, dict)]
        except Exception as exc:
            logger.debug(f"radiff2 graphdiff failed or timed out: {exc}")
        return []

    def match_functions(
        self,
        source_funcs: list[FunctionFingerprint],
        target_funcs: list[FunctionFingerprint],
        radiff2_diffs: list[dict[str, Any]] | None = None,
        min_confidence: float = 0.60,
    ) -> list[FunctionMatch]:
        """Compute deterministic function matches across source and target binaries."""
        matches: list[FunctionMatch] = []
        target_by_offset: dict[int, FunctionFingerprint] = {f.offset: f for f in target_funcs}

        # Build index of radiff2 recommendations
        radiff_map: dict[int, dict[str, Any]] = {}
        if radiff2_diffs:
            for item in radiff2_diffs:
                src_addr = item.get("addr")
                if src_addr is not None:
                    radiff_map[src_addr] = item

        # Candidate mapping: src_idx -> list of (target_func, score, rationale)
        candidates_per_source: dict[int, list[tuple[FunctionFingerprint, float, str]]] = {}

        for s_idx, src in enumerate(source_funcs):
            candidates_per_source[s_idx] = []

            # 1. Check radiff2 suggestion first
            if src.offset in radiff_map:
                rd = radiff_map[src.offset]
                diff_addr = rd.get("diff_addr")
                dist = float(rd.get("dist", 1.0))
                is_match = rd.get("match") == "MATCH"
                if diff_addr in target_by_offset:
                    tgt = target_by_offset[diff_addr]
                    score = 1.0 if (is_match and dist >= 0.99) else max(0.5, dist)
                    candidates_per_source[s_idx].append(
                        (tgt, score, f"radiff2 graphdiff match (dist={dist:.3f})")
                    )

            # 2. Score against all target functions
            for tgt in target_funcs:
                # Avoid duplicate entry from radiff
                if any(c[0].offset == tgt.offset for c in candidates_per_source[s_idx]):
                    continue

                score, rationale = self._score_function_pair(src, tgt)
                if score >= min_confidence:
                    candidates_per_source[s_idx].append((tgt, score, rationale))

            # Sort candidates by score descending
            candidates_per_source[s_idx].sort(key=lambda x: x[1], reverse=True)

        # Reverse candidate index to detect many-to-one ambiguity
        target_match_sources: dict[int, list[tuple[int, float]]] = {}
        for s_idx, cand_list in candidates_per_source.items():
            if cand_list:
                top_tgt, top_score, _ = cand_list[0]
                target_match_sources.setdefault(top_tgt.offset, []).append((s_idx, top_score))

        # Detect many-to-one ambiguity: if multiple source functions claim the same target
        ambiguous_targets: set[int] = set()
        for tgt_offset, claimants in target_match_sources.items():
            if len(claimants) > 1:
                # If claimants have close scores (within 0.10)
                scores = [s for _, s in claimants]
                if max(scores) - min(scores) <= 0.10:
                    ambiguous_targets.add(tgt_offset)

        # Assemble final match decisions
        for s_idx, src in enumerate(source_funcs):
            cands = candidates_per_source.get(s_idx, [])
            if not cands:
                matches.append(
                    FunctionMatch(
                        source_function=src.name,
                        target_function="",
                        source_address=src.address,
                        target_address="",
                        source_offset=src.offset,
                        target_offset=0,
                        match_state=MatchState.UNMATCHED,
                        confidence=0.0,
                        similarity_score=0.0,
                        rationale="No target candidate met the minimum confidence threshold.",
                    )
                )
                continue

            top_tgt, top_score, top_rationale = cands[0]

            # Check for one-to-many ambiguity: multiple candidates with close scores
            if len(cands) > 1 and (cands[0][1] - cands[1][1] < 0.05):
                cand_names = f"{cands[0][0].name} ({cands[0][1]:.2f}) vs {cands[1][0].name} ({cands[1][1]:.2f})"
                matches.append(
                    FunctionMatch(
                        source_function=src.name,
                        target_function=top_tgt.name,
                        source_address=src.address,
                        target_address=top_tgt.address,
                        source_offset=src.offset,
                        target_offset=top_tgt.offset,
                        match_state=MatchState.AMBIGUOUS,
                        confidence=0.0,
                        similarity_score=top_score,
                        rationale=f"One-to-many ambiguity: multiple target candidates have close scores [{cand_names}]. Unresolved.",
                    )
                )
                continue

            # Check for many-to-one ambiguity
            if top_tgt.offset in ambiguous_targets:
                matches.append(
                    FunctionMatch(
                        source_function=src.name,
                        target_function=top_tgt.name,
                        source_address=src.address,
                        target_address=top_tgt.address,
                        source_offset=src.offset,
                        target_offset=top_tgt.offset,
                        match_state=MatchState.AMBIGUOUS,
                        confidence=0.0,
                        similarity_score=top_score,
                        rationale=f"Many-to-one ambiguity: target function '{top_tgt.name}' claimed by multiple source functions with close scores. Unresolved.",
                    )
                )
                continue

            # Classify match state based on confidence
            is_exact = False
            if (
                src.opcode_hash
                and top_tgt.opcode_hash
                and src.opcode_hash == top_tgt.opcode_hash
                and src.size > 0
            ):
                is_exact = True
            elif (
                src.name == top_tgt.name
                and not src.name.startswith("fcn.")
                and not src.name.startswith("sym.imp.")
                and src.size == top_tgt.size
                and src.nbbs == top_tgt.nbbs
                and src.cc == top_tgt.cc
                and (not src.calls or src.calls == top_tgt.calls)
            ):
                is_exact = True

            if is_exact:
                state = MatchState.EXACT
                conf = 1.0
            elif top_score >= 0.85:
                state = MatchState.STRONG_MATCH
                conf = round(top_score, 2)
            elif top_score >= min_confidence:
                state = MatchState.PROBABLE
                conf = round(top_score, 2)
            else:
                state = MatchState.UNMATCHED
                conf = 0.0

            matches.append(
                FunctionMatch(
                    source_function=src.name,
                    target_function=top_tgt.name,
                    source_address=src.address,
                    target_address=top_tgt.address,
                    source_offset=src.offset,
                    target_offset=top_tgt.offset,
                    match_state=state,
                    confidence=conf,
                    similarity_score=round(top_score, 3),
                    rationale=top_rationale,
                )
            )

        return matches

    def _score_function_pair(
        self, src: FunctionFingerprint, tgt: FunctionFingerprint
    ) -> tuple[float, str]:
        """Compute composite similarity score (0.0 to 1.0) and rationale between two functions."""
        # 1. Exact normalized bytecode match
        if src.opcode_hash and tgt.opcode_hash and src.opcode_hash == tgt.opcode_hash:
            return 1.0, "Identical opcode bytecode hash."

        # 2. Identical named function with matching structure
        is_named = not src.name.startswith("fcn.") and not src.name.startswith("sym.imp.")
        same_name = src.name == tgt.name
        if same_name and is_named:
            if src.nbbs == tgt.nbbs and src.cc == tgt.cc and src.size == tgt.size:
                return (
                    1.0,
                    f"Identical symbol name '{src.name}' with identical CFG size and complexity.",
                )

        # 3. Structural feature weighting
        # Name score (0.25): strong weight if both have the same named symbol
        name_score = 1.0 if (same_name and is_named) else 0.0

        # Basic block similarity (0.25)
        max_nbbs = max(src.nbbs, tgt.nbbs, 1)
        nbbs_score = 1.0 - (abs(src.nbbs - tgt.nbbs) / max_nbbs)

        # Cyclomatic complexity similarity (0.20)
        max_cc = max(src.cc, tgt.cc, 1)
        cc_score = 1.0 - (abs(src.cc - tgt.cc) / max_cc)

        # Function size similarity (0.15)
        max_size = max(src.size, tgt.size, 1)
        size_score = 1.0 - (abs(src.size - tgt.size) / max_size)

        # API Call / xref overlap (0.15)
        if src.calls and tgt.calls:
            set_a = set(src.calls)
            set_b = set(tgt.calls)
            intersection = len(set_a & set_b)
            union = len(set_a | set_b)
            call_score = intersection / union if union > 0 else 0.0
        elif not src.calls and not tgt.calls:
            call_score = 1.0
        else:
            call_score = 0.0

        total_score = (
            name_score * 0.25
            + nbbs_score * 0.25
            + cc_score * 0.20
            + size_score * 0.15
            + call_score * 0.15
        )

        rationale = (
            f"CFG metrics: nbbs_sim={nbbs_score:.2f}, cc_sim={cc_score:.2f}, "
            f"size_sim={size_score:.2f}, name_match={name_score:.1f}, calls_sim={call_score:.2f}"
        )
        return total_score, rationale

    async def execute_transfer(
        self,
        source_path: Path | str,
        target_path: Path | str,
        auto_apply_exact: bool = False,
        case_id: str | None = None,
        min_confidence: float = 0.60,
    ) -> dict[str, Any]:
        """Perform end-to-end annotation transfer across binaries."""
        path_src = validate_file_path(str(source_path))
        path_tgt = validate_file_path(str(target_path))

        src_hash = compute_file_sha256(path_src)
        tgt_hash = compute_file_sha256(path_tgt)

        # Check architecture compatibility
        arch_check = await self.check_architecture_compatibility(path_src, path_tgt)
        if not arch_check["compatible"]:
            return {
                "status": "error",
                "error": "Incompatible binary architectures",
                "details": arch_check["reasons"],
                "transferred_count": 0,
                "transfers": [],
            }

        # Extract functions
        src_funcs, tgt_funcs = await asyncio.gather(
            self.extract_functions(path_src),
            self.extract_functions(path_tgt),
        )

        if not src_funcs or not tgt_funcs:
            return {
                "status": "error",
                "error": "Could not extract functions from one or both binaries",
                "src_function_count": len(src_funcs),
                "tgt_function_count": len(tgt_funcs),
                "transferred_count": 0,
                "transfers": [],
            }

        # Radiff2 graphdiff
        radiff_matches = await self._run_radiff2_graphdiff(path_src, path_tgt)

        # Function matching
        function_matches = self.match_functions(
            src_funcs, tgt_funcs, radiff_matches, min_confidence=min_confidence
        )

        # Build mapping from source function name and address to match result
        match_by_src_name: dict[str, FunctionMatch] = {
            m.source_function: m for m in function_matches
        }
        match_by_src_offset: dict[int, FunctionMatch] = {
            m.source_offset: m for m in function_matches
        }

        # Load annotations from source binary
        from reversecore_mcp.tools.radare2.r2_db import (
            _get_db_sync,
            _list_structures_sync,
            _list_types_sync,
            save_transferred_annotations_sync,
        )

        source_bookmarks: list[dict[str, Any]] = []
        with _get_db_sync() as db:
            rows = db.execute(
                "SELECT address, comment, category, created_at FROM bookmarks WHERE binary_hash=?",
                (src_hash,),
            ).fetchall()
            source_bookmarks = [
                {
                    "address": r["address"],
                    "comment": r["comment"],
                    "category": r["category"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]

        source_structures, _ = _list_structures_sync(src_hash, limit=500, offset=0)
        source_types, _ = _list_types_sync(src_hash, limit=500, offset=0)

        # Load findings from case state if provided
        source_findings: list[dict[str, Any]] = []
        if case_id:
            from reversecore_mcp.core.case_state import CaseStateManager

            manager = CaseStateManager()
            case = await manager.get_case(case_id)
            if case:
                raw_findings = case.metadata.get("findings", [])
                if isinstance(raw_findings, list):
                    for f in raw_findings:
                        if isinstance(f, dict):
                            source_findings.append(f)
                        elif hasattr(f, "to_dict"):
                            source_findings.append(f.to_dict())

        transferred_items: list[TransferredItem] = []

        # 1. Map bookmarks
        for b in source_bookmarks:
            addr_str = b["address"]
            try:
                addr_int = int(addr_str, 16)
            except ValueError:
                addr_int = 0

            # Find matching source function
            matched_func: FunctionMatch | None = None
            if addr_int in match_by_src_offset:
                matched_func = match_by_src_offset[addr_int]
            else:
                # Find function spanning this address
                for sf in src_funcs:
                    if sf.offset <= addr_int < sf.offset + max(sf.size, 1):
                        matched_func = match_by_src_name.get(sf.name)
                        break

            if not matched_func or matched_func.match_state in (
                MatchState.UNMATCHED,
                MatchState.AMBIGUOUS,
            ):
                status = TransferStatus.UNRESOLVED
                tgt_addr = ""
                tgt_fn = matched_func.target_function if matched_func else ""
                match_state = matched_func.match_state if matched_func else MatchState.UNMATCHED
                confidence = matched_func.confidence if matched_func else 0.0
            else:
                # Calculate relative offset within target function
                rel_offset = addr_int - matched_func.source_offset
                tgt_offset = matched_func.target_offset + rel_offset
                tgt_addr = f"0x{tgt_offset:x}"
                tgt_fn = matched_func.target_function
                match_state = matched_func.match_state
                confidence = matched_func.confidence

                # Determine if auto-applicable
                if auto_apply_exact and match_state == MatchState.EXACT:
                    status = TransferStatus.VERIFIED
                else:
                    status = TransferStatus.SUGGESTED

            # Retain historical context for changed functions
            raw_comment = b["comment"]
            if match_state in (MatchState.STRONG_MATCH, MatchState.PROBABLE):
                display_comment = (
                    f"[Historical Context from {matched_func.source_function if matched_func else 'source'} "
                    f"({confidence:.2f})] {raw_comment}"
                )
            else:
                display_comment = raw_comment

            content = {
                "address": tgt_addr,
                "comment": display_comment,
                "original_comment": raw_comment,
                "category": b["category"],
            }
            provenance = {
                "source_binary_hash": src_hash,
                "source_function": (matched_func.source_function if matched_func else "unknown"),
                "source_address": addr_str,
                "original_created_at": b["created_at"],
                "match_rationale": (matched_func.rationale if matched_func else "No candidate"),
            }

            transferred_items.append(
                TransferredItem(
                    id=None,
                    source_binary_hash=src_hash,
                    target_binary_hash=tgt_hash,
                    source_function=(matched_func.source_function if matched_func else "unknown"),
                    target_function=tgt_fn,
                    source_address=addr_str,
                    target_address=tgt_addr,
                    item_type="bookmark",
                    name=display_comment[:40],
                    content=content,
                    match_state=match_state,
                    confidence=confidence,
                    status=status,
                    source_provenance=provenance,
                    created_at=_utc_now_iso(),
                )
            )

        # 2. Map structures
        for s in source_structures:
            s_name = s["name"]
            status = TransferStatus.VERIFIED if auto_apply_exact else TransferStatus.SUGGESTED
            provenance = {
                "source_binary_hash": src_hash,
                "source_name": s_name,
                "original_created_at": s.get("created_at", ""),
            }
            transferred_items.append(
                TransferredItem(
                    id=None,
                    source_binary_hash=src_hash,
                    target_binary_hash=tgt_hash,
                    source_function="",
                    target_function="",
                    source_address="",
                    target_address="",
                    item_type="structure",
                    name=s_name,
                    content={"name": s_name, "fields": s["fields"]},
                    match_state=MatchState.EXACT,
                    confidence=1.0,
                    status=status,
                    source_provenance=provenance,
                    created_at=_utc_now_iso(),
                )
            )

        # 3. Map types
        for t in source_types:
            t_name = t["name"]
            status = TransferStatus.VERIFIED if auto_apply_exact else TransferStatus.SUGGESTED
            provenance = {
                "source_binary_hash": src_hash,
                "source_name": t_name,
                "original_created_at": t.get("created_at", ""),
            }
            transferred_items.append(
                TransferredItem(
                    id=None,
                    source_binary_hash=src_hash,
                    target_binary_hash=tgt_hash,
                    source_function="",
                    target_function="",
                    source_address="",
                    target_address="",
                    item_type="type",
                    name=t_name,
                    content={"name": t_name, "definition": t["definition"]},
                    match_state=MatchState.EXACT,
                    confidence=1.0,
                    status=status,
                    source_provenance=provenance,
                    created_at=_utc_now_iso(),
                )
            )

        # 4. Map findings
        for f in source_findings:
            loc = f.get("location", "")
            target_match = None
            for sf_name, fm in match_by_src_name.items():
                if sf_name in loc or fm.source_address == loc:
                    target_match = fm
                    break

            m_state: MatchState
            if target_match and target_match.match_state not in (
                MatchState.UNMATCHED,
                MatchState.AMBIGUOUS,
            ):
                t_fn = target_match.target_function
                t_addr = target_match.target_address
                m_state = target_match.match_state
                conf = target_match.confidence
                stat = TransferStatus.SUGGESTED
            else:
                t_fn = ""
                t_addr = ""
                m_state = MatchState.UNMATCHED
                conf = 0.0
                stat = TransferStatus.UNRESOLVED

            provenance = {
                "source_binary_hash": src_hash,
                "source_finding_id": f.get("finding_id", ""),
                "source_evidence_level": f.get("evidence_level", ""),
            }
            transferred_items.append(
                TransferredItem(
                    id=None,
                    source_binary_hash=src_hash,
                    target_binary_hash=tgt_hash,
                    source_function=(target_match.source_function if target_match else "unknown"),
                    target_function=t_fn,
                    source_address=loc,
                    target_address=t_addr,
                    item_type="finding",
                    name=f.get("title", "finding"),
                    content=f,
                    match_state=m_state,
                    confidence=conf,
                    status=stat,
                    source_provenance=provenance,
                    created_at=_utc_now_iso(),
                )
            )

        # Persist transferred items into SQLite
        transfer_dicts = [item.to_dict() for item in transferred_items]
        await asyncio.to_thread(save_transferred_annotations_sync, transfer_dicts, auto_apply_exact)

        # Count breakdown
        suggested_count = sum(
            1 for item in transferred_items if item.status == TransferStatus.SUGGESTED
        )
        verified_count = sum(
            1 for item in transferred_items if item.status == TransferStatus.VERIFIED
        )
        unresolved_count = sum(
            1 for item in transferred_items if item.status == TransferStatus.UNRESOLVED
        )

        return {
            "status": "success",
            "source_binary_hash": src_hash,
            "target_binary_hash": tgt_hash,
            "total_items_transferred": len(transferred_items),
            "breakdown": {
                "suggested": suggested_count,
                "verified": verified_count,
                "unresolved": unresolved_count,
            },
            "function_matches_count": len(function_matches),
            "function_matches": [m.to_dict() for m in function_matches],
            "transfers": transfer_dicts,
        }
