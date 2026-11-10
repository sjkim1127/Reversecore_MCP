"""Retained Evidence Cache for Summary-First Paging in Reversecore_MCP.

Stores full-fidelity analysis outputs (disassembly instructions, decompiled lines,
extracted strings, Go/Rust symbols, Electron ASAR file trees, Unity IL2CPP metadata)
behind lightweight ``evidence_id`` handles so LLMs can inspect summary metrics first
and paginate through specific facets on demand via ``inspect_analysis_view``.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EvidenceRecord:
    """Represents a retained analysis result with one or more navigable facets."""

    evidence_id: str
    tool_name: str
    target_path: str
    created_at: float
    facets: dict[str, Any]
    summary: dict[str, Any] = field(default_factory=dict)


class EvidenceCache:
    """Thread-safe bounded LRU cache with disk persistence for retained analysis evidence."""

    def __init__(
        self,
        max_records: int = 128,
        ttl_seconds: int = 86400,
        cache_dir: str | Path | None = None,
    ) -> None:
        self._max_records = max(8, max_records)
        self._ttl_seconds = max(60, ttl_seconds)
        self._explicit_cache_dir = Path(cache_dir) if cache_dir else None
        self._records: OrderedDict[str, EvidenceRecord] = OrderedDict()
        self._lock = threading.Lock()

    def _resolve_cache_dir(self) -> Path | None:
        """Resolve writable directory for persisting evidence records across processes."""
        if self._explicit_cache_dir is not None:
            try:
                self._explicit_cache_dir.mkdir(parents=True, exist_ok=True)
                return self._explicit_cache_dir
            except OSError:
                return None

        env_dir = os.environ.get("REVERSECORE_EVIDENCE_CACHE_DIR", "").strip()
        if env_dir:
            try:
                p = Path(env_dir)
                p.mkdir(parents=True, exist_ok=True)
                return p
            except OSError:
                pass

        ws_dir = os.environ.get("REVERSECORE_WORKSPACE", "").strip()
        if ws_dir:
            try:
                ws_path = Path(ws_dir)
                if ws_path.is_dir():
                    p = ws_path / ".reversecore_cache" / "evidence"
                    p.mkdir(parents=True, exist_ok=True)
                    return p
            except OSError:
                pass

        try:
            fallback = Path(tempfile.gettempdir()) / "reversecore_evidence_cache"
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
        except OSError:
            return None

    def _persist_to_disk(self, record: EvidenceRecord) -> None:
        """Write EvidenceRecord to disk JSON file and prune expired/excess files."""
        cdir = self._resolve_cache_dir()
        if cdir is None:
            return
        try:
            file_path = cdir / f"{record.evidence_id}.json"
            payload = {
                "evidence_id": record.evidence_id,
                "tool_name": record.tool_name,
                "target_path": record.target_path,
                "created_at": record.created_at,
                "summary": record.summary,
                "facets": record.facets,
            }
            tmp_path = cdir / f".{record.evidence_id}.{os.getpid()}.tmp"
            tmp_path.write_text(
                json.dumps(payload, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            tmp_path.replace(file_path)

            # Lightweight pruning of excess disk files
            disk_files = sorted(
                cdir.glob("ev_*.json"),
                key=lambda p: p.stat().st_mtime if p.exists() else 0.0,
            )
            while len(disk_files) > self._max_records:
                oldest = disk_files.pop(0)
                oldest.unlink(missing_ok=True)
        except OSError:
            pass

    def _load_from_disk(self, evidence_id: str) -> EvidenceRecord | None:
        """Load an EvidenceRecord from disk if present and not expired."""
        if not evidence_id.startswith("ev_") or "/" in evidence_id or "\\" in evidence_id:
            return None
        cdir = self._resolve_cache_dir()
        if cdir is None:
            return None
        file_path = cdir / f"{evidence_id}.json"
        if not file_path.is_file():
            return None
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
            created_at = float(raw.get("created_at", 0.0))
            if (time.time() - created_at) > self._ttl_seconds:
                file_path.unlink(missing_ok=True)
                return None
            return EvidenceRecord(
                evidence_id=str(raw["evidence_id"]),
                tool_name=str(raw.get("tool_name", "unknown")),
                target_path=str(raw.get("target_path", "")),
                created_at=created_at,
                facets=dict(raw.get("facets") or {}),
                summary=dict(raw.get("summary") or {}),
            )
        except Exception:
            return None

    def store(
        self,
        tool_name: str,
        target_path: str,
        facets: dict[str, Any],
        summary: dict[str, Any] | None = None,
        seed: str = "",
    ) -> str:
        """Store analysis facets and return a retained ``evidence_id``.

        Args:
            tool_name: Name of the producer tool.
            target_path: File path or target identifier.
            facets: Dictionary mapping facet names (e.g. 'lines', 'strings', 'functions')
                to lists, strings, or dicts.
            summary: Optional high-level summary dictionary.
            seed: Optional extra differentiator (e.g. function address or parameters).

        Returns:
            Generated ``evidence_id`` (e.g. ``ev_8f3a92b1c4d0``).
        """
        raw_key = f"{tool_name}:{target_path}:{seed}:{time.time_ns()}"
        digest = hashlib.sha256(raw_key.encode("utf-8", errors="replace")).hexdigest()[:12]
        evidence_id = f"ev_{digest}"

        record = EvidenceRecord(
            evidence_id=evidence_id,
            tool_name=tool_name,
            target_path=str(target_path),
            created_at=time.time(),
            facets=facets,
            summary=summary or {},
        )

        with self._lock:
            self._records[evidence_id] = record
            self._records.move_to_end(evidence_id)
            while len(self._records) > self._max_records:
                self._records.popitem(last=False)

        self._persist_to_disk(record)
        return evidence_id

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """Retrieve an EvidenceRecord by ID (from memory or disk fallback) and refresh LRU."""
        with self._lock:
            record = self._records.get(evidence_id)
            if record is not None:
                if (time.time() - record.created_at) > self._ttl_seconds:
                    self._records.pop(evidence_id, None)
                    return None
                self._records.move_to_end(evidence_id)
                return record

        disk_record = self._load_from_disk(evidence_id)
        if disk_record is not None:
            with self._lock:
                self._records[evidence_id] = disk_record
                self._records.move_to_end(evidence_id)
                while len(self._records) > self._max_records:
                    self._records.popitem(last=False)
            return disk_record

        return None

    def list_records(self, limit: int = 25) -> list[dict[str, Any]]:
        """List recently retained evidence records."""
        with self._lock:
            items = list(reversed(self._records.values()))[: max(1, limit)]
        return [
            {
                "evidence_id": r.evidence_id,
                "tool_name": r.tool_name,
                "target_path": r.target_path,
                "created_at": r.created_at,
                "available_facets": list(r.facets.keys()),
                "summary": r.summary,
            }
            for r in items
        ]

    def clear(self) -> int:
        """Clear all cached records (memory and disk) and return count removed."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
        cdir = self._resolve_cache_dir()
        if cdir is not None:
            try:
                for p in cdir.glob("ev_*.json"):
                    p.unlink(missing_ok=True)
            except OSError:
                pass
        return count

    def query_view(
        self,
        evidence_id: str,
        facet: str | None = None,
        offset: int = 0,
        limit: int = 50,
        filter_query: str | None = None,
    ) -> dict[str, Any] | None:
        """Paginate and optionally filter a specific facet of a retained EvidenceRecord."""
        record = self.get(evidence_id)
        if record is None:
            return None

        available_facets = list(record.facets.keys())
        if not available_facets:
            return {
                "evidence_id": evidence_id,
                "parent_evidence_id": evidence_id,
                "tool_name": record.tool_name,
                "target_path": record.target_path,
                "selected_facet": None,
                "available_facets": [],
                "offset": 0,
                "limit": limit,
                "total_items": 0,
                "returned_items": 0,
                "has_more": False,
                "next_offset": None,
                "items": [],
            }

        selected_facet = facet if (facet and facet in record.facets) else available_facets[0]
        raw_data = record.facets[selected_facet]

        # Normalize raw_data into a list of items for uniform pagination
        items_list: list[Any]
        if isinstance(raw_data, str):
            items_list = [
                {"line_number": idx + 1, "text": line}
                for idx, line in enumerate(raw_data.splitlines())
            ]
        elif isinstance(raw_data, list):
            items_list = raw_data
        elif isinstance(raw_data, dict):
            items_list = [{"key": k, "value": v} for k, v in raw_data.items()]
        else:
            items_list = [raw_data]

        # Apply optional substring filter
        if filter_query and filter_query.strip():
            q_lower = filter_query.strip().lower()
            filtered: list[Any] = []
            for item in items_list:
                if isinstance(item, str):
                    haystack = item.lower()
                elif isinstance(item, dict):
                    haystack = json.dumps(item, ensure_ascii=False, default=str).lower()
                else:
                    haystack = str(item).lower()
                if q_lower in haystack:
                    filtered.append(item)
            items_list = filtered

        total_items = len(items_list)
        safe_offset = max(0, offset)
        safe_limit = max(1, min(limit, 500))
        page_items = items_list[safe_offset : safe_offset + safe_limit]
        has_more = (safe_offset + safe_limit) < total_items

        return {
            "evidence_id": evidence_id,
            "parent_evidence_id": evidence_id,
            "tool_name": record.tool_name,
            "target_path": record.target_path,
            "selected_facet": selected_facet,
            "available_facets": available_facets,
            "filter_query": filter_query,
            "offset": safe_offset,
            "limit": safe_limit,
            "total_items": total_items,
            "returned_items": len(page_items),
            "has_more": has_more,
            "next_offset": (safe_offset + safe_limit) if has_more else None,
            "items": page_items,
        }


_GLOBAL_EVIDENCE_CACHE = EvidenceCache()


def get_evidence_cache() -> EvidenceCache:
    """Return the singleton EvidenceCache instance."""
    return _GLOBAL_EVIDENCE_CACHE
