"""Retained Evidence Cache for Summary-First Paging in Reversecore_MCP.

Stores full-fidelity analysis outputs (disassembly instructions, decompiled lines,
extracted strings, Go/Rust symbols, Electron ASAR file trees, Unity IL2CPP metadata)
behind lightweight ``evidence_id`` handles so LLMs can inspect summary metrics first
and paginate through specific facets on demand via ``inspect_analysis_view``.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
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
    """Thread-safe bounded LRU cache for retained analysis evidence."""

    def __init__(self, max_records: int = 128) -> None:
        self._max_records = max(8, max_records)
        self._records: OrderedDict[str, EvidenceRecord] = OrderedDict()
        self._lock = threading.Lock()

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

        return evidence_id

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """Retrieve an EvidenceRecord by ID and refresh its LRU position."""
        with self._lock:
            record = self._records.get(evidence_id)
            if record is not None:
                self._records.move_to_end(evidence_id)
            return record

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
        """Clear all cached records and return count removed."""
        with self._lock:
            count = len(self._records)
            self._records.clear()
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
