# Analyst Handoff Bundle

A handoff bundle lets one analyst (or MCP client) pass an investigation to another
without redoing discovery. It is composed from existing Reversecore state — there is
no separate collaboration database.

| Source | Reused mechanism |
|--------|------------------|
| Phase, hypotheses + evidence levels, targets, blockers | `CaseState` (`create_case_state`, `update_case_state`) |
| Findings / notes | memory sessions (`save_memory_item`) |
| Bookmarks, structures, types | SQLite annotation DB (`r2_add_bookmark`, `r2_create_structure`) |
| Reports, rules, dumps | referenced by path + SHA-256 (never embedded) |

## Workflow

```text
Analyst A                                   Analyst B
─────────                                   ─────────
export_handoff_bundle(sample_path,   ─►     (transfer sample + *.rchandoff.json)
    artifact_paths=[report, rules])
                                            import_handoff_bundle(bundle_path,
                                                target_file_path=sample, dry_run=True)
                                            import_handoff_bundle(bundle_path,
                                                target_file_path=sample)
                                            resume_case_state(<case_id from report>)
```

Always pass `target_file_path` on import: a SHA-256 mismatch aborts **before**
anything is attached, so findings can never land on the wrong sample.

## Manifest format (`format: "rchandoff"`, `version: 1`)

```jsonc
{
  "format": "rchandoff",
  "version": 1,
  "created_at": "2026-10-22T08:00:00Z",
  "manifest": {
    "sample":   {"sha256": "...", "name": "...", "size_bytes": 0, "format": null},
    "scope":    {"case_id": "...", "session_id": "...", "phase": "deep_analysis"},
    "environment": {"reversecore_version": "3.0.5", "python": "3.12.1", "platform": "..."},
    "sections": {                       // digest + item count per section
      "case_state":      {"sha256": "...", "count": 1},
      "memory_session":  {"sha256": "...", "count": 3},
      "annotations":     {"sha256": "...", "count": 4},
      "handoff_summary": {"sha256": "...", "count": 5}
    },
    "artifacts": [                      // references only
      {"path": "report.md", "sha256": "...", "size_bytes": 12, "status": "referenced"}
    ]
  },
  "sections": {
    "case_state": {},                   // CaseState.to_dict(), verbatim
    "memory_session": {"session": {}, "memories": []},
    "annotations": {"bookmarks": [], "structures": [], "types": []},
    "handoff_summary": {
      "established": [],                // verified hypotheses + completed steps
      "unresolved":  [],                // active / inconclusive hypotheses
      "next_checks": [],                // prioritized pending targets
      "blocked":     []
    }
  },
  "bundle_sha256": "..."                // over manifest + sections (canonical JSON)
}
```

## Integrity and safety guarantees

- **Verified before written** – section digests and `bundle_sha256` are checked first;
  any mismatch (`HANDOFF_IMPORT_INVALID`) aborts with nothing imported.
- **Hash binding** – `SAMPLE_HASH_MISMATCH` if `target_file_path` is a different binary.
- **Provenance preserved** – evidence levels and hypothesis statuses are copied verbatim;
  the imported case records `metadata.handoff` (source bundle hash, original case ID).
- **Receiver wins** – an existing case is never overwritten (the import gets a new
  `<id>_imported_xxxxxx` ID); conflicting annotations keep the local value and are
  listed under `annotations.conflicts`.
- **Missing artifacts are non-fatal** – each referenced artifact is reported as
  `verified`, `missing`, `hash_mismatch` or `not_available`; the rest still imports.
- **Dry run** – `dry_run=True` verifies and reports without writing.

## Current limitations

- Live report-session data (IOCs, ATT&CK mappings, notes held in the in-memory report
  session) is **not** captured automatically because report sessions are owner-scoped
  runtime state. Export the generated report/rule files via `artifact_paths` or record
  them as memory items to carry them across.
- Artifacts are referenced, not copied: the receiver must obtain the files separately.
