# MCP Tool Contract

Every Reversecore MCP tool returns one of the two common result envelopes.
Clients should branch on `status` and must not infer success from a human-readable
message.

## Success response

```json
{
  "status": "success",
  "data": {},
  "metadata": {"execution_time_ms": 12},
  "pagination": null,
  "recommended_next_tools": null
}
```

`data` contains the tool-specific payload. `metadata`, `pagination`, and
`recommended_next_tools` are optional and may be absent or `null`. Clients must
ignore unknown response fields so that additive metadata remains backward
compatible.

## Error response

```json
{
  "status": "error",
  "error_code": "RCMCP-E001",
  "message": "The file is outside the allowed workspace.",
  "hint": "Check REVERSECORE_WORKSPACE.",
  "details": {"tool_name": "run_file"}
}
```

`error_code` is the stable machine-readable identifier. `message` is intended
for users and may be refined without changing the code. `hint` and `details`
are optional. Clients must preserve unknown fields and must not depend on the
wording of `message`.

## Error code policy

Project-defined exception codes use the `RCMCP-E<3 digits>` format:

| Code family | Meaning |
|---|---|
| `RCMCP-E000` | Unclassified/system error |
| `RCMCP-E001`–`E005` | Validation, timeout, output, tool, and execution errors |
| `RCMCP-E100`–`E105` | Binary analysis, decompilation, disassembly, structure, signature, and emulation errors |
| `RCMCP-E200`–`E202` | Tool timeout, Ghidra, and Radare2 integration errors |
| `RCMCP-E300`–`E302` | Workspace, security, and path errors |

New codes must be documented here and covered by an error-formatting test.
Existing codes must not be reused for a different semantic failure.

## Radare2 annotation list pagination (#235)

`r2_list_structures`, `r2_list_types`, and `r2_list_bookmarks` accept a
zero-based `offset` from 0 through SQLite's signed 64-bit integer maximum and a
`limit` from 1 through 500. Invalid values return `VALIDATION_ERROR` before
opening the annotation database or invoking radare2. Successful responses
include `pagination.total_items`, `page`, `page_size`, `has_more`, and
`next_cursor`; `next_cursor` is the decimal offset for the next page. The
`count` in `data` is the number of items in the current page. Type listings
place saved user types first in name order, then radare2-native types in name
and definition order, and apply the same page size and offset to that combined
list.

## Compatibility rules

- Adding optional request fields or response fields is backward compatible.
- Removing or renaming a request field, changing its type, removing a tool, or
  changing a required field is a breaking change and requires a major version.
- Error code changes are breaking changes even when the human message is the
  same.
- Run `python scripts/check_api_schema.py` before merging any tool signature
  change. A reviewed change must update its baseline and include migration
  notes.

## Reviewed migration note: CVE hunting target contract (#229)

`hunt_cve_vulnerabilities.target_path` accepts a compiled LibFuzzer executable.
It returns `UNSUPPORTED_TARGET_TYPE` for C/C++ source and header extensions
before harness synthesis or fuzzing; the pipeline does not compile targets.
Generate a harness with `cve_synthesize_harness`, compile and link it with the
target using LibFuzzer, then pass the executable path. Successful analysis
results include `fuzzed_executable`; the field is `null` when no fuzzing run
succeeded.

`cve_fuzz_target.corpus_dir`, when provided, is copied into a private run
directory under `workspace/.cache/fuzz/<run_id>/seeds`; generated angr seeds and
crash artifacts stay within that run. Without an explicit corpus, the run uses
only its own initial seed and does not reuse a neighboring `cve_seeds` folder.

## Reviewed migration note: portable cache import provenance (#233)

`import_analysis_cache` accepts an optional `target_file_path`. When supplied,
the importer verifies that the local binary's SHA-256 matches the pack before
writing any entries. Offline imports remain supported when the target is not
available. In both cases, imported results are schema-validated and carry
`metadata.cache_provenance = "external_rcpack"`; the boolean
`metadata.cache_target_hash_verified` reports whether a local target hash was
checked. Consumers should treat external cache results as untrusted analysis
data even when the target hash matches.

On upgrade, existing decompilation-cache rows without authoritative provenance
are marked `legacy_unverified`; `r2_decompile` and `r2_recover_structures`
result-cache keys are versioned so pre-upgrade materialized results are
regenerated. New locally generated decompilation-cache entries are marked
`local`.
