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

## Compatibility rules

- Adding optional request fields or response fields is backward compatible.
- Removing or renaming a request field, changing its type, removing a tool, or
  changing a required field is a breaking change and requires a major version.
- Error code changes are breaking changes even when the human message is the
  same.
- Run `python scripts/check_api_schema.py` before merging any tool signature
  change. A reviewed change must update its baseline and include migration
  notes.
