# Project: Reversecore_MCP Optimization and Enhancement

## Architecture
Reversecore_MCP is an enterprise-grade Model Context Protocol (MCP) server for AI-powered binary analysis, reverse engineering, and vulnerability research.

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                           │
│   (Claude Desktop, Cursor, Custom HTTP/SSE AI Agents)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
    [ stdio Transport ]             [ HTTP / SSE Transport ]
    - JSON-RPC over stdin/stdout    - FastAPI Root App (:8000)
    - FastMCP stdio_server()        - Mounted at /mcp (/mcp/sse, /mcp/messages/)
    - Stderr Logging Isolation      - Auth: APIKeyAuthMiddleware
                                    - Security: LoopbackOnly, SecHeaders
                                    - Rate Limiting: SafeSlowAPIMiddleware
               └───────────────┬───────────────┘
                               ▼
            ┌────────────────────────────────────┐
            │       FastMCP Server Instance      │
            │   (Lifespan, Tools, Resources,     │
            │       Prompts, Extensions)         │
            ├────────────────────────────────────┤
            │  - Prompts Engine (23+ RE Prompts) │
            │  - Dynamic Resources Engine        │
            │  - Token-Efficient Schemas & Pagination
            │  - orjson High-Speed Serialization │
            └────────────────────────────────────┘
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | FastMCP stdio & SSE Transport Hardening | Robust initialization, stdio stderr logging isolation, SSE stream lifecycle, and clean lifespan delegation under FastAPI. | M1 | R1 Requirement & Survey 1 |
| 2 | Standardized Progress Reporting Context | Fix untyped `ctx=None` in `file_operations.py`, ensure proper `Context` type hints across tools for transparent schema suppression and `notifications/progress` streaming. | M1 | R1 Requirement & Survey 1 |
| 3 | Dynamic Resource Routing & Path Validation | Secure parameterized URI template routing with path traversal protection in `_get_workspace_path` and MIME type metadata. | M1 | R1 Requirement & Survey 1 |
| 4 | Prompt Registration & Audit Mode Fix | Register `source_code_audit_mode` in `prompts/__init__.py` and ensure 100% of defined prompts are registered and discoverable. | M2 | R2 Requirement & Survey 2 |
| 5 | Advanced Reasoning Prompts | Implement `vulnerability_triage_mode` (ASan/CWE/CVSS v3.1), `exploit_analysis_mode` (mitigations, ROP, pwntools), and `malware_deobfuscation_mode` (API hashing, string decrypt, dead code). | M2 | R2 Requirement & Survey 2 |
| 6 | Expanded Dynamic Context Resources | Add `metadata`, `func/{address}/xrefs`, `func/{address}/context`, `memory_map`, `signatures`, `imports`, and `exports` resources in `resources.py` with MIME types. | M2 | R2 Requirement & Survey 2 |
| 7 | Core Result Model & Pagination Standardization | Add `PaginationMeta` to `core/result.py`, standardize return types across `radare2_mcp_tools.py` using `ToolResult`. | M3 | R3 Requirement & Survey 3 |
| 8 | Double-Serialization Elimination | Eliminate `success(json.dumps(data, indent=2))` anti-patterns across `diff_tools.py`, `lief_tools.py`, etc., passing structured native dicts/models directly. | M3 | R3 Requirement & Survey 3 |
| 9 | High-Speed `orjson` Standardization | Migrate all remaining stdlib `import json` calls to `from reversecore_mcp.core import json_utils as json`. | M3 | R3 Requirement & Survey 3 |
| 10 | Smart Pagination & Token Efficiency | Implement compact tuple schemas for disassembly (`format="compact"`), windowed decompilation (`line_offset`, `max_lines`), bounded xref grouping, and summarized diffs (achieving 40-80% token reduction). | M3 | R3 Requirement & Survey 3 |
| 11 | Protocol-Level Integration Tests | End-to-end transport tests verifying stdio, SSE streams, dynamic resource template resolution via `Client`, and progress streaming. | M4 | R1/R2/R3 & Survey 1/2/3 |
| 12 | Serialization & Token Efficiency Benchmarks | Quantitative micro-benchmarks in `tests/performance/test_performance_regression.py` measuring `orjson` throughput, sub-millisecond serialization, and token reduction. | M4 | R3 & Acceptance Criteria |
| 13 | Full Suite Passing, Coverage & Code Quality | Pass 100% pytest suite, coverage >= 54%, `ruff check` 0 errors, `black --target-version py312` 0 formatting issues. | M4 | Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | FastMCP Protocol & Connection Architecture Hardening | Features 1, 2, 3: Transport stability (stdio/SSE), lifespan delegation, progress reporting context annotations, resource security validation. | Survey Complete | DONE |
| M2 | Advanced Reasoning Prompts & Dynamic Context Resources | Features 4, 5, 6: Register `source_code_audit_mode`, add 3 specialized prompts, add 6 dynamic resources with MIME types and unit tests. | M1 | DONE |
| M3 | Output Schema Optimization & Token Efficiency | Features 7, 8, 9, 10: Standardize `result.py` + `PaginationMeta`, eliminate double-serialization, migrate to `orjson`, compact disasm/decompile/xrefs/diff schemas. | M1, M2 | DONE |
| M4 | E2E Testing, Benchmarks, Adversarial Hardening (Tier 5) & Quality Gate | Features 11, 12, 13: Protocol-level tests, serialization benchmarks, Tier 5 adversarial tests, Ruff/Black py312 validation, coverage >= 54%. | M1, M2, M3 | DONE |

## Interface Contracts

### FastMCP Server & Transport
- Server instance: `reversecore_mcp.server.mcp` (FastMCP 2.14.7+)
- Stdio transport: `mcp.run(transport="stdio")` with stdout reserved exclusively for JSON-RPC 2.0.
- HTTP transport: Root FastAPI app running `mcp.http_app(transport="sse")` mounted at `/mcp` with `mcp._lifespan_manager()` delegated in `app_lifespan`.
- Context injection: Any tool declaring `ctx: Context | None = None` receives injected `fastmcp.Context` for `ctx.report_progress(progress, total)` and `ctx.info/warning/error(msg)`.

### Dynamic Context Resources (`reversecore://...`)
- `reversecore://{filename}/metadata` -> Markdown table of architecture, bits, hashes, mitigations, packer info (`mime_type="text/markdown"`).
- `reversecore://{filename}/func/{address}/xrefs` -> Markdown list/table of callers and callees bounded at 30 items (`mime_type="text/markdown"`).
- `reversecore://{filename}/func/{address}/context` -> Prototype, local variables, recovered structs, and complexity metrics (`mime_type="text/markdown"`).
- `reversecore://{filename}/memory_map` -> Section table, offsets, virtual size, permissions, and entropy (`mime_type="text/markdown"`).
- `reversecore://{filename}/signatures` -> Matched YARA, CAPA, FLIRT, and dormant indicators (`mime_type="text/markdown"`).
- `reversecore://{filename}/imports` / `exports` -> DLL/library grouped symbols with security indicators (`mime_type="text/markdown"`).

### Core Result Models & Pagination (`reversecore_mcp/core/result.py`)
```python
class PaginationMeta(BaseModel):
    has_more: bool = False
    next_cursor: str | None = None
    total_items: int | None = None
    page: int = 1
    page_size: int = 100
    truncated: bool = False

class ToolSuccess(BaseModel):
    status: Literal["success"] = "success"
    data: Any
    metadata: dict[str, Any] | None = None
    pagination: PaginationMeta | None = None
    recommended_next_tools: list[NextToolHint] | None = None
```

## Code Layout
```
reversecore_mcp/
├── core/
│   ├── config.py             # Configuration settings
│   ├── decorators.py         # Function logging/metrics decorators
│   ├── error_handling.py     # Centralized tool error handling
│   ├── exceptions.py         # Exception hierarchy
│   ├── json_utils.py         # High-speed orjson serialization utilities
│   ├── result.py             # ToolSuccess, ToolError, PaginationMeta, TypedDicts
│   ├── security.py           # Path sanitization and workspace boundary guards
│   └── validators.py         # Parameter and binary validation
├── prompts/
│   ├── __init__.py           # Prompt registry (register_prompts)
│   ├── common.py             # General RE prompts
│   ├── cve_research.py       # Taint, heap, fuzzing, CVE pipeline prompts
│   ├── exploit_prompts.py    # (New) exploit_analysis_mode
│   ├── malware.py            # Unpacking, C2, ransomware, full analysis
│   ├── deobfuscation_prompts.py # (New) malware_deobfuscation_mode
│   ├── security.py           # Vuln hunter, patch analysis, source_code_audit
│   ├── triage_prompts.py     # (New) vulnerability_triage_mode
│   └── server_health.py      # Health check and catalog prompts
├── resources.py              # Static and dynamic MCP virtual resources
├── server.py                 # FastMCP server, lifespan, HTTP/SSE transports, auth
├── tools/
│   ├── analysis/             # LIEF, diffs, static analysis, crash triage
│   ├── common/               # File operations, patch explainer
│   ├── deobfuscation/        # String decrypt, API hash resolver, dead code eliminator
│   ├── malware/              # Vaccine, dormant detector, ROP builder, PoC generator
│   ├── radare2/              # Disassembly, decompilation (r2ghidra), xrefs, emulation
│   └── report/               # Report and VEX generation
tests/
├── conftest.py               # Shared fixtures and workspace setup
├── unit/                     # Unit test suites (core, prompts, tools)
├── integration/              # Integration and protocol-level tests
└── performance/              # Performance regression and serialization SLA benchmarks
```
