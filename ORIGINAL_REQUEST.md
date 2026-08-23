# Original User Request

## Initial Request — 2026-08-22T20:31:23+09:00

You are the Project Orchestrator (teamwork_preview_orchestrator) for Reversecore_MCP optimization and enhancement.

Your working directory is: `/Users/sjkim1127/Reversecore_MCP/.agents/orchestrator_1`
Project root: `/Users/sjkim1127/Reversecore_MCP`
Original user request file: `/Users/sjkim1127/Reversecore_MCP/.agents/ORIGINAL_REQUEST.md`

Requirements:
1. R1. FastMCP Protocol & Connection Architecture Hardening:
   - Enhance FastMCP server transport stability (stdio & SSE), dynamic resource URI routing/templates, progress reporting, and connection lifecycle handling.
2. R2. Advanced Reasoning Prompts & Context Resources:
   - Expand and refine reverse engineering prompts (`reversecore_mcp/prompts.py`) and dynamic context resources (`reversecore_mcp/resources.py`) for specialized workflows (vulnerability triage, exploit analysis, malware deobfuscation, patch diffing).
3. R3. Output Schema Optimization & Token Efficiency:
   - Optimize tool return schemas and JSON serialization for large binary analysis outputs (disassembly chunks, decompilation, xref graphs), introducing smart pagination/summarization to conserve LLM context window while preserving critical technical details.

Acceptance Criteria:
- FastMCP server successfully initializes and handles stdio and SSE transport protocols cleanly.
- Dynamic resources and specialized reverse engineering prompts are correctly registered, accessible, and validated with test suites.
- Tool return schemas correctly implement structured, token-efficient formats without loss of semantic analysis fidelity.
- Quantitative serialization benchmarks demonstrate high-speed JSON serialization (e.g. using `orjson`).
- Large disassembly/decompilation outputs achieve measurable token/size reduction through smart summarization/pagination compared to raw unformatted dumps.
- Full test suite (`pytest tests/unit/ tests/integration/`) maintains 100% pass rate with zero regressions (coverage >= 54%).
- Code quality checks (`ruff check`, `black --target-version py312`) pass with 0 errors and 0 formatting issues.

Please maintain your `plan.md`, `progress.md`, and `BRIEFING.md` inside your working directory (`/Users/sjkim1127/Reversecore_MCP/.agents/orchestrator_1/`). Dispatch specialist subagents as needed, monitor progress, synthesize results, ensure thorough test coverage and benchmarks, and notify me when complete.
