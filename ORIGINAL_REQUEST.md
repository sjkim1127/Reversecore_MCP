# Original User Request

## Initial Request — 2026-06-27T02:16:17+09:00

The project aims to improve the test coverage and robustness of low-coverage core analysis modules and utilities in Reversecore_MCP to at least 75%.

Working directory: /Users/sjkim1127/Reversecore_MCP
Integrity mode: development

## Requirements

### R1. Target Coverage Improvement
Increase the test coverage of the following target modules (and any other module under `reversecore_mcp/tools/` with less than 60% coverage) to at least 75%:
- `reversecore_mcp/tools/analysis/capa_tools.py` (currently 33%)
- `reversecore_mcp/tools/analysis/lief_tools.py` (currently 36%)
- `reversecore_mcp/tools/malware/adaptive_vaccine.py` (currently 42%)
- `reversecore_mcp/tools/common/memory_tools.py` (currently 51%)
- `reversecore_mcp/tools/common/patch_explainer.py` (currently 58%)

### R2. Isolated Unit Testing
Write unit tests utilizing robust mocking (`unittest.mock`, `pytest-mock`) for external libraries (e.g. `capa`, `lief`), database setups, and subprocess calls to ensure tests execute quickly and reliably in local and CI/CD (GitHub Actions) environments without requiring local CLI tool installations.

## Acceptance Criteria

### Coverage Thresholds
- [ ] `reversecore_mcp/tools/analysis/capa_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/analysis/lief_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/malware/adaptive_vaccine.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/common/memory_tools.py` coverage >= 75%
- [ ] `reversecore_mcp/tools/common/patch_explainer.py` coverage >= 75%
- [ ] All other tool files under `reversecore_mcp/tools/` have coverage >= 60% (or >= 75% if targeted)

### Verification
- [ ] Running `pytest --cov=reversecore_mcp --cov-report=term-missing` succeeds and shows all target files meet or exceed 75% coverage.
- [ ] All tests pass successfully without leaking subprocesses or memory.
