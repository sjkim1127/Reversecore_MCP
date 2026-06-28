# Project: Reversecore_MCP Test Coverage Improvement

## Architecture
Reversecore_MCP is an enterprise-grade Model Context Protocol (MCP) server for binary analysis. Tools under `reversecore_mcp/tools/` provide specific analysis functionality, integrating with external libraries (capa, LIEF), managing memory/sessions, explaining patch diffs, and generating adaptive vaccine rules.

This project focuses on writing isolated unit tests using standard mocking to improve the test coverage of targeted core analysis tools to at least 75%, and other tool files under `reversecore_mcp/tools/` to at least 60%.

## Code Layout
- `reversecore_mcp/tools/analysis/capa_tools.py` -> Tested by `tests/unit/tools/analysis/test_capa_tools.py`
- `reversecore_mcp/tools/analysis/lief_tools.py` -> Tested by `tests/unit/tools/analysis/test_lief_tools.py`
- `reversecore_mcp/tools/malware/adaptive_vaccine.py` -> Tested by `tests/unit/tools/malware/test_adaptive_vaccine.py`
- `reversecore_mcp/tools/common/memory_tools.py` -> Tested by `tests/unit/tools/common/test_memory_tools.py`
- `reversecore_mcp/tools/common/patch_explainer.py` -> Tested by `tests/unit/tools/common/test_patch_explainer.py`

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| 1 | Baseline Analysis | Analyze current coverage and requirements | None | DONE |
| 2 | capa_tools.py coverage | Improve capa_tools.py test coverage >= 75% | M1 | DONE |
| 3 | lief_tools.py coverage | Improve lief_tools.py test coverage >= 75% | M1 | DONE |
| 4 | adaptive_vaccine.py coverage | Improve adaptive_vaccine.py test coverage >= 75% | M1 | DONE |
| 5 | memory_tools.py coverage | Improve memory_tools.py test coverage >= 75% | M1 | DONE |
| 6 | patch_explainer.py coverage | Improve patch_explainer.py test coverage >= 75% | M1 | DONE |
| 7 | Global verification & other tools | Check coverage of all tools under reversecore_mcp/tools/ >= 60% and run full test suite | M2, M3, M4, M5, M6 | DONE |

## Interface Contracts
- Unit tests must mock all external subprocess calls, libraries (e.g. `capa`, `lief`), database setups, and FastMCP objects.
- Unit tests must be fast, reliable, and run cleanly without requiring local CLI tool installations.
