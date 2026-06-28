## 2026-06-26T17:18:42Z
You are the worker agent. Your working directory is `/Users/sjkim1127/Reversecore_MCP/.agents/worker_m2_1/`.
Your mission is to improve the test coverage of `reversecore_mcp/tools/analysis/capa_tools.py` to at least 75% (currently 35%).

1. Read the current implementation of `reversecore_mcp/tools/analysis/capa_tools.py` and its existing tests in `tests/unit/tools/analysis/test_capa_tools.py`.
2. Read the recommended strategy in `/Users/sjkim1127/Reversecore_MCP/.agents/explorer_m1_1/analysis.md`.
3. Modify/expand `tests/unit/tools/analysis/test_capa_tools.py` to add comprehensive, robust unit tests with mocking. Specifically, patch the `capa` library using `sys.modules` or `patch` to avoid importing the actual native `capa` package during tests.
4. Test the following cases:
   - Success path: finding capabilities, attack techniques, mbc behaviors, and return formatted results.
   - Failure path 1: rules load failure (`capa.rules.get_rules` raises exception).
   - Failure path 2: file load failure (`capa.loader.get_extractor` raises exception).
   - Failure path 3: general exception handling (e.g. `find_capabilities` throws an unexpected error).
5. Run the tests using pytest: `pytest tests/unit/tools/analysis/test_capa_tools.py --cov=reversecore_mcp/tools/analysis/capa_tools.py --cov-report=term-missing`
6. Verify that all tests pass cleanly and coverage of `capa_tools.py` is >= 75%.
7. Write your changes and handoff report to `/Users/sjkim1127/Reversecore_MCP/.agents/worker_m2_1/handoff.md`.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A Forensic Auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.
