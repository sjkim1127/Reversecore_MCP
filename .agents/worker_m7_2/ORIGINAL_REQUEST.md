## 2026-06-27T03:17:04Z

Your working directory is `/Users/sjkim1127/Reversecore_MCP/.agents/worker_m7_2/`.
You are the replacement worker for the global test coverage and verification milestone.
Your mission is to ensure that all tool files under `reversecore_mcp/tools/` satisfy the coverage requirements:
1. Target files (capa_tools.py, lief_tools.py, adaptive_vaccine.py, memory_tools.py, patch_explainer.py) must have >= 75% coverage.
2. All other files under `reversecore_mcp/tools/` must have >= 60% coverage.

The previous worker noted coverage violations in:
- `reversecore_mcp/tools/common/assembler.py` (currently 57% coverage)
- `reversecore_mcp/tools/malware/dormant_detector.py` (currently 49% coverage)

Your task:
1. Run the existing tests to check baseline coverage using pytest.
2. Improve/write unit tests using mocking to bring the coverage of `assembler.py` and `dormant_detector.py` (and any other violating files you find) up to >= 60% coverage.
3. Ensure all tests run and pass cleanly.
4. Update/write unit tests only in the `tests/` directory (e.g., `tests/unit/tools/...`). Follow the project's code quality and testing guidelines (AGENTS.md).
5. Once complete, write a detailed handoff report (`handoff.md`) in your working directory summarizing:
   - Command run and test results.
   - List of files checked and their coverages.
   - Files modified/added.
   - Attestation of clean tests and build.
6. MANDATORY INTEGRITY WARNING: DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A Forensic Auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.
