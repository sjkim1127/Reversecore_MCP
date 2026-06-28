# Worker Task: Milestone 6 (patch_explainer.py coverage)

## Goal
Fix the deserialization bug in `reversecore_mcp/tools/common/patch_explainer.py` and implement the expanded test suite in `tests/unit/tools/common/test_patch_explainer.py` to achieve >= 75% coverage (ideally 100%).

## Context & Inputs
- Target source file: `reversecore_mcp/tools/common/patch_explainer.py`
- Test file to modify: `tests/unit/tools/common/test_patch_explainer.py`
- Explorer findings and patch:
  - `/Users/sjkim1127/Reversecore_MCP/.agents/explorer_m6_3/analysis.md`
  - `/Users/sjkim1127/Reversecore_MCP/.agents/explorer_m6_3/proposed_patch.patch`

## Instructions
1. Apply the patch or implement the deserialization bug fix in `reversecore_mcp/tools/common/patch_explainer.py` (safely loading `diff_result.data` if it is a JSON string).
2. Implement the new test cases in `tests/unit/tools/common/test_patch_explainer.py` covering all the security heuristics (API hardening strcpy->strncpy, sprintf->snprintf, gets->fgets, memcpy->memcpy_s, integer overflow checks, logic removal), targeted functions, decompilation failure paths, and context logs.
3. Run the target test suite and check coverage:
   - `pytest tests/unit/tools/common/test_patch_explainer.py -v --cov=reversecore_mcp/tools/common/patch_explainer --cov-report=term-missing`
4. Confirm target coverage is 100% and that the full codebase test suite executes without regressions:
   - `pytest tests/ -v`
5. Run code linting and formatting:
   - `black --check tests/unit/tools/common/test_patch_explainer.py`
   - `ruff check tests/unit/tools/common/test_patch_explainer.py`
6. Create a handoff.md in your working directory `.agents/worker_m6_1/` summarizing what changes were made, coverage achieved, and verification command output.
