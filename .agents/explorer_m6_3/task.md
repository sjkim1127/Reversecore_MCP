# Explorer Task: Milestone 6 (patch_explainer.py coverage) Explorer 3

## Goal
Design mock configurations, schema shapes, and integration requirements for `patch_explainer.py` test suite.

## Context & Inputs
- Target source file: `reversecore_mcp/tools/common/patch_explainer.py`
- Test file: `tests/unit/tools/common/test_patch_explainer.py`

## Instructions
1. Inspect how `diff_binaries` data dictionary returns differences. Find the correct schema format (e.g. `changes` containing address list, versus `changed_functions` which was incorrectly mocked in the previous test suite).
2. Construct mock dictionary payloads matching `diff_binaries`'s actual output format to avoid schema mismatch errors.
3. Design unit tests that cleanly verify the transition of `explain_patch` from diffing to decompiling, and then explaining.
4. Document the design in `analysis.md` and `handoff.md` inside your working directory `.agents/explorer_m6_3/`.
