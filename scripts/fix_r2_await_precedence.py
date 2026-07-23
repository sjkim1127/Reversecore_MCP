#!/usr/bin/env python3
"""Correct await precedence for chained Radare2 session command results."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
R2_TOOLS = ROOT / "reversecore_mcp/tools/radare2/radare2_mcp_tools.py"
TEST_FILE = ROOT / "tests/unit/tools/radare2/test_r2_runtime_hardening.py"


def main() -> None:
    source = R2_TOOLS.read_text()
    pattern = re.compile(r"await (self\._run_session_cmd\([^\n]+?\))\.strip\(\)")
    corrected, count = pattern.subn(r"(await \1).strip()", source)
    if count == 0:
        remaining = [
            line.strip()
            for line in source.splitlines()
            if "await self._run_session_cmd" in line and ")." in line
        ]
        raise RuntimeError(
            "no await/member-access chains were corrected; candidates=" + repr(remaining)
        )
    if pattern.search(corrected):
        raise RuntimeError("unsafe await/member-access chain remains")
    R2_TOOLS.write_text(corrected)

    tests = TEST_FILE.read_text()
    test_name = "test_awaited_session_results_are_materialized_before_string_methods"
    if test_name not in tests:
        if "import inspect\n" not in tests:
            tests = tests.replace("import asyncio\n", "import asyncio\nimport inspect\n", 1)
        if "import re\n" not in tests:
            tests = tests.replace("import inspect\n", "import inspect\nimport re\n", 1)
        tests = tests.replace(
            "from reversecore_mcp.tools.radare2 import r2_analysis\n",
            "from reversecore_mcp.tools.radare2 import r2_analysis, radare2_mcp_tools\n",
            1,
        )
        tests += '''\n\ndef test_awaited_session_results_are_materialized_before_string_methods() -> None:\n    source = inspect.getsource(radare2_mcp_tools)\n    unsafe_chain = re.compile(\n        r"await self\\._run_session_cmd\\([^\\n]+?\\)\\.[A-Za-z_]"\n    )\n    assert unsafe_chain.search(source) is None\n'''
        TEST_FILE.write_text(tests)

    for path in (
        ROOT / "scripts/fix_r2_await_precedence.py",
        ROOT / ".github/workflows/fix-r2-await-precedence.yml",
    ):
        path.unlink(missing_ok=True)

    print(f"corrected {count} await/member-access chain(s)")


if __name__ == "__main__":
    main()
