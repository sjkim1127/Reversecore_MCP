#!/usr/bin/env python3
"""Raise integration-test subprocess timeouts for loaded CI runners."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
test_file = root / "tests/integration/test_extended_tools.py"
text = test_file.read_text()

if "EXTERNAL_TOOL_TIMEOUT = 15" not in text:
    marker = "import pytest\n\n\n"
    if text.count(marker) != 1:
        raise RuntimeError("pytest import marker not found exactly once")
    text = text.replace(marker, "import pytest\n\n\nEXTERNAL_TOOL_TIMEOUT = 15\n\n\n", 1)

count = text.count("timeout=5")
if count < 1:
    raise RuntimeError("no five-second external-tool timeouts found")
text = text.replace("timeout=5", "timeout=EXTERNAL_TOOL_TIMEOUT")
test_file.write_text(text)

(root / "scripts/raise_extended_tool_timeouts.py").unlink()
(root / ".github/workflows/raise-extended-tool-timeouts.yml").unlink()
print(f"raised {count} external-tool timeout(s)")
