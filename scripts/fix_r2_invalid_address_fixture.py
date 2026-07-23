#!/usr/bin/env python3
"""Use a truly invalid Radare2 address fixture in the unit test."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]
path = root / "tests/unit/tools/radare2/test_radare2_mcp_tools.py"
text = path.read_text()
old = 'result = await tool("/app/test.bin", address="invalid")\n'
new = 'result = await tool("/app/test.bin", address="invalid;command")\n'
if text.count(old) != 1:
    raise RuntimeError("invalid-address fixture not found exactly once")
path.write_text(text.replace(old, new, 1))

(root / "scripts/fix_r2_invalid_address_fixture.py").unlink()
(root / ".github/workflows/fix-r2-invalid-address-fixture.yml").unlink()
