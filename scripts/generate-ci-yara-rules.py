#!/usr/bin/env python3
"""Generate a minimal YARA baseline rule file for CI testing.

This script creates tests/fixtures/rules/ci_baseline.yar so that
YARA-scanning MCP tools always have a valid rule to work with in CI.
"""

import pathlib
import sys

RULES_DIR = pathlib.Path("tests/fixtures/rules")
OUTPUT = RULES_DIR / "ci_baseline.yar"

RULE_CONTENT = """\
rule ci_elf_marker {
    meta:
        description = "Baseline ELF detection rule for CI testing"
        author      = "Reversecore CI"
    strings:
        $elf_magic = { 7F 45 4C 46 }
    condition:
        $elf_magic at 0
}
"""


def main() -> int:
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(RULE_CONTENT)
    print(f"✅ YARA baseline rule written to {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
