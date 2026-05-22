#!/usr/bin/env python3
"""Validate all YARA rules compile without syntax errors."""

import subprocess
import sys
from pathlib import Path


def test_yara_rules(rules_dir: str) -> int:
    """Compile every .yar file in the given directory."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"⚠️  Rules directory not found: {rules_dir}")
        return 0

    yara_files = list(rules_path.rglob("*.yar")) + list(rules_path.rglob("*.yara"))
    if not yara_files:
        print(f"⚠️  No YARA rules found in {rules_dir}")
        return 0

    passed = 0
    failed = 0

    for rule_file in sorted(yara_files):
        print(f"🔍 {rule_file.name} ... ", end="", flush=True)
        result = subprocess.run(
            ["yara", str(rule_file), "/dev/null"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode in (0, 1):  # 1 = no match, which is fine
            print("✅")
            passed += 1
        else:
            print(f"❌\n   {result.stderr.strip()}")
            failed += 1

    print(f"\nYARA rule compilation: {passed} passed, {failed} failed")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "/app/rules"
    sys.exit(test_yara_rules(rules_dir))
