#!/usr/bin/env python3
"""Validate all YARA rules compile without syntax errors."""

import sys
from pathlib import Path


def test_yara_rules(rules_dir: str) -> int:
    """Compile every .yar and .yara file in the given directory using yara-python."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        if Path("rules").exists():
            rules_path = Path("rules")
        else:
            print(f"⚠️  Rules directory not found: {rules_dir}")
            return 0

    try:
        import yara
    except ImportError:
        print("❌ yara-python is not installed (pip install yara-python)")
        return 1

    yara_files = list(rules_path.rglob("*.yar")) + list(rules_path.rglob("*.yara"))
    if not yara_files:
        print(f"⚠️  No YARA rules found in {rules_path}")
        return 0

    passed = 0
    failed = 0

    for rule_file in sorted(yara_files):
        try:
            rel_name = rule_file.relative_to(rules_path)
        except ValueError:
            rel_name = rule_file.name
        print(f"🔍 {rel_name} ... ", end="", flush=True)
        try:
            yara.compile(filepath=str(rule_file))
            print("✅")
            passed += 1
        except Exception as e:
            print(f"❌\n   {e}")
            failed += 1

    print(f"\nYARA rule compilation: {passed} passed, {failed} failed")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "rules"
    sys.exit(test_yara_rules(rules_dir))
