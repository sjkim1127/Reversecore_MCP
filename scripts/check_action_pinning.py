#!/usr/bin/env python3
"""Verify all external GitHub Actions in .github/workflows/*.yml are pinned to 40-character commit SHAs."""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Match 'uses: owner/repo[/path]@ref' (ignoring local actions like './' or 'docker://')
ACTION_REGEX = re.compile(r"^\s*(?:-\s+)?uses:\s+([^./\s][^@\s]*?)@([^\s#]+)")
SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")


def check_action_pinning(workflows_dir: Path) -> int:
    """Scan workflow YAML files and assert all external actions use 40-char commit SHAs.

    Args:
        workflows_dir: Path to the .github/workflows directory.

    Returns:
        0 if all actions are pinned to SHAs, 1 if any unpinned action is found.
    """
    violations: list[tuple[Path, int, str, str]] = []
    checked_count = 0

    yaml_files = sorted(list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml")))

    if not yaml_files:
        print(f"Error: No workflow files found in {workflows_dir}", file=sys.stderr)
        return 1

    for file_path in yaml_files:
        with open(file_path, encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                match = ACTION_REGEX.match(line)
                if not match:
                    continue

                action_name = match.group(1).strip()
                ref = match.group(2).strip()
                checked_count += 1

                if not SHA_REGEX.match(ref):
                    violations.append((file_path, line_no, action_name, ref))

    if violations:
        print(f"FAILED: Found {len(violations)} unpinned GitHub Action(s):", file=sys.stderr)
        for path, line_no, action, ref in violations:
            print(
                f"  {path}:{line_no} -> {action}@{ref} (expected 40-character commit SHA)",
                file=sys.stderr,
            )
        return 1

    print(
        f"SUCCESS: All {checked_count} GitHub Action invocations are strictly pinned to 40-character commit SHAs."
    )
    return 0


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    workflows_dir = repo_root / ".github" / "workflows"
    return check_action_pinning(workflows_dir)


if __name__ == "__main__":
    sys.exit(main())
