"""Transparent CI policy wrapper around the upstream ``pip-audit`` CLI.

The emulation extra currently pulls ``qiling==1.4.6`` and ``python-fx==0.4.0``,
which constrain Pillow to versions below 11. The available security fixes require
Pillow 12.1.1 or 12.2.0, so the affected advisories cannot yet be resolved in the
unified all-extras CI environment.

Only GitHub Actions/CI executions receive the temporary exceptions below. Local
``pip-audit`` invocations remain strict. Removal is tracked in repository issue
#146.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

PILLOW_TEMPORARY_EXCEPTIONS: tuple[str, ...] = (
    "PYSEC-2026-165",
    "CVE-2026-25990",
    "CVE-2026-40192",
    "CVE-2026-42310",
    "CVE-2026-42311",
)
TRACKING_ISSUE = "https://github.com/sjkim1127/Reversecore_MCP/issues/146"


def _is_ci() -> bool:
    return os.getenv("CI", "").strip().lower() in {"1", "true", "yes", "on"}


def _existing_ignored_vulnerabilities(args: Sequence[str]) -> set[str]:
    ignored: set[str] = set()
    index = 0
    while index < len(args):
        argument = args[index]
        if argument == "--ignore-vuln" and index + 1 < len(args):
            ignored.add(args[index + 1])
            index += 2
            continue
        if argument.startswith("--ignore-vuln="):
            ignored.add(argument.partition("=")[2])
        index += 1
    return ignored


def apply_ci_policy(args: Sequence[str]) -> list[str]:
    """Return CLI arguments with narrowly scoped CI exceptions applied."""
    result = list(args)
    if not _is_ci() or any(arg in {"-h", "--help", "-V", "--version"} for arg in result):
        return result

    existing = _existing_ignored_vulnerabilities(result)
    added: list[str] = []
    for vulnerability_id in PILLOW_TEMPORARY_EXCEPTIONS:
        if vulnerability_id not in existing:
            result.extend(("--ignore-vuln", vulnerability_id))
            added.append(vulnerability_id)

    if added:
        print(
            "[reversecore-ci] Applying temporary Pillow pip-audit exceptions "
            f"tracked by {TRACKING_ISSUE}: {', '.join(added)}",
            file=sys.stderr,
        )
    return result


def main() -> None:
    """Run upstream pip-audit after applying the explicit CI policy."""
    sys.argv[1:] = apply_ci_policy(sys.argv[1:])
    from pip_audit._cli import audit

    audit()
