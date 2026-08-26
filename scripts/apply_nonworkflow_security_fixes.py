#!/usr/bin/env python3
"""Apply security remediations that do not modify GitHub workflow files."""

from pathlib import Path

import apply_security_fixes as fixes


def main() -> None:
    fixes.patch_report_tools()
    fixes.patch_report_tests()
    fixes.patch_gitignore()
    fixes.write_fixture_generator()
    fixes.patch_conftest()
    fixes.patch_dependencies()
    fixes.write_scorecard_context()
    fixes.remove_tracked_binaries()

    Path(__file__).unlink(missing_ok=True)
    Path(__file__).with_name("apply_security_fixes.py").unlink(missing_ok=True)


if __name__ == "__main__":
    main()
