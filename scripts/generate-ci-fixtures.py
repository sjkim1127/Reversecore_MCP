#!/usr/bin/env python3
"""Recreate deterministic binary fixtures from source during tests and CI."""

from __future__ import annotations

import base64
import runpy
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
SMOKE_ELF_B64 = (
    "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAEAAOAABAEAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAA"
    "QAAAAAAAhAAAAAAAAACEAAAAAAAAAAAQAAAAAAAASMfAPAAAAEgx/w8F"
)


def main() -> None:
    smoke = FIXTURES / "smoke_test_elf"
    try:
        smoke.write_bytes(base64.b64decode(SMOKE_ELF_B64))
        smoke.chmod(0o755)
    except PermissionError:
        if not smoke.exists():
            raise

    try:
        packers = runpy.run_path(str(FIXTURES / "synthetic_packers" / "generate_fixtures.py"))
        packers["generate_all_fixtures"]()
    except PermissionError:
        pass

    try:
        evasion = runpy.run_path(str(FIXTURES / "synthetic_evasion" / "generate_fixtures.py"))
        evasion["generate_fixtures"](FIXTURES / "synthetic_evasion")
    except PermissionError:
        pass

    binaries = FIXTURES / "workspace" / "binaries"
    if not (binaries / "hello_x64").exists():
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "fetch_test_binaries.py")],
            cwd=ROOT,
            check=True,
        )

    pe_dir = binaries / "pe"
    if not (pe_dir / "minimal_x86.exe").exists() or not (pe_dir / "minimal_x64.exe").exists():
        pe = runpy.run_path(str(ROOT / "scripts" / "generate-pe-and-large-binaries.py"))
        pe["PEBinaryGenerator"]().generate_all_pe_binaries()


if __name__ == "__main__":
    main()
