#!/usr/bin/env python3
"""One-shot repository patcher for the security alert remediation branch."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text()
    if old not in text:
        raise RuntimeError(f"expected text not found in {path}")
    target.write_text(text.replace(old, new, 1))


def patch_report_tools() -> None:
    target = ROOT / "reversecore_mcp/tools/report/report_tools.py"
    text = target.read_text()
    old = '''    async def get_report(self, report_id: str) -> dict:
        """Retrieve a generated report"""
        # Prevent path traversal
        clean_report_id = Path(report_id).name
        report_path = self.output_dir / f"{clean_report_id}.md"

        if not report_path.exists():
            # 리포트 목록 반환
            reports = [f.stem for f in self.output_dir.glob("*.md")]
            return {
                "success": False,
                "error": f"Report not found: {report_id}",
                "available_reports": reports,
            }

        async with aiofiles.open(report_path, encoding="utf-8") as f:
            content = await f.read()
'''
    new = '''    async def get_report(self, report_id: str) -> dict:
        """Retrieve a generated report without deriving a path from user input."""
        if (
            not report_id
            or len(report_id) > 128
            or not report_id.isascii()
            or not all(ch.isalnum() or ch in "_-" for ch in report_id)
        ):
            return {
                "success": False,
                "error": "Invalid report ID",
                "available_reports": [f.stem for f in self.output_dir.glob("*.md")],
            }

        # Enumerate trusted paths first. The untrusted ID is used only as a dict key,
        # so it never reaches a filesystem path expression.
        reports_by_id = {f.stem: f for f in self.output_dir.glob("*.md")}
        report_path = reports_by_id.get(report_id)
        if report_path is None:
            return {
                "success": False,
                "error": f"Report not found: {report_id}",
                "available_reports": sorted(reports_by_id),
            }

        async with aiofiles.open(report_path, encoding="utf-8") as f:
            content = await f.read()
'''
    if old not in text:
        raise RuntimeError("get_report block not found")
    target.write_text(text.replace(old, new, 1))


def patch_report_tests() -> None:
    target = ROOT / "tests/unit/tools/report/test_report_tools.py"
    text = target.read_text()
    anchor = '''    @pytest.mark.asyncio
    async def test_list_reports(self, rt):
'''
    added = '''    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "report_id",
        ["../secret", "../../etc/passwd", "/tmp/report", "nested/report", "nested\\\\report"],
    )
    async def test_get_report_rejects_path_like_ids(self, rt, report_id):
        """Path-like report IDs must never be interpreted as filesystem paths."""
        outside = rt.output_dir.parent / "secret.md"
        outside.write_text("sensitive")
        result = await rt.get_report(report_id)
        assert result["success"] is False
        assert result["error"] == "Invalid report ID"

'''
    if anchor not in text:
        raise RuntimeError("report test insertion anchor not found")
    target.write_text(text.replace(anchor, added + anchor, 1))


def patch_gitignore() -> None:
    target = ROOT / ".gitignore"
    text = target.read_text()
    block = '''

# Generated binary test fixtures (recreated by scripts/generate-ci-fixtures.py)
/scratch/binaries/
/tests/fixtures/dummy.bin
/tests/fixtures/smoke_test_elf
/tests/fixtures/synthetic_evasion/*.exe
/tests/fixtures/synthetic_packers/*.exe
/tests/fixtures/synthetic_packers/synthetic_clean_elf
/tests/fixtures/workspace/binaries/
'''
    if "# Generated binary test fixtures" not in text:
        target.write_text(text.rstrip() + block + "\n")


def write_fixture_generator() -> None:
    target = ROOT / "scripts/generate-ci-fixtures.py"
    target.write_text('''#!/usr/bin/env python3
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
    smoke.write_bytes(base64.b64decode(SMOKE_ELF_B64))
    smoke.chmod(0o755)

    packers = runpy.run_path(str(FIXTURES / "synthetic_packers" / "generate_fixtures.py"))
    packers["generate_all_fixtures"]()

    evasion = runpy.run_path(str(FIXTURES / "synthetic_evasion" / "generate_fixtures.py"))
    evasion["generate_fixtures"](FIXTURES / "synthetic_evasion")

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
''')
    target.chmod(0o755)


def patch_conftest() -> None:
    target = ROOT / "tests/conftest.py"
    text = target.read_text()
    if "generate-ci-fixtures.py" in text:
        return
    text = text.replace("import tempfile\n", "import tempfile\nfrom pathlib import Path\n", 1)
    old = "import subprocess  # noqa: E402\n\nimport pytest  # noqa: E402\n"
    new = '''import subprocess  # noqa: E402
import sys  # noqa: E402

# Generated binary fixtures are recreated from source for clean clones and CI.
_repo_root = Path(__file__).resolve().parent.parent
subprocess.run(
    [sys.executable, str(_repo_root / "scripts" / "generate-ci-fixtures.py")],
    cwd=_repo_root,
    check=True,
)

import pytest  # noqa: E402
'''
    if old not in text:
        raise RuntimeError("tests/conftest.py import anchor not found")
    target.write_text(text.replace(old, new, 1))


def patch_workflows() -> None:
    main = ROOT / ".github/workflows/main.yml"
    text = main.read_text()
    if "\npermissions: read-all\n" not in text:
        text = text.replace("\n# ── Computed globals", "\npermissions: read-all\n\n# ── Computed globals", 1)
    text, count = re.subn(
        r"(docker-verification:\n.*?permissions:\n\s+contents: read\n\s+)packages: write",
        r"\1packages: read",
        text,
        count=1,
        flags=re.S,
    )
    if count != 1:
        raise RuntimeError("docker-verification permission block not found")
    marker = "      - name: Build app Docker image\n"
    if "Generate repository test fixtures" not in text:
        if marker not in text:
            raise RuntimeError("Docker build marker not found")
        text = text.replace(
            marker,
            "      - name: Generate repository test fixtures\n        run: python3 scripts/generate-ci-fixtures.py\n\n" + marker,
            1,
        )
    main.write_text(text)

    for name, marker in [
        ("release.yml", "concurrency:"),
        ("pages.yml", "jobs:"),
        ("nightly-fuzz.yml", "jobs:"),
    ]:
        path = ROOT / ".github/workflows" / name
        text = path.read_text()
        if "\npermissions: read-all\n" not in text:
            if f"\n{marker}" not in text:
                raise RuntimeError(f"workflow insertion marker not found in {name}")
            text = text.replace(f"\n{marker}", f"\npermissions: read-all\n\n{marker}", 1)
        path.write_text(text)


def patch_dependencies() -> None:
    replace_once("requirements.txt", "pip==26.1.2", "pip==26.2")


def write_scorecard_context() -> None:
    (ROOT / "scorecard.yml").write_text('''# Maintainer context for checks whose remaining signal is intentional.
annotations:
  - checks:
      - code-review
    reasons:
      - reason: not-applicable # Sole-maintainer workflow; self-approval adds no security value.
  - checks:
      - token-permissions
    reasons:
      - reason: remediated # Default token is read-only; release creation still needs contents: write.
  - checks:
      - vulnerabilities
    reasons:
      - reason: not-applicable # angr pins Capstone 5.0.6; the CVE requires CAPSTONE_X86_REDUCE, unlike PyPI wheels.
''')


def remove_tracked_binaries() -> None:
    paths = [
        "scratch/binaries/hello_x64",
        "tests/fixtures/dummy.bin",
        "tests/fixtures/smoke_test_elf",
        "tests/fixtures/synthetic_evasion/clean_reference.exe",
        "tests/fixtures/synthetic_evasion/synthetic_combined_evasion.exe",
        "tests/fixtures/synthetic_evasion/synthetic_cpuid_vm.exe",
        "tests/fixtures/synthetic_evasion/synthetic_opaque_seh.exe",
        "tests/fixtures/synthetic_evasion/synthetic_peb_debug.exe",
        "tests/fixtures/synthetic_evasion/synthetic_rdtsc_timing.exe",
        "tests/fixtures/synthetic_packers/synthetic_authenticode.exe",
        "tests/fixtures/synthetic_packers/synthetic_clean_elf",
        "tests/fixtures/synthetic_packers/synthetic_clean_pe.exe",
        "tests/fixtures/synthetic_packers/synthetic_confuserex.exe",
        "tests/fixtures/synthetic_packers/synthetic_pyinstaller.exe",
        "tests/fixtures/synthetic_packers/synthetic_upx.exe",
        "tests/fixtures/synthetic_packers/synthetic_vmprotect.exe",
        "tests/fixtures/workspace/binaries/hello_x64",
        "tests/fixtures/workspace/binaries/hello_x64_stripped",
        "tests/fixtures/workspace/binaries/pe/mingw_x86.exe",
        "tests/fixtures/workspace/binaries/pe/minimal_x64.exe",
        "tests/fixtures/workspace/binaries/pe/minimal_x86.exe",
        "tests/fixtures/workspace/binaries/pie_x64",
        "tests/fixtures/workspace/binaries/vuln_x64",
        "tests/fixtures/workspace/binaries/vuln_x64_stripped",
    ]
    for rel in paths:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel], cwd=ROOT, capture_output=True
        )
        if result.returncode == 0:
            subprocess.run(["git", "rm", "-f", rel], cwd=ROOT, check=True)


def main() -> None:
    patch_report_tools()
    patch_report_tests()
    patch_gitignore()
    write_fixture_generator()
    patch_conftest()
    patch_workflows()
    patch_dependencies()
    write_scorecard_context()
    remove_tracked_binaries()

    # Remove one-shot automation files from the final tree.
    (ROOT / ".github/workflows/apply-security-fixes.yml").unlink(missing_ok=True)
    Path(__file__).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
