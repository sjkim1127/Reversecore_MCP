from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_unified_runtime_uses_secure_pillow_without_qiling() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "main.yml").read_text(encoding="utf-8")
    compiler = (ROOT / "scripts" / "compile-requirements.sh").read_text(encoding="utf-8")
    trivy_ignore = (ROOT / ".trivyignore").read_text(encoding="utf-8")

    assert '"pillow>=12.3.0,<13"' in pyproject
    assert '"qiling>=' not in pyproject
    assert "pillow==12.3.0" in requirements
    assert "qiling==" not in requirements
    assert "python-fx==" not in requirements
    assert not (ROOT / "requirements-qiling.txt").exists()
    assert "requirements-qiling" not in workflow
    assert "requirements-qiling" not in compiler
    assert "CVE-2026-25990" not in trivy_ignore
    assert "CVE-2026-40192" not in trivy_ignore
    assert "CVE-2026-42308" not in trivy_ignore
    assert "CVE-2026-42310" not in trivy_ignore
    assert "CVE-2026-42311" not in trivy_ignore
