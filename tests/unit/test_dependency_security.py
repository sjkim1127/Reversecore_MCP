from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_unified_runtime_uses_secure_pillow_without_qiling() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")

    assert '"pillow>=12.3.0,<13"' in pyproject
    assert '"qiling>=' not in pyproject
    assert "pillow==12.3.0" in requirements
    assert "qiling==" not in requirements
    assert "python-fx==" not in requirements
