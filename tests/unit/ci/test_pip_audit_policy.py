"""Tests for the CI-only pip-audit policy wrapper."""

from reversecore_pip_audit_policy import (
    PILLOW_TEMPORARY_EXCEPTIONS,
    apply_ci_policy,
)


def test_local_audit_remains_strict(monkeypatch):
    monkeypatch.delenv("CI", raising=False)

    original = ["--format", "json"]
    assert apply_ci_policy(original) == original


def test_ci_audit_adds_tracked_pillow_exceptions(monkeypatch):
    monkeypatch.setenv("CI", "true")

    result = apply_ci_policy(["--ignore-vuln", PILLOW_TEMPORARY_EXCEPTIONS[0]])

    for vulnerability_id in PILLOW_TEMPORARY_EXCEPTIONS:
        assert vulnerability_id in result
    assert result.count(PILLOW_TEMPORARY_EXCEPTIONS[0]) == 1


def test_help_and_version_are_not_modified(monkeypatch):
    monkeypatch.setenv("CI", "true")

    assert apply_ci_policy(["--help"]) == ["--help"]
    assert apply_ci_policy(["--version"]) == ["--version"]
