"""Unit tests for SAST Rule Manager."""

import tempfile

from reversecore_mcp.core.sast.rule_manager import SASTRuleManager


def test_default_rules_load():
    """Test that the default rules load correctly."""
    manager = SASTRuleManager()
    manager.load_rules()

    rules = manager.get_all_rules()
    assert len(rules) > 0
    # Check that both C and Python rules exist
    c_rules = manager.get_rules_for_language("c")
    py_rules = manager.get_rules_for_language("python")
    assert len(c_rules) > 0
    assert len(py_rules) > 0

    # Confirm fields are correctly set
    first_rule = rules[0]
    assert first_rule.id != ""
    assert first_rule.pattern != ""
    assert first_rule.match_type in ("regex", "ast")


def test_language_normalization():
    """Test that c, cpp, c++, h are normalized to c."""
    manager = SASTRuleManager()
    manager.load_rules()

    c_rules = manager.get_rules_for_language("c")
    cpp_rules = manager.get_rules_for_language("cpp")
    cplusplus_rules = manager.get_rules_for_language("c++")
    h_rules = manager.get_rules_for_language("h")

    assert len(c_rules) == len(cpp_rules)
    assert len(c_rules) == len(cplusplus_rules)
    assert len(c_rules) == len(h_rules)


def test_custom_rule_override(monkeypatch):
    """Test that custom rules path overrides default rules."""
    custom_yaml = """
rules:
  - id: "CUSTOM-C-001"
    language: "c"
    severity: "low"
    pattern: "custom_func"
    match_type: "regex"
    category: "Custom Category"
    message: "Custom warning message."
"""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as tmp:
        tmp.write(custom_yaml)
        tmp_path = tmp.name

    try:
        # Mock get_config to return our custom path
        class MockConfig:
            sast_rules_path = tmp_path

        import sys

        rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
        monkeypatch.setattr(rm_module, "get_config", lambda: MockConfig())

        manager = SASTRuleManager()
        manager.load_rules()

        rules = manager.get_all_rules()
        assert len(rules) == 1
        assert rules[0].id == "CUSTOM-C-001"
        assert rules[0].pattern == "custom_func"
        assert rules[0].severity == "low"
    finally:
        import os

        os.unlink(tmp_path)
