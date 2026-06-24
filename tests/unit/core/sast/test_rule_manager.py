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


def test_rule_manager_reset():
    """Test SASTRuleManager.reset clearing rules."""
    manager = SASTRuleManager()
    manager.load_rules()
    assert len(manager.get_all_rules()) > 0
    manager.reset()
    assert not manager._loaded
    assert len(manager._rules) == 0


def test_custom_rule_file_not_found(monkeypatch):
    """Test fallback when custom path does not exist."""

    class MockConfig:
        sast_rules_path = "/nonexistent/path/rules.yaml"

    import sys

    rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
    monkeypatch.setattr(rm_module, "get_config", lambda: MockConfig())

    manager = SASTRuleManager()
    manager.load_rules()
    # Should fall back to default rules, so we should have rules loaded
    assert len(manager.get_all_rules()) > 0


def test_get_config_exception(monkeypatch):
    """Test fallback when config retrieval raises an exception."""
    import sys

    def mock_get_config():
        raise Exception("Simulated config error")

    rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
    monkeypatch.setattr(rm_module, "get_config", mock_get_config)

    manager = SASTRuleManager()
    # Should handle the config exception and fall back to default rules
    manager.load_rules()
    assert len(manager.get_all_rules()) > 0


def test_empty_or_invalid_yaml(monkeypatch):
    """Test loading empty YAML file or file without rules key."""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as tmp:
        tmp.write("not_rules_key: hello")
        tmp_path = tmp.name

    try:

        class MockConfig:
            sast_rules_path = tmp_path

        import sys

        rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
        monkeypatch.setattr(rm_module, "get_config", lambda: MockConfig())

        manager = SASTRuleManager()
        manager.load_rules()
        assert len(manager.get_all_rules()) == 0
    finally:
        import os

        os.unlink(tmp_path)


def test_invalid_rule_skipped(monkeypatch):
    """Test that rules without required id or pattern are skipped."""
    custom_yaml = """
rules:
  - id: "" # missing ID
    language: "c"
    pattern: "strcpy"
  - id: "VALID"
    language: "c"
    pattern: "" # missing pattern
  - id: "PARTIALLY_VALID"
    language: "c"
    pattern: "strcpy"
"""
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as tmp:
        tmp.write(custom_yaml)
        tmp_path = tmp.name

    try:

        class MockConfig:
            sast_rules_path = tmp_path

        import sys

        rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
        monkeypatch.setattr(rm_module, "get_config", lambda: MockConfig())

        manager = SASTRuleManager()
        manager.load_rules()
        rules = manager.get_all_rules()
        assert len(rules) == 1
        assert rules[0].id == "PARTIALLY_VALID"
    finally:
        import os

        os.unlink(tmp_path)


def test_load_rules_read_error(monkeypatch):
    """Test load rules handles IO/file read error gracefully."""

    class MockConfig:
        sast_rules_path = (
            "/root/unreadable.yaml"  # usually triggers permission error or file not found
        )

    import sys

    rm_module = sys.modules["reversecore_mcp.core.sast.rule_manager"]
    monkeypatch.setattr(rm_module, "get_config", lambda: MockConfig())
    # Mock exists check to pass so it enters the open block, but open fails
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("pathlib.Path.is_file", lambda self: True)

    manager = SASTRuleManager()
    # Should not raise exception
    manager.load_rules()
    assert len(manager.get_all_rules()) == 0


def test_lazy_loading():
    """Test that rules are lazily loaded if get_all_rules or get_rules_for_language is called first."""
    manager = SASTRuleManager()
    # Calling get_all_rules directly should trigger load_rules()
    rules = manager.get_all_rules()
    assert len(rules) > 0

    manager2 = SASTRuleManager()
    # Calling get_rules_for_language directly should trigger load_rules()
    c_rules = manager2.get_rules_for_language("c")
    assert len(c_rules) > 0
