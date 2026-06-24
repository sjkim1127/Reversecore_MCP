"""Unit tests for Regex Scanner."""

import pytest

from reversecore_mcp.core.sast.regex_scanner import RegexScanner
from reversecore_mcp.core.sast.rule_manager import SASTRule


@pytest.fixture
def test_rules():
    """Sample C rules for testing."""
    return [
        SASTRule(
            id="C-001",
            language="c",
            severity="critical",
            pattern="\\bstrcpy\\b",
            match_type="regex",
            category="Memory Safety",
            message="strcpy call",
        ),
        SASTRule(
            id="C-002",
            language="c",
            severity="critical",
            pattern="\\bgets\\b",
            match_type="regex",
            category="Memory Safety",
            message="gets call",
        ),
    ]


def test_regex_matching(test_rules):
    """Test standard regex rule matching."""
    code = """
int main() {
    char buf[10];
    strcpy(buf, "hello"); // Should be flagged
    printf("strcpy"); // Word match but within print
    char* x = gets(stdin); // Should be flagged
    return 0;
}
"""
    scanner = RegexScanner()
    findings = scanner.scan(code, test_rules)

    assert len(findings) >= 2
    rule_ids = [f["rule_id"] for f in findings]
    assert "C-001" in rule_ids
    assert "C-002" in rule_ids


def test_comment_skipping(test_rules):
    """Test that matches inside comments are skipped."""
    code = """
// strcpy(buf, input); - Inlined comment
/* gets(stdin); */ - Block comment
# strcpy is unsafe - preprocessor comment
   * gets is bad
strcpy(a, b); // Flagged line
"""
    scanner = RegexScanner()
    findings = scanner.scan(code, test_rules)

    assert len(findings) == 1
    assert findings[0]["line"] == 6


def test_malformed_regex_handling():
    """Test that malformed regex rules do not crash the scanner."""
    bad_rule = SASTRule(
        id="BAD-001",
        language="c",
        severity="low",
        pattern="[unclosed-bracket",
        match_type="regex",
        category="General",
        message="bad regex",
    )
    code = "some code line"
    scanner = RegexScanner()
    # Should not raise exception
    findings = scanner.scan(code, [bad_rule])
    assert findings == []
