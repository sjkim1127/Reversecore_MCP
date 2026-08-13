"""Comprehensive unit tests for all MCP prompt generation functions."""

from reversecore_mcp.prompts.common import LANGUAGE_RULE
from reversecore_mcp.prompts.cve_research import (
    cve_discovery_pipeline_mode,
    fuzzing_mode,
    heap_exploit_mode,
    patch_diff_auto_mode,
    taint_analysis_mode,
)
from reversecore_mcp.prompts.game import game_analysis_mode
from reversecore_mcp.prompts.malware import (
    apt_hunting_mode,
    basic_analysis_mode,
    c2_extraction_mode,
    code_similarity_mode,
    full_analysis_mode,
    malware_analysis_mode,
    malware_defense_mode,
    ransomware_triage_mode,
    unpacking_mode,
)
from reversecore_mcp.prompts.report import report_generation_mode
from reversecore_mcp.prompts.security import (
    autonomous_vuln_hunt_mode,
    crypto_analysis_mode,
    firmware_analysis_mode,
    patch_analysis_mode,
    source_code_audit_mode,
    vulnerability_research_mode,
)
from reversecore_mcp.prompts.server_health import (
    server_health_check_mode,
    server_tool_catalog_mode,
)


class TestCveResearchPrompts:
    def test_cve_discovery_pipeline_mode(self):
        text = cve_discovery_pipeline_mode("sample.bin")
        assert "sample.bin" in text
        assert LANGUAGE_RULE in text

    def test_fuzzing_mode(self):
        text = fuzzing_mode("target.elf")
        assert "target.elf" in text
        assert LANGUAGE_RULE in text

    def test_heap_exploit_mode(self):
        text = heap_exploit_mode("heap_vuln.bin")
        assert "heap_vuln.bin" in text
        assert LANGUAGE_RULE in text

    def test_patch_diff_auto_mode(self):
        text = patch_diff_auto_mode("v1.bin", "v2.bin")
        assert "v1.bin" in text
        assert "v2.bin" in text
        assert LANGUAGE_RULE in text

    def test_taint_analysis_mode(self):
        text = taint_analysis_mode("target.bin")
        assert "target.bin" in text
        assert LANGUAGE_RULE in text


class TestMalwarePrompts:
    def test_full_analysis_mode(self):
        text = full_analysis_mode("malware.exe")
        assert "malware.exe" in text
        assert LANGUAGE_RULE in text

    def test_malware_analysis_mode(self):
        text = malware_analysis_mode("threat.dll")
        assert "threat.dll" in text
        assert LANGUAGE_RULE in text

    def test_basic_analysis_mode(self):
        text = basic_analysis_mode("sample.bin")
        assert "sample.bin" in text
        assert LANGUAGE_RULE in text

    def test_apt_hunting_mode(self):
        text = apt_hunting_mode("apt_sample.exe")
        assert "apt_sample.exe" in text
        assert LANGUAGE_RULE in text

    def test_malware_defense_mode(self):
        text = malware_defense_mode("target.exe")
        assert "target.exe" in text
        assert LANGUAGE_RULE in text

    def test_unpacking_mode(self):
        text = unpacking_mode("packed.exe")
        assert "packed.exe" in text
        assert LANGUAGE_RULE in text

    def test_c2_extraction_mode(self):
        text = c2_extraction_mode("bot.exe")
        assert "bot.exe" in text
        assert LANGUAGE_RULE in text

    def test_ransomware_triage_mode(self):
        text = ransomware_triage_mode("locker.exe")
        assert "locker.exe" in text
        assert LANGUAGE_RULE in text

    def test_code_similarity_mode(self):
        text = code_similarity_mode("a.exe")
        assert "a.exe" in text
        assert LANGUAGE_RULE in text


class TestSecurityPrompts:
    def test_patch_analysis_mode(self):
        text = patch_analysis_mode("old.bin", "new.bin")
        assert "old.bin" in text
        assert "new.bin" in text

    def test_crypto_analysis_mode(self):
        text = crypto_analysis_mode("crypto.bin")
        assert "crypto.bin" in text
        assert LANGUAGE_RULE in text

    def test_firmware_analysis_mode(self):
        text = firmware_analysis_mode("firmware.bin")
        assert "firmware.bin" in text
        assert LANGUAGE_RULE in text

    def test_vulnerability_research_mode(self):
        text = vulnerability_research_mode("vuln.bin")
        assert "vuln.bin" in text
        assert LANGUAGE_RULE in text

    def test_autonomous_vuln_hunt_mode(self):
        text = autonomous_vuln_hunt_mode("target.bin")
        assert "target.bin" in text
        assert LANGUAGE_RULE in text

    def test_source_code_audit_mode(self):
        text = source_code_audit_mode()
        assert LANGUAGE_RULE in text


class TestServerHealthPrompts:
    def test_server_health_check_mode(self):
        text = server_health_check_mode()
        assert "Reversecore MCP Server Inspector" in text
        assert LANGUAGE_RULE in text

    def test_server_tool_catalog_mode(self):
        text = server_tool_catalog_mode()
        assert "TOOL CATALOG" in text
        assert LANGUAGE_RULE in text


class TestGameAndReportPrompts:
    def test_game_analysis_mode(self):
        text = game_analysis_mode("game.exe")
        assert "game.exe" in text
        assert LANGUAGE_RULE in text

    def test_report_generation_mode(self):
        text = report_generation_mode("sess_123")
        assert "sess_123" in text
        assert LANGUAGE_RULE in text
