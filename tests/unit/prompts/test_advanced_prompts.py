"""Unit tests for advanced reasoning prompts and prompt registration."""

from unittest.mock import MagicMock

from reversecore_mcp.prompts import (
    __all__ as all_prompts,
)
from reversecore_mcp.prompts import (
    exploit_analysis_mode,
    malware_deobfuscation_mode,
    register_prompts,
    source_code_audit_mode,
    vulnerability_triage_mode,
)
from reversecore_mcp.prompts.common import DOCKER_PATH_RULE, LANGUAGE_RULE


class TestVulnerabilityTriageMode:
    """Tests for vulnerability_triage_mode prompt."""

    def test_default_invocation(self):
        prompt = vulnerability_triage_mode()
        assert LANGUAGE_RULE in prompt
        assert DOCKER_PATH_RULE in prompt
        assert "Vulnerability Triage Report" in prompt
        assert "[🔍 OBSERVED]" in prompt
        assert "[🔎 INFERRED]" in prompt
        assert "[❓ POSSIBLE]" in prompt

    def test_cwe_taxonomy_mapping(self):
        prompt = vulnerability_triage_mode()
        cwes = [
            "CWE-121",
            "CWE-122",
            "CWE-416",
            "CWE-415",
            "CWE-761",
            "CWE-125",
            "CWE-476",
        ]
        for cwe in cwes:
            assert cwe in prompt

    def test_cvss_v31_vector_and_scoring(self):
        prompt = vulnerability_triage_mode()
        assert "CVSS v3.1" in prompt
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in prompt
        assert "9.8" in prompt
        assert "Score" in prompt or "score" in prompt

    def test_with_custom_crash_log(self):
        sample_log = (
            "==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
        )
        prompt = vulnerability_triage_mode(crash_log=sample_log)
        assert sample_log in prompt
        assert "[Crash Log Context]" in prompt

    def test_remediation_and_tool_commands(self):
        prompt = vulnerability_triage_mode()
        assert "triage_asan_log" in prompt
        assert "minimize_poc_file" in prompt
        assert "Remediation" in prompt


class TestExploitAnalysisMode:
    """Tests for exploit_analysis_mode prompt."""

    def test_default_invocation(self):
        prompt = exploit_analysis_mode()
        assert "target_binary" in prompt
        assert LANGUAGE_RULE in prompt
        assert DOCKER_PATH_RULE in prompt
        assert "[🔍 OBSERVED]" in prompt
        assert "[🔎 INFERRED]" in prompt
        assert "[❓ POSSIBLE]" in prompt

    def test_custom_binary_name(self):
        prompt = exploit_analysis_mode("vuln_server.elf")
        assert "vuln_server.elf" in prompt

    def test_mitigation_matrix(self):
        prompt = exploit_analysis_mode("challenge.bin")
        for mitigation in ["Canary", "NX", "PIE", "ASLR", "RELRO", "Fortify"]:
            assert mitigation in prompt

    def test_exploit_primitives_and_techniques(self):
        prompt = exploit_analysis_mode("challenge.bin")
        assert "Arbitrary Read" in prompt
        assert "Arbitrary Write" in prompt
        assert "Control Flow Hijack" in prompt
        assert "ret2libc" in prompt or "Ret2libc" in prompt
        assert "GOT overwrite" in prompt or "GOT" in prompt
        assert "tcache" in prompt
        assert "ROP" in prompt
        assert "build_rop_chain" in prompt

    def test_pwntools_script_generation(self):
        prompt = exploit_analysis_mode("target.elf")
        assert "from pwn import *" in prompt
        assert "context.binary" in prompt
        assert "payload" in prompt


class TestMalwareDeobfuscationMode:
    """Tests for malware_deobfuscation_mode prompt."""

    def test_default_invocation(self):
        prompt = malware_deobfuscation_mode()
        assert "target_binary" in prompt
        assert LANGUAGE_RULE in prompt
        assert DOCKER_PATH_RULE in prompt
        assert "[🔍 OBSERVED]" in prompt
        assert "[🔎 INFERRED]" in prompt
        assert "[❓ POSSIBLE]" in prompt

    def test_layer1_string_decryption(self):
        prompt = malware_deobfuscation_mode("sample.dll")
        assert "String Decryption" in prompt
        assert "Stack Strings" in prompt or "stack strings" in prompt
        assert "XOR" in prompt
        assert "RC4" in prompt
        assert "AES" in prompt
        assert "deobfuscate_strings" in prompt

    def test_layer2_dynamic_api_resolution(self):
        prompt = malware_deobfuscation_mode("sample.dll")
        assert "API Resolution" in prompt or "API Hashing" in prompt
        assert "CRC32" in prompt
        assert "ROR13" in prompt
        assert "DJB2" in prompt
        assert "MurmurHash" in prompt or "Murmur" in prompt
        assert "FNV-1a" in prompt or "fnv1a" in prompt
        assert "resolve_api_hashes" in prompt

    def test_layer3_control_flow_flattening(self):
        prompt = malware_deobfuscation_mode("sample.dll")
        assert "Control-Flow Flattening" in prompt or "Control Flow" in prompt
        assert "eliminate_dead_code" in prompt
        assert "run_deobfuscation_pipeline" in prompt

    def test_layer4_anti_analysis_neutralization(self):
        prompt = malware_deobfuscation_mode("sample.dll")
        assert "Anti-Analysis" in prompt or "Anti-Debugging" in prompt
        assert "BeingDebugged" in prompt
        assert "RDTSC" in prompt


class TestPromptRegistration:
    """Tests for prompt registration in FastMCP."""

    def test_source_code_audit_mode_present(self):
        text = source_code_audit_mode()
        assert "SAST Specialist" in text

    def test_register_prompts_registers_all_new_prompts(self):
        mock_mcp = MagicMock()
        registered_prompts = {}

        def mock_prompt_decorator(name):
            def decorator(fn):
                registered_prompts[name] = fn
                return fn

            return decorator

        mock_mcp.prompt.side_effect = mock_prompt_decorator
        register_prompts(mock_mcp)

        # Verify all new and crucial prompts are registered
        expected_prompts = [
            "source_code_audit_mode",
            "vulnerability_triage_mode",
            "exploit_analysis_mode",
            "malware_deobfuscation_mode",
            "full_analysis_mode",
            "malware_analysis_mode",
            "basic_analysis_mode",
            "apt_hunting_mode",
            "malware_defense_mode",
            "unpacking_mode",
            "c2_extraction_mode",
            "ransomware_triage_mode",
            "code_similarity_mode",
            "patch_analysis_mode",
            "crypto_analysis_mode",
            "firmware_analysis_mode",
            "vulnerability_research_mode",
            "vulnerability_hunter_mode",
            "autonomous_vuln_hunt_mode",
            "taint_analysis_mode",
            "heap_exploit_mode",
            "fuzzing_mode",
            "patch_diff_auto_mode",
            "cve_discovery_pipeline_mode",
            "game_analysis_mode",
            "report_generation_mode",
            "server_health_check_mode",
            "server_tool_catalog_mode",
        ]

        for prompt_name in expected_prompts:
            assert prompt_name in registered_prompts, f"Prompt {prompt_name} was not registered!"

    def test_all_prompts_export_list(self):
        assert "vulnerability_triage_mode" in all_prompts
        assert "exploit_analysis_mode" in all_prompts
        assert "malware_deobfuscation_mode" in all_prompts
        assert "source_code_audit_mode" in all_prompts
        assert "register_prompts" in all_prompts
