"""Unit tests for prompts module."""

from unittest.mock import Mock

import pytest

from reversecore_mcp.prompts import register_prompts


class TestPromptsRegistration:
    """Test prompt registration with FastMCP."""

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock FastMCP instance."""
        # Don't use spec=FastMCP to avoid issues with module mocking in other tests
        mcp = Mock()
        mcp.prompt = Mock()
        return mcp

    def test_register_prompts_called(self, mock_mcp):
        """Test that register_prompts registers handlers with MCP."""
        register_prompts(mock_mcp)

        # Should register 10 prompts (full, malware, patch, basic, game, firmware, vulnerability, crypto, trinity_defense, apt_hunting)
        assert mock_mcp.prompt.call_count == 10

    def test_full_analysis_mode_registered(self, mock_mcp):
        """Test full_analysis_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "full_analysis_mode" in registered_prompts
        full_analysis_func = registered_prompts["full_analysis_mode"]

        # Test the prompt generates content
        result = full_analysis_func("test.exe")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "test.exe" in result
        assert "Elite Reverse Engineering Expert" in result
        assert "PHASE 1" in result

    def test_basic_analysis_mode_registered(self, mock_mcp):
        """Test basic_analysis_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "basic_analysis_mode" in registered_prompts
        basic_analysis_func = registered_prompts["basic_analysis_mode"]

        # Test the prompt generates content
        result = basic_analysis_func("sample.bin")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "sample.bin" in result
        assert "Rapid Static Analysis" in result
        assert "run_file" in result

    def test_game_analysis_mode_registered(self, mock_mcp):
        """Test game_analysis_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "game_analysis_mode" in registered_prompts
        game_analysis_func = registered_prompts["game_analysis_mode"]

        # Test the prompt generates content
        result = game_analysis_func("game_client.exe")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "game_client.exe" in result
        assert "Elite Game Security Researcher" in result
        assert "Anti-Cheat" in result

    def test_firmware_analysis_mode_registered(self, mock_mcp):
        """Test firmware_analysis_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "firmware_analysis_mode" in registered_prompts
        firmware_analysis_func = registered_prompts["firmware_analysis_mode"]

        # Test the prompt generates content
        result = firmware_analysis_func("firmware.bin")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "firmware.bin" in result
        assert "Embedded Systems Security Expert" in result
        assert "run_binwalk" in result

    def test_vulnerability_research_mode_registered(self, mock_mcp):
        """Test vulnerability_research_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "vulnerability_research_mode" in registered_prompts
        vuln_research_func = registered_prompts["vulnerability_research_mode"]

        # Test the prompt generates content
        result = vuln_research_func("target.exe")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "target.exe" in result
        assert "Vulnerability Researcher" in result
        assert "strcpy" in result or "system" in result

    def test_crypto_analysis_mode_registered(self, mock_mcp):
        """Test crypto_analysis_mode prompt is registered."""
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        assert "crypto_analysis_mode" in registered_prompts
        crypto_analysis_func = registered_prompts["crypto_analysis_mode"]

        # Test the prompt generates content
        result = crypto_analysis_func("crypto_app.exe")
        assert isinstance(result, str)
        assert len(result) > 0
        assert "crypto_app.exe" in result
        assert "Cryptography Analyst" in result
        assert "AES" in result or "RSA" in result


class TestPromptContent:
    """Test the content and structure of prompt responses."""

    def test_full_analysis_mode_content(self):
        """Test full_analysis_mode generates comprehensive instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        full_analysis = registered_prompts["full_analysis_mode"]
        result = full_analysis("malware.exe")

        # Check for key sections
        assert "Language Rule" in result
        assert "PHASE 1" in result
        assert "PHASE 2" in result
        assert "PHASE 3" in result
        assert "REASONING CHECKPOINT" in result
        assert "Intelligence Report" in result

        # Check for key tools mentioned
        assert "run_file" in result
        assert "extract_iocs" in result
        assert "match_libraries" in result
        assert "analyze_xrefs" in result
        assert "recover_structures" in result
        assert "smart_decompile" in result
        assert "generate_yara_rule" in result

    def test_basic_analysis_mode_content(self):
        """Test basic_analysis_mode generates lightweight analysis instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        basic_analysis = registered_prompts["basic_analysis_mode"]
        result = basic_analysis("sample.exe")

        # Check content
        assert "Rapid Static Analysis" in result
        assert "lightweight tools" in result
        assert "run_file" in result
        assert "parse_binary_with_lief" in result
        assert "run_strings" in result
        assert "extract_iocs" in result

        # Should NOT mention heavy tools
        assert "Ghidra" not in result or "Never use" in result

    def test_game_analysis_mode_content(self):
        """Test game_analysis_mode generates game-specific instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        game_analysis = registered_prompts["game_analysis_mode"]
        result = game_analysis("game.exe")

        # Check game-specific content
        assert "Elite Game Security Researcher" in result
        assert "Anti-Cheat" in result or "Protection Analysis" in result
        assert "recover_structures" in result
        assert "Player" in result or "Entity" in result
        assert "Unity" in result or "Unreal" in result

    def test_firmware_analysis_mode_content(self):
        """Test firmware_analysis_mode generates firmware-specific instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        firmware_analysis = registered_prompts["firmware_analysis_mode"]
        result = firmware_analysis("firmware.bin")

        # Check firmware-specific content
        assert "Embedded Systems" in result
        assert "run_binwalk" in result
        assert "SquashFS" in result or "UBIFS" in result
        assert "ARM" in result or "MIPS" in result
        assert "hardcoded credentials" in result or "Secret Hunting" in result

    def test_vulnerability_research_mode_content(self):
        """Test vulnerability_research_mode generates vuln-specific instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        vuln_research = registered_prompts["vulnerability_research_mode"]
        result = vuln_research("target.exe")

        # Check vuln research content
        assert "Vulnerability Researcher" in result
        assert "Buffer Overflow" in result or "strcpy" in result
        assert "analyze_xrefs" in result
        assert "ASLR" in result or "DEP" in result
        assert "parse_binary_with_lief" in result

    def test_crypto_analysis_mode_content(self):
        """Test crypto_analysis_mode generates crypto-specific instructions."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        crypto_analysis = registered_prompts["crypto_analysis_mode"]
        result = crypto_analysis("crypto.exe")

        # Check crypto-specific content
        assert "Cryptography Analyst" in result
        assert "AES" in result or "RSA" in result
        assert "S-Boxes" in result or "IVs" in result
        assert "run_yara" in result or "match_libraries" in result
        assert "OpenSSL" in result or "mbedTLS" in result
        assert "hardcoded keys" in result or "Key Management" in result


class TestPromptParameterization:
    """Test that prompts properly use the filename parameter."""

    def test_all_prompts_use_filename(self):
        """Test that all prompts properly incorporate the filename parameter."""
        mock_mcp = Mock()
        registered_prompts = {}

        def capture_prompt(name):
            def decorator(func):
                registered_prompts[name] = func
                return func

            return decorator

        mock_mcp.prompt = capture_prompt
        register_prompts(mock_mcp)

        test_filename = "unique_test_binary_12345.exe"
        test_patched_filename = "unique_test_binary_patched.exe"

        # Test each prompt
        for prompt_name, prompt_func in registered_prompts.items():
            if prompt_name == "patch_analysis_mode":
                # patch_analysis_mode requires two filenames
                result = prompt_func(test_filename, test_patched_filename)
                assert test_filename in result, f"Prompt {prompt_name} doesn't include original filename"
                assert test_patched_filename in result, f"Prompt {prompt_name} doesn't include patched filename"
            else:
                result = prompt_func(test_filename)
                assert test_filename in result, f"Prompt {prompt_name} doesn't include filename"
