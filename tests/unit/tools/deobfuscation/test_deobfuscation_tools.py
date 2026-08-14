"""Unit tests for Deobfuscation MCP tool wrappers and Plugin."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.tools.deobfuscation import DeobfuscationToolsPlugin
from reversecore_mcp.tools.deobfuscation.deobfuscation_tools import (
    deobfuscate_strings,
    eliminate_dead_code,
    resolve_api_hashes,
    run_deobfuscation_pipeline,
)


@pytest.mark.unit
class TestDeobfuscationToolsWrappers:
    """Test FastMCP tool wrapper functions."""

    @pytest.mark.asyncio
    async def test_deobfuscate_strings_wrapper(self):
        with patch(
            "reversecore_mcp.tools.deobfuscation.deobfuscation_tools.deobfuscate_strings_impl",
            new_callable=AsyncMock,
            return_value=success({"recovered_strings": []}),
        ) as mock_impl:
            res = await deobfuscate_strings("/app/workspace/sample.bin", function_address="main")
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                "/app/workspace/sample.bin",
                function_address="main",
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_resolve_api_hashes_wrapper(self):
        with patch(
            "reversecore_mcp.tools.deobfuscation.deobfuscation_tools.resolve_api_hashes_impl",
            new_callable=AsyncMock,
            return_value=success({"resolved_apis": []}),
        ) as mock_impl:
            res = await resolve_api_hashes(
                "/app/workspace/sample.bin",
                algorithm="crc32",
                custom_hashes={"0x1234": "sample.dll!Api"},
            )
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                "/app/workspace/sample.bin",
                algorithm="crc32",
                custom_hashes={"0x1234": "sample.dll!Api"},
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_eliminate_dead_code_wrapper(self):
        with patch(
            "reversecore_mcp.tools.deobfuscation.deobfuscation_tools.eliminate_dead_code_impl",
            new_callable=AsyncMock,
            return_value=success({"opaque_predicates": []}),
        ) as mock_impl:
            res = await eliminate_dead_code(
                "/app/workspace/sample.bin", function_address="0x401000"
            )
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                "/app/workspace/sample.bin",
                function_address="0x401000",
                timeout=None,
            )

    @pytest.mark.asyncio
    async def test_run_deobfuscation_pipeline_wrapper(self):
        with patch(
            "reversecore_mcp.tools.deobfuscation.deobfuscation_tools.run_deobfuscation_pipeline_impl",
            new_callable=AsyncMock,
            return_value=success({"obfuscation_level": "LOW"}),
        ) as mock_impl:
            res = await run_deobfuscation_pipeline(
                "/app/workspace/sample.bin", options={"algorithm": "auto"}
            )
            assert res.status == "success"
            mock_impl.assert_called_once_with(
                "/app/workspace/sample.bin",
                options={"algorithm": "auto"},
                timeout=None,
            )


@pytest.mark.unit
class TestDeobfuscationToolsPlugin:
    """Test DeobfuscationToolsPlugin class and tool registration."""

    def test_plugin_properties_and_register(self):
        plugin = DeobfuscationToolsPlugin()
        assert plugin.name == "deobfuscation_tools"
        assert "deobfuscation" in plugin.description.lower()

        mock_server = MagicMock()
        plugin.register(mock_server)
        assert mock_server.tool.call_count == 4
