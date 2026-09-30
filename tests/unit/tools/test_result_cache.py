"""Unit tests for the result caching decorator."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.core.result_cache import cache_tool_result


# Mock ToolResult for testing
def _success_result(val):
    return ToolSuccess(data=str(val))


class TestResultCache:
    @pytest.mark.asyncio
    @patch("reversecore_mcp.core.result_cache.set_cached_result")
    @patch("reversecore_mcp.core.result_cache.get_cached_result")
    async def test_cache_miss_calls_function(self, mock_get, mock_set):
        mock_get.return_value = None

        call_count = 0

        @cache_tool_result("test_tool", ttl=3600)
        async def dummy_tool(file_path: str, arg1: int):
            nonlocal call_count
            call_count += 1
            return _success_result(arg1 * 2)

        res = await dummy_tool(file_path="/tmp/test", arg1=5)

        assert call_count == 1
        assert res.data == "10"
        assert mock_set.call_count == 1

    @pytest.mark.asyncio
    @patch("reversecore_mcp.core.result_cache.get_cached_result")
    async def test_cache_hit_returns_cached_without_calling(self, mock_get):
        cached_data = ToolSuccess(data="42")
        mock_get.return_value = cached_data

        call_count = 0

        @cache_tool_result("test_tool", ttl=3600)
        async def dummy_tool(file_path: str, arg1: int):
            nonlocal call_count
            call_count += 1
            return _success_result(arg1 * 2)

        res = await dummy_tool(file_path="/tmp/test", arg1=5)

        assert call_count == 0  # Function should NOT be called
        assert res.data == "42"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.core.result_cache.set_cached_result")
    @patch("reversecore_mcp.core.result_cache.get_cached_result")
    async def test_error_result_is_not_cached(self, mock_get, mock_set):
        mock_get.return_value = None

        @cache_tool_result("test_tool", ttl=3600)
        async def dummy_tool(file_path: str):
            return ToolError(error_code="TEST_ERROR", message="fail")

        res = await dummy_tool(file_path="/tmp/test")

        assert res.status == "error"
        assert mock_set.call_count == 0  # Should not cache errors

    @pytest.mark.asyncio
    @patch("reversecore_mcp.core.result_cache.get_cached_result")
    async def test_cache_version_bypasses_older_persisted_result(self, mock_get):
        mock_get.return_value = None

        @cache_tool_result("test_tool", cache_version=1)
        async def old_tool(file_path: str):
            return ToolError(error_code="MISS", message="old version")

        @cache_tool_result("test_tool", cache_version=2)
        async def new_tool(file_path: str):
            return ToolError(error_code="MISS", message="new version")

        await old_tool(file_path="/tmp/test")
        await new_tool(file_path="/tmp/test")

        old_key = mock_get.call_args_list[0].args[1]
        new_key = mock_get.call_args_list[1].args[1]
        assert old_key != new_key
