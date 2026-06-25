"""Unit tests for the Redis-based analysis cache component."""

from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.analysis_cache import (
    _deserialize_result,
    _serialize_result,
    calculate_file_sha256,
    get_cached_decompile,
    set_cached_decompile,
)
from reversecore_mcp.core.result import failure, success


def test_calculate_file_sha256(tmp_path):
    # Test nonexistent file
    assert calculate_file_sha256(tmp_path / "nonexistent") == ""

    # Test valid file
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello world")
    expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert calculate_file_sha256(test_file) == expected_hash


def test_serialization_roundtrip():
    # Test success result
    suc = success("decompiled code", author="test", decompiler="ghidra")
    serialized = _serialize_result(suc)
    deserialized = _deserialize_result(serialized)
    assert deserialized.status == "success"
    assert deserialized.data == "decompiled code"
    assert deserialized.metadata["author"] == "test"
    assert deserialized.metadata["decompiler"] == "ghidra"

    # Test failure result
    fail = failure("ERR_CODE", "Something failed", hint="Try again", details_val="detail")
    serialized = _serialize_result(fail)
    deserialized = _deserialize_result(serialized)
    assert deserialized.status == "error"
    assert deserialized.error_code == "ERR_CODE"
    assert deserialized.message == "Something failed"
    assert deserialized.hint == "Try again"
    assert deserialized.details["details_val"] == "detail"


@pytest.mark.asyncio
async def test_cache_operations_redis_disabled():
    # Force get_redis_client to return None
    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=None):
        # get_cached_decompile should immediately return None
        res = await get_cached_decompile("dummy_path", "main")
        assert res is None

        # set_cached_decompile should run without exception
        suc = success("code")
        await set_cached_decompile("dummy_path", "main", suc)


@pytest.mark.asyncio
async def test_cache_operations_success(tmp_path):
    test_file = tmp_path / "target.bin"
    test_file.write_bytes(b"target binary")
    file_hash = calculate_file_sha256(test_file)

    mock_redis = AsyncMock()
    # Mock redis get and setex
    cached_val = None

    async def mock_get(key):
        return cached_val

    async def mock_setex(key, ttl, value):
        nonlocal cached_val
        cached_val = value

    mock_redis.get.side_effect = mock_get
    mock_redis.setex.side_effect = mock_setex

    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=mock_redis):
        # 1. Check cache miss
        res = await get_cached_decompile(test_file, "main", use_ghidra=True)
        assert res is None

        # 2. Store in cache
        suc = success("decompiled output", func="main")
        await set_cached_decompile(test_file, "main", suc, use_ghidra=True)

        # Verify key used in Redis
        expected_key = f"ghidra:decompile:{file_hash}:main:ghidra"
        mock_redis.setex.assert_called_once()
        assert mock_redis.setex.call_args[0][0] == expected_key

        # 3. Check cache hit
        res_hit = await get_cached_decompile(test_file, "main", use_ghidra=True)
        assert res_hit is not None
        assert res_hit.status == "success"
        assert res_hit.data == "decompiled output"
        assert res_hit.metadata["cache_hit"] is True
