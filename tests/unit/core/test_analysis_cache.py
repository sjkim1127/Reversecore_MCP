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


@pytest.mark.asyncio
async def test_cache_operations_sqlite_success(patched_config):
    # Reuse the workspace configured by patched_config
    workspace_dir = patched_config.workspace

    test_file = workspace_dir / "target.bin"
    test_file.write_bytes(b"target binary contents")

    # Patch get_redis_client to return None so it falls back to SQLite
    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=None):
        # 1. Check cache miss
        res = await get_cached_decompile(test_file, "main", use_ghidra=True)
        assert res is None

        # 2. Store in cache
        suc = success("decompiled output from sqlite", func="main")
        await set_cached_decompile(test_file, "main", suc, use_ghidra=True)

        # Verify SQLite cache database file exists
        db_path = workspace_dir / ".reversecore_cache.db"
        assert db_path.exists()

        # 3. Check cache hit
        res_hit = await get_cached_decompile(test_file, "main", use_ghidra=True)
        assert res_hit is not None
        assert res_hit.status == "success"
        assert res_hit.data == "decompiled output from sqlite"
        assert res_hit.metadata["cache_hit"] is True

        # 4. Invalidation check: query cache with a different file hash
        other_file = workspace_dir / "other.bin"
        other_file.write_bytes(b"different contents")

        res_miss = await get_cached_decompile(other_file, "main", use_ghidra=True)
        assert res_miss is None


@pytest.mark.asyncio
async def test_export_and_import_cache_data(patched_config):
    from reversecore_mcp.core.analysis_cache import (
        export_cache_by_hash,
        import_cache_data,
    )

    workspace_dir = patched_config.workspace
    test_file = workspace_dir / "export_target.bin"
    test_file.write_bytes(b"export target data")
    file_hash = calculate_file_sha256(test_file)

    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=None):
        # 1. Populate cache in SQLite
        suc = success("int main() { return 42; }", func="main")
        await set_cached_decompile(test_file, "0x401000", suc, use_ghidra=True)

        # 2. Export cache
        exported = await export_cache_by_hash(file_hash)
        assert exported["format"] == "rcpack"
        assert exported["file_hash"] == file_hash
        assert len(exported["entries"]) == 1
        assert exported["entries"][0]["function_address"] == "0x401000"

        # 3. Import cache
        mock_redis = AsyncMock()
        with patch(
            "reversecore_mcp.core.analysis_cache.get_redis_client",
            return_value=mock_redis,
        ):
            count = await import_cache_data(exported)
            assert count == 1
            mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_import_cache_data_invalid_format():
    from reversecore_mcp.core.analysis_cache import import_cache_data

    with pytest.raises(ValueError, match="Invalid cache data format"):
        await import_cache_data({"format": "invalid"})


@pytest.mark.asyncio
async def test_import_cache_data_empty():
    from reversecore_mcp.core.analysis_cache import import_cache_data

    assert await import_cache_data({"format": "rcpack", "file_hash": ""}) == 0
    assert await import_cache_data({"format": "rcpack", "file_hash": "abc", "entries": []}) == 0


@pytest.mark.asyncio
async def test_close_redis():
    from reversecore_mcp.core import analysis_cache

    mock_client = AsyncMock()
    analysis_cache._redis_client = mock_client
    await analysis_cache.close_redis()
    mock_client.aclose.assert_called_once()
    assert analysis_cache._redis_client is None

    # Error handling during close
    mock_client_err = AsyncMock()
    mock_client_err.aclose.side_effect = RuntimeError("Close failed")
    analysis_cache._redis_client = mock_client_err
    await analysis_cache.close_redis()
    assert analysis_cache._redis_client is None


def test_deserialize_invalid_json():
    assert _deserialize_result("invalid json content {") is None


def test_calculate_file_sha256_read_exception(tmp_path):
    test_file = tmp_path / "unreadable.bin"
    test_file.write_bytes(b"data")
    with patch("builtins.open", side_effect=PermissionError("Denied")):
        assert calculate_file_sha256(test_file) == ""


def test_sqlite_read_write_exceptions(tmp_path):
    from reversecore_mcp.core.analysis_cache import (
        _read_from_sqlite,
        _write_to_sqlite,
    )

    db_path = tmp_path / "invalid_db.db"
    db_path.write_bytes(b"not a valid sqlite database header")

    # Should handle SQLite error gracefully and return None
    assert _read_from_sqlite(db_path, "hash", "0x1000", "ghidra") is None

    # Should handle SQLite write error gracefully
    _write_to_sqlite(db_path, "hash", "0x1000", "ghidra", "success", "data")


def test_get_redis_client_init_and_failure():
    from reversecore_mcp.core import analysis_cache

    # 1. Test redis disabled flag
    analysis_cache._redis_enabled = False
    analysis_cache._redis_client = None
    assert analysis_cache.get_redis_client() is None

    # 2. Test redis init exception
    analysis_cache._redis_enabled = True
    analysis_cache._redis_client = None
    with patch("redis.asyncio.from_url", side_effect=Exception("Redis connection error")):
        assert analysis_cache.get_redis_client() is None
        assert analysis_cache._redis_enabled is False

    # Reset
    analysis_cache._redis_enabled = True
    analysis_cache._redis_client = None


@pytest.mark.asyncio
async def test_get_cached_decompile_redis_error_fallback(patched_config):
    from reversecore_mcp.core import analysis_cache

    workspace_dir = patched_config.workspace
    test_file = workspace_dir / "fallback_target.bin"
    test_file.write_bytes(b"fallback binary data")

    mock_redis = AsyncMock()
    mock_redis.get.side_effect = Exception("Redis get failed")

    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=mock_redis):
        # Store in SQLite directly
        suc = success("code in sqlite", func="main")
        await analysis_cache.set_cached_decompile(test_file, "main", suc, use_ghidra=True)

        # get_cached_decompile should catch redis error and fall back to SQLite hit
        res = await analysis_cache.get_cached_decompile(test_file, "main", use_ghidra=True)
        assert res is not None
        assert res.data == "code in sqlite"


@pytest.mark.asyncio
async def test_set_cached_decompile_skips_failure(patched_config):
    from reversecore_mcp.core import analysis_cache

    workspace_dir = patched_config.workspace
    test_file = workspace_dir / "fail_target.bin"
    test_file.write_bytes(b"data")

    # Should not cache failure results
    fail = failure("ERROR", "Failed decompilation")
    await analysis_cache.set_cached_decompile(test_file, "main", fail)

    res = await analysis_cache.get_cached_decompile(test_file, "main")
    assert res is None


@pytest.mark.asyncio
async def test_cache_errors_during_set_and_export(patched_config):
    from reversecore_mcp.core import analysis_cache

    workspace_dir = patched_config.workspace
    test_file = workspace_dir / "err_target.bin"
    test_file.write_bytes(b"data")

    # Redis setex error
    mock_redis = AsyncMock()
    mock_redis.setex.side_effect = Exception("Redis setex error")
    with patch("reversecore_mcp.core.analysis_cache.get_redis_client", return_value=mock_redis):
        suc = success("code")
        await analysis_cache.set_cached_decompile(test_file, "main", suc)

    # SQLite error during export
    with patch(
        "reversecore_mcp.core.analysis_cache._init_sqlite_db",
        side_effect=Exception("DB init failed"),
    ):
        exported = await analysis_cache.export_cache_by_hash("some_hash")
        assert exported["entries"] == []

    # SQLite error during import
    with patch(
        "reversecore_mcp.core.analysis_cache._init_sqlite_db",
        side_effect=Exception("DB init failed"),
    ):
        count = await analysis_cache.import_cache_data(
            {
                "format": "rcpack",
                "file_hash": "some_hash",
                "entries": [
                    {
                        "function_address": "0x1000",
                        "decompiler": "ghidra",
                        "status": "success",
                        "data": "{}",
                    }
                ],
            }
        )
        assert count == 0
