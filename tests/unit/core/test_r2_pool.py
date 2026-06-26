"""Unit tests for R2ConnectionPool."""

import asyncio
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.r2_pool import R2ConnectionPool

r2_pool_mod = sys.modules["reversecore_mcp.core.r2_pool"]


class TestR2ConnectionPoolInit:
    """Tests for pool initialization."""

    def test_default_init(self):
        """Should initialize with defaults."""
        pool = R2ConnectionPool()
        assert pool._max_connections is None
        assert pool._acquisition_timeout is None
        assert pool._config_loaded is False
        assert len(pool._pool) == 0

    def test_custom_init(self):
        """Should accept custom values."""
        pool = R2ConnectionPool(max_connections=5, acquisition_timeout=10, health_check_interval=30)
        assert pool._max_connections == 5
        assert pool._acquisition_timeout == 10
        assert pool._health_check_interval == 30

    def test_stats_initialized(self):
        """Should initialize statistics."""
        pool = R2ConnectionPool()
        assert pool._stats["connections_created"] == 0
        assert pool._stats["connections_evicted"] == 0
        assert pool._stats["cache_hits"] == 0
        assert pool._stats["cache_misses"] == 0
        assert pool._stats["reconnections"] == 0


class TestR2ConnectionPoolConfig:
    """Tests for lazy config loading."""

    def test_load_config_from_env(self):
        """Should load config from environment."""
        pool = R2ConnectionPool()
        with patch("reversecore_mcp.core.config.get_config") as mock_cfg:
            mock_cfg.return_value.r2_pool_size = 7
            mock_cfg.return_value.r2_pool_timeout = 45
            pool._load_config()
            assert pool._max_connections == 7
            assert pool._acquisition_timeout == 45

    def test_load_config_fallback(self):
        """Should use defaults when config unavailable."""
        pool = R2ConnectionPool()
        with patch("reversecore_mcp.core.config.get_config", side_effect=ImportError):
            pool._load_config()
            assert pool._max_connections == 10
            assert pool._acquisition_timeout == 30

    def test_load_config_idempotent(self):
        """Should only load config once."""
        pool = R2ConnectionPool()
        with patch("reversecore_mcp.core.config.get_config") as mock_cfg:
            mock_cfg.return_value.r2_pool_size = 3
            mock_cfg.return_value.r2_pool_timeout = 15
            pool._load_config()
            pool._load_config()
            assert mock_cfg.call_count == 1

    def test_max_connections_property(self):
        """Property should trigger config load."""
        pool = R2ConnectionPool()
        with patch("reversecore_mcp.core.config.get_config") as mock_cfg:
            mock_cfg.return_value.r2_pool_size = 8
            mock_cfg.return_value.r2_pool_timeout = 20
            assert pool.max_connections == 8

    def test_acquisition_timeout_property(self):
        """Property should trigger config load."""
        pool = R2ConnectionPool()
        with patch("reversecore_mcp.core.config.get_config") as mock_cfg:
            mock_cfg.return_value.r2_pool_size = 4
            mock_cfg.return_value.r2_pool_timeout = 60
            assert pool.acquisition_timeout == 60


class TestR2ConnectionPoolSemaphores:
    """Tests for semaphore creation."""

    def test_get_connection_semaphore(self):
        """Should create semaphore lazily."""
        pool = R2ConnectionPool(max_connections=3)
        sem = pool._get_connection_semaphore()
        assert isinstance(sem, threading.Semaphore)
        assert sem._value == 3

    def test_get_async_semaphore(self):
        """Should create async semaphore lazily."""
        pool = R2ConnectionPool(max_connections=5)
        sem = pool._get_async_semaphore()
        assert isinstance(sem, asyncio.Semaphore)
        assert sem._value == 5

    def test_get_async_lock(self):
        """Should create async lock lazily."""
        pool = R2ConnectionPool()
        lock = pool._get_async_lock()
        assert isinstance(lock, asyncio.Lock)
        # Second call should return same lock
        lock2 = pool._get_async_lock()
        assert lock is lock2


class TestR2ConnectionPoolHealthCheck:
    """Tests for health checking."""

    def test_is_connection_healthy(self):
        """Should return True for responsive connection."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="0x1000")
        assert pool._is_connection_healthy("/app/test.bin", mock_r2) is True

    def test_is_connection_unhealthy(self):
        """Should return False for broken connection."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(side_effect=RuntimeError("broken"))
        assert pool._is_connection_healthy("/app/test.bin", mock_r2) is False

    def test_maybe_health_check_recent(self):
        """Should skip check if recent."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._last_health_check["/app/test.bin"] = time.time()
        assert pool._maybe_health_check("/app/test.bin", mock_r2) is True

    def test_maybe_health_check_stale(self):
        """Should perform check if stale."""
        pool = R2ConnectionPool(health_check_interval=1)
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="0x1000")
        pool._last_health_check["/app/test.bin"] = time.time() - 100
        assert pool._maybe_health_check("/app/test.bin", mock_r2) is True


class TestR2ConnectionPoolEviction:
    """Tests for connection eviction."""

    def test_evict_oldest_connection(self):
        """Should evict oldest connection."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/old.bin"] = mock_r2
        pool._evict_oldest_connection()
        assert "/app/old.bin" not in pool._pool
        mock_r2.quit.assert_called_once()
        assert pool._stats["connections_evicted"] == 1

    def test_evict_oldest_quit_error(self):
        """Should handle quit error gracefully."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.quit = MagicMock(side_effect=RuntimeError("fail"))
        pool._pool["/app/old.bin"] = mock_r2
        pool._evict_oldest_connection()
        assert "/app/old.bin" not in pool._pool

    def test_remove_connection_unsafe(self):
        """Should remove connection and clean state."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_access["/app/test.bin"] = time.time()
        pool._last_health_check["/app/test.bin"] = time.time()
        pool._analyzed_files.add("/app/test.bin")
        pool._remove_connection_unsafe("/app/test.bin")
        assert "/app/test.bin" not in pool._pool
        assert "/app/test.bin" not in pool._last_access
        assert "/app/test.bin" not in pool._analyzed_files

    def test_cleanup_connection_state(self):
        """Should clean all auxiliary state."""
        pool = R2ConnectionPool()
        pool._last_access["/app/test.bin"] = time.time()
        pool._last_health_check["/app/test.bin"] = time.time()
        pool._analyzed_files.add("/app/test.bin")
        pool._cleanup_connection_state("/app/test.bin")
        assert "/app/test.bin" not in pool._last_access
        assert "/app/test.bin" not in pool._last_health_check
        assert "/app/test.bin" not in pool._analyzed_files


class TestR2ConnectionPoolGetConnection:
    """Tests for connection acquisition."""

    def test_r2pipe_not_installed(self):
        """Should raise ImportError when r2pipe missing."""
        pool = R2ConnectionPool()
        with patch.object(r2_pool_mod, "r2pipe", None):
            with pytest.raises(ImportError, match="r2pipe is not installed"):
                pool.get_connection("/app/test.bin")

    def test_cache_hit(self):
        """Should return cached connection."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="0x0")
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            result = pool.get_connection("/app/test.bin")
            assert result is mock_r2
            assert pool._stats["cache_hits"] == 1

    def test_cache_miss_creates_new(self):
        """Should create new connection on cache miss."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        with patch.object(r2_pool_mod, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open = MagicMock(return_value=mock_r2)
            result = pool.get_connection("/app/test.bin")
            assert result is mock_r2
            assert pool._stats["cache_misses"] == 1
            assert pool._stats["connections_created"] == 1

    def test_eviction_when_full(self):
        """Should evict oldest when pool full."""
        pool = R2ConnectionPool(max_connections=1)
        old_r2 = MagicMock()
        new_r2 = MagicMock()
        pool._pool["/app/old.bin"] = old_r2
        with patch.object(r2_pool_mod, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open = MagicMock(return_value=new_r2)
            pool.get_connection("/app/new.bin")
        assert "/app/old.bin" not in pool._pool
        assert "/app/new.bin" in pool._pool

    def test_stale_connection_reconnect(self):
        """Should reconnect on stale connection."""
        pool = R2ConnectionPool(health_check_interval=0)
        old_r2 = MagicMock()
        old_r2.cmd = MagicMock(side_effect=RuntimeError("stale"))
        new_r2 = MagicMock()
        pool._pool["/app/test.bin"] = old_r2
        with patch.object(r2_pool_mod, "r2pipe") as mock_r2pipe:
            mock_r2pipe.open = MagicMock(return_value=new_r2)
            result = pool.get_connection("/app/test.bin")
            assert result is new_r2


class TestR2ConnectionPoolExecute:
    """Tests for command execution."""

    def test_execute_success(self):
        """Should execute command successfully."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="result")
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            result = pool.execute("/app/test.bin", "pdf")
            assert result == "result"

    def test_execute_retry_on_failure(self):
        """Should retry on command failure."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(side_effect=[RuntimeError("fail"), "success"])
        with patch.object(pool, "get_connection", return_value=mock_r2):
            result = pool.execute("/app/test.bin", "pdf")
            assert result == "success"
            assert pool._stats["reconnections"] == 1

    def test_execute_retry_fails(self):
        """Should raise when retry also fails."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(side_effect=RuntimeError("fail"))
        with patch.object(pool, "get_connection", return_value=mock_r2):
            with pytest.raises(RuntimeError):
                pool.execute("/app/test.bin", "pdf")


class TestR2ConnectionPoolAsync:
    """Tests for async operations."""

    @pytest.mark.asyncio
    async def test_execute_async(self):
        """Should execute asynchronously."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        mock_r2.cmd = MagicMock(return_value="async result")
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            result = await pool.execute_async("/app/test.bin", "pdf")
            assert result == "async result"

    @pytest.mark.asyncio
    async def test_async_session(self):
        """Should provide async context manager."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            async with pool.async_session("/app/test.bin") as r2:
                assert r2 is mock_r2

    @pytest.mark.asyncio
    async def test_async_session_error_invalidates(self):
        """Should invalidate connection on session error."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            with pytest.raises(RuntimeError):
                async with pool.async_session("/app/test.bin"):
                    raise RuntimeError("session error")
        assert "/app/test.bin" not in pool._pool


class TestR2ConnectionPoolSyncSession:
    """Tests for sync session context manager."""

    def test_sync_session(self):
        """Should provide sync context manager."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            with pool.sync_session("/app/test.bin") as r2:
                assert r2 is mock_r2

    def test_sync_session_error(self):
        """Should remove connection on session error."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool._last_health_check["/app/test.bin"] = time.time()
        with patch.object(r2_pool_mod, "r2pipe"):
            with pytest.raises(RuntimeError):
                with pool.sync_session("/app/test.bin"):
                    raise RuntimeError("session error")
        assert "/app/test.bin" not in pool._pool


class TestR2ConnectionPoolLifecycle:
    """Tests for pool lifecycle management."""

    def test_close_all(self):
        """Should close all connections."""
        pool = R2ConnectionPool()
        r1 = MagicMock()
        r2 = MagicMock()
        pool._pool["/app/a.bin"] = r1
        pool._pool["/app/b.bin"] = r2
        pool._last_access["/app/a.bin"] = time.time()
        pool._analyzed_files.add("/app/a.bin")
        pool.close_all()
        assert len(pool._pool) == 0
        assert len(pool._last_access) == 0
        assert len(pool._analyzed_files) == 0
        r1.quit.assert_called_once()
        r2.quit.assert_called_once()

    def test_close_all_quit_error(self):
        """Should handle quit errors during close_all."""
        pool = R2ConnectionPool()
        r1 = MagicMock()
        r1.quit = MagicMock(side_effect=RuntimeError("fail"))
        pool._pool["/app/a.bin"] = r1
        pool.close_all()
        assert len(pool._pool) == 0


class TestR2ConnectionPoolAnalyzed:
    """Tests for analyzed file tracking."""

    def test_is_analyzed_false(self):
        """Should return False for unanalyzed file."""
        pool = R2ConnectionPool()
        assert pool.is_analyzed("/app/test.bin") is False

    def test_is_analyzed_true(self):
        """Should return True after marking."""
        pool = R2ConnectionPool()
        mock_r2 = MagicMock()
        pool._pool["/app/test.bin"] = mock_r2
        pool.mark_analyzed("/app/test.bin")
        assert pool.is_analyzed("/app/test.bin") is True

    def test_mark_analyzed_no_pool(self):
        """Should not mark if not in pool."""
        pool = R2ConnectionPool()
        pool.mark_analyzed("/app/test.bin")
        assert pool.is_analyzed("/app/test.bin") is False


class TestR2ConnectionPoolStats:
    """Tests for statistics."""

    def test_get_stats(self):
        """Should return current statistics."""
        pool = R2ConnectionPool(max_connections=5)
        pool._stats["connections_created"] = 3
        pool._stats["cache_hits"] = 10
        pool._pool["/app/test.bin"] = MagicMock()
        pool._analyzed_files.add("/app/test.bin")
        stats = pool.get_stats()
        assert stats["connections_created"] == 3
        assert stats["cache_hits"] == 10
        assert stats["current_connections"] == 1
        assert stats["max_connections"] == 5
        assert stats["analyzed_files"] == 1

    def test_get_stats_thread_safe(self):
        """Should acquire lock when getting stats."""
        pool = R2ConnectionPool()
        stats = pool.get_stats()
        assert "connections_created" in stats
