"""Unit tests for server_lifespan lifecycle and reliability (Issue #266)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP

from reversecore_mcp.server import server_lifespan


@pytest.fixture
def mock_server():
    return FastMCP("TestReversecoreServer", lifespan=server_lifespan)


class TestServerLifespanReliability:
    """Tests for Issue #266: Run server lifespan cleanup from finally when startup or serving raises."""

    @pytest.mark.asyncio
    async def test_normal_shutdown_cleans_all_resources(self, mock_server, tmp_path):
        """Normal execution through yield unwinds all resources."""
        mock_rm = AsyncMock()
        mock_memory_store = AsyncMock()

        with (
            patch("reversecore_mcp.core.config.get_config") as mock_cfg,
            patch("reversecore_mcp.server.resource_manager", mock_rm),
            patch(
                "reversecore_mcp.core.memory.initialize_memory_store",
                new_callable=AsyncMock,
            ),
            patch(
                "reversecore_mcp.core.memory.get_memory_store",
                return_value=mock_memory_store,
            ),
            patch(
                "reversecore_mcp.core.task_queue.get_arq_pool",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "reversecore_mcp.core.analysis_cache.close_redis", new_callable=AsyncMock
            ) as mock_close_redis,
            patch("reversecore_mcp.core.container.get_r2_pool") as mock_get_r2_pool,
        ):
            mock_cfg.return_value.workspace = tmp_path / "workspace"
            mock_cfg.return_value.memory_db_path = tmp_path / "memory.db"
            mock_pool = MagicMock()
            mock_get_r2_pool.return_value = mock_pool

            async with server_lifespan(mock_server):
                mock_rm.start.assert_called_once()

            # Shutdown in finally:
            mock_rm.stop.assert_called_once()
            mock_memory_store.close.assert_called_once()
            mock_close_redis.assert_called_once()
            mock_pool.close_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_exception_in_serving_body_triggers_full_cleanup(self, mock_server, tmp_path):
        """When serving raises an exception, finally block executes and shuts down all started resources."""
        mock_rm = AsyncMock()
        mock_memory_store = AsyncMock()

        with (
            patch("reversecore_mcp.core.config.get_config") as mock_cfg,
            patch("reversecore_mcp.server.resource_manager", mock_rm),
            patch(
                "reversecore_mcp.core.memory.initialize_memory_store",
                new_callable=AsyncMock,
            ),
            patch(
                "reversecore_mcp.core.memory.get_memory_store",
                return_value=mock_memory_store,
            ),
            patch(
                "reversecore_mcp.core.task_queue.get_arq_pool",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "reversecore_mcp.core.analysis_cache.close_redis", new_callable=AsyncMock
            ) as mock_close_redis,
            patch("reversecore_mcp.core.container.get_r2_pool") as mock_get_r2_pool,
        ):
            mock_cfg.return_value.workspace = tmp_path / "workspace"
            mock_cfg.return_value.memory_db_path = tmp_path / "memory.db"
            mock_pool = MagicMock()
            mock_get_r2_pool.return_value = mock_pool

            with pytest.raises(RuntimeError, match="Crash inside server body"):
                async with server_lifespan(mock_server):
                    raise RuntimeError("Crash inside server body")

            # Must still execute cleanup despite exception
            mock_rm.stop.assert_called_once()
            mock_memory_store.close.assert_called_once()
            mock_close_redis.assert_called_once()
            mock_pool.close_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_exception_during_late_startup_unwinds_started_resources(
        self, mock_server, tmp_path
    ):
        """If startup fails after resource_manager.start() (e.g. at memory init), resource_manager is stopped."""
        mock_rm = AsyncMock()

        with (
            patch("reversecore_mcp.core.config.get_config") as mock_cfg,
            patch("reversecore_mcp.server.resource_manager", mock_rm),
            patch(
                "reversecore_mcp.core.memory.initialize_memory_store",
                new_callable=AsyncMock,
                side_effect=RuntimeError("Memory store DB fatal corruption"),
            ),
            patch(
                "reversecore_mcp.core.task_queue.get_arq_pool",
                new_callable=AsyncMock,
                side_effect=RuntimeError("Redis connection refused during startup"),
            ),
        ):
            mock_cfg.return_value.workspace = tmp_path / "workspace"
            mock_cfg.return_value.memory_db_path = tmp_path / "memory.db"

            with pytest.raises(RuntimeError, match="Redis connection refused"):
                async with server_lifespan(mock_server):
                    pass

            # Resource manager was started, so it must be stopped in finally
            mock_rm.start.assert_called_once()
            mock_rm.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_reenter_lifespan_after_failed_run(self, mock_server, tmp_path):
        """Can re-enter the lifespan context after an earlier failure without leaked resources."""
        mock_rm = AsyncMock()
        mock_memory_store = AsyncMock()

        with (
            patch("reversecore_mcp.core.config.get_config") as mock_cfg,
            patch("reversecore_mcp.server.resource_manager", mock_rm),
            patch(
                "reversecore_mcp.core.memory.initialize_memory_store",
                new_callable=AsyncMock,
            ),
            patch(
                "reversecore_mcp.core.memory.get_memory_store",
                return_value=mock_memory_store,
            ),
            patch(
                "reversecore_mcp.core.task_queue.get_arq_pool",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch("reversecore_mcp.core.analysis_cache.close_redis", new_callable=AsyncMock),
            patch("reversecore_mcp.core.container.get_r2_pool"),
        ):
            mock_cfg.return_value.workspace = tmp_path / "workspace"
            mock_cfg.return_value.memory_db_path = tmp_path / "memory.db"

            # 1. First run fails
            with pytest.raises(ValueError):
                async with server_lifespan(mock_server):
                    raise ValueError("First run failed")

            assert mock_rm.stop.call_count == 1

            # 2. Second run succeeds cleanly
            async with server_lifespan(mock_server):
                pass

            assert mock_rm.start.call_count == 2
            assert mock_rm.stop.call_count == 2
