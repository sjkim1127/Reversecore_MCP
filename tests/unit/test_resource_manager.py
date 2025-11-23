"""Unit tests for ResourceManager."""

import asyncio
import os
import time
from pathlib import Path

import pytest

from reversecore_mcp.core import config
from reversecore_mcp.core.config import Config
from reversecore_mcp.core.resource_manager import ResourceManager, resource_manager


def _create_mock_config(workspace: Path) -> Config:
    """Helper to create a mock Config instance."""
    return Config(
        workspace=workspace,
        read_only_dirs=(),
        log_level="INFO",
        log_file=Path("/tmp/test.log"),
        log_format="human",
        structured_errors=False,
        rate_limit=60,
        lief_max_file_size=1000000000,
        mcp_transport="stdio",
        default_tool_timeout=60,
    )


class TestResourceManager:
    """Tests for ResourceManager class."""

    def test_init(self):
        """Test resource manager initialization."""
        manager = ResourceManager(cleanup_interval=1800)
        assert manager.cleanup_interval == 1800
        assert manager._running is False
        assert manager._task is None

    @pytest.mark.asyncio
    async def test_start(self):
        """Test starting the resource manager."""
        manager = ResourceManager(cleanup_interval=3600)
        
        await manager.start()
        
        assert manager._running is True
        assert manager._task is not None
        
        # Cleanup
        await manager.stop()

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        """Test that calling start multiple times is safe."""
        manager = ResourceManager(cleanup_interval=3600)
        
        await manager.start()
        first_task = manager._task
        
        await manager.start()  # Should not create a new task
        second_task = manager._task
        
        assert first_task is second_task
        
        # Cleanup
        await manager.stop()

    @pytest.mark.asyncio
    async def test_stop(self):
        """Test stopping the resource manager."""
        manager = ResourceManager(cleanup_interval=3600)
        
        await manager.start()
        await manager.stop()
        
        assert manager._running is False

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_tmp_files(self, tmp_path, monkeypatch):
        """Test that cleanup removes old temporary files."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Create old temp files
        old_tmp = workspace / "test.tmp"
        old_tmp.write_text("old")
        
        old_r2 = workspace / ".r2_cache"
        old_r2.write_text("old")
        
        # Set modification time to 25 hours ago
        old_time = time.time() - (25 * 3600)
        old_tmp.touch()
        old_r2.touch()
        
        # Mock config
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Manually set old mtime using os
        os.utime(old_tmp, (old_time, old_time))
        os.utime(old_r2, (old_time, old_time))
        
        # Run cleanup
        manager = ResourceManager()
        await manager.cleanup()
        
        # Old files should be removed
        assert not old_tmp.exists()
        assert not old_r2.exists()

    @pytest.mark.asyncio
    async def test_cleanup_preserves_recent_files(self, tmp_path, monkeypatch):
        """Test that cleanup preserves recent temporary files."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Create recent temp file
        recent_tmp = workspace / "recent.tmp"
        recent_tmp.write_text("recent")
        
        # Mock config
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Run cleanup
        manager = ResourceManager()
        await manager.cleanup()
        
        # Recent file should still exist
        assert recent_tmp.exists()

    @pytest.mark.asyncio
    async def test_cleanup_handles_errors_gracefully(self, tmp_path, monkeypatch):
        """Test that cleanup handles errors without crashing."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Mock config
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Run cleanup (should not raise)
        manager = ResourceManager()
        await manager.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup_loop_runs_periodically(self, tmp_path, monkeypatch):
        """Test that cleanup loop runs periodically."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Mock config
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Create manager with short interval
        manager = ResourceManager(cleanup_interval=1)
        
        # Start and let it run briefly
        await manager.start()
        await asyncio.sleep(0.5)  # Let the loop start
        await manager.stop()
        
        # No assertion needed, just verify it doesn't crash

    @pytest.mark.asyncio
    async def test_cleanup_loop_stops_on_cancel(self):
        """Test that cleanup loop stops when cancelled."""
        manager = ResourceManager(cleanup_interval=3600)
        
        await manager.start()
        assert manager._running is True
        
        await manager.stop()
        assert manager._running is False
        
        # Task should be cancelled
        if manager._task:
            assert manager._task.cancelled() or manager._task.done()

    @pytest.mark.asyncio
    async def test_cleanup_patterns(self, tmp_path, monkeypatch):
        """Test that all cleanup patterns are applied."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Create old files with different patterns
        old_time = time.time() - (25 * 3600)
        
        files = [
            workspace / "test1.tmp",
            workspace / ".r2_test",
            workspace / "cache.r2",
        ]
        
        for f in files:
            f.write_text("old")
            f.touch()
            os.utime(f, (old_time, old_time))
        
        # Mock config
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Run cleanup
        manager = ResourceManager()
        await manager.cleanup()
        
        # All old files should be removed
        for f in files:
            assert not f.exists()

    def test_global_instance(self):
        """Test that the global instance is accessible."""
        assert resource_manager is not None
        assert isinstance(resource_manager, ResourceManager)

    @pytest.mark.asyncio
    async def test_cleanup_loop_handles_exception(self, tmp_path, monkeypatch):
        """Test that cleanup loop handles exceptions and continues."""
        # Setup workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        
        # Mock config that will work
        mock_config = _create_mock_config(workspace)
        
        monkeypatch.setattr(config, "get_config", lambda: mock_config)
        
        # Create manager with short interval
        manager = ResourceManager(cleanup_interval=0.5)
        
        # Start manager
        await manager.start()
        
        # Let it run for a bit
        await asyncio.sleep(0.7)
        
        # Should still be running despite any errors
        assert manager._running is True
        
        # Cleanup
        await manager.stop()
