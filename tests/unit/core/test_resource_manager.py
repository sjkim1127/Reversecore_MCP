"""Unit tests for ResourceManager."""

import asyncio
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.core import config
from reversecore_mcp.core.config import Config
from reversecore_mcp.core.resource_manager import ResourceManager, resource_manager

resource_manager_mod = sys.modules["reversecore_mcp.core.resource_manager"]


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
    async def test_cleanup_stale_temp_extraction_dirs(self, tmp_path, monkeypatch):
        """Test cleaning up stale extraction directories in workspace/tmp."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        ws_tmp = workspace / "tmp"
        ws_tmp.mkdir()

        stale_extract_dir = ws_tmp / "binwalk_extract_old123"
        stale_extract_dir.mkdir()
        (stale_extract_dir / "extracted_data.bin").write_bytes(b"\x00" * 50)
        old_time = time.time() - (25 * 3600)
        os.utime(stale_extract_dir, (old_time, old_time))

        recent_extract_dir = ws_tmp / "binwalk_extract_new456"
        recent_extract_dir.mkdir()

        mock_config = _create_mock_config(workspace)
        monkeypatch.setattr(config, "get_config", lambda: mock_config)

        manager = ResourceManager()
        await manager.cleanup()

        assert not stale_extract_dir.exists()
        assert recent_extract_dir.exists()

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

    @pytest.mark.skipif(sys.platform == "win32", reason="waitpid behavior differs on Windows")
    def test_reap_zombies_child_process_error(self):
        """_reap_zombies handles ChildProcessError and removes PID from tracked."""
        manager = ResourceManager()
        manager._tracked_pids.add(99999)
        with patch.object(
            resource_manager_mod,
            "waitpid",
            side_effect=ChildProcessError,
        ):
            manager._reap_zombies()
        assert 99999 not in manager._tracked_pids

    @pytest.mark.skipif(sys.platform == "win32", reason="waitpid behavior differs on Windows")
    def test_reap_zombies_generic_exception(self):
        """_reap_zombies handles generic Exception for a PID and does not crash."""
        manager = ResourceManager()
        manager._tracked_pids.add(88888)
        with patch.object(
            resource_manager_mod,
            "waitpid",
            side_effect=PermissionError("denied"),
        ):
            manager._reap_zombies()
        assert manager._tracked_pids <= {88888}

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
        manager = ResourceManager(cleanup_interval=0.1)

        # Start manager with mocked cleanup that raises an exception to cover lines 72-73
        with patch.object(manager, "cleanup", side_effect=Exception("cleanup fail")):
            await manager.start()
            await asyncio.sleep(0.3)
            assert manager._running is True
            await manager.stop()

    @pytest.mark.skipif(sys.platform == "win32", reason="waitpid behavior differs on Windows")
    def test_reap_zombies_successful_reap(self):
        """Test _reap_zombies successfully reaps a tracked zombie PID."""
        manager = ResourceManager()
        # Track a dummy PID using the track_pid method to cover line 40
        manager.track_pid(12345)
        assert 12345 in manager._tracked_pids

        # Mock waitpid to return the PID (as if it was a zombie and successfully reaped)
        with patch.object(resource_manager_mod, "waitpid", return_value=(12345, 0)):
            manager._reap_zombies()

        # The PID should have been removed from tracked
        assert 12345 not in manager._tracked_pids

    def test_reap_zombies_empty_tracked(self):
        """Test _reap_zombies returns early when tracked_pids is empty."""
        manager = ResourceManager()
        with patch.object(resource_manager_mod, "waitpid") as mock_waitpid:
            manager._reap_zombies()
            mock_waitpid.assert_not_called()

    @pytest.mark.asyncio
    async def test_pid_check_loop_handles_exception(self):
        """Test that _pid_check_loop handles exceptions and continues running."""
        manager = ResourceManager(pid_check_interval=0.1)

        # Mock _reap_zombies to raise an Exception
        with patch.object(manager, "_reap_zombies", side_effect=Exception("reap failure")):
            await manager.start()
            await asyncio.sleep(0.2)
            assert manager._running is True
            await manager.stop()

    @pytest.mark.asyncio
    async def test_cleanup_handles_unlink_exception(self, tmp_path, monkeypatch):
        """Test that cleanup logs a warning if a temp file deletion throws an exception."""
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        old_tmp = workspace / "failed_delete.tmp"
        old_tmp.write_text("old")

        # Set mtime to 25 hours ago
        old_time = time.time() - (25 * 3600)
        old_tmp.touch()
        os.utime(old_tmp, (old_time, old_time))

        mock_config = _create_mock_config(workspace)
        monkeypatch.setattr(config, "get_config", lambda: mock_config)

        # Mock Path.unlink to raise OSError
        with patch("pathlib.Path.unlink", side_effect=OSError("Permission denied")):
            manager = ResourceManager()
            # Should not raise exception
            await manager.cleanup()
            assert old_tmp.exists()

    @pytest.mark.asyncio
    async def test_cleanup_handles_general_exception(self, monkeypatch):
        """Test that cleanup handles general exceptions (e.g. config error) and completes."""

        def mock_get_config_fail():
            raise Exception("Config load failure")

        monkeypatch.setattr(config, "get_config", mock_get_config_fail)
        manager = ResourceManager()
        # Should not raise exception
        await manager.cleanup()
