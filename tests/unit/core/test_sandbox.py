"""Unit tests for the sandbox execution engine."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.execution import (
    SandboxExecutor,
    execute_subprocess_async,
    is_in_container,
)


class TestContainerDetection:
    """Test is_in_container detection logic."""

    def test_dockerenv_exists(self):
        """Should return True if /.dockerenv exists."""
        with patch("os.path.exists", return_value=True) as mock_exists:
            assert is_in_container() is True
            mock_exists.assert_called_once_with("/.dockerenv")

    def test_cgroup_contains_docker(self):
        """Should return True if /.dockerenv doesn't exist but cgroup has docker."""
        with (
            patch("os.path.exists", return_value=False),
            patch("builtins.open", new_callable=MagicMock) as mock_open,
        ):
            mock_file = MagicMock()
            mock_file.read.return_value = "1:name=systemd:/docker/123456abcdef"
            mock_open.return_value.__enter__.return_value = mock_file

            assert is_in_container() is True

    def test_cgroup_contains_kubepods(self):
        """Should return True if cgroup has kubepods."""
        with (
            patch("os.path.exists", return_value=False),
            patch("builtins.open", new_callable=MagicMock) as mock_open,
        ):
            mock_file = MagicMock()
            mock_file.read.return_value = "1:name=systemd:/kubepods/besteffort/pod123"
            mock_open.return_value.__enter__.return_value = mock_file

            assert is_in_container() is True

    def test_cgroup_other_content(self):
        """Should return False if cgroup does not contain container substrings."""
        with (
            patch("os.path.exists", return_value=False),
            patch("builtins.open", new_callable=MagicMock) as mock_open,
        ):
            mock_file = MagicMock()
            mock_file.read.return_value = "1:name=systemd:/"
            mock_open.return_value.__enter__.return_value = mock_file

            assert is_in_container() is False

    def test_os_error_handling(self):
        """Should return False if cgroup open throws error."""
        with (
            patch("os.path.exists", return_value=False),
            patch("builtins.open", side_effect=OSError),
        ):
            assert is_in_container() is False


class TestSandboxExecutorWrapCmd:
    """Test SandboxExecutor command wrapping under various modes."""

    def test_sandbox_disabled(self, patched_config):
        """Should return original command when sandbox is disabled."""
        patched_config._settings.sandbox_enabled = False
        cmd = ["yara", "rules.yar", "file.bin"]
        assert SandboxExecutor.wrap_cmd(cmd) == cmd

    def test_sandbox_mode_disabled(self, patched_config):
        """Should return original command when sandbox mode is disabled."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "disabled"
        cmd = ["yara", "rules.yar", "file.bin"]
        assert SandboxExecutor.wrap_cmd(cmd) == cmd

    def test_host_mode_docker_not_available(self, patched_config):
        """Should log warning and return original command if docker command is missing in PATH."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "host"

        with (
            patch("shutil.which", return_value=None),
            patch("reversecore_mcp.core.execution.logger.warning") as mock_warn,
        ):
            cmd = ["yara", "rules.yar", "file.bin"]
            assert SandboxExecutor.wrap_cmd(cmd) == cmd
            mock_warn.assert_called_once()

    def test_host_mode_success(self, patched_config):
        """Should generate docker run command with resource limits and path mounts."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "host"
        patched_config._settings.sandbox_docker_image = "test-sandbox:latest"
        patched_config._settings.sandbox_cpu_limit = 2.0
        patched_config._settings.sandbox_memory_limit = "1g"
        patched_config._settings.sandbox_pids_limit = 50

        # Workspace configuration
        ws = Path("/my/ws")
        patched_config._settings.workspace = ws
        patched_config._settings.read_dirs = "/my/rules,/my/other"

        # Cache exists mock
        with (
            patch("shutil.which", return_value="/usr/bin/docker"),
            patch.object(Path, "exists", return_value=True),
        ):
            cmd = ["yara", "rules.yar", "file.bin"]
            wrapped = SandboxExecutor.wrap_cmd(cmd)

            # Check basic structure
            assert wrapped[0] == "docker"
            assert wrapped[1] == "run"
            assert "--rm" in wrapped
            assert "--network" in wrapped
            assert "none" in wrapped

            # Check mounts
            assert "-v" in wrapped
            assert f"{ws}:{ws}:ro" in wrapped
            assert f"{ws}/.cache:{ws}/.cache:rw" in wrapped
            for rd in patched_config.read_only_dirs:
                assert f"{rd}:{rd}:ro" in wrapped

            # Check limits
            assert "--cpus" in wrapped
            assert "2.0" in wrapped
            assert "--memory" in wrapped
            assert "1g" in wrapped
            assert "--pids-limit" in wrapped
            assert "50" in wrapped

            # Target image and command
            assert wrapped[-4] == "test-sandbox:latest"
            assert wrapped[-3:] == cmd

    def test_container_mode_capsh_available(self, patched_config):
        """Should wrap command with capsh in container mode."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "container"
        patched_config._settings.sandbox_user = "sandbox_user"

        with (
            patch("shutil.which", side_effect=lambda x: "/usr/bin/capsh" if x == "capsh" else None),
            patch("reversecore_mcp.core.execution.is_in_container", return_value=True),
        ):
            cmd = ["yara", "rules.yar", "file.bin"]
            wrapped = SandboxExecutor.wrap_cmd(cmd)

            assert wrapped[0] == "capsh"
            assert wrapped[1] == "--user=sandbox_user"
            assert wrapped[2] == "--drop=all"
            assert wrapped[3] == "--"
            assert wrapped[4:] == cmd

    def test_container_mode_capsh_not_available(self, patched_config):
        """Should return original command if capsh is not available."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "container"

        with (
            patch("shutil.which", return_value=None),
            patch("reversecore_mcp.core.execution.is_in_container", return_value=True),
        ):
            cmd = ["yara", "rules.yar", "file.bin"]
            wrapped = SandboxExecutor.wrap_cmd(cmd)
            assert wrapped == cmd


class TestExecuteSubprocessAsyncSandbox:
    """Test integration of SandboxExecutor inside execute_subprocess_async."""

    @pytest.mark.asyncio
    async def test_sandbox_enabled_container_mode_capsh_missing_user_kwargs(self, patched_config):
        """Should pass 'user' kwargs to asyncio.create_subprocess_exec when capsh is missing on Unix."""
        patched_config._settings.sandbox_enabled = True
        patched_config._settings.sandbox_mode = "container"
        patched_config._settings.sandbox_user = "nobody"

        mock_process = AsyncMock()
        mock_process.stdout.read = AsyncMock(side_effect=[b"output", b""])
        mock_process.stderr.read = AsyncMock(return_value=b"")
        mock_process.wait = AsyncMock(return_value=0)
        mock_process.returncode = 0

        from reversecore_mcp.core.resource_manager import ResourceManager

        with (
            patch("sys.platform", "linux"),
            patch("shutil.which", return_value=None),  # capsh missing
            patch("reversecore_mcp.core.execution.is_in_container", return_value=True),
            patch("asyncio.create_subprocess_exec", return_value=mock_process) as mock_exec,
            patch.object(ResourceManager, "track_pid"),
        ):
            cmd = ["yara", "rules.yar", "file.bin"]
            await execute_subprocess_async(cmd)

            # verify it was called with original command (as capsh is missing) but user kwarg
            mock_exec.assert_called_once_with(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                user="nobody",
            )
