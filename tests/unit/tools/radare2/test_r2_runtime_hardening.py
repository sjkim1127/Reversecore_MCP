from __future__ import annotations

import asyncio
import inspect
import re
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.radare2 import r2_analysis, radare2_mcp_tools
from reversecore_mcp.tools.radare2.radare2_mcp_tools import Radare2ToolsPlugin


class FakeSession:
    def __init__(self, session_id: str = "fake") -> None:
        self.session_id = session_id
        self.is_open = True
        self.closed = False
        self.active = 0
        self.max_active = 0
        self.thread_ids: list[int] = []

    def cmd(self, command: str) -> str:
        self.thread_ids.append(threading.get_ident())
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        time.sleep(0.03)
        self.active -= 1
        return command

    def analyze(self, level: int) -> int:
        self.thread_ids.append(threading.get_ident())
        return level

    def close(self) -> None:
        self.closed = True
        self.is_open = False


@pytest.mark.asyncio
async def test_session_commands_run_off_loop_and_serialize() -> None:
    plugin = Radare2ToolsPlugin()
    session = FakeSession()
    loop_thread = threading.get_ident()

    results = await asyncio.gather(
        plugin._run_session_cmd(session, "iI"),
        plugin._run_session_cmd(session, "afl"),
    )

    assert results == ["iI", "afl"]
    assert session.max_active == 1
    assert all(thread_id != loop_thread for thread_id in session.thread_ids)


@pytest.mark.asyncio
async def test_idle_sessions_are_closed_and_removed() -> None:
    plugin = Radare2ToolsPlugin()
    session = FakeSession("stale")
    plugin._sessions[session.session_id] = session
    plugin._file_to_session["/tmp/stale"] = session.session_id
    plugin._session_locks[session.session_id] = asyncio.Lock()
    plugin._session_last_used[session.session_id] = time.monotonic() - 100
    plugin._session_idle_ttl = 30
    plugin._max_sessions = 8

    async with plugin._lock:
        await plugin._evict_stale_sessions_locked()

    assert session.closed is True
    assert plugin._sessions == {}
    assert plugin._file_to_session == {}


@pytest.mark.asyncio
async def test_extension_mutated_path_is_revalidated(monkeypatch) -> None:
    registry = MagicMock()
    registry.run_r2_pre_hooks = AsyncMock(return_value=("/unsafe/path", "iI"))
    monkeypatch.setattr(r2_analysis, "get_extension_registry", lambda: registry)
    path_validator = MagicMock(side_effect=ValidationError("path rejected"))
    monkeypatch.setattr(r2_analysis, "validate_file_path", path_validator)

    with pytest.raises(ValidationError, match="path rejected"):
        await r2_analysis._apply_validated_r2_pre_hooks("/safe/path", "iI")

    path_validator.assert_called_once_with("/unsafe/path")


@pytest.mark.asyncio
async def test_extension_mutated_command_is_revalidated(monkeypatch) -> None:
    registry = MagicMock()
    registry.run_r2_pre_hooks = AsyncMock(return_value=("/safe/path", "!sh"))
    monkeypatch.setattr(r2_analysis, "get_extension_registry", lambda: registry)
    monkeypatch.setattr(r2_analysis, "validate_file_path", lambda value: Path(value))
    command_validator = MagicMock(side_effect=ValidationError("command rejected"))
    monkeypatch.setattr(r2_analysis, "validate_r2_command", command_validator)

    with pytest.raises(ValidationError, match="command rejected"):
        await r2_analysis._apply_validated_r2_pre_hooks("/safe/path", "iI")

    command_validator.assert_called_once_with("!sh")


def test_awaited_session_results_are_materialized_before_string_methods() -> None:
    source = inspect.getsource(radare2_mcp_tools)
    unsafe_chain = re.compile(r"(?<!\()await self\._run_session_cmd\([^\n]+?\)\.[A-Za-z_]")
    assert unsafe_chain.search(source) is None
