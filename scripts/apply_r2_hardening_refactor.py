#!/usr/bin/env python3
"""One-shot source transformer for the Radare2 async/session hardening PR."""

from __future__ import annotations

from pathlib import Path

import libcst as cst
import libcst.matchers as m


ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative_path: str, old: str, new: str) -> None:
    path = ROOT / relative_path
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(
            f"{relative_path}: expected exactly one replacement, found {count}: {old[:100]!r}"
        )
    path.write_text(text.replace(old, new, 1))


def patch_config() -> None:
    replace_once(
        "reversecore_mcp/core/config.py",
        "    r2_pool_timeout: int = Field(\n"
        "        default=30,\n"
        "        ge=5,\n"
        "        le=300,\n"
        "        description=\"Timeout for acquiring radare2 connection from pool\",\n"
        "    )\n",
        "    r2_pool_timeout: int = Field(\n"
        "        default=30,\n"
        "        ge=5,\n"
        "        le=300,\n"
        "        description=\"Timeout for acquiring radare2 connection from pool\",\n"
        "    )\n"
        "    r2_session_max: int = Field(\n"
        "        default=8,\n"
        "        ge=1,\n"
        "        le=64,\n"
        "        description=\"Maximum number of persistent Radare2 file sessions\",\n"
        "    )\n"
        "    r2_session_idle_ttl: int = Field(\n"
        "        default=900,\n"
        "        ge=30,\n"
        "        le=86_400,\n"
        "        description=\"Idle seconds before a Radare2 session is closed\",\n"
        "    )\n",
    )
    replace_once(
        "reversecore_mcp/core/config.py",
        "    def r2_pool_timeout(self) -> int:\n"
        "        return self._settings.r2_pool_timeout\n",
        "    def r2_pool_timeout(self) -> int:\n"
        "        return self._settings.r2_pool_timeout\n\n"
        "    @property\n"
        "    def r2_session_max(self) -> int:\n"
        "        return self._settings.r2_session_max\n\n"
        "    @property\n"
        "    def r2_session_idle_ttl(self) -> int:\n"
        "        return self._settings.r2_session_idle_ttl\n",
    )
    replace_once(
        ".env.example",
        "# Connection acquisition timeout in seconds (default: 30).\n"
        "# REVERSECORE_R2_POOL_TIMEOUT=30\n",
        "# Connection acquisition timeout in seconds (default: 30).\n"
        "# REVERSECORE_R2_POOL_TIMEOUT=30\n\n"
        "# Maximum number of persistent file-backed Radare2 sessions (default: 8).\n"
        "# REVERSECORE_R2_SESSION_MAX=8\n\n"
        "# Close idle Radare2 sessions after this many seconds (default: 900).\n"
        "# REVERSECORE_R2_SESSION_IDLE_TTL=900\n",
    )
    replace_once(
        "docker-compose.yml",
        "    - REVERSECORE_STRICT_PATHS=true\n    - PYTHONDONTWRITEBYTECODE=1\n",
        "    - REVERSECORE_STRICT_PATHS=true\n"
        "    - REVERSECORE_R2_SESSION_MAX=${REVERSECORE_R2_SESSION_MAX:-8}\n"
        "    - REVERSECORE_R2_SESSION_IDLE_TTL=${REVERSECORE_R2_SESSION_IDLE_TTL:-900}\n"
        "    - PYTHONDONTWRITEBYTECODE=1\n",
    )


class SessionCallTransformer(cst.CSTTransformer):
    """Await blocking R2Session calls through plugin worker-thread helpers."""

    def leave_FunctionDef(
        self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef
    ) -> cst.FunctionDef:
        if updated_node.name.value == "_ensure_analyzed":
            return updated_node.with_changes(asynchronous=cst.Asynchronous())
        return updated_node

    def leave_Call(
        self, original_node: cst.Call, updated_node: cst.Call
    ) -> cst.BaseExpression:
        if m.matches(
            updated_node.func,
            m.Attribute(value=m.Name("session"), attr=m.Name("cmd")),
        ):
            return cst.Await(
                cst.Call(
                    func=cst.Attribute(
                        value=cst.Name("self"), attr=cst.Name("_run_session_cmd")
                    ),
                    args=[cst.Arg(cst.Name("session")), *updated_node.args],
                )
            )
        if m.matches(
            updated_node.func,
            m.Attribute(value=m.Name("session"), attr=m.Name("analyze")),
        ):
            return cst.Await(
                cst.Call(
                    func=cst.Attribute(
                        value=cst.Name("self"), attr=cst.Name("_run_session_analyze")
                    ),
                    args=[cst.Arg(cst.Name("session")), *updated_node.args],
                )
            )
        if m.matches(
            updated_node.func,
            m.Attribute(value=m.Name("self"), attr=m.Name("_ensure_analyzed")),
        ):
            return cst.Await(updated_node)
        return updated_node


def patch_radare2_plugin() -> None:
    relative = "reversecore_mcp/tools/radare2/radare2_mcp_tools.py"
    path = ROOT / relative
    module = cst.parse_module(path.read_text())
    path.write_text(module.visit(SessionCallTransformer()).code)

    replace_once(relative, "import os\nimport shutil\n", "import os\nimport shutil\nimport time\n")
    replace_once(
        relative,
        "from reversecore_mcp.core.exceptions import ValidationError\n",
        "from reversecore_mcp.core.exceptions import ToolExecutionError, ValidationError\n",
    )
    replace_once(
        relative,
        "    def __init__(self):\n"
        "        self._sessions: dict[str, R2Session] = {}  # session_id -> Session\n"
        "        self._file_to_session: dict[str, str] = {}  # file_path -> session_id\n"
        "        self._lock = asyncio.Lock()  # Protects session creation race conditions\n",
        "    def __init__(self):\n"
        "        settings = get_config()\n"
        "        self._sessions: dict[str, R2Session] = {}  # session_id -> Session\n"
        "        self._file_to_session: dict[str, str] = {}  # file_path -> session_id\n"
        "        self._session_locks: dict[str, asyncio.Lock] = {}\n"
        "        self._session_last_used: dict[str, float] = {}\n"
        "        self._max_sessions = settings.r2_session_max\n"
        "        self._session_idle_ttl = settings.r2_session_idle_ttl\n"
        "        self._lock = asyncio.Lock()  # Protects session lifecycle mutations\n",
    )

    helpers = '''    def _touch_session(self, session_id: str) -> None:
        self._session_last_used[session_id] = time.monotonic()

    async def _run_session_cmd(self, session: R2Session, command: str) -> str:
        """Serialize commands per r2pipe process and keep blocking I/O off the event loop."""
        lock = self._session_locks.setdefault(session.session_id, asyncio.Lock())
        async with lock:
            if not session.is_open:
                raise ToolExecutionError("Radare2 session is closed")
            self._touch_session(session.session_id)
            try:
                return await asyncio.to_thread(session.cmd, command)
            finally:
                self._touch_session(session.session_id)

    async def _run_session_analyze(self, session: R2Session, level: int) -> Any:
        """Serialize blocking analysis for a session in a worker thread."""
        lock = self._session_locks.setdefault(session.session_id, asyncio.Lock())
        async with lock:
            if not session.is_open:
                raise ToolExecutionError("Radare2 session is closed")
            self._touch_session(session.session_id)
            try:
                return await asyncio.to_thread(session.analyze, level)
            finally:
                self._touch_session(session.session_id)

    async def _close_session_locked(self, session_id: str, *, wait: bool = True) -> bool:
        """Close and remove a session while the lifecycle lock is held."""
        session = self._sessions.get(session_id)
        if session is None:
            return True

        session_lock = self._session_locks.setdefault(session_id, asyncio.Lock())
        if session_lock.locked() and not wait:
            return False

        async with session_lock:
            await asyncio.to_thread(session.close)

        self._sessions.pop(session_id, None)
        self._session_locks.pop(session_id, None)
        self._session_last_used.pop(session_id, None)
        for file_path, mapped_id in list(self._file_to_session.items()):
            if mapped_id == session_id:
                self._file_to_session.pop(file_path, None)
        return True

    async def _evict_stale_sessions_locked(self) -> None:
        """Evict idle sessions and enforce a bounded persistent-session set."""
        now = time.monotonic()
        stale_ids = [
            session_id
            for session_id, last_used in self._session_last_used.items()
            if now - last_used >= self._session_idle_ttl
        ]
        for session_id in stale_ids:
            await self._close_session_locked(session_id, wait=False)

        while len(self._sessions) >= self._max_sessions:
            candidates = [
                session_id
                for session_id in self._sessions
                if not (
                    self._session_locks.get(session_id)
                    and self._session_locks[session_id].locked()
                )
            ]
            if not candidates:
                raise ToolExecutionError(
                    f"Radare2 session capacity reached ({self._max_sessions}); "
                    "close a session or retry after an active command finishes"
                )
            oldest = min(
                candidates,
                key=lambda session_id: self._session_last_used.get(session_id, 0.0),
            )
            await self._close_session_locked(oldest, wait=False)

'''
    replace_once(
        relative,
        "    def _diagnose_error(self, file_path: str, error: Exception) -> dict[str, Any]:\n",
        helpers + "    def _diagnose_error(self, file_path: str, error: Exception) -> dict[str, Any]:\n",
    )

    replace_once(
        relative,
        "        except ValidationError:\n            return R2Session(file_path)\n",
        "        except ValidationError as exc:\n"
        "            raise ToolExecutionError(f\"Invalid Radare2 file path: {file_path}\") from exc\n",
    )
    replace_once(
        relative,
        "                    if session.is_open:\n"
        "                        return session\n"
        "                    else:\n"
        "                        # Stale session, remove it\n"
        "                        del self._sessions[sid]\n"
        "                        del self._file_to_session[file_path]\n",
        "                    if session.is_open:\n"
        "                        self._session_locks.setdefault(sid, asyncio.Lock())\n"
        "                        self._touch_session(sid)\n"
        "                        return session\n"
        "                    await self._close_session_locked(sid)\n",
    )
    replace_once(
        relative,
        "            # 3. Create new session (blocking I/O wrapped in thread)\n",
        "            await self._evict_stale_sessions_locked()\n\n"
        "            # 3. Create new session (blocking I/O wrapped in thread)\n",
    )
    replace_once(
        relative,
        "                self._sessions[session.session_id] = session\n"
        "                self._file_to_session[file_path] = session.session_id\n",
        "                self._sessions[session.session_id] = session\n"
        "                self._file_to_session[file_path] = session.session_id\n"
        "                self._session_locks[session.session_id] = asyncio.Lock()\n"
        "                self._touch_session(session.session_id)\n",
    )
    replace_once(
        relative,
        "                    await asyncio.to_thread(session.cmd, \"aaa\")\n",
        "                    await self._run_session_cmd(session, \"aaa\")\n",
    )
    replace_once(
        relative,
        "                from reversecore_mcp.core.exceptions import ToolExecutionError\n\n"
        "                raise ToolExecutionError(f\"Cannot open file with radare2: {file_path}\") from e\n",
        "                raise ToolExecutionError(f\"Cannot open file with radare2: {file_path}\") from e\n",
    )
    replace_once(
        relative,
        "                # Check mapping\n"
        "                if abs_path in self._file_to_session:\n"
        "                    sid = self._file_to_session[abs_path]\n"
        "                    if sid in self._sessions:\n"
        "                        self._sessions[sid].close()\n"
        "                        del self._sessions[sid]\n"
        "                    del self._file_to_session[abs_path]\n"
        "                    return {\n",
        "                # Check mapping\n"
        "                if abs_path in self._file_to_session:\n"
        "                    sid = self._file_to_session[abs_path]\n"
        "                    async with self._lock:\n"
        "                        await self._close_session_locked(sid)\n"
        "                    return {\n",
    )

    cleanup = '''    async def cleanup(self) -> None:
        """Close every persistent Radare2 process during server shutdown."""
        async with self._lock:
            for session_id in list(self._sessions):
                await self._close_session_locked(session_id)

'''
    replace_once(relative, "    def register(self, mcp: FastMCP) -> None:\n", cleanup + "    def register(self, mcp: FastMCP) -> None:\n")


def patch_extension_boundary() -> None:
    relative = "reversecore_mcp/tools/radare2/r2_analysis.py"
    replace_once(
        relative,
        "DEFAULT_TIMEOUT = get_config().default_tool_timeout\n\n\n",
        "DEFAULT_TIMEOUT = get_config().default_tool_timeout\n\n\n"
        "async def _apply_validated_r2_pre_hooks(file_path: str, command: str) -> tuple[str, str]:\n"
        "    \"\"\"Run extension pre-hooks, then reapply core path and command validation.\"\"\"\n"
        "    registry = get_extension_registry()\n"
        "    hooked_path, hooked_command = await registry.run_r2_pre_hooks(file_path, command)\n"
        "    return str(validate_file_path(hooked_path)), validate_r2_command(hooked_command)\n\n\n",
    )
    replace_once(
        relative,
        "        validated_path, validated_command = await _registry.run_r2_pre_hooks(\n"
        "            str(validated_path), validated_command\n"
        "        )\n",
        "        validated_path, validated_command = await _apply_validated_r2_pre_hooks(\n"
        "            str(validated_path), validated_command\n"
        "        )\n",
    )


def add_tests() -> None:
    path = ROOT / "tests/unit/tools/radare2/test_r2_runtime_hardening.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '''from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.tools.radare2 import r2_analysis
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
'''
    )


def main() -> None:
    patch_config()
    patch_radare2_plugin()
    patch_extension_boundary()
    add_tests()

    # Remove one-shot machinery from the generated source commit.
    (ROOT / "scripts/apply_r2_hardening_refactor.py").unlink()
    (ROOT / ".github/workflows/apply-r2-hardening.yml").unlink()


if __name__ == "__main__":
    main()
