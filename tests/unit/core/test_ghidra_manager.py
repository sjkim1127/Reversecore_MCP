"""Unit tests for GhidraManager."""

import threading
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.ghidra_manager import (
    DecompilationError,
    GhidraError,
    GhidraManager,
    get_ghidra_manager,
)


class TestGhidraExceptions:
    """Tests for custom exceptions."""

    def test_ghidra_error_is_exception(self):
        """GhidraError should be an Exception."""
        with pytest.raises(GhidraError):
            raise GhidraError("test error")

    def test_decompilation_error_is_ghidra_error(self):
        """DecompilationError should inherit from GhidraError."""
        assert issubclass(DecompilationError, GhidraError)
        with pytest.raises(GhidraError):
            raise DecompilationError("decomp failed")


class TestGhidraManagerSingleton:
    """Tests for singleton behavior."""

    def test_singleton(self):
        """Multiple instantiations should return same object."""
        m1 = GhidraManager()
        m2 = GhidraManager()
        assert m1 is m2

    def test_thread_safe_creation(self):
        """Should handle concurrent creation safely."""
        instances = []

        def create():
            instances.append(GhidraManager())

        threads = [threading.Thread(target=create) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(set(id(i) for i in instances)) == 1


class TestGhidraManagerInit:
    """Tests for initialization."""

    def test_initialized_flag(self):
        """Should set initialized flag."""
        # Reset singleton for test
        GhidraManager._instance = None
        m = GhidraManager()
        assert m._initialized is True

    def test_jvm_not_started_initially(self):
        """JVM should not be started on init."""
        GhidraManager._instance = None
        m = GhidraManager()
        assert m._jvm_started is False

    def test_projects_dict_empty(self):
        """Projects cache should be empty."""
        GhidraManager._instance = None
        m = GhidraManager()
        assert m._projects == {}

    def test_max_projects_from_config(self):
        """Max projects should come from config."""
        GhidraManager._instance = None
        with patch("reversecore_mcp.core.ghidra_manager.get_config") as mock_cfg:
            mock_cfg.return_value.ghidra_max_projects = 5
            m = GhidraManager()
            assert m._max_projects == 5


class TestEnsureJvmStarted:
    """Tests for JVM startup."""

    def test_already_started_skips(self):
        """Should skip if JVM already started."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()

        with patch("reversecore_mcp.core.ghidra_manager.get_config") as mock_cfg:
            mock_cfg.return_value.ghidra_max_projects = 1
            m2 = GhidraManager()
            m2._ensure_jvm_started()
            # pyghidra should NOT be imported again
            assert m2._jvm_started is True

    def test_pyghidra_not_installed(self):
        """Should raise ImportError when pyghidra missing."""
        GhidraManager._instance = None
        m = GhidraManager()
        with patch.dict("sys.modules", {"pyghidra": None}):
            with pytest.raises(ImportError):
                m._ensure_jvm_started()

    def test_pyghidra_start_exception(self):
        """Should handle pyghidra.start() exception gracefully."""
        GhidraManager._instance = None
        m = GhidraManager()
        mock_pyghidra = MagicMock()
        mock_pyghidra.start.side_effect = RuntimeError("already running")
        mock_flat = MagicMock()

        with patch.dict("sys.modules", {"pyghidra": mock_pyghidra, "pyghidra.core": MagicMock()}):
            with patch("builtins.__import__", side_effect=lambda name, *a, **k: {
                "pyghidra": mock_pyghidra,
                "pyghidra.core": MagicMock(FlatProgramAPI=mock_flat),
            }.get(name)):
                m._ensure_jvm_started()
        assert m._jvm_started is True


class TestProjectCache:
    """Tests for project caching."""

    def test_get_cached_project(self):
        """Should return cached project."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        result = m._get_project("/app/test.bin")
        assert result == (mock_program, mock_api, mock_ctx)

    def test_load_new_project(self):
        """Should load new project when not cached."""
        GhidraManager._instance = None
        m = GhidraManager()
        mock_pyghidra = MagicMock()
        mock_ctx = MagicMock()
        mock_api = MagicMock()
        mock_program = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_api)
        mock_api.getCurrentProgram = MagicMock(return_value=mock_program)
        mock_pyghidra.open_program = MagicMock(return_value=mock_ctx)
        m._pyghidra = mock_pyghidra

        result = m._get_project("/app/new.bin")
        assert result[0] == mock_program
        assert result[1] == mock_api
        assert "/app/new.bin" in m._projects

    def test_eviction_on_max_projects(self):
        """Should evict oldest project when cache full."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._max_projects = 1
        m._pyghidra = MagicMock()

        # Add first project
        ctx1 = MagicMock()
        api1 = MagicMock()
        prog1 = MagicMock()
        ctx1.__enter__ = MagicMock(return_value=api1)
        api1.getCurrentProgram = MagicMock(return_value=prog1)
        m._pyghidra.open_program = MagicMock(return_value=ctx1)
        m._get_project("/app/old.bin")

        # Load second project - should evict first
        ctx2 = MagicMock()
        api2 = MagicMock()
        prog2 = MagicMock()
        ctx2.__enter__ = MagicMock(return_value=api2)
        api2.getCurrentProgram = MagicMock(return_value=prog2)
        m._pyghidra.open_program = MagicMock(return_value=ctx2)
        m._get_project("/app/new.bin")

        assert "/app/old.bin" not in m._projects
        assert "/app/new.bin" in m._projects
        ctx1.__exit__.assert_called_once()

    def test_close_project(self):
        """Should properly close project context."""
        GhidraManager._instance = None
        m = GhidraManager()
        ctx = MagicMock()
        m._close_project("/app/test.bin", ctx)
        ctx.__exit__.assert_called_once_with(None, None, None)

    def test_close_all(self):
        """Should close all projects."""
        GhidraManager._instance = None
        m = GhidraManager()
        ctx1 = MagicMock()
        ctx2 = MagicMock()
        m._projects = {
            "/app/a.bin": (MagicMock(), MagicMock(), ctx1),
            "/app/b.bin": (MagicMock(), MagicMock(), ctx2),
        }
        m.close_all()
        assert m._projects == {}
        ctx1.__exit__.assert_called_once()
        ctx2.__exit__.assert_called_once()


class TestDecompile:
    """Tests for decompilation."""

    def test_decompile_no_address_raises(self):
        """Should raise when no function address provided."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        with patch.dict("sys.modules", {
            "ghidra": MagicMock(),
            "ghidra.app": MagicMock(),
            "ghidra.app.decompiler": MagicMock(),
            "ghidra.util": MagicMock(),
            "ghidra.util.task": MagicMock(),
        }):
            with pytest.raises(NotImplementedError):
                m.decompile("/app/test.bin", function_address=None)

    def test_decompile_invalid_address(self):
        """Should raise on invalid address."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_api.toAddr = MagicMock(return_value=None)
        mock_api.getGlobalFunctions = MagicMock(return_value=[])
        mock_api.getFunctionBefore = MagicMock(return_value=None)
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        with patch.dict("sys.modules", {
            "ghidra.app.decompiler": MagicMock(),
            "ghidra.util.task": MagicMock(),
        }):
            with pytest.raises(ValueError):
                m.decompile("/app/test.bin", function_address="0xdeadbeef")

    def test_decompile_success(self):
        """Should return decompiled C code."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_addr = MagicMock()
        mock_api.toAddr = MagicMock(return_value=mock_addr)
        mock_func = MagicMock()
        mock_api.getFunctionAt = MagicMock(return_value=mock_func)
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        mock_decomp = MagicMock()
        mock_result = MagicMock()
        mock_result.decompileCompleted = MagicMock(return_value=True)
        mock_decomp_func = MagicMock()
        mock_decomp_func.getC = MagicMock(return_value="int main() { return 0; }")
        mock_result.getDecompiledFunction = MagicMock(return_value=mock_decomp_func)
        mock_decomp.decompileFunction = MagicMock(return_value=mock_result)
        mock_decomp.openProgram = MagicMock()

        mock_monitor = MagicMock()

        with patch.dict("sys.modules", {
            "ghidra.app.decompiler": MagicMock(DecompInterface=lambda: mock_decomp),
            "ghidra.util.task": MagicMock(ConsoleTaskMonitor=lambda: mock_monitor),
        }):
            result = m.decompile("/app/test.bin", function_address="0x401000")
        assert result == "int main() { return 0; }"

    def test_decompile_failure_raises(self):
        """Should raise DecompilationError on failure."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_addr = MagicMock()
        mock_api.toAddr = MagicMock(return_value=mock_addr)
        mock_func = MagicMock()
        mock_api.getFunctionAt = MagicMock(return_value=mock_func)
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        mock_decomp = MagicMock()
        mock_result = MagicMock()
        mock_result.decompileCompleted = MagicMock(return_value=False)
        mock_result.getErrorMessage = MagicMock(return_value="timeout")
        mock_decomp.decompileFunction = MagicMock(return_value=mock_result)
        mock_decomp.openProgram = MagicMock()

        mock_monitor = MagicMock()

        with patch.dict("sys.modules", {
            "ghidra.app.decompiler": MagicMock(DecompInterface=lambda: mock_decomp),
            "ghidra.util.task": MagicMock(ConsoleTaskMonitor=lambda: mock_monitor),
        }):
            with pytest.raises(DecompilationError):
                m.decompile("/app/test.bin", function_address="0x401000")

    def test_decompile_invalidates_cache_on_error(self):
        """Should remove file from cache on error."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_api.toAddr = MagicMock(return_value=None)
        mock_api.getGlobalFunctions = MagicMock(return_value=[])
        mock_api.getFunctionBefore = MagicMock(return_value=None)
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        with patch.dict("sys.modules", {
            "ghidra.app.decompiler": MagicMock(),
            "ghidra.util.task": MagicMock(),
        }):
            with pytest.raises(ValueError):
                m.decompile("/app/test.bin", function_address="bad")
        assert "/app/test.bin" not in m._projects

    @pytest.mark.asyncio
    async def test_decompile_async(self):
        """Should run decompile in thread pool."""
        GhidraManager._instance = None
        m = GhidraManager()
        m._jvm_started = True
        m._pyghidra = MagicMock()
        mock_program = MagicMock()
        mock_api = MagicMock()
        mock_addr = MagicMock()
        mock_api.toAddr = MagicMock(return_value=mock_addr)
        mock_func = MagicMock()
        mock_api.getFunctionAt = MagicMock(return_value=mock_func)
        mock_ctx = MagicMock()
        m._projects["/app/test.bin"] = (mock_program, mock_api, mock_ctx)

        mock_decomp = MagicMock()
        mock_result = MagicMock()
        mock_result.decompileCompleted = MagicMock(return_value=True)
        mock_decomp_func = MagicMock()
        mock_decomp_func.getC = MagicMock(return_value="void foo() {}")
        mock_result.getDecompiledFunction = MagicMock(return_value=mock_decomp_func)
        mock_decomp.decompileFunction = MagicMock(return_value=mock_result)
        mock_decomp.openProgram = MagicMock()
        mock_monitor = MagicMock()

        with patch.dict("sys.modules", {
            "ghidra.app.decompiler": MagicMock(DecompInterface=lambda: mock_decomp),
            "ghidra.util.task": MagicMock(ConsoleTaskMonitor=lambda: mock_monitor),
        }):
            result = await m.decompile_async("/app/test.bin", function_address="0x401000")
        assert result == "void foo() {}"


class TestGetGhidraManager:
    """Tests for global accessor."""

    def test_returns_singleton(self):
        """Should return the global singleton."""
        m1 = get_ghidra_manager()
        m2 = get_ghidra_manager()
        assert m1 is m2
        assert isinstance(m1, GhidraManager)
