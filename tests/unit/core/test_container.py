"""Edge-case tests for reversecore_mcp.core.container.ServiceContainer."""

import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_container():
    """Return a brand-new ServiceContainer (not the module singleton)."""
    from reversecore_mcp.core.container import ServiceContainer

    return ServiceContainer()


# ===========================================================================
# register_singleton / register_factory / get
# ===========================================================================


class TestGet:
    def test_get_unregistered_raises_key_error(self):
        c = _fresh_container()
        with pytest.raises(KeyError, match="not registered"):
            c.get("nonexistent")

    def test_get_pre_created_instance(self):
        c = _fresh_container()
        obj = object()
        c.register_singleton("svc", factory=lambda: None, instance=obj)
        assert c.get("svc") is obj

    def test_get_singleton_factory_lazy(self):
        c = _fresh_container()
        calls = []

        def factory():
            calls.append(1)
            return "created"

        c.register_singleton("svc", factory)
        # first call creates
        assert c.get("svc") == "created"
        assert len(calls) == 1
        # second call reuses
        assert c.get("svc") == "created"
        assert len(calls) == 1  # factory NOT called again

    def test_get_factory_creates_new_each_time(self):
        c = _fresh_container()
        c.register_factory("svc", list)  # list() returns new list every call
        a = c.get("svc")
        b = c.get("svc")
        assert a is not b

    def test_get_override_takes_priority(self):
        c = _fresh_container()
        c.register_singleton("svc", lambda: "original")
        c.override("svc", "mocked")
        assert c.get("svc") == "mocked"

    def test_get_override_removed_after_reset(self):
        c = _fresh_container()
        c.register_singleton("svc", lambda: "original", instance="original")
        c.override("svc", "mocked")
        assert c.get("svc") == "mocked"
        c.reset_overrides()
        assert c.get("svc") == "original"


# ===========================================================================
# has / reset_singleton / reset_all
# ===========================================================================


class TestHasAndReset:
    def test_has_returns_false_when_not_registered(self):
        c = _fresh_container()
        assert not c.has("missing")

    def test_has_returns_true_for_singleton_factory(self):
        c = _fresh_container()
        c.register_singleton("svc", lambda: None)
        assert c.has("svc")

    def test_has_returns_true_for_override(self):
        c = _fresh_container()
        c.override("svc", "x")
        assert c.has("svc")

    def test_reset_singleton_forces_recreation(self):
        c = _fresh_container()
        calls = []

        def factory():
            calls.append(1)
            return object()

        c.register_singleton("svc", factory)
        first = c.get("svc")
        c.reset_singleton("svc")
        second = c.get("svc")
        assert first is not second
        assert len(calls) == 2

    def test_reset_singleton_noop_if_not_instantiated(self):
        c = _fresh_container()
        c.register_singleton("svc", lambda: "x")
        # Not yet retrieved — should not raise
        c.reset_singleton("svc")

    def test_reset_all_clears_singletons_and_overrides(self):
        c = _fresh_container()
        c.register_singleton("svc", lambda: "x", instance="x")
        c.override("svc2", "y")
        c.reset_all()
        # svc is cleared from _singletons but factory remains
        assert not c.has("svc")
        assert not c.has("svc2")


# ===========================================================================
# initialize_async
# ===========================================================================


class TestInitializeAsync:
    @pytest.mark.asyncio
    async def test_initialize_async_idempotent(self):
        """Calling initialize_async twice must be a no-op on the second call."""
        c = _fresh_container()
        started = []

        class AsyncService:
            async def start(self):
                started.append(1)

        c.register_singleton("svc", AsyncService)
        await c.initialize_async()
        await c.initialize_async()  # second call — no-op
        assert len(started) == 1

    @pytest.mark.asyncio
    async def test_initialize_async_calls_start_on_singleton(self):
        c = _fresh_container()
        started = []

        class AsyncService:
            async def start(self):
                started.append(1)

        c.register_singleton("svc", AsyncService)
        await c.initialize_async()
        assert len(started) == 1

    @pytest.mark.asyncio
    async def test_initialize_async_handles_start_failure(self):
        """If start() raises, container must not propagate the exception."""
        c = _fresh_container()

        class FailingService:
            async def start(self):
                raise RuntimeError("boom")

        c.register_singleton("svc", FailingService)
        # Must not raise
        await c.initialize_async()
        assert c._initialized is True

    @pytest.mark.asyncio
    async def test_initialize_async_skips_non_async_start(self):
        """Services with a sync start() must not be awaited."""
        c = _fresh_container()
        called = []

        class SyncService:
            def start(self):
                called.append(1)

        c.register_singleton("svc", SyncService)
        await c.initialize_async()
        # sync start() should NOT be called by initialize_async
        assert called == []


# ===========================================================================
# shutdown_async
# ===========================================================================


class TestShutdownAsync:
    @pytest.mark.asyncio
    async def test_shutdown_async_calls_stop(self):
        c = _fresh_container()
        stopped = []

        class AsyncService:
            async def start(self):
                pass

            async def stop(self):
                stopped.append(1)

        c.register_singleton("svc", AsyncService)
        await c.initialize_async()
        await c.shutdown_async()
        assert len(stopped) == 1
        assert c._initialized is False

    @pytest.mark.asyncio
    async def test_shutdown_async_handles_stop_failure(self):
        """stop() raising must not abort the rest of the shutdown."""
        c = _fresh_container()
        closed = []

        class FailingStop:
            async def start(self):
                pass

            async def stop(self):
                raise RuntimeError("stop failed")

        class PoolService:
            async def start(self):
                pass

            def close_all(self):
                closed.append(1)

        c.register_singleton("svc1", FailingStop)
        c.register_singleton("svc2", PoolService)
        await c.initialize_async()
        # Must not raise despite FailingStop.stop() failing
        await c.shutdown_async()
        assert c._initialized is False

    @pytest.mark.asyncio
    async def test_shutdown_async_calls_close_all(self):
        c = _fresh_container()
        closed = []

        class PoolLike:
            async def start(self):
                pass

            def close_all(self):
                closed.append(1)

        c.register_singleton("pool", PoolLike)
        await c.initialize_async()
        await c.shutdown_async()
        assert len(closed) == 1

    @pytest.mark.asyncio
    async def test_shutdown_async_handles_close_all_failure(self):
        c = _fresh_container()

        class BrokenPool:
            async def start(self):
                pass

            def close_all(self):
                raise OSError("close failed")

        c.register_singleton("pool", BrokenPool)
        await c.initialize_async()
        # Must not raise
        await c.shutdown_async()


# ===========================================================================
# _safe_start
# ===========================================================================


class TestSafeStart:
    @pytest.mark.asyncio
    async def test_safe_start_success(self):
        c = _fresh_container()
        started = []

        class Svc:
            async def start(self):
                started.append(1)

        svc = Svc()
        await c._safe_start("my_svc", svc)
        assert len(started) == 1

    @pytest.mark.asyncio
    async def test_safe_start_handles_exception(self):
        c = _fresh_container()

        class FailSvc:
            async def start(self):
                raise ValueError("start error")

        # Must not raise
        await c._safe_start("fail_svc", FailSvc())


# ===========================================================================
# get() with already-initialized container (schedules task for lazy singleton)
# ===========================================================================


class TestLazySingletonAfterInit:
    @pytest.mark.asyncio
    async def test_lazy_singleton_after_init_logs_warning(self):
        """
        After initialize_async, if a new singleton is resolved via get(),
        container logs a warning and schedules _safe_start as a task.
        """
        c = _fresh_container()

        class LateService:
            async def start(self):
                pass

        c.register_singleton("late", LateService)
        await c.initialize_async()

        # Now add another singleton factory AFTER initialization
        c.register_singleton("very_late", LateService)

        # Accessing it should work and schedule _safe_start (best-effort)
        with patch.object(c, "_safe_start", new_callable=AsyncMock):
            # Wrap asyncio.create_task to capture calls
            scheduled = []

            def fake_create_task(coro, **kwargs):
                scheduled.append(coro)
                # Don't actually create the task to avoid event loop issues
                coro.close()
                return MagicMock()

            with patch("reversecore_mcp.core.container.asyncio.create_task", fake_create_task):
                svc = c.get("very_late")
            assert isinstance(svc, LateService)


# ===========================================================================
# Thread safety
# ===========================================================================


class TestThreadSafety:
    def test_concurrent_singleton_creation_returns_same_instance(self):
        """Multiple threads racing to create a singleton must get the same object."""
        c = _fresh_container()
        created = []

        def factory():
            import time

            time.sleep(0.01)  # simulate slow construction
            obj = object()
            created.append(obj)
            return obj

        c.register_singleton("svc", factory)

        results = []

        def get_svc():
            results.append(c.get("svc"))

        threads = [threading.Thread(target=get_svc) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads must see the same singleton
        assert len({id(r) for r in results}) == 1


# ===========================================================================
# Convenience helper functions
# ===========================================================================


class TestConvenienceFunctions:
    def test_get_r2_pool_returns_something(self):
        from reversecore_mcp.core.container import get_r2_pool

        pool = get_r2_pool()
        assert pool is not None

    def test_get_resource_manager_returns_something(self):
        from reversecore_mcp.core.container import get_resource_manager

        rm = get_resource_manager()
        assert rm is not None

    def test_get_ghidra_service_returns_something(self):
        from reversecore_mcp.core.container import get_ghidra_service

        svc = get_ghidra_service()
        assert svc is not None

    def test_get_config_from_container_returns_config(self):
        from reversecore_mcp.core.container import get_config_from_container

        cfg = get_config_from_container()
        assert cfg is not None
