"""Unit tests for the ARQ-based task queue component."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.core.task_queue import (
    get_job_result,
    run_task_or_fallback,
    task_run_strings,
    task_run_yara,
    task_smart_decompile,
    task_vulnerability_hunter,
)


@pytest.mark.asyncio
async def test_run_task_or_fallback_redis_disabled(patched_config):
    mock_inner = AsyncMock(return_value=success("fallback result"))

    async def mock_fallback(*args, **kwargs):
        return await mock_inner(*args, **kwargs)

    with patch(
        "reversecore_mcp.core.task_queue.get_arq_pool",
        new_callable=AsyncMock,
        return_value=None,
    ):
        # Should directly call fallback
        result = await run_task_or_fallback(
            "task_smart_decompile",
            mock_fallback,
            "dummy_file",
            "main",
        )
        assert result.status == "success"
        assert result.data == "fallback result"
        mock_inner.assert_called_once_with("dummy_file", "main", _bypass_queue=True)


@pytest.mark.asyncio
async def test_run_task_or_fallback_enqueue_and_await(patched_config):
    mock_inner = AsyncMock(return_value=success("fallback result"))

    async def mock_fallback(*args, **kwargs):
        return await mock_inner(*args, **kwargs)

    mock_job = AsyncMock()
    mock_job.job_id = "fake-job-id"
    mock_job.result.return_value = success("queued result")

    mock_pool = AsyncMock()
    mock_pool.enqueue_job.return_value = mock_job

    with patch(
        "reversecore_mcp.core.task_queue.get_arq_pool",
        new_callable=AsyncMock,
        return_value=mock_pool,
    ):
        # 1. Sync mode (default) -> enqueues and waits for result
        result = await run_task_or_fallback(
            "task_smart_decompile",
            mock_fallback,
            "dummy_file",
            "main",
        )
        assert result.status == "success"
        assert result.data == "queued result"
        mock_pool.enqueue_job.assert_called_once_with("task_smart_decompile", "dummy_file", "main")
        mock_job.result.assert_called_once()
        mock_inner.assert_not_called()

        # 2. Async mode -> enqueues and returns job ID immediately
        mock_pool.enqueue_job.reset_mock()
        result_async = await run_task_or_fallback(
            "task_smart_decompile",
            mock_fallback,
            "dummy_file",
            "main",
            run_async=True,
        )
        assert result_async.status == "success"
        assert result_async.data["job_id"] == "fake-job-id"
        assert result_async.data["status"] == "queued"
        mock_pool.enqueue_job.assert_called_once_with("task_smart_decompile", "dummy_file", "main")


@pytest.mark.asyncio
async def test_get_job_result_tool(patched_config):
    mock_pool = AsyncMock()
    mock_job = MagicMock()

    # 1. Job complete
    mock_job.status = AsyncMock(return_value=MagicMock(value="complete"))
    mock_job.result = AsyncMock(return_value=success("final output"))

    # Patch Job instantiation
    with (
        patch(
            "reversecore_mcp.core.task_queue.get_arq_pool",
            new_callable=AsyncMock,
            return_value=mock_pool,
        ),
        patch("reversecore_mcp.core.task_queue.Job", return_value=mock_job),
    ):
        # Test complete status
        from arq.jobs import JobStatus

        mock_job.status.return_value = JobStatus.complete
        res = await get_job_result("fake-job-id")
        assert res.status == "success"
        assert res.data == "final output"

        # Test queued/in_progress status
        mock_job.status.return_value = JobStatus.in_progress
        res_progress = await get_job_result("fake-job-id")
        assert res_progress.status == "success"
        assert res_progress.data["status"] == "in_progress"

        # Test job not found
        mock_job.status.return_value = JobStatus.not_found
        res_not_found = await get_job_result("fake-job-id")
        assert res_not_found.status == "error"
        assert res_not_found.error_code == "JOB_NOT_FOUND"


@pytest.mark.asyncio
async def test_worker_proxy_handlers(patched_config):
    # 1. task_smart_decompile
    with patch(
        "reversecore_mcp.tools.radare2.r2ghidra_tools.r2_decompile",
        new_callable=AsyncMock,
    ) as mock_impl:
        mock_impl.return_value = success("decompiled code")
        res = await task_smart_decompile(None, "file.bin", "main", 120, True)
        assert res.status == "success"
        mock_impl.assert_called_once_with(
            file_path="file.bin", function_address="main", timeout=120
        )

    # 2. task_run_yara
    with patch(
        "reversecore_mcp.tools.malware.yara_tools.run_yara", new_callable=AsyncMock
    ) as mock_yara:
        mock_yara.return_value = success("yara matches")
        res = await task_run_yara(None, "file.bin", "rules.yar", 300)
        assert res.status == "success"
        mock_yara.assert_called_once_with(
            file_path="file.bin", rule_file="rules.yar", timeout=300, _bypass_queue=True
        )

    # 3. task_run_strings
    with patch(
        "reversecore_mcp.tools.analysis.static_analysis.run_strings",
        new_callable=AsyncMock,
    ) as mock_strings:
        mock_strings.return_value = success("strings output")
        res = await task_run_strings(None, "file.bin", 10, 1000, 120)
        assert res.status == "success"
        mock_strings.assert_called_once_with(
            file_path="file.bin",
            min_length=10,
            max_output_size=1000,
            timeout=120,
            _bypass_queue=True,
        )

    # 4. task_vulnerability_hunter
    with patch(
        "reversecore_mcp.tools.malware.vulnerability_hunter.vulnerability_hunter",
        new_callable=AsyncMock,
    ) as mock_vuln:
        mock_vuln.return_value = success("vulns report")
        res = await task_vulnerability_hunter(None, "file.bin", 3, "all", True, 300)
        assert res.status == "success"
        mock_vuln.assert_called_once_with(
            file_path="file.bin",
            max_depth=3,
            severity_filter="all",
            generate_yara=True,
            timeout=300,
            use_symbolic_execution=True,
            auto_dynamic_verify=True,
            target_functions=None,
            _bypass_queue=True,
        )


@pytest.mark.asyncio
async def test_close_and_reset_task_queue():
    from reversecore_mcp.core import task_queue

    task_queue._queue_enabled = False
    task_queue._arq_pool = MagicMock()
    task_queue._arq_pool.close = AsyncMock()

    await task_queue.close_arq_pool()
    assert task_queue._queue_enabled is True
    assert task_queue._arq_pool is None

    task_queue._queue_enabled = False
    task_queue.reset_task_queue()
    assert task_queue._queue_enabled is True


class TestIssue278RedisRetryAndBackoff:
    """Acceptance tests for Issue #278: Redis queue retry and bounded backoff."""

    def setup_method(self):
        from reversecore_mcp.core import task_queue

        task_queue.reset_task_queue()

    def teardown_method(self):
        from reversecore_mcp.core import task_queue

        task_queue.reset_task_queue()

    @pytest.mark.asyncio
    async def test_transient_failure_retries_and_succeeds(self):
        """First Redis connection attempt fails, later attempt succeeds without process restart."""
        from reversecore_mcp.core import task_queue

        mock_pool = MagicMock()
        mock_create = AsyncMock(side_effect=[ConnectionError("Redis unavailable"), mock_pool])

        with (
            patch("reversecore_mcp.core.task_queue.create_pool", mock_create),
            patch("reversecore_mcp.core.task_queue.get_config") as mock_cfg,
        ):
            cfg = MagicMock()
            cfg.redis_url = "redis://localhost:6379/0"
            mock_cfg.return_value = cfg

            # Attempt 1: Transient outage -> returns None, queue remains enabled for retry
            pool1 = await task_queue.get_arq_pool()
            assert pool1 is None
            assert task_queue._queue_enabled is True
            assert task_queue._failure_count == 1
            assert mock_create.call_count == 1

            # Advance time past backoff delay
            future_time = task_queue._next_retry_time + 0.1
            with patch("time.monotonic", return_value=future_time):
                pool2 = await task_queue.get_arq_pool()
                assert pool2 == mock_pool
                assert task_queue._failure_count == 0
                assert mock_create.call_count == 2

    @pytest.mark.asyncio
    async def test_explicitly_disabled_configuration_never_retries(self):
        """Administratively disabled configuration never attempts reconnection or retry."""
        from reversecore_mcp.core import task_queue

        mock_create = AsyncMock()

        with (
            patch("reversecore_mcp.core.task_queue.create_pool", mock_create),
            patch("reversecore_mcp.core.task_queue.get_config") as mock_cfg,
        ):
            cfg = MagicMock()
            cfg.redis_url = ""  # empty / disabled
            mock_cfg.return_value = cfg

            pool1 = await task_queue.get_arq_pool()
            assert pool1 is None
            assert task_queue._queue_administratively_disabled is True
            assert mock_create.call_count == 0

            # Subsequent call does not retry even with arbitrary time advancement
            with patch("time.monotonic", return_value=999999999.0):
                pool2 = await task_queue.get_arq_pool()
                assert pool2 is None
                assert mock_create.call_count == 0

    @pytest.mark.asyncio
    async def test_repeated_failures_use_bounded_backoff(self):
        """Repeated failures use exponential backoff rather than reconnecting on every request."""
        from reversecore_mcp.core import task_queue

        mock_create = AsyncMock(side_effect=ConnectionError("Redis down"))

        with (
            patch("reversecore_mcp.core.task_queue.create_pool", mock_create),
            patch("reversecore_mcp.core.task_queue.get_config") as mock_cfg,
        ):
            cfg = MagicMock()
            cfg.redis_url = "redis://localhost:6379/0"
            mock_cfg.return_value = cfg

            base_time = 100.0
            with patch("time.monotonic", return_value=base_time):
                # 1st failure: backoff = 1.0s -> next retry at 101.0
                p1 = await task_queue.get_arq_pool()
                assert p1 is None
                assert mock_create.call_count == 1
                assert task_queue._failure_count == 1

            # Request within backoff window (time=100.5): must NOT attempt create_pool
            with patch("time.monotonic", return_value=base_time + 0.5):
                p_early = await task_queue.get_arq_pool()
                assert p_early is None
                assert mock_create.call_count == 1  # Not incremented

            # Request after backoff window (time=101.1): attempts reconnect and fails again
            with patch("time.monotonic", return_value=base_time + 1.1):
                p2 = await task_queue.get_arq_pool()
                assert p2 is None
                assert mock_create.call_count == 2
                assert task_queue._failure_count == 2
                # Backoff doubled to 2.0s -> next retry at 101.1 + 2.0 = 103.1

            # Request within new backoff window (time=102.0): must NOT attempt create_pool
            with patch("time.monotonic", return_value=base_time + 2.0):
                p_early2 = await task_queue.get_arq_pool()
                assert p_early2 is None
                assert mock_create.call_count == 2  # Still 2

    @pytest.mark.asyncio
    async def test_successful_reconnection_restores_queued_execution(self):
        """Task execution falls back during outage and restores queued execution once reconnected."""
        from reversecore_mcp.core import task_queue

        mock_job = AsyncMock()
        mock_job.result.return_value = success("queued result")
        mock_pool = AsyncMock()
        mock_pool.enqueue_job.return_value = mock_job

        mock_create = AsyncMock(side_effect=[ConnectionError("Temporary Redis outage"), mock_pool])
        mock_inner = AsyncMock(return_value=success("fallback result"))

        async def mock_fallback(*args, **kwargs):
            return await mock_inner(*args, **kwargs)

        with (
            patch("reversecore_mcp.core.task_queue.create_pool", mock_create),
            patch("reversecore_mcp.core.task_queue.get_config") as mock_cfg,
        ):
            cfg = MagicMock()
            cfg.redis_url = "redis://localhost:6379/0"
            mock_cfg.return_value = cfg

            base_time = 100.0
            with patch("time.monotonic", return_value=base_time):
                # 1. During outage: falls back to direct execution
                res1 = await task_queue.run_task_or_fallback(
                    "task_smart_decompile",
                    mock_fallback,
                    "sample.bin",
                    "main",
                )
                assert res1.status == "success"
                assert res1.data == "fallback result"
                mock_inner.assert_called_once_with("sample.bin", "main", _bypass_queue=True)
                mock_pool.enqueue_job.assert_not_called()

            # 2. After Redis recovers and backoff window expires
            mock_inner.reset_mock()
            with patch("time.monotonic", return_value=base_time + 5.0):
                res2 = await task_queue.run_task_or_fallback(
                    "task_smart_decompile",
                    mock_fallback,
                    "sample.bin",
                    "main",
                )
                assert res2.status == "success"
                assert res2.data == "queued result"
                mock_inner.assert_not_called()
                mock_pool.enqueue_job.assert_called_once_with(
                    "task_smart_decompile", "sample.bin", "main"
                )
