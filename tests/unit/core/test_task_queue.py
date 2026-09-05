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
