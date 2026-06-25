"""ARQ-based task queue integration for Reversecore MCP.

Provides async job submission, background worker execution, result polling,
and resilient fallback to in-process execution when Redis is unavailable.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings
from arq.jobs import Job, JobStatus

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success

logger = get_logger(__name__)

# Global ARQ Redis connection pool
_arq_pool: Any = None
_queue_enabled: bool = True


async def get_arq_pool() -> Any:
    """Get or initialize the global ARQ Redis pool client."""
    global _arq_pool, _queue_enabled
    if not _queue_enabled:
        return None

    if _arq_pool is None:
        try:
            config = get_config()
            redis_settings = RedisSettings.from_dsn(config.redis_url)
            _arq_pool = await create_pool(redis_settings)
            logger.info("Initialized ARQ Redis task queue pool client.")
        except Exception as e:
            logger.warning(
                f"Failed to initialize ARQ task queue pool: {e}. Queue is disabled (falling back to direct execution)."
            )
            _queue_enabled = False
            return None

    return _arq_pool


async def close_arq_pool() -> None:
    """Close the global ARQ Redis connection pool."""
    global _arq_pool
    if _arq_pool is not None:
        try:
            await _arq_pool.close()
            logger.info("Closed ARQ Redis pool.")
        except Exception as e:
            logger.debug(f"Error closing ARQ pool: {e}")
        finally:
            _arq_pool = None


async def run_task_or_fallback(
    task_name: str,
    fallback_func: Callable[..., Coroutine[Any, Any, ToolResult]],
    *args: Any,
    run_async: bool = False,
    timeout_seconds: float | None = None,
    **kwargs: Any,
) -> ToolResult:
    """Submit a task to the queue or fall back to direct execution.

    Args:
        task_name: The registered ARQ function name (e.g. 'task_run_yara').
        fallback_func: The actual local implementation to run if queue is bypassed/unavailable.
        run_async: If True, return job ID immediately instead of waiting for result.
        timeout_seconds: Optional timeout for waiting for the job result.
        args, kwargs: Arguments passed to the function.

    Returns:
        ToolResult from the task execution or fallback.
    """
    import inspect

    sig = inspect.signature(fallback_func)
    has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
    has_bypass = "_bypass_queue" in sig.parameters

    def get_fallback_kwargs(bypass: bool = False) -> dict[str, Any]:
        fk = kwargs.copy()
        if bypass:
            fk["_bypass_queue"] = True
        if not (has_kwargs or has_bypass):
            fk.pop("_bypass_queue", None)
        return fk

    _bypass_queue = kwargs.get("_bypass_queue", False)
    if _bypass_queue:
        logger.debug(f"Bypassing queue for task '{task_name}' (executing directly in-process).")
        return await fallback_func(*args, **get_fallback_kwargs(bypass=True))

    pool = await get_arq_pool()
    if pool is None:
        logger.info(f"Task queue unavailable. Executing '{task_name}' directly in-process.")
        return await fallback_func(*args, **get_fallback_kwargs(bypass=True))

    try:
        # Enqueue the job on ARQ
        # Map arguments to worker task
        job = await pool.enqueue_job(task_name, *args, **kwargs)
        logger.info(f"Enqueued job {job.job_id} for task '{task_name}'.")

        if run_async:
            return success(
                {
                    "status": "queued",
                    "job_id": job.job_id,
                    "message": f"Job enqueued. Query status using 'get_job_result' tool with job ID: {job.job_id}",
                }
            )

        # Wait for the job to complete and return its result
        # Ensure we pass the configured default timeout or custom timeout
        effective_timeout = timeout_seconds or get_config().default_tool_timeout or 300.0
        try:
            result = await job.result(timeout=effective_timeout)
            return result
        except asyncio.TimeoutError:
            logger.error(f"Job {job.job_id} ({task_name}) timed out after {effective_timeout}s.")
            return failure(
                "TIMEOUT",
                f"Task execution timed out after {effective_timeout} seconds on queue.",
                timeout_seconds=int(effective_timeout),
            )

    except Exception as e:
        logger.warning(
            f"Queue submission failed for '{task_name}': {e}. Falling back to direct execution."
        )
        return await fallback_func(*args, **get_fallback_kwargs(bypass=True))


# =============================================================================
# ARQ Worker Task Definitions (Proxy handlers to avoid circular imports)
# =============================================================================


async def task_smart_decompile(
    ctx: Any, file_path: str, function_address: str, timeout: int, use_ghidra: bool
) -> ToolResult:
    """ARQ Worker proxy for smart_decompile (now maps to r2_decompile)."""
    logger.info(f"Worker executing task_smart_decompile for {function_address} in {file_path}")
    from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile

    return await r2_decompile(
        file_path=file_path,
        function_address=function_address,
        timeout=timeout,
    )


async def task_run_yara(ctx: Any, file_path: str, rule_file: str, timeout: int) -> ToolResult:
    """ARQ Worker proxy for run_yara."""
    logger.info(f"Worker executing task_run_yara for {file_path}")
    from reversecore_mcp.tools.malware.yara_tools import run_yara

    # We call run_yara with _bypass_queue=True to execute the actual logic in the worker
    return await run_yara(
        file_path=file_path,
        rule_file=rule_file,
        timeout=timeout,
        _bypass_queue=True,
    )


async def task_run_strings(
    ctx: Any, file_path: str, min_length: int, max_output_size: int, timeout: int
) -> ToolResult:
    """ARQ Worker proxy for run_strings."""
    logger.info(f"Worker executing task_run_strings for {file_path}")
    from reversecore_mcp.tools.analysis.static_analysis import run_strings

    return await run_strings(
        file_path=file_path,
        min_length=min_length,
        max_output_size=max_output_size,
        timeout=timeout,
        _bypass_queue=True,
    )


async def task_vulnerability_hunter(
    ctx: Any,
    file_path: str,
    max_depth: int,
    severity_filter: str,
    generate_yara: bool,
    timeout: int,
) -> ToolResult:
    """ARQ Worker proxy for vulnerability_hunter."""
    logger.info(f"Worker executing task_vulnerability_hunter for {file_path}")
    from reversecore_mcp.tools.malware.vulnerability_hunter import vulnerability_hunter

    return await vulnerability_hunter(
        file_path=file_path,
        max_depth=max_depth,
        severity_filter=severity_filter,
        generate_yara=generate_yara,
        timeout=timeout,
        _bypass_queue=True,
    )


# =============================================================================
# ARQ WorkerSettings class for standalone worker execution
# =============================================================================


async def startup(ctx: Any) -> None:
    """Worker startup handler."""
    logger.info("ARQ Worker starting up...")


async def shutdown(ctx: Any) -> None:
    """Worker shutdown handler."""
    logger.info("ARQ Worker shutting down...")


class WorkerSettings:
    """Settings class for ARQ Worker.

    Run using: `arq reversecore_mcp.core.task_queue.WorkerSettings`
    """

    functions = [
        task_smart_decompile,
        task_run_yara,
        task_run_strings,
        task_vulnerability_hunter,
    ]
    # Dynamically grab the redis url from configuration
    redis_settings = RedisSettings.from_dsn(get_config().redis_url)
    on_startup = startup
    on_shutdown = shutdown


async def get_job_result(job_id: str) -> ToolResult:
    """Retrieve the status and result of a background job from the task queue.

    Args:
        job_id: The ID of the queued job to check.

    Returns:
        ToolResult containing status details or the job output if finished.
    """
    pool = await get_arq_pool()
    if pool is None:
        return failure("QUEUE_UNAVAILABLE", "ARQ task queue Redis pool is not connected.")

    try:
        job = Job(job_id, pool)
        status = await job.status()

        if status == JobStatus.not_found:
            return failure("JOB_NOT_FOUND", f"Job with ID '{job_id}' was not found or has expired.")

        if status == JobStatus.complete:
            # Job is complete; retrieve result
            result = await job.result()
            # If the result is a dict (or parsed ToolSuccess/ToolError dict), return success
            if isinstance(result, (dict, list)):
                return success(result)
            return result

        # Job is still queued/in-progress/deferred
        return success(
            {
                "job_id": job_id,
                "status": status.value if hasattr(status, "value") else str(status),
                "message": f"Job is currently in status: '{status}'",
            }
        )
    except Exception as e:
        logger.error(f"Error checking job status for {job_id}: {e}")
        return failure("JOB_CHECK_ERROR", f"Failed to check job status: {e}")
