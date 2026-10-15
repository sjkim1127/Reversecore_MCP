"""Generic batch execution tool for repeated analysis and inspection operations."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any

from pydantic import Field

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success

MAX_BATCH_SIZE = 50
MAX_CONCURRENCY = 16
DEFAULT_ITEM_TIMEOUT = 30
DEFAULT_TOTAL_TIMEOUT = 120
MAX_ITEM_TIMEOUT = 300
MAX_TOTAL_TIMEOUT = 600

DISALLOWED_BATCH_TOOLS = frozenset({"batch_execute"})


def _extract_item_result(raw_result: Any) -> tuple[str, Any, dict[str, Any] | None]:
    """Extract (status, data, error) from a tool execution result.

    Handles FastMCP ToolResult instances, wrapped dict envelopes, and raw payloads.
    """
    if hasattr(raw_result, "structured_content") and isinstance(
        raw_result.structured_content, dict
    ):
        structured = raw_result.structured_content.get("result", raw_result.structured_content)
        if isinstance(structured, dict):
            status = structured.get("status", "success" if structured.get("ok", True) else "error")
            data = structured.get("data")
            error = structured.get("error")
            return status, data, error

    if hasattr(raw_result, "content") and raw_result.content:
        first = raw_result.content[0]
        text = getattr(first, "text", str(first))
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                status = parsed.get("status", "success" if parsed.get("ok", True) else "error")
                return status, parsed.get("data"), parsed.get("error")
        except Exception:
            return "success", text, None

    if isinstance(raw_result, dict):
        status = raw_result.get("status", "success" if raw_result.get("ok", True) else "error")
        return status, raw_result.get("data"), raw_result.get("error")

    return "success", raw_result, None


async def _resolve_server() -> Any:
    """Resolve the active FastMCP server instance."""
    from reversecore_mcp import server

    return server.mcp


@log_execution(tool_name="batch_execute")
@track_metrics("batch_execute")
@handle_tool_errors
async def batch_execute(
    operations: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "List of tool invocation specifications. Each item must contain 'tool' (str) "
                "and 'arguments' (dict). An optional 'id' (str) can be provided for correlation. "
                "Example: [{'id': 'fn1', 'tool': 'r2_decompile', 'arguments': {'file_path': 'sample.bin', 'function_address': 'main'}}]"
            ),
        ),
    ],
    max_concurrency: Annotated[
        int,
        Field(
            default=4,
            ge=1,
            le=16,
            description="Maximum number of parallel operations (default: 4, max: 16). Set to 1 for strict sequential execution.",
        ),
    ] = 4,
    item_timeout: Annotated[
        int,
        Field(
            default=30,
            ge=1,
            le=300,
            description="Per-item timeout in seconds (default: 30s, max: 300s).",
        ),
    ] = 30,
    total_timeout: Annotated[
        int,
        Field(
            default=120,
            ge=5,
            le=600,
            description="Overall timeout for entire batch execution in seconds (default: 120s, max: 600s).",
        ),
    ] = 120,
    stop_on_error: Annotated[
        bool,
        Field(
            default=False,
            description="If True, halts execution on first item error and returns partial results.",
        ),
    ] = False,
) -> ToolResult:
    """Execute a batch of repeated or heterogeneous analysis operations within bounded resources.

    Enables AI agents to perform bulk decompilations, cross-reference searches,
    tagging, and static analysis sweeps in a single MCP request, eliminating round-trips
    while isolating individual item failures and enforcing strict execution quotas.

    Args:
        operations: List of operation dicts, each with 'tool' (str) and 'arguments' (dict).
        max_concurrency: Maximum parallel operations (1 to 16, default 4).
        item_timeout: Per-item timeout in seconds (1 to 300s, default 30s).
        total_timeout: Total batch timeout in seconds (5 to 600s, default 120s).
        stop_on_error: If True, halts further batch execution on first item error.

    Returns:
        ToolResult containing:
        - requested: Total operations submitted
        - completed: Count of successfully executed operations
        - failed: Count of failed/timed-out operations
        - results: Sorted list of successful execution payloads with original index & id
        - errors: Sorted list of failed items with error codes and diagnostics
    """
    if not operations:
        return failure(
            "EMPTY_BATCH",
            "Batch cannot be empty. Provide at least one operation in 'operations'.",
            recovery_hint="Provide a list containing between 1 and 50 tool operation specifications.",
        )

    if len(operations) > MAX_BATCH_SIZE:
        return failure(
            "BATCH_SIZE_EXCEEDED",
            f"Batch size {len(operations)} exceeds maximum allowed limit of {MAX_BATCH_SIZE}.",
            recovery_hint=f"Split your workload into smaller batches of at most {MAX_BATCH_SIZE} operations each.",
        )

    server_inst = await _resolve_server()
    raw_tools = await server_inst.list_tools()
    tools_list = raw_tools if isinstance(raw_tools, list) else list(raw_tools.values())
    tool_map = {t.name: t for t in tools_list}

    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    semaphore = asyncio.Semaphore(max(1, min(max_concurrency, MAX_CONCURRENCY)))
    stop_event = asyncio.Event()

    async def _execute_single(idx: int, op: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        op_id = op.get("id") if isinstance(op, dict) else None
        tool_name = op.get("tool") if isinstance(op, dict) else None

        if not isinstance(op, dict) or not tool_name or not isinstance(tool_name, str):
            err_item = {
                "index": idx,
                "id": op_id,
                "tool": str(tool_name) if tool_name else "",
                "status": "error",
                "error": {
                    "code": "INVALID_OPERATION_SPEC",
                    "message": "Each operation item must be a dictionary containing a non-empty string 'tool' field.",
                    "retryable": False,
                },
            }
            if stop_on_error:
                stop_event.set()
            return "error", err_item

        if tool_name in DISALLOWED_BATCH_TOOLS:
            err_item = {
                "index": idx,
                "id": op_id,
                "tool": tool_name,
                "status": "error",
                "error": {
                    "code": "DISALLOWED_BATCH_TOOL",
                    "message": f"Recursive or nested invocation of '{tool_name}' within a batch is prohibited.",
                    "retryable": False,
                },
            }
            if stop_on_error:
                stop_event.set()
            return "error", err_item

        tool_obj = tool_map.get(tool_name)
        if tool_obj is None:
            err_item = {
                "index": idx,
                "id": op_id,
                "tool": tool_name,
                "status": "error",
                "error": {
                    "code": "TOOL_NOT_FOUND",
                    "message": f"Tool '{tool_name}' is not registered or not permitted under the active profile.",
                    "retryable": False,
                },
            }
            if stop_on_error:
                stop_event.set()
            return "error", err_item

        arguments = op.get("arguments") or {}
        if not isinstance(arguments, dict):
            err_item = {
                "index": idx,
                "id": op_id,
                "tool": tool_name,
                "status": "error",
                "error": {
                    "code": "INVALID_ARGUMENTS",
                    "message": "Tool 'arguments' must be a dictionary of parameter key-value pairs.",
                    "retryable": False,
                },
            }
            if stop_on_error:
                stop_event.set()
            return "error", err_item

        async with semaphore:
            if stop_event.is_set():
                return "cancelled", {
                    "index": idx,
                    "id": op_id,
                    "tool": tool_name,
                    "status": "error",
                    "error": {
                        "code": "BATCH_HALTED",
                        "message": "Execution halted due to earlier item failure (stop_on_error=True).",
                        "retryable": True,
                    },
                }

            try:
                raw_res = await asyncio.wait_for(
                    tool_obj.run(arguments),
                    timeout=float(item_timeout),
                )
                status, data, error = _extract_item_result(raw_res)

                if status == "success":
                    return "result", {
                        "index": idx,
                        "id": op_id,
                        "tool": tool_name,
                        "status": "success",
                        "data": data,
                    }

                err_item = {
                    "index": idx,
                    "id": op_id,
                    "tool": tool_name,
                    "status": "error",
                    "error": error
                    or {
                        "code": "TOOL_ERROR",
                        "message": "Tool execution returned error status.",
                        "retryable": False,
                    },
                }
                if stop_on_error:
                    stop_event.set()
                return "error", err_item

            except asyncio.TimeoutError:
                err_item = {
                    "index": idx,
                    "id": op_id,
                    "tool": tool_name,
                    "status": "error",
                    "error": {
                        "code": "ITEM_TIMEOUT",
                        "message": f"Operation timed out after {item_timeout} seconds.",
                        "retryable": True,
                    },
                }
                if stop_on_error:
                    stop_event.set()
                return "error", err_item
            except Exception as exc:
                err_item = {
                    "index": idx,
                    "id": op_id,
                    "tool": tool_name,
                    "status": "error",
                    "error": {
                        "code": "EXECUTION_ERROR",
                        "message": str(exc),
                        "retryable": False,
                    },
                }
                if stop_on_error:
                    stop_event.set()
                return "error", err_item

    tasks = [asyncio.create_task(_execute_single(i, op)) for i, op in enumerate(operations)]

    try:
        outcomes = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=float(total_timeout),
        )
        for idx, outcome in enumerate(outcomes):
            if isinstance(outcome, BaseException):
                errors.append(
                    {
                        "index": idx,
                        "id": operations[idx].get("id")
                        if isinstance(operations[idx], dict)
                        else None,
                        "tool": operations[idx].get("tool", "")
                        if isinstance(operations[idx], dict)
                        else "",
                        "status": "error",
                        "error": {
                            "code": "UNHANDLED_EXCEPTION",
                            "message": str(outcome),
                            "retryable": False,
                        },
                    }
                )
            elif isinstance(outcome, tuple):
                kind, payload = outcome
                if kind == "result":
                    results.append(payload)
                else:
                    errors.append(payload)
    except asyncio.TimeoutError:
        # Total batch timeout expired: collect whatever completed and mark remaining
        for idx, task in enumerate(tasks):
            op = operations[idx] if isinstance(operations[idx], dict) else {}
            op_id = op.get("id")
            tool_name = op.get("tool", "")
            if task.done() and not task.cancelled():
                try:
                    outcome = task.result()
                    if isinstance(outcome, tuple):
                        kind, payload = outcome
                        if kind == "result":
                            results.append(payload)
                        else:
                            errors.append(payload)
                        continue
                except Exception as exc:
                    errors.append(
                        {
                            "index": idx,
                            "id": op_id,
                            "tool": tool_name,
                            "status": "error",
                            "error": {
                                "code": "UNHANDLED_EXCEPTION",
                                "message": str(exc),
                                "retryable": False,
                            },
                        }
                    )
                    continue

            # Task was not completed before total timeout
            task.cancel()
            errors.append(
                {
                    "index": idx,
                    "id": op_id,
                    "tool": tool_name,
                    "status": "error",
                    "error": {
                        "code": "TOTAL_TIMEOUT",
                        "message": f"Batch reached total timeout of {total_timeout}s before this item completed.",
                        "retryable": True,
                    },
                }
            )

    results.sort(key=lambda x: x["index"])
    errors.sort(key=lambda x: x["index"])

    return success(
        {
            "requested": len(operations),
            "completed": len(results),
            "failed": len(errors),
            "results": results,
            "errors": errors,
        },
        description=f"Batch execution completed: {len(results)}/{len(operations)} successful, {len(errors)} failed.",
    )
