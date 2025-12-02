"""
Performance metrics collection for monitoring.
"""

import inspect
import threading
import time
from collections import defaultdict
from functools import wraps
from typing import Any

from reversecore_mcp.core.result import ToolError


class MetricsCollector:
    """
    Thread-safe performance metrics collector.

    Uses threading.Lock to ensure safe concurrent access in multi-threaded
    or async environments (e.g., FastMCP server with multiple tool calls).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.tool_metrics: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "calls": 0,
                "errors": 0,
                "total_time": 0.0,
                "avg_time": 0.0,
                "max_time": 0.0,
                "min_time": float("inf"),
            }
        )
        self.cache_metrics: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "hits": 0,
                "misses": 0,
            }
        )
        self.circuit_breaker_states: dict[str, str] = {}

    def record_tool_execution(self, tool_name: str, execution_time: float, success: bool = True):
        """
        Record metrics for a tool execution (thread-safe).

        Args:
            tool_name: Name of the tool
            execution_time: Execution duration in seconds
            success: Whether the execution succeeded
        """
        with self._lock:
            metrics = self.tool_metrics[tool_name]
            metrics["calls"] += 1

            if not success:
                metrics["errors"] += 1

            metrics["total_time"] += execution_time
            metrics["avg_time"] = metrics["total_time"] / metrics["calls"]
            metrics["max_time"] = max(metrics["max_time"], execution_time)
            metrics["min_time"] = min(metrics["min_time"], execution_time)

    def record_cache_hit(self, cache_name: str):
        """Record a cache hit."""
        with self._lock:
            self.cache_metrics[cache_name]["hits"] += 1

    def record_cache_miss(self, cache_name: str):
        """Record a cache miss."""
        with self._lock:
            self.cache_metrics[cache_name]["misses"] += 1

    def record_circuit_breaker_state(self, tool_name: str, state: str):
        """Record circuit breaker state change."""
        with self._lock:
            self.circuit_breaker_states[tool_name] = state

    def get_metrics(self) -> dict[str, Any]:
        """Get all collected metrics (thread-safe)."""
        with self._lock:
            return {
                "tools": dict(self.tool_metrics),
                "cache": dict(self.cache_metrics),
                "circuit_breakers": dict(self.circuit_breaker_states),
            }

    def reset(self):
        """Reset all metrics (thread-safe)."""
        with self._lock:
            self.tool_metrics.clear()
            self.cache_metrics.clear()
            self.circuit_breaker_states.clear()


# Global metrics collector
metrics_collector = MetricsCollector()


def _determine_success(result: Any) -> bool:
    """
    Determine if a tool execution result indicates success.

    This helper function consolidates the success determination logic
    used in both sync and async wrappers, reducing code duplication.

    Args:
        result: The result returned by the tool function

    Returns:
        True if the result indicates success, False otherwise
    """
    if isinstance(result, ToolError):
        return False
    if hasattr(result, "status"):
        return result.status == "success"
    if isinstance(result, dict) and "status" in result:
        return result["status"] == "success"
    return True


def track_metrics(tool_name: str):
    """
    Decorator to track tool execution metrics.

    Supports both synchronous and asynchronous functions.
    Automatically detects function type using inspect.iscoroutinefunction().
    """

    def decorator(func):
        # Check if function is async
        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                success = True

                try:
                    result = await func(*args, **kwargs)
                    success = _determine_success(result)
                    return result
                except Exception:
                    success = False
                    raise
                finally:
                    execution_time = time.time() - start_time
                    metrics_collector.record_tool_execution(tool_name, execution_time, success)

            return async_wrapper
        else:

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                success = True

                try:
                    result = func(*args, **kwargs)
                    success = _determine_success(result)
                    return result
                except Exception:
                    success = False
                    raise
                finally:
                    execution_time = time.time() - start_time
                    metrics_collector.record_tool_execution(tool_name, execution_time, success)

            return sync_wrapper

    return decorator
