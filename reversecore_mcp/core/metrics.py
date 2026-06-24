"""
Performance metrics collection for monitoring.
"""

import inspect
import threading
import time
from functools import wraps
from typing import Any

from reversecore_mcp.core.result import ToolError


class MetricsCollector:
    """
    Thread-safe performance metrics collector with bounded memory.

    Uses threading.Lock to ensure safe concurrent access in multi-threaded
    or async environments (e.g., FastMCP server with multiple tool calls).

    Memory protection: Limits entries to MAX_ENTRIES to prevent unbounded growth.
    """

    # Maximum number of unique entries per category to prevent memory leaks
    MAX_TOOL_ENTRIES = 500
    MAX_CACHE_ENTRIES = 200
    MAX_CIRCUIT_BREAKER_ENTRIES = 100

    def __init__(self):
        self._lock = threading.Lock()
        # Use regular dict instead of defaultdict for LRU control
        self.tool_metrics: dict[str, dict[str, Any]] = {}
        self.cache_metrics: dict[str, dict[str, int]] = {}
        self.circuit_breaker_states: dict[str, str] = {}

    def _get_default_tool_metrics(self) -> dict[str, Any]:
        """Create default metrics dict for a new tool."""
        return {
            "calls": 0,
            "errors": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
            "max_time": 0.0,
            "min_time": float("inf"),
        }

    def _get_default_cache_metrics(self) -> dict[str, int]:
        """Create default metrics dict for a new cache."""
        return {"hits": 0, "misses": 0}

    def _evict_oldest(self, d: dict, max_entries: int) -> None:
        """Evict oldest entries if dict exceeds max size (FIFO eviction)."""
        while len(d) > max_entries:
            oldest_key = next(iter(d))
            del d[oldest_key]

    def record_tool_execution(self, tool_name: str, execution_time: float, success: bool = True):
        """
        Record metrics for a tool execution (thread-safe, bounded).

        Args:
            tool_name: Name of the tool
            execution_time: Execution duration in seconds
            success: Whether the execution succeeded
        """
        with self._lock:
            if tool_name not in self.tool_metrics:
                self._evict_oldest(self.tool_metrics, self.MAX_TOOL_ENTRIES - 1)
                self.tool_metrics[tool_name] = self._get_default_tool_metrics()

            metrics = self.tool_metrics[tool_name]
            metrics["calls"] += 1

            if not success:
                metrics["errors"] += 1

            metrics["total_time"] += execution_time
            metrics["avg_time"] = metrics["total_time"] / metrics["calls"]
            metrics["max_time"] = max(metrics["max_time"], execution_time)
            metrics["min_time"] = min(metrics["min_time"], execution_time)

    def record_cache_hit(self, cache_name: str):
        """Record a cache hit (thread-safe, bounded)."""
        with self._lock:
            if cache_name not in self.cache_metrics:
                self._evict_oldest(self.cache_metrics, self.MAX_CACHE_ENTRIES - 1)
                self.cache_metrics[cache_name] = self._get_default_cache_metrics()
            self.cache_metrics[cache_name]["hits"] += 1

    def record_cache_miss(self, cache_name: str):
        """Record a cache miss (thread-safe, bounded)."""
        with self._lock:
            if cache_name not in self.cache_metrics:
                self._evict_oldest(self.cache_metrics, self.MAX_CACHE_ENTRIES - 1)
                self.cache_metrics[cache_name] = self._get_default_cache_metrics()
            self.cache_metrics[cache_name]["misses"] += 1

    def record_circuit_breaker_state(self, tool_name: str, state: str):
        """Record circuit breaker state change (thread-safe, bounded)."""
        with self._lock:
            if tool_name not in self.circuit_breaker_states:
                self._evict_oldest(
                    self.circuit_breaker_states, self.MAX_CIRCUIT_BREAKER_ENTRIES - 1
                )
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
