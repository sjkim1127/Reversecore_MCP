"""
Performance metrics collection for monitoring.
"""

import asyncio
import inspect
import threading
import time
from collections import defaultdict
from functools import wraps
from typing import Any, Dict

from reversecore_mcp.core.result import ToolError


class MetricsCollector:
    """
    Thread-safe performance metrics collector.
    
    Uses threading.Lock to ensure safe concurrent access in multi-threaded
    or async environments (e.g., FastMCP server with multiple tool calls).
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self.tool_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "calls": 0,
            "errors": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
            "max_time": 0.0,
            "min_time": float('inf'),
        })
    
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
    
    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all collected metrics (thread-safe)."""
        with self._lock:
            return dict(self.tool_metrics)
    
    def reset(self):
        """Reset all metrics (thread-safe)."""
        with self._lock:
            self.tool_metrics.clear()


# Global metrics collector
metrics_collector = MetricsCollector()


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

                    if isinstance(result, ToolError):
                        success = False
                    elif hasattr(result, "status"):
                        success = getattr(result, "status") == "success"
                    elif isinstance(result, dict) and "status" in result:
                        success = result["status"] == "success"
                    else:
                        success = True

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

                    if isinstance(result, ToolError):
                        success = False
                    elif hasattr(result, "status"):
                        success = getattr(result, "status") == "success"
                    elif isinstance(result, dict) and "status" in result:
                        success = result["status"] == "success"
                    else:
                        success = True

                    return result
                except Exception:
                    success = False
                    raise
                finally:
                    execution_time = time.time() - start_time
                    metrics_collector.record_tool_execution(tool_name, execution_time, success)
            
            return sync_wrapper
    
    return decorator
