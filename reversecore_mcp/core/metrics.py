"""
Performance metrics collection for monitoring.
"""

import time
from collections import defaultdict
from typing import Dict, Any
from functools import wraps


class MetricsCollector:
    """Collects and reports performance metrics."""
    
    def __init__(self):
        self.tool_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "calls": 0,
            "errors": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
            "max_time": 0.0,
            "min_time": float('inf'),
        })
    
    def record_tool_execution(self, tool_name: str, execution_time: float, success: bool = True):
        """Record metrics for a tool execution."""
        metrics = self.tool_metrics[tool_name]
        metrics["calls"] += 1
        
        if not success:
            metrics["errors"] += 1
        
        metrics["total_time"] += execution_time
        metrics["avg_time"] = metrics["total_time"] / metrics["calls"]
        metrics["max_time"] = max(metrics["max_time"], execution_time)
        metrics["min_time"] = min(metrics["min_time"], execution_time)
    
    def get_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get all collected metrics."""
        return dict(self.tool_metrics)
    
    def reset(self):
        """Reset all metrics."""
        self.tool_metrics.clear()


# Global metrics collector
metrics_collector = MetricsCollector()


def track_metrics(tool_name: str):
    """Decorator to track tool execution metrics."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            
            try:
                result = func(*args, **kwargs)
                if "Error" in str(result):
                    success = False
                return result
            except Exception as e:
                success = False
                raise
            finally:
                execution_time = time.time() - start_time
                metrics_collector.record_tool_execution(tool_name, execution_time, success)
        
        return wrapper
    return decorator
