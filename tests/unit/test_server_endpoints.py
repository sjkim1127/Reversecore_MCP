"""
Unit tests for server endpoints (health and metrics).
"""

import pytest


def test_metrics_collector_tracks_tools():
    """Test that metrics collector properly tracks tool executions."""
    from reversecore_mcp.core.metrics import metrics_collector
    
    # Reset metrics
    metrics_collector.reset()
    
    # Record some tool executions
    metrics_collector.record_tool_execution("test_tool", 1.5, success=True)
    metrics_collector.record_tool_execution("test_tool", 2.0, success=True)
    metrics_collector.record_tool_execution("test_tool", 0.5, success=False)
    
    # Get metrics
    metrics = metrics_collector.get_metrics()
    
    # Verify metrics were recorded
    assert "test_tool" in metrics
    assert metrics["test_tool"]["calls"] == 3
    assert metrics["test_tool"]["errors"] == 1
    assert metrics["test_tool"]["total_time"] == 4.0
    assert metrics["test_tool"]["avg_time"] == pytest.approx(4.0 / 3, 0.01)
    assert metrics["test_tool"]["max_time"] == 2.0
    assert metrics["test_tool"]["min_time"] == 0.5


def test_track_metrics_decorator():
    """Test that @track_metrics decorator records metrics."""
    from reversecore_mcp.core.metrics import track_metrics, metrics_collector
    from reversecore_mcp.core.result import failure, success
    
    # Reset metrics
    metrics_collector.reset()
    
    # Create a test function with the decorator
    @track_metrics("test_decorated_tool")
    def test_func(should_error=False):
        if should_error:
            return failure("INTERNAL_ERROR", "boom")
        return success("ok")
    
    # Call the function
    test_func()
    test_func()
    test_func(should_error=True)
    
    # Get metrics
    metrics = metrics_collector.get_metrics()
    
    # Verify metrics were recorded
    assert "test_decorated_tool" in metrics
    assert metrics["test_decorated_tool"]["calls"] == 3
    assert metrics["test_decorated_tool"]["errors"] == 1  # One error from error string

