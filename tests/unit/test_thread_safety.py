"""Thread-safety tests for MetricsCollector."""

import asyncio
import threading
import time

import pytest

from reversecore_mcp.core.metrics import MetricsCollector, track_metrics
from reversecore_mcp.core.result import success


def test_metrics_collector_thread_safety():
    """Test that MetricsCollector is thread-safe under concurrent access."""
    collector = MetricsCollector()
    
    def record_metrics(thread_id: int):
        """Record metrics from a thread."""
        for i in range(100):
            collector.record_tool_execution(
                f"tool_{thread_id % 3}",  # 3 different tools
                execution_time=0.001 * i,
                success=(i % 2 == 0)
            )
    
    # Create 10 threads
    threads = []
    for i in range(10):
        thread = threading.Thread(target=record_metrics, args=(i,))
        threads.append(thread)
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for completion
    for thread in threads:
        thread.join()
    
    # Verify metrics were recorded correctly
    metrics = collector.get_metrics()
    
    # Each of 3 tools should have been called from multiple threads
    assert len(metrics) == 3
    
    # Total calls across all tools should be 10 threads * 100 calls = 1000
    total_calls = sum(m["calls"] for m in metrics.values())
    assert total_calls == 1000
    
    # Verify error counts (50% error rate per thread)
    total_errors = sum(m["errors"] for m in metrics.values())
    assert total_errors == 500


def test_metrics_collector_concurrent_reset():
    """Test that reset() is thread-safe during concurrent access."""
    collector = MetricsCollector()
    
    def record_and_reset():
        """Record metrics and occasionally reset."""
        for i in range(50):
            collector.record_tool_execution("test_tool", 0.001, True)
            if i % 10 == 0:
                collector.reset()
    
    threads = [threading.Thread(target=record_and_reset) for _ in range(5)]
    
    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # Should not crash (main assertion is no deadlock/race condition)
    final_metrics = collector.get_metrics()
    assert isinstance(final_metrics, dict)


def test_track_metrics_sync_function():
    """Test track_metrics decorator with synchronous function."""
    collector = MetricsCollector()
    
    @track_metrics("sync_tool")
    def sync_function():
        time.sleep(0.01)
        return success("test data")
    
    result = sync_function()
    
    assert result.status == "success"
    
    # Check metrics were recorded
    # Note: Uses global metrics_collector, so we check it exists
    from reversecore_mcp.core.metrics import metrics_collector
    metrics = metrics_collector.get_metrics()
    assert "sync_tool" in metrics
    assert metrics["sync_tool"]["calls"] >= 1


@pytest.mark.asyncio
async def test_track_metrics_async_function():
    """Test track_metrics decorator with asynchronous function."""
    
    @track_metrics("async_tool")
    async def async_function():
        await asyncio.sleep(0.01)
        return success("async data")
    
    result = await async_function()
    
    assert result.status == "success"
    
    # Check metrics were recorded
    from reversecore_mcp.core.metrics import metrics_collector
    metrics = metrics_collector.get_metrics()
    assert "async_tool" in metrics
    assert metrics["async_tool"]["calls"] >= 1


def test_track_metrics_error_handling():
    """Test that track_metrics correctly records failures."""
    
    @track_metrics("error_tool")
    def failing_function():
        raise ValueError("Test error")
    
    with pytest.raises(ValueError):
        failing_function()
    
    # Verify error was recorded
    from reversecore_mcp.core.metrics import metrics_collector
    metrics = metrics_collector.get_metrics()
    assert "error_tool" in metrics
    assert metrics["error_tool"]["errors"] >= 1


@pytest.mark.asyncio
async def test_track_metrics_async_error():
    """Test that track_metrics correctly records async failures."""
    
    @track_metrics("async_error_tool")
    async def async_failing_function():
        await asyncio.sleep(0.001)
        raise RuntimeError("Async test error")
    
    with pytest.raises(RuntimeError):
        await async_failing_function()
    
    # Verify error was recorded
    from reversecore_mcp.core.metrics import metrics_collector
    metrics = metrics_collector.get_metrics()
    assert "async_error_tool" in metrics
    assert metrics["async_error_tool"]["errors"] >= 1


def test_metrics_concurrent_get_metrics():
    """Test that get_metrics() is thread-safe."""
    collector = MetricsCollector()
    
    # Pre-populate some data
    for i in range(10):
        collector.record_tool_execution(f"tool_{i}", 0.001, True)
    
    results = []
    
    def get_metrics_repeatedly():
        """Get metrics multiple times."""
        for _ in range(50):
            metrics = collector.get_metrics()
            results.append(len(metrics))
    
    threads = [threading.Thread(target=get_metrics_repeatedly) for _ in range(5)]
    
    for thread in threads:
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # All reads should see consistent data (10 tools)
    assert all(count == 10 for count in results)


def test_metrics_timing_accuracy():
    """Test that execution times are recorded accurately."""
    collector = MetricsCollector()
    
    @track_metrics("timed_tool")
    def timed_function():
        time.sleep(0.05)  # 50ms
        return success("done")
    
    result = timed_function()
    
    assert result.status == "success"
    
    from reversecore_mcp.core.metrics import metrics_collector
    metrics = metrics_collector.get_metrics()
    
    assert "timed_tool" in metrics
    # Execution time should be around 50ms (with some tolerance)
    assert 0.04 < metrics["timed_tool"]["avg_time"] < 0.1
