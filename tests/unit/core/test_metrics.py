"""Unit tests for metrics collection."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.metrics import (
    MetricsCollector,
    _determine_success,
)
from reversecore_mcp.core.result import ToolError


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_evict_oldest_tool_metrics(self):
        """Eviction runs when tool_metrics exceeds max entries."""
        collector = MetricsCollector()
        with patch.object(collector, "MAX_TOOL_ENTRIES", 2):
            collector.record_tool_execution("tool_a", 0.1)
            collector.record_tool_execution("tool_b", 0.2)
            collector.record_tool_execution("tool_c", 0.3)  # evicts oldest
            m = collector.get_metrics()
            assert "tools" in m
            assert len(m["tools"]) <= 2

    def test_evict_oldest_cache_metrics(self):
        """Eviction runs when cache_metrics exceeds max entries."""
        collector = MetricsCollector()
        with patch.object(collector, "MAX_CACHE_ENTRIES", 2):
            collector.record_cache_miss("c1")
            collector.record_cache_miss("c2")
            collector.record_cache_miss("c3")  # evicts oldest
            m = collector.get_metrics()
            assert "cache" in m
            assert len(m["cache"]) <= 2

    def test_record_tool_execution_failure(self):
        """Record tool execution with success=False increments errors."""
        collector = MetricsCollector()
        collector.record_tool_execution("failing_tool", 1.0, success=False)
        m = collector.get_metrics()
        assert m["tools"]["failing_tool"]["errors"] == 1
        assert m["tools"]["failing_tool"]["calls"] == 1

    def test_evict_oldest_circuit_breaker_states(self):
        """Eviction runs when circuit_breaker_states exceeds max entries."""
        collector = MetricsCollector()
        with patch.object(collector, "MAX_CIRCUIT_BREAKER_ENTRIES", 2):
            collector.record_circuit_breaker_state("t1", "open")
            collector.record_circuit_breaker_state("t2", "closed")
            collector.record_circuit_breaker_state("t3", "half-open")  # evicts oldest (t1)
            m = collector.get_metrics()
            assert "circuit_breakers" in m
            assert len(m["circuit_breakers"]) <= 2
            assert "t1" not in m["circuit_breakers"]
            assert m["circuit_breakers"]["t2"] == "closed"
            assert m["circuit_breakers"]["t3"] == "half-open"

    def test_record_cache_hit_eviction(self):
        """Eviction runs when cache hits exceed max entries."""
        collector = MetricsCollector()
        with patch.object(collector, "MAX_CACHE_ENTRIES", 2):
            collector.record_cache_hit("c1")
            collector.record_cache_hit("c2")
            collector.record_cache_hit("c3")  # evicts oldest (c1)
            m = collector.get_metrics()
            assert len(m["cache"]) <= 2
            assert "c1" not in m["cache"]

    def test_reset(self):
        """Reset clears all collected metrics."""
        collector = MetricsCollector()
        collector.record_tool_execution("t", 0.5)
        collector.record_cache_hit("c")
        collector.record_circuit_breaker_state("b", "open")

        # Verify populated
        m = collector.get_metrics()
        assert len(m["tools"]) > 0
        assert len(m["cache"]) > 0
        assert len(m["circuit_breakers"]) > 0

        collector.reset()

        # Verify empty
        m_empty = collector.get_metrics()
        assert len(m_empty["tools"]) == 0
        assert len(m_empty["cache"]) == 0
        assert len(m_empty["circuit_breakers"]) == 0


class TestDetermineSuccess:
    """Tests for _determine_success helper."""

    def test_tool_error_returns_false(self):
        assert _determine_success(ToolError(error_code="CODE", message="msg")) is False

    def test_object_with_status_success(self):
        class R:
            status = "success"

        assert _determine_success(R()) is True

    def test_object_with_status_error(self):
        class R:
            status = "error"

        assert _determine_success(R()) is False

    def test_dict_status_success(self):
        assert _determine_success({"status": "success"}) is True

    def test_dict_status_error(self):
        assert _determine_success({"status": "error"}) is False

    def test_fallback_returns_true(self):
        """Result with no status attribute falls through to True."""
        assert _determine_success(None) is True
        assert _determine_success(object()) is True
        assert _determine_success({"other": 1}) is True


class TestTrackMetrics:
    """Tests for track_metrics decorator."""

    def test_sync_success(self):
        from reversecore_mcp.core.metrics import track_metrics

        @track_metrics("test_tool")
        def my_tool():
            return {"status": "success"}

        result = my_tool()
        assert result["status"] == "success"

    def test_sync_error(self):
        from reversecore_mcp.core.metrics import track_metrics

        @track_metrics("test_tool")
        def my_tool():
            return {"status": "error"}

        result = my_tool()
        assert result["status"] == "error"

    def test_exception(self):
        from reversecore_mcp.core.metrics import track_metrics

        @track_metrics("test_tool")
        def my_tool():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            my_tool()

    @pytest.mark.asyncio
    async def test_async_success(self):
        from reversecore_mcp.core.metrics import track_metrics

        @track_metrics("test_tool")
        async def my_tool():
            return {"status": "success"}

        result = await my_tool()
        assert result["status"] == "success"

    def test_sync_records_metrics(self):
        from reversecore_mcp.core.metrics import metrics_collector, track_metrics

        with patch.object(metrics_collector, "record_tool_execution") as mock_record:

            @track_metrics("test_tool")
            def my_tool():
                return {"status": "success"}

            result = my_tool()
            assert result["status"] == "success"
            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_records_metrics(self):
        from reversecore_mcp.core.metrics import metrics_collector, track_metrics

        with patch.object(metrics_collector, "record_tool_execution") as mock_record:

            @track_metrics("test_tool")
            async def my_tool():
                return {"status": "success"}

            result = await my_tool()
            assert result["status"] == "success"
            mock_record.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_exception(self):
        from reversecore_mcp.core.metrics import track_metrics

        @track_metrics("test_tool")
        async def my_tool():
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await my_tool()
