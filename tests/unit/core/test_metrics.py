"""Unit tests for metrics collection."""

from unittest.mock import patch

import pytest

from reversecore_mcp.core.result import ToolError
from reversecore_mcp.core.metrics import (
    MetricsCollector,
    _determine_success,
)


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
