"""Unit tests for resilience patterns (Circuit Breaker)."""

import time

import pytest

from reversecore_mcp.core.exceptions import ToolExecutionError
from reversecore_mcp.core.resilience import (
    CircuitBreaker,
    CircuitState,
    circuit_breaker,
    get_circuit_breaker,
)


@pytest.fixture(autouse=True)
def clear_breaker_registry():
    """Clear the circuit breaker registry before each test."""
    # Import the private variable only in the fixture
    from reversecore_mcp.core import resilience

    resilience._breakers.clear()
    yield
    resilience._breakers.clear()


class TestCircuitBreaker:
    """Tests for CircuitBreaker class."""

    def test_init(self):
        """Test circuit breaker initialization."""
        breaker = CircuitBreaker("test", failure_threshold=3, recovery_timeout=30)
        assert breaker.name == "test"
        assert breaker.failure_threshold == 3
        assert breaker.recovery_timeout == 30
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failures == 0

    def test_allow_request_when_closed(self):
        """Test that requests are allowed in CLOSED state."""
        breaker = CircuitBreaker("test")
        assert breaker.allow_request() is True

    def test_record_failure_increases_count(self):
        """Test that record_failure increases failure count."""
        breaker = CircuitBreaker("test", failure_threshold=3)

        breaker.record_failure()
        assert breaker.failures == 1
        assert breaker.state == CircuitState.CLOSED

        breaker.record_failure()
        assert breaker.failures == 2
        assert breaker.state == CircuitState.CLOSED

    def test_circuit_opens_on_threshold(self):
        """Test that circuit opens when failure threshold is reached."""
        breaker = CircuitBreaker("test", failure_threshold=3)

        # Record failures up to threshold
        breaker.record_failure()
        breaker.record_failure()
        breaker.record_failure()

        assert breaker.state == CircuitState.OPEN
        assert breaker.failures == 3

    def test_allow_request_when_open(self):
        """Test that requests are blocked in OPEN state."""
        breaker = CircuitBreaker("test", failure_threshold=2, recovery_timeout=60)

        # Trigger circuit open
        breaker.record_failure()
        breaker.record_failure()

        assert breaker.state == CircuitState.OPEN
        assert breaker.allow_request() is False

    def test_half_open_after_recovery_timeout(self):
        """Test that circuit enters HALF_OPEN after recovery timeout."""
        breaker = CircuitBreaker("test", failure_threshold=2, recovery_timeout=1)

        # Trigger circuit open
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(1.1)

        # Next request should transition to HALF_OPEN
        assert breaker.allow_request() is True
        assert breaker.state == CircuitState.HALF_OPEN

    def test_record_success_in_half_open_closes_circuit(self):
        """Test that success in HALF_OPEN state closes the circuit."""
        breaker = CircuitBreaker("test", failure_threshold=2, recovery_timeout=1)

        # Open the circuit
        breaker.record_failure()
        breaker.record_failure()

        # Wait and enter HALF_OPEN
        time.sleep(1.1)
        breaker.allow_request()
        assert breaker.state == CircuitState.HALF_OPEN

        # Record success
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failures == 0

    def test_record_failure_in_half_open_reopens_circuit(self):
        """Test that failure in HALF_OPEN state reopens the circuit."""
        breaker = CircuitBreaker("test", failure_threshold=2, recovery_timeout=1)

        # Open the circuit
        breaker.record_failure()
        breaker.record_failure()

        # Wait and enter HALF_OPEN
        time.sleep(1.1)
        breaker.allow_request()
        assert breaker.state == CircuitState.HALF_OPEN

        # Record failure
        breaker.record_failure()
        assert breaker.state == CircuitState.OPEN

    def test_record_success_in_closed_resets_failures(self):
        """Test that success in CLOSED state resets failure count."""
        breaker = CircuitBreaker("test", failure_threshold=3)

        breaker.record_failure()
        assert breaker.failures == 1

        breaker.record_success()
        assert breaker.failures == 0

    def test_allow_request_in_half_open(self):
        """Test that requests are allowed in HALF_OPEN state."""
        breaker = CircuitBreaker("test", failure_threshold=2, recovery_timeout=1)

        # Open the circuit
        breaker.record_failure()
        breaker.record_failure()

        # Wait and enter HALF_OPEN
        time.sleep(1.1)
        breaker.allow_request()

        # Should allow requests in HALF_OPEN
        assert breaker.allow_request() is True


class TestGetCircuitBreaker:
    """Tests for get_circuit_breaker function."""

    def test_creates_new_breaker(self):
        """Test that get_circuit_breaker creates a new breaker."""
        # Clear registry

        breaker = get_circuit_breaker("test_tool", failure_threshold=5)
        assert breaker.name == "test_tool"
        assert breaker.failure_threshold == 5

    def test_returns_existing_breaker(self):
        """Test that get_circuit_breaker returns existing breaker."""

        breaker1 = get_circuit_breaker("test_tool")
        breaker2 = get_circuit_breaker("test_tool")

        assert breaker1 is breaker2


class TestCircuitBreakerDecorator:
    """Tests for circuit_breaker decorator."""

    @pytest.mark.asyncio
    async def test_decorator_allows_request_when_closed(self):
        """Test that decorator allows request when circuit is closed."""

        @circuit_breaker("test_tool", failure_threshold=3)
        async def test_func():
            return "success"

        result = await test_func()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_decorator_records_success(self):
        """Test that decorator records successful execution."""

        @circuit_breaker("test_tool", failure_threshold=3)
        async def test_func():
            return "success"

        await test_func()

        breaker = get_circuit_breaker("test_tool")
        assert breaker.failures == 0

    @pytest.mark.asyncio
    async def test_decorator_records_failure(self):
        """Test that decorator records failed execution."""

        @circuit_breaker("test_tool", failure_threshold=3)
        async def test_func():
            raise RuntimeError("test error")

        with pytest.raises(RuntimeError, match="test error"):
            await test_func()

        breaker = get_circuit_breaker("test_tool")
        assert breaker.failures == 1

    @pytest.mark.asyncio
    async def test_decorator_blocks_when_open(self):
        """Test that decorator blocks requests when circuit is open."""

        @circuit_breaker("test_tool", failure_threshold=2, recovery_timeout=60)
        async def test_func():
            raise RuntimeError("test error")

        # Trigger failures to open circuit
        with pytest.raises(RuntimeError):
            await test_func()
        with pytest.raises(RuntimeError):
            await test_func()

        # Next request should be blocked
        with pytest.raises(ToolExecutionError, match="temporarily unavailable"):
            await test_func()

    @pytest.mark.asyncio
    async def test_decorator_recovers_after_success(self):
        """Test that circuit recovers after successful execution."""

        call_count = [0]

        @circuit_breaker("test_tool", failure_threshold=2, recovery_timeout=1)
        async def test_func():
            call_count[0] += 1
            if call_count[0] <= 2:
                raise RuntimeError("fail")
            return "success"

        # Fail twice to open circuit
        with pytest.raises(RuntimeError):
            await test_func()
        with pytest.raises(RuntimeError):
            await test_func()

        breaker = get_circuit_breaker("test_tool")
        assert breaker.state == CircuitState.OPEN

        # Wait for recovery
        time.sleep(1.1)

        # Should succeed and close circuit
        result = await test_func()
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_decorator_preserves_function_metadata(self):
        """Test that decorator preserves function metadata."""

        @circuit_breaker("test_tool")
        async def test_func():
            """Test function docstring."""
            return "success"

        assert test_func.__name__ == "test_func"
        assert test_func.__doc__ == "Test function docstring."

    def test_sync_decorator(self):
        """Test circuit_breaker_sync decorator."""
        from reversecore_mcp.core.resilience import circuit_breaker_sync

        @circuit_breaker_sync("sync_tool")
        def sync_func():
            return "success"

        result = sync_func()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_async_decorator(self):
        """Test circuit_breaker_async decorator."""
        from reversecore_mcp.core.resilience import circuit_breaker_async

        @circuit_breaker_async("async_tool")
        async def async_func():
            return "success"

        result = await async_func()
        assert result == "success"

    def test_sync_decorator_failure_and_blocked(self):
        """Test circuit_breaker_sync decorator failure and open behavior."""
        from reversecore_mcp.core.resilience import circuit_breaker_sync

        failures_count = 0

        @circuit_breaker_sync("sync_tool_fail", failure_threshold=2, recovery_timeout=60)
        def sync_func():
            nonlocal failures_count
            failures_count += 1
            raise RuntimeError("sync fail")

        # Trigger failure 1
        with pytest.raises(RuntimeError, match="sync fail"):
            sync_func()

        # Trigger failure 2 -> opens circuit
        with pytest.raises(RuntimeError, match="sync fail"):
            sync_func()

        breaker = get_circuit_breaker("sync_tool_fail")
        assert breaker.state == CircuitState.OPEN

        # Next request should be blocked
        with pytest.raises(ToolExecutionError, match="temporarily unavailable"):
            sync_func()

    @pytest.mark.asyncio
    async def test_async_decorator_failure_and_blocked(self):
        """Test circuit_breaker_async decorator failure and open behavior."""
        from reversecore_mcp.core.resilience import circuit_breaker_async

        failures_count = 0

        @circuit_breaker_async("async_tool_fail", failure_threshold=2, recovery_timeout=60)
        async def async_func():
            nonlocal failures_count
            failures_count += 1
            raise RuntimeError("async fail")

        # Trigger failure 1
        with pytest.raises(RuntimeError, match="async fail"):
            await async_func()

        # Trigger failure 2 -> opens circuit
        with pytest.raises(RuntimeError, match="async fail"):
            await async_func()

        breaker = get_circuit_breaker("async_tool_fail")
        assert breaker.state == CircuitState.OPEN

        # Next request should be blocked
        with pytest.raises(ToolExecutionError, match="temporarily unavailable"):
            await async_func()

    def test_general_decorator_with_sync_function(self):
        """Test general circuit_breaker decorator with a sync function (success, failure, and open)."""
        from reversecore_mcp.core.resilience import circuit_breaker

        failures_count = 0

        @circuit_breaker("general_sync_tool", failure_threshold=2, recovery_timeout=60)
        def sync_func(should_fail=False):
            nonlocal failures_count
            if should_fail:
                failures_count += 1
                raise RuntimeError("general sync fail")
            return "success"

        # Test success
        assert sync_func() == "success"

        # Test failure 1
        with pytest.raises(RuntimeError, match="general sync fail"):
            sync_func(should_fail=True)

        # Test failure 2 -> opens circuit
        with pytest.raises(RuntimeError, match="general sync fail"):
            sync_func(should_fail=True)

        breaker = get_circuit_breaker("general_sync_tool")
        assert breaker.state == CircuitState.OPEN

        # Test blocked
        with pytest.raises(ToolExecutionError, match="temporarily unavailable"):
            sync_func()

    def test_allow_request_invalid_state_fallback(self):
        """Test allow_request fallback for an invalid state."""
        breaker = CircuitBreaker("invalid_state_tool")
        breaker.state = "INVALID_STATE"  # Mock invalid state
        assert breaker.allow_request() is True
