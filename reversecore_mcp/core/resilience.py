"""
Resilience patterns for Reversecore_MCP.

This module implements the Circuit Breaker pattern to prevent cascading failures
when external tools (like Radare2 or Ghidra) become unstable.
"""

import functools
import inspect
import time
from collections.abc import Callable
from enum import Enum
from typing import TypeVar

from reversecore_mcp.core.exceptions import ToolExecutionError
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

F = TypeVar("F", bound=Callable)


class CircuitState(Enum):
    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"  # Failing, requests blocked
    HALF_OPEN = "HALF_OPEN"  # Testing recovery


class CircuitBreaker:
    """
    Circuit Breaker implementation.

    If a tool fails 'failure_threshold' times within a window, the circuit opens
    and blocks requests for 'recovery_timeout' seconds.
    """

    def __init__(self, name: str, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self.state = CircuitState.CLOSED
        self.failures = 0
        self.last_failure_time = 0.0
        self.next_attempt_time = 0.0

    def allow_request(self) -> bool:
        """Check if a request is allowed."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if time.time() >= self.next_attempt_time:
                logger.info(f"Circuit {self.name} entering HALF_OPEN state")
                self.state = CircuitState.HALF_OPEN
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # Allow one request to test recovery
            # In a real concurrent system, we might need a lock here to allow ONLY one.
            # For simplicity, we allow requests in HALF_OPEN, and the first success/fail determines fate.
            return True

        return True

    def record_success(self):
        """Record a successful execution."""
        if self.state == CircuitState.HALF_OPEN:
            logger.info(f"Circuit {self.name} recovered (CLOSED)")
            self.state = CircuitState.CLOSED
            self.failures = 0
        elif self.state == CircuitState.CLOSED:
            self.failures = 0

    def record_failure(self):
        """Record a failed execution."""
        self.failures += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.CLOSED:
            if self.failures >= self.failure_threshold:
                logger.warning(f"Circuit {self.name} opened due to {self.failures} failures")
                self.state = CircuitState.OPEN
                self.next_attempt_time = time.time() + self.recovery_timeout

        elif self.state == CircuitState.HALF_OPEN:
            logger.warning(f"Circuit {self.name} failed recovery, reopening")
            self.state = CircuitState.OPEN
            self.next_attempt_time = time.time() + self.recovery_timeout


# Global registry of circuit breakers
_breakers: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker for the given name."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name, **kwargs)
    return _breakers[name]


def circuit_breaker(
    tool_name: str, failure_threshold: int = 5, recovery_timeout: int = 60
) -> Callable[[F], F]:
    """
    Decorator to apply circuit breaker pattern to a function.

    Automatically detects if the decorated function is async or sync
    and applies the appropriate wrapper.

    Args:
        tool_name: Name of the tool for circuit breaker tracking
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery

    Returns:
        Decorated function with circuit breaker protection
    """

    def decorator(func: F) -> F:
        breaker = get_circuit_breaker(
            tool_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

        def _get_error_message() -> str:
            """Generate error message for circuit open state."""
            remaining = int(breaker.next_attempt_time - time.time())
            return (
                f"Tool '{tool_name}' is temporarily unavailable due to repeated failures. "
                f"Please try again in {max(0, remaining)} seconds."
            )

        # Check if function is async
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                if not breaker.allow_request():
                    raise ToolExecutionError(_get_error_message())

                try:
                    result = await func(*args, **kwargs)
                    breaker.record_success()
                    return result
                except Exception:
                    breaker.record_failure()
                    raise

            return async_wrapper  # type: ignore[return-value]

        # Sync version
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not breaker.allow_request():
                raise ToolExecutionError(_get_error_message())

            try:
                result = func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception:
                breaker.record_failure()
                raise

        return sync_wrapper  # type: ignore[return-value]

    return decorator


def circuit_breaker_sync(
    tool_name: str, failure_threshold: int = 5, recovery_timeout: int = 60
) -> Callable[[F], F]:
    """
    Explicit sync-only circuit breaker decorator.

    Use this when you want to explicitly mark a function as sync,
    or when the auto-detection in circuit_breaker doesn't work correctly.
    """

    def decorator(func: F) -> F:
        breaker = get_circuit_breaker(
            tool_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not breaker.allow_request():
                raise ToolExecutionError(
                    f"Tool '{tool_name}' is temporarily unavailable due to repeated failures. "
                    f"Please try again in {int(breaker.next_attempt_time - time.time())} seconds."
                )

            try:
                result = func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception:
                breaker.record_failure()
                raise

        return wrapper  # type: ignore[return-value]

    return decorator


def circuit_breaker_async(
    tool_name: str, failure_threshold: int = 5, recovery_timeout: int = 60
) -> Callable[[F], F]:
    """
    Explicit async-only circuit breaker decorator.

    Use this when you want to explicitly mark a function as async,
    or when the auto-detection in circuit_breaker doesn't work correctly.
    """

    def decorator(func: F) -> F:
        breaker = get_circuit_breaker(
            tool_name,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if not breaker.allow_request():
                raise ToolExecutionError(
                    f"Tool '{tool_name}' is temporarily unavailable due to repeated failures. "
                    f"Please try again in {int(breaker.next_attempt_time - time.time())} seconds."
                )

            try:
                result = await func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception:
                breaker.record_failure()
                raise

        return wrapper  # type: ignore[return-value]

    return decorator
