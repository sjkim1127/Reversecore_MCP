"""
Resilience patterns for Reversecore_MCP.

This module implements the Circuit Breaker pattern to prevent cascading failures
when external tools (like Radare2 or Ghidra) become unstable.
"""

import time
import functools
from enum import Enum
from typing import Dict

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.exceptions import ToolExecutionError

logger = get_logger(__name__)


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

    def __init__(
        self, name: str, failure_threshold: int = 5, recovery_timeout: int = 60
    ):
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
                logger.warning(
                    f"Circuit {self.name} opened due to {self.failures} failures"
                )
                self.state = CircuitState.OPEN
                self.next_attempt_time = time.time() + self.recovery_timeout

        elif self.state == CircuitState.HALF_OPEN:
            logger.warning(f"Circuit {self.name} failed recovery, reopening")
            self.state = CircuitState.OPEN
            self.next_attempt_time = time.time() + self.recovery_timeout


# Global registry of circuit breakers
_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker for the given name."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name, **kwargs)
    return _breakers[name]


def circuit_breaker(
    tool_name: str, failure_threshold: int = 5, recovery_timeout: int = 60
):
    """
    Decorator to apply circuit breaker pattern to a function.
    """

    def decorator(func):
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

        return wrapper

    return decorator
