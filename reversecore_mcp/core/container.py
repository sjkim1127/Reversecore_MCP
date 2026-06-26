"""
Dependency Injection Container for Reversecore_MCP

This module provides a lightweight dependency injection container that:
- Centralizes service registration and lifecycle management
- Enables easy testing through service replacement
- Supports singleton and factory patterns
- Allows async initialization of services

Usage:
    from reversecore_mcp.core.container import container, ServiceContainer

    # Register services
    container.register_singleton('r2_pool', R2ConnectionPool)
    container.register_factory('config', get_config)

    # Get services
    pool = container.get('r2_pool')

    # Override for testing
    container.override('r2_pool', mock_pool)

    # Reset overrides
    container.reset_overrides()
"""

import asyncio
import threading
from asyncio import create_task
from collections.abc import Callable
from typing import Any, TypeVar

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class ServiceContainer:
    """
    A lightweight dependency injection container.

    Features:
    - Singleton management (create once, reuse)
    - Factory support (create new instance each time)
    - Service overrides for testing
    - Async initialization support
    - Thread-safe operations
    """

    def __init__(self) -> None:
        self._singletons: dict[str, Any] = {}
        self._singleton_factories: dict[str, Callable[[], Any]] = {}
        self._factories: dict[str, Callable[[], Any]] = {}
        self._overrides: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._initialized = False

    def register_singleton(
        self,
        name: str,
        factory: Callable[[], T] | type[T],
        instance: T | None = None,
    ) -> None:
        """
        Register a singleton service.

        Args:
            name: Service name for lookup
            factory: Callable that creates the service instance
            instance: Optional pre-created instance (skips factory)
        """
        with self._lock:
            if instance is not None:
                self._singletons[name] = instance
            else:
                self._singleton_factories[name] = factory

    def register_factory(self, name: str, factory: Callable[[], T]) -> None:
        """
        Register a factory service (new instance each call).

        Args:
            name: Service name for lookup
            factory: Callable that creates a new service instance
        """
        with self._lock:
            self._factories[name] = factory

    def get(self, name: str) -> Any:
        """
        Get a service by name.

        Args:
            name: Service name

        Returns:
            Service instance

        Raises:
            KeyError: If service not registered
        """
        with self._lock:
            # Check overrides first (for testing)
            if name in self._overrides:
                return self._overrides[name]

            # Check existing singletons
            if name in self._singletons:
                return self._singletons[name]

            # Check singleton factories (lazy initialization)
            if name in self._singleton_factories:
                instance = self._singleton_factories[name]()
                self._singletons[name] = instance

                # If container is already initialized, start the service immediately
                if (
                    self._initialized
                    and hasattr(instance, "start")
                    and asyncio.iscoroutinefunction(instance.start)
                ):
                    # We can't await here as get is sync, but we can schedule it
                    # Warning: This creates a potential race condition for immediate use
                    # ideally initialize_async should have caught this.
                    # For safety, we log this event.
                    logger.warning(
                        f"Service '{name}' instantiated after initialization. Scheduling start."
                    )
                    create_task(self._safe_start(name, instance))

                return instance

            # Check factories
            if name in self._factories:
                return self._factories[name]()

            raise KeyError(f"Service '{name}' not registered")

    def override(self, name: str, instance: Any) -> None:
        """
        Override a service for testing.

        Args:
            name: Service name to override
            instance: Mock or test instance to use
        """
        with self._lock:
            self._overrides[name] = instance
            logger.debug(f"Service '{name}' overridden for testing")

    def reset_overrides(self) -> None:
        """Remove all test overrides."""
        with self._lock:
            self._overrides.clear()
            logger.debug("All service overrides cleared")

    def reset_singleton(self, name: str) -> None:
        """
        Reset a singleton (force re-creation on next get).

        Args:
            name: Service name to reset
        """
        with self._lock:
            if name in self._singletons:
                del self._singletons[name]
                logger.debug(f"Singleton '{name}' reset")

    def reset_all(self) -> None:
        """Reset all singletons and overrides."""
        with self._lock:
            self._singletons.clear()
            self._overrides.clear()
            logger.debug("All services reset")

    def has(self, name: str) -> bool:
        """Check if a service is registered."""
        with self._lock:
            return (
                name in self._overrides
                or name in self._singletons
                or name in self._singleton_factories
                or name in self._factories
            )

    async def _safe_start(self, name: str, instance: Any) -> None:
        """Helper to start a service safely in background."""
        try:
            await instance.start()
            logger.info(f"Async service '{name}' started (lazy)")
        except Exception as e:
            logger.error(f"Failed to start '{name}': {e}")

    async def initialize_async(self) -> None:
        """
        Initialize all async-capable singletons.

        Call this during application startup.
        """
        if self._initialized:
            return

        with self._lock:
            self._initialized = True

            # Eagerly instantiate all singleton factories to ensure they are started
            # This prevents race conditions where a service is accessed later but missed the start phase
            for name in list(self._singleton_factories.keys()):
                self.get(name)

            # Initialize singletons that have async start methods
            for name, instance in self._singletons.items():
                if hasattr(instance, "start") and asyncio.iscoroutinefunction(instance.start):
                    try:
                        await instance.start()
                        logger.info(f"Async service '{name}' started")
                    except Exception as e:
                        logger.error(f"Failed to start '{name}': {e}")

    async def shutdown_async(self) -> None:
        """
        Shutdown all async-capable singletons.

        Call this during application shutdown.
        """
        with self._lock:
            self._initialized = False

            # Stop singletons that have async stop methods
            for name, instance in self._singletons.items():
                if hasattr(instance, "stop") and asyncio.iscoroutinefunction(instance.stop):
                    try:
                        await instance.stop()
                        logger.info(f"Async service '{name}' stopped")
                    except Exception as e:
                        logger.error(f"Failed to stop '{name}': {e}")

                # Also try close_all for pools
                if hasattr(instance, "close_all"):
                    try:
                        instance.close_all()
                        logger.info(f"Service '{name}' closed")
                    except Exception as e:
                        logger.error(f"Failed to close '{name}': {e}")


# Global container instance
container = ServiceContainer()


def _initialize_default_services() -> None:
    """Register default services in the container."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.r2_pool import R2ConnectionPool
    from reversecore_mcp.core.resource_manager import ResourceManager

    # Register config as factory (always fresh)
    container.register_factory("config", get_config)

    # Register R2 pool as singleton
    container.register_singleton("r2_pool", R2ConnectionPool)

    # Register resource manager as singleton
    container.register_singleton("resource_manager", ResourceManager)


# Initialize default services on module load
_initialize_default_services()


# Convenience functions for common services
def get_r2_pool():
    """Get the R2 connection pool instance."""
    return container.get("r2_pool")


def get_resource_manager():
    """Get the resource manager instance."""
    return container.get("resource_manager")


def get_ghidra_service():
    """Get the Ghidra service instance."""
    return None


def get_config_from_container():
    """Get configuration from container."""
    return container.get("config")
