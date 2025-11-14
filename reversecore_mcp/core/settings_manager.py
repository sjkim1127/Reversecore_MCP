"""
Context-based settings manager using contextvars.

This module provides a context-based settings management system that allows
different settings for different execution contexts. This enables:
- Multi-tenant scenarios (different workspaces per client)
- Proper test isolation (no global state pollution)
- Dependency injection support

This replaces the global singleton pattern with context variables.
"""

from contextvars import ContextVar
from typing import Optional, AsyncContextManager
from contextlib import asynccontextmanager
import asyncio

from reversecore_mcp.core.config import Settings


# Context variable for settings
_settings_context: ContextVar[Optional[Settings]] = ContextVar('settings', default=None)


class SettingsManager:
    """
    Context-based settings manager.
    
    This manager provides settings that are scoped to the current context,
    allowing different settings for different execution contexts without
    global state pollution.
    """
    
    @staticmethod
    def get() -> Settings:
        """
        Get the current settings for this context.
        
        If no settings have been set in this context, creates and caches
        a new Settings instance.
        
        Returns:
            Settings instance for this context
        """
        settings = _settings_context.get()
        if settings is None:
            settings = Settings()
            _settings_context.set(settings)
        return settings
    
    @staticmethod
    def set(settings: Settings) -> None:
        """
        Set the settings for the current context.
        
        Args:
            settings: Settings instance to use in this context
        """
        _settings_context.set(settings)
    
    @staticmethod
    def clear() -> None:
        """
        Clear the settings for the current context.
        
        This is useful for test cleanup to ensure tests don't
        affect each other.
        """
        _settings_context.set(None)
    
    @staticmethod
    @asynccontextmanager
    async def with_settings(settings: Settings):
        """
        Context manager for executing code with specific settings.
        
        This allows temporary override of settings for a specific operation.
        
        Args:
            settings: Settings to use within the context
            
        Example:
            >>> custom_settings = Settings(reversecore_workspace="/custom/path")
            >>> async with SettingsManager.with_settings(custom_settings):
            ...     result = await some_tool_function()
        """
        # Save current settings
        previous = _settings_context.get()
        
        # Set new settings
        _settings_context.set(settings)
        
        try:
            yield settings
        finally:
            # Restore previous settings
            _settings_context.set(previous)


# For backward compatibility, provide a get_settings function
def get_settings() -> Settings:
    """
    Get the current settings (backward compatible API).
    
    Returns:
        Settings instance for this context
    """
    return SettingsManager.get()


def set_settings(settings: Settings) -> None:
    """
    Set the settings for the current context (backward compatible API).
    
    Args:
        settings: Settings instance to use
    """
    SettingsManager.set(settings)


def clear_settings() -> None:
    """
    Clear the settings for the current context (backward compatible API).
    """
    SettingsManager.clear()
