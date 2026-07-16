"""Decorator for caching ToolResult outputs based on binary hash and arguments."""

from __future__ import annotations

import functools
import hashlib
import json
from inspect import iscoroutinefunction

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import metrics_collector
from reversecore_mcp.tools.radare2.r2_db import get_cached_result, set_cached_result

logger = get_logger(__name__)


def cache_tool_result(
    tool_name: str, ttl: int | None = None, cache_kwargs: list[str] | None = None
):
    """
    Decorator that caches ToolResult outputs based on binary hash and kwargs.

    Args:
        tool_name: Name of the tool (used for metrics and cache namespaces).
        ttl: Time to live in seconds (None = never expires).
        cache_kwargs: List of kwarg names to include in the cache key.
                     If None, all kwargs are included.

    Note:
        The decorated function must accept 'file_path' as a keyword argument
        or as the first positional argument.
    """

    def decorator(func):
        if not iscoroutinefunction(func):
            raise TypeError(
                f"cache_tool_result can only be applied to async functions ({func.__name__} is sync)"
            )

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            import inspect

            # Extract file_path
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            file_path = bound_args.arguments.get("file_path")
            if not file_path:
                logger.warning(f"Cache bypassed for {tool_name}: no file_path found in arguments")
                return await func(*args, **kwargs)

            # Build cache key from kwargs
            key_dict = {}
            for k, v in bound_args.arguments.items():
                if k == "file_path":
                    continue
                if cache_kwargs is not None and k not in cache_kwargs:
                    continue
                # Skip context parameters, self, etc.
                if k in ("ctx", "self", "cls"):
                    continue
                key_dict[k] = v

            # Serialize and hash the relevant kwargs
            try:
                sorted_json = json.dumps(key_dict, sort_keys=True)
            except TypeError:
                logger.warning(f"Cache bypassed for {tool_name}: kwargs not JSON serializable")
                return await func(*args, **kwargs)

            cache_key = hashlib.sha256(f"{tool_name}::{sorted_json}".encode()).hexdigest()

            # Attempt to get from cache
            cached_result = await get_cached_result(file_path, cache_key)
            if cached_result is not None:
                metrics_collector.record_cache_hit(tool_name)
                logger.debug(f"Cache HIT for {tool_name} on {file_path}")
                return cached_result

            # Cache miss, execute actual function
            metrics_collector.record_cache_miss(tool_name)
            logger.debug(f"Cache MISS for {tool_name} on {file_path}")

            result = await func(*args, **kwargs)

            # Cache the result if successful
            if isinstance(result, dict) and result.get("status") == "success":
                await set_cached_result(file_path, tool_name, cache_key, result, ttl)

            return result

        return async_wrapper

    return decorator
