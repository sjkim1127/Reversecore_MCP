"""Compact Schema Profile for Reversecore_MCP.

Optimizes advertised FastMCP tool schemas and docstrings for low-context LLMs
(Claude Code, Cursor, Kimi, Moonshot, Gemini) by:
1. Stripping verbose docstring sections (Args, Returns, Examples, Raises)
   down to a concise 1-2 sentence functional summary.
2. Stripping non-essential JSON schema annotations ('title', 'examples', 'example').
3. Flattening excessively nested schema properties deeper than max_depth (default: 8)
   to shallow object definitions, preventing LLM gateway schema rejection.
4. Preserving canonical server-side validation and execution without any loss of functionality.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Sequence
from typing import Any

from fastmcp import FastMCP

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Section headers that mark the start of parameter documentation in docstrings
_DOCSTRING_SPLIT_PATTERN = re.compile(
    r"\n\s*(?:Args|Parameters|Arguments|Returns|Yields|Raises|Examples?|Notes?|See Also):\s*",
    re.IGNORECASE,
)

ANNOTATION_KEYS_TO_STRIP = {"title", "examples", "example"}


def compact_tool_description(description: str | None, max_length: int = 250) -> str:
    """Trim a verbose docstring down to its primary summary sentence/paragraph.

    Args:
        description: Raw docstring of the tool.
        max_length: Maximum allowed length for the compacted summary.

    Returns:
        Compacted tool description string.
    """
    if not description or not description.strip():
        return ""

    text = description.strip()
    # 1. Split at Args:, Returns:, Examples:, etc.
    parts = _DOCSTRING_SPLIT_PATTERN.split(text, maxsplit=1)
    summary = parts[0].strip()

    # 2. Normalize whitespace
    summary = " ".join(summary.split())

    # 3. If still overly long, take the first sentence or truncate cleanly
    if len(summary) > max_length:
        first_sentence = summary.split(". ")[0].strip()
        if first_sentence and len(first_sentence) < max_length:
            summary = first_sentence + "."
        else:
            summary = summary[: max_length - 3].rstrip() + "..."

    return summary


def compact_json_schema(
    schema: dict[str, Any],
    max_depth: int = 8,
    current_depth: int = 0,
) -> dict[str, Any]:
    """Recursively strip non-essential annotations and cap schema nesting depth.

    Args:
        schema: Input JSON schema dictionary.
        max_depth: Maximum recursion depth for nested properties.
        current_depth: Current depth in the schema tree.

    Returns:
        Compacted JSON schema dictionary.
    """
    result: dict[str, Any] = {}

    for key, value in schema.items():
        if key in ANNOTATION_KEYS_TO_STRIP:
            continue

        if key == "properties" and isinstance(value, dict):
            if current_depth >= max_depth:
                # Clamp nested properties to generic object
                continue
            compacted_props: dict[str, Any] = {}
            for prop_name, prop_schema in value.items():
                if isinstance(prop_schema, dict):
                    compacted_props[prop_name] = compact_json_schema(
                        prop_schema,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                    )
                else:
                    compacted_props[prop_name] = prop_schema
            result["properties"] = compacted_props
        elif key == "items" and isinstance(value, dict):
            if current_depth >= max_depth:
                result["items"] = {}
            else:
                result["items"] = compact_json_schema(
                    value,
                    max_depth=max_depth,
                    current_depth=current_depth + 1,
                )
        else:
            result[key] = copy.deepcopy(value)

    return result


def setup_compact_schema_mode(mcp_server: FastMCP, profile: str | None = None) -> None:
    """Configure Compact Schema Profile on the FastMCP instance.

    Args:
        mcp_server: FastMCP server instance.
        profile: Active schema profile string ('compact' or 'full').
    """
    normalized = (profile or "").strip().lower()
    if normalized != "compact":
        logger.debug("Compact schema profile inactive (profile=%s)", profile)
        return

    logger.info(
        "⚡ Activating Compact Schema Profile: Pruning descriptions and deep parameter schemas for LLMs."
    )

    orig_list_tools = mcp_server.list_tools

    async def compact_list_tools(*args: Any, **kwargs: Any) -> Sequence[Any]:
        tools = await orig_list_tools(*args, **kwargs)
        compacted = []
        for t in tools:
            try:
                new_desc = compact_tool_description(t.description)
                new_params = compact_json_schema(t.parameters)
                compacted.append(
                    t.model_copy(update={"description": new_desc, "parameters": new_params})
                )
            except Exception as e:
                logger.debug(
                    "Failed to compact schema for tool %s: %s", getattr(t, "name", "unknown"), e
                )
                compacted.append(t)
        return compacted

    mcp_server.list_tools = compact_list_tools  # type: ignore[method-assign]
