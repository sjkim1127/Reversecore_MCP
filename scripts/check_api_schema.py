#!/usr/bin/env python3
"""Verify the published MCP tool schema has not changed unexpectedly."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Running a script sets ``sys.path[0]`` to ``scripts/``. Put the checkout root
# first so the snapshot always describes the source tree being verified rather
# than an unrelated installed distribution.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reversecore_mcp import server

# Update deliberately when a reviewed API change is made. The canonical form
# makes this independent of dictionary insertion order and JSON whitespace.
EXPECTED_TOOL_COUNT = 151
# Canonical schema SHA-256 for FastMCP 3.4.4 (pinned in project requirements).
# This reviewed API change adds the optional source port to TCP stream reconstruction.
EXPECTED_SCHEMA_SHA256 = "26c519ec5e0e8c16abbd91b07303b3534c0bc51c52a7fdbfc4e1b3522664a6ff"
VALID_SCHEMA_SHA256S = {EXPECTED_SCHEMA_SHA256}


async def _canonical_schema() -> list[dict[str, Any]]:
    if hasattr(server.mcp, "list_tools"):
        tools = await server.mcp.list_tools()
        tools_list = tools if isinstance(tools, list) else list(tools.values())
    elif hasattr(server.mcp, "get_tools"):
        tools = await server.mcp.get_tools()
        tools_list = tools if isinstance(tools, list) else list(tools.values())
    else:
        raise AttributeError("No tool listing method found on FastMCP instance")

    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.parameters,
        }
        for tool in sorted(tools_list, key=lambda t: t.name)
    ]


async def main() -> int:
    """Validate tool count and canonical schema digest."""
    schema = await _canonical_schema()
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(encoded).hexdigest()

    if len(schema) != EXPECTED_TOOL_COUNT:
        raise SystemExit(
            f"MCP tool count changed: expected {EXPECTED_TOOL_COUNT}, got {len(schema)}"
        )
    if digest not in VALID_SCHEMA_SHA256S:
        raise SystemExit(
            "MCP tool schema changed: "
            f"expected {EXPECTED_SCHEMA_SHA256}, got {digest}. "
            "Review the API change and update the baseline deliberately."
        )
    print(f"MCP API schema OK: {len(schema)} tools, sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
