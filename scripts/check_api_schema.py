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
# Primary canonical schema SHA-256 for fastmcp>=3.4.4 (pinned in requirements.txt)
EXPECTED_SCHEMA_SHA256 = "cc8d360eec0b2805030a7278eafc9f92c6166564d2f90b191f310d71da51994c"
# Allowed digests across supported FastMCP runtime versions (3.4.x vs legacy 2.14.x)
VALID_SCHEMA_SHA256S = {
    EXPECTED_SCHEMA_SHA256,
    "48f0ef470adb01e71a0d68bd84d1b1e4f332a46aa455b6b5a434f425e51408e7",
}


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
