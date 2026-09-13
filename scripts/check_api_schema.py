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
EXPECTED_SCHEMA_SHA256 = "48f0ef470adb01e71a0d68bd84d1b1e4f332a46aa455b6b5a434f425e51408e7"


async def _canonical_schema() -> list[dict[str, Any]]:
    tools = await server.mcp.get_tools()
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.parameters,
        }
        for _, tool in sorted(tools.items())
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
    if digest != EXPECTED_SCHEMA_SHA256:
        raise SystemExit(
            "MCP tool schema changed: "
            f"expected {EXPECTED_SCHEMA_SHA256}, got {digest}. "
            "Review the API change and update the baseline deliberately."
        )
    print(f"MCP API schema OK: {len(schema)} tools, sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
