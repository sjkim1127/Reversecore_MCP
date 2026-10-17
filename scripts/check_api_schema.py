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
# plus issue #325's registration of recommend_analysis_plan,
# plus issue #320's registration of case state management tools (create_case_state, get_case_state, update_case_state, resume_case_state, list_case_states),
# plus issue #323's registration of priority queue tools (plan_next_analysis_targets, populate_case_queue_from_triage, add_priority_target, update_priority_target, resolve_target_blocker).
EXPECTED_TOOL_COUNT = 173
EXPECTED_SCHEMA_SHA256 = "61520ac433908776312f6581d86e8ed7f0c8f546f890058d51eb483d9cdc4660"
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
