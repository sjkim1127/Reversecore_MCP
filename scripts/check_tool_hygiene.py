#!/usr/bin/env python3
"""Enforce strict hygiene on all FastMCP tools and dynamic resource templates.

Verifies:
1. Tool count and registry health (151 registered tools).
2. Every tool has a descriptive, comprehensive description.
3. Every tool input schema is well-formed with parameter definitions.
4. All dynamic context resource templates are properly registered with valid MIME types.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path

# Ensure repository root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reversecore_mcp import server

EXPECTED_MIN_TOOLS = 151
EXPECTED_RESOURCE_TEMPLATES = {
    "reversecore://{filename}/metadata",
    "reversecore://{filename}/func/{address}/xrefs",
    "reversecore://{filename}/func/{address}/context",
    "reversecore://{filename}/memory_map",
    "reversecore://{filename}/signatures",
    "reversecore://{filename}/imports",
    "reversecore://{filename}/exports",
}


async def check_tool_hygiene() -> int:
    """Validate all tools and resource templates against quality contracts."""
    violations: list[str] = []

    # 1. Retrieve tools
    if hasattr(server.mcp, "list_tools"):
        tools_raw = await server.mcp.list_tools()
        tools = tools_raw if isinstance(tools_raw, list) else list(tools_raw.values())
    elif hasattr(server.mcp, "get_tools"):
        tools_raw = await server.mcp.get_tools()
        tools = tools_raw if isinstance(tools_raw, list) else list(tools_raw.values())
    else:
        print("ERROR: FastMCP server has no tool listing method", file=sys.stderr)
        return 1

    if len(tools) < EXPECTED_MIN_TOOLS:
        violations.append(
            f"Expected at least {EXPECTED_MIN_TOOLS} registered tools, found {len(tools)}"
        )

    # 2. Inspect each tool
    for tool in tools:
        name = getattr(tool, "name", None) or "unnamed"

        # Check description
        desc = getattr(tool, "description", None) or ""
        if not desc.strip():
            violations.append(f"Tool '{name}' has an empty or missing description")
        elif len(desc.strip()) < 15:
            violations.append(
                f"Tool '{name}' description is too short ({len(desc.strip())} chars): '{desc}'"
            )

        # Check input schema
        params = getattr(tool, "parameters", None)
        if not isinstance(params, dict):
            violations.append(f"Tool '{name}' parameters is not a dict: {type(params)}")
        else:
            if params.get("type") != "object":
                violations.append(f"Tool '{name}' parameter schema type is not 'object'")
            if "properties" not in params:
                violations.append(f"Tool '{name}' schema lacks 'properties' mapping")

    # 3. Inspect resource templates
    templates_fn = getattr(
        server.mcp,
        "list_resource_templates",
        getattr(server.mcp, "get_resource_templates", None),
    )
    if templates_fn is None:
        violations.append("FastMCP server has no resource template listing method")
    else:
        res = templates_fn()
        templates = await res if inspect.isawaitable(res) else res
        found_uris = set()
        for tmpl in templates:
            uri = getattr(tmpl, "uri_template", getattr(tmpl, "uriTemplate", None)) or str(tmpl)
            found_uris.add(uri)
            mime = getattr(tmpl, "mime_type", getattr(tmpl, "mimeType", None))
            if mime != "text/markdown":
                violations.append(
                    f"Resource template '{uri}' MIME type expected 'text/markdown', got '{mime}'"
                )

        missing_uris = EXPECTED_RESOURCE_TEMPLATES - found_uris
        if missing_uris:
            violations.append(f"Missing expected resource templates: {sorted(missing_uris)}")

    if violations:
        print(f"FAILED: Found {len(violations)} tool/resource hygiene defect(s):", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        return 1

    print(
        f"SUCCESS: All {len(tools)} tools and {len(EXPECTED_RESOURCE_TEMPLATES)} resource templates passed hygiene contracts."
    )
    return 0


def main() -> int:
    return asyncio.run(check_tool_hygiene())


if __name__ == "__main__":
    sys.exit(main())
