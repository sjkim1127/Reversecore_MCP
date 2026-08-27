#!/usr/bin/env python3
"""Strict MCP registry and core-tool verification inside a running container."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp")
REQUIRED_TOOLS = frozenset(
    {
        "get_server_health",
        "list_workspace",
        "run_file",
        "run_strings",
    }
)


def extract_result_text(result: Any) -> str:
    """Extract textual or structured content from an MCP call result."""
    chunks: list[str] = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text is not None:
            chunks.append(str(text))

    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    if structured is not None:
        chunks.append(json.dumps(structured, sort_keys=True, default=str))

    return "\n".join(chunks).strip()


def require_success(result: Any, tool_name: str) -> str:
    """Reject MCP protocol errors, empty responses, and explicit failure payloads."""
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        raise AssertionError(f"{tool_name} returned an MCP error result")

    text = extract_result_text(result)
    if not text:
        raise AssertionError(f"{tool_name} returned no content")

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None

    if isinstance(payload, dict):
        status = str(payload.get("status", "")).lower()
        if payload.get("success") is False or payload.get("ok") is False:
            raise AssertionError(f"{tool_name} returned a failure payload: {text[:300]}")
        if status in {"error", "failed", "failure"}:
            raise AssertionError(f"{tool_name} returned status={status}: {text[:300]}")

    return text


def select_binary() -> Path:
    """Select a deterministic ELF fixture available in both CI workflows."""
    candidates = (
        Path("/app/workspace/binaries/hello_x64"),
        Path("/app/workspace/sample.elf"),
        Path("/app/workspace/smoke_test_elf"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"No ELF fixture found in: {', '.join(map(str, candidates))}")


async def main() -> int:
    """Connect to the server and prove registry and core tools actually work."""
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        print(f"❌ mcp library is required for E2E verification: {exc}")
        return 1

    try:
        target = select_binary()
        strings_target = Path("/app/workspace/test_binary.bin")
        if not strings_target.is_file():
            raise FileNotFoundError(f"Missing strings fixture: {strings_target}")

        async with streamable_http_client(MCP_SERVER_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools_result = await session.list_tools()
                tool_names = {tool.name for tool in tools_result.tools}
                missing = sorted(REQUIRED_TOOLS - tool_names)
                if missing:
                    raise AssertionError(f"Required MCP tools are not registered: {missing}")
                print(f"✅ Registered tools: {len(tool_names)}; required core tools present")

                health_text = require_success(
                    await session.call_tool("get_server_health", {}),
                    "get_server_health",
                )
                print(f"✅ get_server_health: {health_text[:160]}")

                workspace_text = require_success(
                    await session.call_tool("list_workspace", {}), "list_workspace"
                )
                if target.name.lower() not in workspace_text.lower():
                    raise AssertionError(
                        f"list_workspace did not expose fixture {target.name}: {workspace_text[:300]}"
                    )
                print(f"✅ list_workspace contains {target.name}")

                file_text = require_success(
                    await session.call_tool("run_file", {"file_path": str(target)}),
                    "run_file",
                )
                if "elf" not in file_text.lower():
                    raise AssertionError(
                        f"run_file did not identify ELF content: {file_text[:300]}"
                    )
                print(f"✅ run_file identified ELF: {file_text[:160]}")

                strings_text = require_success(
                    await session.call_tool(
                        "run_strings",
                        {"file_path": str(strings_target), "min_length": 4},
                    ),
                    "run_strings",
                )
                if "hello world" not in strings_text.lower():
                    raise AssertionError(
                        f"run_strings did not return the known fixture string: {strings_text[:300]}"
                    )
                print(f"✅ run_strings returned known content: {strings_text[:160]}")

        print("🎉 Strict MCP registry and invocation verification passed")
        return 0
    except Exception as exc:
        print(f"❌ Strict MCP verification failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
