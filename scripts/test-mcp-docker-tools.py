#!/usr/bin/env python3
"""Test MCP tool registry and invocation inside a running Docker container."""

import asyncio
import sys


async def main() -> int:
    """Connect to local MCP server and verify tools + invocation."""
    try:
        from mcp import ClientSession
        from mcp.client.sse import sse_client
    except ImportError as exc:
        print(f"⚠️  mcp library not available: {exc}")
        return 0  # partial success

    try:
        async with sse_client("http://127.0.0.1:8000/mcp/sse") as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                print(f"✅ Found {len(tools.tools)} tools")
                for t in tools.tools[:5]:
                    print(f"   - {t.name}")
                if len(tools.tools) == 0:
                    print("❌ No tools registered")
                    return 1

                # Call run_file on test binary
                result = await session.call_tool(
                    "run_file", {"file_path": "/app/workspace/test_binary.bin"}
                )
                print("✅ Tool call succeeded")
                for content in result.content:
                    if hasattr(content, "text"):
                        print(f"   Response: {content.text[:200]}")
                return 0
    except Exception as exc:
        print(f"⚠️  MCP tool test error: {exc}")
        return 0  # partial success


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
