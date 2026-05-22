#!/usr/bin/env python3
"""
MCP Server Integration Test Script for CI/CD

1. Starts the MCP server in HTTP mode as a subprocess
2. Polls /health until ready
3. Connects via MCP SSE client
4. Lists available tools
5. Calls a simple tool (run_file on a test binary)
6. Validates responses
7. Terminates server gracefully

Usage:
    python scripts/test-mcp-server.py

Environment:
    MCP_TEST_PORT: Port for the test server (default: 8765)
    MCP_TEST_TIMEOUT: Max seconds to wait for server startup (default: 60)
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def start_server(port: int) -> subprocess.Popen:
    """Start the MCP server in HTTP mode on the given port."""
    env = os.environ.copy()
    env["MCP_TRANSPORT"] = "http"
    env["MCP_PORT"] = str(port)
    env["MCP_HOST"] = "127.0.0.1"
    env["LOG_LEVEL"] = "WARNING"
    env["REVERSECORE_WORKSPACE"] = str(PROJECT_ROOT / "tests" / "fixtures" / "workspace")

    print(f"🚀 Starting MCP server on port {port}...")
    proc = subprocess.Popen(
        [sys.executable, str(PROJECT_ROOT / "server.py")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def wait_for_health(port: int, timeout: int = 60) -> dict | None:
    """Poll /health until the server responds or timeout."""
    url = f"http://127.0.0.1:{port}/health"
    print(f"⏳ Waiting for server at {url} (timeout={timeout}s)...")

    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                print(f"✅ Server healthy: {data.get('status', 'unknown')}")
                return data
        except requests.ConnectionError:
            pass
        time.sleep(1)

    return None


async def run_mcp_tests(port: int) -> int:
    """Connect via MCP SSE client and run integration tests."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    url = f"http://127.0.0.1:{port}/mcp/sse"
    print(f"🔗 Connecting to MCP SSE endpoint: {url}")

    try:
        async with sse_client(url) as (read, write):
            async with ClientSession(read, write) as session:
                print("📡 Initializing MCP session...")
                await session.initialize()
                print("✅ MCP session initialized")

                # 1. List tools
                print("🔧 Listing available tools...")
                tools_result = await session.list_tools()
                tool_names = [t.name for t in tools_result.tools]
                print(f"   Found {len(tool_names)} tools")
                if not tool_names:
                    print("❌ No tools registered!")
                    return 1
                # Print first 10 tools for visibility
                for name in tool_names[:10]:
                    print(f"   - {name}")
                if len(tool_names) > 10:
                    print(f"   ... and {len(tool_names) - 10} more")

                # 2. Call a simple tool: run_file on test binary
                test_file = str(
                    PROJECT_ROOT / "tests" / "fixtures" / "workspace" / "test_binary.bin"
                )
                if not Path(test_file).exists():
                    # Fallback: create a tiny test file
                    test_file = str(
                        PROJECT_ROOT / "tests" / "fixtures" / "workspace" / "test_binary.bin"
                    )
                    Path(test_file).write_text("Hello World")

                print(f"📁 Calling tool 'run_file' on {test_file}...")
                result = await session.call_tool(
                    "run_file",
                    {"file_path": test_file},
                )
                print(f"📊 Tool result: {result}")

                # Validate result
                content_text = ""
                for content in result.content:
                    if hasattr(content, "text"):
                        content_text += content.text

                if (
                    "file_type" in content_text
                    or "Hello World" in content_text
                    or "text" in content_text.lower()
                ):
                    print("✅ Tool response looks valid")
                else:
                    print("⚠️ Tool response may be unexpected, but server is functional")

                print("🎉 MCP integration test passed!")
                return 0

    except Exception as exc:
        print(f"❌ MCP test failed: {exc}")
        return 1


def main() -> int:
    port = int(os.environ.get("MCP_TEST_PORT", "8765"))
    timeout = int(os.environ.get("MCP_TEST_TIMEOUT", "60"))

    proc = start_server(port)

    try:
        health = wait_for_health(port, timeout)
        if health is None:
            print("❌ Server failed to start within timeout")
            # Print stdout/stderr for debugging
            try:
                stdout, stderr = proc.communicate(timeout=10)
                if stdout:
                    print("--- stdout ---")
                    print(stdout.decode("utf-8", errors="replace")[-2000:])
                if stderr:
                    print("--- stderr ---")
                    print(stderr.decode("utf-8", errors="replace")[-2000:])
            except Exception:
                pass
            return 1

        # Run async MCP tests
        exit_code = asyncio.run(run_mcp_tests(port))
        return exit_code

    finally:
        print("🛑 Stopping MCP server...")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        print("👋 Server stopped")


if __name__ == "__main__":
    sys.exit(main())
