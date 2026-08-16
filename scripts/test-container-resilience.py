#!/usr/bin/env python3
"""Strict resilience checks for a running Reversecore MCP container."""

from __future__ import annotations

import asyncio
import os
import sys
import time
import urllib.request

HEALTH_URL = os.environ.get("HEALTH_URL", "http://127.0.0.1:8000/health")
MCP_SSE_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp/sse")
HEALTH_REQUESTS = 20
MCP_SESSIONS = 3
MAX_HEALTH_LATENCY_SECONDS = 2.0


def health_request() -> bool:
    """Return True only for an HTTP 200 health response."""
    try:
        request = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False


async def concurrent_health_checks() -> tuple[int, int]:
    """Run concurrent health requests without allowing soft failures."""
    results = await asyncio.gather(
        *(asyncio.to_thread(health_request) for _ in range(HEALTH_REQUESTS))
    )
    passed = sum(1 for result in results if result)
    return passed, HEALTH_REQUESTS - passed


async def mcp_session_probe(index: int) -> int:
    """Open an independent MCP session and list registered tools."""
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    async with sse_client(MCP_SSE_URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            count = len(tools.tools)
            if count < 4:
                raise AssertionError(f"MCP probe {index} discovered only {count} tools")
            return count


async def test_resilience() -> int:
    """Verify concurrent HTTP and MCP requests remain healthy and responsive."""
    try:
        print(f"📡 Running {HEALTH_REQUESTS} concurrent health checks...")
        passed, failed = await concurrent_health_checks()
        print(f"   health: {passed} passed, {failed} failed")
        if failed:
            raise AssertionError(f"{failed} concurrent health request(s) failed")

        print(f"📡 Opening {MCP_SESSIONS} concurrent MCP sessions...")
        counts = await asyncio.gather(*(mcp_session_probe(i) for i in range(MCP_SESSIONS)))
        print(f"   MCP tool counts: {counts}")
        if len(set(counts)) != 1:
            raise AssertionError(
                f"Concurrent MCP sessions observed inconsistent registries: {counts}"
            )

        print("⏱️  Measuring health endpoint latency...")
        started = time.perf_counter()
        if not await asyncio.to_thread(health_request):
            raise AssertionError("Final health request failed")
        elapsed = time.perf_counter() - started
        print(f"   response time: {elapsed:.3f}s")
        if elapsed > MAX_HEALTH_LATENCY_SECONDS:
            raise AssertionError(
                f"Health endpoint exceeded {MAX_HEALTH_LATENCY_SECONDS:.1f}s: {elapsed:.3f}s"
            )

        print("✅ Strict container resilience checks passed")
        return 0
    except Exception as exc:
        print(f"❌ Container resilience check failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(test_resilience()))
