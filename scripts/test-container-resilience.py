#!/usr/bin/env python3
"""Test container restart resilience and concurrent request handling."""

import asyncio
import sys
import time

import aiohttp

HEALTH_URL = "http://127.0.0.1:8000/health"
MCP_SSE_URL = "http://127.0.0.1:8000/mcp/sse"


async def concurrent_health_check(count: int = 10) -> tuple[int, int]:
    """Send N concurrent /health requests."""
    passed = 0
    failed = 0

    async def fetch(session: aiohttp.ClientSession) -> bool:
        try:
            async with session.get(HEALTH_URL, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                return resp.status == 200
        except Exception:
            return False

    async with aiohttp.ClientSession() as session:
        tasks = [fetch(session) for _ in range(count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if r is True:
                passed += 1
            else:
                failed += 1

    return passed, failed


async def test_resilience() -> int:
    """Run resilience tests against the MCP server."""
    print("🔄 Testing container resilience...")

    # 1. Concurrent health checks
    print("\n📡 Concurrent health checks (10 requests)...")
    passed, failed = await concurrent_health_check(10)
    print(f"   {passed} passed, {failed} failed")
    if failed > 5:
        print("❌ Too many concurrent health check failures")
        return 1

    # 2. SSE endpoint availability
    print("\n📡 Checking SSE endpoint availability...")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(MCP_SSE_URL, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status in (200, 405):
                    print(f"   ✅ SSE responds with HTTP {resp.status}")
                else:
                    print(f"   ⚠️  SSE responds with HTTP {resp.status}")
    except Exception as exc:
        print(f"   ⚠️  SSE error: {exc}")

    # 3. Response time check
    print("\n⏱️  Response time check...")
    async with aiohttp.ClientSession() as session:
        start = time.perf_counter()
        async with session.get(HEALTH_URL, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            elapsed = time.perf_counter() - start
            print(f"   Response time: {elapsed:.3f}s")
            if elapsed > 2.0:
                print("   ⚠️  Health check is slow (>2s)")

    print("\n✅ Resilience tests complete")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_resilience()))
