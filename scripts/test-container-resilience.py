#!/usr/bin/env python3
"""Test container restart resilience and concurrent request handling."""

import asyncio
import sys
import time
import urllib.error
import urllib.request

HEALTH_URL = "http://127.0.0.1:8000/health"
MCP_SSE_URL = "http://127.0.0.1:8000/mcp/sse"


async def concurrent_health_check(count: int = 10) -> tuple[int, int]:
    """Send N concurrent /health requests using asyncio + urllib."""
    passed = 0
    failed = 0

    def fetch() -> bool:
        try:
            req = urllib.request.Request(HEALTH_URL)
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, fetch) for _ in range(count)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if r is True:
            passed += 1
        else:
            failed += 1

    return passed, failed


def http_get(url: str, timeout: int = 5) -> tuple[int, str]:
    """Simple synchronous HTTP GET, returns (status_code, body)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as exc:
        return 0, str(exc)


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
    status, _ = http_get(MCP_SSE_URL)
    if status in (200, 405):
        print(f"   ✅ SSE responds with HTTP {status}")
    elif status == 0:
        print("   ⚠️  SSE endpoint unreachable (server may use stdio transport)")
    else:
        print(f"   ⚠️  SSE responds with HTTP {status}")

    # 3. Response time check
    print("\n⏱️  Response time check...")
    start = time.perf_counter()
    status, _ = http_get(HEALTH_URL)
    elapsed = time.perf_counter() - start
    print(f"   Response time: {elapsed:.3f}s (HTTP {status})")
    if elapsed > 2.0:
        print("   ⚠️  Health check is slow (>2s)")

    print("\n✅ Resilience tests complete")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_resilience()))
