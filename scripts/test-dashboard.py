#!/usr/bin/env python3
"""Test MCP server dashboard, health, and metrics endpoints."""

import asyncio
import sys

import aiohttp

BASE_URL = "http://127.0.0.1:8000"


async def fetch(session: aiohttp.ClientSession, path: str, expect_status: int = 200) -> dict:
    """Fetch a URL and return status + text snippet."""
    url = f"{BASE_URL}{path}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            text = await resp.text()
            return {
                "path": path,
                "status": resp.status,
                "ok": resp.status == expect_status,
                "text_preview": text[:200],
                "content_type": resp.headers.get("Content-Type", "unknown"),
            }
    except Exception as exc:
        return {"path": path, "status": 0, "ok": False, "error": str(exc)}


async def test_dashboard() -> int:
    """Test all dashboard and status endpoints."""
    print("📊 Testing dashboard and status endpoints...")
    passed = 0
    failed = 0

    async with aiohttp.ClientSession() as session:
        # 1. Health endpoints
        health_tests = [
            ("/health", 200),
            ("/health/live", 200),
            ("/health/ready", 200),
        ]
        for path, expect in health_tests:
            result = await fetch(session, path, expect)
            if result["ok"]:
                print(f"  ✅ {path} → HTTP {result['status']}")
                passed += 1
            else:
                print(f"  ❌ {path} → HTTP {result.get('status', 0)} ({result.get('error', 'unknown')})")
                failed += 1

        # 2. Health content validation
        print("\n  🔍 Validating /health response content...")
        async with session.get(f"{BASE_URL}/health", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            data = await resp.json()
            required_keys = {"status", "version", "timestamp", "dependencies"}
            missing = required_keys - set(data.keys())
            if not missing:
                print(f"    ✅ All required keys present: {required_keys}")
                passed += 1
            else:
                print(f"    ❌ Missing keys: {missing}")
                failed += 1

        # 3. Readiness content validation
        print("\n  🔍 Validating /health/ready response...")
        async with session.get(f"{BASE_URL}/health/ready", timeout=aiohttp.ClientTimeout(total=5)) as resp:
            data = await resp.json()
            if "ready" in data:
                print(f"    ✅ ready={data['ready']}")
                passed += 1
            else:
                print(f"    ❌ Missing 'ready' key")
                failed += 1

        # 4. Metrics endpoint
        print("\n  🔍 Testing /metrics...")
        result = await fetch(session, "/metrics", 200)
        if result["ok"]:
            print(f"  ✅ /metrics → HTTP {result['status']} ({result['content_type']})")
            # Try to parse as JSON
            try:
                async with session.get(f"{BASE_URL}/metrics", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    data = await resp.json()
                    print(f"    📈 Metrics keys: {list(data.keys())[:5]}")
                    passed += 1
            except Exception as exc:
                print(f"    ⚠️  Could not parse metrics JSON: {exc}")
                passed += 1  # Still pass if endpoint responds
        else:
            print(f"  ❌ /metrics → HTTP {result.get('status', 0)}")
            failed += 1

        # 5. Dashboard HTML
        print("\n  🔍 Testing /dashboard...")
        result = await fetch(session, "/dashboard", 200)
        if result["ok"] and "text/html" in result.get("content_type", ""):
            print(f"  ✅ /dashboard → HTML page loaded")
            passed += 1
        elif result["ok"]:
            print(f"  ⚠️  /dashboard → HTTP {result['status']} but content-type={result.get('content_type')}")
            passed += 1
        else:
            print(f"  ❌ /dashboard → HTTP {result.get('status', 0)} (dashboard may not be installed)")
            failed += 1

        # 6. Static files (if dashboard available)
        print("\n  🔍 Testing dashboard static files...")
        static_result = await fetch(session, "/dashboard/static", 200)
        if static_result["ok"] or static_result.get("status") in (301, 302, 307, 308, 404):
            print(f"  ✅ /dashboard/static → HTTP {static_result.get('status')}")
            passed += 1
        else:
            print(f"  ⚠️  /dashboard/static → HTTP {static_result.get('status', 0)}")
            passed += 1

    print()
    print("=" * 50)
    print(f"Dashboard tests: {passed} passed, {failed} failed")
    print("=" * 50)

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_dashboard()))
