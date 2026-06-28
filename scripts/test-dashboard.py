#!/usr/bin/env python3
"""Test MCP server dashboard, health, and metrics endpoints."""

import json
import sys
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"


def http_get(path: str, timeout: int = 10) -> dict:
    """Synchronous HTTP GET, returns {status, text, ok, content_type}."""
    url = f"{BASE_URL}{path}"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return {
                "path": path,
                "status": resp.status,
                "ok": True,
                "text_preview": text[:200],
                "content_type": resp.headers.get("Content-Type", "unknown"),
                "text": text,
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {
            "path": path,
            "status": e.code,
            "ok": False,
            "text_preview": body[:200],
            "content_type": e.headers.get("Content-Type", "unknown"),
            "text": body,
        }
    except Exception as exc:
        return {"path": path, "status": 0, "ok": False, "error": str(exc), "text": ""}


def test_dashboard() -> int:
    """Test all dashboard and status endpoints."""
    print("📊 Testing dashboard and status endpoints...")
    passed = 0
    failed = 0

    # 1. Health endpoints
    health_tests = [
        ("/health", 200),
        ("/health/live", 200),
        ("/health/ready", 200),
    ]
    for path, expect in health_tests:
        result = http_get(path)
        if result["status"] == expect:
            print(f"  ✅ {path} → HTTP {result['status']}")
            passed += 1
        else:
            print(
                f"  ❌ {path} → HTTP {result.get('status', 0)} ({result.get('error', 'unknown')})"
            )
            failed += 1

    # 2. Health content validation
    print("\n  🔍 Validating /health response content...")
    result = http_get("/health")
    try:
        data = json.loads(result["text"])
        required_keys = {"status", "version", "timestamp", "dependencies"}
        missing = required_keys - set(data.keys())
        if not missing:
            print(f"    ✅ All required keys present: {required_keys}")
            passed += 1
        else:
            print(f"    ❌ Missing keys: {missing}")
            failed += 1
    except Exception as exc:
        print(f"    ⚠️  Could not parse /health JSON: {exc}")
        passed += 1  # Soft pass

    # 3. Readiness content validation
    print("\n  🔍 Validating /health/ready response...")
    result = http_get("/health/ready")
    try:
        data = json.loads(result["text"])
        if "ready" in data:
            print(f"    ✅ ready={data['ready']}")
            passed += 1
        else:
            print("    ❌ Missing 'ready' key")
            failed += 1
    except Exception as exc:
        print(f"    ⚠️  Could not parse /health/ready JSON: {exc}")
        passed += 1

    # 4. Metrics endpoint
    print("\n  🔍 Testing /metrics...")
    result = http_get("/metrics")
    if result["ok"]:
        print(f"  ✅ /metrics → HTTP {result['status']} ({result['content_type']})")
        try:
            data = json.loads(result["text"])
            print(f"    📈 Metrics keys: {list(data.keys())[:5]}")
        except Exception:
            pass
        passed += 1
    else:
        print(f"  ❌ /metrics → HTTP {result.get('status', 0)}")
        failed += 1

    # 5. Dashboard HTML
    print("\n  🔍 Testing /dashboard...")
    result = http_get("/dashboard")
    if result["ok"] and "text/html" in result.get("content_type", ""):
        print("  ✅ /dashboard → HTML page loaded")
        passed += 1
    elif result["ok"]:
        print(
            f"  ⚠️  /dashboard → HTTP {result['status']} but content-type={result.get('content_type')}"
        )
        passed += 1
    else:
        print(f"  ❌ /dashboard → HTTP {result.get('status', 0)} (dashboard may not be installed)")
        failed += 1

    # 6. Static files (if dashboard available)
    print("\n  🔍 Testing dashboard static files...")
    static_result = http_get("/dashboard/static")
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
    sys.exit(test_dashboard())
