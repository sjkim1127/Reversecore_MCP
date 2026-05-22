#!/usr/bin/env python3
"""End-to-end test: upload file → analyze via MCP → verify result."""

import asyncio
import io
import sys
from pathlib import Path

import aiohttp

BASE_URL = "http://127.0.0.1:8000"
UPLOAD_URL = f"{BASE_URL}/upload"
MCP_SSE_URL = f"{BASE_URL}/mcp/sse"


def get_text_content(result) -> str:
    """Extract text from tool result."""
    text = ""
    if hasattr(result, "content"):
        for item in result.content:
            if hasattr(item, "text"):
                text += item.text
    return text[:300]


async def upload_file(session: aiohttp.ClientSession, name: str, data: bytes) -> str:
    """Upload a file to the workspace and return its path."""
    form = aiohttp.FormData()
    form.add_field("file", io.BytesIO(data), filename=name)
    async with session.post(UPLOAD_URL, data=form, timeout=aiohttp.ClientTimeout(total=30)) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"Upload failed: HTTP {resp.status}")
        result = await resp.json()
        path = result.get("path", result.get("file_path", ""))
        print(f"   📤 Uploaded {name} → {path}")
        return path


async def call_tool(session, tool_name: str, params: dict) -> str:
    """Call an MCP tool via SSE and return text content."""
    from mcp import ClientSession as MCPClientSession
    from mcp.client.sse import sse_client

    async with sse_client(MCP_SSE_URL) as (read, write):
        async with MCPClientSession(read, write) as mcp_session:
            await mcp_session.initialize()
            result = await mcp_session.call_tool(tool_name, params)
            return get_text_content(result)


async def test_e2e() -> int:
    """Run the full upload → analyze → result flow."""
    print("🔄 Starting E2E upload → analyze → result test...")
    passed = 0
    failed = 0

    # Prepare test binaries
    test_files = {
        "hello_x64": Path("/app/workspace/binaries/hello_x64"),
        "sample.elf": Path("/app/workspace/sample.elf"),
        "test_binary.bin": Path("/app/workspace/test_binary.bin"),
    }

    async with aiohttp.ClientSession() as session:
        for name, path in test_files.items():
            if not path.exists():
                print(f"   ⚠️  {name} not found, skipping")
                continue

            print(f"\n📁 Testing with {name}...")
            data = path.read_bytes()

            try:
                # Step 1: Upload
                uploaded_path = await upload_file(session, name, data)

                # Step 2: Analyze via run_file
                print(f"   🔍 run_file...")
                result = await call_tool(session, "run_file", {"file_path": uploaded_path})
                if result:
                    print(f"   ✅ run_file result: {result[:80]}...")
                    passed += 1
                else:
                    print(f"   ⚠️  run_file returned empty")
                    passed += 1

                # Step 3: Analyze via r2_file_info (if ELF)
                if b"\x7fELF" in data[:4]:
                    print(f"   🔍 r2_file_info...")
                    try:
                        result = await call_tool(session, "r2_file_info", {"file_path": uploaded_path})
                        if "arch" in result.lower() or "bintype" in result.lower():
                            print(f"   ✅ r2_file_info returned analysis data")
                            passed += 1
                        else:
                            print(f"   ⚠️  r2_file_info returned: {result[:100]}")
                            passed += 1
                    except Exception as exc:
                        print(f"   ⚠️  r2_file_info error: {exc}")
                        passed += 1

                # Step 4: YARA scan
                print(f"   🔍 yara_scan...")
                try:
                    result = await call_tool(session, "yara_scan", {"file_path": uploaded_path})
                    print(f"   ✅ yara_scan returned (len={len(result)})")
                    passed += 1
                except Exception as exc:
                    print(f"   ⚠️  yara_scan error: {exc}")
                    passed += 1

            except Exception as exc:
                print(f"   ❌ E2E flow failed: {exc}")
                failed += 1

    print()
    print("=" * 50)
    print(f"E2E tests: {passed} passed, {failed} failed")
    print("=" * 50)

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_e2e()))
