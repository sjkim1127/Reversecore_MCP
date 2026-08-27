#!/usr/bin/env python3
"""Strict end-to-end test for workspace/upload → MCP analysis → verified result."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = os.environ.get("MCP_HTTP_BASE_URL", "http://127.0.0.1:8000")
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", f"{BASE_URL}/mcp")
WORKSPACE = Path(os.environ.get("REVERSECORE_WORKSPACE", "/app/workspace")).resolve()


def extract_result_text(result: Any) -> str:
    """Extract textual and structured content from an MCP result."""
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
    """Require a non-empty MCP result without an explicit error status."""
    if bool(getattr(result, "isError", False) or getattr(result, "is_error", False)):
        raise AssertionError(f"{tool_name} returned an MCP error")

    text = extract_result_text(result)
    if not text:
        raise AssertionError(f"{tool_name} returned empty content")

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


def http_status(url: str, timeout: int = 5) -> int:
    """Return an HTTP status, or zero only when the endpoint is unreachable."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def select_elf_fixture() -> Path:
    """Select a real ELF fixture that must exist before the E2E flow starts."""
    candidates = (
        WORKSPACE / "binaries" / "hello_x64",
        WORKSPACE / "sample.elf",
        WORKSPACE / "smoke_test_elf",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"No ELF fixture found in: {', '.join(map(str, candidates))}")


def normalize_workspace_path(raw_path: str) -> Path | None:
    """Return a valid workspace-contained file path, including renamed uploads."""
    if not raw_path:
        return None

    candidate = Path(raw_path)
    attempts = [candidate] if candidate.is_absolute() else [WORKSPACE / candidate]
    for attempt in attempts:
        resolved = attempt.resolve()
        try:
            resolved.relative_to(WORKSPACE)
        except ValueError:
            continue
        if resolved.is_file():
            return resolved

    # The upload API intentionally returns only a randomized filename while
    # storing the file in a workspace subdirectory. Resolve it recursively but
    # never allow a path outside the configured workspace.
    basename = candidate.name
    if basename:
        matches = [match.resolve() for match in WORKSPACE.rglob(basename) if match.is_file()]
        if matches:
            return max(matches, key=lambda match: match.stat().st_mtime_ns)
    return None


def iter_upload_path_values(value: Any, parent_key: str = ""):
    """Yield path-like strings from common top-level or nested upload payload fields."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower()
            if isinstance(child, str) and (
                "path" in normalized_key
                or normalized_key in {"file", "filename", "name", "saved_as", "location"}
            ):
                yield child
            yield from iter_upload_path_values(child, normalized_key)
    elif isinstance(value, list):
        for child in value:
            yield from iter_upload_path_values(child, parent_key)


def upload_file(path: Path) -> Path:
    """Upload a fixture and resolve the server response to a real workspace file."""
    existing_matches = {candidate.resolve() for candidate in WORKSPACE.rglob(path.name)}
    boundary = "----ReversecoreE2EBoundary"
    body = (
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + path.read_bytes()
        + f"\r\n--{boundary}--\r\n".encode()
    )
    request = urllib.request.Request(
        f"{BASE_URL}/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status not in (200, 201):
            raise AssertionError(f"Upload returned HTTP {response.status}")
        payload = json.loads(response.read())

    print(f"   upload response: {json.dumps(payload, sort_keys=True, default=str)[:600]}")

    for raw_path in iter_upload_path_values(payload):
        resolved = normalize_workspace_path(raw_path)
        if resolved is not None:
            return resolved

    new_matches = [
        candidate.resolve()
        for candidate in WORKSPACE.rglob(path.name)
        if candidate.is_file() and candidate.resolve() not in existing_matches
    ]
    if len(new_matches) == 1:
        return new_matches[0]
    if len(new_matches) > 1:
        return max(new_matches, key=lambda candidate: candidate.stat().st_mtime_ns)

    raise AssertionError(
        "Upload succeeded but no workspace-contained file could be resolved from "
        f"payload={payload!r}"
    )


async def call_tool(session: Any, tool_name: str, params: dict[str, Any]) -> str:
    """Call a tool with a hard timeout and validate its result."""
    result = await asyncio.wait_for(session.call_tool(tool_name, params), timeout=30)
    return require_success(result, tool_name)


async def test_e2e() -> int:
    """Run deterministic workspace/upload and analysis flows with strict assertions."""
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as exc:
        print(f"❌ mcp library is required for E2E verification: {exc}")
        return 1

    try:
        elf_fixture = select_elf_fixture()
        strings_fixture = WORKSPACE / "test_binary.bin"
        if not strings_fixture.is_file():
            raise FileNotFoundError(f"Missing strings fixture: {strings_fixture}")

        upload_status = http_status(f"{BASE_URL}/upload")
        if upload_status == 0:
            raise ConnectionError("HTTP server is unreachable while probing /upload")

        if upload_status in (200, 201, 405):
            print(f"📤 Upload endpoint detected (HTTP {upload_status}); exercising upload flow")
            analysis_target = upload_file(elf_fixture)
            print(f"   uploaded {elf_fixture.name} → {analysis_target}")
        elif upload_status == 404:
            print("ℹ️  Upload endpoint is not exposed; exercising strict workspace-path flow")
            analysis_target = elf_fixture.resolve()
        else:
            raise AssertionError(f"Unexpected /upload response: HTTP {upload_status}")

        async with streamable_http_client(MCP_SERVER_URL) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = await session.list_tools()
                tool_names = {tool.name for tool in tools.tools}
                required = {"list_workspace", "run_file", "run_strings"}
                missing = sorted(required - tool_names)
                if missing:
                    raise AssertionError(f"Required E2E tools are missing: {missing}")

                workspace_text = await call_tool(session, "list_workspace", {})
                if analysis_target.name.lower() not in workspace_text.lower():
                    raise AssertionError(
                        f"list_workspace did not include {analysis_target.name}: {workspace_text[:300]}"
                    )
                print(f"✅ list_workspace exposes {analysis_target.name}")

                file_text = await call_tool(
                    session, "run_file", {"file_path": str(analysis_target)}
                )
                if "elf" not in file_text.lower():
                    raise AssertionError(f"run_file did not identify ELF: {file_text[:300]}")
                print(f"✅ run_file verified ELF output: {file_text[:160]}")

                strings_text = await call_tool(
                    session,
                    "run_strings",
                    {"file_path": str(strings_fixture), "min_length": 4},
                )
                if "hello world" not in strings_text.lower():
                    raise AssertionError(
                        f"run_strings did not return known fixture content: {strings_text[:300]}"
                    )
                print(f"✅ run_strings verified known content: {strings_text[:160]}")

        print("🎉 Strict E2E workspace/upload → analyze → result flow passed")
        return 0
    except Exception as exc:
        print(f"❌ Strict E2E flow failed: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(test_e2e()))
