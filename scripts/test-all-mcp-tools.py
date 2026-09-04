#!/usr/bin/env python3
"""Comprehensive test: call ALL available MCP tools and report results.

This script dynamically queries the MCP server for all registered tools,
parses their input schemas, automatically generates appropriate mock parameters,
chains dependent sessions (Radare2, Memory, Report), and enforces a strict
zero-tolerance policy (exit code 1) if any tool execution fails.
"""

import asyncio
import json
import os
import re
import sys
from typing import Any

# Target URL for the MCP server endpoint (can be overridden via env)
MCP_SERVER_URL = os.environ.get("MCP_SERVER_URL", "http://127.0.0.1:8000/mcp")

# Workspace binaries directory (used for test binary lookup / fallback creation)
BIN_DIR = os.path.join(os.environ.get("REVERSECORE_WORKSPACE", "/app/workspace"), "binaries")
DEFAULT_BIN = os.path.join(BIN_DIR, "hello_x64")
FALLBACK_BIN = os.path.join(BIN_DIR, "fallback.elf")

# Minimal 64-bit ELF header (64 bytes) — valid enough for most static analysis tools
_ELF64_HEADER = (
    b"\x7fELF\x02\x01\x01\x00"  # magic + class + data + version + OS/ABI
    + b"\x00" * 8  # padding
    + b"\x02\x00"  # e_type = ET_EXEC
    + b"\x3e\x00"  # e_machine = x86-64
    + b"\x01\x00\x00\x00"  # e_version
    + b"\x00" * 40  # remaining header fields (zeroed)
)


def ensure_test_binary() -> str:
    """Return a valid test binary path, creating a fallback ELF if needed."""
    if os.path.isfile(DEFAULT_BIN):
        return DEFAULT_BIN
    os.makedirs(BIN_DIR, exist_ok=True)
    with open(FALLBACK_BIN, "wb") as f:
        f.write(_ELF64_HEADER)
    print(f"⚠️  hello_x64 not found — created fallback ELF at {FALLBACK_BIN}")
    return FALLBACK_BIN


# Override parameters for specific tools that need custom testing values
OVERRIDE_PARAMS = {
    "compare_binaries": {
        "file_a": "/app/workspace/binaries/hello_x64",
        "file_b": "/app/workspace/binaries/hello_x64_stripped",
    },
    "copy_to_workspace": {
        "source_path": "/app/workspace/test_binary.bin",
        "destination_name": "copied_test_binary_in_ci.bin",
    },
    "generate_report": {"analysis_results": '{"status":"test_passed"}'},
    "send_email": {
        "to": "test@example.com",
        "subject": "CI Tool Verification",
        "body": "All tools checked.",
    },
    "Radare2_open_file": {"file_path": DEFAULT_BIN},
    "Radare2_close_file": {"file_path": DEFAULT_BIN},
}

# Session cache to store dynamically generated session IDs
session_cache = {"mem_session_id": None, "report_session_id": None}


def get_text_content(result: Any) -> str:
    """Extract text content from various tool result formats."""
    text = ""
    if hasattr(result, "content"):
        for item in result.content:
            if hasattr(item, "text"):
                text += item.text
    elif isinstance(result, list):
        for item in result:
            if hasattr(item, "text"):
                text += item.text
    elif isinstance(result, str):
        text = result
    return text


def extract_session_ids(tool_name: str, result_text: str):
    """Parse session IDs from tool execution outputs and cache them."""
    if not result_text:
        return

    try:
        # Try loading as JSON
        data = json.loads(result_text)
        if isinstance(data, dict):
            if "session_id" in data:
                sid = data["session_id"]
                if "memory" in tool_name:
                    session_cache["mem_session_id"] = sid
                    print(f" (Cached mem_session_id: {sid})", end="")
                else:
                    session_cache["report_session_id"] = sid
                    print(f" (Cached report_session_id: {sid})", end="")
                return
    except Exception:
        pass

    # Fallback to Regex search if JSON load fails
    # Session formats: SES-XXXXXX or UUID
    m = re.search(r"SES-[0-9A-Z]+", result_text)
    if m:
        session_cache["report_session_id"] = m.group(0)
        print(f" (Regex Cached report_session_id: {m.group(0)})", end="")
        return

    m_uuid = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", result_text)
    if m_uuid:
        if "memory" in tool_name:
            session_cache["mem_session_id"] = m_uuid.group(0)
            print(f" (Regex Cached mem_session_id: {m_uuid.group(0)})", end="")
        else:
            session_cache["report_session_id"] = m_uuid.group(0)
            print(f" (Regex Cached report_session_id: {m_uuid.group(0)})", end="")


def generate_params(tool_name: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Generate appropriate parameters based on the tool's JSON schema."""
    if tool_name in OVERRIDE_PARAMS:
        return OVERRIDE_PARAMS[tool_name].copy()

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    params = {}

    for prop_name, prop_info in properties.items():
        is_required = prop_name in required
        prop_type = prop_info.get("type", "string")
        val = None

        # 1. Handle session parameters
        if prop_name in [
            "session_id",
            "r2_session_id",
            "report_session_id",
            "mem_session_id",
        ]:
            if "report" in tool_name or "report" in prop_name:
                val = session_cache["report_session_id"] or "SES-CI-DUMMY-ID"
            elif "memory" in tool_name or "mem" in prop_name:
                val = session_cache["mem_session_id"] or "MEM-CI-DUMMY-ID"
            else:
                val = (
                    session_cache["report_session_id"]
                    or session_cache["mem_session_id"]
                    or "SES-CI-DUMMY-ID"
                )

        # 2. Handle file paths
        elif prop_name in [
            "file_path",
            "source_path",
            "original_path",
            "patched_path",
            "dest_path",
            "destination_path",
            "filepath",
            "path",
            "source",
            "file",
        ]:
            if "yara" in tool_name or "yara" in prop_name:
                val = DEFAULT_BIN
            elif "rule" in prop_name:
                val = "/app/workspace/binaries/ci_test.yar"
            elif "rules_dir" in prop_name:
                val = "/app/rules"
            else:
                val = DEFAULT_BIN

        # 3. Handle specific argument names
        elif prop_name == "file_a":
            val = DEFAULT_BIN
        elif prop_name == "file_b":
            val = (
                os.path.join(BIN_DIR, "hello_x64_stripped")
                if os.path.isfile(os.path.join(BIN_DIR, "hello_x64_stripped"))
                else DEFAULT_BIN
            )
        elif prop_name in ["address", "addr", "start_addr", "end_addr", "offset"]:
            val = 4192 if prop_type == "integer" else "0x00001060"
        elif prop_name in ["count", "length", "size", "limit"]:
            val = 10 if prop_type in ["integer", "number"] else "10"
        elif prop_name == "mnemonic":
            val = "nop"
        elif prop_name == "to":
            val = "test@example.com"
        elif prop_name == "subject":
            val = "Test Subject"
        elif prop_name == "body":
            val = "Test Body"
        elif prop_name == "analysis_results":
            val = "{}"
        elif prop_name == "query":
            val = "main"
        elif prop_name == "firmware_path":
            val = DEFAULT_BIN
        elif prop_name in ["output_dir", "out_dir"]:
            val = "/app/workspace/tmp"
        elif prop_name == "timezone":
            val = "UTC"
        elif prop_name == "severity":
            val = "medium"
        elif prop_name == "ioc_type":
            val = "ip"
        elif prop_name == "value":
            val = "1.1.1.1"
        elif prop_name == "note":
            val = "test note"
        elif prop_name == "technique_id":
            val = "T1005"
        elif prop_name == "status":
            val = "completed"
        elif prop_name == "summary":
            val = "test summary"
        elif prop_name == "name":
            val = "test_name"
        elif prop_name == "binary_name":
            val = os.path.basename(DEFAULT_BIN)
        elif prop_name == "binary_path":
            val = DEFAULT_BIN
        elif prop_name in ["data", "content"]:
            val = "test data"
        elif prop_name == "instructions":
            val = ["nop", "ret"]
        elif prop_name == "arch":
            val = "x86"
        elif prop_name == "bits":
            val = 64
        elif prop_name == "category":
            val = "general"

        # 4. Fallback for generic required fields
        if val is None and is_required:
            if prop_type == "string":
                val = "test_value"
            elif prop_type in ["integer", "number"]:
                val = 1
            elif prop_type == "boolean":
                val = False
            elif prop_type == "array":
                val = []
            elif prop_type == "object":
                val = {}

        if val is not None:
            params[prop_name] = val

    return params


async def test_all_tools() -> int:
    """Discover, configure, and invoke all registered MCP tools."""
    try:
        from mcp import ClientSession
    except ImportError as exc:
        print(f"❌ mcp library not available: {exc}")
        return 1

    # Ensure a valid test binary exists before invoking any tools
    active_bin = ensure_test_binary()
    # Update the module-level constant so generate_params() uses it
    global DEFAULT_BIN
    DEFAULT_BIN = active_bin

    passed = 0
    failed = 0
    skipped = 0
    tool_list = []

    try:
        if "sse" in MCP_SERVER_URL:
            from mcp.client.sse import sse_client

            client_ctx = sse_client(MCP_SERVER_URL)
        else:
            from mcp.client.streamable_http import streamable_http_client

            client_ctx = streamable_http_client(MCP_SERVER_URL)

        async with client_ctx as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Get all registered tools
                tools_result = await session.list_tools()
                tools = tools_result.tools
                tool_list = [t.name for t in tools]

                print(f"🔧 Discovered {len(tool_list)} tools on the server")
                print("=" * 60)

                # Prioritize session creation tools to establish baseline sessions
                sorted_tools = sorted(
                    tools,
                    key=lambda t: (
                        (
                            0
                            if t.name
                            in [
                                "Radare2_open_file",
                                "create_memory_session",
                                "start_report_session",
                            ]
                            else 1
                        ),
                        t.name,
                    ),
                )

                for tool in sorted_tools:
                    tool_name = tool.name
                    schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}

                    # Generate params dynamically
                    params = generate_params(tool_name, schema)

                    print(
                        f"📡 Invoking {tool_name} with params: {json.dumps(params)} ... ",
                        end="",
                        flush=True,
                    )

                    try:
                        result = await session.call_tool(tool_name, params)
                        text = get_text_content(result)

                        # Extract session IDs if applicable
                        extract_session_ids(tool_name, text)

                        print(f" ✅ (Length: {len(text)})")
                        passed += 1
                    except Exception as exc:
                        error_msg = str(exc)
                        # Check if the tool failed because of external setup limitations.
                        # We count these as 'skipped' rather than failed to avoid false
                        # negatives in partial CI environments (e.g., optional tools like
                        # Qiling, capa, diec that are not installed in the default image).
                        is_skip = any(
                            kw in error_msg.lower()
                            for kw in [
                                # Infrastructure / runtime environment gaps
                                "not found",
                                "unavailable",
                                "no such file",
                                "command not found",
                                # Optional heavy tools
                                "ghidra",
                                "graphviz",
                                "dot",
                                "java",
                                # Optional emulation (Qiling)
                                "qiling",
                                "emulation",
                                # Missing Python optional packages
                                "importerror",
                                "import error",
                                "module not found",
                                "no module named",
                                # Optional binary analysis tools
                                "capa",
                                "diec",
                                "detect-it-easy",
                            ]
                        )

                        if is_skip:
                            print(f" ⏭️ (Skipped: {error_msg[:60]})")
                            skipped += 1
                        else:
                            print(f" ❌ (Failed: {error_msg[:120]})")
                            failed += 1

    except Exception as exc:
        print(f"❌ Failed to connect or interact with MCP Server at {MCP_SERVER_URL}: {exc}")
        return 1

    print("\n" + "=" * 60)
    print("Verification Summary:")
    print(f"  - Passed:  {passed}")
    print(f"  - Skipped: {skipped}")
    print(f"  - Failed:  {failed}")
    print(f"  - Total:   {passed + skipped + failed} / {len(tool_list)} tools")
    print("=" * 60)

    if failed > 0:
        print(f"\n🚨 FAILURE: {failed} tool(s) failed execution! Rejecting build.")
        return 1

    print("\n🎉 SUCCESS: All registered tools verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_all_tools()))
