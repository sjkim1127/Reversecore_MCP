"""Unit tests for AddressSanitizer Crash Triager and Root Cause Analyzer."""

from pathlib import Path

import pytest

from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.cve_hunter.asan_crash_triager import (
    calculate_cvss_score,
    parse_asan_stack_trace,
    triage_asan_log,
    triage_crash_impl,
)
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import cve_triage_crash


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


SAMPLE_ASAN_HEAP_OVERFLOW = """
=================================================================
==34891==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000034 at pc 0x555555555230 bp 0x7fffffffe000 sp 0x7fffffffdff8
WRITE of size 4 at 0x602000000034 thread T0
    #0 0x555555555230 in parse_png_chunk /app/workspace/png_parser.c:48:9
    #1 0x555555555350 in LLVMFuzzerTestOneInput /app/workspace/harness.cc:19:5
    #2 0x555555590120 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /llvm/FuzzerLoop.cpp:599:15

0x602000000034 is located 0 bytes to the right of 20-byte region [0x602000000020,0x602000000034)
allocated by thread T0 here:
    #0 0x7ffff7a12345 in malloc /llvm/asan_malloc_linux.cpp:145
    #1 0x555555555190 in parse_png_chunk /app/workspace/png_parser.c:32:18
    #2 0x555555555350 in LLVMFuzzerTestOneInput /app/workspace/harness.cc:19:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /app/workspace/png_parser.c:48:9 in parse_png_chunk
"""

SAMPLE_ASAN_UAF = """
=================================================================
==45120==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000100 at pc 0x555555556100 bp 0x7fffffffe100 sp 0x7fffffffdff0
READ of size 8 at 0x603000000100 thread T0
    #0 0x555555556100 in process_node /app/workspace/tree_parser.c:112:14
    #1 0x555555556280 in LLVMFuzzerTestOneInput /app/workspace/harness.cc:22:5

freed by thread T0 here:
    #0 0x7ffff7a12400 in free /llvm/asan_malloc_linux.cpp:123
    #1 0x555555555980 in delete_node /app/workspace/tree_parser.c:85:5

previously allocated by thread T0 here:
    #0 0x7ffff7a12345 in malloc /llvm/asan_malloc_linux.cpp:145
    #1 0x555555555800 in create_node /app/workspace/tree_parser.c:40:20
"""


@pytest.mark.unit
class TestAsanCrashTriager:
    """Tests for AddressSanitizer crash log parsing and root cause analysis."""

    def test_parse_stack_trace(self):
        lines = SAMPLE_ASAN_HEAP_OVERFLOW.splitlines()
        frames = parse_asan_stack_trace(lines)
        assert len(frames) >= 3
        user_frames = [f for f in frames if not f["is_sanitizer_internal"]]
        assert user_frames[0]["symbol"] == "parse_png_chunk"
        assert user_frames[0]["source_file"] == "/app/workspace/png_parser.c"
        assert user_frames[0]["line"] == 48

    def test_calculate_cvss_score(self):
        cvss_write = calculate_cvss_score("heap-buffer-overflow", "WRITE", 8)
        assert cvss_write["cvss_v31_score"] >= 8.0
        assert cvss_write["severity"] == "HIGH"

        cvss_read = calculate_cvss_score("heap-buffer-overflow", "READ", 4)
        assert cvss_read["cvss_v31_score"] <= 7.0
        assert cvss_read["severity"] == "MEDIUM"

        cvss_df = calculate_cvss_score("double-free", "UNKNOWN", 0)
        assert cvss_df["cvss_v31_score"] >= 8.0

    def test_triage_asan_heap_overflow(self):
        triage = triage_asan_log(SAMPLE_ASAN_HEAP_OVERFLOW)
        assert triage["bug_type"] == "heap-buffer-overflow"
        assert triage["cwe_id"] == "CWE-122"
        assert triage["access_type"] == "WRITE"
        assert triage["access_size"] == 4
        assert triage["faulting_function"] == "parse_png_chunk"
        assert triage["is_heap_corruption"] is True
        assert len(triage["allocation_callstack"]) >= 1

    def test_triage_asan_uaf(self):
        triage = triage_asan_log(SAMPLE_ASAN_UAF)
        assert triage["bug_type"] == "heap-use-after-free"
        assert triage["cwe_id"] == "CWE-416"
        assert triage["access_type"] == "READ"
        assert triage["access_size"] == 8
        assert triage["faulting_function"] == "process_node"
        assert len(triage["free_callstack"]) >= 1

    @pytest.mark.asyncio
    async def test_triage_crash_impl_empty(self):
        res = await triage_crash_impl("   ")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_triage_crash_impl_success(self):
        res = await triage_crash_impl(SAMPLE_ASAN_HEAP_OVERFLOW)
        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["cwe_id"] == "CWE-122"
        assert "CVSS v3.1" in data["summary"]

    @pytest.mark.asyncio
    async def test_triage_crash_via_file_path(self, workspace_file):
        log_file = workspace_file("asan_crash.log", content=SAMPLE_ASAN_HEAP_OVERFLOW.encode())
        res = await triage_crash_impl(str(log_file))
        assert res.status == "success"
        assert res.data["faulting_function"] == "parse_png_chunk"

    @pytest.mark.asyncio
    async def test_triage_crash_via_tool_wrapper(self):
        res = await cve_triage_crash(SAMPLE_ASAN_HEAP_OVERFLOW)
        assert res.status == "success"
        assert res.data["cwe_id"] == "CWE-122"
