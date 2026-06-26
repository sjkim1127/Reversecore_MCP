"""Unit tests for the crash triage tool."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reversecore_mcp.tools.analysis.crash_triage import (
    _assess_exploitability,
    _parse_gdb_output,
    triage_crash,
)

# Sample GDB outputs for testing
GDB_OUTPUT_SIGSEGV_PC_CONTROL = """
---CRASH_INFO_START---
[SIGNAL]
Program stopped with signal SIGSEGV, Segmentation fault.
[REGISTERS]
rax            0x0                 0
rbx            0x0                 0
rcx            0x4141414141414141  4702111234474983745
rdx            0x0                 0
rsi            0x7fffffffdf98      140737488347032
rdi            0x1                 1
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffe080      0x7fffffffe080
r8             0x7ffff7fcb360      140737353925472
r9             0x0                 0
r10            0x10                16
r11            0x246               582
r12            0x7fffffffe198      140737488347544
r13            0x401146            4198726
r14            0x0                 0
r15            0x7ffff7ffd040      140737354129472
rip            0x4141414141414141  0x4141414141414141
eflags         0x10202             [ IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
[BACKTRACE]
#0  0x4141414141414141 in ?? ()
#1  0x0000000000000000 in ?? ()
[INSTRUCTION]
=> 0x4141414141414141:	Cannot access memory at address 0x4141414141414141
---CRASH_INFO_END---
"""

GDB_OUTPUT_SIGSEGV_CALL = """
---CRASH_INFO_START---
[SIGNAL]
Program received signal SIGSEGV, Segmentation fault.
[REGISTERS]
rax            0x0                 0
rip            0x40115e            0x40115e <main+24>
[BACKTRACE]
#0  0x000000000040115e in main ()
[INSTRUCTION]
=> 0x40115e <main+24>:	call   *rax
---CRASH_INFO_END---
"""

GDB_OUTPUT_SIGABRT = """
---CRASH_INFO_START---
[SIGNAL]
Program terminated with signal SIGABRT, Aborted.
[REGISTERS]
rax            0x0                 0
rip            0x7ffff7e4600b      0x7ffff7e4600b <raise+27>
[BACKTRACE]
#0  0x00007ffff7e4600b in raise () from /lib/x86_64-linux-gnu/libc.so.6
#1  0x00007ffff7e25859 in abort () from /lib/x86_64-linux-gnu/libc.so.6
#2  0x000000000040117a in main ()
[INSTRUCTION]
=> 0x7ffff7e4600b <raise+27>:	cmp    rax,0xfffffffffffff000
---CRASH_INFO_END---
"""

GDB_OUTPUT_NORMAL = """
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 1234) exited normally]
"""


class TestParseGDBOutput:
    """Tests for _parse_gdb_output."""

    def test_parse_sigsegv_pc_control(self):
        result = _parse_gdb_output(GDB_OUTPUT_SIGSEGV_PC_CONTROL)
        assert result["signal"] == "SIGSEGV"
        assert result["registers"]["rip"] == "0x4141414141414141"
        assert result["faulting_address"] == "0x4141414141414141"
        assert len(result["backtrace"]) == 2
        assert result["backtrace"][0].startswith("#0")
        assert "Cannot access memory" in result["instruction"]

    def test_parse_sigabrt(self):
        result = _parse_gdb_output(GDB_OUTPUT_SIGABRT)
        assert result["signal"] == "SIGABRT"
        assert result["registers"]["rip"] == "0x7ffff7e4600b"
        assert len(result["backtrace"]) == 3
        assert result["backtrace"][2] == "#2  0x000000000040117a in main ()"
        assert "cmp" in result["instruction"]


class TestAssessExploitability:
    """Tests for _assess_exploitability."""

    def test_assess_pc_control(self):
        info = _parse_gdb_output(GDB_OUTPUT_SIGSEGV_PC_CONTROL)
        assessment = _assess_exploitability(info)
        assert assessment["status"] == "CRITICAL"
        assert "pc_control" in assessment["tags"]

    def test_assess_call(self):
        info = _parse_gdb_output(GDB_OUTPUT_SIGSEGV_CALL)
        assessment = _assess_exploitability(info)
        assert assessment["status"] == "HIGH"
        assert "control_flow_hijack" in assessment["tags"]

    def test_assess_aborted(self):
        info = _parse_gdb_output(GDB_OUTPUT_SIGABRT)
        assessment = _assess_exploitability(info)
        assert assessment["status"] == "LOW"
        assert "aborted" in assessment["tags"]


@pytest.mark.asyncio
class TestTriageCrash:
    """Tests for the triage_crash tool."""

    @patch("reversecore_mcp.tools.analysis.crash_triage.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.crash_triage.os.access")
    @patch("reversecore_mcp.tools.analysis.crash_triage.execute_subprocess_async")
    async def test_triage_crash_success(
        self, mock_exec: AsyncMock, mock_access: MagicMock, mock_validate: MagicMock
    ):
        mock_validate.side_effect = lambda x: x
        mock_access.return_value = True
        mock_exec.return_value = (GDB_OUTPUT_SIGSEGV_PC_CONTROL, "")

        result = await triage_crash("vuln_bin", "crash.txt", use_stdin=True)

        assert result.status == "success"
        data = result.data

        assert data["crashed"] is True
        assert data["signal"] == "SIGSEGV"
        assert data["exploitability"]["status"] == "CRITICAL"

    @patch("reversecore_mcp.tools.analysis.crash_triage.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.crash_triage.os.access")
    @patch("reversecore_mcp.tools.analysis.crash_triage.execute_subprocess_async")
    async def test_triage_crash_no_crash(
        self, mock_exec: AsyncMock, mock_access: MagicMock, mock_validate: MagicMock
    ):
        mock_validate.side_effect = lambda x: x
        mock_access.return_value = True
        mock_exec.return_value = (GDB_OUTPUT_NORMAL, "")

        result = await triage_crash("vuln_bin", "normal_input.txt")

        assert result.status == "success"
        data = result.data

        assert data["crashed"] is False
        assert "message" in data
