"""Unit tests for Hybrid Fuzzing and Symbolic Constraint Solver Orchestrator."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import cve_fuzz_target
from reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator import (
    run_hybrid_fuzz_impl,
    solve_branch_constraints_angr,
)


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content)
        return f

    return _create


SAMPLE_ASAN_CRASH_LOG = """
==9999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x555555555120
WRITE of size 4 at 0x602000000010 thread T0
    #0 0x555555555120 in parse_test /app/workspace/target.c:20:5
    #1 0x555555555200 in LLVMFuzzerTestOneInput /app/workspace/harness.cc:10:5
stat::number_of_executed_units: 15420
"""


@pytest.mark.unit
class TestHybridFuzzOrchestrator:
    """Tests for hybrid fuzzing runner and concolic constraint solving."""

    def test_solve_branch_constraints_angr_fallback(self):
        solutions = solve_branch_constraints_angr("/non/existent/binary")
        assert isinstance(solutions, list)

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_invalid_path(self):
        res = await run_hybrid_fuzz_impl("/non/existent/bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_via_tool_wrapper(self):
        res = await cve_fuzz_target("/non/existent/bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_success_with_crash_and_dict(self, workspace_file):
        test_bin = workspace_file("test_fuzzer_bin.bin", content=b"\x7fELF" + b"\x00" * 100)
        dict_file = workspace_file("tokens.dict", content=b'token_0 = "TEST"')
        corpus_dir = workspace_file("seeds/init.bin", content=b"INITIAL_SEED")

        # Mock asyncio subprocess execution of LibFuzzer
        async def mock_create_proc(*args, **kwargs):
            mock_p = AsyncMock()
            mock_p.communicate.return_value = (b"", SAMPLE_ASAN_CRASH_LOG.encode())
            mock_p.returncode = 1
            return mock_p

        with (
            patch("asyncio.create_subprocess_exec", side_effect=mock_create_proc),
            patch(
                "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.solve_branch_constraints_angr",
                return_value=[b"SOLVED_SEED"],
            ),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                corpus_dir=str(corpus_dir.parent),
                dictionary_path=str(dict_file),
                max_total_time_seconds=5,
                enable_angr_concolic=True,
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["concolic_seeds_injected"] >= 1
        assert data["total_executions"] == 15420
        assert data["crashes_detected"] >= 1
        assert data["triaged_crashes"][0]["crash_type"] == "heap-buffer-overflow"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_timeout_handling(self, workspace_file):
        test_bin = workspace_file("timeout_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)

        async def mock_create_proc(*args, **kwargs):
            mock_p = AsyncMock()
            mock_p.communicate.side_effect = [
                asyncio.TimeoutError(),
                (b"", b"stat::number_of_executed_units: 500\n"),
            ]
            mock_p.kill.return_value = None
            return mock_p

        with patch("asyncio.create_subprocess_exec", side_effect=mock_create_proc):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                max_total_time_seconds=1,
                enable_angr_concolic=False,
            )

        assert res.status == "success"
        assert res.data["total_executions"] == 500
