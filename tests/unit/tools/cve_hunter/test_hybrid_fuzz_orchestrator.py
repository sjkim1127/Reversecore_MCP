"""Unit tests for Hybrid Fuzzing and Symbolic Constraint Solver Orchestrator."""

import asyncio
import hashlib
import subprocess
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
    async def test_run_hybrid_fuzz_rejects_auxiliary_paths_outside_workspace(
        self, workspace_file, tmp_path
    ):
        test_bin = workspace_file("path_guard_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        outside_corpus = tmp_path / "outside-corpus"
        outside_dict = tmp_path / "outside.dict"
        outside_dict.write_text('token = "TEST"')

        res = await run_hybrid_fuzz_impl(
            target_binary_path=str(test_bin),
            corpus_dir=str(outside_corpus),
            dictionary_path=str(outside_dict),
            enable_angr_concolic=False,
        )

        assert res.status == "error"
        assert res.error_code == "INVALID_PATH"
        assert not outside_corpus.exists()

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_via_tool_wrapper(self):
        res = await cve_fuzz_target("/non/existent/bin")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_success_with_crash_and_dict(self, workspace_file):
        test_bin = workspace_file("test_fuzzer_bin.bin", content=b"\x7fELF" + b"\x00" * 100)
        dict_file = workspace_file("tokens.dict", content=b'token_0 = "TEST"')
        corpus_dir = workspace_file("seeds/init.bin", content=b"INITIAL_SEED")

        async def execute_with_crash_artifact(cmd, **kwargs):
            artifact_prefix = next(
                arg.split("=", 1)[1] for arg in cmd if arg.startswith("-artifact_prefix=")
            )
            artifact = Path(artifact_prefix) / "crash-test-input"
            artifact.write_bytes(b"REAL_CRASH_INPUT")
            run_seeds = Path(cmd[1])
            assert run_seeds.parent == Path(artifact_prefix).parent
            assert (run_seeds / "init.bin").read_bytes() == b"INITIAL_SEED"
            angr_seeds = list(run_seeds.glob("angr_seed_*.bin"))
            assert len(angr_seeds) == 1
            assert angr_seeds[0].read_bytes() == b"SOLVED_SEED"
            output = SAMPLE_ASAN_CRASH_LOG.replace(
                "stat::number_of_executed_units:",
                f"Test unit written to {artifact}\nstat::number_of_executed_units:",
            )
            raise subprocess.CalledProcessError(1, cmd, output=output, stderr="")

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
                new=AsyncMock(side_effect=execute_with_crash_artifact),
            ),
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
        assert data["execution_status"] == "crash_detected"
        assert data["triaged_crashes"][0]["crash_input_path"].endswith("crash-test-input")
        run_path_parts = Path(data["triaged_crashes"][0]["crash_input_path"]).parts
        cache_index = run_path_parts.index(".cache")
        assert run_path_parts[cache_index + 1] == "fuzz"
        assert run_path_parts[cache_index + 2].startswith("run_")
        assert (
            data["triaged_crashes"][0]["crash_input_sha256"]
            == hashlib.sha256(b"REAL_CRASH_INPUT").hexdigest()
        )
        assert (corpus_dir.parent / "init.bin").read_bytes() == b"INITIAL_SEED"
        assert not list(corpus_dir.parent.glob("angr_seed_*.bin"))

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_uses_isolated_seeds_and_run_directories(self, workspace_file):
        test_bin_a = workspace_file("shared-targets/target-a.bin", content=b"A" * 100)
        test_bin_b = workspace_file("shared-targets/target-b.bin", content=b"B" * 100)
        legacy_seeds = test_bin_a.parent / "cve_seeds"
        legacy_seeds.mkdir(exist_ok=True)
        (legacy_seeds / "stale-seed.bin").write_bytes(b"FROM_OLD_RUN")
        legacy_crashes = test_bin_a.parent / "cve_crashes"
        legacy_crashes.mkdir(exist_ok=True)
        (legacy_crashes / "crash-stale").write_bytes(b"FROM_OLD_RUN")

        observed: list[tuple[Path, Path, set[str]]] = []

        async def execute_crashing_run(cmd, **kwargs):
            seeds = Path(cmd[1])
            artifact_prefix = Path(
                next(arg.split("=", 1)[1] for arg in cmd if arg.startswith("-artifact_prefix="))
            )
            artifact = artifact_prefix / "crash-current-run"
            artifact.write_bytes(Path(cmd[0]).name.encode())
            observed.append((seeds, artifact_prefix, {path.name for path in seeds.iterdir()}))
            await asyncio.sleep(0)
            output = SAMPLE_ASAN_CRASH_LOG.replace(
                "stat::number_of_executed_units:",
                f"Test unit written to {artifact}\nstat::number_of_executed_units:",
            )
            return output, len(output)

        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(side_effect=execute_crashing_run),
        ):
            results = await asyncio.gather(
                run_hybrid_fuzz_impl(str(test_bin_a), enable_angr_concolic=False),
                run_hybrid_fuzz_impl(str(test_bin_b), enable_angr_concolic=False),
            )

        assert all(result.status == "success" for result in results)
        assert len(observed) == 2
        assert observed[0][0] != observed[1][0]
        assert observed[0][0].parent != observed[1][0].parent
        assert all(seeds.parent == crashes.parent for seeds, crashes, _ in observed)
        assert all(names == {"seed_init.bin"} for _, _, names in observed)
        assert all(
            seeds.is_relative_to(get_workspace_config().workspace / ".cache" / "fuzz")
            for seeds, _, _ in observed
        )
        crash_inputs = [Path(result.data["crash_artifacts"][0]) for result in results]
        assert crash_inputs[0] != crash_inputs[1]
        assert len({path.parent for path in crash_inputs}) == 2
        for result, artifact in zip(results, crash_inputs, strict=True):
            assert artifact.read_bytes() == Path(result.data["target_binary"]).name.encode()
            assert result.data["triaged_crashes"][0]["crash_input_path"] == str(artifact)
        assert (legacy_seeds / "stale-seed.bin").read_bytes() == b"FROM_OLD_RUN"
        assert (legacy_crashes / "crash-stale").read_bytes() == b"FROM_OLD_RUN"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_clean_run_reports_no_crashes(self, workspace_file):
        test_bin = workspace_file("clean_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        clean_output = "stat::number_of_executed_units: 42\n"
        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(return_value=(clean_output, len(clean_output))),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "success"
        assert res.data["execution_status"] == "completed"
        assert res.data["crashes_detected"] == 0
        assert res.data["triaged_crashes"] == []

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_requires_completion_statistics(self, workspace_file):
        test_bin = workspace_file("missing_stats_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        output = "program exited successfully\n"
        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(return_value=(output, len(output))),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "error"
        assert res.error_code == "FUZZING_INCOMPLETE"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_zero_executions_is_incomplete(self, workspace_file):
        test_bin = workspace_file("zero_exec_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        output = "stat::number_of_executed_units: 0\n"
        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(return_value=(output, len(output))),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "error"
        assert res.error_code == "FUZZING_INCOMPLETE"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_does_not_treat_generic_error_as_crash(self, workspace_file):
        test_bin = workspace_file("error_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        subprocess_error = subprocess.CalledProcessError(
            1,
            [str(test_bin)],
            output="ERROR: could not open input file",
            stderr="",
        )
        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(side_effect=subprocess_error),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "error"
        assert res.error_code == "FUZZING_FAILED"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_rejects_sanitizer_without_crash_input(self, workspace_file):
        test_bin = workspace_file("unlinked_crash_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)
        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(return_value=(SAMPLE_ASAN_CRASH_LOG, len(SAMPLE_ASAN_CRASH_LOG))),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "error"
        assert res.error_code == "CRASH_EVIDENCE_INCOMPLETE"

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_preserves_unmapped_sanitizer_class(self, workspace_file):
        test_bin = workspace_file("unmapped_crash_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)

        async def execute_with_unmapped_crash(cmd, **kwargs):
            artifact_prefix = next(
                arg.split("=", 1)[1] for arg in cmd if arg.startswith("-artifact_prefix=")
            )
            artifact = Path(artifact_prefix) / "crash-unmapped-input"
            artifact.write_bytes(b"UNKNOWN_SANITIZER_CRASH")
            output = (
                "==1234==ERROR: AddressSanitizer: container-overflow on address 0x602000000010\n"
                f"Test unit written to {artifact}\n"
                "stat::number_of_executed_units: 11\n"
            )
            return output, len(output)

        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(side_effect=execute_with_unmapped_crash),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                enable_angr_concolic=False,
            )

        assert res.status == "success"
        assert res.data["execution_status"] == "crash_detected"
        triage = res.data["triaged_crashes"][0]
        assert triage["bug_type"] == "container-overflow"
        assert triage["cwe_id"] is None
        assert triage["cvss"] is None
        assert (
            triage["crash_input_sha256"] == hashlib.sha256(b"UNKNOWN_SANITIZER_CRASH").hexdigest()
        )

    @pytest.mark.asyncio
    async def test_run_hybrid_fuzz_timeout_handling(self, workspace_file):
        test_bin = workspace_file("timeout_fuzzer.bin", content=b"\x7fELF" + b"\x00" * 100)

        with patch(
            "reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator.execute_subprocess_async",
            new=AsyncMock(return_value=("stat::number_of_executed_units: 500\n", 38)),
        ):
            res = await run_hybrid_fuzz_impl(
                target_binary_path=str(test_bin),
                max_total_time_seconds=1,
                enable_angr_concolic=False,
            )

        assert res.status == "success"
        assert res.data["total_executions"] == 500
