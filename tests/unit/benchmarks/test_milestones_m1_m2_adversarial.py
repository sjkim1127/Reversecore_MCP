"""Adversarial and empirical stress tests for Milestones M1 and M2.

Stress-tests:
1. CapabilityDetector:
   - Precedence hierarchy with valid and invalid override paths.
   - Non-executable file, directory path, hanging script (3s timeout containment).
   - Segfaulting/crashing compiler script, malformed output.
   - High-concurrency multithreaded detection without race conditions or cache corruption.
2. LiveTargetCompilerRunner:
   - Corrupted C code compilation, missing symbols, header errors.
   - 0-byte PoC execution, 1-byte non-crashing PoC, 11MB+ oversized PoC.
   - Infinite loop subprocess timeout containment.
   - Delta-debugging minimization on irreducible, non-crashing, partially-reducible, and iteration-bounded payloads.
3. BenchmarkRunner Hybrid Fallback:
   - 100% reliability in mock mode.
   - Clean fallback to mock when compiler is missing or compilation fails with auto_fallback=True.
   - Graceful error recording and scorecard aggregation when auto_fallback=False.
"""

from __future__ import annotations

import os
import stat
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.benchmarks.capabilities import (
    CapabilityDetector,
    ToolchainCapabilities,
    detect_capabilities,
)
from reversecore_mcp.benchmarks.compiler_runner import (
    LiveTargetCompilerRunner,
)
from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import (
    CVSSGroundTruth,
    ExecutionOptions,
    FixturePaths,
    TargetGroundTruth,
)
from reversecore_mcp.benchmarks.runner import BenchmarkRunner


def _make_dummy_target(
    target_id: str = "adversarial_target",
    vulnerable_source: str = "targets/sqlite_fts5/vulnerable.c",
) -> TargetGroundTruth:
    """Create a minimal valid TargetGroundTruth instance for testing."""
    return TargetGroundTruth(
        target_id=target_id,
        target_name=f"Target {target_id}",
        category="parser",
        real_world_library="libtest",
        target_version="1.0.0",
        cve_reference="CVE-2026-0001",
        vulnerability_class="heap_buffer_overflow",
        cwe_id="CWE-122",
        cwe_name="Heap-based Buffer Overflow",
        faulting_symbol="fts5UnicodeTokenize",
        source_file="vulnerable.c",
        source_line=44,
        expected_memory_access_type="WRITE_OOB",
        expected_access_size=4,
        cvss=CVSSGroundTruth(
            base_score_min=8.0,
            base_score_max=9.5,
            severity="HIGH",
            expected_score=8.8,
            expected_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
        fixtures=FixturePaths(
            vulnerable_source=vulnerable_source,
            patched_source="targets/sqlite_fts5/patched.c",
            patch_diff="targets/sqlite_fts5/patch.diff",
            harness_c="targets/sqlite_fts5/harness.c",
            asan_crash_log="targets/sqlite_fts5/asan_crash.log",
            raw_crash_poc="targets/sqlite_fts5/raw_poc.bin",
            minimized_poc="targets/sqlite_fts5/minimized_poc.bin",
            valid_seed_corpus="targets/sqlite_fts5/seed_corpus.bin",
        ),
        raw_poc_size_bytes=39,
        minimized_poc_target_bytes=2,
        expected_minimization_ratio_min=0.5,
    )


# ============================================================================
# 1. Adversarial Tests for CapabilityDetector (Milestone M1)
# ============================================================================


@pytest.mark.unit
class TestCapabilityDetectorAdversarial:
    """Stress tests and boundary condition attacks against CapabilityDetector."""

    def test_nonexistent_clang_path_override_hierarchy(self, tmp_path: Path):
        """When an invalid override path is provided, find_clang_binary falls back down the hierarchy."""
        non_existent = tmp_path / "non_existent_clang_binary_xyz_123"

        # Mock PATH, env, and config as empty to test total absence
        with (
            patch.dict(os.environ, {"REVERSECORE_CLANG_PATH": ""}, clear=True),
            patch("shutil.which", return_value=None),
            patch.object(CapabilityDetector, "_STANDARD_CLANG_PATHS", ()),
        ):
            found = CapabilityDetector.find_clang_binary(override_path=non_existent)
            assert found is None

            caps = detect_capabilities(clang_path_override=non_existent)
            assert caps.clang_available is False
            assert caps.clang_path is None
            assert caps.live_fuzzing_ready is False

    def test_non_executable_clang_file(self, tmp_path: Path):
        """File without execute permissions must be rejected during precedence evaluation."""
        non_exec = tmp_path / "clang_no_exec"
        non_exec.write_text("#!/bin/sh\necho clang", encoding="utf-8")
        non_exec.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 (no +x)

        with (
            patch.dict(os.environ, {"REVERSECORE_CLANG_PATH": ""}, clear=True),
            patch("shutil.which", return_value=None),
            patch.object(CapabilityDetector, "_STANDARD_CLANG_PATHS", ()),
        ):
            found = CapabilityDetector.find_clang_binary(override_path=non_exec)
            assert found is None

    def test_directory_as_clang_path(self, tmp_path: Path):
        """Passing a directory instead of a binary must be safely rejected."""
        a_dir = tmp_path / "clang_dir"
        a_dir.mkdir()

        res = CapabilityDetector._probe_compiler_flag(
            a_dir, ["-fsanitize=address"], "int main(){return 0;}"
        )
        assert res is False

    def test_hanging_clang_script_timeout_containment(self, tmp_path: Path):
        """A compiler script that sleeps forever must timeout in <=3.5s and return False."""
        hang_script = tmp_path / "hanging_clang.sh"
        hang_script.write_text("#!/bin/sh\nwhile true; do sleep 1; done\n", encoding="utf-8")
        hang_script.chmod(stat.S_IRWXU)

        start = time.perf_counter()
        res = CapabilityDetector._probe_compiler_flag(
            hang_script, ["-fsanitize=address"], "int main(){return 0;}"
        )
        elapsed = time.perf_counter() - start

        assert res is False
        assert elapsed < 5.0, f"Probe took too long ({elapsed}s), timeout failed"

        # Version probe should also timeout safely
        ver_start = time.perf_counter()
        ver = CapabilityDetector._get_clang_version(hang_script)
        ver_elapsed = time.perf_counter() - ver_start

        assert ver is None
        assert ver_elapsed < 5.0, f"Version probe took too long ({ver_elapsed}s), timeout failed"

        # When hanging script is used as clang override in detect(), live_fuzzing_ready is False
        caps = detect_capabilities(clang_path_override=hang_script)
        assert caps.clang_available is True
        assert caps.asan_supported is False
        assert caps.live_fuzzing_ready is False

    def test_crashing_and_segfaulting_clang_script(self, tmp_path: Path):
        """A compiler script that exits with non-zero or crashes must be handled cleanly."""
        crash_script = tmp_path / "crash_clang.sh"
        crash_script.write_text("#!/bin/sh\nkill -SEGV $$\n", encoding="utf-8")
        crash_script.chmod(stat.S_IRWXU)

        res = CapabilityDetector._probe_compiler_flag(
            crash_script, ["-fsanitize=address"], "int main(){return 0;}"
        )
        assert res is False

        ver = CapabilityDetector._get_clang_version(crash_script)
        assert ver is None

    def test_empty_output_clang_script(self, tmp_path: Path):
        """A compiler script that outputs nothing and returns 0 must not cause index errors."""
        empty_script = tmp_path / "empty_clang.sh"
        empty_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        empty_script.chmod(stat.S_IRWXU)

        ver = CapabilityDetector._get_clang_version(empty_script)
        assert ver is None

    def test_concurrency_race_conditions_detect_multithreaded(self):
        """Verify 50 concurrent threads calling detect() with force_refresh do not race or deadlock."""
        num_threads = 50
        results: list[ToolchainCapabilities] = []
        errors: list[Exception] = []

        def worker():
            try:
                caps = CapabilityDetector.detect(force_refresh=True)
                results.append(caps)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker) for _ in range(num_threads)]
            for f in futures:
                f.result()

        assert len(errors) == 0, f"Encountered thread errors: {errors}"
        assert len(results) == num_threads
        for r in results:
            assert isinstance(r, ToolchainCapabilities)

    def test_concurrency_mixed_overrides_and_cache_integrity(self, tmp_path: Path):
        """Verify concurrent calls with different clang overrides do not corrupt global cache."""
        fake_clang = tmp_path / "fake_clang_worker"
        fake_clang.write_text("#!/bin/sh\necho fake", encoding="utf-8")
        fake_clang.chmod(stat.S_IRWXU)

        # Baseline cache
        baseline = detect_capabilities(force_refresh=True)

        def worker_override():
            caps = detect_capabilities(clang_path_override=fake_clang)
            assert caps.clang_path == fake_clang.resolve()

        def worker_cached():
            caps = detect_capabilities(force_refresh=False)
            assert caps.clang_path == baseline.clang_path

        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = []
            for i in range(30):
                if i % 2 == 0:
                    futures.append(pool.submit(worker_override))
                else:
                    futures.append(pool.submit(worker_cached))
            for f in futures:
                f.result()

        # Cache must remain intact
        final_cached = detect_capabilities(force_refresh=False)
        assert final_cached.clang_path == baseline.clang_path


# ============================================================================
# 2. Adversarial Tests for LiveTargetCompilerRunner (Milestone M2)
# ============================================================================


@pytest.mark.unit
class TestLiveTargetCompilerRunnerAdversarial:
    """Stress tests and boundary condition attacks against LiveTargetCompilerRunner."""

    def test_compile_corrupted_c_code(self, tmp_path: Path):
        """Compiling a target with syntax errors must return None cleanly."""
        corrupted_dir = tmp_path / "corrupted_target"
        corrupted_dir.mkdir()
        bad_c = corrupted_dir / "vulnerable.c"
        bad_c.write_text("INVALID C SYNTAX {{{ @@@ @#$!%#", encoding="utf-8")

        target = _make_dummy_target(
            target_id="corrupted_c",
            vulnerable_source="corrupted_target/vulnerable.c",
        )

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=target,
            work_dir=tmp_path / "build",
            corpus_dir=tmp_path,
        )
        assert compiled_bin is None

    def test_compile_missing_external_symbols(self, tmp_path: Path):
        """Compiling a target referencing non-existent linker symbols must return None."""
        sym_dir = tmp_path / "missing_sym_target"
        sym_dir.mkdir()
        src_c = sym_dir / "vulnerable.c"
        src_c.write_text(
            """#include <stdint.h>
#include <stddef.h>
extern void nonexistent_external_symbol_12345(void);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    nonexistent_external_symbol_12345();
    return 0;
}
""",
            encoding="utf-8",
        )

        target = _make_dummy_target(
            target_id="missing_sym",
            vulnerable_source="missing_sym_target/vulnerable.c",
        )

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=target,
            work_dir=tmp_path / "build",
            corpus_dir=tmp_path,
        )
        assert compiled_bin is None

    def test_execute_zero_byte_poc(self, tmp_path: Path):
        """Executing with a 0-byte PoC must succeed gracefully without crashing."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang/ASan not available on host")

        corpus_loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = {t.target_id: t for t in corpus_loader.load_corpus()}
        sqlite_target = targets["sqlite3_fts5_unicode"]

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None

        rc, stderr, elapsed_ttc = LiveTargetCompilerRunner.execute_live_target(
            target=sqlite_target,
            compiled_bin=compiled_bin,
            poc_payload=b"",
            timeout_seconds=5.0,
        )
        # Driver checks sz <= 0 and returns 0 cleanly
        assert rc == 0
        assert "AddressSanitizer" not in stderr
        assert elapsed_ttc >= 0.0

    def test_execute_oversized_11mb_poc(self, tmp_path: Path):
        """Executing with an oversized 11MB PoC must be safely handled without memory blowout."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang/ASan not available on host")

        corpus_loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = {t.target_id: t for t in corpus_loader.load_corpus()}
        sqlite_target = targets["sqlite3_fts5_unicode"]

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None

        oversized_poc = b"A" * (11 * 1024 * 1024)  # 11MB
        rc, stderr, elapsed_ttc = LiveTargetCompilerRunner.execute_live_target(
            target=sqlite_target,
            compiled_bin=compiled_bin,
            poc_payload=oversized_poc,
            timeout_seconds=5.0,
        )
        # Driver guards against sz > 10MB and returns 0 cleanly
        assert rc == 0
        assert "AddressSanitizer" not in stderr

    def test_execute_safe_non_crashing_input(self, tmp_path: Path):
        """Executing with safe 1-byte payload must return returncode 0 without ASan report."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang/ASan not available on host")

        corpus_loader = CorpusLoader("tests/fixtures/benchmarks")
        targets = {t.target_id: t for t in corpus_loader.load_corpus()}
        sqlite_target = targets["sqlite3_fts5_unicode"]

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None

        # 1-byte input is filtered by harness (size < 2 returns 0) and does not crash
        safe_input = b"A"
        rc, stderr, elapsed_ttc = LiveTargetCompilerRunner.execute_live_target(
            target=sqlite_target,
            compiled_bin=compiled_bin,
            poc_payload=safe_input,
            timeout_seconds=5.0,
        )
        assert rc == 0
        assert "AddressSanitizer" not in stderr

    def test_execute_target_infinite_loop_timeout(self, tmp_path: Path):
        """Target execution entering an infinite loop must be halted by timeout_seconds."""
        fake_bin = tmp_path / "infinite_loop_bin"
        fake_bin.touch()

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["bin"], timeout=1.0),
        ):
            target = _make_dummy_target()
            start = time.perf_counter()
            rc, stderr, ttc = LiveTargetCompilerRunner.execute_live_target(
                target=target,
                compiled_bin=fake_bin,
                poc_payload=b"TRIGGER",
                timeout_seconds=1.0,
            )
            elapsed = time.perf_counter() - start

            assert rc == -1
            assert "timed out" in stderr.lower()
            assert elapsed < 3.0

    def test_minimization_irreducible_crashing_payload(self, tmp_path: Path):
        """When every remaining byte is essential to reproduce the crash, minimization preserves it."""
        target = _make_dummy_target()
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        # Mock execute_live_target: only crashes if candidate == b"CRASH_EXACT_9B"
        def mock_exec(target, compiled_bin, poc_payload, timeout_seconds):
            if poc_payload == b"CRASH_EXACT_9B":
                return (-6, "ERROR: AddressSanitizer: heap-buffer-overflow", 0.01)
            return (0, "no crash", 0.01)

        with patch.object(LiveTargetCompilerRunner, "execute_live_target", side_effect=mock_exec):
            min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
                target=target,
                compiled_bin=fake_bin,
                raw_poc=b"CRASH_EXACT_9B",
                max_iterations=20,
            )
            assert min_bytes == b"CRASH_EXACT_9B"
            assert ratio == 0.0

    def test_minimization_partially_reducible_payload(self, tmp_path: Path):
        """When padding surrounds the crash trigger, delta-debugging trims the padding."""
        target = _make_dummy_target()
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        # Crash occurs whenever b"TRIGGER" is a substring of poc_payload
        def mock_exec(target, compiled_bin, poc_payload, timeout_seconds):
            if b"TRIGGER" in poc_payload:
                return (-6, "ERROR: AddressSanitizer: heap-buffer-overflow", 0.01)
            return (0, "no crash", 0.01)

        raw_payload = b"PAD1111111111111" + b"TRIGGER" + b"PAD2222222222222"
        with patch.object(LiveTargetCompilerRunner, "execute_live_target", side_effect=mock_exec):
            min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
                target=target,
                compiled_bin=fake_bin,
                raw_poc=raw_payload,
                max_iterations=30,
            )
            assert b"TRIGGER" in min_bytes
            assert len(min_bytes) < len(raw_payload)
            assert ratio > 0.0

    def test_minimization_max_iterations_bound(self, tmp_path: Path):
        """Max iterations limit must stop delta-debugging gracefully without infinite loops."""
        target = _make_dummy_target()
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        with patch.object(
            LiveTargetCompilerRunner,
            "execute_live_target",
            return_value=(-6, "ERROR: AddressSanitizer: crash", 0.01),
        ):
            raw_payload = b"X" * 1024
            min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
                target=target,
                compiled_bin=fake_bin,
                raw_poc=raw_payload,
                max_iterations=2,
            )
            assert isinstance(min_bytes, bytes)
            assert 0.0 <= ratio <= 1.0


# ============================================================================
# 3. Adversarial Tests for BenchmarkRunner Hybrid Fallback (Milestones M1 & M2)
# ============================================================================


@pytest.mark.unit
class TestBenchmarkRunnerHybridFallbackAdversarial:
    """Stress tests for BenchmarkRunner fallback logic and option handling."""

    @pytest.mark.asyncio
    async def test_mock_mode_100_percent_reliable_across_corpus(self):
        """Mock mode must execute 10/10 targets with 100% TPR and exact CWE matches."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)
        scorecard = await runner.run_suite("all", "all")

        assert scorecard.total_targets == 10
        assert scorecard.discovered_count == 10
        assert scorecard.discovery_rate_tpr_pct == 100.0
        assert scorecard.cwe_exact_match_rate_pct == 100.0
        assert scorecard.cvss_tolerance_match_rate_pct == 100.0
        assert scorecard.error_count == 0

    @pytest.mark.asyncio
    async def test_live_mode_missing_compiler_clean_fallback(self):
        """When live mode is requested but clang is missing, runner cleanly routes to mock pipeline."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)
        targets = runner.corpus_loader.load_corpus()
        target = targets[0]

        # Pass a non-existent compiler override with auto_fallback=True
        # and patch detect_capabilities to return live_fuzzing_ready=False
        dummy_caps = ToolchainCapabilities(
            clang_available=False,
            clang_path=None,
            clang_version=None,
            asan_supported=False,
            ubsan_supported=False,
            libfuzzer_supported=False,
            llvm_symbolizer_available=False,
            llvm_symbolizer_path=None,
            afl_available=False,
            afl_path=None,
            docker_available=False,
            angr_available=False,
            radare2_available=False,
        )
        with patch(
            "reversecore_mcp.benchmarks.runner.detect_capabilities",
            return_value=dummy_caps,
        ):
            opts = ExecutionOptions(
                mock_mode=False,
                clang_path="/nonexistent/clang_compiler_path_xyz",
                auto_fallback=True,
            )
            result = await runner.run_target(target, options=opts)

            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.ground_truth_cwe == target.cwe_id

    @pytest.mark.asyncio
    async def test_live_mode_compilation_failure_clean_fallback(self, tmp_path: Path):
        """When compilation fails for a target with auto_fallback=True, mock pipeline is used."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)
        targets = runner.corpus_loader.load_corpus()
        target = targets[0]

        # Simulate compilation failure returning None
        with patch.object(LiveTargetCompilerRunner, "compile_target", return_value=None):
            opts = ExecutionOptions(mock_mode=False, auto_fallback=True)
            result = await runner.run_target(target, options=opts)

            assert result.status == "DISCOVERED"
            assert result.is_true_positive is True
            assert result.cwe_exact_match is True

    @pytest.mark.asyncio
    async def test_auto_fallback_disabled_compilation_failure_error_recording(self):
        """When compilation fails with auto_fallback=False, target evaluation returns status='ERROR'."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)
        targets = runner.corpus_loader.load_corpus()
        target = targets[0]

        # Simulate compilation failure returning None
        with patch.object(LiveTargetCompilerRunner, "compile_target", return_value=None):
            opts = ExecutionOptions(mock_mode=False, auto_fallback=False)
            result = await runner.run_target(target, options=opts)

            assert result.status == "ERROR"
            assert result.is_true_positive is False
            assert "compilation failed" in str(result.error_message).lower()

    @pytest.mark.asyncio
    async def test_suite_error_aggregation_when_fallback_disabled(self):
        """Running suite with auto_fallback=False when compilation fails aggregates errors properly."""
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=False)

        with patch.object(LiveTargetCompilerRunner, "compile_target", return_value=None):
            opts = ExecutionOptions(
                mock_mode=False,
                auto_fallback=False,
                parallel_workers=2,
            )
            # Run against 2 targets
            scorecard = await runner.run_suite(
                target_filter=["sqlite3_fts5_unicode", "libpng_eXIf_int_overflow"],
                options=opts,
            )

            assert scorecard.total_targets == 2
            assert scorecard.discovered_count == 0
            assert scorecard.error_count == 2
            for res in scorecard.target_results:
                assert res.status == "ERROR"
                assert "compilation failed" in str(res.error_message).lower()

    @pytest.mark.asyncio
    async def test_execution_options_precedence(self):
        """ExecutionOptions passed to run_target must override BenchmarkRunner defaults."""
        # Runner initialized with mock_mode=True
        runner = BenchmarkRunner(corpus_dir="tests/fixtures/benchmarks", mock_mode=True)
        target = runner.corpus_loader.load_corpus()[0]

        # Explicit dict options with mock_mode=False and auto_fallback=False
        with patch.object(LiveTargetCompilerRunner, "compile_target", return_value=None):
            res = await runner.run_target(
                target,
                options={"mock_mode": False, "auto_fallback": False},
            )
            assert res.status == "ERROR"
            assert "compilation failed" in str(res.error_message).lower()
