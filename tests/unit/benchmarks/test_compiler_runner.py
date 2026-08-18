"""Unit tests for LiveTargetCompilerRunner dynamic compilation and execution."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.benchmarks.capabilities import detect_capabilities
from reversecore_mcp.benchmarks.compiler_runner import LiveTargetCompilerRunner
from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import TargetGroundTruth


@pytest.fixture
def corpus_loader() -> CorpusLoader:
    return CorpusLoader(corpus_dir="tests/fixtures/benchmarks")


@pytest.fixture
def sqlite_target(corpus_loader: CorpusLoader) -> TargetGroundTruth:
    targets = {t.target_id: t for t in corpus_loader.load_corpus()}
    return targets["sqlite3_fts5_unicode"]


@pytest.fixture
def openssl_target(corpus_loader: CorpusLoader) -> TargetGroundTruth:
    targets = {t.target_id: t for t in corpus_loader.load_corpus()}
    return targets["openssl_bn_infinite_loop"]


@pytest.mark.unit
class TestLiveTargetCompilerRunner:
    """Tests for LiveTargetCompilerRunner."""

    def test_compile_target_real_clang_sqlite3(
        self, sqlite_target: TargetGroundTruth, tmp_path: Path
    ):
        """Verify dynamic compilation succeeds on self-contained SQLite3 target."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang or ASan not available on host system")

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None
        assert compiled_bin.exists()
        assert compiled_bin.is_file()

    def test_compile_target_missing_clang(self, sqlite_target: TargetGroundTruth, tmp_path: Path):
        """Verify compilation returns None when invalid compiler path is passed."""
        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            clang_path=tmp_path / "non_existent_clang_9999",
            work_dir=tmp_path,
        )
        assert compiled_bin is None

    def test_compile_target_missing_source(self, sqlite_target: TargetGroundTruth, tmp_path: Path):
        """Verify compilation returns None when vulnerable source does not exist."""
        fake_target = sqlite_target.model_copy(deep=True)
        fake_target.fixtures.vulnerable_source = "targets/nonexistent/fake.c"
        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=fake_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is None

    def test_compile_target_with_header_dependency_returns_none_cleanly(
        self, openssl_target: TargetGroundTruth, tmp_path: Path
    ):
        """Verify compilation of targets requiring external headers fails cleanly with None."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang or ASan not available on host system")

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=openssl_target,
            work_dir=tmp_path,
        )
        # OpenSSL target requires openssl/bn.h which is absent in standalone compile
        assert compiled_bin is None

    def test_execute_live_target_sqlite3_crash(
        self,
        sqlite_target: TargetGroundTruth,
        corpus_loader: CorpusLoader,
        tmp_path: Path,
    ):
        """Verify executing compiled SQLite target with raw PoC reproduces ASan crash."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang or ASan not available on host system")

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None

        raw_poc = (corpus_loader.corpus_dir / sqlite_target.fixtures.raw_crash_poc).read_bytes()
        rc, stderr, elapsed_ttc = LiveTargetCompilerRunner.execute_live_target(
            target=sqlite_target,
            compiled_bin=compiled_bin,
            poc_payload=raw_poc,
            timeout_seconds=30.0,
        )
        assert rc != 0
        assert "AddressSanitizer" in stderr
        assert "heap-buffer-overflow" in stderr
        assert "fts5UnicodeTokenize" in stderr
        assert elapsed_ttc > 0.0

    def test_execute_live_target_nonexistent_binary(
        self, sqlite_target: TargetGroundTruth, tmp_path: Path
    ):
        """Verify executing a nonexistent binary returns error tuple cleanly."""
        fake_bin = tmp_path / "fake_bin"
        rc, stderr, ttc = LiveTargetCompilerRunner.execute_live_target(
            target=sqlite_target,
            compiled_bin=fake_bin,
            poc_payload=b"AAAA",
            timeout_seconds=5.0,
        )
        assert rc == -1
        assert "not found" in stderr

    def test_execute_live_target_timeout(self, sqlite_target: TargetGroundTruth, tmp_path: Path):
        """Verify execution timeout is caught and formatted cleanly."""
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["target_bin"], timeout=1.0),
        ):
            rc, stderr, ttc = LiveTargetCompilerRunner.execute_live_target(
                target=sqlite_target,
                compiled_bin=fake_bin,
                poc_payload=b"AAAA",
                timeout_seconds=1.0,
            )
            assert rc == -1
            assert "timed out" in stderr.lower()

    def test_run_live_poc_minimization_sqlite3(
        self,
        sqlite_target: TargetGroundTruth,
        corpus_loader: CorpusLoader,
        tmp_path: Path,
    ):
        """Verify delta-debugging minimization shrinks SQLite3 raw payload with >= 80% reduction."""
        caps = detect_capabilities()
        if not caps.live_fuzzing_ready:
            pytest.skip("Clang or ASan not available on host system")

        compiled_bin = LiveTargetCompilerRunner.compile_target(
            target=sqlite_target,
            work_dir=tmp_path,
        )
        assert compiled_bin is not None

        raw_poc = (corpus_loader.corpus_dir / sqlite_target.fixtures.raw_crash_poc).read_bytes()
        min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
            target=sqlite_target,
            compiled_bin=compiled_bin,
            raw_poc=raw_poc,
            max_iterations=30,
        )
        assert len(min_bytes) < len(raw_poc)
        assert ratio >= 0.80

    def test_run_live_poc_minimization_short_payload(
        self, sqlite_target: TargetGroundTruth, tmp_path: Path
    ):
        """Verify payloads <= 4 bytes are returned as-is without minimization."""
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
            target=sqlite_target,
            compiled_bin=fake_bin,
            raw_poc=b"ABC",
        )
        assert min_bytes == b"ABC"
        assert ratio == 0.0

    def test_run_live_poc_minimization_non_crashing_payload(
        self, sqlite_target: TargetGroundTruth, tmp_path: Path
    ):
        """Verify payloads that do not trigger a crash are returned unchanged."""
        fake_bin = tmp_path / "bin"
        fake_bin.touch()

        # Mock execute_live_target to return 0 (no crash)
        with patch.object(
            LiveTargetCompilerRunner,
            "execute_live_target",
            return_value=(0, "Normal execution without crash", 0.05),
        ):
            non_crash_payload = b"SAFE_NON_CRASHING_INPUT_12345678"
            min_bytes, ratio = LiveTargetCompilerRunner.run_live_poc_minimization(
                target=sqlite_target,
                compiled_bin=fake_bin,
                raw_poc=non_crash_payload,
            )
            assert min_bytes == non_crash_payload
            assert ratio == 0.0
