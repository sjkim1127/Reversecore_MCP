"""Dynamic C Target Compilation, ASan Execution, and PoC Minimization Runner.

Compiles ground-truth C/C++ benchmark target harnesses with AddressSanitizer and UndefinedBehaviorSanitizer,
executes them against raw/synthesized PoCs to capture live crash telemetry and Time-To-Crash (TTC),
and applies delta-debugging minimization to verify payload byte reduction ratios.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

from reversecore_mcp.benchmarks.capabilities import detect_capabilities
from reversecore_mcp.benchmarks.models import TargetGroundTruth
from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)

# Lightweight standalone fuzzer/harness driver template
_GENERIC_DRIVER_C = """#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 10 * 1024 * 1024) {
        fclose(f);
        return 0;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 1;
    }
    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    int res = LLVMFuzzerTestOneInput(buf, read_bytes);
    free(buf);
    return res;
}
"""


class LiveTargetCompilerRunner:
    """Dynamic compiler and execution runner for benchmark C targets."""

    @classmethod
    def compile_target(
        cls,
        target: TargetGroundTruth,
        clang_path: Path | str | None = None,
        work_dir: Path | str | None = None,
        corpus_dir: Path | str | None = None,
    ) -> Path | None:
        """Compile target vulnerable.c + harness.c + driver with AddressSanitizer.

        Args:
            target: Ground truth target definition.
            clang_path: Optional explicit Clang compiler binary path.
            work_dir: Optional compilation working directory.
            corpus_dir: Optional root directory of benchmark corpus.

        Returns:
            Path to compiled executable binary, or None if compilation fails.
        """
        # 1. Resolve Clang compiler executable
        clang_bin: Path | None
        if clang_path:
            clang_bin = Path(clang_path).expanduser().resolve()
        else:
            caps = detect_capabilities()
            clang_bin = caps.clang_path

        if not clang_bin or not clang_bin.exists():
            logger.warning(
                "Clang compiler not available for live compilation of %s",
                target.target_id,
            )
            return None

        # 2. Resolve source file paths
        c_root = (
            Path(corpus_dir).resolve()
            if corpus_dir
            else Path("tests/fixtures/benchmarks").resolve()
        )
        vuln_c = (c_root / target.fixtures.vulnerable_source).resolve()
        if not vuln_c.exists():
            logger.warning("Vulnerable source file not found: %s", vuln_c)
            return None

        target_dir = vuln_c.parent
        harness_c = target_dir / "harness.c"

        # 3. Setup build directory
        build_dir = (
            Path(work_dir).resolve()
            if work_dir
            else Path(tempfile.mkdtemp(prefix=f"rcmcp_build_{target.target_id}_"))
        )
        build_dir.mkdir(parents=True, exist_ok=True)

        driver_c = build_dir / "driver.c"
        driver_c.write_text(_GENERIC_DRIVER_C, encoding="utf-8")

        out_bin = build_dir / f"{target.target_id}_bin"

        # 4. Build compilation command
        cmd: list[str] = [
            str(clang_bin),
            "-fsanitize=address,undefined",
            "-g",
            "-O1",
            f"-I{target_dir}",
            f"-I{c_root}",
            str(driver_c),
            str(vuln_c),
        ]
        if harness_c.exists():
            cmd.append(str(harness_c))
        cmd.extend(["-o", str(out_bin)])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15.0,
            )
            if res.returncode == 0 and out_bin.exists():
                out_bin.chmod(0o755)
                logger.info(
                    "Successfully compiled live target %s -> %s",
                    target.target_id,
                    out_bin,
                )
                return out_bin
            else:
                logger.debug(
                    "Live target %s compilation returned non-zero code %d. Stderr: %s",
                    target.target_id,
                    res.returncode,
                    res.stderr,
                )
                return None
        except Exception as exc:
            logger.debug("Exception during live compilation of %s: %s", target.target_id, exc)
            return None

    @classmethod
    def execute_live_target(
        cls,
        target: TargetGroundTruth,
        compiled_bin: Path | str,
        poc_payload: bytes,
        timeout_seconds: float = 30.0,
    ) -> tuple[int, str, float]:
        """Execute compiled target binary with PoC payload and ASan environment.

        Args:
            target: Ground truth target definition.
            compiled_bin: Path to compiled target executable.
            poc_payload: Binary crash-inducing payload.
            timeout_seconds: Execution timeout in seconds.

        Returns:
            Tuple of (returncode, stderr, elapsed_time_to_crash_seconds).
        """
        bin_path = Path(compiled_bin).resolve()
        if not bin_path.exists():
            return (-1, f"Compiled binary not found: {bin_path}", 0.001)

        asan_env = {
            **os.environ,
            "ASAN_OPTIONS": "detect_leaks=0:symbolize=1:abort_on_error=1:halt_on_error=1:color=never",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }

        with tempfile.NamedTemporaryFile(prefix="rcmcp_poc_", suffix=".bin", delete=False) as tmp_f:
            tmp_f.write(poc_payload)
            tmp_poc_path = Path(tmp_f.name)

        start_time = time.perf_counter()
        try:
            proc = subprocess.run(
                [str(bin_path), str(tmp_poc_path)],
                capture_output=True,
                text=True,
                env=asan_env,
                timeout=timeout_seconds,
            )
            elapsed_ttc = time.perf_counter() - start_time
            return (proc.returncode, proc.stderr, round(max(0.001, elapsed_ttc), 4))
        except subprocess.TimeoutExpired:
            elapsed_ttc = time.perf_counter() - start_time
            return (
                -1,
                f"Live target execution timed out after {timeout_seconds}s",
                round(elapsed_ttc, 4),
            )
        except Exception as exc:
            elapsed_ttc = time.perf_counter() - start_time
            return (
                -1,
                f"Execution exception: {exc}",
                round(max(0.001, elapsed_ttc), 4),
            )
        finally:
            try:
                if tmp_poc_path.exists():
                    tmp_poc_path.unlink()
            except OSError:
                pass

    @classmethod
    def run_live_poc_minimization(
        cls,
        target: TargetGroundTruth,
        compiled_bin: Path | str,
        raw_poc: bytes,
        max_iterations: int = 50,
    ) -> tuple[bytes, float]:
        """Perform delta-debugging minimization against compiled binary.

        Args:
            target: Ground truth target definition.
            compiled_bin: Path to compiled target executable.
            raw_poc: Initial raw crash payload.
            max_iterations: Maximum bisection reduction passes.

        Returns:
            Tuple of (minimized_bytes, reduction_ratio [0.0 to 1.0]).
        """
        if len(raw_poc) <= 4:
            return (raw_poc, 0.0)

        bin_path = Path(compiled_bin).resolve()

        def _test_crash(candidate: bytes) -> bool:
            if not candidate:
                return False
            rc, stderr, _ = cls.execute_live_target(
                target, bin_path, candidate, timeout_seconds=3.0
            )
            return rc != 0 or "AddressSanitizer" in stderr or "SUMMARY:" in stderr

        # Verify initial input reproduces crash
        if not _test_crash(raw_poc):
            logger.debug(
                "Initial raw PoC does not crash target %s, skipping minimization",
                target.target_id,
            )
            return (raw_poc, 0.0)

        current = bytearray(raw_poc)
        chunk_size = len(current) // 2
        iteration = 0

        while chunk_size > 0 and iteration < max_iterations:
            iteration += 1
            reduced = False
            i = 0
            while i < len(current):
                candidate = current[:i] + current[i + chunk_size :]
                if len(candidate) > 0 and _test_crash(bytes(candidate)):
                    current = candidate
                    reduced = True
                    break
                i += chunk_size

            if not reduced:
                chunk_size //= 2

        minimized = bytes(current)
        orig_len = len(raw_poc)
        min_len = len(minimized)
        reduction_ratio = round((orig_len - min_len) / orig_len, 4) if orig_len > 0 else 0.0

        logger.info(
            "PoC minimization for %s: %dB -> %dB (%.1f%% reduction)",
            target.target_id,
            orig_len,
            min_len,
            reduction_ratio * 100.0,
        )
        return (minimized, reduction_ratio)
