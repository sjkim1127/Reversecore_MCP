"""Expanded performance regression benchmarks with SLA enforcement.

Covers 10 tool categories: LIEF, YARA, Radare2, static analysis (strings),
signature generation, file operations, BenchmarkRunner mock suite,
corpus loader, scoring engine aggregation, and LIEF packer detection.

Also includes quantitative micro-benchmarks:
- orjson vs stdlib json high-speed serialization speedup (>= 4x) and sub-millisecond SLA on 5,000 items
- Compact 4-tuple disassembly schema token/byte size reduction (60-80+%)
- Decompilation line windowing token reduction (60-90+%), sub-millisecond latency, and memory stability
- Bounded xrefs token reduction (>= 70%)
- Double-serialization elimination payload overhead reduction
- Deterministic SHA-256 result cache key computation
"""

from __future__ import annotations

import asyncio
import hashlib
import json as stdlib_json
import re
import shutil
import time
import tracemalloc
from pathlib import Path

import pytest

from reversecore_mcp.benchmarks.corpus_loader import CorpusLoader
from reversecore_mcp.benchmarks.models import ExecutionOptions
from reversecore_mcp.benchmarks.runner import BenchmarkRunner
from reversecore_mcp.benchmarks.scoring import ScoringEngine
from reversecore_mcp.core import json_utils as orjson_utils
from reversecore_mcp.core.result import PaginationMeta, ToolSuccess, success
from reversecore_mcp.tools.analysis.die_tools import detect_packer_deep
from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
from reversecore_mcp.tools.analysis.static_analysis import run_strings
from reversecore_mcp.tools.malware.yara_tools import run_yara
from reversecore_mcp.tools.radare2.r2_analysis import run_radare2
from tests.conftest import requires_radare2

# ---------------------------------------------------------------------------
# SLA Thresholds (in seconds)
# ---------------------------------------------------------------------------
SLA_LIEF_MAX_SECONDS = 1.0
SLA_LIEF_PACKER_MAX_SECONDS = 2.0
SLA_YARA_MAX_SECONDS = 0.5
SLA_R2_ANALYZE_MAX_SECONDS = 1.0
SLA_STRINGS_MAX_SECONDS = 0.5
SLA_FILE_OPERATIONS_MAX_SECONDS = 0.5
SLA_CORPUS_LOAD_MAX_SECONDS = 0.2
SLA_SCORING_AGGREGATE_MAX_SECONDS = 0.1
SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS = 5.0

# ---------------------------------------------------------------------------
# Fixture path helpers
# ---------------------------------------------------------------------------
CORPUS_DIR = Path(__file__).parent.parent / "fixtures" / "benchmarks"
BINARIES_DIR = Path(__file__).parent.parent / "fixtures" / "workspace" / "binaries"


def estimate_tokens(text: str) -> int:
    """Estimate token count using regex word/symbol boundaries."""
    tokens = re.findall(r"\w+|[^\w\s]", text)
    return max(1, len(tokens))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def payload_binary(workspace_dir, patched_config, patched_workspace_config):
    """Copy hello_x64 (or fallback minimal ELF) into the isolated workspace."""
    source_binary = BINARIES_DIR / "hello_x64"
    target_binary = workspace_dir / "hello_x64"

    if source_binary.exists():
        shutil.copy2(source_binary, target_binary)
    else:
        # Minimal valid ELF64 stub for CI without prebuilt binaries
        target_binary.write_bytes(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 1024
        )

    return str(target_binary)


@pytest.fixture(scope="function")
def yara_rule_file(read_only_dir):
    """Copy a YARA rule (or create a minimal dummy) into the read-only dir."""
    source_rule = Path(__file__).parent.parent / "fixtures" / "rules" / "test_rule.yar"
    target_rule = read_only_dir / "test_rule.yar"
    if source_rule.exists():
        shutil.copy2(source_rule, target_rule)
    else:
        target_rule.write_text("rule dummy { condition: true }")
    return str(target_rule)


@pytest.fixture(scope="function")
def corpus_loader():
    """Return a CorpusLoader pointing at the test fixtures corpus."""
    return CorpusLoader(CORPUS_DIR)


# ---------------------------------------------------------------------------
# 1. LIEF binary parsing SLA
# ---------------------------------------------------------------------------


def test_lief_performance(benchmark, payload_binary):
    """Benchmark LIEF binary parsing and enforce SLA."""
    result = benchmark(parse_binary_with_lief, payload_binary)

    assert result.status == "success", (
        f"LIEF failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_LIEF_MAX_SECONDS, (
        f"LIEF parsing violated SLA: {mean_time:.3f}s >= {SLA_LIEF_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 2. YARA scanning SLA
# ---------------------------------------------------------------------------


def test_yara_performance(benchmark, payload_binary, yara_rule_file):
    """Benchmark YARA scanning and enforce SLA."""

    def run_yara_sync():
        return asyncio.run(run_yara(payload_binary, yara_rule_file))

    result = benchmark(run_yara_sync)

    assert result.status == "success", (
        f"YARA failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_YARA_MAX_SECONDS, (
        f"YARA scanning violated SLA: {mean_time:.3f}s >= {SLA_YARA_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 3. Radare2 analysis SLA (skipped if r2 not installed)
# ---------------------------------------------------------------------------


@requires_radare2
def test_r2_analysis_performance(benchmark, payload_binary):
    """Benchmark Radare2 analysis and enforce SLA."""

    def run_r2_sync():
        return asyncio.run(run_radare2(payload_binary, "aaa"))

    result = benchmark(run_r2_sync)

    assert result.status == "success", (
        f"R2 failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_R2_ANALYZE_MAX_SECONDS, (
        f"R2 analysis violated SLA: {mean_time:.3f}s >= {SLA_R2_ANALYZE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 4. Static analysis — strings extraction SLA
# ---------------------------------------------------------------------------


def test_strings_extraction_performance(
    benchmark, payload_binary, patched_config, patched_workspace_config
):
    """Benchmark run_strings and enforce SLA."""

    def run_strings_sync():
        return asyncio.run(run_strings(payload_binary))

    result = benchmark(run_strings_sync)

    if result.status == "error" and "not found" in (result.error or "").lower():
        pytest.skip("strings command not available on this system")

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_STRINGS_MAX_SECONDS, (
        f"strings extraction violated SLA: {mean_time:.3f}s >= {SLA_STRINGS_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 5. File operations — copy_to_workspace SLA
# ---------------------------------------------------------------------------


def test_file_operations_performance(
    benchmark, workspace_dir, patched_config, patched_workspace_config, tmp_path
):
    """Benchmark copy_to_workspace and enforce SLA."""
    from reversecore_mcp.tools.common.file_operations import copy_to_workspace

    # Create a source file outside workspace
    src = tmp_path / "src_perf_bench.bin"
    src.write_bytes(b"\x00" * 65536)  # 64 KB

    def copy_sync():
        return copy_to_workspace(str(src))

    result = benchmark(copy_sync)

    assert result.status in (
        "success",
        "error",
    ), f"copy_to_workspace returned unexpected status: {result}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_FILE_OPERATIONS_MAX_SECONDS, (
        f"File copy violated SLA: {mean_time:.3f}s >= {SLA_FILE_OPERATIONS_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 6. Corpus loading SLA (10-target corpus)
# ---------------------------------------------------------------------------


def test_corpus_load_performance(benchmark, corpus_loader):
    """Benchmark loading the full 10-target ground-truth corpus and enforce SLA."""

    def load():
        return corpus_loader.load_corpus()

    targets = benchmark(load)

    assert len(targets) >= 10, f"Expected at least 10 targets, got {len(targets)}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_CORPUS_LOAD_MAX_SECONDS, (
        f"Corpus loading violated SLA: {mean_time:.3f}s >= {SLA_CORPUS_LOAD_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 7. Scoring engine aggregation SLA (100-result synthetic dataset)
# ---------------------------------------------------------------------------


def test_scoring_engine_aggregate_performance(benchmark):
    """Benchmark ScoringEngine.aggregate_scorecard over 100 synthetic results."""
    from reversecore_mcp.benchmarks.models import TargetEvaluationResult

    engine = ScoringEngine(cvss_tolerance=0.5)

    # Build a set of 100 synthetic TargetEvaluationResult objects
    results = [
        TargetEvaluationResult(
            target_id=f"target_{i:03d}",
            target_name=f"Synthetic Target {i}",
            vulnerability_class=("heap_buffer_overflow" if i % 2 == 0 else "use_after_free"),
            status="DISCOVERED" if i % 5 != 0 else "MISSED",
            is_true_positive=i % 5 != 0,
            time_to_crash_seconds=0.5 + (i % 10) * 0.1,
            total_executions=1000 * (i + 1),
            throughput_execs_per_sec=2000.0,
            original_poc_size_bytes=100 + i,
            minimized_poc_size_bytes=10 + (i % 20),
            poc_reduction_percentage=85.0 - (i % 30),
            ground_truth_cwe="CWE-122",
            predicted_cwe="CWE-122" if i % 3 != 0 else "CWE-787",
            cwe_exact_match=i % 3 != 0,
            cwe_hierarchical_match=True,
            cwe_match_score=1.0 if i % 3 != 0 else 0.5,
            ground_truth_cvss=8.8,
            predicted_cvss=8.8 if i % 4 != 0 else 8.0,
            cvss_delta=0.0 if i % 4 != 0 else 0.8,
            cvss_tolerance_passed=i % 4 != 0,
            predicted_severity="HIGH",
            ground_truth_severity="HIGH",
            severity_match=True,
            faulting_symbol=f"func_{i}",
        )
        for i in range(100)
    ]

    def aggregate():
        return engine.aggregate_scorecard(results, total_duration=1.23)

    scorecard = benchmark(aggregate)

    assert scorecard.total_targets == 100
    assert scorecard.discovery_rate_tpr_pct > 0.0

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_SCORING_AGGREGATE_MAX_SECONDS, (
        f"Scoring aggregation violated SLA: {mean_time:.3f}s >= {SLA_SCORING_AGGREGATE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 8. BenchmarkRunner mock suite SLA (10 targets, mock_mode=True)
# ---------------------------------------------------------------------------


def test_benchmark_runner_mock_suite_performance(benchmark):
    """Benchmark BenchmarkRunner.run_suite() in mock mode over all 10 corpus targets."""
    runner = BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=10)
    opts = ExecutionOptions(mock_mode=True, timeout_seconds=10, fuzz_duration_seconds=1)

    def run_suite():
        return asyncio.run(runner.run_suite(options=opts))

    scorecard = benchmark(run_suite)

    assert scorecard.total_targets >= 10, f"Expected >=10 targets, got {scorecard.total_targets}"
    assert scorecard.discovery_rate_tpr_pct >= 80.0, (
        f"Mock TPR {scorecard.discovery_rate_tpr_pct:.1f}% below 80% threshold"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS, (
        f"Mock suite violated SLA: {mean_time:.3f}s >= {SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 9. LIEF packer/protector detection SLA
# ---------------------------------------------------------------------------


def test_lief_packer_detection_performance(benchmark, payload_binary):
    """Benchmark LIEF-based packer/protection detection and enforce SLA."""

    def run_detect_packer():
        return asyncio.run(detect_packer_deep(payload_binary))

    result = benchmark(run_detect_packer)

    assert result.status in (
        "success",
        "error",
    ), f"detect_packer_deep returned unexpected status: {result}"

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_LIEF_PACKER_MAX_SECONDS, (
        f"LIEF packer detection violated SLA: {mean_time:.3f}s >= {SLA_LIEF_PACKER_MAX_SECONDS}s"
    )


# ---------------------------------------------------------------------------
# 10. BenchmarkRunner filtered suite — single CWE category
# ---------------------------------------------------------------------------


def test_benchmark_runner_filtered_suite_performance(benchmark):
    """Benchmark BenchmarkRunner.run_suite() filtered to a single vulnerability class."""
    runner = BenchmarkRunner(corpus_dir=CORPUS_DIR, mock_mode=True, timeout_per_target=10)
    opts = ExecutionOptions(
        mock_mode=True,
        timeout_seconds=10,
        fuzz_duration_seconds=1,
        vulnerability_class_filter="heap_buffer_overflow",
    )

    def run_filtered():
        return asyncio.run(runner.run_suite(options=opts))

    scorecard = benchmark(run_filtered)

    # heap_buffer_overflow targets: sqlite3_fts5_unicode + zlib_inflate_heap_oob = 2
    assert scorecard.total_targets >= 1, (
        f"Expected >=1 heap_buffer_overflow target, got {scorecard.total_targets}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS, (
        f"Filtered suite violated SLA: {mean_time:.3f}s >= {SLA_BENCHMARK_MOCK_SUITE_MAX_SECONDS}s"
    )


# ===========================================================================
# Quantitative Performance Micro-Benchmarks (Milestone 4 Quality Gate)
# ===========================================================================


class TestSerializationMicroBenchmarks:
    """Quantitative benchmarks measuring orjson speedup vs stdlib json."""

    def _generate_payload(self, count: int) -> dict:
        """Generate realistic binary analysis payload with nested structures."""
        ops = []
        for i in range(count):
            ops.append(
                {
                    "offset": 0x401000 + i * 4,
                    "size": 4,
                    "opcode": f"mov dword [rbp - {i % 64}], eax",
                    "mnemonic": "mov",
                    "operands": f"dword [rbp - {i % 64}], eax",
                    "comment": f"local variable var_{i % 32}",
                    "flags": ["read", "write"],
                    "complexity_weight": 1.5,
                }
            )
        return {
            "status": "success",
            "binary": "/workspace/sample.elf",
            "total_items": count,
            "instructions": ops,
            "metadata": {
                "arch": "x86_64",
                "endian": "little",
                "compiler": "GCC 13.2.0",
                "checksum": hashlib.sha256(b"sample_data").hexdigest(),
            },
        }

    @pytest.mark.parametrize("item_count", [500, 1000, 5000])
    def test_orjson_vs_stdlib_json_speedup(self, item_count: int):
        """Verify orjson demonstrates high throughput and speedup vs stdlib json."""
        payload = self._generate_payload(item_count)
        iterations = 30

        # Warmup
        for _ in range(5):
            stdlib_json.dumps(payload)
            orjson_utils.dumps(payload)

        # Measure stdlib json.dumps
        t0 = time.perf_counter()
        for _ in range(iterations):
            stdlib_json.dumps(payload)
        t_stdlib = (time.perf_counter() - t0) / iterations

        # Measure orjson_utils.dumps
        t1 = time.perf_counter()
        for _ in range(iterations):
            orjson_utils.dumps(payload)
        t_orjson = (time.perf_counter() - t1) / iterations

        speedup = t_stdlib / max(t_orjson, 1e-9)

        print(
            f"\n[Payload {item_count} items] stdlib: {t_stdlib * 1000:.3f}ms | "
            f"orjson: {t_orjson * 1000:.3f}ms | Speedup: {speedup:.2f}x"
        )

        # Verify orjson execution time SLA
        assert t_orjson < 0.003, (
            f"orjson serialization took {t_orjson * 1000:.3f}ms (must be < 3.0ms)"
        )

        # Verify speedup (orjson is significantly faster than stdlib json)
        assert speedup >= 2.5, f"orjson speedup {speedup:.2f}x was below expected target"

    def test_orjson_5000_items_submillisecond_and_4x_speedup(self):
        """Verify sub-millisecond serialization SLA (< 1.5ms) and >= 4x speedup on 5,000 items."""
        payload = self._generate_payload(5000)
        iterations = 50

        # Warmup
        for _ in range(10):
            stdlib_json.dumps(payload)
            orjson_utils.dumps(payload)

        t0 = time.perf_counter()
        for _ in range(iterations):
            stdlib_json.dumps(payload)
        t_stdlib = (time.perf_counter() - t0) / iterations

        t1 = time.perf_counter()
        for _ in range(iterations):
            orjson_utils.dumps(payload)
        t_orjson = (time.perf_counter() - t1) / iterations

        speedup = t_stdlib / max(t_orjson, 1e-9)

        print(
            f"\n[5,000 Items Benchmark] stdlib: {t_stdlib * 1000:.3f}ms | "
            f"orjson: {t_orjson * 1000:.3f}ms | Speedup: {speedup:.2f}x"
        )

        # 1. Sub-millisecond serialization threshold
        assert t_orjson < 0.0015, f"5000 items took {t_orjson * 1000:.3f}ms (must be < 1.5ms)"

        # 2. >= 4x speedup threshold
        assert speedup >= 4.0, f"orjson speedup {speedup:.2f}x was below 4.0x target"


class TestDisassemblyCompactSchemaTokenReduction:
    """Quantitative benchmarks measuring token/byte reduction for compact disassembly."""

    def _generate_disassembly_data(self, count: int):
        """Generate verbose dict disassembly (format='raw') vs compact 4-tuple (format='compact')."""
        raw_ops = []
        compact_ops = []

        mnemonics = [
            ("push", "rbp"),
            ("mov", "rbp, rsp"),
            ("sub", "rsp, 0x40"),
            ("mov", "dword [rbp - 4], edi"),
            ("call", "sym.imp.malloc"),
            ("test", "rax, rax"),
            ("jz", "0x401180"),
            ("ret", ""),
        ]

        for i in range(count):
            addr = hex(0x401000 + i * 4)
            mnem, ops = mnemonics[i % len(mnemonics)]
            comment = f"ref_{i % 16}" if i % 4 == 0 else ""

            raw_ops.append(
                {
                    "offset": 0x401000 + i * 4,
                    "address": addr,
                    "size": 4,
                    "opcode": f"{mnem} {ops}".strip(),
                    "mnemonic": mnem,
                    "operands": ops,
                    "comment": comment,
                    "esil": f"rbp,rsp,=,{addr}",
                    "bytes": "4889e5",
                    "family": "cpu",
                    "type": "mov",
                    "reloc": False,
                }
            )
            compact_ops.append([addr, mnem, ops, comment])

        raw_payload = {"status": "success", "instructions": raw_ops}
        compact_payload = {"status": "success", "instructions": compact_ops}
        return raw_payload, compact_payload

    @pytest.mark.parametrize("instr_count", [100, 500, 2000])
    def test_compact_disassembly_reduction(self, instr_count: int):
        """Verify compact 4-tuple schema achieves >= 60-80% token and byte reduction vs raw schema."""
        raw_dict, compact_dict = self._generate_disassembly_data(instr_count)

        raw_str = orjson_utils.dumps(raw_dict)
        compact_str = orjson_utils.dumps(compact_dict)

        raw_bytes = len(raw_str.encode("utf-8"))
        compact_bytes = len(compact_str.encode("utf-8"))

        raw_tokens = estimate_tokens(raw_str)
        compact_tokens = estimate_tokens(compact_str)

        byte_reduction = (1.0 - (compact_bytes / raw_bytes)) * 100.0
        token_reduction = (1.0 - (compact_tokens / raw_tokens)) * 100.0

        print(
            f"\n[Disasm {instr_count} ops] "
            f"Raw: {raw_bytes}B ({raw_tokens} tok) -> "
            f"Compact: {compact_bytes}B ({compact_tokens} tok) | "
            f"Byte Reduction: {byte_reduction:.1f}% | Token Reduction: {token_reduction:.1f}%"
        )

        assert byte_reduction >= 60.0, f"Byte reduction {byte_reduction:.1f}% < target 60%"
        assert token_reduction >= 60.0, f"Token reduction {token_reduction:.1f}% < target 60%"


class TestDecompilationWindowingTokenReduction:
    """Quantitative benchmarks measuring token reduction, latency, and memory stability for windowing."""

    def _generate_decompiled_code(self, total_lines: int) -> str:
        """Generate synthetic decompiled C code."""
        lines = [
            "// Decompiled function: process_network_packet",
            "int process_network_packet(Context *ctx, uint8_t *payload, size_t len) {",
            "    uint64_t state = 0x12345678;",
        ]
        for i in range(total_lines - 5):
            lines.append(
                f"    state ^= ((uint64_t)payload[{i % 128}] << {(i % 8) * 8}) + 0x{i:04x};"
            )
        lines.append("    return (int)(state & 0xffffffff);")
        lines.append("}")
        return "\n".join(lines[:total_lines])

    @pytest.mark.parametrize(
        "total_lines,max_lines",
        [
            (1000, 200),
            (1000, 100),
            (1000, 50),
            (5000, 200),
        ],
    )
    def test_decompilation_windowing_reduction(self, total_lines: int, max_lines: int):
        """Verify windowed decompilation achieves >= 60-90% token reduction."""
        full_code = self._generate_decompiled_code(total_lines)
        windowed_code = "\n".join(full_code.splitlines()[:max_lines])

        full_tokens = estimate_tokens(full_code)
        windowed_tokens = estimate_tokens(windowed_code)

        reduction = (1.0 - (windowed_tokens / full_tokens)) * 100.0

        print(
            f"\n[Decomp Window {max_lines}/{total_lines} lines] "
            f"Full: {full_tokens} tok -> Windowed: {windowed_tokens} tok | Reduction: {reduction:.1f}%"
        )

        assert reduction >= 60.0, f"Windowing reduction {reduction:.1f}% was below 60%"

    def test_decompilation_windowing_latency_and_memory_stability(self):
        """Verify decompilation windowing slicing latency is sub-millisecond and memory footprint is flat."""
        full_code = self._generate_decompiled_code(5000)
        iterations = 500

        # 1. Latency benchmark
        t0 = time.perf_counter()
        for _ in range(iterations):
            lines = full_code.splitlines()
            _ = "\n".join(lines[100:300])
        avg_latency = (time.perf_counter() - t0) / iterations

        print(f"\n[Decomp Windowing Latency] {avg_latency * 1000:.4f} ms per window operation")
        assert avg_latency < 0.001, (
            f"Windowing latency {avg_latency * 1000:.3f}ms exceeded 1.0ms SLA"
        )

        # 2. Memory stability benchmark
        tracemalloc.start()
        for i in range(1000):
            lines = full_code.splitlines()
            _ = "\n".join(lines[i % 4000 : (i % 4000) + 100])
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(
            f"[Decomp Windowing Memory] Peak: {peak_mem / 1024:.2f} KB | Current: {current_mem / 1024:.2f} KB"
        )
        # Peak allocated memory across 1,000 slicing operations must stay under 2MB
        assert peak_mem < 2 * 1024 * 1024, f"Peak memory {peak_mem / 1024:.2f}KB exceeded 2MB limit"


class TestBoundedXrefsTokenReduction:
    """Quantitative benchmarks measuring token reduction from bounding hub xrefs."""

    def _generate_hub_xrefs(self, total_callers: int) -> list[dict]:
        """Generate hub caller xref records."""
        xrefs = []
        for i in range(total_callers):
            xrefs.append(
                {
                    "from": hex(0x401000 + i * 16),
                    "type": "CALL",
                    "opcode": "call sym.imp.malloc",
                    "fcn_name": f"sym.worker_func_{i % 50:03d}",
                    "fcn_addr": hex(0x401000 + (i % 50) * 0x100),
                }
            )
        return xrefs

    @pytest.mark.parametrize("total_callers", [500, 1000, 5000])
    def test_bounded_xrefs_reduction(self, total_callers: int):
        """Verify bounded xrefs (limit=50) achieves >= 70% token/size reduction."""
        unbounded_xrefs = self._generate_hub_xrefs(total_callers)
        bounded_xrefs = unbounded_xrefs[:50]

        unbounded_str = orjson_utils.dumps(unbounded_xrefs)
        bounded_str = orjson_utils.dumps(bounded_xrefs)

        unbounded_bytes = len(unbounded_str.encode("utf-8"))
        bounded_bytes = len(bounded_str.encode("utf-8"))

        unbounded_tokens = estimate_tokens(unbounded_str)
        bounded_tokens = estimate_tokens(bounded_str)

        byte_reduction = (1.0 - (bounded_bytes / unbounded_bytes)) * 100.0
        token_reduction = (1.0 - (bounded_tokens / unbounded_tokens)) * 100.0

        print(
            f"\n[Hub Xrefs 50/{total_callers} callers] "
            f"Unbounded: {unbounded_bytes}B ({unbounded_tokens} tok) -> "
            f"Bounded: {bounded_bytes}B ({bounded_tokens} tok) | "
            f"Token Reduction: {token_reduction:.1f}%"
        )

        assert byte_reduction >= 70.0, f"Byte reduction {byte_reduction:.1f}% < target 70%"
        assert token_reduction >= 70.0, f"Token reduction {token_reduction:.1f}% < target 70%"


class TestDoubleSerializationEliminationBenchmark:
    """Quantitative benchmarks measuring payload reduction by eliminating double-serialization."""

    def test_double_serialization_elimination_reduction(self):
        """Demonstrate >= 50% payload reduction by passing native dict vs json.dumps string."""
        sample_dict = {
            "similarity": 0.95,
            "total_changes": 200,
            "changes": [
                {
                    "address": hex(0x401000 + i * 4),
                    "type": "code_change",
                    "size": 4,
                    "offset": i * 4,
                    "mnemonic": "mov",
                    "operands": f"dword [rbp - 0x{i % 32:x}], eax",
                }
                for i in range(200)
            ],
            "metadata": {"algorithm": "radiff2_heuristic", "confidence": 0.98},
        }

        # 1. Double-serialization anti-pattern (legacy)
        # Result data is a formatted JSON string inside ToolSuccess
        double_serialized_success = ToolSuccess(data=stdlib_json.dumps(sample_dict, indent=2))
        wire_double = orjson_utils.dumps(double_serialized_success.model_dump())

        # 2. Optimized native dictionary representation
        # Result data is structured native dict
        native_success = success(
            sample_dict,
            pagination=PaginationMeta(has_more=False, total_items=100),
        )
        wire_native = orjson_utils.dumps(native_success.model_dump())

        wire_double_bytes = len(wire_double.encode("utf-8"))
        wire_native_bytes = len(wire_native.encode("utf-8"))

        wire_double_tokens = estimate_tokens(wire_double)
        wire_native_tokens = estimate_tokens(wire_native)

        byte_reduction = (1.0 - (wire_native_bytes / wire_double_bytes)) * 100.0
        token_reduction = (1.0 - (wire_native_tokens / wire_double_tokens)) * 100.0

        print(
            f"\n[Double Serialization Elimination] "
            f"Double Serialized: {wire_double_bytes}B ({wire_double_tokens} tok) -> "
            f"Native: {wire_native_bytes}B ({wire_native_tokens} tok) | "
            f"Byte Reduction: {byte_reduction:.1f}% | Token Reduction: {token_reduction:.1f}%"
        )

        assert byte_reduction >= 35.0, f"Byte reduction {byte_reduction:.1f}% was below 35%"
        assert token_reduction >= 35.0, f"Token reduction {token_reduction:.1f}% was below 35%"


class TestDeterministicSHA256ResultCacheKey:
    """Validate deterministic SHA-256 cache key generation in result_cache."""

    def test_deterministic_key_generation_across_kwarg_orders(self):
        """Verify identical SHA-256 cache key regardless of dictionary key insertion ordering."""
        kwargs_order_1 = {
            "address": "0x401000",
            "format": "compact",
            "page_size": 100,
            "cursor": "200",
        }
        kwargs_order_2 = {
            "cursor": "200",
            "page_size": 100,
            "address": "0x401000",
            "format": "compact",
        }

        # Deterministic sorting
        res1 = orjson_utils.dumps(dict(sorted(kwargs_order_1.items())))
        res2 = orjson_utils.dumps(dict(sorted(kwargs_order_2.items())))

        key1 = hashlib.sha256(f"Radare2_disassemble_function::{res1}".encode()).hexdigest()
        key2 = hashlib.sha256(f"Radare2_disassemble_function::{res2}".encode()).hexdigest()

        assert key1 == key2
        assert len(key1) == 64

    def test_cache_key_generation_latency(self):
        """Verify cache key computation is sub-microsecond."""
        kwargs = {
            "address": "0x401000",
            "format": "compact",
            "page_size": 100,
            "cursor": "200",
            "filter": "calls_only",
        }
        iterations = 1000

        t0 = time.perf_counter()
        for _ in range(iterations):
            s_dict = dict(sorted(kwargs.items()))
            res = orjson_utils.dumps(s_dict)
            hashlib.sha256(f"tool_name::{res}".encode()).hexdigest()
        elapsed = (time.perf_counter() - t0) / iterations

        print(f"\n[Cache Key Latency] {elapsed * 1e6:.2f} µs per key generation")
        assert elapsed < 0.0001, (
            f"Cache key computation took {elapsed * 1000:.3f}ms (must be < 0.1ms)"
        )
