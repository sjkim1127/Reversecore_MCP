import asyncio
from pathlib import Path

import pytest

from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
from reversecore_mcp.tools.malware.yara_tools import run_yara
from reversecore_mcp.tools.radare2.r2_analysis import run_radare2
from tests.conftest import requires_radare2

# -----------------------------------------------------------------------------
# SLA Thresholds (in seconds)
# -----------------------------------------------------------------------------
SLA_LIEF_MAX_SECONDS = 1.0
SLA_YARA_MAX_SECONDS = 0.5
SLA_R2_ANALYZE_MAX_SECONDS = 1.0

# -----------------------------------------------------------------------------
# Test Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture(scope="function")
def payload_binary(workspace_dir, patched_config, patched_workspace_config):
    """
    Copies the actual CI compiled hello_x64 to the test workspace for realistic SLA testing.
    """
    import shutil

    # Path to the persistent fixture binary
    source_binary = (
        Path(__file__).parent.parent / "fixtures" / "workspace" / "binaries" / "hello_x64"
    )

    # Destination inside the isolated workspace
    target_binary = workspace_dir / "hello_x64"

    if source_binary.exists():
        shutil.copy2(source_binary, target_binary)
    else:
        # Fallback minimal ELF if running in a weird environment
        target_binary.write_bytes(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 1024
        )

    return str(target_binary)


# -----------------------------------------------------------------------------
# Benchmark Tests
# -----------------------------------------------------------------------------


def test_lief_performance(benchmark, payload_binary):
    """Benchmark LIEF binary parsing and enforce SLA."""

    # We benchmark the synchronous function directly
    result = benchmark(parse_binary_with_lief, payload_binary)

    # Assert successful execution
    assert result.status == "success", (
        f"LIEF failed: {result.error if hasattr(result, 'error') else result}"
    )

    # Enforce SLA limit
    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_LIEF_MAX_SECONDS, (
        f"LIEF parsing violated SLA: {mean_time:.3f}s >= {SLA_LIEF_MAX_SECONDS}s"
    )


def test_yara_performance(benchmark, payload_binary, read_only_dir):
    """Benchmark YARA scanning and enforce SLA."""
    import shutil

    # Copy a dummy yara rule to read_only_dir
    source_rule = Path(__file__).parent.parent / "fixtures" / "rules" / "test_rule.yar"
    target_rule = read_only_dir / "test_rule.yar"
    if source_rule.exists():
        shutil.copy2(source_rule, target_rule)
    else:
        target_rule.write_text("rule dummy { condition: true }")

    # Since run_yara is async, we wrap it in asyncio.run
    def run_yara_sync():
        return asyncio.run(run_yara(payload_binary, str(target_rule)))

    result = benchmark(run_yara_sync)

    assert result.status == "success", (
        f"YARA failed: {result.error if hasattr(result, 'error') else result}"
    )

    mean_time = benchmark.stats.stats.mean
    assert mean_time < SLA_YARA_MAX_SECONDS, (
        f"YARA scanning violated SLA: {mean_time:.3f}s >= {SLA_YARA_MAX_SECONDS}s"
    )


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
