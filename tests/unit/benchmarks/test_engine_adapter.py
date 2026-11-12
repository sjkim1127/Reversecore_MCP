"""Unit tests for Multi-Engine Benchmark Adapters (Radare2 vs Fission vs Mock)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.benchmarks.engine_adapter import (
    EngineBenchmarkRunner,
    FissionEngineAdapter,
    MockEngineAdapter,
    Radare2EngineAdapter,
)
from reversecore_mcp.benchmarks.models import EngineAnalysisResult


@pytest.mark.unit
@pytest.mark.asyncio
async def test_mock_engine_adapter(tmp_path: Path) -> None:
    """Test MockEngineAdapter analyze and decompile methods."""
    dummy_bin = tmp_path / "sample.bin"
    dummy_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)

    adapter = MockEngineAdapter(simulated_latency=0.001)
    assert adapter.name == "mock"
    assert await adapter.is_available() is True

    result = await adapter.analyze(dummy_bin, expected_symbols=["main", "init"])
    assert isinstance(result, EngineAnalysisResult)
    assert result.engine_name == "mock"
    assert result.target_id == "sample.bin"
    assert result.entry_point_found is True
    assert result.symbols_recovery_rate_pct == 100.0
    assert "main" in result.key_symbols_recovered

    decomp = await adapter.decompile_function(dummy_bin, "main")
    assert decomp is not None
    assert "int main()" in decomp


@pytest.mark.unit
@pytest.mark.asyncio
async def test_fission_engine_adapter_preview(tmp_path: Path) -> None:
    """Test FissionEngineAdapter transition preview mode when Fission binary is absent."""
    dummy_bin = tmp_path / "sample.bin"
    dummy_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)

    adapter = FissionEngineAdapter(fission_bin_path=None)
    assert adapter.name == "fission"

    result = await adapter.analyze(dummy_bin, expected_symbols=["main", "target_func"])
    assert result.engine_name == "fission"
    assert result.entry_point_found is True
    assert result.functions_count > 0
    assert result.symbols_recovery_rate_pct == 100.0

    decomp = await adapter.decompile_function(dummy_bin, "main")
    assert decomp is not None
    assert "Fission Decompiler Preview" in decomp
    assert "void main()" in decomp


@pytest.mark.unit
@pytest.mark.asyncio
async def test_radare2_engine_adapter_unavailable(tmp_path: Path) -> None:
    """Test Radare2EngineAdapter graceful failure when r2 is unavailable."""
    dummy_bin = tmp_path / "sample.bin"
    dummy_bin.write_bytes(b"dummy")

    adapter = Radare2EngineAdapter()
    with patch.object(adapter, "is_available", new_callable=AsyncMock) as mock_avail:
        mock_avail.return_value = False
        res = await adapter.analyze(dummy_bin)
        assert res.engine_name == "radare2"
        assert res.functions_count == 0
        assert "not found" in (res.error_message or "")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_engine_benchmark_runner(tmp_path: Path) -> None:
    """Test EngineBenchmarkRunner comparative execution across multiple engines."""
    dummy_bin1 = tmp_path / "target1.bin"
    dummy_bin1.write_bytes(b"\x7fELF" + b"\x00" * 60)
    dummy_bin2 = tmp_path / "target2.bin"
    dummy_bin2.write_bytes(b"MZ" + b"\x00" * 60)

    engine1 = MockEngineAdapter(simulated_latency=0.001)
    engine2 = MockEngineAdapter(simulated_latency=0.002)

    runner = EngineBenchmarkRunner([engine1, engine2])
    summary = await runner.run_comparison(
        [
            (dummy_bin1, ["main"]),
            (dummy_bin2, ["_start"]),
        ]
    )

    assert summary.total_targets == 2
    assert len(summary.engines_evaluated) == 2
    assert "target1.bin" in summary.results_by_target
    assert "target2.bin" in summary.results_by_target
    assert summary.total_duration_seconds >= 0.0

    # Serialization test
    as_dict = summary.to_dict()
    assert as_dict["total_targets"] == 2
    json_str = summary.to_json()
    assert "target1.bin" in json_str
