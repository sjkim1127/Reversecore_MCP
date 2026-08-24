"""
Adversarial Stress Test Suite for Milestone 1 (YARA Engine & Heuristics).

Covers:
1. Large binary scanning latency & throughput (1MB, 5MB, 10MB, 15MB, sparse, high-entropy, deep matches).
2. Invalid and edge-case inputs (non-existent file, empty file, unicode text, malformed rules, missing includes).
3. Concurrency safety & `_YARA_RULES_CACHE` hit rates, eviction, and mtime invalidation.
4. Category isolation and multi-condition match precision.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
import tracemalloc
from pathlib import Path

import pytest

from reversecore_mcp.core.config import reload_settings
from reversecore_mcp.core.security import refresh_workspace_config
from reversecore_mcp.tools.malware.yara_tools import (
    _YARA_RULES_CACHE,
    _update_cache,
    run_yara,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_RULES_DIR = REPO_ROOT / "rules"

# Known crypto constants from rules
AES_FORWARD_SBOX = bytes(
    [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
    ]
)

CHACHA_CONSTANTS = b"expand 32-byte k"

SYSCALL_STUB = bytes([0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Ensure workspace and read dirs are properly configured for each test."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    custom_rules_dir = tmp_path / "custom_rules"
    custom_rules_dir.mkdir(exist_ok=True)

    read_dirs = f"{REPO_RULES_DIR},{custom_rules_dir}"
    monkeypatch.setenv("REVERSECORE_WORKSPACE", str(workspace))
    monkeypatch.setenv("REVERSECORE_READ_DIRS", read_dirs)
    reload_settings()
    refresh_workspace_config()

    yield {
        "workspace": workspace,
        "custom_rules_dir": custom_rules_dir,
    }

    _YARA_RULES_CACHE.clear()


# ============================================================================
# 1. Large File Scanning Latency & Throughput Benchmark
# ============================================================================


class TestYaraLargeFileLatency:
    """Empirical latency and throughput benchmarks on large files (up to 10MB+)."""

    @pytest.mark.asyncio
    async def test_1mb_binary_latency(self, setup_test_env):
        """Scan 1MB synthetic binary with embedded crypto constants."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_1mb.bin"

        # Generate 1MB binary with AES S-box in the middle
        data = bytearray(secrets.token_bytes(1024 * 1024))
        data[500_000 : 500_000 + len(AES_FORWARD_SBOX)] = AES_FORWARD_SBOX
        target.write_bytes(data)

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        assert result.data["match_count"] >= 1
        assert "Crypto_AES_SBox_Forward" in [m["rule"] for m in result.data["matches"]]
        assert elapsed < 0.5, f"1MB scan took {elapsed:.4f}s (SLA is < 0.5s)"

    @pytest.mark.asyncio
    async def test_5mb_binary_latency(self, setup_test_env):
        """Scan 5MB synthetic binary with embedded ChaCha constants."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_5mb.bin"

        data = bytearray(secrets.token_bytes(5 * 1024 * 1024))
        data[2_500_000 : 2_500_000 + len(CHACHA_CONSTANTS)] = CHACHA_CONSTANTS
        target.write_bytes(data)

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        assert result.data["match_count"] >= 1
        assert "Crypto_ChaCha20_Salsa20_Constants" in [m["rule"] for m in result.data["matches"]]
        assert elapsed < 0.8, f"5MB scan took {elapsed:.4f}s (SLA is < 0.8s)"

    @pytest.mark.asyncio
    async def test_10mb_binary_random_entropy(self, setup_test_env):
        """Scan 10MB high-entropy random data (worst-case search space)."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb_random.bin"

        data = secrets.token_bytes(10 * 1024 * 1024)
        target.write_bytes(data)

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        assert elapsed < 1.0, f"10MB random scan took {elapsed:.4f}s (SLA is < 1.0s)"

    @pytest.mark.asyncio
    async def test_10mb_binary_sparse_zeroes(self, setup_test_env):
        """Scan 10MB sparse zero-filled binary."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb_zeroes.bin"

        target.write_bytes(b"\x00" * (10 * 1024 * 1024))

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        assert result.data["match_count"] == 0
        assert elapsed < 1.0, f"10MB sparse scan took {elapsed:.4f}s (SLA is < 1.0s)"

    @pytest.mark.asyncio
    async def test_10mb_binary_deep_matches_precision_and_latency(self, setup_test_env):
        """Scan 10MB binary with patterns placed at offset 0, 5MB, and 9.99MB."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb_deep.bin"

        data = bytearray(10 * 1024 * 1024)
        # 1. AES S-box at offset 64
        data[64 : 64 + len(AES_FORWARD_SBOX)] = AES_FORWARD_SBOX
        # 2. ChaCha constant at offset 5,000,000
        data[5_000_000 : 5_000_000 + len(CHACHA_CONSTANTS)] = CHACHA_CONSTANTS
        # 3. Direct syscall stub at offset 10,400,000 (9.9MB)
        offset_syscall = 10_400_000
        data[offset_syscall : offset_syscall + len(SYSCALL_STUB)] = SYSCALL_STUB
        target.write_bytes(data)

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        matches = result.data["matches"]
        matched_rules = {m["rule"]: m for m in matches}

        assert "Crypto_AES_SBox_Forward" in matched_rules
        assert "Crypto_ChaCha20_Salsa20_Constants" in matched_rules
        assert "Injection_Direct_Syscall_Stub" in matched_rules

        # Verify offset precision
        syscall_match = matched_rules["Injection_Direct_Syscall_Stub"]
        string_offsets = [s["offset"] for s in syscall_match["strings"]]
        assert offset_syscall in string_offsets, (
            f"Expected offset {offset_syscall} in {string_offsets}"
        )

        # Verify category counts
        categories = result.data["categories"]
        assert categories["crypto"] >= 2
        assert categories["injection"] >= 1

        assert elapsed < 1.0, f"10MB deep match scan took {elapsed:.4f}s (SLA is < 1.0s)"

    @pytest.mark.asyncio
    async def test_10mb_text_file_scan(self, setup_test_env):
        """Scan 10MB non-binary text file (source code / log style)."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb.txt"

        line = "function test_handler(event) { console.log('Handling event', event.id); return true; }\n"
        repetitions = (10 * 1024 * 1024) // len(line) + 1
        target.write_text(line * repetitions, encoding="utf-8")

        start = time.perf_counter()
        result = await run_yara(str(target), _bypass_queue=True)
        elapsed = time.perf_counter() - start

        assert result.status == "success", f"Failed with: {getattr(result, 'message', '')}"
        assert result.data["match_count"] == 0
        assert elapsed < 1.0, f"10MB text file scan took {elapsed:.4f}s (SLA is < 1.0s)"

    @pytest.mark.asyncio
    async def test_category_filtered_scan_latency(self, setup_test_env):
        """Category-scoped scan on 10MB binary."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb_cat.bin"

        data = bytearray(10 * 1024 * 1024)
        data[100 : 100 + len(AES_FORWARD_SBOX)] = AES_FORWARD_SBOX
        data[500 : 500 + len(SYSCALL_STUB)] = SYSCALL_STUB
        target.write_bytes(data)

        # Scan ONLY crypto category
        res_crypto = await run_yara(str(target), category="crypto", _bypass_queue=True)
        assert res_crypto.status == "success", f"Failed: {getattr(res_crypto, 'message', '')}"
        crypto_rules = [m["rule"] for m in res_crypto.data["matches"]]
        assert "Crypto_AES_SBox_Forward" in crypto_rules
        assert "Injection_Direct_Syscall_Stub" not in crypto_rules

        # Scan ONLY injection category
        res_inj = await run_yara(str(target), category="injection", _bypass_queue=True)
        assert res_inj.status == "success", f"Failed: {getattr(res_inj, 'message', '')}"
        inj_rules = [m["rule"] for m in res_inj.data["matches"]]
        assert "Injection_Direct_Syscall_Stub" in inj_rules
        assert "Crypto_AES_SBox_Forward" not in inj_rules

    @pytest.mark.asyncio
    async def test_memory_stability_under_repeated_scans(self, setup_test_env):
        """Ensure repeated scans on 10MB files do not leak memory."""
        workspace = setup_test_env["workspace"]
        target = workspace / "sample_10mb_mem.bin"
        target.write_bytes(secrets.token_bytes(10 * 1024 * 1024))

        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        for _ in range(5):
            res = await run_yara(str(target), _bypass_queue=True)
            assert res.status == "success"

        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
        # Memory growth should be well below 20MB after 5 scans
        assert total_growth < 20 * 1024 * 1024, (
            f"Memory growth too high: {total_growth / (1024 * 1024):.2f}MB"
        )


# ============================================================================
# 2. Invalid & Adversarial Inputs
# ============================================================================


class TestYaraInvalidInputs:
    """Stress tests on invalid, malformed, and adversarial inputs."""

    @pytest.mark.asyncio
    async def test_nonexistent_binary_file(self, setup_test_env):
        """Scanning a non-existent binary returns error ToolResult."""
        workspace = setup_test_env["workspace"]
        nonexistent = workspace / "does_not_exist.bin"

        result = await run_yara(str(nonexistent), _bypass_queue=True)
        assert result.status == "error"
        assert "Invalid file path" in result.message or "does not exist" in result.message

    @pytest.mark.asyncio
    async def test_nonexistent_rule_file(self, setup_test_env):
        """Scanning with a non-existent rule file returns error ToolResult."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"HELLO_WORLD")

        nonexistent_rule = workspace / "missing_rule.yar"
        result = await run_yara(str(target), rule_file=str(nonexistent_rule), _bypass_queue=True)
        assert result.status == "error"
        assert "Invalid file path" in result.message or "does not exist" in result.message

    @pytest.mark.asyncio
    async def test_empty_binary_file(self, setup_test_env):
        """Scanning a 0-byte empty file succeeds with 0 matches without crashing."""
        workspace = setup_test_env["workspace"]
        target = workspace / "empty.bin"
        target.write_bytes(b"")

        result = await run_yara(str(target), _bypass_queue=True)
        assert result.status == "success", f"Failed: {getattr(result, 'message', '')}"
        assert result.data["match_count"] == 0
        assert result.data["matches"] == []

    @pytest.mark.asyncio
    async def test_non_binary_unicode_text_file(self, setup_test_env):
        """Scanning text files with unicode/multilingual characters."""
        workspace = setup_test_env["workspace"]
        target = workspace / "unicode.txt"
        target.write_text(
            "Reversecore MCP 🚀 리버스 엔지니어링 逆向工程 Тест UTF-8\n" * 100,
            encoding="utf-8",
        )

        result = await run_yara(str(target), _bypass_queue=True)
        assert result.status == "success", f"Failed: {getattr(result, 'message', '')}"
        assert result.data["match_count"] == 0

    @pytest.mark.asyncio
    async def test_malformed_rule_file_syntax_error(self, setup_test_env):
        """Scanning with a syntactically invalid YARA rule returns clean error."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"MZ\x90\x00")

        bad_rule = workspace / "broken.yar"
        bad_rule.write_text("rule broken_syntax { strings: $a = { ZZ XX } condition: $a }")

        result = await run_yara(str(target), rule_file=str(bad_rule), _bypass_queue=True)
        assert result.status == "error"
        assert (
            "YARA" in result.message
            or "compilation" in result.message.lower()
            or "error" in result.message.lower()
        )

    @pytest.mark.asyncio
    async def test_malformed_rule_missing_include(self, setup_test_env):
        """Scanning with a rule that includes a non-existent file."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"MZ\x90\x00")

        bad_rule = workspace / "include_broken.yar"
        bad_rule.write_text('include "non_existent_subrule.yar"\nrule test { condition: true }')

        result = await run_yara(str(target), rule_file=str(bad_rule), _bypass_queue=True)
        assert result.status == "error"
        assert "YARA" in result.message or "error" in result.message.lower()

    @pytest.mark.asyncio
    async def test_empty_rule_file(self, setup_test_env):
        """Scanning with a 0-byte rule file compiles empty ruleset with 0 matches."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"MZ\x90\x00")

        empty_rule = workspace / "empty.yar"
        empty_rule.write_text("")

        result = await run_yara(str(target), rule_file=str(empty_rule), _bypass_queue=True)
        assert result.status == "success", f"Failed: {getattr(result, 'message', '')}"
        assert result.data["match_count"] == 0

    @pytest.mark.asyncio
    async def test_binary_file_as_rule_file(self, setup_test_env):
        """Passing a binary file as rule_file handles YARA compilation failure gracefully."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"MZ\x90\x00")

        bin_rule = workspace / "fake_rule.yar"
        bin_rule.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        result = await run_yara(str(target), rule_file=str(bin_rule), _bypass_queue=True)
        assert result.status == "error"
        assert "YARA" in result.message or "error" in result.message.lower()

    @pytest.mark.asyncio
    async def test_invalid_timeout_validation(self, setup_test_env):
        """Passing invalid timeout (<= 0 or non-int) triggers validation error."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(b"MZ\x90\x00")

        res_zero = await run_yara(str(target), timeout=0, _bypass_queue=True)
        assert res_zero.status == "error"
        assert "timeout" in res_zero.message.lower()

        res_neg = await run_yara(str(target), timeout=-5, _bypass_queue=True)
        assert res_neg.status == "error"
        assert "timeout" in res_neg.message.lower()

    @pytest.mark.asyncio
    async def test_unknown_category_fallback(self, setup_test_env):
        """Passing an unrecognized category name falls back gracefully to default categories."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target.bin"
        target.write_bytes(AES_FORWARD_SBOX)

        result = await run_yara(str(target), category="non_existent_category", _bypass_queue=True)
        assert result.status == "success", f"Failed: {getattr(result, 'message', '')}"


# ============================================================================
# 3. Concurrency Safety & `_YARA_RULES_CACHE` Cache Verification
# ============================================================================


class TestYaraConcurrencyAndCache:
    """Stress testing concurrent execution and caching mechanisms."""

    @pytest.mark.asyncio
    async def test_concurrent_scanning_50_coroutines(self, setup_test_env):
        """Execute 50 concurrent scans across multiple files and categories."""
        workspace = setup_test_env["workspace"]

        # Prepare 5 different target files
        targets = []
        for i in range(5):
            t = workspace / f"concurrent_target_{i}.bin"
            content = bytearray(secrets.token_bytes(200_000))
            if i % 2 == 0:
                content[50_000 : 50_000 + len(AES_FORWARD_SBOX)] = AES_FORWARD_SBOX
            if i % 3 == 0:
                content[100_000 : 100_000 + len(SYSCALL_STUB)] = SYSCALL_STUB
            t.write_bytes(content)
            targets.append(t)

        categories = [None, "crypto", "injection", "exploits", "malware"]

        async def worker(idx: int):
            target = targets[idx % len(targets)]
            cat = categories[idx % len(categories)]
            return await run_yara(str(target), category=cat, _bypass_queue=True)

        tasks = [worker(i) for i in range(50)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 50
        for r in results:
            assert r.status == "success", f"Failed: {getattr(r, 'message', '')}"
            assert isinstance(r.data["match_count"], int)

    @pytest.mark.asyncio
    async def test_cache_hit_performance_speedup(self, setup_test_env):
        """Verify warm cache scan provides significant speedup over cold compilation."""
        workspace = setup_test_env["workspace"]
        target = workspace / "cache_perf.bin"
        target.write_bytes(b"\x00" * 100_000)

        _YARA_RULES_CACHE.clear()

        # Cold run (must compile all rules)
        start_cold = time.perf_counter()
        res_cold = await run_yara(str(target), _bypass_queue=True)
        time_cold = time.perf_counter() - start_cold

        assert res_cold.status == "success", f"Failed: {getattr(res_cold, 'message', '')}"
        assert len(_YARA_RULES_CACHE) >= 1

        # Warm runs (should hit cache)
        warm_times = []
        for _ in range(10):
            start_warm = time.perf_counter()
            res_warm = await run_yara(str(target), _bypass_queue=True)
            warm_times.append(time.perf_counter() - start_warm)
            assert res_warm.status == "success"

        avg_warm = sum(warm_times) / len(warm_times)
        # Warm should be noticeably faster than cold compilation or very fast
        assert avg_warm < time_cold or avg_warm < 0.05, (
            f"Cold: {time_cold:.4f}s, Avg Warm: {avg_warm:.4f}s"
        )

    @pytest.mark.asyncio
    async def test_cache_eviction_at_100_entries(self, setup_test_env):
        """Verify FIFO eviction maintains cache size <= 100 without KeyError."""
        _YARA_RULES_CACHE.clear()

        # Insert 150 dummy entries into cache
        for i in range(150):
            _update_cache(f"key_{i}", float(i), f"mock_rules_{i}")

        assert len(_YARA_RULES_CACHE) == 100
        assert "key_0" not in _YARA_RULES_CACHE  # Evicted
        assert "key_149" in _YARA_RULES_CACHE  # Present

    @pytest.mark.asyncio
    async def test_cache_mtime_invalidation(self, setup_test_env):
        """Verify cache recompiles rule when rule file mtime changes."""
        workspace = setup_test_env["workspace"]
        target = workspace / "target_mtime.bin"
        target.write_bytes(b"HELLO_WORLD_TEST")

        rule_file = workspace / "custom_mtime.yar"
        rule_file.write_text('rule v1 { strings: $a = "HELLO" condition: $a }')

        # First run (v1)
        res1 = await run_yara(str(target), rule_file=str(rule_file), _bypass_queue=True)
        assert res1.status == "success", f"Failed: {getattr(res1, 'message', '')}"
        assert res1.data["match_count"] == 1
        assert res1.data["matches"][0]["rule"] == "v1"

        # Update rule file to v2 and force new mtime
        time.sleep(0.05)
        rule_file.write_text('rule v2 { strings: $a = "WORLD" condition: $a }')
        new_mtime = time.time() + 10
        os.utime(rule_file, (new_mtime, new_mtime))

        # Second run should recompile and match v2
        res2 = await run_yara(str(target), rule_file=str(rule_file), _bypass_queue=True)
        assert res2.status == "success", f"Failed: {getattr(res2, 'message', '')}"
        assert res2.data["match_count"] == 1
        assert res2.data["matches"][0]["rule"] == "v2"
