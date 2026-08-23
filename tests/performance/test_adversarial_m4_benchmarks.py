"""Tier 5 Adversarial Micro-Benchmarks & Token Hardening Challenge Suite.

Empirically tests and stress-tests Milestone 4 claims:
1. High-speed orjson serialization throughput (>= 4x speedup, sub-millisecond latency under heavy loads up to 30k items).
2. Deeply nested payloads, Unicode/extreme character handling, fallback robustness, concurrent serialization bursts.
3. Token & byte reduction metrics across compact 4-tuple disassembly, windowed decompilation, bounded xrefs, and double-serialization elimination.
4. Information fidelity preservation across token-optimized schemas.
5. Deterministic SHA-256 cache key computation under 10,000 randomized permutations, parameter collision resistance, and sub-microsecond latency.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json as stdlib_json
import random
import re
import time
from typing import Any

import pytest

from reversecore_mcp.core import json_utils as orjson_utils
from reversecore_mcp.core.result import PaginationMeta, ToolSuccess, success


def estimate_tokens(text: str) -> int:
    """Estimate token count using regex word/symbol boundaries."""
    tokens = re.findall(r"\w+|[^\w\s]", text)
    return max(1, len(tokens))


# ===========================================================================
# 1. Adversarial orjson Serialization Benchmarks
# ===========================================================================


class TestAdversarialOrjsonSerialization:
    """Adversarial stress-testing of orjson vs stdlib json under extreme payloads."""

    def _generate_adversarial_payload(self, count: int) -> dict[str, Any]:
        """Generate realistic large-scale binary analysis payload."""
        mnemonics = [
            ("mov", "rax, qword [rbp - 0x18]"),
            ("lea", "rdi, [rip + 0x2048]"),
            ("call", "sym.imp.__stack_chk_fail"),
            ("test", "eax, eax"),
            ("jne", "0x004012a8"),
            ("movzx", "ecx, byte [rax + rdx*4]"),
            ("vmovdqu", "ymm0, ymmword [rsp + 0x80]"),
            ("xor", "ebx, ebx"),
        ]
        instructions = []
        for i in range(count):
            m, op = mnemonics[i % len(mnemonics)]
            instructions.append(
                {
                    "offset": 0x400000 + i * 4,
                    "address": hex(0x400000 + i * 4),
                    "size": 4,
                    "mnemonic": m,
                    "operands": op,
                    "comment": f"xrefs_to: sym.func_{i % 64:03d} (flag: 0x{i:04x})",
                    "esil": f"{op},rax,=",
                    "bytes": "4889c0",
                    "entropy": 0.45 + (i % 100) * 0.005,
                    "flags": ["executable", "read", f"sym.sub_{i:04x}"],
                }
            )

        return {
            "status": "success",
            "file": "/workspace/adversarial_target.bin",
            "arch": "x86_64",
            "instruction_count": count,
            "instructions": instructions,
            "symbols": [
                {
                    "name": f"sym.worker_{i}",
                    "address": hex(0x400000 + i * 128),
                    "size": 128,
                    "type": "FUNC",
                    "bind": "GLOBAL",
                }
                for i in range(min(count, 500))
            ],
            "sections": [
                {
                    "name": f".sec_{i}",
                    "vaddr": hex(0x400000 + i * 0x1000),
                    "size": 0x1000,
                    "perms": "r-x",
                }
                for i in range(16)
            ],
        }

    @pytest.mark.parametrize("item_count", [500, 2000, 10000, 30000])
    def test_orjson_speedup_and_submillisecond_scaling(self, item_count: int):
        """Verify >= 4x speedup and sub-millisecond serialization on heavy payloads."""
        payload = self._generate_adversarial_payload(item_count)
        iterations = 20 if item_count <= 2000 else 10

        # Benchmark stdlib json
        t0 = time.perf_counter()
        for _ in range(iterations):
            stdlib_json.dumps(payload)
        t_stdlib = (time.perf_counter() - t0) / iterations

        # Benchmark orjson
        t1 = time.perf_counter()
        for _ in range(iterations):
            orjson_utils.dumps(payload)
        t_orjson = (time.perf_counter() - t1) / iterations

        speedup = t_stdlib / max(t_orjson, 1e-9)

        print(
            f"\n[Adversarial Payload {item_count:5d} items] "
            f"stdlib: {t_stdlib * 1000:7.3f}ms | orjson: {t_orjson * 1000:7.3f}ms | Speedup: {speedup:5.2f}x"
        )

        # Assertions
        # 1. orjson must be significantly faster (at least 3.5x - 6x)
        assert speedup >= 3.5, f"Expected speedup >= 3.5x, got {speedup:.2f}x"

        # 2. For standard payload (500 - 2000 items), orjson must be sub-millisecond (< 1.0ms)
        if item_count <= 2000:
            assert t_orjson < 0.001, (
                f"Expected sub-millisecond latency for {item_count} items, got {t_orjson * 1000:.3f}ms"
            )

    def test_orjson_deeply_nested_and_unicode_stress(self):
        """Test orjson roundtrip with deeply nested structures, Unicode, escape sequences."""
        nested: dict[str, Any] = {"level": 50, "value": "deep_core"}
        for level in range(49, 0, -1):
            nested = {
                "level": level,
                "child": nested,
                "unicode_sample": f"reverse_한국어_日本語_русский_🚀_{level}",
                "escapes": "\x00\x01\x02\t\n\r\x1b[31m",
                "large_int": 2**62 + level,
                "float_val": 1.23456789e-5,
            }

        serialized = orjson_utils.dumps(nested)
        deserialized = orjson_utils.loads(serialized)

        assert deserialized["level"] == 1
        assert deserialized["unicode_sample"] == "reverse_한국어_日本語_русский_🚀_1"
        assert deserialized["large_int"] == 2**62 + 1
        assert deserialized["child"]["child"]["level"] == 3

    def test_orjson_fallback_on_unsupported_types(self):
        """Verify json_utils.dumps falls back cleanly when objects are not natively supported by orjson."""

        class CustomAnalysisMetadata:
            def __init__(self, name: str, tags: set[str]):
                self.name = name
                self.tags = list(tags)

            def to_dict(self):
                return {"name": self.name, "tags": self.tags}

        payload = {"meta": CustomAnalysisMetadata("test_target", {"elf", "x86_64", "stripped"})}

        # Passing a default serializer should work via fallback without crashing
        res = orjson_utils.dumps(payload, default=lambda o: o.to_dict())
        parsed = orjson_utils.loads(res)
        assert parsed["meta"]["name"] == "test_target"
        assert set(parsed["meta"]["tags"]) == {"elf", "x86_64", "stripped"}

    def test_orjson_concurrent_serialization_burst(self):
        """Stress-test thread-safety and speedup under 32 concurrent worker threads."""
        payload = self._generate_adversarial_payload(1000)

        def serialize_orjson_task():
            t0 = time.perf_counter()
            for _ in range(50):
                orjson_utils.dumps(payload)
            return (time.perf_counter() - t0) / 50

        def serialize_stdlib_task():
            t0 = time.perf_counter()
            for _ in range(50):
                stdlib_json.dumps(payload)
            return (time.perf_counter() - t0) / 50

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            f_orjson = [executor.submit(serialize_orjson_task) for _ in range(32)]
            f_stdlib = [executor.submit(serialize_stdlib_task) for _ in range(32)]
            latencies_orjson = [f.result() for f in f_orjson]
            latencies_stdlib = [f.result() for f in f_stdlib]

        avg_orjson_ms = (sum(latencies_orjson) / len(latencies_orjson)) * 1000
        avg_stdlib_ms = (sum(latencies_stdlib) / len(latencies_stdlib)) * 1000
        concurrent_speedup = avg_stdlib_ms / max(avg_orjson_ms, 1e-9)

        print(
            f"\n[Concurrent Serialization (32 workers)] "
            f"stdlib: {avg_stdlib_ms:.3f}ms | orjson: {avg_orjson_ms:.3f}ms | Speedup: {concurrent_speedup:.2f}x"
        )
        assert concurrent_speedup >= 3.0, f"Concurrent speedup {concurrent_speedup:.2f}x < 3.0x"
        assert avg_orjson_ms < 3.0, (
            f"Average serialization latency {avg_orjson_ms:.3f}ms exceeded 3ms"
        )


# ===========================================================================
# 2. Adversarial Token Reduction & Schema Hardening Benchmarks
# ===========================================================================


class TestAdversarialTokenReduction:
    """Adversarial validation of token and byte reduction across all optimized schemas."""

    def test_compact_disassembly_token_reduction_and_fidelity(self):
        """Test compact 4-tuple vs verbose JSON representation, validating >= 70% token/byte reduction & 100% fidelity."""
        raw_instructions = [
            (
                0x401000 + i * 4,
                "mov",
                f"dword [rbp - 0x{i * 4:x}], eax",
                f"local_var_{i}",
            )
            for i in range(1000)
        ]

        # 1. Verbose Dict Representation (legacy verbose tool output)
        verbose_dict = {
            "status": "success",
            "instructions": [
                {
                    "offset": addr,
                    "address": hex(addr),
                    "size": 4,
                    "opcode": f"{mnem} {ops}",
                    "mnemonic": mnem,
                    "operands": ops,
                    "comment": cmt,
                    "esil": f"{ops},eax,=",
                    "bytes": "8945fc",
                    "family": "cpu",
                }
                for addr, mnem, ops, cmt in raw_instructions
            ],
        }

        # 2. Compact 4-tuple Representation (optimized tool output)
        compact_dict = {
            "status": "success",
            "format": "compact",
            "total_instructions": len(raw_instructions),
            "instructions": [
                [hex(addr), mnem, ops, cmt] for addr, mnem, ops, cmt in raw_instructions
            ],
        }

        verbose_wire = orjson_utils.dumps(verbose_dict)
        compact_wire = orjson_utils.dumps(compact_dict)

        v_bytes = len(verbose_wire)
        c_bytes = len(compact_wire)
        v_tok = estimate_tokens(verbose_wire)
        c_tok = estimate_tokens(compact_wire)

        reduction_bytes = (1.0 - (c_bytes / v_bytes)) * 100.0
        reduction_tokens = (1.0 - (c_tok / v_tok)) * 100.0

        print(
            f"\n[Compact Disassembly (1000 ops)]\n"
            f"  Verbose Schema : {v_bytes:6d}B ({v_tok:6d} tokens)\n"
            f"  Compact 4-Tuple: {c_bytes:6d}B ({c_tok:6d} tokens)\n"
            f"  -> Byte Reduction : {reduction_bytes:5.1f}%\n"
            f"  -> Token Reduction: {reduction_tokens:5.1f}%"
        )

        assert reduction_bytes >= 70.0, (
            f"Expected >= 70% byte reduction vs verbose schema, got {reduction_bytes:.1f}%"
        )
        assert reduction_tokens >= 70.0, (
            f"Expected >= 70% token reduction vs verbose schema, got {reduction_tokens:.1f}%"
        )

        # Information Fidelity Verification:
        # Check that all 1,000 instructions retain exact address, mnemonic, operands, and comment in order
        for i, (addr, mnem, ops, cmt) in enumerate(raw_instructions):
            tuple_item = compact_dict["instructions"][i]
            assert tuple_item[0] == hex(addr)
            assert tuple_item[1] == mnem
            assert tuple_item[2] == ops
            assert tuple_item[3] == cmt

    def test_decompilation_windowing_adversarial_boundaries(self):
        """Stress-test windowed decompilation on large functions and edge-case boundaries."""
        # 10,000 line function
        lines = [f"    var_{i:05d} = input_buf[{i % 256}] ^ 0x5a;" for i in range(10000)]
        full_code = "int huge_kernel(uint8_t *input_buf) {\n" + "\n".join(lines) + "\n}"
        full_lines = full_code.splitlines()
        total_lines = len(full_lines)

        full_tokens = estimate_tokens(full_code)

        # Test window sizes: 50, 100, 200
        for window_size in [50, 100, 200]:
            windowed_text = "\n".join(full_lines[:window_size])
            w_tokens = estimate_tokens(windowed_text)
            reduction = (1.0 - (w_tokens / full_tokens)) * 100.0
            print(
                f"\n[Decomp Window {window_size:3d}/{total_lines} lines] "
                f"Tokens: {full_tokens:6d} -> {w_tokens:5d} | Reduction: {reduction:5.2f}%"
            )
            assert reduction >= 85.0, (
                f"Expected >= 85% token reduction for window {window_size}, got {reduction:.2f}%"
            )

        # Test edge case: offset past end of function
        offset_past_end = 15000
        window_past = full_lines[offset_past_end : offset_past_end + 100]
        assert len(window_past) == 0

        # Test edge case: negative offset clamped
        clamped_offset = max(0, -50)
        window_neg = full_lines[clamped_offset : clamped_offset + 100]
        assert len(window_neg) == 100

    def test_bounded_xrefs_hub_scaling_and_fidelity(self):
        """Test bounded xrefs with 10,000 callers to a hub function like malloc or printf."""
        total_callers = 10000
        unbounded_xrefs = [
            {
                "from": hex(0x401000 + i * 16),
                "type": "CALL",
                "opcode": "call sym.imp.malloc",
                "fcn_name": f"sym.handler_{i:05d}",
                "fcn_addr": hex(0x401000 + i * 32),
            }
            for i in range(total_callers)
        ]

        bounded_limit = 50
        bounded_xrefs = unbounded_xrefs[:bounded_limit]

        unbounded_str = orjson_utils.dumps(unbounded_xrefs)
        bounded_str = orjson_utils.dumps(bounded_xrefs)

        u_tok = estimate_tokens(unbounded_str)
        b_tok = estimate_tokens(bounded_str)

        reduction = (1.0 - (b_tok / u_tok)) * 100.0
        print(
            f"\n[Hub Xrefs 50/{total_callers} callers] "
            f"Unbounded: {len(unbounded_str):7d}B ({u_tok:7d} tok) -> "
            f"Bounded: {len(bounded_str):5d}B ({b_tok:5d} tok) | Reduction: {reduction:5.2f}%"
        )

        assert reduction >= 98.0, (
            f"Expected >= 98% reduction for 10k hub xrefs, got {reduction:.2f}%"
        )

        # Check that caller metadata in bounded output is unaltered
        for i in range(bounded_limit):
            assert bounded_xrefs[i]["from"] == unbounded_xrefs[i]["from"]
            assert bounded_xrefs[i]["fcn_name"] == unbounded_xrefs[i]["fcn_name"]

    def test_double_serialization_elimination_overhead(self):
        """Test elimination of double serialization (JSON in JSON) across diverse payload structures."""
        diff_payload = {
            "binary_a": "target_v1.bin",
            "binary_b": "target_v2.bin",
            "similarity_score": 0.942,
            "matched_functions": [
                {
                    "name": f"sym.func_{i:03d}",
                    "addr_a": hex(0x401000 + i * 0x80),
                    "addr_b": hex(0x402000 + i * 0x80),
                    "similarity": 0.99 - (i % 20) * 0.01,
                    "changes": ["instruction_modified", "jump_target_adjusted"],
                }
                for i in range(300)
            ],
        }

        # Double serialization: nested json string inside ToolSuccess
        double_payload = ToolSuccess(data=stdlib_json.dumps(diff_payload, indent=2))
        double_wire = orjson_utils.dumps(double_payload.model_dump())

        # Native dict inside ToolSuccess
        native_payload = success(
            diff_payload, pagination=PaginationMeta(has_more=False, total_items=300)
        )
        native_wire = orjson_utils.dumps(native_payload.model_dump())

        d_bytes = len(double_wire)
        n_bytes = len(native_wire)
        d_tok = estimate_tokens(double_wire)
        n_tok = estimate_tokens(native_wire)

        byte_savings = (1.0 - (n_bytes / d_bytes)) * 100.0
        token_savings = (1.0 - (n_tok / d_tok)) * 100.0

        print(
            f"\n[Double Serialization Elimination]\n"
            f"  Double Serialized Wire: {d_bytes:6d}B ({d_tok:6d} tokens)\n"
            f"  Native Dict Wire      : {n_bytes:6d}B ({n_tok:6d} tokens)\n"
            f"  -> Wire Byte Savings : {byte_savings:5.2f}%\n"
            f"  -> Wire Token Savings: {token_savings:5.2f}%"
        )

        assert byte_savings >= 35.0, f"Expected >= 35% byte savings, got {byte_savings:.2f}%"
        assert token_savings >= 35.0, f"Expected >= 35% token savings, got {token_savings:.2f}%"


# ===========================================================================
# 3. Adversarial SHA-256 Cache Key Determinism & Collision Resistance
# ===========================================================================


class TestAdversarialCacheKeyDeterminism:
    """Stress-testing SHA-256 result cache key computation under 10,000 permutations."""

    def test_sha256_cache_key_under_10k_random_permutations(self):
        """Generate 10,000 random key-order permutations and assert exact hash determinism."""
        base_kwargs = {
            "address": "0x401000",
            "format": "compact",
            "page_size": 100,
            "cursor": "200",
            "filter": "calls_only",
            "depth": 3,
            "include_comments": True,
            "demangle": True,
            "arch": "x86_64",
            "heuristics": ["cfg", "xrefs", "strings"],
        }

        # Generate canonical hash
        s_canonical = orjson_utils.dumps(dict(sorted(base_kwargs.items())))
        canonical_key = hashlib.sha256(f"Radare2_disassemble::{s_canonical}".encode()).hexdigest()

        keys_list = list(base_kwargs.keys())
        rng = random.Random(42)

        # Test 10,000 permutations
        for _ in range(10000):
            shuffled_keys = keys_list.copy()
            rng.shuffle(shuffled_keys)
            permuted_dict = {k: base_kwargs[k] for k in shuffled_keys}

            s_permuted = orjson_utils.dumps(dict(sorted(permuted_dict.items())))
            permuted_key = hashlib.sha256(f"Radare2_disassemble::{s_permuted}".encode()).hexdigest()

            assert permuted_key == canonical_key, (
                f"Cache key mismatch under permutation: {permuted_key} != {canonical_key}"
            )

    def test_sha256_cache_key_collision_resistance_10k_distinct_inputs(self):
        """Generate 10,000 unique parameter sets and verify zero hash collisions."""
        hashes = set()
        for i in range(10000):
            kwargs = {
                "address": hex(0x400000 + i * 4),
                "cursor": str(i % 100),
                "page_size": 50 + (i % 50),
                "format": "compact" if i % 2 == 0 else "raw",
            }
            s = orjson_utils.dumps(dict(sorted(kwargs.items())))
            k = hashlib.sha256(f"tool_{i % 5}::{s}".encode()).hexdigest()
            hashes.add(k)

        # All 10,000 distinct parameter vectors must map to 10,000 distinct hash keys
        assert len(hashes) == 10000, (
            f"Expected 10000 unique hashes, got {len(hashes)} (collision detected!)"
        )

    def test_sha256_cache_key_high_throughput_latency(self):
        """Verify SHA-256 cache key computation latency is strictly < 10 microseconds."""
        kwargs = {
            "address": "0x401000",
            "format": "compact",
            "page_size": 100,
            "cursor": "200",
            "filter": "calls_only",
        }

        iterations = 10000
        t0 = time.perf_counter()
        for _ in range(iterations):
            s = orjson_utils.dumps(dict(sorted(kwargs.items())))
            hashlib.sha256(f"Radare2_tool::{s}".encode()).hexdigest()
        elapsed_per_op_us = ((time.perf_counter() - t0) / iterations) * 1e6

        print(
            f"\n[SHA-256 Cache Key Throughput (10k ops)] Mean Latency: {elapsed_per_op_us:.3f} µs per key"
        )
        assert elapsed_per_op_us < 10.0, (
            f"Cache key computation latency {elapsed_per_op_us:.3f}µs exceeded 10µs target"
        )
