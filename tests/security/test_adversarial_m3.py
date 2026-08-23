"""Milestone 3 Empirical Adversarial Test Suite for Output Schema & Serialization.

Verifies:
1. High-speed `orjson` serialization vs stdlib `json` across large binary payloads (5,000+ items).
2. Elimination of double-serialization in `diff_tools.py` (native dicts instead of escaped strings).
3. Serialization resilience on non-serializable objects (custom classes, sets, bytearrays, NaN/Infinity, 64-bit/large ints) via `json_utils`.
4. Verification of all 10 migrated modules using standardized `json_utils`.
"""

from __future__ import annotations

import ast
import json as stdlib_json
import time
from typing import Any
from unittest.mock import patch

import pytest

from reversecore_mcp.core import json_utils
from reversecore_mcp.core.result import PaginationMeta, ToolSuccess
from reversecore_mcp.tools.analysis.diff_tools import (
    analyze_variant_changes,
    diff_binaries,
    match_libraries,
    patch_diff_1day,
)

pytestmark = pytest.mark.security


# ============================================================================
# 1. orjson vs stdlib json Performance & Parity Across Large Binary Payloads
# ============================================================================


class TestOrjsonPerformanceAndParityAdversarial:
    """Adversarial stress-testing and empirical benchmarking of orjson vs stdlib json."""

    def test_orjson_availability(self):
        """Verify that orjson is installed, enabled, and active in json_utils."""
        assert json_utils.is_orjson_available() is True

    def test_orjson_vs_stdlib_dumps_benchmark_5000_items(self):
        """Empirical benchmark: verify orjson dumps throughput is significantly faster (>1.8x compact, >5.0x indent)."""
        # Generate 5,000 realistic disassembly records
        payload_5000 = [
            {
                "address": f"0x{0x401000 + i * 4:08x}",
                "mnemonic": "mov" if i % 2 == 0 else "call",
                "operands": (
                    f"eax, [ebp - 0x{i:x}]" if i % 2 == 0 else f"0x{0x500000 + (i % 50) * 16:x}"
                ),
                "bytes": "8b45f4" if i % 2 == 0 else "e812345678",
                "comment": f"ref to var_{i}" if i % 3 == 0 else None,
            }
            for i in range(5000)
        ]

        iterations = 20

        # Benchmark compact serialization
        t0 = time.perf_counter()
        for _ in range(iterations):
            stdlib_json.dumps(payload_5000)
        std_time_compact = (time.perf_counter() - t0) / iterations

        t0 = time.perf_counter()
        for _ in range(iterations):
            s_fast = json_utils.dumps(payload_5000)
        fast_time_compact = (time.perf_counter() - t0) / iterations

        speedup_compact = std_time_compact / fast_time_compact

        # Benchmark formatted serialization (indent=2)
        t0 = time.perf_counter()
        for _ in range(iterations):
            stdlib_json.dumps(payload_5000, indent=2)
        std_time_fmt = (time.perf_counter() - t0) / iterations

        t0 = time.perf_counter()
        for _ in range(iterations):
            s_fast_fmt = json_utils.dumps(payload_5000, indent=2)
        fast_time_fmt = (time.perf_counter() - t0) / iterations

        speedup_fmt = std_time_fmt / fast_time_fmt

        assert isinstance(s_fast, str), "json_utils.dumps must return str"
        assert isinstance(s_fast_fmt, str), "json_utils.dumps must return str"

        # Assert performance acceleration
        assert speedup_compact >= 1.8, (
            f"Expected compact speedup >= 1.8x, got {speedup_compact:.2f}x"
        )
        assert speedup_fmt >= 5.0, f"Expected formatted speedup >= 5.0x, got {speedup_fmt:.2f}x"

    def test_orjson_vs_stdlib_loads_benchmark_5000_items(self):
        """Empirical benchmark: verify orjson loads throughput is faster than stdlib loads."""
        payload_5000 = [
            {
                "name": f"sym.func_{i:05d}",
                "offset": 0x400000 + i * 64,
                "size": 64 + (i % 256),
                "calltype": "cdecl",
                "nargs": i % 8,
                "nbbs": 1 + (i % 16),
                "edges": 2 + (i % 32),
                "cc": 1 + (i % 10),
            }
            for i in range(5000)
        ]

        raw_json_str = stdlib_json.dumps(payload_5000)
        raw_json_bytes = raw_json_str.encode("utf-8")

        iterations = 20

        t0 = time.perf_counter()
        for _ in range(iterations):
            _ = stdlib_json.loads(raw_json_str)
        std_load_time = (time.perf_counter() - t0) / iterations

        t0 = time.perf_counter()
        for _ in range(iterations):
            _ = json_utils.loads(raw_json_str)
        fast_load_str_time = (time.perf_counter() - t0) / iterations

        t0 = time.perf_counter()
        for _ in range(iterations):
            _ = json_utils.loads(raw_json_bytes)
        fast_load_bytes_time = (time.perf_counter() - t0) / iterations

        assert std_load_time / fast_load_str_time >= 1.5
        assert std_load_time / fast_load_bytes_time >= 1.5

    def test_json_parity_roundtrip(self):
        """Verify perfect round-trip data fidelity between orjson and stdlib json."""
        complex_payload = {
            "strings": ["hello", "world", "reverse engineering", "\x00\x01\x1f\n\t"],
            "integers": [0, -1, 42, 2**31 - 1, -(2**31)],
            "floats": [0.0, 3.141592653589793, -123.456, 1e10, 1e-10],
            "booleans": [True, False, None],
            "nested_dict": {
                "level1": {"level2": {"level3": {"binary_addr": "0x401000", "size": 1024}}}
            },
            "array_of_objs": [{"id": i, "tag": f"tag_{i}"} for i in range(100)],
        }

        # Serialized with json_utils, loaded with stdlib
        fast_serialized = json_utils.dumps(complex_payload)
        stdlib_loaded = stdlib_json.loads(fast_serialized)
        assert stdlib_loaded == complex_payload

        # Serialized with stdlib, loaded with json_utils
        stdlib_serialized = stdlib_json.dumps(complex_payload)
        fast_loaded = json_utils.loads(stdlib_serialized)
        assert fast_loaded == complex_payload

    def test_json_decode_error_compatibility(self):
        """Verify JSONDecodeError raised by json_utils is catchable by stdlib and json_utils handlers."""
        invalid_json = '{"unclosed": "string'

        # Must catch with json_utils.JSONDecodeError
        with pytest.raises(json_utils.JSONDecodeError):
            json_utils.loads(invalid_json)

        # Must catch with stdlib_json.JSONDecodeError
        with pytest.raises(stdlib_json.JSONDecodeError):
            json_utils.loads(invalid_json)


# ============================================================================
# 2. Elimination of Double-Serialization in diff_tools.py
# ============================================================================


class TestDoubleSerializationEliminationAdversarial:
    """Verify that all diff tools return native structured dicts and never double-encode JSON."""

    @pytest.mark.asyncio
    async def test_diff_binaries_returns_native_dict(self):
        """Verify diff_binaries returns native dict in ToolSuccess.data, not a JSON string."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async") as mock_sub,
        ):
            mock_sub.side_effect = [
                ("0x401000 new block\n0x401050 removed block\n", 60),
                ("similarity: 0.92\n", 20),
            ]

            res = await diff_binaries("bin_a.exe", "bin_b.exe")

            assert isinstance(res, ToolSuccess)
            # 1. res.data MUST be a native Python dict
            assert isinstance(res.data, dict)
            assert not isinstance(res.data, str)

            # 2. Verify internal fields
            assert res.data["similarity"] == 0.92
            assert res.data["total_changes"] == 2
            assert len(res.data["changes"]) == 2
            assert isinstance(res.data["summary"], dict)
            assert res.data["summary"]["similarity_score"] == 0.92

            # 3. Verify pagination object is attached
            assert isinstance(res.pagination, PaginationMeta)
            assert res.pagination.total_items == 2

            # 4. Wire-level serialization: serialize ToolSuccess.model_dump()
            dumped = res.model_dump()
            wire_json = json_utils.dumps(dumped)

            # Assert NO double serialization (i.e. 'data' must be a JSON object, not escaped string)
            parsed_wire = json_utils.loads(wire_json)
            assert isinstance(parsed_wire["data"], dict)
            assert parsed_wire["data"]["similarity"] == 0.92

    @pytest.mark.asyncio
    async def test_analyze_variant_changes_returns_native_dict(self):
        """Verify analyze_variant_changes returns native dict in ToolSuccess.data."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries") as mock_diff,
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                return_value=(
                    '[{"offset": 4198400, "size": 256, "name": "main"}]',
                    100,
                ),
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.generate_function_graph",
                return_value=ToolSuccess(data="graph TD; A-->B;"),
            ),
        ):
            # diff_binaries returns native dict
            mock_diff.return_value = ToolSuccess(
                data={
                    "similarity": 0.88,
                    "total_changes": 1,
                    "changes": [{"address": "0x401010", "type": "code_change"}],
                }
            )

            res = await analyze_variant_changes("orig.bin", "variant.bin")

            assert isinstance(res, ToolSuccess)
            assert isinstance(res.data, dict)
            assert not isinstance(res.data, str)
            assert res.data["similarity"] == 0.88
            assert len(res.data["top_modified_functions"]) == 1
            assert res.data["top_modified_functions"][0]["function"] == "main"

            wire_json = json_utils.dumps(res.model_dump())
            parsed_wire = json_utils.loads(wire_json)
            assert isinstance(parsed_wire["data"], dict)

    @pytest.mark.asyncio
    async def test_analyze_variant_changes_handles_legacy_string_fallback(self):
        """Verify analyze_variant_changes gracefully handles legacy string diff_result.data."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries") as mock_diff,
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.execute_subprocess_async",
                return_value=(
                    '[{"offset": 4198400, "size": 256, "name": "main"}]',
                    100,
                ),
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.generate_function_graph",
                return_value=ToolSuccess(data="graph TD; A-->B;"),
            ),
        ):
            # Simulate legacy string data
            legacy_string_data = stdlib_json.dumps(
                {
                    "similarity": 0.75,
                    "total_changes": 1,
                    "changes": [{"address": "0x401020", "type": "control_flow_change"}],
                }
            )
            mock_diff.return_value = ToolSuccess(data=legacy_string_data)

            res = await analyze_variant_changes("orig.bin", "variant.bin")

            assert isinstance(res, ToolSuccess)
            assert isinstance(res.data, dict)
            assert res.data["similarity"] == 0.75

    @pytest.mark.asyncio
    async def test_match_libraries_returns_native_dict(self):
        """Verify match_libraries returns native dict without double-encoding."""
        with (
            patch(
                "reversecore_mcp.tools.analysis.diff_tools.validate_file_path",
                side_effect=lambda p: p,
            ),
            patch(
                "reversecore_mcp.tools.analysis.diff_tools._execute_r2_command",
                return_value=(
                    '[{"name": "sym.imp.strcpy", "offset": 4198400}, {"name": "main", "offset": 4199000}]',
                    150,
                ),
            ),
            patch("os.path.getsize", return_value=1024 * 1024),
        ):
            res = await match_libraries("sample.exe")

            assert isinstance(res, ToolSuccess)
            assert isinstance(res.data, dict)
            assert not isinstance(res.data, str)
            assert res.data["total_functions"] == 2
            assert res.data["library_functions"] == 1
            assert res.data["user_functions"] == 1
            assert res.data["noise_reduction_percentage"] == 50.0

            wire_json = json_utils.dumps(res.model_dump())
            parsed_wire = json_utils.loads(wire_json)
            assert isinstance(parsed_wire["data"], dict)
            assert isinstance(parsed_wire["data"]["library_matches"], list)

    @pytest.mark.asyncio
    async def test_patch_diff_1day_returns_native_dict(self):
        """Verify patch_diff_1day returns native dict without double-encoding."""
        with (
            patch("reversecore_mcp.tools.analysis.diff_tools.diff_binaries") as mock_diff,
            patch("reversecore_mcp.tools.analysis.diff_tools.analyze_variant_changes") as mock_var,
        ):
            mock_diff.return_value = ToolSuccess(
                data={"similarity": 0.85, "changes": [{"address": "0x401000"}]}
            )
            mock_var.return_value = ToolSuccess(
                data={
                    "similarity": 0.85,
                    "top_modified_functions": [
                        {
                            "function": "vuln_func",
                            "change_count": 3,
                            "cfg_mermaid": "graph TD;",
                        }
                    ],
                }
            )

            res = await patch_diff_1day("vuln_v1.exe", "patched_v2.exe")

            assert isinstance(res, ToolSuccess)
            assert isinstance(res.data, dict)
            assert res.data["similarity_score"] == 0.85
            assert len(res.data["top_modified_functions"]) == 1

            wire_json = json_utils.dumps(res.model_dump())
            parsed_wire = json_utils.loads(wire_json)
            assert isinstance(parsed_wire["data"], dict)


# ============================================================================
# 3. Serialization Resilience on Non-Serializable Types & Edge Cases
# ============================================================================


class CustomTestEntity:
    """Test entity for non-serializable custom class testing."""

    def __init__(self, name: str, value: int):
        self.name = name
        self.value = value

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value}


class TestSerializationResilienceAdversarial:
    """Verify json_utils handles non-standard, non-serializable, and boundary types gracefully."""

    def test_set_and_frozenset_resilience(self):
        """Verify sets and frozensets serialize properly when passing default=list."""
        payload = {
            "tags": {"malware", "ransomware", "c2"},
            "frozen_ids": frozenset([101, 102, 103]),
        }

        # With default=list, must succeed via stdlib fallback
        serialized = json_utils.dumps(payload, default=list)
        loaded = json_utils.loads(serialized)

        assert isinstance(loaded["tags"], list)
        assert set(loaded["tags"]) == {"malware", "ransomware", "c2"}
        assert set(loaded["frozen_ids"]) == {101, 102, 103}

    def test_bytearray_and_bytes_resilience(self):
        """Verify bytearray and bytes serialize properly with default=str or custom converter."""
        payload = {
            "raw_bytes": b"\x90\x90\xcc\xc3",
            "buffer": bytearray(b"MZ\x90\x00"),
        }

        # With default=str
        serialized = json_utils.dumps(payload, default=str)
        loaded = json_utils.loads(serialized)

        assert "raw_bytes" in loaded
        assert "buffer" in loaded

    def test_nan_and_infinity_compliance(self):
        """Verify NaN and Infinity serialize to valid JSON null (strict RFC 8259 compliance)."""
        payload = {
            "nan_val": float("nan"),
            "pos_inf": float("inf"),
            "neg_inf": float("-inf"),
        }

        serialized = json_utils.dumps(payload)
        assert "NaN" not in serialized, "NaN is invalid JSON token"
        assert "Infinity" not in serialized, "Infinity is invalid JSON token"

        loaded = json_utils.loads(serialized)
        assert loaded["nan_val"] is None
        assert loaded["pos_inf"] is None
        assert loaded["neg_inf"] is None

    def test_custom_class_instance_resilience(self):
        """Verify custom Python class instances serialize with default callable."""
        entity = CustomTestEntity("sample_binary", 4096)
        payload = {"entity": entity}

        serialized = json_utils.dumps(
            payload,
            default=lambda o: (o.to_dict() if isinstance(o, CustomTestEntity) else str(o)),
        )
        loaded = json_utils.loads(serialized)

        assert loaded["entity"] == {"name": "sample_binary", "value": 4096}

    def test_64bit_integer_and_overflow_resilience(self):
        """Verify full 64-bit integers and large integer fallback behavior."""
        u64_max = 2**64 - 1
        i64_max = 2**63 - 1
        payload_64 = {"u64": u64_max, "i64": i64_max}

        # Full 64-bit uint is supported natively
        serialized_64 = json_utils.dumps(payload_64)
        loaded_64 = json_utils.loads(serialized_64)
        assert loaded_64["u64"] == u64_max
        assert loaded_64["i64"] == i64_max

        # > 64-bit integer triggers stdlib fallback without throwing exception
        big_int_128 = 2**127 + 12345
        payload_128 = {"huge_number": big_int_128}
        serialized_128 = json_utils.dumps(payload_128)
        assert str(big_int_128) in serialized_128

    def test_deeply_nested_structures(self):
        """Verify deeply nested dict/list hierarchy (50 levels deep) serializes and loads accurately."""
        root: dict[str, Any] = {"level": 0}
        curr = root
        for i in range(1, 50):
            curr["child"] = {"level": i}
            curr = curr["child"]

        serialized = json_utils.dumps(root)
        loaded = json_utils.loads(serialized)

        # Traverse to level 49
        node = loaded
        for i in range(50):
            assert node["level"] == i
            if i < 49:
                node = node["child"]


# ============================================================================
# 4. Audit of Migrated Modules
# ============================================================================


class TestMigratedModulesAudit:
    """Verify that all 10 surveyed modules in Milestone 3 import json_utils instead of stdlib json directly."""

    MIGRATED_FILES = [
        "reversecore_mcp/benchmarks/corpus_loader.py",
        "reversecore_mcp/benchmarks/models.py",
        "reversecore_mcp/core/audit.py",
        "reversecore_mcp/core/memory.py",
        "reversecore_mcp/core/result_cache.py",
        "reversecore_mcp/tools/analysis/advanced_yara.py",
        "reversecore_mcp/tools/analysis/symbolic_analysis.py",
        "reversecore_mcp/tools/forensics/memory.py",
        "reversecore_mcp/tools/report/vex_generator.py",
        "reversecore_mcp/tools/radare2/radare2_mcp_tools.py",
    ]

    def test_no_raw_json_imports_in_migrated_modules(self):
        """Verify AST of each migrated module has no raw 'import json'."""
        for file_path in self.MIGRATED_FILES:
            with open(file_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)

            has_json_utils_import = False
            has_raw_json_import = False

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "json":
                            has_raw_json_import = True
                elif isinstance(node, ast.ImportFrom):
                    if (
                        node.module == "reversecore_mcp.core"
                        or node.module == "reversecore_mcp.core.json_utils"
                    ):
                        for alias in node.names:
                            if alias.name == "json_utils" or alias.name == "json":
                                has_json_utils_import = True

            assert not has_raw_json_import, f"File {file_path} contains forbidden raw 'import json'"
            assert has_json_utils_import, (
                f"File {file_path} is missing 'from reversecore_mcp.core import json_utils'"
            )
