"""Milestone 2 Empirical Adversarial Test Suite for Dynamic Resources.

Verifies:
1. Dynamic resource endpoints against edge cases:
   - Binaries with 0 sections, 500 sections, all sections entropy > 7.0.
   - Hub functions with 5,000 xrefs, functions with 0 xrefs.
   - Missing binaries and path traversal attempts.
   - Malformed addresses (SQL/command injection, non-hex, negative offsets, huge hex).
2. Output formatting, token limits (truncation/bounding), and error handling.
3. FastMCP resource manager routing and wire-level resolution.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.result import ToolError, ToolSuccess
from reversecore_mcp.resources import (
    register_resources,
)
from reversecore_mcp.server import mcp

pytestmark = pytest.mark.security


@pytest.fixture
def mock_mcp():
    """Fixture providing a mock FastMCP instance and capturing registered handlers."""
    registered = {}
    mcp_mock = MagicMock()

    def capture_resource(uri, **kwargs):
        def decorator(func):
            registered[uri] = func
            return func

        return decorator

    mcp_mock.resource = capture_resource
    register_resources(mcp_mock)
    return registered


# ============================================================================
# 1. Section Table & Entropy Adversarial Tests
# ============================================================================


class TestSectionsAndEntropyAdversarial:
    """Stress testing memory map and section resources against edge cases."""

    @pytest.mark.asyncio
    async def test_memory_map_zero_sections(self, mock_mcp):
        """Test memory map on a binary with 0 sections (stripped/custom header)."""
        sec_func = mock_mcp.get("reversecore://{filename}/memory_map")
        assert sec_func is not None

        mock_lief_res = ToolSuccess(
            data={"sections": []},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/zero_sec.bin",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await sec_func("zero_sec.bin")
            assert "# 🗺️ Memory Map & Section Table: zero_sec.bin" in result
            assert "No sections found in binary header." in result

    @pytest.mark.asyncio
    async def test_memory_map_500_sections_scaling(self, mock_mcp):
        """Test memory map with 500 sections (heavy stress test)."""
        sec_func = mock_mcp.get("reversecore://{filename}/memory_map")
        assert sec_func is not None

        sections_500 = [
            {
                "name": f".sec_{i:04d}",
                "virtual_address": f"0x{0x1000 + i * 0x1000:x}",
                "size": 4096,
                "entropy": 4.5 + (i % 40) * 0.1,  # some <= 7.0, some > 7.0
            }
            for i in range(500)
        ]

        expected_high_entropy = sum(1 for s in sections_500 if s["entropy"] > 7.0)

        mock_lief_res = ToolSuccess(
            data={"sections": sections_500},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/500_sec.bin",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await sec_func("500_sec.bin")
            assert "# 🗺️ Memory Map & Section Table: 500_sec.bin" in result
            assert "Total Sections**: 500" in result
            assert f"High Entropy Sections**: {expected_high_entropy}" in result
            assert ".sec_0000" in result
            assert ".sec_0499" in result
            # Verify table markdown structure is intact
            assert (
                "| Section Name | Virtual Address | Size | Entropy | Flags / Anomalies |" in result
            )

    @pytest.mark.asyncio
    async def test_memory_map_all_high_entropy_sections(self, mock_mcp):
        """Test binary where 100% of sections have entropy > 7.0 (fully packed/encrypted)."""
        sec_func = mock_mcp.get("reversecore://{filename}/memory_map")
        assert sec_func is not None

        packed_sections = [
            {
                "name": f".packed_{i}",
                "virtual_address": f"0x{0x2000 + i * 0x1000:x}",
                "size": 8192,
                "entropy": 7.1 + (i * 0.05),
            }
            for i in range(15)
        ]

        mock_lief_res = ToolSuccess(
            data={"sections": packed_sections},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/packed.exe",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await sec_func("packed.exe")
            assert "Total Sections**: 15" in result
            assert "High Entropy Sections**: 15" in result
            # Verify every row contains the warning badge
            assert result.count("⚠️ High Entropy (>7.0) - Likely Packed/Encrypted") == 15

    @pytest.mark.asyncio
    async def test_memory_map_anomalous_entropy_values(self, mock_mcp):
        """Test robustness against None, negative, zero, and out-of-range entropy values."""
        sec_func = mock_mcp.get("reversecore://{filename}/memory_map")
        assert sec_func is not None

        anomalous_sections = [
            {
                "name": ".none_entropy",
                "virtual_address": "0x1000",
                "size": 100,
                "entropy": None,
            },
            {
                "name": ".zero_entropy",
                "virtual_address": "0x2000",
                "size": 100,
                "entropy": 0.0,
            },
            {
                "name": ".negative_entropy",
                "virtual_address": "0x3000",
                "size": 100,
                "entropy": -0.5,
            },
            {
                "name": ".low_entropy",
                "virtual_address": "0x4000",
                "size": 100,
                "entropy": 0.8,
            },
        ]

        mock_lief_res = ToolSuccess(
            data={"sections": anomalous_sections},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/anomalous.bin",
            ),
            patch(
                "reversecore_mcp.tools.analysis.lief_tools.parse_binary_with_lief",
                return_value=mock_lief_res,
            ),
        ):
            result = await sec_func("anomalous.bin")
            assert "Total Sections**: 4" in result
            assert ".none_entropy" in result
            assert "N/A" in result  # For None entropy
            assert "ℹ️ Low Entropy (<1.0) - Sparse/Zeroed" in result

    @pytest.mark.asyncio
    async def test_memory_map_missing_binary(self, mock_mcp):
        """Test memory map handling when file is missing or inaccessible."""
        sec_func = mock_mcp.get("reversecore://{filename}/memory_map")
        assert sec_func is not None

        with patch(
            "reversecore_mcp.resources._get_workspace_path",
            side_effect=ValidationError("Path traversal detected"),
        ):
            result = await sec_func("../../../secret.bin")
            assert "Error reading memory map" in result or "Path traversal detected" in result


# ============================================================================
# 2. Cross-References (xrefs) Hub & Scaling Adversarial Tests
# ============================================================================


class TestFunctionXrefsAdversarial:
    """Stress testing xrefs endpoint against hub functions (5,000 xrefs), 0 xrefs, and malformed inputs."""

    @pytest.mark.asyncio
    async def test_hub_function_5000_xrefs_bounded(self, mock_mcp):
        """Verify hub function with 5,000 caller and 5,000 callee xrefs is bounded to top 30."""
        xrefs_func = mock_mcp.get("reversecore://{filename}/func/{address}/xrefs")
        assert xrefs_func is not None

        callers_5000 = [
            {
                "from": f"0x{0x400000 + i * 4:x}",
                "type": "call",
                "fcn_name": f"fcn_{i:05d}",
            }
            for i in range(5000)
        ]
        callees_5000 = [
            {
                "addr": f"0x{0x600000 + i * 4:x}",
                "type": "call",
                "name": f"lib_call_{i:05d}",
            }
            for i in range(5000)
        ]

        mock_r2_res = ToolSuccess(
            data={
                "xrefs_to": callers_5000,
                "xrefs_from": callees_5000,
                "total_refs_to": 5000,
                "total_refs_from": 5000,
            },
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/hub_sample.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
                return_value=mock_r2_res,
            ),
        ):
            result = await xrefs_func("hub_sample.exe", "0x401000")

            # 1. Total counts must accurately reflect 5,000
            assert "Callers: 5000" in result
            assert "Callees: 5000" in result

            # 2. Must contain truncation notice
            assert "Showing 30 of 5000 total callers" in result
            assert "Showing 30 of 5000 total callees" in result

            # 3. Table rows must be strictly bounded at 30 items per direction
            assert "fcn_00000" in result
            assert "fcn_00029" in result
            assert "fcn_00030" not in result  # 31st item must NOT leak
            assert "fcn_04999" not in result

            # 4. Token length check: bounded result must be compact (< 6,000 characters / ~1,500 tokens)
            assert len(result) < 6000, f"Result exceeded bounding length: {len(result)} chars"

    @pytest.mark.asyncio
    async def test_function_zero_xrefs(self, mock_mcp):
        """Verify isolated function with 0 callers and 0 callees renders clean fallback."""
        xrefs_func = mock_mcp.get("reversecore://{filename}/func/{address}/xrefs")
        assert xrefs_func is not None

        mock_r2_res = ToolSuccess(
            data={
                "xrefs_to": [],
                "xrefs_from": [],
                "total_refs_to": 0,
                "total_refs_from": 0,
            },
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.bin",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
                return_value=mock_r2_res,
            ),
        ):
            result = await xrefs_func("sample.bin", "0x500000")
            assert "Callers: 0" in result
            assert "Callees: 0" in result
            assert "No ingoing cross-references found." in result
            assert "No outgoing cross-references found." in result
            assert "Showing" not in result

    @pytest.mark.asyncio
    async def test_function_xrefs_malformed_and_injection_addresses(self, mock_mcp):
        """Test xrefs endpoint against malicious, malformed, and injection address strings."""
        xrefs_func = mock_mcp.get("reversecore://{filename}/func/{address}/xrefs")
        assert xrefs_func is not None

        malformed_addresses = [
            "",  # empty
            "0x",  # incomplete
            "0xZZZZZZZZ",  # invalid hex
            "-1",  # negative integer
            "-0x401000",  # negative hex
            "0x" + "F" * 10000,  # massive buffer
            "'; DROP TABLE xrefs; --",  # SQL injection
            "main; cat /etc/passwd",  # command injection
            "$(whoami)",  # command substitution
            "`id`",  # backtick injection
            "<script>alert('xss')</script>",  # HTML injection
            "\x00\x01\x02\x03",  # raw binary bytes
            "None",  # string None
            "undefined",  # string undefined
            "0x401000\n0x402000",  # newline injection
        ]

        for malformed in malformed_addresses:
            mock_r2_res = ToolError(
                error_code="RCMCP-E002",
                message=f"Invalid address: {malformed}",
            )

            with (
                patch(
                    "reversecore_mcp.resources._get_workspace_path",
                    return_value="/workspace/sample.exe",
                ),
                patch(
                    "reversecore_mcp.tools.radare2.r2_analysis.analyze_xrefs",
                    return_value=mock_r2_res,
                ),
            ):
                result = await xrefs_func("sample.exe", malformed)
                assert isinstance(result, str)
                assert "Error" in result or "Invalid" in result


# ============================================================================
# 3. Function Context & Recovered Structures Adversarial Tests
# ============================================================================


class TestFunctionContextAdversarial:
    """Stress testing function context endpoint against zero values, massive structs, and errors."""

    @pytest.mark.asyncio
    async def test_function_context_zero_and_missing_values(self, mock_mcp):
        """Test function context when analysis returns 0 size, complexity, and 0 structures."""
        ctx_func = mock_mcp.get("reversecore://{filename}/func/{address}/context")
        assert ctx_func is not None

        mock_fn_res = ToolSuccess(
            data={
                "name": "orphan_stub",
                "offset": "0x401000",
                "size": 0,
                "complexity": 0,
                "nbbs": 0,
                "edges": 0,
                "signature": "void orphan_stub()",
                "calltype": "cdecl",
            },
        )
        mock_struct_res = ToolSuccess(
            data={"structures": []},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.resources.r2_analyze_function",
                return_value=mock_fn_res,
            ),
            patch(
                "reversecore_mcp.resources.r2_recover_structures",
                return_value=mock_struct_res,
            ),
        ):
            result = await ctx_func("sample.exe", "0x401000")
            assert "# 🧩 Function Context: sample.exe @ 0x401000" in result
            assert "Cyclomatic Complexity**: 0" in result
            assert "Basic Blocks (nbbs)**: 0" in result
            assert "No local variables or structures recovered." in result

    @pytest.mark.asyncio
    async def test_function_context_massive_structures(self, mock_mcp):
        """Test function context with 500 recovered stack structures/variables."""
        ctx_func = mock_mcp.get("reversecore://{filename}/func/{address}/context")
        assert ctx_func is not None

        structures_500 = [
            {
                "name": f"var_{i}",
                "type": "uint64_t" if i % 2 == 0 else "char[32]",
                "offset": f"-0x{(i + 1) * 8:x}",
                "size": 8 if i % 2 == 0 else 32,
            }
            for i in range(500)
        ]

        mock_fn_res = ToolSuccess(
            data={
                "name": "huge_frame_function",
                "offset": "0x402000",
                "size": 8192,
                "complexity": 25,
                "nbbs": 30,
                "edges": 45,
                "signature": "int huge_frame_function(void)",
                "calltype": "cdecl",
            },
        )
        mock_struct_res = ToolSuccess(
            data={"structures": structures_500},
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.resources.r2_analyze_function",
                return_value=mock_fn_res,
            ),
            patch(
                "reversecore_mcp.resources.r2_recover_structures",
                return_value=mock_struct_res,
            ),
        ):
            result = await ctx_func("sample.exe", "0x402000")
            assert "Local Variables & Recovered Structures (500)" in result
            assert "var_0" in result
            assert "var_499" in result

    @pytest.mark.asyncio
    async def test_function_context_malformed_address(self, mock_mcp):
        """Test function context error handling on invalid function address."""
        ctx_func = mock_mcp.get("reversecore://{filename}/func/{address}/context")
        assert ctx_func is not None

        mock_fn_res = ToolError(
            error_code="RCMCP-E002",
            message="No function found at 0xdeadbeef",
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/sample.exe",
            ),
            patch(
                "reversecore_mcp.resources.r2_analyze_function",
                return_value=mock_fn_res,
            ),
        ):
            result = await ctx_func("sample.exe", "0xdeadbeef")
            assert "Error analyzing function 0xdeadbeef" in result


# ============================================================================
# 4. Imports & Exports Scaling and Sensitive API Tagging Tests
# ============================================================================


class TestImportsExportsScaling:
    """Adversarial testing of imports and exports bounding limits and API sensitivity classification."""

    @pytest.mark.asyncio
    async def test_imports_5000_items_bounded_at_100(self, mock_mcp):
        """Verify 5,000 imported functions are bounded at max 100 with truncation note."""
        imports_func = mock_mcp.get("reversecore://{filename}/imports")
        assert imports_func is not None

        # 5,000 imports across 50 DLLs
        imports_5000 = [
            {"libname": f"lib_{i % 50}.dll", "name": f"Function_{i:05d}"} for i in range(5000)
        ]

        mock_r2_res = ToolSuccess(
            data=str(imports_5000).replace("'", '"'),
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/large_imports.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await imports_func("large_imports.exe")

            assert "Total Imports**: 5000" in result
            assert "Truncated: showing 100 of 5000 total imports" in result
            # Token size verification: bounded string must be under 10KB
            assert len(result) < 10000

    @pytest.mark.asyncio
    async def test_imports_sensitive_api_classification_exhaustive(self, mock_mcp):
        """Verify sensitive API tagging detects Process Injection, Dynamic Loading, Crypto, Anti-Debug, C2."""
        imports_func = mock_mcp.get("reversecore://{filename}/imports")
        assert imports_func is not None

        sensitive_imports = [
            {"libname": "kernel32.dll", "name": "VirtualAllocEx"},
            {"libname": "kernel32.dll", "name": "WriteProcessMemory"},
            {"libname": "kernel32.dll", "name": "CreateRemoteThread"},
            {"libname": "kernel32.dll", "name": "LoadLibraryA"},
            {"libname": "kernel32.dll", "name": "GetProcAddress"},
            {"libname": "advapi32.dll", "name": "CryptEncrypt"},
            {"libname": "kernel32.dll", "name": "IsDebuggerPresent"},
            {"libname": "kernel32.dll", "name": "CheckRemoteDebuggerPresent"},
            {"libname": "ws2_32.dll", "name": "connect"},
            {"libname": "wininet.dll", "name": "InternetConnectA"},
            {"libname": "kernel32.dll", "name": "WinExec"},
            {"libname": "libc.so.6", "name": "ptrace"},
            {"libname": "libc.so.6", "name": "dlopen"},
            {"libname": "libc.so.6", "name": "system"},
        ]

        mock_r2_res = ToolSuccess(
            data=str(sensitive_imports).replace("'", '"'),
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/malware_apis.exe",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await imports_func("malware_apis.exe")
            assert "Total Imports**: 14" in result
            assert "Sensitive / High-Risk APIs**: 14" in result
            assert "[!] Process Injection" in result
            assert "[!] Dynamic Loading" in result
            assert "[!] File Encryption" in result
            assert "[!] Anti-Debugging" in result
            assert "[!] Network/C2" in result
            assert "[!] Process Execution" in result

    @pytest.mark.asyncio
    async def test_exports_5000_items_bounded_at_50(self, mock_mcp):
        """Verify 5,000 exported symbols are bounded at max 50 with truncation note."""
        exports_func = mock_mcp.get("reversecore://{filename}/exports")
        assert exports_func is not None

        exports_5000 = [
            {
                "ordinal": i + 1,
                "vaddr": f"0x{0x1000 + i * 16:x}",
                "name": f"Export_{i:05d}",
            }
            for i in range(5000)
        ]

        mock_r2_res = ToolSuccess(
            data=str(exports_5000).replace("'", '"'),
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/massive_exports.dll",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await exports_func("massive_exports.dll")
            assert "Total Exports**: 5000" in result
            assert "Showing 50 of 5000 total exports" in result
            assert "Export_00000" in result
            assert "Export_00049" in result
            assert "Export_00050" not in result
            assert len(result) < 5000

    @pytest.mark.asyncio
    async def test_functions_list_5000_items_bounded_at_50(self, mock_mcp):
        """Verify function listing with 5,000 functions is bounded at 50."""
        func_list = mock_mcp.get("reversecore://{filename}/functions")
        assert func_list is not None

        funcs_5000 = [
            {"name": f"sub_{i:05d}", "offset": 0x401000 + i * 32, "size": 32} for i in range(5000)
        ]

        mock_r2_res = ToolSuccess(
            data=str(funcs_5000).replace("'", '"'),
        )

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/massive_funcs.bin",
            ),
            patch(
                "reversecore_mcp.tools.radare2.r2_analysis.run_radare2",
                return_value=mock_r2_res,
            ),
        ):
            result = await func_list("massive_funcs.bin")
            assert "Total functions: 5000" in result
            assert "Showing: 50" in result
            assert "sub_00000" in result
            assert "sub_00049" in result
            assert "sub_00050" not in result


# ============================================================================
# 5. Threat Signatures & Dormant Detector Adversarial Tests
# ============================================================================


class TestThreatSignaturesAndDormantAdversarial:
    """Stress testing signatures and dormant detector against empty, massive, and failing subsystems."""

    @pytest.mark.asyncio
    async def test_signatures_report_all_empty(self, mock_mcp):
        """Test threat signatures report when all tools return empty results."""
        sig_func = mock_mcp.get("reversecore://{filename}/signatures")
        assert sig_func is not None

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/clean.exe",
            ),
            patch(
                "reversecore_mcp.tools.malware.yara_tools.run_yara",
                return_value=ToolSuccess(data={"matches": []}),
            ),
            patch(
                "reversecore_mcp.tools.analysis.capa_tools.run_capa",
                return_value=ToolSuccess(data={"capabilities": [], "mitre_attack": []}),
            ),
            patch(
                "reversecore_mcp.tools.malware.dormant_detector.dormant_detector",
                return_value=ToolSuccess(data={"orphan_functions": [], "suspicious_logic": []}),
            ),
        ):
            result = await sig_func("clean.exe")
            assert "No YARA signatures matched." in result
            assert "No CAPA capabilities detected or CAPA unavailable." in result
            assert "No MITRE ATT&CK techniques mapped." in result
            assert "No dormant anomalies detected." in result

    @pytest.mark.asyncio
    async def test_signatures_report_subsystem_failures_graceful_fallback(self, mock_mcp):
        """Verify signatures report survives when YARA, CAPA, and Dormant Detector throw exceptions."""
        sig_func = mock_mcp.get("reversecore://{filename}/signatures")
        assert sig_func is not None

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/clean.exe",
            ),
            patch(
                "reversecore_mcp.tools.malware.yara_tools.run_yara",
                side_effect=RuntimeError("YARA engine crashed"),
            ),
            patch(
                "reversecore_mcp.tools.analysis.capa_tools.run_capa",
                side_effect=FileNotFoundError("capa binary missing"),
            ),
            patch(
                "reversecore_mcp.tools.malware.dormant_detector.dormant_detector",
                side_effect=TimeoutError("Radare2 timeout"),
            ),
        ):
            # Must NOT raise exception; must gracefully output fallback sections
            result = await sig_func("clean.exe")
            assert "# 🛡️ Threat Signatures & Capabilities: clean.exe" in result
            assert "No YARA signatures matched." in result
            assert "No CAPA capabilities detected or CAPA unavailable." in result
            assert "No dormant anomalies detected." in result

    @pytest.mark.asyncio
    async def test_signatures_capa_500_items_bounded(self, mock_mcp):
        """Verify 500 CAPA capabilities and MITRE techniques are bounded at top 20 each."""
        sig_func = mock_mcp.get("reversecore://{filename}/signatures")
        assert sig_func is not None

        capa_500 = [f"capability_{i:04d}" for i in range(500)]
        mitre_500 = [f"T100{i % 100} Technique {i}" for i in range(500)]

        with (
            patch(
                "reversecore_mcp.resources._get_workspace_path",
                return_value="/workspace/complex_malware.exe",
            ),
            patch(
                "reversecore_mcp.tools.malware.yara_tools.run_yara",
                return_value=ToolSuccess(data={"matches": []}),
            ),
            patch(
                "reversecore_mcp.tools.analysis.capa_tools.run_capa",
                return_value=ToolSuccess(
                    data={"capabilities": capa_500, "mitre_attack": mitre_500}
                ),
            ),
            patch(
                "reversecore_mcp.tools.malware.dormant_detector.dormant_detector",
                return_value=ToolSuccess(data={"orphan_functions": [], "suspicious_logic": []}),
            ),
        ):
            result = await sig_func("complex_malware.exe")
            assert "capability_0000" in result
            assert "capability_0019" in result
            assert "capability_0020" not in result  # Bounded at 20


# ============================================================================
# 6. FastMCP Server Wire-Level Resource Dispatcher Verification
# ============================================================================


class TestFastMCPWireLevelResourceDispatch:
    """Verify live FastMCP server instance resource resolution across all registered URIs."""

    @pytest.mark.asyncio
    async def test_all_dynamic_and_static_uris_registered_on_server_mcp(self):
        """Verify all Milestone 2 resource URI templates are present on the server MCP instance."""
        # Read static resources from mcp._resource_manager
        static_keys = set(mcp._resource_manager._resources.keys())
        expected_statics = {
            "reversecore://guide",
            "reversecore://guide/structures",
            "reversecore://tools",
            "reversecore://logs",
        }
        for expected in expected_statics:
            assert expected in static_keys, f"Static resource {expected} missing from server.mcp"

        # Read template URIs from mcp._resource_manager
        template_uris = {t.uri_template for t in mcp._resource_manager._templates.values()}
        expected_templates = {
            "reversecore://{filename}/metadata",
            "reversecore://{filename}/info",
            "reversecore://{filename}/func/{address}/xrefs",
            "reversecore://{filename}/func/{address}/context",
            "reversecore://{filename}/memory_map",
            "reversecore://{filename}/sections",
            "reversecore://{filename}/signatures",
            "reversecore://{filename}/imports",
            "reversecore://{filename}/exports",
            "reversecore://{filename}/strings",
            "reversecore://{filename}/iocs",
            "reversecore://{filename}/func/{address}/code",
            "reversecore://{filename}/func/{address}/asm",
            "reversecore://{filename}/func/{address}/cfg",
            "reversecore://{filename}/functions",
            "reversecore://{filename}/dormant_detector",
        }

        for expected_temp in expected_templates:
            assert expected_temp in template_uris, (
                f"Resource template {expected_temp} missing from server.mcp"
            )

    @pytest.mark.asyncio
    async def test_server_read_resource_token_and_error_bounds(self):
        """Verify wire-level read_resource calls return bounded strings without unhandled exceptions."""
        test_uris = [
            "reversecore://guide",
            "reversecore://guide/structures",
            "reversecore://tools",
            "reversecore://logs",
            "reversecore://nonexistent_binary.exe/metadata",
            "reversecore://nonexistent_binary.exe/memory_map",
            "reversecore://nonexistent_binary.exe/signatures",
            "reversecore://nonexistent_binary.exe/imports",
            "reversecore://nonexistent_binary.exe/exports",
            "reversecore://nonexistent_binary.exe/func/0x401000/xrefs",
            "reversecore://nonexistent_binary.exe/func/0x401000/context",
        ]

        for uri in test_uris:
            res = await mcp._resource_manager.read_resource(uri)
            assert res is not None
            res_content = str(res)
            # Token estimate: approx 4 chars per token -> must not exceed 25,000 tokens (100k chars)
            estimated_tokens = len(res_content) / 4.0
            assert estimated_tokens < 25000, (
                f"URI {uri} exceeded token limit: {estimated_tokens} tokens"
            )
