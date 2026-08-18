"""Unit tests for Unified One-Click CVE Hunting Pipeline."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import success
from reversecore_mcp.core.security import get_workspace_config
from reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline import (
    generate_cve_advisory_markdown,
    hunt_cve_pipeline_impl,
)
from reversecore_mcp.tools.cve_hunter.cve_hunter_tools import hunt_cve_vulnerabilities


@pytest.fixture
def workspace_file():
    ws = get_workspace_config().workspace

    def _create(filename: str, content: bytes = b"\x90" * 100) -> Path:
        f = ws / filename
        f.write_bytes(content)
        return f

    return _create


@pytest.mark.unit
class TestCveHuntPipeline:
    """Tests for end-to-end CVE discovery pipeline and advisory report generation."""

    def test_generate_cve_advisory_markdown(self):
        triage_mock = {
            "bug_type": "heap-buffer-overflow",
            "cwe_id": "CWE-122",
            "cwe_name": "Heap-based Buffer Overflow",
            "access_type": "WRITE",
            "access_size": 4,
            "faulting_function": "parse_image_header",
            "faulting_source_location": "src/image.c:50",
            "cvss": {
                "cvss_v31_score": 8.8,
                "severity": "HIGH",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            },
            "crash_callstack": [
                {
                    "frame": 0,
                    "address": "0x401000",
                    "symbol": "parse_image_header",
                    "source_file": "src/image.c",
                    "line": 50,
                },
            ],
            "exploitability_assessment": "Arbitrary heap memory write leading to RCE",
        }
        md = generate_cve_advisory_markdown(
            target_name="libimage.so",
            triage=triage_mock,
            poc_script="#!/usr/bin/env python3\nprint('poc')",
            c_harness="int main() { return 0; }",
        )
        assert "Security Advisory: Heap-based Buffer Overflow in `libimage.so` (CWE-122)" in md
        assert "**CVSS v3.1 Base Score:** 8.8 (HIGH)" in md
        assert "parse_image_header" in md
        assert "Python Reproducer" in md
        assert "Standalone C Harness" in md

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_invalid_path(self):
        res = await hunt_cve_pipeline_impl("/non/existent/target.h")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_via_tool_wrapper(self):
        res = await hunt_cve_vulnerabilities("/non/existent/target.h")
        assert res.status == "error"

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_success(self, workspace_file):
        target_h = workspace_file(
            "test_target.h",
            content=b"int parse_archive(const uint8_t *data, size_t size);",
        )
        sample_bin = workspace_file("sample.bin", content=b"PK\x03\x04testpayload")

        mock_harness_res = success(
            {
                "selected_target_function": "parse_archive",
                "candidate_functions": [{"function_name": "parse_archive"}],
                "harness_source_code": "int LLVMFuzzerTestOneInput() { return 0; }",
                "dictionary_token_count": 5,
            }
        )

        mock_fuzz_res = success(
            {
                "total_executions": 25000,
                "crashes_detected": 1,
                "triaged_crashes": [
                    {
                        "bug_type": "heap-buffer-overflow",
                        "cwe_id": "CWE-122",
                        "cwe_name": "Heap-based Buffer Overflow",
                        "faulting_function": "parse_archive",
                        "faulting_source_location": "archive.c:42",
                        "cvss": {
                            "cvss_v31_score": 8.8,
                            "severity": "HIGH",
                            "cvss_vector": "CVSS:3.1/...",
                        },
                        "crash_callstack": [],
                    }
                ],
            }
        )

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=mock_harness_res,
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=mock_fuzz_res,
            ),
        ):
            res = await hunt_cve_pipeline_impl(
                target_path_str=str(target_h),
                sample_file_path=str(sample_bin),
                options={"fuzz_duration": 5, "enable_angr": True},
            )

        assert res.status == "success"
        data = res.data
        assert data is not None
        assert data["cwe_id"] == "CWE-122"
        assert data["cvss_v31_score"] == 8.8
        assert "cve_security_advisory_markdown" in data
        assert "standalone_python_poc" in data

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_with_custom_crash_log_and_fallback(self, workspace_file):
        target_h = workspace_file(
            "test_target2.h",
            content=b"int parse_stream(const uint8_t *data, size_t size);",
        )

        mock_harness_res = success(
            {
                "selected_target_function": "parse_stream",
                "candidate_functions": [],
                "harness_source_code": "int LLVMFuzzerTestOneInput() { return 0; }",
                "dictionary_token_count": 0,
            }
        )
        mock_fuzz_res = success(
            {
                "total_executions": 100,
                "crashes_detected": 0,
                "triaged_crashes": [],
            }
        )

        custom_asan_log = """
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 8 at 0x602000000010
    #0 0x401000 in parse_stream parser.c:10
"""

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=mock_harness_res,
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=mock_fuzz_res,
            ),
        ):
            res_custom = await hunt_cve_pipeline_impl(
                target_path_str=str(target_h),
                options={"crash_log": custom_asan_log},
            )
            assert res_custom.status == "success"
            assert res_custom.data["cwe_id"] == "CWE-416"

            res_fallback = await hunt_cve_pipeline_impl(
                target_path_str=str(target_h),
            )
            assert res_fallback.status == "success"
            assert res_fallback.data["cwe_id"] == "CWE-122"
