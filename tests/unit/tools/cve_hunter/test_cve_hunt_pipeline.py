"""Unit tests for Unified One-Click CVE Hunting Pipeline."""

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from reversecore_mcp.core.result import failure, success
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
        f.parent.mkdir(parents=True, exist_ok=True)
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
        assert "**Automated CVSS v3.1 estimate:** 8.8 (HIGH)" in md
        assert "parse_image_header" in md
        assert "Python Reproducer" in md
        assert "Standalone C Harness" in md

    def test_generate_cve_advisory_does_not_fill_missing_finding_fields(self):
        md = generate_cve_advisory_markdown(
            target_name="unknown.bin",
            triage={},
            poc_script=None,
            c_harness=None,
        )

        assert "Unknown CWE" in md
        assert "Not calculated" in md
        assert "CWE-119" not in md
        assert "CVSS:3.1/AV:N" not in md

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
        crash_input = workspace_file("pipeline-crashes/crash-input", content=b"REAL_CRASH_INPUT")

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
                "execution_status": "crash_detected",
                "crash_artifacts": [str(crash_input)],
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
                        "evidence_source": "hybrid_fuzzer",
                        "crash_log_sha256": "a" * 64,
                        "crash_input_path": str(crash_input),
                        "crash_input_sha256": hashlib.sha256(b"REAL_CRASH_INPUT").hexdigest(),
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
        assert data["finding_status"] == "found"
        assert data["cwe_id"] == "CWE-122"
        assert data["cvss_v31_score"] == 8.8
        assert "cve_security_advisory_markdown" in data
        assert "standalone_python_poc" in data
        assert (
            data["triaged_crashes"][0]["crash_input_sha256"]
            == hashlib.sha256(b"REAL_CRASH_INPUT").hexdigest()
        )
        assert "REAL_CRASH_INPUT" not in data["standalone_python_poc"]
        assert "5245414c5f43524153485f494e505554" in data["standalone_python_poc"]

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_omits_truncated_c_harness(self, workspace_file):
        target_h = workspace_file("large_crash_target.h")
        payload = b"LARGE_CRASH_INPUT" * 40
        crash_input = workspace_file("large-crash/crash", content=payload)
        fuzz_res = success(
            {
                "execution_status": "crash_detected",
                "crashes_detected": 1,
                "crash_artifacts": [str(crash_input)],
                "triaged_crashes": [
                    {
                        "bug_type": "heap-buffer-overflow",
                        "cwe_id": "CWE-122",
                        "cwe_name": "Heap-based Buffer Overflow",
                        "cvss": {"cvss_v31_score": 8.8, "severity": "HIGH"},
                        "evidence_source": "hybrid_fuzzer",
                        "crash_log_sha256": "b" * 64,
                        "crash_input_path": str(crash_input),
                        "crash_input_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            }
        )

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=success({}),
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=fuzz_res,
            ),
        ):
            res = await hunt_cve_pipeline_impl(target_path_str=str(target_h))

        assert res.status == "success"
        assert res.data["standalone_python_poc"] is not None
        assert res.data["standalone_c_poc"] is None
        assert payload.hex() in res.data["standalone_python_poc"]
        assert "C harness was omitted" in res.data["cve_security_advisory_markdown"]

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_rejects_changed_crash_input(self, workspace_file):
        target_h = workspace_file("changed_input_target.h")
        crash_input = workspace_file("changed-input/crash", content=b"TAMPERED_INPUT")
        harness_res = success({})
        fuzz_res = success(
            {
                "execution_status": "crash_detected",
                "crashes_detected": 1,
                "crash_artifacts": [str(crash_input)],
                "triaged_crashes": [
                    {
                        "bug_type": "heap-buffer-overflow",
                        "cwe_id": "CWE-122",
                        "cwe_name": "Heap-based Buffer Overflow",
                        "cvss": {"cvss_v31_score": 8.8, "severity": "HIGH"},
                        "evidence_source": "hybrid_fuzzer",
                        "crash_log_sha256": "a" * 64,
                        "crash_input_path": str(crash_input),
                        "crash_input_sha256": hashlib.sha256(b"ORIGINAL_INPUT").hexdigest(),
                    }
                ],
            }
        )

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=harness_res,
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=fuzz_res,
            ),
        ):
            res = await hunt_cve_pipeline_impl(target_path_str=str(target_h))

        assert res.status == "error"
        assert res.error_code == "CRASH_EVIDENCE_INCOMPLETE"

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_clean_run_returns_no_finding(self, workspace_file):
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
                "execution_status": "completed",
                "crash_artifacts": [],
                "triaged_crashes": [],
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
            res = await hunt_cve_pipeline_impl(target_path_str=str(target_h))

        assert res.status == "success"
        assert res.data["finding_status"] == "none"
        assert res.data["cwe_id"] is None
        assert res.data["cvss_v31_score"] is None
        assert res.data["triaged_crashes"] == []
        assert res.data["standalone_python_poc"] is None
        assert res.data["cve_security_advisory_markdown"] is None
        assert "no sanitizer crash observed" in res.data["summary"]

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_external_log_is_marked_and_has_no_fake_poc(
        self, workspace_file
    ):
        target_h = workspace_file(
            "external_log_target.h",
            content=b"int parse_stream(const uint8_t *data, size_t size);",
        )
        harness_res = success({"selected_target_function": "parse_stream"})
        fuzz_res = failure("FUZZING_FAILED", "fuzzer binary was unavailable")
        custom_asan_log = """
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 8 at 0x602000000010
    #0 0x401000 in parse_stream parser.c:10
"""

        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=harness_res,
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=fuzz_res,
            ),
        ):
            res = await hunt_cve_pipeline_impl(
                target_path_str=str(target_h),
                options={"crash_log": custom_asan_log},
            )

        assert res.status == "success"
        assert res.data["finding_status"] == "found"
        assert res.data["analysis_status"] == "partial"
        assert res.data["execution_status"] == "failed"
        assert res.data["cwe_id"] == "CWE-416"
        assert res.data["triaged_crashes"][0]["evidence_source"] == "external_crash_log"
        assert res.data["triaged_crashes"][0]["crash_input_path"] is None
        assert res.data["standalone_python_poc"] is None
        assert res.data["standalone_c_poc"] is None
        assert "No PoC was generated" in res.data["cve_security_advisory_markdown"]
        assert "externally supplied sanitizer log" in res.data["summary"]

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_rejects_invalid_external_log(self, workspace_file):
        target_h = workspace_file("invalid_external_log_target.h")
        harness_res = success({})
        fuzz_res = success(
            {
                "execution_status": "completed",
                "total_executions": 1,
                "crashes_detected": 0,
                "crash_artifacts": [],
                "triaged_crashes": [],
            }
        )
        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=harness_res,
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=fuzz_res,
            ),
        ):
            res = await hunt_cve_pipeline_impl(
                target_path_str=str(target_h),
                options={"crash_log": "ERROR: disk failure"},
            )

        assert res.status == "error"
        assert res.error_code == "INVALID_CRASH_LOG"

    @pytest.mark.asyncio
    async def test_hunt_cve_pipeline_propagates_fuzz_failure_without_external_log(
        self, workspace_file
    ):
        target_h = workspace_file("fuzz_failure_target.h")
        with (
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.synthesize_fuzz_harness_impl",
                new_callable=AsyncMock,
                return_value=success({}),
            ),
            patch(
                "reversecore_mcp.tools.cve_hunter.cve_hunt_pipeline.run_hybrid_fuzz_impl",
                new_callable=AsyncMock,
                return_value=failure("FUZZING_FAILED", "fuzzer binary was unavailable"),
            ),
        ):
            res = await hunt_cve_pipeline_impl(target_path_str=str(target_h))

        assert res.status == "error"
        assert res.error_code == "FUZZING_INCOMPLETE"
