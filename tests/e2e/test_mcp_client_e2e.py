"""Real MCP Client End-to-End (E2E) Integration Tests.

Exercises full toolchains over real MCP stdio subprocess sessions:
- Scenario 1: ELF Happy Path (static profile)
- Scenario 5: Crash Complex Path (vuln-research profile)

Validates profile exposure, schema serialization, cross-tool chaining,
semantic contracts, and error propagation.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).parent.parent.parent.resolve()
FIXTURES_DIR = ROOT / "tests" / "fixtures"


@asynccontextmanager
async def spawn_mcp_session(
    profile: str,
    workspace_dir: Path,
) -> AsyncGenerator[ClientSession, None]:
    """Spawn an isolated Reversecore MCP server subprocess and connect via stdio ClientSession.

    Args:
        profile: Profile name ('static', 'vuln-research', etc.).
        workspace_dir: Isolated directory to serve as REVERSECORE_WORKSPACE.

    Yields:
        Initialized mcp.ClientSession ready for tool calls.
    """
    env = os.environ.copy()
    env["MCP_TRANSPORT"] = "stdio"
    env["REVERSECORE_TRANSPORT"] = "stdio"
    env.pop("PORT", None)
    env.pop("MCP_PORT", None)
    env["REVERSECORE_PROFILE"] = profile
    env["REVERSECORE_WORKSPACE"] = str(workspace_dir)
    env["REVERSECORE_REDIS_URL"] = "disabled"
    env["MEMORY_DB_PATH"] = str(workspace_dir / ".memory.db")
    env["R2GHIDRA_DB_PATH"] = str(workspace_dir / ".r2db")
    env["PYTHONPATH"] = str(ROOT)

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "reversecore_mcp.server"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def call_tool_json(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
) -> tuple[dict[str, Any], float]:
    """Execute an MCP tool call and return parsed JSON data alongside execution latency.

    Args:
        session: Active MCP ClientSession.
        tool_name: Name of registered MCP tool.
        arguments: Key-value parameters matching tool schema.

    Returns:
        Tuple of (parsed response dict, latency in seconds).
    """
    t0 = time.perf_counter()
    result = await session.call_tool(tool_name, arguments)
    latency = time.perf_counter() - t0

    assert not result.isError, f"Tool '{tool_name}' returned error: {result}"
    assert len(result.content) > 0, f"Tool '{tool_name}' returned empty content list"

    first_block = result.content[0]
    raw_text = getattr(first_block, "text", str(first_block))
    try:
        data = json.loads(raw_text)
    except Exception:
        data = {"status": "success", "raw_text": raw_text}

    return data, latency


@pytest.mark.e2e
@pytest.mark.asyncio
class TestMcpClientE2EWorkflows:
    """E2E test suite running analysis pipelines through actual MCP stdio sessions."""

    async def test_scenario_1_elf_happy_path(self):
        """Scenario 1: ELF Happy Path in static profile.

        Verifies:
        1. static profile tool exposure (97 tools, no malware-only tools).
        2. Binary identification via run_file (ELF/x86-64).
        3. Function enumeration via Radare2_list_functions (main function discovered).
        4. Decompilation via r2_decompile (non-empty pseudo-C).
        5. Report session lifecycle: start -> add_note -> create_analysis_report.
        6. Workspace containment: report file created strictly inside workspace.
        7. Step latency diagnostics tracking.
        """
        diagnostics: dict[str, float] = {}

        with tempfile.TemporaryDirectory() as temp_ws:
            ws_path = Path(temp_ws).resolve()

            # Copy deterministic test ELF into workspace
            fixture_elf = FIXTURES_DIR / "binaries" / "hello_elf_x64"
            assert fixture_elf.exists(), f"Missing fixture ELF at {fixture_elf}"
            target_elf = ws_path / "hello_elf_x64"
            shutil.copy2(fixture_elf, target_elf)
            target_elf.chmod(0o755)

            async with spawn_mcp_session("static", ws_path) as session:
                # -------------------------------------------------------------
                # 1. Profile Exposure Check
                # -------------------------------------------------------------
                tools_res = await session.list_tools()
                exposed_tools = {t.name for t in tools_res.tools}

                # Contract: Exactly 97 tools for static profile
                assert len(exposed_tools) == 97, f"Expected 97 tools, got {len(exposed_tools)}"
                # Static analysis tools must be present
                assert "run_file" in exposed_tools
                assert "parse_binary_with_lief" in exposed_tools
                assert "Radare2_list_functions" in exposed_tools
                assert "r2_decompile" in exposed_tools
                assert "create_analysis_report" in exposed_tools
                # Malware-only tools must NOT be present
                assert "generate_vaccine" not in exposed_tools
                assert "detect_anti_analysis" not in exposed_tools
                assert "analyze_heap_exploit" not in exposed_tools

                # -------------------------------------------------------------
                # 2. Step 1: File Identification & Parsing
                # -------------------------------------------------------------
                ident_data, d_time = await call_tool_json(
                    session,
                    "run_file",
                    {"file_path": str(target_elf)},
                )
                diagnostics["step1_run_file_seconds"] = d_time
                assert ident_data.get("status") == "success"
                file_info = ident_data.get("data", {}).get("file_type", "")
                assert "ELF" in file_info, f"Binary not recognized as ELF: {file_info}"
                assert "x86-64" in file_info or "x86_64" in file_info

                # -------------------------------------------------------------
                # 3. Step 2: Function Enumeration via Radare2
                # -------------------------------------------------------------
                fn_data, d_time = await call_tool_json(
                    session,
                    "Radare2_list_functions",
                    {"file_path": str(target_elf)},
                )
                diagnostics["step2_list_functions_seconds"] = d_time
                assert fn_data.get("status") == "success"
                functions_output = fn_data.get("functions", "")
                assert "main" in functions_output, (
                    f"'main' not found in functions: {functions_output}"
                )

                # -------------------------------------------------------------
                # 4. Step 3: Decompilation of main function
                # -------------------------------------------------------------
                decomp_data, d_time = await call_tool_json(
                    session,
                    "r2_decompile",
                    {"file_path": str(target_elf), "function_address": "main"},
                )
                diagnostics["step3_r2_decompile_seconds"] = d_time
                assert decomp_data.get("status") == "success"
                pseudo_c = decomp_data.get("data", {}).get("pseudo_c", "")
                assert len(pseudo_c) > 0, "Decompiled pseudo_c output is empty"
                assert "main" in pseudo_c

                # -------------------------------------------------------------
                # 5. Step 4: Report Session Creation & Verification
                # -------------------------------------------------------------
                start_sess, d_time = await call_tool_json(
                    session,
                    "start_report_session",
                    {"sample_path": str(target_elf)},
                )
                diagnostics["step4_start_session_seconds"] = d_time
                session_id = start_sess.get("session_id")
                assert session_id, "start_report_session did not return a session_id"

                # Record analysis evidence
                _, d_time = await call_tool_json(
                    session,
                    "add_analysis_note",
                    {
                        "session_id": session_id,
                        "note": "Discovered main function with write syscall referencing Hello World string",
                        "category": "decompilation",
                    },
                )
                diagnostics["step4_add_note_seconds"] = d_time

                # Generate comprehensive analysis report
                report_res, d_time = await call_tool_json(
                    session,
                    "create_analysis_report",
                    {
                        "session_id": session_id,
                        "sample_path": str(target_elf),
                        "template_type": "full_analysis",
                    },
                )
                diagnostics["step4_create_report_seconds"] = d_time
                assert report_res.get("success") is True, f"Report generation failed: {report_res}"
                report_text = report_res.get("report_content", "")
                assert (
                    "6ad7a95ce4f1c9d0528372c1a8e1aaa9f4b5e38da84073cce0bf35a175d6f0d2"
                    in report_text
                )
                assert "hello_elf_x64" in report_text

                # -------------------------------------------------------------
                # 6. Workspace Containment Check
                # -------------------------------------------------------------
                report_path_str = report_res.get("path", "")
                report_file = Path(report_path_str)
                if not report_file.is_absolute():
                    report_file = ws_path / report_path_str
                assert report_file.exists(), f"Report file not found: {report_file}"
                assert report_file.resolve().is_relative_to(ws_path), (
                    f"Report was created outside workspace: {report_file} (workspace: {ws_path})"
                )

        # Print latency diagnostics for performance profiling
        print("\n[Scenario 1 Latency Diagnostics]")
        for step, duration in diagnostics.items():
            print(f"  {step}: {duration:.3f}s")

    async def test_scenario_2_pe_malware_triage(self):
        """Scenario 2: PE Malware Triage in malware profile.

        Verifies:
        1. malware profile tool exposure (65 tools, no static/forensics-only tools).
        2. Binary identification & metadata via run_file.
        3. Indicator of Compromise (IoC) extraction: IPv4, URL, Bitcoin, CVE, Registry.
        4. YARA signature matching using custom rules.
        5. Anti-evasion detection (detect_anti_analysis): VM/debugger indicators, MITRE ATT&CK mapping.
        6. Defensive strategy generation via adaptive_vaccine.
        7. Step latency diagnostics tracking.
        """
        diagnostics: dict[str, float] = {}

        with tempfile.TemporaryDirectory() as temp_ws:
            ws_path = Path(temp_ws).resolve()

            # Copy deterministic test malware payload into workspace
            fixture_payload = FIXTURES_DIR / "binaries" / "sample_malware.bin"
            assert fixture_payload.exists(), f"Missing fixture payload at {fixture_payload}"
            target_bin = ws_path / "sample_malware.exe"
            shutil.copy2(fixture_payload, target_bin)
            target_bin.chmod(0o755)

            # Write custom YARA rule to test rule matching
            rule_file = ws_path / "test_malware.yar"
            rule_file.write_text(
                "rule Test_Malware_Payload {\n"
                "    meta:\n"
                '        description = "Detect test payload signature"\n'
                "    strings:\n"
                '        $sig = "REVERSECORE_TEST_PAYLOAD_SIGNATURE_2026"\n'
                "    condition:\n"
                "        $sig\n"
                "}\n"
            )

            async with spawn_mcp_session("malware", ws_path) as session:
                # 1. Profile Exposure Check (Contract: Exactly 65 tools)
                tools_res = await session.list_tools()
                exposed_tools = {t.name for t in tools_res.tools}
                assert len(exposed_tools) == 65, f"Expected 65 tools, got {len(exposed_tools)}"
                assert "extract_iocs" in exposed_tools
                assert "run_yara" in exposed_tools
                assert "detect_anti_analysis" in exposed_tools
                assert "adaptive_vaccine" in exposed_tools
                # Static and forensics tools must be excluded
                assert "Radare2_list_functions" not in exposed_tools
                assert "r2_decompile" not in exposed_tools
                assert "pcap_analyze" not in exposed_tools

                # 2. Step 1: Binary Identification
                ident_data, d_time = await call_tool_json(
                    session,
                    "run_file",
                    {"file_path": str(target_bin)},
                )
                diagnostics["step1_run_file_seconds"] = d_time
                assert ident_data.get("status") == "success"

                # 3. Step 2: IoC Extraction
                ioc_data, d_time = await call_tool_json(
                    session,
                    "extract_iocs",
                    {"file_path": str(target_bin)},
                )
                diagnostics["step2_extract_iocs_seconds"] = d_time
                assert ioc_data.get("status") == "success"
                iocs = ioc_data.get("data", {})
                assert "198.51.100.42" in iocs.get("ipv4", [])
                assert any("update-check-service.org" in u for u in iocs.get("urls", []))
                assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in iocs.get("bitcoin_addresses", [])
                assert "CVE-2024-38077" in iocs.get("cves", [])

                # 4. Step 3: YARA Scanning
                yara_data, d_time = await call_tool_json(
                    session,
                    "run_yara",
                    {"file_path": str(target_bin), "rule_file": str(rule_file)},
                )
                diagnostics["step3_run_yara_seconds"] = d_time
                assert yara_data.get("status") == "success"
                matches = yara_data.get("data", {}).get("matches", [])
                assert len(matches) >= 1
                assert matches[0].get("rule") == "Test_Malware_Payload"

                # 5. Step 4: Anti-Analysis & Evasion Detection
                anti_data, d_time = await call_tool_json(
                    session,
                    "detect_anti_analysis",
                    {"file_path": str(target_bin)},
                )
                diagnostics["step4_detect_anti_analysis_seconds"] = d_time
                assert anti_data.get("status") == "success"
                anti_res = anti_data.get("data", {})
                assert anti_res.get("evasion_score", 0) >= 50
                assert anti_res.get("verdict") in ("HIGHLY_EVASIVE", "SUSPICIOUS")
                assert len(anti_res.get("mitre_techniques", [])) > 0

                # 6. Step 5: Adaptive Vaccine Generation
                threat_report = {
                    "function": "c2_beacon",
                    "address": "0x401000",
                    "instruction": "cmp eax, 0x19851100",
                    "reason": "C2 beacon communication detected",
                    "refined_code": 'if (beacon_target == "198.51.100.42")',
                }
                vaccine_data, d_time = await call_tool_json(
                    session,
                    "adaptive_vaccine",
                    {"threat_report": threat_report, "action": "yara"},
                )
                diagnostics["step5_adaptive_vaccine_seconds"] = d_time
                assert vaccine_data.get("status") == "success"
                vaccine_res = vaccine_data.get("data", {})
                assert "yara_rule" in vaccine_res

        print("\n[Scenario 2 Latency Diagnostics]")
        for step, duration in diagnostics.items():
            print(f"  {step}: {duration:.3f}s")

    async def test_scenario_3_patch_diffing_security_impact(self):
        """Scenario 3: Binary Patch Diffing & Security Impact in vuln-research profile.

        Verifies:
        1. vuln-research profile tool exposure (103 tools).
        2. Binary diffing via diff_binaries: computes similarity score and code delta.
        3. Automated patch inference via analyze_patch_diff_auto: verdicts and vulnerability assessment.
        4. Identical binary fast-path: perfect similarity (1.0) and IDENTICAL verdict.
        5. Step latency diagnostics tracking.
        """
        diagnostics: dict[str, float] = {}

        with tempfile.TemporaryDirectory() as temp_ws:
            ws_path = Path(temp_ws).resolve()

            # Create original and modified binary variants
            fixture_elf = FIXTURES_DIR / "binaries" / "hello_elf_x64"
            assert fixture_elf.exists(), f"Missing fixture ELF at {fixture_elf}"
            bin_v1 = ws_path / "app_v1"
            bin_v2 = ws_path / "app_v2"

            src_data = fixture_elf.read_bytes()
            bin_v1.write_bytes(src_data)

            # Patch 100 bytes to create realistic modified variant
            modified = bytearray(src_data)
            for i in range(100):
                modified[0x200 + i] = (modified[0x200 + i] + 1) % 256
            bin_v2.write_bytes(bytes(modified))

            bin_v1.chmod(0o755)
            bin_v2.chmod(0o755)

            async with spawn_mcp_session("vuln-research", ws_path) as session:
                # 1. Profile Exposure Check
                tools_res = await session.list_tools()
                exposed_tools = {t.name for t in tools_res.tools}
                assert len(exposed_tools) == 103, f"Expected 103 tools, got {len(exposed_tools)}"
                assert "diff_binaries" in exposed_tools
                assert "analyze_patch_diff_auto" in exposed_tools

                # 2. Step 1: radiff2-based Binary Diffing
                diff_data, d_time = await call_tool_json(
                    session,
                    "diff_binaries",
                    {"file_path_a": str(bin_v1), "file_path_b": str(bin_v2)},
                )
                diagnostics["step1_diff_binaries_seconds"] = d_time
                assert diff_data.get("status") == "success"
                diff_res = diff_data.get("data", {})
                similarity = diff_res.get("similarity", 0.0)
                assert 0.0 < similarity < 1.0, f"Expected similarity in (0, 1), got {similarity}"

                # 3. Step 2: Automated Patch Vulnerability Inference
                patch_data, d_time = await call_tool_json(
                    session,
                    "analyze_patch_diff_auto",
                    {"file_path_old": str(bin_v1), "file_path_new": str(bin_v2)},
                )
                diagnostics["step2_analyze_patch_diff_seconds"] = d_time
                assert patch_data.get("status") == "success"
                patch_res = patch_data.get("data", {})
                assert "patch_verdict" in patch_res
                assert "statistics" in patch_res

                # 4. Step 3: Identical Binary Fast-path Verification
                ident_data, d_time = await call_tool_json(
                    session,
                    "analyze_patch_diff_auto",
                    {"file_path_old": str(bin_v1), "file_path_new": str(bin_v1)},
                )
                diagnostics["step3_identical_check_seconds"] = d_time
                assert ident_data.get("status") == "success"
                assert ident_data.get("data", {}).get("patch_verdict") == "IDENTICAL"

        print("\n[Scenario 3 Latency Diagnostics]")
        for step, duration in diagnostics.items():
            print(f"  {step}: {duration:.3f}s")

    async def test_scenario_4_incident_pcap_forensics(self):
        """Scenario 4: Incident & Network PCAP Forensics in forensics profile.

        Verifies:
        1. forensics profile tool exposure (57 tools, no radare2/cve-hunter tools).
        2. PCAP packet triage and protocol distribution via pcap_analyze.
        3. DNS query and response domain extraction via pcap_extract_dns.
        4. 5-tuple network connection enumeration via pcap_list_connections.
        5. Artifact correlation pipeline: artifact_collect -> artifact_correlate_ioc.
        6. Step latency diagnostics tracking.
        """
        diagnostics: dict[str, float] = {}

        with tempfile.TemporaryDirectory() as temp_ws:
            ws_path = Path(temp_ws).resolve()

            # Copy deterministic PCAP fixture into workspace
            fixture_pcap = FIXTURES_DIR / "pcap" / "sample_traffic.pcap"
            assert fixture_pcap.exists(), f"Missing fixture PCAP at {fixture_pcap}"
            target_pcap = ws_path / "incident_capture.pcap"
            shutil.copy2(fixture_pcap, target_pcap)

            async with spawn_mcp_session("forensics", ws_path) as session:
                # 1. Profile Exposure Check (Contract: Exactly 57 tools)
                tools_res = await session.list_tools()
                exposed_tools = {t.name for t in tools_res.tools}
                assert len(exposed_tools) == 57, f"Expected 57 tools, got {len(exposed_tools)}"
                assert "pcap_analyze" in exposed_tools
                assert "pcap_extract_dns" in exposed_tools
                assert "pcap_list_connections" in exposed_tools
                assert "artifact_collect" in exposed_tools
                assert "artifact_correlate_ioc" in exposed_tools
                # Static and CVE hunter tools must be excluded
                assert "r2_decompile" not in exposed_tools
                assert "Radare2_list_functions" not in exposed_tools
                assert "cve_triage_crash" not in exposed_tools

                # 2. Step 1: PCAP Statistical Analysis
                pcap_data, d_time = await call_tool_json(
                    session,
                    "pcap_analyze",
                    {"pcap_path": str(target_pcap)},
                )
                diagnostics["step1_pcap_analyze_seconds"] = d_time
                assert pcap_data.get("status") == "success"
                pcap_res = pcap_data.get("data", {})
                assert pcap_res.get("total_packets", 0) >= 5
                proto_dist = pcap_res.get("protocol_distribution", {})
                assert "UDP" in proto_dist or "DNS" in proto_dist
                assert "TCP" in proto_dist

                # 3. Step 2: DNS Query Extraction
                dns_data, d_time = await call_tool_json(
                    session,
                    "pcap_extract_dns",
                    {"pcap_path": str(target_pcap)},
                )
                diagnostics["step2_pcap_extract_dns_seconds"] = d_time
                assert dns_data.get("status") == "success"
                dns_res = dns_data.get("data", {})
                assert "evil-c2.com" in dns_res.get("unique_domains", [])

                # 4. Step 3: Connection Enumeration
                conn_data, d_time = await call_tool_json(
                    session,
                    "pcap_list_connections",
                    {"pcap_path": str(target_pcap)},
                )
                diagnostics["step3_pcap_list_connections_seconds"] = d_time
                assert conn_data.get("status") == "success"
                connections = conn_data.get("data", {}).get("connections", [])
                assert len(connections) >= 1
                dports = {c.get("dst_port") for c in connections if isinstance(c, dict)}
                assert 4444 in dports or 53 in dports

                # 5. Step 4: Forensic Artifact Collection and Correlation
                raw_artifacts = [
                    {"value": "evil-c2.com", "resolved": "203.0.113.50"},
                    {"value": "203.0.113.50", "port": 4444},
                ]
                collect_data, d_time = await call_tool_json(
                    session,
                    "artifact_collect",
                    {
                        "artifacts": raw_artifacts,
                        "artifact_type": "ip",
                        "source": "pcap_forensics",
                    },
                )
                diagnostics["step4_artifact_collect_seconds"] = d_time
                assert collect_data.get("status") == "success"
                collected_list = collect_data.get("data", {}).get("artifacts", [])
                assert len(collected_list) == 2

                correlate_data, d_time = await call_tool_json(
                    session,
                    "artifact_correlate_ioc",
                    {"artifacts": collected_list},
                )
                diagnostics["step5_artifact_correlate_seconds"] = d_time
                assert correlate_data.get("status") == "success"

        print("\n[Scenario 4 Latency Diagnostics]")
        for step, duration in diagnostics.items():
            print(f"  {step}: {duration:.3f}s")

    async def test_scenario_5_crash_complex_path(self):
        """Scenario 5: Crash Unhappy/Complex Path in vuln-research profile.

        Verifies:
        1. vuln-research profile tool exposure (103 tools, no forensics-only tools).
        2. Deterministic ASan triage: bug class, CWE, faulting function, and signature.
        3. Signature stability contract: identical signature returned on repeated triage.
        4. Testcase minimization: delta debugging minimizes input size while preserving crash.
        5. Standalone PoC reproduction code generation (Python + C).
        6. Error resilience: malformed / empty input handled gracefully with structured error.
        7. Step latency diagnostics tracking.
        """
        diagnostics: dict[str, float] = {}

        with tempfile.TemporaryDirectory() as temp_ws:
            ws_path = Path(temp_ws).resolve()

            # Read deterministic ASan crash fixture
            fixture_asan = FIXTURES_DIR / "crash" / "sample_asan.log"
            assert fixture_asan.exists(), f"Missing ASan fixture at {fixture_asan}"
            asan_log_text = fixture_asan.read_text()

            # Create an executable target binary inside workspace that crashes on TRIGGER
            target_fuzzer = ws_path / "target_fuzzer"
            target_fuzzer.write_text(
                "#!/bin/sh\n"
                'if grep -q "TRIGGER" "$1" 2>/dev/null; then\n'
                '    echo "AddressSanitizer: heap-buffer-overflow READ on address 0x603000001000" >&2\n'
                "    exit 1\n"
                "else\n"
                "    exit 0\n"
                "fi\n"
            )
            target_fuzzer.chmod(0o755)

            # Create crash input with padding and trigger sequence
            crash_input = ws_path / "raw_crash_payload.bin"
            original_payload = b"HEADER_AAA_BBB_CCC_TRIGGER_FOOTER_XXX_YYY_ZZZ"
            crash_input.write_bytes(original_payload)

            async with spawn_mcp_session("vuln-research", ws_path) as session:
                # -------------------------------------------------------------
                # 1. Profile Exposure Check
                # -------------------------------------------------------------
                tools_res = await session.list_tools()
                exposed_tools = {t.name for t in tools_res.tools}

                # Contract: Exactly 103 tools for vuln-research profile
                assert len(exposed_tools) == 103, f"Expected 103 tools, got {len(exposed_tools)}"
                # Vulnerability research tools must be present
                assert "cve_triage_crash" in exposed_tools
                assert "cve_minimize_poc" in exposed_tools
                assert "cve_synthesize_harness" in exposed_tools
                assert "hunt_cve_vulnerabilities" in exposed_tools
                # Forensics-only tools must NOT be present
                assert "pcap_summary" not in exposed_tools
                assert "volatility_pslist" not in exposed_tools

                # -------------------------------------------------------------
                # 2. Step 1: ASan Crash Triage
                # -------------------------------------------------------------
                triage_res, d_time = await call_tool_json(
                    session,
                    "cve_triage_crash",
                    {"crash_log_or_text": asan_log_text},
                )
                diagnostics["step1_triage_crash_seconds"] = d_time
                assert triage_res.get("status") == "success"
                triage_data = triage_res.get("data", {})

                # Contract assertions
                assert triage_data.get("bug_type") == "heap-buffer-overflow"
                assert triage_data.get("cwe_id") == "CWE-122"
                assert triage_data.get("access_type") == "READ"
                assert triage_data.get("faulting_function") == "Curl_http_output_auth"
                sig_1 = triage_data.get("crash_signature_id")
                assert sig_1 and len(sig_1) == 16, f"Invalid signature: {sig_1}"

                # -------------------------------------------------------------
                # 3. Step 2: Crash Signature Stability Contract
                # -------------------------------------------------------------
                triage_res2, d_time = await call_tool_json(
                    session,
                    "cve_triage_crash",
                    {"crash_log_or_text": asan_log_text},
                )
                diagnostics["step2_stability_check_seconds"] = d_time
                sig_2 = triage_res2.get("data", {}).get("crash_signature_id")
                assert sig_1 == sig_2, f"Signature mismatch: {sig_1} != {sig_2}"

                # -------------------------------------------------------------
                # 4. Step 3: Testcase Minimization & PoC Generation
                # -------------------------------------------------------------
                min_res, d_time = await call_tool_json(
                    session,
                    "cve_minimize_poc",
                    {
                        "binary_path": str(target_fuzzer),
                        "crash_input_path": str(crash_input),
                    },
                )
                diagnostics["step3_minimize_poc_seconds"] = d_time
                assert min_res.get("status") == "success"
                min_data = min_res.get("data", {})

                orig_size = min_data.get("original_input_size_bytes")
                min_size = min_data.get("minimized_input_size_bytes")
                assert orig_size == len(original_payload)
                # Contract: minimized size must be strictly less than or equal to original
                assert min_size <= orig_size
                assert min_size == len(b"TRIGGER")

                # Standalone reproduction code verification
                py_poc = min_data.get("standalone_python_poc", "")
                assert "def reproduce():" in py_poc
                assert "subprocess.run" in py_poc
                assert str(target_fuzzer) in py_poc

                c_poc = min_data.get("standalone_c_poc", "")
                assert "g_poc_payload" in c_poc

                # -------------------------------------------------------------
                # 5. Step 4: Error Resilience & Propagation Contract
                # -------------------------------------------------------------
                # Empty input must return a structured failure without crashing session
                t0 = time.perf_counter()
                err_call = await session.call_tool("cve_triage_crash", {"crash_log_or_text": "   "})
                diagnostics["step4_error_resilience_seconds"] = time.perf_counter() - t0
                err_first_block = err_call.content[0]
                err_text = getattr(err_first_block, "text", str(err_first_block))
                err_obj = json.loads(err_text)
                assert err_obj.get("status") == "error"
                assert (
                    "INVALID_INPUT" in err_obj.get("error_code", "") or "empty" in err_text.lower()
                )

                # Session remains alive and responsive after error
                after_err_res, _ = await call_tool_json(
                    session,
                    "cve_triage_crash",
                    {"crash_log_or_text": asan_log_text},
                )
                assert after_err_res.get("status") == "success"

        # Print latency diagnostics for performance profiling
        print("\n[Scenario 5 Latency Diagnostics]")
        for step, duration in diagnostics.items():
            print(f"  {step}: {duration:.3f}s")
