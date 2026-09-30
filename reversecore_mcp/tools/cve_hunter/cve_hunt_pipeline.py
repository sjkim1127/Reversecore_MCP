"""Unified One-Click C/C++ CVE Hunting & Exploitability Engine Pipeline."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.r2_helpers import calculate_dynamic_timeout
from reversecore_mcp.core.result import ToolResult, ToolSuccess, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.cve_hunter.asan_crash_triager import triage_asan_log
from reversecore_mcp.tools.cve_hunter.harness_synthesizer import (
    synthesize_fuzz_harness_impl,
)
from reversecore_mcp.tools.cve_hunter.hybrid_fuzz_orchestrator import (
    run_hybrid_fuzz_impl,
)
from reversecore_mcp.tools.cve_hunter.poc_minimizer import (
    MAX_C_POC_PAYLOAD_SIZE,
    generate_c_poc_harness,
    generate_python_poc_script,
)

logger = get_logger(__name__)

_SOURCE_TARGET_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def generate_cve_advisory_markdown(
    target_name: str,
    triage: dict[str, Any],
    poc_script: str | None,
    c_harness: str | None,
    evidence: dict[str, Any] | None = None,
    poc_note: str | None = None,
) -> str:
    """Generate a formal Markdown Security Advisory draft for vendor/NVD submission."""
    cwe_id = triage.get("cwe_id") or "Unknown CWE"
    cwe_name = triage.get("cwe_name") or "Unclassified sanitizer finding"
    cvss = triage.get("cvss") or {}
    score = cvss.get("cvss_v31_score", "Not calculated")
    severity = cvss.get("severity", "Not rated")
    vector = cvss.get("cvss_vector", "Not available")

    faulting_func = triage.get("faulting_function", "unknown")
    faulting_loc = triage.get("faulting_source_location", "unknown")
    bug_type = triage.get("bug_type", "unclassified sanitizer event")
    access_type = triage.get("access_type", "UNKNOWN")
    access_size = triage.get("access_size", 0)
    evidence = evidence or {}

    poc_parts = []
    if poc_script:
        poc_parts.append(f"### Python Reproducer\n```python\n{poc_script.strip()}\n```")
    if c_harness:
        poc_parts.append(f"### Standalone C Harness\n```c\n{c_harness.strip()}\n```")
    if poc_parts:
        poc_section = "## 4. Proof of Concept\n\n" + "\n\n".join(poc_parts)
    else:
        poc_section = (
            "## 4. Proof of Concept\n\n"
            "No PoC was generated because the supplied sanitizer log did not include the crash input."
        )
    if poc_note:
        poc_section += f"\n\n{poc_note}"

    evidence_source = evidence.get("evidence_source", "unknown")
    input_path = evidence.get("crash_input_path")
    input_description = (
        f"`{Path(input_path).name}` (SHA-256: `{evidence.get('crash_input_sha256')}`)"
        if input_path
        else "not supplied"
    )

    advisory = f"""# Security Advisory: {cwe_name} in `{target_name}` ({cwe_id})

## 1. Vulnerability Summary
- **Target Component:** `{target_name}`
- **Vulnerability Class:** {cwe_name} ({cwe_id})
- **Discovered Bug:** `{bug_type}` on memory {access_type} of size {access_size} bytes
- **Faulting Function:** `{faulting_func}`
- **Source Location:** `{faulting_loc}`
- **Automated CVSS v3.1 estimate:** {score} ({severity})
- **CVSS Vector:** `{vector}`

---

## 2. Sanitizer Evidence
The sanitizer report records a `{bug_type}` while executing `{faulting_func}`. The report alone does not establish the source-level root cause, affected releases, or exploitability; confirm those details against the target source and reproduce the crash before disclosure.

### Faulting Callstack
```text
"""
    for frame in triage.get("crash_callstack", [])[:6]:
        advisory += f"#{frame.get('frame')} {frame.get('address')} in {frame.get('symbol')} at {frame.get('source_file')}:{frame.get('line')}\n"

    advisory += f"""```

---

## 3. Preliminary Exploitability Assessment
- **Automated impact estimate:** {triage.get("exploitability_assessment", "Not assessed from the available evidence.")}
- **Attack vector:** Not established by the sanitizer trace; assess the target's deployment and input path.

---

## Evidence & Provenance
- **Evidence source:** `{evidence_source}`
- **Sanitizer log SHA-256:** `{evidence.get("crash_log_sha256", "unavailable")}`
- **Crash input:** {input_description}

---

{poc_section}

---

## 5. Suggested Remediation
1. Implement strict size and boundary validation before executing buffer copy/indexing operations in `{faulting_func}`.
2. Ensure dynamic allocation checks account for integer overflow when multiplying chunk counts by element sizes.
"""
    return advisory


async def hunt_cve_pipeline_impl(
    target_path_str: str,
    sample_file_path: str | None = None,
    options: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Execute the CVE hunting pipeline against a compiled LibFuzzer executable.

    Args:
        target_path_str: Path to a compiled LibFuzzer executable. Source and header files must be
            compiled with a generated harness before they can be passed to this pipeline.
        sample_file_path: Optional path to a valid sample file.
        options: Optional configuration dictionary (e.g. fuzz_duration, target_function).
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with CVE findings, triaged crashes, PoCs, and an advisory report. Successful
        fuzzing results include the executed path in ``fuzzed_executable``; it is null when no
        fuzzing run succeeded.
    """
    try:
        safe_path = validate_file_path(target_path_str)
    except Exception as e:
        return failure("INVALID_PATH", f"Validation error on target path: {e}")

    if not safe_path.exists():
        return failure("FILE_NOT_FOUND", f"Target file does not exist: {target_path_str}")

    if not safe_path.is_file():
        return failure("INVALID_TARGET_TYPE", "The fuzz target must be a regular file.")

    if safe_path.suffix.lower() in _SOURCE_TARGET_SUFFIXES:
        return failure(
            "UNSUPPORTED_TARGET_TYPE",
            "The CVE hunting pipeline accepts compiled LibFuzzer executables only. "
            "It does not compile source or header files, so they will not be sent to the "
            "fuzzer. Generate a harness with cve_synthesize_harness, compile and link it "
            "with the target using LibFuzzer, then pass the executable path.",
        )

    opts = options or {}
    fuzz_duration = int(opts.get("fuzz_duration", 15))
    target_func = opts.get("target_function")

    calc_timeout = calculate_dynamic_timeout(
        safe_path, base_timeout=timeout or (fuzz_duration + 45)
    )

    logger.info(f"Starting CVE Hunt Pipeline for target: {safe_path}")

    # Stage 1: Harness & Dictionary Synthesis
    harness_res = await synthesize_fuzz_harness_impl(
        header_or_binary_path=str(safe_path),
        sample_file_path=sample_file_path,
        target_function=target_func,
        timeout=10,
    )
    harness_data = (
        harness_res.data
        if harness_res.status == "success" and isinstance(harness_res.data, dict)
        else {}
    )

    # Stage 2: Hybrid Fuzzing & Symbolic Solving
    fuzz_res = await run_hybrid_fuzz_impl(
        target_binary_path=str(safe_path),
        max_total_time_seconds=fuzz_duration,
        enable_angr_concolic=opts.get("enable_angr", True),
        timeout=calc_timeout,
    )
    if isinstance(fuzz_res, ToolSuccess) and isinstance(fuzz_res.data, dict):
        fuzz_data = fuzz_res.data
        fuzz_success = True
    else:
        fuzz_data = {}
        fuzz_success = False
    fuzz_execution_status = fuzz_data.get("execution_status", "failed")
    fuzz_completed = fuzz_success and fuzz_execution_status in {"completed", "crash_detected"}
    fuzzed_executable = (
        fuzz_data.get("target_binary")
        if isinstance(fuzz_data.get("target_binary"), str)
        else (str(safe_path) if fuzz_success else None)
    )

    custom_crash_log = opts.get("crash_log")
    external_triage: dict[str, Any] | None = None
    if custom_crash_log is not None:
        if not isinstance(custom_crash_log, str) or not custom_crash_log.strip():
            return failure(
                "INVALID_CRASH_LOG",
                "The supplied crash log must be non-empty text or a readable file path.",
            )

        raw_crash_log = custom_crash_log
        if len(raw_crash_log) < 4096 and "\n" not in raw_crash_log and "\r" not in raw_crash_log:
            try:
                log_path = validate_file_path(raw_crash_log, read_only=True)
                if log_path.is_file():
                    if log_path.stat().st_size > get_config().max_output_size:
                        return failure(
                            "CRASH_LOG_TOO_LARGE",
                            "The supplied crash log exceeds the configured output size limit.",
                        )
                    raw_crash_log = log_path.read_text(errors="replace")
            except Exception:
                # If this is not a permitted file path, treat it as literal log text.
                pass

        if len(raw_crash_log.encode()) > get_config().max_output_size:
            return failure(
                "CRASH_LOG_TOO_LARGE",
                "The supplied crash log exceeds the configured output size limit.",
            )

        external_triage = triage_asan_log(raw_crash_log)
        if not external_triage["is_sanitizer_report"]:
            return failure(
                "INVALID_CRASH_LOG",
                "The supplied text does not contain a recognized sanitizer crash report.",
            )
        external_triage.update(
            {
                "evidence_source": "external_crash_log",
                "crash_log_sha256": hashlib.sha256(raw_crash_log.encode()).hexdigest(),
                "crash_input_path": None,
                "crash_input_sha256": None,
            }
        )

    if not fuzz_completed and external_triage is None:
        error_code = getattr(fuzz_res, "error_code", "FUZZING_INCOMPLETE")
        error_message = getattr(fuzz_res, "message", "Fuzzing did not report a completed run.")
        return failure(
            "FUZZING_INCOMPLETE",
            f"CVE analysis stopped because fuzzing did not complete: {error_message}",
            hint="Resolve the fuzzer execution error and run the analysis again.",
            upstream_error_code=error_code,
        )

    # Stage 3: Accept only triage records linked to an artifact from this run.
    raw_triaged = fuzz_data.get("triaged_crashes", []) if fuzz_success else []
    if not isinstance(raw_triaged, list):
        return failure("CRASH_TRIAGE_INCOMPLETE", "Fuzzer returned malformed crash triage data.")

    triaged_crashes: list[dict[str, Any]] = []
    crash_payloads: list[bytes] = []
    workspace = get_config().workspace.resolve()
    for item in raw_triaged:
        if not isinstance(item, dict) or item.get("bug_type") in (None, "unknown_crash"):
            return failure(
                "CRASH_TRIAGE_INCOMPLETE", "Fuzzer returned an unrecognized crash triage record."
            )
        if item.get("evidence_source") != "hybrid_fuzzer":
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                "Crash triage is missing current-run fuzz evidence provenance.",
            )

        crash_input_path = item.get("crash_input_path")
        input_digest = item.get("crash_input_sha256")
        log_digest = item.get("crash_log_sha256")
        if (
            not isinstance(crash_input_path, str)
            or not isinstance(input_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", input_digest)
            or not isinstance(log_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", log_digest)
        ):
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                "Crash triage is missing linked input or sanitizer-log hashes.",
            )

        try:
            validated_crash_path = validate_file_path(crash_input_path, read_only=True)
            resolved_crash_path = validated_crash_path.resolve(strict=True)
            resolved_crash_path.relative_to(workspace)
            if not resolved_crash_path.is_file():
                raise ValueError("crash input is not a regular file")
            if resolved_crash_path.stat().st_size > get_config().max_output_size:
                return failure(
                    "CRASH_INPUT_TOO_LARGE",
                    "Crash input exceeds the configured PoC generation size limit.",
                )
            crash_payload = resolved_crash_path.read_bytes()
        except Exception as e:
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                f"Could not validate the crash input artifact: {type(e).__name__}",
            )

        if hashlib.sha256(crash_payload).hexdigest() != input_digest:
            return failure(
                "CRASH_EVIDENCE_INCOMPLETE",
                "Crash input changed after fuzz triage; refusing to generate a PoC.",
            )

        linked_triage = dict(item)
        linked_triage["crash_input_path"] = str(resolved_crash_path)
        triaged_crashes.append(linked_triage)
        crash_payloads.append(crash_payload)

    if triaged_crashes and fuzz_execution_status != "crash_detected":
        # A sanitizer report is itself evidence that this run detected a crash.
        fuzz_execution_status = "crash_detected"

    artifact_paths = fuzz_data.get("crash_artifacts", []) if fuzz_success else []
    reported_crashes = fuzz_data.get("crashes_detected", 0) if fuzz_success else 0
    if (
        not triaged_crashes
        and fuzz_completed
        and (fuzz_execution_status == "crash_detected" or reported_crashes or artifact_paths)
    ):
        return failure(
            "CRASH_TRIAGE_INCOMPLETE",
            "Fuzzing reported crash evidence that could not be linked to a triaged crash input.",
        )

    if not triaged_crashes and external_triage is None:
        # A completed clean run is a valid result, but it is not a vulnerability finding.
        result_payload: dict[str, Any] = {
            "target_file": str(safe_path),
            "fuzzed_executable": fuzzed_executable,
            "finding_status": "none",
            "analysis_status": "complete",
            "execution_status": "completed",
            "target_function": None,
            "vulnerability_class": None,
            "cwe_id": None,
            "cvss_v31_score": None,
            "cvss_severity": None,
            "cvss_vector": None,
            "harness_synthesis": {
                "candidate_functions": harness_data.get("candidate_functions", []),
                "dictionary_token_count": harness_data.get("dictionary_token_count", 0),
            },
            "fuzzing_stats": {
                "executions": fuzz_data.get("total_executions", 0),
                "crashes_detected": 0,
                "findings_count": 0,
            },
            "triaged_crashes": [],
            "standalone_python_poc": None,
            "standalone_c_poc": None,
            "cve_security_advisory_markdown": None,
            "summary": f"Fuzzing completed for '{safe_path.name}' with no sanitizer crash observed; no vulnerability finding was produced.",
        }
        return success(result_payload)

    if not triaged_crashes and external_triage is not None:
        triaged_crashes.append(external_triage)

    primary_triage = triaged_crashes[0]
    primary_payload = crash_payloads[0] if crash_payloads else None

    if primary_triage.get("cwe_id") is None or not isinstance(primary_triage.get("cvss"), dict):
        reported_crashes = fuzz_data.get("crashes_detected", 0)
        crash_count = reported_crashes if isinstance(reported_crashes, int) else 0
        artifact_paths = fuzz_data.get("crash_artifacts", [])
        analysis_status = "complete" if fuzz_completed else "partial"
        return success(
            {
                "target_file": str(safe_path),
                "fuzzed_executable": fuzzed_executable,
                "finding_status": "unclassified",
                "analysis_status": analysis_status,
                "execution_status": fuzz_execution_status,
                "target_function": primary_triage.get("faulting_function"),
                "vulnerability_class": None,
                "cwe_id": None,
                "cvss_v31_score": None,
                "cvss_severity": None,
                "cvss_vector": None,
                "harness_synthesis": {
                    "candidate_functions": harness_data.get("candidate_functions", []),
                    "dictionary_token_count": harness_data.get("dictionary_token_count", 0),
                },
                "fuzzing_stats": {
                    "executions": fuzz_data.get("total_executions", 0),
                    "crashes_detected": crash_count,
                    "findings_count": 0,
                    "unclassified_sanitizer_reports": len(triaged_crashes),
                    "crash_artifacts": artifact_paths,
                },
                "triaged_crashes": triaged_crashes,
                "standalone_python_poc": None,
                "standalone_c_poc": None,
                "cve_security_advisory_markdown": None,
                "summary": (
                    f"Sanitizer evidence for '{safe_path.name}' was preserved as "
                    f"'{primary_triage.get('bug_type', 'unknown')}', but its error class has "
                    "no CWE/CVSS mapping; no vulnerability classification, PoC, or advisory was generated."
                ),
            }
        )

    # Stage 4: Generate PoCs only from the linked crash artifact bytes.
    py_poc: str | None = None
    c_poc: str | None = None
    poc_note: str | None = None
    if primary_payload is not None:
        py_poc = generate_python_poc_script(
            target_binary_path=str(safe_path),
            payload_bytes=primary_payload,
            cwe_id=primary_triage["cwe_id"],
            bug_name=primary_triage["cwe_name"],
        )
        if 0 < len(primary_payload) <= MAX_C_POC_PAYLOAD_SIZE:
            c_poc = generate_c_poc_harness(
                target_function=primary_triage.get("faulting_function", "parse_data"),
                payload_bytes=primary_payload,
                cwe_id=primary_triage["cwe_id"],
            )
        elif len(primary_payload) > MAX_C_POC_PAYLOAD_SIZE:
            poc_note = (
                "The C harness was omitted because its generator embeds at most "
                f"{MAX_C_POC_PAYLOAD_SIZE} bytes; the Python reproducer retains the full crash input."
            )
        else:
            poc_note = "The C harness was omitted because the linked crash input is empty."

    # Stage 5: Generate an advisory that records the evidence origin.
    advisory_md = generate_cve_advisory_markdown(
        target_name=safe_path.name,
        triage=primary_triage,
        poc_script=py_poc,
        c_harness=c_poc,
        evidence=primary_triage,
        poc_note=poc_note,
    )

    analysis_status = "complete" if fuzz_completed else "partial"
    fuzz_crash_count = int(reported_crashes) if isinstance(reported_crashes, int) else 0
    if primary_triage.get("evidence_source") == "external_crash_log":
        evidence_summary = "Finding triaged from an externally supplied sanitizer log"
    else:
        evidence_summary = (
            "Finding linked to a sanitizer report and crash input produced by this fuzz run"
        )
    completion_note = (
        "; fuzzing did not complete, so this result is partial" if not fuzz_completed else ""
    )

    result_payload = {
        "target_file": str(safe_path),
        "fuzzed_executable": fuzzed_executable,
        "finding_status": "found",
        "analysis_status": analysis_status,
        "execution_status": fuzz_execution_status,
        "target_function": primary_triage.get("faulting_function"),
        "vulnerability_class": primary_triage.get("cwe_name"),
        "cwe_id": primary_triage.get("cwe_id"),
        "cvss_v31_score": primary_triage.get("cvss", {}).get("cvss_v31_score"),
        "cvss_severity": primary_triage.get("cvss", {}).get("severity"),
        "cvss_vector": primary_triage.get("cvss", {}).get("cvss_vector"),
        "harness_synthesis": {
            "candidate_functions": harness_data.get("candidate_functions", []),
            "dictionary_token_count": harness_data.get("dictionary_token_count", 0),
        },
        "fuzzing_stats": {
            "executions": fuzz_data.get("total_executions", 0),
            "crashes_detected": fuzz_crash_count,
            "findings_count": len(triaged_crashes),
            "crash_artifacts": artifact_paths,
        },
        "triaged_crashes": triaged_crashes,
        "standalone_python_poc": py_poc,
        "standalone_c_poc": c_poc,
        "cve_security_advisory_markdown": advisory_md,
        "summary": (
            f"{evidence_summary} for '{safe_path.name}'{completion_note}. "
            f"Identified {primary_triage.get('cwe_id')} ({primary_triage.get('cwe_name')}) "
            f"with CVSS v3.1 score {primary_triage.get('cvss', {}).get('cvss_v31_score')} "
            f"({primary_triage.get('cvss', {}).get('severity')})."
        ),
    }

    return success(result_payload)
