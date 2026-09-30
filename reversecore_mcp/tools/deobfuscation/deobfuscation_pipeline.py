"""
Unified Deobfuscation Pipeline Orchestrator.

Combines stack string recovery, emulation-based string decryption, API hash resolution,
and opaque predicate dead code elimination into a single comprehensive analysis report.
"""

from __future__ import annotations

import asyncio
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolError, ToolResult, ToolSuccess, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.deobfuscation.api_hash_resolver import (
    resolve_api_hashes_impl,
)
from reversecore_mcp.tools.deobfuscation.dead_code_eliminator import (
    eliminate_dead_code_impl,
)
from reversecore_mcp.tools.deobfuscation.string_decryptor import (
    deobfuscate_strings_impl,
)

logger = get_logger(__name__)

# Sensitive API categories for threat scoring
_INJECTION_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "NtQueueApcThread",
    "SetThreadContext",
    "NtMapViewOfSection",
}
_PERSISTENCE_APIS = {
    "RegSetValueExA",
    "RegSetValueExW",
    "CreateServiceA",
    "StartServiceA",
}
_EVASION_APIS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
}


@log_execution(tool_name="run_deobfuscation_pipeline")
@track_metrics(tool_name="run_deobfuscation_pipeline")
async def run_deobfuscation_pipeline_impl(
    file_path: str,
    options: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Run all deobfuscation engines concurrently and assemble a unified intelligence report.

    Args:
        file_path: Path to the binary file to analyze.
        options: Optional configuration dictionary (e.g. algorithm, custom_hashes, function_address).
        timeout: Maximum execution timeout in seconds.

    Returns:
        ToolResult with the integrated analysis and per-engine status. Partial
        runs use ``INCOMPLETE`` for ``obfuscation_level``; total engine failure
        returns ``ANALYSIS_FAILED`` with diagnostics instead of a clean verdict.
    """
    safe_path = validate_file_path(file_path)
    if not safe_path.exists() or not safe_path.is_file():
        return failure("INVALID_PATH", f"Target file does not exist: {file_path}")

    opts = options or {}
    algo = opts.get("algorithm", "auto")
    custom_hashes = opts.get("custom_hashes")
    func_addr = opts.get("function_address")

    # Run the three sub-engines concurrently
    string_task = deobfuscate_strings_impl(
        str(safe_path), function_address=func_addr, timeout=timeout
    )
    api_task = resolve_api_hashes_impl(
        str(safe_path), algorithm=algo, custom_hashes=custom_hashes, timeout=timeout
    )
    dead_code_task = eliminate_dead_code_impl(
        str(safe_path), function_address=func_addr, timeout=timeout
    )

    results: tuple[Any, ...] = await asyncio.gather(
        string_task, api_task, dead_code_task, return_exceptions=True
    )
    engine_results = {
        "strings": results[0],
        "apis": results[1],
        "dead_code": results[2],
    }
    engine_status: dict[str, dict[str, Any]] = {}
    engine_data: dict[str, dict[str, Any]] = {}

    for engine_name, engine_result in engine_results.items():
        if isinstance(engine_result, ToolSuccess) and isinstance(engine_result.data, dict):
            engine_status[engine_name] = {"status": "success"}
            engine_data[engine_name] = engine_result.data
        elif isinstance(engine_result, ToolError):
            diagnostic: dict[str, Any] = {
                "status": "error",
                "error_code": engine_result.error_code,
                "message": engine_result.message,
            }
            if engine_result.hint:
                diagnostic["hint"] = engine_result.hint
            if engine_result.details:
                diagnostic["details"] = engine_result.details
            engine_status[engine_name] = diagnostic
        elif isinstance(engine_result, BaseException):
            engine_status[engine_name] = {
                "status": "error",
                "error_code": type(engine_result).__name__,
                "message": str(engine_result) or type(engine_result).__name__,
            }
        else:
            engine_status[engine_name] = {
                "status": "error",
                "error_code": "INVALID_RESULT",
                "message": (
                    f"Engine returned an unsupported result type: {type(engine_result).__name__}"
                ),
            }

    successful_engine_count = len(engine_data)
    if successful_engine_count == 0:
        return failure(
            "ANALYSIS_FAILED",
            "All deobfuscation engines failed; an obfuscation verdict cannot be determined.",
            hint="Review the per-engine diagnostics and retry after resolving the reported errors.",
            pipeline_status="failed",
            engine_status=engine_status,
        )

    strings_data = engine_data.get("strings", {})
    apis_data = engine_data.get("apis", {})
    dead_code_data = engine_data.get("dead_code", {})

    recovered_strings = strings_data.get("recovered_strings", [])
    resolved_apis = apis_data.get("resolved_apis", [])
    peb_walking = apis_data.get("peb_walking_detected", False)
    opaque_predicates = dead_code_data.get("opaque_predicates", [])

    # Calculate Obfuscation Severity Score
    severity_score = 0
    threat_tags: list[str] = []

    if len(recovered_strings) > 0:
        severity_score += min(len(recovered_strings) * 5, 30)
        threat_tags.append("Stack Strings / Loop Obfuscation")

    if peb_walking:
        severity_score += 25
        threat_tags.append("Dynamic PEB/TEB Walking")

    if len(resolved_apis) > 0:
        severity_score += min(len(resolved_apis) * 5, 30)
        threat_tags.append("API Hashing")

    if len(opaque_predicates) > 0:
        severity_score += min(len(opaque_predicates) * 5, 15)
        threat_tags.append("Opaque Predicates / Dead Code")

    # Threat capabilities breakdown
    detected_capabilities: list[str] = []
    for api_item in resolved_apis:
        api_name = api_item.get("api_name", "")
        if api_name in _INJECTION_APIS:
            detected_capabilities.append(f"Process Injection ({api_name})")
        elif api_name in _PERSISTENCE_APIS:
            detected_capabilities.append(f"System Persistence ({api_name})")
        elif api_name in _EVASION_APIS:
            detected_capabilities.append(f"Anti-Analysis Evasion ({api_name})")

    detected_capabilities = sorted(set(detected_capabilities))

    if severity_score >= 50:
        observed_obfuscation_level = "HIGH"
    elif severity_score >= 20:
        observed_obfuscation_level = "MEDIUM"
    else:
        observed_obfuscation_level = "LOW"

    pipeline_status = "complete" if successful_engine_count == len(engine_results) else "partial"
    obfuscation_level = (
        observed_obfuscation_level if pipeline_status == "complete" else "INCOMPLETE"
    )

    report = {
        "file_path": str(safe_path),
        "pipeline_status": pipeline_status,
        "engine_status": engine_status,
        "obfuscation_level": obfuscation_level,
        "observed_obfuscation_level": observed_obfuscation_level,
        "obfuscation_severity_score": min(severity_score, 100),
        "threat_tags": threat_tags,
        "detected_capabilities": detected_capabilities,
        "summary": {
            "total_strings_recovered": len(recovered_strings),
            "total_apis_resolved": len(resolved_apis),
            "peb_walking_detected": peb_walking,
            "total_opaque_predicates": len(opaque_predicates),
        },
        "strings": recovered_strings,
        "apis": resolved_apis,
        "dead_code": {
            "opaque_predicates": opaque_predicates,
            "cfg_simplifications": dead_code_data.get("cfg_simplifications", []),
        },
    }

    return success(report)
