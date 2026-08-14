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
from reversecore_mcp.core.result import ToolResult, failure, success
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
        ToolResult with the integrated deobfuscation analysis report.
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

    string_res, api_res, dead_code_res = await asyncio.gather(
        string_task, api_task, dead_code_task, return_exceptions=True
    )

    # Unwrap results safely
    strings_data: dict[str, Any] = {}
    apis_data: dict[str, Any] = {}
    dead_code_data: dict[str, Any] = {}

    if isinstance(string_res, ToolResult) and string_res.status == "success":
        strings_data = string_res.data or {}
    if isinstance(api_res, ToolResult) and api_res.status == "success":
        apis_data = api_res.data or {}
    if isinstance(dead_code_res, ToolResult) and dead_code_res.status == "success":
        dead_code_data = dead_code_res.data or {}

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
        obfuscation_level = "HIGH"
    elif severity_score >= 20:
        obfuscation_level = "MEDIUM"
    else:
        obfuscation_level = "LOW"

    report = {
        "file_path": str(safe_path),
        "obfuscation_level": obfuscation_level,
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
