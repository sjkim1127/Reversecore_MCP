"""Verify whether extracted strings are actually referenced by code (Issue #324).

Distinguishes artifact-only string observations from active, behavior-capable code
references by analyzing cross-references (xrefs) and calling functions via Radare2.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from pydantic import Field

from reversecore_mcp.core.evidence import (
    EvidenceLevel,
    EvidenceOrigin,
    artifact_finding,
    structural_finding,
)
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.tools.radare2.r2_session import R2Session

logger = get_logger(__name__)


def _is_code_xref(xref_item: dict[str, Any]) -> bool:
    """Determine whether an axtj cross-reference item originates from executable code."""
    fcn_name = str(xref_item.get("fcn_name") or xref_item.get("name") or "")
    # Non-code references often carry synthetic section labels like 'aav.0x...'
    if fcn_name and not fcn_name.startswith("aav.") and not fcn_name.startswith("data."):
        return True

    xref_type = str(xref_item.get("type", "")).upper()
    if xref_type in ("CODE", "CALL", "JMP", "STRN"):
        return True

    opcode = str(xref_item.get("opcode", "")).lower()
    code_instructions = ("lea", "mov", "add", "push", "ldr", "adr", "call", "jmp")
    return any(opcode.startswith(inst) for inst in code_instructions)


def _parse_address_safely(addr_val: Any) -> int | None:
    """Parse address into integer representation."""
    if addr_val is None:
        return None
    if isinstance(addr_val, int):
        return addr_val
    try:
        s = str(addr_val).strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s, 10)
    except (ValueError, TypeError):
        return None


def _perform_string_verification(
    file_path: str,
    target_strings: list[str] | None,
    target_addresses: list[str] | None,
    include_context: bool,
    limit: int,
) -> dict[str, Any]:
    """Execute Radare2 string xref analysis synchronously inside worker thread."""
    session = R2Session()
    if not session.open(file_path):
        raise RuntimeError(session.last_error or "Failed to open binary with Radare2")

    try:
        # Perform standard binary analysis to resolve xrefs and functions
        session.cmd("aaa")

        # Extract string tables
        raw_data_strings = session.cmdj("izj") or []
        if not isinstance(raw_data_strings, list):
            raw_data_strings = []

        raw_all_strings = session.cmdj("izzj") or []
        if not isinstance(raw_all_strings, list):
            raw_all_strings = []

        # Merge and index strings by vaddr and value
        strings_by_vaddr: dict[int, dict[str, Any]] = {}
        for item in raw_data_strings + raw_all_strings:
            if isinstance(item, dict) and "vaddr" in item:
                vaddr = _parse_address_safely(item["vaddr"])
                if vaddr is not None and vaddr not in strings_by_vaddr:
                    strings_by_vaddr[vaddr] = item

        items_to_verify: list[dict[str, Any]] = []

        if target_addresses:
            for addr_str in target_addresses:
                parsed_addr = _parse_address_safely(addr_str)
                if parsed_addr is None or parsed_addr not in strings_by_vaddr:
                    # Try reading string at address directly
                    str_read = session.cmd(f"psz @ {addr_str}").strip() if parsed_addr else ""
                    if str_read and parsed_addr is not None:
                        items_to_verify.append(
                            {"vaddr": parsed_addr, "string": str_read, "explicit_addr": addr_str}
                        )
                    else:
                        items_to_verify.append(
                            {"vaddr": None, "string": None, "explicit_addr": addr_str}
                        )
                else:
                    item = strings_by_vaddr[parsed_addr]
                    items_to_verify.append(
                        {
                            "vaddr": parsed_addr,
                            "string": item.get("string", ""),
                            "explicit_addr": addr_str,
                        }
                    )

        elif target_strings:
            for s_target in target_strings:
                matched_entries = [
                    item
                    for item in strings_by_vaddr.values()
                    if s_target.lower() in str(item.get("string", "")).lower()
                ]
                if matched_entries:
                    for entry in matched_entries:
                        items_to_verify.append(
                            {
                                "vaddr": _parse_address_safely(entry.get("vaddr")),
                                "string": entry.get("string", ""),
                                "query": s_target,
                            }
                        )
                else:
                    items_to_verify.append({"vaddr": None, "string": s_target, "query": s_target})

        else:
            # Default: evaluate top strings up to limit
            for entry in list(strings_by_vaddr.values())[:limit]:
                items_to_verify.append(
                    {
                        "vaddr": _parse_address_safely(entry.get("vaddr")),
                        "string": entry.get("string", ""),
                    }
                )

        verified_strings: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        summary = {
            "total_evaluated": len(items_to_verify),
            "referenced": 0,
            "unreferenced": 0,
            "ambiguous": 0,
            "unresolved": 0,
        }

        for item in items_to_verify:
            vaddr = item.get("vaddr")
            str_val: str = str(item.get("string") or "")
            str_preview: str = str_val[:40]

            if vaddr is None:
                record: dict[str, Any] = {
                    "string": str_val,
                    "address": item.get("explicit_addr"),
                    "usage": "unresolved",
                    "xref_count": 0,
                    "referencing_addresses": [],
                    "referencing_functions": [],
                    "is_code_reference": False,
                    "evidence_origin": EvidenceOrigin.ARTIFACT.value,
                    "classification": "artifact_only",
                    "confidence": EvidenceLevel.POSSIBLE.value,
                    "reason": "String or address could not be resolved in binary sections",
                }
                summary["unresolved"] += 1
                verified_strings.append(record)
                continue

            hex_vaddr = hex(vaddr)
            raw_xrefs = session.cmdj(f"axtj @ {hex_vaddr}") or []
            if not isinstance(raw_xrefs, list):
                raw_xrefs = []

            if not raw_xrefs:
                record = {
                    "string": str_val,
                    "address": hex_vaddr,
                    "usage": "unreferenced",
                    "xref_count": 0,
                    "referencing_addresses": [],
                    "referencing_functions": [],
                    "is_code_reference": False,
                    "evidence_origin": EvidenceOrigin.ARTIFACT.value,
                    "classification": "artifact_only",
                    "confidence": EvidenceLevel.OBSERVED.value,
                    "reason": "String exists in binary data section but has no cross-references",
                }
                summary["unreferenced"] += 1

                # Generate artifact finding
                finding = artifact_finding(
                    title=f"Unreferenced String: {str_preview}",
                    description=f"Dead/unreferenced string '{str_val}' present at {hex_vaddr} with 0 code cross-references.",
                    category="string_artifact",
                )
                finding.add_evidence(
                    source="r2_string_verifier",
                    location=hex_vaddr,
                    description=f"String defined at {hex_vaddr} has 0 xrefs",
                    raw_data=str_val,
                    origin=EvidenceOrigin.ARTIFACT,
                )
                findings.append(finding.to_dict())

            else:
                code_xrefs = [x for x in raw_xrefs if _is_code_xref(x)]
                all_referencing_addrs = [
                    hex(x["from"])
                    for x in raw_xrefs
                    if isinstance(x.get("from"), int) and x["from"] > 0
                ]
                referencing_functions = sorted(
                    {
                        str(x.get("fcn_name") or x.get("name"))
                        for x in code_xrefs
                        if x.get("fcn_name") or x.get("name")
                    }
                )

                if code_xrefs:
                    usage = "referenced"
                    is_code_ref = True
                    origin = EvidenceOrigin.STRUCTURAL
                    classification = "behavior_capable"
                    confidence = EvidenceLevel.INFERRED
                    reason = (
                        f"String referenced by {len(code_xrefs)} executable code instruction(s) "
                        f"in function(s): {', '.join(referencing_functions) if referencing_functions else 'unnamed code'}"
                    )
                    summary["referenced"] += 1

                    finding = structural_finding(
                        title=f"Active Code Reference: {str_preview}",
                        description=(
                            f"String '{str_val}' at {hex_vaddr} is actively referenced by code in "
                            f"{', '.join(referencing_functions) if referencing_functions else 'executable section'}."
                        ),
                        category="code_string_reference",
                    )
                    for cx in code_xrefs[:5]:
                        cx_addr = hex(cx.get("from", 0))
                        cx_op = cx.get("opcode", "")
                        cx_fcn = cx.get("fcn_name", "unknown")
                        finding.add_evidence(
                            source="r2_axtj",
                            location=cx_addr,
                            description=f"Referenced in {cx_fcn}: {cx_op}",
                            raw_data=cx_op,
                            origin=EvidenceOrigin.STRUCTURAL,
                        )
                    findings.append(finding.to_dict())

                else:
                    usage = "ambiguous"
                    is_code_ref = False
                    origin = EvidenceOrigin.STRUCTURAL
                    classification = "behavior_capable"
                    confidence = EvidenceLevel.POSSIBLE
                    reason = (
                        f"String has {len(raw_xrefs)} cross-reference(s) originating only from "
                        f"data/relocation sections without direct code function caller"
                    )
                    summary["ambiguous"] += 1

                record = {
                    "string": str_val,
                    "address": hex_vaddr,
                    "usage": usage,
                    "xref_count": len(raw_xrefs),
                    "code_xref_count": len(code_xrefs),
                    "referencing_addresses": all_referencing_addrs,
                    "referencing_functions": referencing_functions,
                    "is_code_reference": is_code_ref,
                    "evidence_origin": origin.value,
                    "classification": classification,
                    "confidence": confidence.value,
                    "reason": reason,
                }

                if include_context and code_xrefs:
                    primary_xref = code_xrefs[0]
                    from_addr = hex(primary_xref.get("from", 0))
                    opcode = primary_xref.get("opcode", "")
                    context_disasm = session.cmd(f"pd 3 @ {from_addr}")
                    record["context"] = {
                        "primary_address": from_addr,
                        "primary_opcode": opcode,
                        "disassembly_snippet": context_disasm.strip(),
                    }

            verified_strings.append(record)

        return {
            "file_path": file_path,
            "summary": summary,
            "verified_strings": verified_strings,
            "findings": findings,
        }

    finally:
        session.close()


async def verify_string_references(
    file_path: Annotated[
        str,
        Field(description="Path to the binary file to analyze."),
    ],
    strings: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Optional list of string literals to verify for code references.",
        ),
    ] = None,
    addresses: Annotated[
        list[str] | None,
        Field(
            default=None,
            description="Optional list of string virtual addresses (e.g. '0x402010') to verify.",
        ),
    ] = None,
    include_context: Annotated[
        bool,
        Field(
            default=False,
            description="If True, includes referencing instruction opcode disassembly snippet.",
        ),
    ] = False,
    limit: Annotated[
        int,
        Field(
            default=50,
            ge=1,
            le=500,
            description="Maximum number of strings to analyze when neither strings nor addresses are specified.",
        ),
    ] = 50,
) -> ToolResult:
    """Verify whether extracted strings are actually referenced by executable code.

    Distinguishes artifact-only strings from behavior-capable logic by analyzing
    radare2 cross-references, calling functions, and instruction contexts.

    Args:
        file_path: Path to the binary file.
        strings: Optional list of string literals to verify.
        addresses: Optional list of virtual addresses to verify.
        include_context: Whether to include instruction disassembly context.
        limit: Maximum strings to evaluate when analyzing default binary strings.

    Returns:
        ToolResult with classified string usage (referenced, unreferenced, ambiguous, unresolved).
    """
    try:
        validated_path = validate_file_path(file_path, read_only=True)
        if not validated_path.is_file():
            raise ValueError(f"Path is not a regular file: {validated_path}")
    except Exception as exc:
        return failure(
            "VALIDATION_ERROR",
            str(exc),
            recovery_hint="Provide a valid, existing binary file path within the workspace.",
        )

    try:
        loop = asyncio.get_running_loop()
        result_data = await loop.run_in_executor(
            None,
            _perform_string_verification,
            str(validated_path),
            strings,
            addresses,
            include_context,
            limit,
        )
        return success(
            data=result_data,
            meta={"engine": "radare2", "analysis_type": "string_code_reference_verification"},
        )
    except Exception as exc:
        logger.error("Failed to verify string references in %s: %s", file_path, exc, exc_info=True)
        return failure(
            "ANALYSIS_FAILED",
            f"String reference verification failed: {exc}",
            recovery_hint="Verify that Radare2 is installed and that the file is an executable binary.",
        )
