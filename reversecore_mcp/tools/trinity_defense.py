"""
Trinity Defense System: Integrated Automated Defense Framework.

This orchestrator coordinates three signature technologies:
1. Ghost Trace - Discovers hidden threats
2. Neural Decompiler - Understands threat intent
3. Adaptive Vaccine - Neutralizes threats

Architecture: DISCOVER → UNDERSTAND → NEUTRALIZE
"""

import asyncio
from typing import Dict, Any, List, Tuple

from fastmcp import FastMCP, Context
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.security import validate_file_path

# Import the three signature tools
from reversecore_mcp.tools.ghost_trace import ghost_trace
from reversecore_mcp.tools.neural_decompiler import neural_decompile
from reversecore_mcp.tools.adaptive_vaccine import adaptive_vaccine

logger = get_logger(__name__)


def register_trinity_defense(mcp: FastMCP) -> None:
    """Register the Trinity Defense System with the FastMCP server."""
    mcp.tool(trinity_defense)


@log_execution(tool_name="trinity_defense")
async def trinity_defense(
    file_path: str,
    mode: str = "full",
    max_threats: int = 5,
    generate_vaccine: bool = True,
    ctx: Context = None,
) -> ToolResult:
    """
    Trinity Defense System - Full-cycle automated threat detection and neutralization.

    This orchestrator runs a 3-phase pipeline:
    - Phase 1 (DISCOVER): Ghost Trace finds hidden threats
    - Phase 2 (UNDERSTAND): Neural Decompiler analyzes threat intent
    - Phase 3 (NEUTRALIZE): Adaptive Vaccine generates defenses

    Modes:
    - "discover": Phase 1 only (Ghost Trace)
    - "analyze": Phase 1+2 (Ghost Trace + Neural Decompiler)
    - "full": All 3 phases (+ Adaptive Vaccine)

    Args:
        file_path: Path to the binary to analyze
        mode: Analysis mode ("discover", "analyze", or "full")
        max_threats: Maximum number of threats to analyze in detail (default: 5)
        generate_vaccine: Whether to generate YARA rules (default: True)

    Returns:
        ToolResult containing comprehensive threat report
    """
    validated_path = validate_file_path(file_path)

    if ctx:
        await ctx.info("🔱 Trinity Defense System: Initiating full-spectrum analysis...")
        await ctx.info(f"📁 Target: {validated_path.name}")
        await ctx.info(f"⚙️ Mode: {mode.upper()}")

    # ============================================================
    # PHASE 1: DISCOVER - Ghost Trace
    # ============================================================
    if ctx:
        await ctx.info("\\n🔍 PHASE 1: DISCOVER (Ghost Trace)")

    try:
        ghost_result = await ghost_trace(file_path=str(validated_path), ctx=ctx)

        # Check if ghost_trace returned an error
        if ghost_result.status == "error":
            return failure(error_code="GHOST_TRACE_FAILED", message=f"Phase 1 failed: {ghost_result.message}")

        # Extract threats from ToolResult.data
        ghost_data = ghost_result.data
        orphan_functions = ghost_data.get("orphan_functions", [])
        suspicious_logic = ghost_data.get("suspicious_logic", [])
        all_threats = orphan_functions + suspicious_logic

        if not all_threats:
            return success({"status": "clean", "message": "No threats detected by Ghost Trace", "phases_completed": 1})

        logger.info(f"Phase 1 complete: {len(all_threats)} threats discovered")

        if mode == "discover":
            return success(
                {
                    "status": "discovery_complete",
                    "threats_discovered": len(all_threats),
                    "threats": all_threats,
                    "phases_completed": 1,
                }
            )

    except Exception as e:
        return failure(error_code="GHOST_TRACE_ERROR", message=f"Phase 1 (Ghost Trace) failed: {str(e)}")

    # ============================================================
    # PHASE 2: UNDERSTAND - Neural Decompiler
    # ============================================================
    if ctx:
        await ctx.info("\\n🧠 PHASE 2: UNDERSTAND (Neural Decompiler)")
        await ctx.info(f"📊 Analyzing top {min(max_threats, len(all_threats))} threats...")

    refined_threats = []

    try:
        # Analyze top N threats in parallel for better performance
        tasks = []
        for threat in all_threats[:max_threats]:
            task = neural_decompile(
                file_path=str(validated_path),
                function_address=threat.get("address", "0x0"),
                ctx=None,  # Suppress nested context messages
            )
            tasks.append((threat, task))

        # Execute all decompilations in parallel
        if ctx:
            await ctx.info("  🔄 Parallel analysis in progress...")

        results = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)

        # Process results
        for i, ((threat, _), result) in enumerate(zip(tasks, results)):
            if ctx:
                await ctx.info(f"  [{i+1}/{len(tasks)}] Processed {threat.get('function', threat.get('address'))}")

            if isinstance(result, Exception):
                logger.warning(f"Failed to analyze {threat.get('address')}: {result}")
                refined_threats.append({**threat, "error": str(result), "intent": "unknown", "confidence": 0.0})
            elif result.status != "error":
                # Infer intent from refined code with confidence
                intent, confidence = _infer_intent_with_confidence(neural_result=result.data, threat_info=threat)

                refined_threats.append(
                    {
                        **threat,
                        "refined_code": result.data.get("neural_code", ""),
                        "intent": intent,
                        "confidence": confidence,
                        "refinement_stats": result.data.get("refinement_stats", {}),
                    }
                )
            else:
                refined_threats.append(
                    {**threat, "error": "Decompilation failed", "intent": "unknown", "confidence": 0.0}
                )

        logger.info(f"Phase 2 complete: {len(refined_threats)} threats analyzed")

        if mode == "analyze":
            return success(
                {
                    "status": "analysis_complete",
                    "threats_discovered": len(all_threats),
                    "threats_analyzed": refined_threats,
                    "phases_completed": 2,
                }
            )

    except Exception as e:
        return failure(error_code="NEURAL_DECOMPILER_ERROR", message=f"Phase 2 (Neural Decompiler) failed: {str(e)}")

    # ============================================================
    # PHASE 3: NEUTRALIZE - Adaptive Vaccine
    # ============================================================
    if ctx:
        await ctx.info("\\n🛡️ PHASE 3: NEUTRALIZE (Adaptive Vaccine)")

    defenses = []

    try:
        if generate_vaccine:
            for i, threat in enumerate(refined_threats):
                if ctx:
                    await ctx.info(
                        f"  [{i+1}/{len(refined_threats)}] Generating defense for {threat.get('function', threat.get('address'))}..."
                    )

                try:
                    vaccine_result = await adaptive_vaccine(
                        threat_report=threat,
                        action="yara",  # Generate YARA rule only (patch is risky)
                        dry_run=True,
                        ctx=None,
                    )

                    if vaccine_result.status != "error":
                        defenses.append(vaccine_result.data)
                except Exception as e:
                    logger.warning(f"Failed to generate vaccine for {threat.get('address')}: {e}")

        logger.info(f"Phase 3 complete: {len(defenses)} defenses generated")

    except Exception as e:
        return failure(error_code="ADAPTIVE_VACCINE_ERROR", message=f"Phase 3 (Adaptive Vaccine) failed: {str(e)}")

    # ============================================================
    # FINAL REPORT
    # ============================================================
    if ctx:
        await ctx.info("\\n✅ Trinity Defense System: Analysis complete")
        await ctx.info(
            f"📊 Summary: {len(all_threats)} threats discovered, {len(refined_threats)} analyzed, {len(defenses)} defenses generated"
        )

    return success(
        {
            "status": "full_analysis_complete",
            "phases_completed": 3,
            "summary": {
                "threats_discovered": len(all_threats),
                "threats_analyzed": len(refined_threats),
                "defenses_generated": len(defenses),
            },
            "phase_1_discover": {
                "orphan_functions": len(orphan_functions),
                "suspicious_logic": len(suspicious_logic),
                "total_threats": len(all_threats),
            },
            "phase_2_understand": refined_threats,
            "phase_3_neutralize": defenses,
            "recommendations": _generate_recommendations(refined_threats),
        }
    )


def _infer_intent_with_confidence(neural_result: Dict[str, Any], threat_info: Dict[str, Any]) -> Tuple[str, float]:
    """Infer threat intent with confidence score using context-aware analysis.

    Args:
        neural_result: Result from Neural Decompiler
        threat_info: Original threat information

    Returns:
        Tuple of (intent, confidence_score)
    """
    code = neural_result.get("neural_code", "").lower()
    reason = threat_info.get("reason", "").lower()

    # Score-based detection with context awareness
    scores = {}

    # Backdoor: network operations with suspicious context
    if "socket" in code or "connect" in code:
        if "listen" in code and "accept" in code:
            scores["backdoor"] = 0.3  # Could be normal server
        elif "connect" in code and ("send" in code or "recv" in code):
            scores["backdoor"] = 0.85  # Outbound connection
            # Boost if found in orphan function
            if "orphan" in reason or "no.*ref" in reason:
                scores["backdoor"] = 0.95

    # File deletion: destructive file operations
    if any(kw in code for kw in ["unlink", "remove", "delete"]):
        scores["file_deletion"] = 0.75
        # Boost if has rm -rf pattern
        if "rm -rf" in code or "rmdir" in code:
            scores["file_deletion"] = 0.95

    # Time bomb: temporal checks + destructive actions
    if any(kw in code for kw in ["time", "date", "clock"]):
        if any(kw in code for kw in ["delete", "unlink", "format", "system"]):
            scores["time_bomb"] = 0.9  # High confidence
        elif "cmp" in code or "magic" in reason:
            scores["time_bomb"] = 0.7  # Temporal comparison
        else:
            scores["time_bomb"] = 0.2  # Just time check

    # Data exfiltration: send + network
    if any(kw in code for kw in ["send", "sendto", "write"]):
        if any(kw in code for kw in ["socket", "http", "ftp"]):
            scores["data_exfiltration"] = 0.8

    # Persistence: registry/startup modifications
    if any(kw in code for kw in ["regsetvalue", "regcreatekey"]):
        if any(kw in code for kw in ["run", "startup", "autorun"]):
            scores["persistence"] = 0.9
        else:
            scores["persistence"] = 0.6

    # Credential theft
    if any(kw in code for kw in ["password", "credential", "token", "cookie"]):
        scores["credential_theft"] = 0.7

    # Encryption/Ransomware
    if any(kw in code for kw in ["aes", "rsa", "encrypt", "cipher"]):
        if "file" in code or "directory" in code:
            scores["encryption"] = 0.85  # Possible ransomware
        else:
            scores["encryption"] = 0.5  # Just encryption usage

    # Process injection
    if any(kw in code for kw in ["createremotethread", "writeprocessmemory"]):
        scores["process_injection"] = 0.9

    # Privilege escalation
    if any(kw in code for kw in ["runas", "uac", "admin", "elevate"]):
        scores["privilege_escalation"] = 0.75

    # Keylogger
    if any(kw in code for kw in ["getkeystate", "keyboard", "keypress"]):
        scores["keylogger"] = 0.85

    # Return highest confidence intent
    if not scores:
        return "unknown_behavior", 0.0

    intent, confidence = max(scores.items(), key=lambda x: x[1])

    # If multiple high-confidence intents, mark as multi-stage
    high_conf_intents = [i for i, c in scores.items() if c >= 0.7]
    if len(high_conf_intents) > 1:
        combined_conf = sum(scores[i] for i in high_conf_intents) / len(high_conf_intents)
        return f"multi_stage_attack({','.join(high_conf_intents)})", combined_conf

    return intent, confidence


def _infer_intent(code: str) -> str:
    """
    Infer threat intent from refined code using heuristic pattern matching.

    Args:
        code: Refined code from Neural Decompiler

    Returns:
        Intent classification string
    """
    code_lower = code.lower()

    # Pattern matching for common malicious behaviors
    patterns = {
        "file_deletion": ["unlink", "remove", "delete", "rm -rf"],
        "backdoor": ["socket", "connect", "bind", "listen", "accept"],
        "data_exfiltration": ["send", "sendto", "ftp", "http"],
        "persistence": ["regsetvalue", "createfile", "startup", "autorun"],
        "credential_theft": ["password", "credential", "cookie", "token"],
        "encryption": ["aes", "rsa", "encrypt", "cipher"],
        "time_bomb": ["time", "date", "sleep", "delay"],
        "keylogger": ["getkeystate", "keyboard", "keypress"],
        "process_injection": ["createremotethread", "writeprocessmemory"],
        "privilege_escalation": ["runas", "uac", "admin", "elevate"],
    }

    detected_intents = []
    for intent, keywords in patterns.items():
        if any(keyword in code_lower for keyword in keywords):
            detected_intents.append(intent)

    if not detected_intents:
        return "unknown_behavior"
    elif len(detected_intents) == 1:
        return detected_intents[0]
    else:
        return f"multi_stage_attack({','.join(detected_intents)})"


def _generate_recommendations(threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate detailed, actionable recommendations based on discovered threats.

    Args:
        threats: List of analyzed threats

    Returns:
        List of detailed recommendation dictionaries
    """
    recommendations = []

    # Group threats by intent
    intent_groups = {}
    for threat in threats:
        intent = threat.get("intent", "unknown")
        confidence = threat.get("confidence", 0.0)

        # Only process high-confidence threats
        if confidence >= 0.5:
            if intent not in intent_groups:
                intent_groups[intent] = []
            intent_groups[intent].append(threat)

    # Generate specific recommendations per intent type
    for intent, threat_list in intent_groups.items():
        if "backdoor" in intent:
            for threat in threat_list:
                recommendations.append(
                    {
                        "severity": "CRITICAL",
                        "threat_type": "Backdoor",
                        "location": f"{threat.get('function', 'unknown')} @ {threat.get('address')}",
                        "confidence": threat.get("confidence", 0.0),
                        "immediate_actions": [
                            "🚨 ISOLATE: Disconnect system from network immediately",
                            f"🔒 BLOCK: Add firewall rule to deny all traffic from binary at {threat.get('address')}",
                            "📊 MONITOR: Enable network traffic logging to identify C2 servers",
                            "🛡️ DEPLOY: Apply generated YARA rule to all endpoints",
                        ],
                        "investigation": [
                            "Check network logs for suspicious outbound connections",
                            "Identify C2 server IP addresses from connection attempts",
                            "Examine all files created/modified by this process",
                        ],
                        "remediation": [
                            f"Binary patch: NOP out backdoor code at {threat.get('address')}",
                            "Rebuild system from known-good backup",
                            "Update IDS/IPS signatures with IOCs",
                        ],
                    }
                )

        elif "time_bomb" in intent:
            for threat in threat_list:
                recommendations.append(
                    {
                        "severity": "HIGH",
                        "threat_type": "Logic Bomb / Time Bomb",
                        "location": f"{threat.get('function', 'unknown')} @ {threat.get('address')}",
                        "confidence": threat.get("confidence", 0.0),
                        "immediate_actions": [
                            "⏰ URGENT: Check system date/time to determine if trigger condition is imminent",
                            f"🔧 PATCH: Apply NOP patch at {threat.get('address')} to disable trigger logic",
                            "💾 BACKUP: Create full system backup before trigger date",
                            "👁️ MONITOR: Set up alerting for unusual system behavior",
                        ],
                        "investigation": [
                            f"Analyze trigger condition in code: {threat.get('instruction', 'N/A')}",
                            "Determine exact trigger date/time from magic value comparison",
                            "Test behavior in isolated sandbox with trigger condition met",
                        ],
                        "remediation": [
                            "Replace conditional jump with unconditional or NOP",
                            "Remove entire logic bomb function from binary",
                            "Keep offline backup until past trigger date",
                        ],
                    }
                )

        elif "file_deletion" in intent:
            for threat in threat_list:
                recommendations.append(
                    {
                        "severity": "CRITICAL",
                        "threat_type": "Destructive File Operations",
                        "location": f"{threat.get('function', 'unknown')} @ {threat.get('address')}",
                        "confidence": threat.get("confidence", 0.0),
                        "immediate_actions": [
                            "💾 BACKUP: Immediately backup all critical data",
                            "🔒 PROTECT: Enable file system write protection where possible",
                            "🛑 QUARANTINE: Isolate affected system to prevent data loss",
                            "📋 SNAPSHOT: Create VM snapshot if running in virtual environment",
                        ],
                        "investigation": [
                            "Identify target files/directories from code analysis",
                            "Check if deletion has already occurred",
                            "Examine file system audit logs for deletion attempts",
                        ],
                        "remediation": [
                            f"Binary patch: NOP out file deletion calls at {threat.get('address')}",
                            "Restore deleted files from backup if necessary",
                            "Implement file integrity monitoring (FIM)",
                        ],
                    }
                )

        elif "data_exfiltration" in intent:
            for threat in threat_list:
                recommendations.append(
                    {
                        "severity": "HIGH",
                        "threat_type": "Data Exfiltration",
                        "location": f"{threat.get('function', 'unknown')} @ {threat.get('address')}",
                        "confidence": threat.get("confidence", 0.0),
                        "immediate_actions": [
                            "🌐 NETWORK: Enable DLP (Data Loss Prevention) policies",
                            "🚫 EGRESS: Block outbound connections from this binary",
                            "📊 CAPTURE: Enable packet capture on affected network segment",
                            "🔐 ENCRYPT: Ensure sensitive data at rest is encrypted",
                        ],
                        "investigation": [
                            "Analyze network traffic for data exfiltration patterns",
                            "Identify what data was accessed before transmission",
                            "Determine exfiltration destination (IP, domain, protocol)",
                        ],
                        "remediation": [
                            "Block destination IPs/domains at firewall level",
                            "Rotate compromised credentials if leaked",
                            "Implement network segmentation to limit data access",
                        ],
                    }
                )

    # Add summary recommendation if multiple threats
    if len(recommendations) > 1:
        recommendations.insert(
            0,
            {
                "severity": "CRITICAL",
                "threat_type": "Multiple Threats Detected",
                "location": "System-wide",
                "confidence": 1.0,
                "immediate_actions": [
                    f"⚠️ {len(recommendations)} distinct threats identified in this binary",
                    "🔴 Treat as Advanced Persistent Threat (APT) - coordinate response",
                    "📞 Escalate to security incident response team",
                    "🔒 Isolate all affected systems immediately",
                ],
                "investigation": [
                    "Conduct full forensic analysis of affected systems",
                    "Check for lateral movement to other systems",
                    "Timeline analysis to determine initial infection vector",
                ],
                "remediation": [
                    "Complete system rebuild recommended",
                    "Deploy all generated YARA rules across organization",
                    "Review and update security controls to prevent re-infection",
                ],
            },
        )
    elif not recommendations:
        recommendations.append(
            {
                "severity": "INFO",
                "threat_type": "No High-Confidence Threats",
                "location": "N/A",
                "confidence": 0.0,
                "immediate_actions": [
                    "✅ No immediate action required",
                    "👁️ Continue monitoring with deployed YARA rules",
                    "📊 Review low-confidence findings manually",
                ],
                "investigation": ["Periodic rescans recommended", "Keep YARA rules updated"],
                "remediation": [],
            }
        )

    return recommendations
