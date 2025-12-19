"""
CAPA integration for capability detection.

CAPA (by Mandiant FLARE) identifies capabilities in executable files,
providing high-level behavioral information like encryption, file deletion, etc.
"""

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import success, failure, ToolSuccess
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


def _is_capa_available() -> bool:
    """Check if CAPA library is available."""
    try:
        import capa  # noqa: F401

        return True
    except ImportError:
        return False


@log_execution()
async def run_capa(file_path: str, output_format: str = "summary"):
    """
    Analyze binary capabilities using CAPA (Mandiant FLARE).

    CAPA identifies capabilities in executable files and provides high-level
    behavioral information such as:
    - "encrypt data using AES"
    - "delete files"
    - "communicate via HTTP"
    - "create persistence via registry"

    Args:
        file_path: Path to the binary file to analyze
        output_format: Output format - "summary" (default), "detailed", or "json"

    Returns:
        ToolResult with capability analysis including:
        - capabilities: List of detected capabilities
        - mitre_attack: MITRE ATT&CK technique mappings
        - mbc: Malware Behavior Catalog mappings
    """
    validated_path = validate_file_path(file_path)

    if not _is_capa_available():
        return failure(
            error_code="CAPA_NOT_INSTALLED",
            message="CAPA is not installed. Install with: pip install flare-capa",
        )

    try:
        import capa.loader
        import capa.main
        import capa.rules

        # Get default rules path
        rules_path = capa.main.get_default_root()

        # Load rules
        try:
            rules, _ = capa.rules.get_rules([rules_path])
        except Exception as e:
            # Falls back to no rules if default path fails
            logger.warning(f"Failed to load CAPA rules: {e}")
            return failure(
                error_code="CAPA_RULES_LOAD_FAILED",
                message=f"Failed to load CAPA rules. Run: capa --update-rules\nError: {e}",
            )

        # Analyze the file
        try:
            extractor = capa.loader.get_extractor(
                str(validated_path),
                "auto",  # Auto-detect format
                capa.main.BACKEND_VIV,  # Use vivisect backend
                [],  # No signatures
                False,  # Disable progress
            )
        except Exception as e:
            logger.error(f"CAPA failed to load file: {e}")
            return failure(
                error_code="CAPA_LOAD_FILE_FAILED",
                message=f"CAPA cannot analyze this file: {e}",
            )

        # Get capabilities
        capabilities, counts = capa.main.find_capabilities(rules, extractor)

        # Format results
        result = {
            "capabilities": [],
            "mitre_attack": [],
            "mbc": [],
            "summary": {
                "total_capabilities": len(capabilities),
                "namespaces": {},
            },
        }

        for rule_name, matches in capabilities.items():
            rule = rules[rule_name]

            capability = {
                "name": rule_name,
                "namespace": rule.meta.get("namespace", ""),
                "description": rule.meta.get("description", ""),
                "scope": rule.meta.get("scope", "function"),
                "match_count": len(matches),
            }

            # Extract MITRE ATT&CK
            if "att&ck" in rule.meta:
                for attack in rule.meta["att&ck"]:
                    if attack not in result["mitre_attack"]:
                        result["mitre_attack"].append(attack)

            # Extract MBC (Malware Behavior Catalog)
            if "mbc" in rule.meta:
                for mbc in rule.meta["mbc"]:
                    if mbc not in result["mbc"]:
                        result["mbc"].append(mbc)

            result["capabilities"].append(capability)

            # Count by namespace
            ns = capability["namespace"]
            result["summary"]["namespaces"][ns] = result["summary"]["namespaces"].get(ns, 0) + 1

        # Create summary message
        high_risk_namespaces = [
            "anti-analysis",
            "collection",
            "command-and-control",
            "defense-evasion",
            "exfiltration",
            "impact",
            "persistence",
        ]

        high_risk_count = sum(
            result["summary"]["namespaces"].get(ns, 0) for ns in high_risk_namespaces
        )

        message = f"Detected {len(capabilities)} capabilities"
        if high_risk_count > 0:
            message += f" ({high_risk_count} high-risk)"
        if result["mitre_attack"]:
            message += f", {len(result['mitre_attack'])} MITRE ATT&CK techniques"

        return success(
            data=result,
            message=message,
            high_risk_count=high_risk_count,
            mitre_count=len(result["mitre_attack"]),
        )

    except Exception as e:
        logger.error(f"CAPA analysis failed: {e}")
        return failure(error_code="CAPA_ANALYSIS_FAILED", message=f"CAPA analysis failed: {e}")


@log_execution()
async def run_capa_quick(file_path: str):
    """
    Quick CAPA scan returning only high-risk capabilities.

    Faster than full run_capa, focuses on:
    - Anti-analysis techniques
    - Persistence mechanisms
    - C2 communication
    - Data exfiltration
    - Impact capabilities

    Args:
        file_path: Path to the binary file

    Returns:
        ToolResult with high-risk capabilities only
    """
    result = await run_capa(file_path)

    if not isinstance(result, ToolSuccess):
        return result

    # Filter to high-risk only
    high_risk_namespaces = {
        "anti-analysis",
        "collection",
        "command-and-control",
        "defense-evasion",
        "exfiltration",
        "impact",
        "persistence",
        "execution",
    }

    filtered_caps = [
        cap
        for cap in result.data["capabilities"]
        if any(ns in cap["namespace"] for ns in high_risk_namespaces)
    ]

    return success(
        data={
            "high_risk_capabilities": filtered_caps,
            "mitre_attack": result.data["mitre_attack"],
            "total_filtered": len(filtered_caps),
        },
        message=f"{len(filtered_caps)} high-risk capabilities detected",
    )
