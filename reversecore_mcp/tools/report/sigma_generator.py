import uuid
from datetime import datetime
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success


def _generate_sigma_yaml(
    title: str,
    description: str,
    logsource: dict[str, str],
    detection: dict[str, Any],
    condition: str,
    level: str = "medium",
    author: str = "Reversecore_MCP",
) -> str:
    """Helper to format Sigma rule to YAML string."""
    rule_id = str(uuid.uuid4())
    date_str = datetime.now().strftime("%Y/%m/%d")

    # We construct YAML manually to ensure it meets standard formatting
    # and to avoid strict PyYAML dependency requirements for this simple structure.
    yaml_lines = [
        f'title: "{title}"',
        f"id: {rule_id}",
        "status: experimental",
        f'description: "{description}"',
        f'author: "{author}"',
        f"date: {date_str}",
        "logsource:",
    ]

    for k, v in logsource.items():
        yaml_lines.append(f"    {k}: {v}")

    yaml_lines.append("detection:")

    for key, value in detection.items():
        yaml_lines.append(f"    {key}:")
        if isinstance(value, dict):
            for sub_k, sub_v in value.items():
                if isinstance(sub_v, list):
                    yaml_lines.append(f"        {sub_k}:")
                    for item in sub_v:
                        yaml_lines.append(f'            - "{item}"')
                else:
                    yaml_lines.append(f'        {sub_k}: "{sub_v}"')
        elif isinstance(value, list):
            for item in value:
                yaml_lines.append(f'        - "{item}"')
        else:
            yaml_lines.append(f'        "{value}"')

    yaml_lines.append(f"    condition: {condition}")
    yaml_lines.append(f"level: {level}")

    return "\n".join(yaml_lines)


@log_execution(tool_name="generate_sigma_rule")
@track_metrics("generate_sigma_rule")
@handle_tool_errors
async def generate_sigma_rule(
    title: str,
    iocs: list[str] | None = None,
    api_calls: list[str] | None = None,
    category: str = "process_creation",
    product: str = "windows",
    level: str = "medium",
    description: str = "Auto-generated Sigma rule based on binary analysis",
) -> ToolResult:
    """
    Generate a Sigma rule (YAML) for SIEM integration based on extracted IOCs or API calls.

    Args:
        title: Title of the Sigma rule
        iocs: List of IP addresses, URLs, or file hashes to detect
        api_calls: List of API functions to detect (e.g., VirtualAlloc, CreateRemoteThread)
        category: Logsource category (e.g., process_creation, network_connection)
        product: Logsource product (e.g., windows, linux)
        level: Severity level (low, medium, high, critical)
        description: Description of the rule

    Returns:
        ToolResult with the generated Sigma YAML string.
    """
    if not iocs and not api_calls:
        return failure(
            "VALIDATION_ERROR",
            "At least one of 'iocs' or 'api_calls' must be provided to generate a detection rule.",
        )

    if level not in ["low", "medium", "high", "critical"]:
        return failure("VALIDATION_ERROR", "Level must be low, medium, high, or critical.")

    logsource = {"category": category, "product": product}

    detection: dict[str, Any] = {}
    condition_parts = []

    if iocs:
        # Simplistic heuristic to divide IOCs
        ips = [i for i in iocs if i.replace(".", "").isdigit()]
        hashes = [i for i in iocs if len(i) in (32, 40, 64) and i.isalnum()]
        others = [i for i in iocs if i not in ips and i not in hashes]

        selection_ioc = {}
        if ips:
            selection_ioc["DestinationIp"] = ips
        if hashes:
            selection_ioc["Hashes"] = hashes
        if others:
            # Assuming remaining IOCs might be domains/URLs or filenames
            selection_ioc["CommandLine|contains"] = others

        if selection_ioc:
            detection["selection_iocs"] = selection_ioc
            condition_parts.append("selection_iocs")

    if api_calls:
        # Map API calls to typical sysmon or API monitor logs
        selection_api = {"CallTrace|contains": api_calls}
        detection["selection_apis"] = selection_api
        condition_parts.append("selection_apis")

    if not detection:
        return failure(
            "PROCESSING_ERROR", "Could not map provided inputs to Sigma detection logic."
        )

    # Combine conditions using OR if both are present
    condition = " or ".join(condition_parts)

    try:
        yaml_output = _generate_sigma_yaml(
            title=title,
            description=description,
            logsource=logsource,
            detection=detection,
            condition=condition,
            level=level,
        )
    except Exception as e:
        return failure("GENERATION_ERROR", f"Failed to format Sigma YAML: {e}")

    return success(
        {"rule_title": title, "sigma_yaml": yaml_output, "format": "sigma", "category": category}
    )
