import ipaddress
import json
import re
import uuid
from datetime import datetime
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success

_HASH_LENGTHS = {32, 40, 64}
_IPV4_CANDIDATE = re.compile(r"\d+(?:\.\d+){3}\Z")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]+\Z")
_LOGSOURCE_KEYS = {"category", "product", "service", "definition"}
_LOGSOURCE_KEY_PATTERN = re.compile(r"[a-z][a-z0-9_]*\Z")
_SELECTOR_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_FIELD_PATTERN = re.compile(r"[A-Za-z0-9_@.-]+(?:\|[A-Za-z_][A-Za-z0-9_]*)?\Z")


def _quote_yaml_scalar(value: str) -> str:
    """Quote a string using JSON escapes, which are valid YAML double-quoted scalars."""
    if not isinstance(value, str):
        raise ValueError("Sigma YAML scalar values must be strings.")

    quoted = json.dumps(value, ensure_ascii=False)

    # YAML treats these Unicode separators as line breaks; escape them so they
    # remain part of the scalar just like JSON's escaped ASCII control chars.
    def escape_yaml_non_printable(character: str) -> str:
        codepoint = ord(character)
        if (
            codepoint in {0x0085, 0x2028, 0x2029, 0xFFFE, 0xFFFF}
            or 0x007F <= codepoint <= 0x0084
            or 0x0086 <= codepoint <= 0x009F
            or 0xD800 <= codepoint <= 0xDFFF
        ):
            return f"\\u{codepoint:04x}"
        return character

    return "".join(escape_yaml_non_printable(character) for character in quoted)


def _validate_string_list(name: str, values: list[str] | None) -> list[str]:
    """Validate a public list of text indicators without changing their contents."""
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list of non-empty strings.")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{name} must contain only non-empty strings.")
    return values


def _validate_sigma_inputs(
    title: str,
    description: str,
    logsource: dict[str, str],
    detection: dict[str, Any],
    condition: str,
    level: str,
    author: str,
) -> None:
    """Validate the structure and types accepted by the Sigma YAML formatter."""
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Title must be a non-empty string.")
    if not isinstance(description, str) or not isinstance(author, str):
        raise ValueError("Description and author must be strings.")
    if not isinstance(level, str) or level not in {"low", "medium", "high", "critical"}:
        raise ValueError("Level must be low, medium, high, or critical.")

    if not isinstance(logsource, dict) or not {"category", "product"}.issubset(logsource):
        raise ValueError("Logsource must include category and product string values.")
    if set(logsource) - _LOGSOURCE_KEYS:
        raise ValueError("Logsource contains an unsupported key.")
    for key, value in logsource.items():
        if (
            not isinstance(key, str)
            or not _LOGSOURCE_KEY_PATTERN.fullmatch(key)
            or not isinstance(value, str)
            or not value.strip()
        ):
            raise ValueError("Logsource keys and values must be valid non-empty strings.")

    if not isinstance(detection, dict) or not detection or "condition" in detection:
        raise ValueError(
            "Detection must contain at least one selection and cannot define condition."
        )
    for selector, fields in detection.items():
        if not isinstance(selector, str) or not _SELECTOR_PATTERN.fullmatch(selector):
            raise ValueError("Detection selection names must be identifiers.")
        if not isinstance(fields, dict) or not fields:
            raise ValueError("Each detection selection must contain fields.")
        for field, values in fields.items():
            if not isinstance(field, str) or not _FIELD_PATTERN.fullmatch(field):
                raise ValueError("Detection field names must be valid Sigma field identifiers.")
            if isinstance(values, list):
                if not values or any(not isinstance(value, str) for value in values):
                    raise ValueError("Detection field lists must contain strings.")
            elif not isinstance(values, str):
                raise ValueError("Detection field values must be strings or lists of strings.")

    if not isinstance(condition, str) or not condition:
        raise ValueError("Condition must reference a detection selection.")
    condition_selectors = condition.split(" or ")
    if any(
        not _SELECTOR_PATTERN.fullmatch(selector) or selector not in detection
        for selector in condition_selectors
    ) or len(set(condition_selectors)) != len(condition_selectors):
        raise ValueError(
            "Condition must reference existing selection identifiers joined with 'or'."
        )


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
    _validate_sigma_inputs(title, description, logsource, detection, condition, level, author)

    rule_id = str(uuid.uuid4())
    date_str = datetime.now().strftime("%Y/%m/%d")

    # JSON-quoted strings use escapes that YAML accepts and prevent user values
    # from changing the generated document structure.
    yaml_lines = [
        f"title: {_quote_yaml_scalar(title)}",
        f"id: {_quote_yaml_scalar(rule_id)}",
        "status: experimental",
        f"description: {_quote_yaml_scalar(description)}",
        f"author: {_quote_yaml_scalar(author)}",
        f"date: {date_str}",
        "logsource:",
    ]

    for k, v in logsource.items():
        yaml_lines.append(f"    {k}: {_quote_yaml_scalar(v)}")

    yaml_lines.append("detection:")

    for selector, fields in detection.items():
        yaml_lines.append(f"    {selector}:")
        for field, values in fields.items():
            if isinstance(values, list):
                yaml_lines.append(f"        {field}:")
                for item in values:
                    yaml_lines.append(f"            - {_quote_yaml_scalar(item)}")
            else:
                yaml_lines.append(f"        {field}: {_quote_yaml_scalar(values)}")

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
    try:
        iocs = _validate_string_list("iocs", iocs)
        api_calls = _validate_string_list("api_calls", api_calls)
    except ValueError as e:
        return failure("VALIDATION_ERROR", str(e))

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
        # Classify only valid IP addresses and supported hexadecimal digest sizes.
        ips: list[str] = []
        hashes: list[str] = []
        others: list[str] = []
        for ioc in iocs:
            try:
                ipaddress.ip_address(ioc)
                ips.append(ioc)
                continue
            except ValueError:
                if _IPV4_CANDIDATE.fullmatch(ioc) or (
                    ioc.count(":") >= 2 and _IPV6_CANDIDATE.fullmatch(ioc)
                ):
                    return failure(
                        "VALIDATION_ERROR",
                        "IOC entries that look like IP addresses must use valid IPv4 or IPv6 syntax.",
                    )

            if len(ioc) in _HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", ioc):
                hashes.append(ioc)
            else:
                others.append(ioc)

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
            "PROCESSING_ERROR",
            "Could not map provided inputs to Sigma detection logic.",
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
    except ValueError as e:
        return failure("VALIDATION_ERROR", str(e))
    except Exception as e:
        return failure("GENERATION_ERROR", f"Failed to format Sigma YAML: {e}")

    return success(
        {
            "rule_title": title,
            "sigma_yaml": yaml_output,
            "format": "sigma",
            "category": category,
        }
    )
