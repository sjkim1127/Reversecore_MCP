"""YARA scanning tools for binary analysis with rule matching."""

from typing import Any, Dict, List, Optional, Protocol, Tuple

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters

# Global cache for compiled YARA rules: {file_path: (timestamp, compiled_rules)}
_YARA_RULES_CACHE: Dict[str, Tuple[float, Any]] = {}


class YaraStringMatchInstance(Protocol):
    """Subset of yara.StringMatchInstance used by our formatter."""

    offset: Optional[int]
    matched_data: Optional[bytes]


class YaraStringMatch(Protocol):
    """Subset of yara.StringMatch used by our formatter."""

    identifier: Optional[str]
    instances: Optional[List[YaraStringMatchInstance]]


class YaraMatch(Protocol):
    """Subset of yara.Match used by our formatter."""

    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: Optional[List[YaraStringMatch]]


def _format_yara_match(match: YaraMatch) -> Dict[str, Any]:
    """
    Format a YARA match result as a dictionary.

    This helper function extracts match information and formats it
    consistently. Supports both modern and legacy yara-python APIs.

    Args:
        match: YARA match object

    Returns:
        Dictionary with formatted match information
    """
    formatted_strings = []

    # Check if match has strings attribute
    match_strings = getattr(match, "strings", None)
    if match_strings:
        try:
            # OPTIMIZATION: Cache isinstance check and reduce getattr calls
            # Try modern API first (more common case)
            for sm in match_strings:
                identifier = getattr(sm, "identifier", None)
                instances = getattr(sm, "instances", None)
                if instances:
                    # Pre-cache the formatted string for reuse
                    for inst in instances:
                        offset = getattr(inst, "offset", None)
                        matched_data = getattr(inst, "matched_data", None)
                        # Convert matched_data to string (optimized with early check)
                        if matched_data is None:
                            data_str = None
                        else:
                            # Single isinstance check instead of repeated checks
                            data_str = matched_data.hex() if isinstance(matched_data, bytes) else str(matched_data)

                        formatted_strings.append(
                            {
                                "identifier": identifier,
                                "offset": int(offset) if offset is not None else None,
                                "matched_data": data_str,
                            }
                        )
        except (AttributeError, TypeError):
            # Fallback: older API may return tuples (offset, identifier, data)
            formatted_strings = []
            for t in match_strings:
                if isinstance(t, (list, tuple)) and len(t) >= 3:
                    off, ident, data = t[0], t[1], t[2]
                    data_str = data.hex() if isinstance(data, bytes) else str(data)
                    formatted_strings.append(
                        {
                            "identifier": ident,
                            "offset": int(off) if off is not None else None,
                            "matched_data": data_str,
                        }
                    )

    return {
        "rule": match.rule,
        "namespace": match.namespace,
        "tags": match.tags,
        "meta": match.meta,
        "strings": formatted_strings,
    }


@log_execution(tool_name="run_yara")
@track_metrics("run_yara")
@handle_tool_errors
def run_yara(
    file_path: str,
    rule_file: str,
    timeout: int = 300,
) -> ToolResult:
    """Scan binaries against YARA rules via ``yara-python``."""

    validate_tool_parameters(
        "run_yara",
        {"rule_file": rule_file, "timeout": timeout},
    )
    validated_file = validate_file_path(file_path)
    validated_rule = validate_file_path(rule_file, read_only=True)

    try:
        import yara
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "yara-python library is not installed",
            hint="Install with: pip install yara-python",
        )

    timeout_error = getattr(yara, "TimeoutError", None)
    generic_error = getattr(yara, "Error", None)

    # Check cache for compiled rules
    rule_path_str = str(validated_rule)
    current_mtime = validated_rule.stat().st_mtime

    rules = None
    if rule_path_str in _YARA_RULES_CACHE:
        cached_mtime, cached_rules = _YARA_RULES_CACHE[rule_path_str]
        if cached_mtime == current_mtime:
            rules = cached_rules

    if rules is None:
        try:
            rules = yara.compile(filepath=rule_path_str)
            # Update cache
            _YARA_RULES_CACHE[rule_path_str] = (current_mtime, rules)
        except Exception as exc:  # noqa: BLE001 - need yara-specific surface area
            # Try fallback for non-ASCII paths on Windows
            try:
                # Read rule content and compile from source
                rule_content = validated_rule.read_text(encoding="utf-8")
                rules = yara.compile(source=rule_content)
                _YARA_RULES_CACHE[rule_path_str] = (current_mtime, rules)
            except Exception:
                # If fallback fails, report original error
                if generic_error and isinstance(exc, generic_error):
                    return failure("YARA_ERROR", f"YARA error: {exc}")
                raise

    try:
        matches = rules.match(str(validated_file), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - need to inspect yara-specific errors
        # Check for timeout first
        if timeout_error and isinstance(exc, timeout_error):
            return failure(
                "TIMEOUT",
                f"YARA scan timed out after {timeout} seconds",
                timeout_seconds=timeout,
                details={"error": str(exc)},
            )

        # For any other error (including "Illegal byte sequence" on Windows),
        # try fallback to memory scan if file size permits
        file_size = 0
        try:
            file_size = validated_file.stat().st_size
        except Exception:
            pass

        if file_size < 100 * 1024 * 1024:
            try:
                data = validated_file.read_bytes()
                matches = rules.match(data=data, timeout=timeout)
            except Exception as fallback_exc:
                # If fallback fails, return the original error
                if generic_error and isinstance(exc, generic_error):
                    return failure("YARA_ERROR", f"Fallback failed: {fallback_exc}. Original: {exc}")
                raise
        else:
            if generic_error and isinstance(exc, generic_error):
                return failure("YARA_ERROR", f"YARA error: {exc}")
            raise

    if not matches:
        return success({"matches": [], "match_count": 0})

    results = [_format_yara_match(match) for match in matches]
    return success({"matches": results, "match_count": len(matches)})
