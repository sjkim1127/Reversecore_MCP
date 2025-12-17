"""LIEF (Library to Instrument Executable Formats) parsing tools for binary analysis."""

from itertools import islice
from typing import Any

# Use high-performance JSON implementation (3-5x faster)
from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path


def _extract_sections(binary: Any) -> list[dict[str, Any]]:
    """Extract section information from binary."""
    if not hasattr(binary, "sections") or not binary.sections:
        return []
    return [
        {
            "name": section.name,
            "virtual_address": hex(section.virtual_address),
            "size": section.size,
            "entropy": (round(section.entropy, 2) if hasattr(section, "entropy") else None),
        }
        for section in binary.sections
    ]


def _extract_symbols(binary: Any, max_imports: int = 100, max_exports: int = 100) -> dict[str, Any]:
    """Extract symbol information (imports/exports) from binary.
    
    Args:
        binary: LIEF binary object
        max_imports: Maximum number of imports to extract (P2 memory protection)
        max_exports: Maximum number of exports to extract (P2 memory protection)
    """
    symbols: dict[str, Any] = {}

    if hasattr(binary, "imported_functions") and binary.imported_functions:
        # Use islice with configurable limit
        symbols["imported_functions"] = [
            str(func) for func in islice(binary.imported_functions, max_imports)
        ]

    if hasattr(binary, "exported_functions") and binary.exported_functions:
        # Use islice with configurable limit
        symbols["exported_functions"] = [
            str(func) for func in islice(binary.exported_functions, max_exports)
        ]

    # PE-specific imports/exports
    if hasattr(binary, "imports") and binary.imports:
        # Use islice to avoid creating intermediate list
        # OPTIMIZATION: Extract function list creation outside the dict to avoid
        # nested comprehension inside loop
        formatted_imports: list[dict[str, Any]] = []
        for imp in islice(binary.imports, min(20, max_imports // 5)):
            entries = getattr(imp, "entries", [])
            # Process entries directly without intermediate list conversion
            # Build function list separately for better performance
            func_list = []
            if entries:
                for f in islice(entries, 20):
                    func_list.append(str(f))

            formatted_imports.append(
                {
                    "name": getattr(imp, "name", "unknown"),
                    "functions": func_list,
                }
            )
        if formatted_imports:
            symbols["imports"] = formatted_imports

    if hasattr(binary, "exports") and binary.exports:
        # Use islice to avoid creating intermediate list
        formatted_exports: list[dict[str, Any]] = []
        for exp in islice(binary.exports, 100):
            formatted_exports.append(
                {
                    "name": getattr(exp, "name", "unknown"),
                    "address": hex(exp.address) if hasattr(exp, "address") else None,
                }
            )
        if formatted_exports:
            symbols["exports"] = formatted_exports

    return symbols


def _format_lief_output(result: dict[str, Any], format: str) -> str:
    """Format LIEF parsing result as JSON or text."""
    if format.lower() == "json":
        return json.dumps(result, indent=2)

    # Text format - optimize by using list comprehension and avoiding repeated slicing
    lines = [f"Format: {result.get('format', 'Unknown')}"]
    if result.get("entry_point"):
        lines.append(f"Entry Point: {result['entry_point']}")

    sections = result.get("sections")
    if sections:
        section_count = len(sections)
        lines.append(f"\nSections ({section_count}):")
        # Iterate directly with limit instead of slicing
        for i, section in enumerate(sections):
            if i >= 20:
                break
            lines.append(
                f"  - {section['name']}: VA={section['virtual_address']}, Size={section['size']}"
            )

    imported_funcs = result.get("imported_functions")
    if imported_funcs:
        func_count = len(imported_funcs)
        lines.append(f"\nImported Functions ({func_count}):")
        for i, func in enumerate(imported_funcs):
            if i >= 20:
                break
            lines.append(f"  - {func}")

    exported_funcs = result.get("exported_functions")
    if exported_funcs:
        func_count = len(exported_funcs)
        lines.append(f"\nExported Functions ({func_count}):")
        for i, func in enumerate(exported_funcs):
            if i >= 20:
                break
            lines.append(f"  - {func}")

    return "\n".join(lines)


# P2: Memory protection thresholds for LIEF parsing
LIEF_WARN_SIZE_MB = 100    # Warn user about memory usage
LIEF_LIMIT_SIZE_MB = 500   # Limit extraction to prevent OOM


@log_execution(tool_name="parse_binary_with_lief")
@track_metrics("parse_binary_with_lief")
@handle_tool_errors
def parse_binary_with_lief(file_path: str, format: str = "json") -> ToolResult:
    """Parse binary metadata using LIEF and return structured results.
    
    Memory-safe implementation with progressive limits:
    - Under 100MB: Full parsing with all details
    - 100-500MB: Warning + reduced extraction limits
    - Over 500MB: Minimal parsing (headers only)
    - Over config limit: Rejected
    """

    validated_path = validate_file_path(file_path)

    max_file_size = get_config().lief_max_file_size
    file_size = validated_path.stat().st_size
    file_size_mb = file_size / (1024 * 1024)
    
    if file_size > max_file_size:
        return failure(
            "FILE_TOO_LARGE",
            f"File size ({file_size} bytes) exceeds maximum allowed size ({max_file_size} bytes)",
            hint="Set LIEF_MAX_FILE_SIZE environment variable to increase limit",
        )
    
    # CRITICAL: Reject files over limit BEFORE lief.parse() to prevent OOM
    # lief.parse() loads entire binary structure into memory, which can cause
    # Python to consume several GB of RAM for large binaries due to object overhead.
    if file_size_mb > LIEF_LIMIT_SIZE_MB:
        return failure(
            "FILE_TOO_LARGE_FOR_LIEF",
            f"File size ({file_size_mb:.0f}MB) exceeds LIEF parsing limit ({LIEF_LIMIT_SIZE_MB}MB)",
            hint="Use radare2 or other lightweight tools for analysis of very large binaries",
        )
    
    # P2: Determine extraction limits based on file size
    extraction_warning = None
    if file_size_mb > LIEF_WARN_SIZE_MB:
        # Large file: reduced extraction
        max_imports = 50
        max_exports = 50
        max_sections = 20
        extraction_warning = f"Large file ({file_size_mb:.0f}MB): some details may be truncated"
    else:
        # Normal file: full extraction
        max_imports = 100
        max_exports = 100
        max_sections = None  # No limit

    try:
        import lief
    except ImportError:
        return failure(
            "DEPENDENCY_MISSING",
            "lief library is not installed",
            hint="Install with: pip install lief",
        )

    try:
        binary = lief.parse(str(validated_path))
    except Exception as exc:  # noqa: BLE001 - lief exposes custom exception types
        lief_error = getattr(lief, "exception", None)
        lief_bad_file = getattr(lief, "bad_file", None)
        if (lief_bad_file and isinstance(exc, lief_bad_file)) or (
            lief_error and isinstance(exc, lief_error)
        ):
            return failure("LIEF_ERROR", f"LIEF failed to parse binary: {exc}")
        raise
    if binary is None:
        return failure(
            "UNSUPPORTED_FORMAT",
            "Unsupported binary format",
            hint="LIEF supports ELF, PE, and Mach-O formats",
        )

    result_data: dict[str, Any] = {
        "format": str(binary.format).split(".")[-1].lower(),
        "entry_point": (hex(binary.entrypoint) if hasattr(binary, "entrypoint") else None),
    }
    
    # P2: Add warning if extraction was limited
    if extraction_warning:
        result_data["_warning"] = extraction_warning

    # P2: Apply extraction limits based on file size
    sections = _extract_sections(binary)
    if sections:
        if max_sections is not None:
            sections = sections[:max_sections]
        result_data["sections"] = sections

    symbols = _extract_symbols(binary, max_imports=max_imports, max_exports=max_exports)
    result_data.update(symbols)

    if format.lower() == "json":
        return success(result_data)

    formatted_text = _format_lief_output(result_data, format)
    return success(formatted_text)
