import asyncio
import hashlib
from collections import deque
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar, cast

from fastmcp import FastMCP

from reversecore_mcp.core import json_utils as json  # Use optimized JSON (3-5x faster)
from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.metrics import track_metrics

# Import tools at module level for better performance
# These imports are used by resource functions below
from reversecore_mcp.tools.analysis import (
    capa_tools,
    die_tools,
    lief_tools,
    static_analysis,
)
from reversecore_mcp.tools.malware import dormant_detector, ioc_tools, yara_tools
from reversecore_mcp.tools.radare2 import r2_analysis
from reversecore_mcp.tools.radare2.r2ghidra_tools import (
    r2_analyze_function,
    r2_decompile,
    r2_recover_structures,
)

# Type variable for generic function wrapper
F = TypeVar("F", bound=Callable[..., Any])

# Type alias for decorator return
DecoratorType = Callable[[F], F]

_SENSITIVE_API_TAGS = {
    # Process Injection
    "VirtualAllocEx": "[!] Process Injection",
    "WriteProcessMemory": "[!] Process Injection",
    "CreateRemoteThread": "[!] Process Injection",
    "QueueUserAPC": "[!] Process Injection",
    "NtCreateThreadEx": "[!] Process Injection",
    "SetThreadContext": "[!] Process Injection",
    "ptrace": "[!] Process Injection / Debugger",
    "process_vm_writev": "[!] Process Injection",
    # Dynamic Loading
    "LoadLibraryA": "[!] Dynamic Loading",
    "LoadLibraryW": "[!] Dynamic Loading",
    "LoadLibraryExA": "[!] Dynamic Loading",
    "LoadLibraryExW": "[!] Dynamic Loading",
    "GetProcAddress": "[!] Dynamic Loading",
    "LdrLoadDll": "[!] Dynamic Loading",
    "dlopen": "[!] Dynamic Loading",
    "dlsym": "[!] Dynamic Loading",
    # File Encryption / Ransomware
    "CryptEncrypt": "[!] File Encryption",
    "BCryptEncrypt": "[!] File Encryption",
    "CryptDeriveKey": "[!] File Encryption",
    "BCryptDeriveKey": "[!] File Encryption",
    "EVP_EncryptInit": "[!] File Encryption",
    "EVP_CIPHER_CTX_new": "[!] File Encryption",
    # Anti-Debugging
    "IsDebuggerPresent": "[!] Anti-Debugging",
    "CheckRemoteDebuggerPresent": "[!] Anti-Debugging",
    "NtQueryInformationProcess": "[!] Anti-Debugging",
    # Network / C2
    "WSAStartup": "[!] Network/C2",
    "connect": "[!] Network/C2",
    "socket": "[!] Network/C2",
    "HttpOpenRequestA": "[!] Network/C2",
    "HttpOpenRequestW": "[!] Network/C2",
    "InternetConnectA": "[!] Network/C2",
    "InternetConnectW": "[!] Network/C2",
    "InternetReadFile": "[!] Network/C2",
    "URLDownloadToFileA": "[!] Network/C2",
    "URLDownloadToFileW": "[!] Network/C2",
    # Process Execution
    "WinExec": "[!] Process Execution",
    "ShellExecuteA": "[!] Process Execution",
    "ShellExecuteW": "[!] Process Execution",
    "CreateProcessA": "[!] Process Execution",
    "CreateProcessW": "[!] Process Execution",
    "system": "[!] Process Execution",
    "execve": "[!] Process Execution",
    "popen": "[!] Process Execution",
}


def _calculate_file_hashes(file_path: str) -> dict[str, str]:
    """Calculate MD5, SHA1, SHA256 and SSDEEP hashes of a file."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256(usedforsecurity=False)

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except Exception:
        pass

    ssdeep_hash = "N/A"
    try:
        import ssdeep  # noqa: F401

        ssdeep_hash = ssdeep.hash_from_file(file_path)
    except Exception:
        pass

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "ssdeep": ssdeep_hash,
    }


def resource_decorator(resource_name: str) -> DecoratorType:
    """Combined decorator for resource functions with logging and metrics.

    Applies @log_execution and @track_metrics to resource functions
    for consistent monitoring and observability.

    Args:
        resource_name: Name identifier for logging and metrics tracking

    Returns:
        A decorator that wraps the function with logging and metrics
    """

    def decorator(func: F) -> F:
        # Apply decorators in reverse order (innermost first)
        wrapped = track_metrics(resource_name)(func)
        wrapped = log_execution(tool_name=resource_name)(wrapped)

        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await wrapped(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            return wrapped(*args, **kwargs)

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def _get_resources_path() -> Path:
    """Get resources path from config or use default."""
    config = get_config()
    # Resources are typically in a sibling directory to workspace
    resources_path = config.workspace.parent / "resources"
    if resources_path.exists():
        return resources_path
    # Fallback to local resources directory
    local_resources = Path(__file__).parent.parent / "resources"
    if local_resources.exists():
        return local_resources
    return resources_path  # Return config-based path even if not exists


def _get_workspace_path(filename: str) -> str:
    """Get validated full path to a file in the workspace with path traversal protection."""
    from reversecore_mcp.core.exceptions import ValidationError

    config = get_config()
    workspace = config.workspace.resolve()

    file_path = Path(filename)
    if file_path.is_absolute():
        resolved_path = file_path.resolve()
    else:
        resolved_path = (workspace / file_path).resolve()

    try:
        resolved_path.relative_to(workspace)
    except ValueError:
        raise ValidationError(
            f"Path traversal detected: '{filename}' resolves outside workspace directory {workspace}"
        )

    return str(resolved_path)


def _register_resource(mcp: FastMCP, uri: str, mime_type: str | None = None) -> DecoratorType:
    """Register resource with FastMCP while preserving the wrapped callable type."""
    try:
        if mime_type is not None:
            return cast(DecoratorType, mcp.resource(uri, mime_type=mime_type))
        return cast(DecoratorType, mcp.resource(uri))
    except TypeError:
        return cast(DecoratorType, mcp.resource(uri))


def register_resources(mcp: FastMCP):
    """Register MCP resources for AI agents."""

    # ============================================================================
    # Static Resources
    # ============================================================================

    @_register_resource(mcp, "reversecore://guide", mime_type="text/markdown")
    def get_guide() -> str:
        """Reversecore MCP Tool Usage Guide"""
        guide_path = _get_resources_path() / "FILE_COPY_TOOL_GUIDE.md"
        if guide_path.exists():
            return guide_path.read_text(encoding="utf-8")
        return "Guide not found."

    @_register_resource(mcp, "reversecore://guide/structures", mime_type="text/markdown")
    def get_structure_guide() -> str:
        """Structure Recovery and Cross-Reference Analysis Technical Guide"""
        doc_path = _get_resources_path() / "XREFS_AND_STRUCTURES_IMPLEMENTATION.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Documentation not found."

    @_register_resource(mcp, "reversecore://tools", mime_type="text/markdown")
    def get_tools_doc() -> str:
        """Complete documentation for all available tools"""
        doc_path = _get_resources_path() / "TOOLS.md"
        if doc_path.exists():
            return doc_path.read_text(encoding="utf-8")
        return "Tools documentation not found."

    @_register_resource(mcp, "reversecore://logs", mime_type="text/plain")
    def get_logs() -> str:
        """Application logs (last 100 lines)"""
        log_file = get_config().log_file
        if log_file.exists():
            try:
                # OPTIMIZED: Use deque to read only last N lines efficiently
                # This avoids loading the entire log file into memory
                with open(log_file, encoding="utf-8", errors="replace") as f:
                    # deque with maxlen automatically keeps only last N items
                    last_lines = deque(f, maxlen=100)
                    return "".join(last_lines)
            except (OSError, PermissionError) as e:
                return f"Error reading logs: {e}"
        return "No logs found."

    # ============================================================================
    # Dynamic Resources - Binary Virtual File System
    # ============================================================================

    @_register_resource(mcp, "reversecore://{filename}/metadata", mime_type="text/markdown")
    @resource_decorator("resource_get_binary_metadata")
    async def get_binary_metadata(filename: str) -> str:
        """Get binary metadata, architecture, hashes, mitigations, and packer/compiler info"""
        try:
            path = _get_workspace_path(filename)
            hashes = _calculate_file_hashes(path)

            lief_res = lief_tools.parse_binary_with_lief(path, format="json")
            lief_data = (
                lief_res.data
                if lief_res.status == "success" and isinstance(lief_res.data, dict)
                else {}
            )

            packer_res = await die_tools.detect_packer(path)
            packer_data = (
                packer_res.data
                if packer_res.status == "success" and isinstance(packer_res.data, dict)
                else {}
            )

            format_name = lief_data.get("format", packer_data.get("file_type", "Unknown"))
            if isinstance(format_name, str):
                format_name = format_name.upper()

            arch = packer_data.get("arch", "Unknown")
            entry_point = lief_data.get("entry_point", "N/A")
            mitigations = lief_data.get("mitigations", {})
            packer = packer_data.get("packer", "None detected")
            compiler = packer_data.get("compiler", "Unknown")
            sections_count = len(lief_data.get("sections", []))

            mitigations_lines = []
            if mitigations and isinstance(mitigations, dict):
                for k, v in mitigations.items():
                    val_str = (
                        "✅ Enabled" if v is True else ("❌ Disabled" if v is False else str(v))
                    )
                    mitigations_lines.append(f"- **{k.upper()}**: {val_str}")
            mitigations_table = (
                "\n".join(mitigations_lines) if mitigations_lines else "- No mitigations identified"
            )

            return f"""# 📋 Binary Metadata: {filename}

## General Information
- **File Format**: {format_name}
- **Architecture**: {arch}
- **Entry Point**: `{entry_point}`
- **Total Sections**: {sections_count}
- **Detected Compiler**: {compiler}
- **Detected Packer**: {packer}

## Cryptographic Hashes
- **MD5**: `{hashes.get("md5")}`
- **SHA1**: `{hashes.get("sha1")}`
- **SHA256**: `{hashes.get("sha256")}`
- **SSDEEP**: `{hashes.get("ssdeep")}`

## Security Mitigations
{mitigations_table}
"""
        except Exception as e:
            return f"Error extracting metadata for {filename}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/info", mime_type="text/markdown")
    @resource_decorator("resource_get_binary_info")
    async def get_binary_info(filename: str) -> str:
        """Get binary metadata (alias for reversecore://{filename}/metadata)"""
        return await get_binary_metadata(filename)

    @_register_resource(
        mcp, "reversecore://{filename}/func/{address}/xrefs", mime_type="text/markdown"
    )
    @resource_decorator("resource_get_function_xrefs")
    async def get_function_xrefs(filename: str, address: str) -> str:
        """Get ingoing and outgoing cross-references for a specific function"""
        try:
            path = _get_workspace_path(filename)
            res = await r2_analysis.analyze_xrefs(path, address, xref_type="all")
            if res.status != "success":
                return f"Error analyzing cross-references for {address}: {res.message if hasattr(res, 'message') else 'Unknown error'}"

            data = res.data if isinstance(res.data, dict) else {}
            xrefs_to = data.get("xrefs_to", [])
            xrefs_from = data.get("xrefs_from", [])
            total_to = data.get("total_refs_to", len(xrefs_to))
            total_from = data.get("total_refs_from", len(xrefs_from))

            # Bounded at top 30 items per direction
            capped_to = xrefs_to[:30]
            capped_from = xrefs_from[:30]

            to_rows = []
            for ref in capped_to:
                from_addr = ref.get("from", ref.get("addr", "N/A"))
                ref_type = ref.get("type", "call")
                fcn = ref.get("fcn_name", "unknown")
                to_rows.append(f"| `{from_addr}` | `{ref_type}` | `{fcn}` |")

            from_rows = []
            for ref in capped_from:
                target_addr = ref.get("addr", ref.get("to", "N/A"))
                ref_type = ref.get("type", "call")
                fcn = ref.get("fcn_name", ref.get("name", "unknown"))
                from_rows.append(f"| `{target_addr}` | `{ref_type}` | `{fcn}` |")

            to_table = (
                "| Source Address | Reference Type | Caller Function |\n|---|---|---|\n"
                + "\n".join(to_rows)
                if to_rows
                else "No ingoing cross-references found."
            )
            from_table = (
                "| Target Address | Reference Type | Callee / Symbol |\n|---|---|---|\n"
                + "\n".join(from_rows)
                if from_rows
                else "No outgoing cross-references found."
            )

            to_note = (
                f"\n*(Showing {len(capped_to)} of {total_to} total callers)*"
                if total_to > 30
                else ""
            )
            from_note = (
                f"\n*(Showing {len(capped_from)} of {total_from} total callees)*"
                if total_from > 30
                else ""
            )

            return f"""# 🔄 Cross-References: {filename} @ {address}

## Ingoing References (Callers: {total_to}){to_note}
{to_table}

## Outgoing References (Callees: {total_from}){from_note}
{from_table}
"""
        except Exception as e:
            return f"Error extracting xrefs for {address}: {e}"

    @_register_resource(
        mcp,
        "reversecore://{filename}/func/{address}/context",
        mime_type="text/markdown",
    )
    @resource_decorator("resource_get_function_context")
    async def get_function_context(filename: str, address: str) -> str:
        """Get function metadata, variables, stack layout, and recovered structures"""
        try:
            path = _get_workspace_path(filename)
            fn_res = await r2_analyze_function(path, address)
            struct_res = await r2_recover_structures(path, address)

            if fn_res.status != "success":
                return f"Error analyzing function {address}: {fn_res.message if hasattr(fn_res, 'message') else 'Unknown error'}"

            fn_data = fn_res.data if isinstance(fn_res.data, dict) else {}
            struct_data = (
                struct_res.data
                if struct_res.status == "success" and isinstance(struct_res.data, dict)
                else {}
            )

            fn_name = fn_data.get("name", address)
            fn_size = fn_data.get("size", 0)
            cc = fn_data.get("complexity", 0)
            nbbs = fn_data.get("nbbs", 0)
            edges = fn_data.get("edges", 0)
            signature = fn_data.get("signature", f"void {fn_name}()")
            calltype = fn_data.get("calltype", "cdecl")

            structures = struct_data.get("structures", [])
            var_rows = []
            for s in structures:
                var_rows.append(
                    f"| `{s.get('name')}` | `{s.get('type')}` | `{s.get('offset')}` | `{s.get('size')} B` |"
                )

            var_table = (
                "| Variable Name | Type | Stack Offset | Size |\n|---|---|---|---|\n"
                + "\n".join(var_rows)
                if var_rows
                else "No local variables or structures recovered."
            )

            return f"""# 🧩 Function Context: {filename} @ {address}

## Prototype & Signature
```c
{signature}
```

## Function Metrics
- **Name**: `{fn_name}`
- **Address / Offset**: `{fn_data.get("offset", address)}`
- **Size**: {fn_size} bytes
- **Cyclomatic Complexity**: {cc}
- **Basic Blocks (nbbs)**: {nbbs}
- **Control Flow Edges**: {edges}
- **Calling Convention**: `{calltype}`

## Local Variables & Recovered Structures ({len(structures)})
{var_table}
"""
        except Exception as e:
            return f"Error extracting function context for {address}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/memory_map", mime_type="text/markdown")
    @resource_decorator("resource_get_memory_map")
    async def get_memory_map(filename: str) -> str:
        """Get binary memory map, section table, permissions, and entropy analysis"""
        try:
            path = _get_workspace_path(filename)
            lief_res = lief_tools.parse_binary_with_lief(path, format="json")
            if lief_res.status != "success":
                return f"Error parsing sections for {filename}: {lief_res.message if hasattr(lief_res, 'message') else 'LIEF parse failed'}"

            data = lief_res.data if isinstance(lief_res.data, dict) else {}
            sections = data.get("sections", [])
            if not sections:
                return f"# 🗺️ Memory Map & Section Table: {filename}\n\nNo sections found in binary header."

            rows = []
            high_entropy_count = 0
            for sec in sections:
                name = sec.get("name", "unnamed")
                va = sec.get("virtual_address", "0x0")
                size = sec.get("size", 0)
                entropy = sec.get("entropy")

                flag = ""
                if entropy is not None and entropy > 7.0:
                    flag = "⚠️ High Entropy (>7.0) - Likely Packed/Encrypted"
                    high_entropy_count += 1
                elif entropy is not None and entropy < 1.0:
                    flag = "ℹ️ Low Entropy (<1.0) - Sparse/Zeroed"

                entropy_str = f"{entropy:.2f}" if entropy is not None else "N/A"
                rows.append(f"| `{name}` | `{va}` | `{size}` bytes | `{entropy_str}` | {flag} |")

            table = (
                "| Section Name | Virtual Address | Size | Entropy | Flags / Anomalies |\n|---|---|---|---|---|\n"
                + "\n".join(rows)
            )

            return f"""# 🗺️ Memory Map & Section Table: {filename}

## Summary
- **Total Sections**: {len(sections)}
- **High Entropy Sections**: {high_entropy_count}

## Section Table
{table}
"""
        except Exception as e:
            return f"Error reading memory map for {filename}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/sections", mime_type="text/markdown")
    @resource_decorator("resource_get_sections")
    async def get_sections(filename: str) -> str:
        """Get binary memory map and section table (alias for reversecore://{filename}/memory_map)"""
        return await get_memory_map(filename)

    @_register_resource(mcp, "reversecore://{filename}/signatures", mime_type="text/markdown")
    @resource_decorator("resource_get_signatures_report")
    async def get_signatures_report(filename: str) -> str:
        """Get consolidated threat signatures, YARA matches, CAPA capabilities, and Dormant Detector results"""
        try:
            path = _get_workspace_path(filename)

            # 1. YARA match
            yara_matches = []
            try:
                yara_res = await yara_tools.run_yara(file_path=path)
                if yara_res.status == "success" and isinstance(yara_res.data, dict):
                    matches = yara_res.data.get("matches", [])
                    for m in matches:
                        rule_name = m.get("rule", "unknown")
                        tags = m.get("tags", [])
                        yara_matches.append(
                            f"- **{rule_name}** (tags: {', '.join(tags) if tags else 'none'})"
                        )
            except Exception:
                pass

            # 2. CAPA capabilities
            capa_capabilities = []
            mitre_attack = []
            try:
                capa_res = await capa_tools.run_capa(file_path=path, output_format="summary")
                if capa_res.status == "success" and isinstance(capa_res.data, dict):
                    caps = capa_res.data.get("capabilities", [])
                    for c in caps[:20]:
                        capa_capabilities.append(f"- {c}")
                    mitre = capa_res.data.get("mitre_attack", [])
                    for m in mitre[:20]:
                        mitre_attack.append(f"- {m}")
            except Exception:
                pass

            # 3. Dormant detector
            orphans = []
            suspicious = []
            try:
                dd_res = await dormant_detector.dormant_detector(file_path=path)
                if dd_res.status == "success" and isinstance(dd_res.data, dict):
                    orphans = dd_res.data.get("orphan_functions", [])
                    suspicious = dd_res.data.get("suspicious_logic", [])
            except Exception:
                pass

            yara_section = (
                "\n".join(yara_matches) if yara_matches else "No YARA signatures matched."
            )
            capa_section = (
                "\n".join(capa_capabilities)
                if capa_capabilities
                else "No CAPA capabilities detected or CAPA unavailable."
            )
            mitre_section = (
                "\n".join(mitre_attack) if mitre_attack else "No MITRE ATT&CK techniques mapped."
            )
            dormant_section = (
                f"- Found {len(orphans)} unreferenced orphan function(s)\n- Found {len(suspicious)} suspicious magic value pattern(s)"
                if (orphans or suspicious)
                else "No dormant anomalies detected."
            )

            return f"""# 🛡️ Threat Signatures & Capabilities: {filename}

## YARA Rule Matches
{yara_section}

## CAPA Behavioral Capabilities
{capa_section}

## MITRE ATT&CK Mapping
{mitre_section}

## Dormant Detector & Hidden Logic
{dormant_section}
"""
        except Exception as e:
            return f"Error extracting signatures for {filename}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/imports", mime_type="text/markdown")
    @resource_decorator("resource_get_imports")
    async def get_imports(filename: str) -> str:
        """Get imported functions grouped by library with security risk categorization"""
        try:
            path = _get_workspace_path(filename)
            res = await r2_analysis.run_radare2(path, "iij")
            imports = []
            if res.status == "success":
                try:
                    imports = json.loads(res.data if isinstance(res.data, str) else str(res.data))
                except Exception:
                    imports = []

            if not imports:
                # Fallback to LIEF
                lief_res = lief_tools.parse_binary_with_lief(path, format="json")
                if lief_res.status == "success" and isinstance(lief_res.data, dict):
                    lief_imports = lief_res.data.get("imports", [])
                    for lib in lief_imports:
                        lib_name = lib.get("name", "unknown")
                        for func in lib.get("functions", []):
                            imports.append({"libname": lib_name, "name": func})

            if not imports:
                return f"# 📥 Imports for {filename}\n\nNo imported functions found (statically linked or packed binary)."

            # Group by library
            grouped: dict[str, list[dict[str, Any]]] = {}
            sensitive_count = 0

            for imp in imports:
                lib = imp.get("libname", imp.get("lib", "General / System"))
                func_name = imp.get("name", "unknown")
                tag = _SENSITIVE_API_TAGS.get(func_name, "")
                if tag:
                    sensitive_count += 1
                grouped.setdefault(lib, []).append({"name": func_name, "tag": tag})

            sections = []
            total_shown = 0
            max_total = 100

            for lib, funcs in grouped.items():
                func_lines = []
                for f in funcs:
                    if total_shown >= max_total:
                        break
                    tag_str = f" `{f['tag']}`" if f["tag"] else ""
                    func_lines.append(f"- `{f['name']}`{tag_str}")
                    total_shown += 1

                sections.append(f"### {lib} ({len(funcs)} functions)\n" + "\n".join(func_lines))
                if total_shown >= max_total:
                    sections.append(
                        f"\n*(Truncated: showing {max_total} of {len(imports)} total imports)*"
                    )
                    break

            return f"""# 📥 Imported Libraries & Functions: {filename}

## Summary
- **Total Imports**: {len(imports)}
- **Sensitive / High-Risk APIs**: {sensitive_count}

{chr(10).join(sections)}
"""
        except Exception as e:
            return f"Error extracting imports for {filename}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/exports", mime_type="text/markdown")
    @resource_decorator("resource_get_exports")
    async def get_exports(filename: str) -> str:
        """Get exported functions and symbols"""
        try:
            path = _get_workspace_path(filename)
            exports = []
            res = await r2_analysis.run_radare2(path, "iEj")
            if res.status == "success":
                try:
                    exports = json.loads(res.data if isinstance(res.data, str) else str(res.data))
                except Exception:
                    exports = []

            if not exports:
                lief_res = lief_tools.parse_binary_with_lief(path, format="json")
                if lief_res.status == "success" and isinstance(lief_res.data, dict):
                    exports = lief_res.data.get("exports", [])

            if not exports:
                return f"# 📤 Exports for {filename}\n\nNo exported symbols found in binary."

            rows = []
            capped_exports = exports[:50]
            for exp in capped_exports:
                name = exp.get("name", "unknown")
                addr = exp.get("vaddr", exp.get("address", "0x0"))
                ordinal = exp.get("ordinal", exp.get("ord", "N/A"))
                rows.append(f"| `{ordinal}` | `{addr}` | `{name}` |")

            table = "| Ordinal | Virtual Address | Symbol Name |\n|---|---|---|\n" + "\n".join(rows)
            note = f"\n*(Showing 50 of {len(exports)} total exports)*" if len(exports) > 50 else ""

            return f"""# 📤 Exported Symbols: {filename}

## Summary
- **Total Exports**: {len(exports)}{note}

{table}
"""
        except Exception as e:
            return f"Error extracting exports for {filename}: {e}"

    @_register_resource(mcp, "reversecore://{filename}/strings", mime_type="text/markdown")
    @resource_decorator("resource_get_file_strings")
    async def get_file_strings(filename: str) -> str:
        """Extract all strings from a binary file"""
        try:
            result = await static_analysis.run_strings(_get_workspace_path(filename))
            if result.status == "success":
                # Get content from ToolResult
                content = result.data if isinstance(result.data, str) else str(result.data)
                return f"# Strings from {filename}\n\n{content}"
            return f"Error extracting strings: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @_register_resource(mcp, "reversecore://{filename}/iocs", mime_type="text/markdown")
    @resource_decorator("resource_get_file_iocs")
    async def get_file_iocs(filename: str) -> str:
        """Extract IOCs (IPs, URLs, Emails) from a binary file"""
        try:
            # 1. Extract strings
            strings_res = await static_analysis.run_strings(_get_workspace_path(filename))
            if strings_res.status != "success":
                return f"Failed to extract strings from {filename}"

            # 2. Extract IOCs from strings
            strings_data = (
                strings_res.data if isinstance(strings_res.data, str) else str(strings_res.data)
            )
            ioc_res = ioc_tools.extract_iocs(strings_data)

            # 3. Format output
            if ioc_res.status == "success":
                data = ioc_res.data
                ipv4_list = data.get("ipv4", [])
                urls_list = data.get("urls", [])
                emails_list = data.get("emails", [])

                return f"""# IOC Report for {filename}

## IPv4 Addresses ({len(ipv4_list)})
{chr(10).join(f"- {ip}" for ip in ipv4_list) if ipv4_list else "No IPv4 addresses found"}

## URLs ({len(urls_list)})
{chr(10).join(f"- {url}" for url in urls_list) if urls_list else "No URLs found"}

## Email Addresses ({len(emails_list)})
{chr(10).join(f"- {email}" for email in emails_list) if emails_list else "No emails found"}
"""
            return f"Error extracting IOCs: {ioc_res.message if hasattr(ioc_res, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @_register_resource(
        mcp, "reversecore://{filename}/func/{address}/code", mime_type="text/markdown"
    )
    @resource_decorator("resource_get_decompiled_code")
    async def get_decompiled_code(filename: str, address: str) -> str:
        """Get decompiled pseudo-C code for a specific function"""
        try:
            result = await r2_decompile(_get_workspace_path(filename), address)

            if result.status == "success":
                if isinstance(result.data, dict):
                    content = result.data.get("pseudo_c", "")
                else:
                    content = str(result.data)
                return f"""# Decompiled Code: {filename} @ {address}

```c
{content}
```
"""
            return f"Error decompiling {address}: {result.message if hasattr(result, 'message') else 'Decompilation failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @_register_resource(
        mcp, "reversecore://{filename}/func/{address}/asm", mime_type="text/markdown"
    )
    @resource_decorator("resource_get_disassembly")
    async def get_disassembly(filename: str, address: str) -> str:
        """Get disassembly for a specific function"""
        try:
            result = await r2_analysis.run_radare2(
                _get_workspace_path(filename), f"pdf @ {address}"
            )

            if result.status == "success":
                content = result.data if isinstance(result.data, str) else str(result.data)
                return f"""# Disassembly: {filename} @ {address}

```asm
{content}
```
"""
            return f"Error disassembling {address}: {result.message if hasattr(result, 'message') else 'Disassembly failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @_register_resource(
        mcp, "reversecore://{filename}/func/{address}/cfg", mime_type="text/markdown"
    )
    @resource_decorator("resource_get_function_cfg")
    async def get_function_cfg(filename: str, address: str) -> str:
        """Get Control Flow Graph (Mermaid) for a specific function"""
        try:
            result = await r2_analysis.generate_function_graph(
                _get_workspace_path(filename), address, format="mermaid"
            )

            if result.status == "success":
                content = result.data if isinstance(result.data, str) else str(result.data)
                return f"""# Control Flow Graph: {filename} @ {address}

{content}
"""
            return f"Error generating CFG for {address}: {result.message if hasattr(result, 'message') else 'CFG generation failed'}"
        except Exception as e:
            return f"Error: {str(e)}"

    @_register_resource(mcp, "reversecore://{filename}/functions", mime_type="text/markdown")
    @resource_decorator("resource_get_function_list")
    async def get_function_list(filename: str) -> str:
        """Get list of all functions in the binary"""
        try:
            result = await r2_analysis.run_radare2(
                _get_workspace_path(filename), "aflj"
            )  # List functions in JSON format

            if result.status == "success":
                content = result.data if isinstance(result.data, str) else str(result.data)

                try:
                    functions = json.loads(content)
                    func_list = []
                    for func in functions[:50]:  # Limit to first 50 for readability
                        name = func.get("name", "unknown")
                        offset = func.get("offset", 0)
                        size = func.get("size", 0)
                        func_list.append(f"- `{name}` @ 0x{offset:x} (size: {size} bytes)")

                    total = len(functions)
                    shown = min(50, total)

                    return f"""# Functions in {filename}

Total functions: {total}
Showing: {shown}

{chr(10).join(func_list)}
"""
                except Exception:  # Catch all JSON parsing errors
                    return f"# Functions in {filename}\n\n{content}"

            return f"Error listing functions: {result.message if hasattr(result, 'message') else 'Failed to list functions'}"
        except Exception as e:
            return f"Error: {str(e)}"

    # ============================================================================
    # Reversecore Signature Resources (Dormant Detector)
    # ============================================================================

    @_register_resource(mcp, "reversecore://{filename}/dormant_detector", mime_type="text/markdown")
    @resource_decorator("resource_get_dormant_detector_results")
    async def get_dormant_detector_results(filename: str) -> str:
        """Get Dormant Detector analysis results (orphan functions and logic bombs)"""
        try:
            result = await dormant_detector.dormant_detector(
                file_path=_get_workspace_path(filename)
            )

            if result.status == "success":
                data = result.data
                orphans = data.get("orphan_functions", [])
                suspicious = data.get("suspicious_logic", [])

                report = f"""# 🔍 Dormant Detector Results: {filename}

## Orphan Functions (Never Called)
Found {len(orphans)} orphan function(s):

"""
                for func in orphans[:10]:
                    report += f"""### {func.get("name", "unknown")}
- **Address**: {func.get("address", "N/A")}
- **Size**: {func.get("size", 0)} bytes
- **Cross-References**: {func.get("xrefs", 0)}
- **Assessment**: Potentially hidden backdoor or logic bomb

"""

                report += f"\n## Suspicious Logic (Magic Values)\nFound {len(suspicious)} suspicious pattern(s):\n\n"

                for logic in suspicious[:10]:
                    report += f"""### {logic.get("function", "unknown")}
- **Address**: {logic.get("address", "N/A")}
- **Instruction**: `{logic.get("instruction", "N/A")}`
- **Reason**: {logic.get("reason", "N/A")}

"""

                return report

            return f"Dormant Detector analysis failed: {result.message if hasattr(result, 'message') else 'Unknown error'}"
        except Exception as e:
            return f"Error: {str(e)}"