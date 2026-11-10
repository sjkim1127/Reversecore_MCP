"""Modern Application & Runtime Target Analyzers for Reversecore_MCP.

Provides zero-dependency, pure-Python static parsers and metadata recovery tools
for modern compiled and packaged application targets:
1. ``inspect_go_rust_binary``: Stripped Go (`gopclntab`, `buildinfo`) and Rust
   (`.dep-v0` cargo-auditable, crate paths, symbol demangling) binaries.
2. ``inspect_electron_asar``: Electron `.asar` archives (Chromium Pickle header,
   virtual file tree, `package.json`, IPC attack surface, security flags, extraction).
3. ``inspect_unity_il2cpp``: Unity IL2CPP `global-metadata.dat` (header magic
   `0xFAB11BAF`, string literals, class/method/namespace identifiers) and `libil2cpp.so`.
"""

from __future__ import annotations

import json
import math
import re
import struct
import zlib
from pathlib import Path
from typing import Any

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.evidence_cache import get_evidence_cache
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

# Maximum file size to read in-memory for static parsing (128 MB)
_MAX_SCAN_BYTES = 128 * 1024 * 1024

# Go pclntab magic headers (little-endian and big-endian variants)
_GOPCLNTAB_MAGICS: dict[bytes, str] = {
    b"\xfb\xff\xff\xff\x00\x00": "Go 1.2 - 1.15 (pclntab 0xfffffffb)",
    b"\xfa\xff\xff\xff\x00\x00": "Go 1.16 - 1.17 (pclntab 0xfffffffa)",
    b"\xf0\xff\xff\xff\x00\x00": "Go 1.18 - 1.19 (pclntab 0xfffffff0)",
    b"\xf1\xff\xff\xff\x00\x00": "Go 1.20+ (pclntab 0xfffffff1)",
    b"\xff\xff\xff\xfb\x00\x00": "Go 1.2 - 1.15 Big-Endian",
    b"\xff\xff\xff\xfa\x00\x00": "Go 1.16 - 1.17 Big-Endian",
    b"\xff\xff\xff\xf0\x00\x00": "Go 1.18 - 1.19 Big-Endian",
    b"\xff\xff\xff\xf1\x00\x00": "Go 1.20+ Big-Endian",
}

# Rust escape sequences in legacy mangled names
_RUST_ESCAPES: dict[str, str] = {
    "$LT$": "<",
    "$GT$": ">",
    "$LP$": "(",
    "$RP$": ")",
    "$C$": ",",
    "$u20$": " ",
    "$u27$": "'",
    "$u5b$": "[",
    "$u5d$": "]",
    "$u7b$": "{",
    "$u7d$": "}",
    "$u3b$": ";",
    "$u2b$": "+",
    "$BP$": "*",
    "$RF$": "&",
    "..": "::",
}


def _demangle_rust_symbol(symbol: str) -> str:
    """Demangle a legacy Rust ``_ZN...E`` symbol into ``crate::module::item`` format."""
    s = symbol.strip()
    if s.startswith("__ZN"):
        s = s[1:]
    if not s.startswith("_ZN") or not s.endswith("E"):
        return symbol

    inner = s[3:-1]
    parts: list[str] = []
    idx = 0
    n = len(inner)
    while idx < n:
        num_start = idx
        while idx < n and inner[idx].isdigit():
            idx += 1
        if idx == num_start:
            break
        seg_len = int(inner[num_start:idx])
        if seg_len <= 0 or idx + seg_len > n:
            break
        seg = inner[idx : idx + seg_len]
        idx += seg_len
        for esc, rep in _RUST_ESCAPES.items():
            seg = seg.replace(esc, rep)
        parts.append(seg)

    if not parts:
        return symbol

    # Strip trailing 17h<16-hex> hash suffix if present
    if len(parts) > 1 and re.fullmatch(r"h[0-9a-fA-F]{16}", parts[-1]):
        parts.pop()

    return "::".join(parts)


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (0.0 - 8.0 bits/byte) of a byte buffer."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ==============================================================================
# 1. Go & Rust Binary Analyzer
# ==============================================================================
@log_execution(tool_name="inspect_go_rust_binary")
@track_metrics("inspect_go_rust_binary")
@handle_tool_errors
async def inspect_go_rust_binary(
    file_path: str,
    detail: str = "summary",
    limit: int = 100,
) -> ToolResult:
    """Recover compiler metadata, stripped symbols, and dependencies from Go and Rust binaries.

    Inspects native binaries (ELF, PE, Mach-O) in pure Python without requiring a Go
    or Rust toolchain:
    - **Go**: Detects `gopclntab` headers (`0xfffffffb`/`fa`/`f0`/`f1`), `Go build ID`,
      `Go buildinf` module tables, user package functions (`main.*`, `github.com/*`), and `.go` files.
    - **Rust**: Detects `/rustc/<commit>/` compiler provenance, decodes `.dep-v0`
      (`cargo-auditable`) dependency graphs, extracts cargo crate versions, and demangles `_ZN...E` symbols.

    Args:
        file_path: Path to the target binary file.
        detail: Output detail level ('summary' or 'full'). Default: 'summary'.
        limit: Maximum items per category when detail='full' (default: 100, max: 1000).

    Returns:
        ToolResult with language detection, recovered symbols, crate/module dependencies,
        epistemic ledger (observations, inferences, residual_unknowns), and `evidence_id`.
    """
    validated = validate_file_path(file_path)
    file_size = validated.stat().st_size
    read_size = min(file_size, _MAX_SCAN_BYTES)

    with validated.open("rb") as f:
        data = f.read(read_size)

    observations: list[str] = []
    inferences: list[str] = []
    residual_unknowns: list[str] = []

    if file_size > _MAX_SCAN_BYTES:
        residual_unknowns.append(
            f"Binary size ({file_size} bytes) exceeds scan window ({_MAX_SCAN_BYTES} bytes); trailing sections were not scanned."
        )

    # --- Go Detection & Recovery ---
    pclntab_hits: list[dict[str, Any]] = []
    for magic, version_desc in _GOPCLNTAB_MAGICS.items():
        pos = data.find(magic)
        if pos != -1:
            ptr_size = data[pos + 7] if pos + 7 < len(data) else None
            if ptr_size in (4, 8):
                pclntab_hits.append(
                    {
                        "offset": hex(pos),
                        "format": version_desc,
                        "pointer_size": ptr_size,
                    }
                )
                observations.append(
                    f"Located Go pclntab header ({version_desc}, ptr_size={ptr_size}) at file offset {hex(pos)}."
                )

    go_version_matches = sorted(
        {m.decode("ascii", errors="ignore") for m in re.findall(rb"go1\.\d+(?:\.\d+)?", data)}
    )
    go_build_id_match = re.search(rb'Go build ID: "([^"\x00]{4,120})"', data)
    go_build_id = (
        go_build_id_match.group(1).decode("ascii", errors="ignore") if go_build_id_match else None
    )
    if go_build_id:
        observations.append(f"Extracted Go build ID: '{go_build_id}'.")

    # Extract Go module buildinfo lines (path, mod, dep, build)
    go_modules: list[dict[str, str]] = []
    for m in re.finditer(rb"(?:^|\n)(path|mod|dep|build)\t([^\n\r\x00]{3,160})", data):
        kind = m.group(1).decode("ascii", errors="ignore")
        val = m.group(2).decode("utf-8", errors="ignore").strip()
        go_modules.append({"directive": kind, "value": val})

    # Extract Go function names (main.*, runtime.*, domain/pkg.Func)
    go_func_Set: set[str] = set()
    for m in re.finditer(
        rb"\b((?:main|runtime|sync|net|crypto|os|fmt|syscall|encoding|strings|bytes|io|(?:[a-z0-9\-]+\.)+[a-z]{2,}/[a-zA-Z0-9_\-\./]+)\.[A-Z_a-z][a-zA-Z0-9_\.\(\)\*]{1,90})\b",
        data,
    ):
        fn = m.group(1).decode("ascii", errors="ignore")
        if not fn.endswith(".go") and ".." not in fn:
            go_func_Set.add(fn)

    go_functions = sorted(go_func_Set)
    go_user_functions = [
        f
        for f in go_functions
        if (
            f.startswith("main.")
            or (
                "/" in f
                and not f.startswith(
                    (
                        "runtime/",
                        "internal/",
                        "eq.",
                        "type:.",
                        "go:itab.",
                        "crypto/internal/",
                        "vendor/",
                    )
                )
            )
        )
    ]

    # Recover Go custom structs, type equality descriptors, and interface itabs
    go_types_set: set[str] = set()
    for m in re.finditer(
        rb"(?:type:\.eq\.|go:itab\.|\*?(?:main|(?:[a-z0-9\-]+\.)+[a-z]{2,}/[a-zA-Z0-9_\-\./]+)\.)([A-Za-z][a-zA-Z0-9_,\.\*]{2,80})",
        data,
    ):
        raw_t = m.group(0).decode("ascii", errors="ignore")
        if not raw_t.endswith(".go") and ".." not in raw_t:
            go_types_set.add(raw_t)
    for fn_name in go_functions:
        if fn_name.startswith("eq.") and not fn_name.startswith(("eq.runtime.", "eq.internal/")):
            go_types_set.add(fn_name[3:])
    go_types = sorted(go_types_set)

    go_source_files = sorted(
        {
            m.decode("utf-8", errors="ignore")
            for m in re.findall(rb"(?:/[a-zA-Z0-9_\-\.]+){2,}/[a-zA-Z0-9_\-]+\.go", data)
        }
    )

    # --- Rust Detection & Recovery ---
    rustc_commits = sorted(
        {m.decode("ascii", errors="ignore") for m in re.findall(rb"/rustc/([0-9a-f]{40})/", data)}
    )
    if rustc_commits:
        observations.append(
            f"Detected Rust compiler commit hash(es): {', '.join(rustc_commits[:3])}."
        )

    # Extract crates from Unix/Windows /cargo/registry/src/.../<crate>-<semver>/ and git checkouts
    rust_crates_map: dict[str, dict[str, str]] = {}
    for m in re.finditer(
        rb"(?:/|\\)cargo(?:/|\\)registry(?:/|\\)src(?:/|\\)[^/\\\x00]+(?:/|\\)([a-zA-Z0-9_\-]+)-(\d+\.\d+\.\d+[a-zA-Z0-9\.\-\+]*)(?:/|\\)",
        data,
    ):
        crate_name = m.group(1).decode("ascii", errors="ignore")
        crate_ver = m.group(2).decode("ascii", errors="ignore")
        rust_crates_map[f"{crate_name}@{crate_ver}"] = {
            "name": crate_name,
            "version": crate_ver,
            "source": "cargo-registry-path",
        }
    for m in re.finditer(
        rb"(?:/|\\)cargo(?:/|\\)git(?:/|\\)checkouts(?:/|\\)([a-zA-Z0-9_\-]+)-([0-9a-f]{7,16})(?:/|\\)",
        data,
    ):
        crate_name = m.group(1).decode("ascii", errors="ignore")
        git_rev = m.group(2).decode("ascii", errors="ignore")
        rust_crates_map[f"{crate_name}@{git_rev}"] = {
            "name": crate_name,
            "version": f"git:{git_rev}",
            "source": "cargo-git-checkout",
        }

    # Check for cargo-auditable (.dep-v0) compressed JSON if present
    dep_v0_marker = data.find(b".dep-v0")
    if dep_v0_marker != -1:
        observations.append(
            f"Observed '.dep-v0' (cargo-auditable) section marker near offset {hex(dep_v0_marker)}."
        )
        # Scan for zlib headers (0x78 0x9c, 0x78 0x01, 0x78 0xda) containing '"packages"'
        for z_match in re.finditer(rb"\x78[\x01\x9c\xda]", data):
            z_pos = z_match.start()
            try:
                decompressed = zlib.decompress(data[z_pos : z_pos + 65536])
                if b'"packages"' in decompressed:
                    parsed_audit = json.loads(decompressed.decode("utf-8", errors="ignore"))
                    for pkg in parsed_audit.get("packages", []):
                        c_name = str(pkg.get("name", ""))
                        c_ver = str(pkg.get("version", ""))
                        if c_name:
                            rust_crates_map[f"{c_name}@{c_ver}"] = {
                                "name": c_name,
                                "version": c_ver,
                                "source": "cargo-auditable (.dep-v0)",
                            }
                    observations.append(
                        f"Decoded cargo-auditable dependency graph with {len(parsed_audit.get('packages', []))} packages."
                    )
                    break
            except Exception:
                continue

    # Extract and demangle Rust mangled symbols (_ZN...E)
    raw_rust_syms = {
        m.decode("ascii", errors="ignore")
        for m in re.findall(rb"_?_ZN[0-9a-zA-Z_\$]{6,160}E", data)
    }
    demangled_rust_symbols: list[dict[str, str]] = []
    _rust_stdlib_crates = {
        "std",
        "core",
        "alloc",
        "proc_macro",
        "test",
        "rustc_std_workspace_core",
        "rustc_demangle",
        " unwind",
        "panic_unwind",
        "panic_abort",
    }
    for sym in sorted(raw_rust_syms):
        demangled = _demangle_rust_symbol(sym)
        if "::" in demangled:
            demangled_rust_symbols.append({"mangled": sym, "demangled": demangled})
            # Fallback crate inference from top-level namespace if not already in rust_crates_map
            top_ns = demangled.split("::", 1)[0].lstrip("_<>")
            if (
                top_ns
                and re.fullmatch(r"[a-z][a-z0-9_]{2,40}", top_ns)
                and top_ns not in _rust_stdlib_crates
                and not any(v["name"] == top_ns for v in rust_crates_map.values())
            ):
                rust_crates_map[f"{top_ns}@unknown"] = {
                    "name": top_ns,
                    "version": "unknown (inferred from symbol)",
                    "source": "symbol-namespace-inference",
                }

    rust_crates = sorted(rust_crates_map.values(), key=lambda x: x["name"])

    rust_source_files = sorted(
        {
            m.decode("utf-8", errors="ignore")
            for m in re.findall(rb"(?:[a-zA-Z0-9_\-]+/){1,8}[a-zA-Z0-9_\-]+\.rs", data)
        }
    )

    rust_panic_strings = sorted(
        {
            m.decode("utf-8", errors="ignore").strip()
            for m in re.findall(
                rb"(?:panicked at [^\x00\n\r]{4,120}|called `(?:Option|Result)::[a-z_]+\(\)` on an? `[^\x00\n\r]{2,80}|index out of bounds: the len is [^\x00\n\r]{2,60})",
                data,
            )
        }
    )

    # Determine primary language classification
    is_go = bool(pclntab_hits or go_build_id or go_version_matches or len(go_functions) >= 3)
    is_rust = bool(
        rustc_commits or rust_crates or len(demangled_rust_symbols) >= 3 or rust_panic_strings
    )

    if is_go and is_rust:
        detected_runtime = "go+rust (hybrid/cgo-ffi)"
        inferences.append(
            "Binary contains both Go runtime structures and Rust crate artifacts (likely FFI/CGO linkage)."
        )
    elif is_go:
        detected_runtime = "go"
        inferences.append(
            f"Binary is compiled with Go ({', '.join(go_version_matches[:2]) or 'version inferred from pclntab'})."
        )
    elif is_rust:
        detected_runtime = "rust"
        inferences.append("Binary is compiled with Rust (`rustc`).")
    else:
        detected_runtime = "unknown (neither Go nor Rust markers confirmed)"
        residual_unknowns.append(
            "No Go pclntab/buildinfo or Rust rustc/crate markers were observed; binary may be C/C++ or heavily packed."
        )

    summary_metrics = {
        "detected_runtime": detected_runtime,
        "go_compiler_versions": go_version_matches[:5],
        "go_build_id": go_build_id,
        "go_pclntab_count": len(pclntab_hits),
        "go_total_functions": len(go_functions),
        "go_user_functions_count": len(go_user_functions),
        "go_types_count": len(go_types),
        "go_modules_count": len(go_modules),
        "go_source_files_count": len(go_source_files),
        "rust_compiler_commits": rustc_commits[:3],
        "rust_crates_count": len(rust_crates),
        "rust_demangled_symbols_count": len(demangled_rust_symbols),
        "rust_source_files_count": len(rust_source_files),
        "rust_panic_strings_count": len(rust_panic_strings),
    }

    ev_id = get_evidence_cache().store(
        tool_name="inspect_go_rust_binary",
        target_path=str(validated),
        facets={
            "go_user_functions": go_user_functions,
            "go_types": go_types,
            "go_all_functions": go_functions,
            "go_modules": go_modules,
            "go_source_files": go_source_files,
            "rust_crates": rust_crates,
            "rust_symbols": demangled_rust_symbols,
            "rust_source_files": rust_source_files,
            "rust_panic_strings": rust_panic_strings,
        },
        summary=summary_metrics,
    )

    safe_limit = max(1, min(limit, 1000))
    if detail == "summary":
        return success(
            data={
                "status": "success",
                "file_path": str(validated),
                "detail_level": "summary",
                "evidence_id": ev_id,
                "parent_evidence_id": ev_id,
                "detected_runtime": detected_runtime,
                "summary": summary_metrics,
                "go_preview": {
                    "pclntab_headers": pclntab_hits[:3],
                    "sample_user_functions": go_user_functions[:10],
                    "sample_types": go_types[:10],
                    "sample_modules": go_modules[:5],
                },
                "rust_preview": {
                    "sample_crates": rust_crates[:10],
                    "sample_demangled_symbols": demangled_rust_symbols[:10],
                    "sample_panic_strings": rust_panic_strings[:5],
                },
                "observations": observations,
                "inferences": inferences,
                "residual_unknowns": residual_unknowns,
                "hint": (
                    f"Use inspect_analysis_view(evidence_id='{ev_id}', facet='go_user_functions' | 'go_types' | 'rust_crates' | 'rust_symbols') "
                    "to paginate full recovered tables."
                ),
            },
            message=f"Analyzed {validated.name}: detected runtime '{detected_runtime}' (evidence_id={ev_id}).",
        )

    return success(
        data={
            "status": "success",
            "file_path": str(validated),
            "detail_level": "full",
            "evidence_id": ev_id,
            "parent_evidence_id": ev_id,
            "detected_runtime": detected_runtime,
            "summary": summary_metrics,
            "go": {
                "pclntab_headers": pclntab_hits,
                "user_functions": go_user_functions[:safe_limit],
                "types": go_types[:safe_limit],
                "all_functions": go_functions[:safe_limit],
                "modules": go_modules[:safe_limit],
                "source_files": go_source_files[:safe_limit],
            },
            "rust": {
                "compiler_commits": rustc_commits,
                "crates": rust_crates[:safe_limit],
                "demangled_symbols": demangled_rust_symbols[:safe_limit],
                "source_files": rust_source_files[:safe_limit],
                "panic_strings": rust_panic_strings[:safe_limit],
            },
            "observations": observations,
            "inferences": inferences,
            "residual_unknowns": residual_unknowns,
        },
        message=f"Completed full Go/Rust inspection for {validated.name} (evidence_id={ev_id}).",
    )


# ==============================================================================
# 2. Electron ASAR Archive Inspector & Unpacker
# ==============================================================================
def _parse_asar_header(file_bytes: bytes) -> tuple[dict[str, Any], int]:
    """Parse Chromium Pickle header from an Electron `.asar` archive.

    Returns:
        Tuple of ``(header_json_dict, payload_base_offset)``.
    """
    if len(file_bytes) < 16:
        raise ValueError("File is too small (< 16 bytes) to be a valid Electron ASAR archive.")

    pickle_size, header_size, header_obj_size, json_str_len = struct.unpack(
        "<IIII", file_bytes[:16]
    )
    if pickle_size != 4:
        raise ValueError(
            f"Invalid ASAR Chromium Pickle header (expected pickle_size=4, got {pickle_size})."
        )

    payload_offset = 8 + header_size
    if 16 + json_str_len > len(file_bytes) or payload_offset > len(file_bytes):
        raise ValueError("Truncated ASAR archive: header length exceeds file size.")

    raw_json = file_bytes[16 : 16 + json_str_len].decode("utf-8", errors="replace").rstrip("\x00")
    tree = json.loads(raw_json)
    if not isinstance(tree, dict) or "files" not in tree:
        raise ValueError("ASAR header JSON does not contain a root 'files' object.")

    return tree, payload_offset


def _flatten_asar_tree(
    node: dict[str, Any],
    prefix: str = "",
) -> list[dict[str, Any]]:
    """Recursively flatten an ASAR ``files`` tree into a list of file records."""
    entries: list[dict[str, Any]] = []
    files_dict = node.get("files", {})
    if not isinstance(files_dict, dict):
        return entries

    for name, meta in sorted(files_dict.items()):
        rel_path = f"{prefix}/{name}" if prefix else name
        if not isinstance(meta, dict):
            continue
        if "files" in meta:
            entries.extend(_flatten_asar_tree(meta, rel_path))
        else:
            offset_val = meta.get("offset", "0")
            try:
                int_offset = int(offset_val)
            except (ValueError, TypeError):
                int_offset = 0
            size_val = int(meta.get("size", 0) or 0)
            integrity = meta.get("integrity", {})
            entries.append(
                {
                    "path": rel_path,
                    "size": size_val,
                    "offset": int_offset,
                    "unpacked": bool(meta.get("unpacked", False)),
                    "executable": bool(meta.get("executable", False)),
                    "sha256": integrity.get("hash") if isinstance(integrity, dict) else None,
                }
            )
    return entries


@log_execution(tool_name="inspect_electron_asar")
@track_metrics("inspect_electron_asar")
@handle_tool_errors
async def inspect_electron_asar(
    file_path: str,
    extract_path: str | None = None,
    search_pattern: str | None = None,
    detail: str = "summary",
) -> ToolResult:
    """Inspect, audit, and optionally unpack an Electron `.asar` application archive.

    Parses Chromium's binary Pickle header and JSON virtual filesystem in pure Python:
    - Inventories all bundled JavaScript, HTML, CSS, JSON, and `.node` native addons.
    - Extracts `package.json` metadata (app name, version, main entry, dependencies).
    - Audits Electron security settings (`nodeIntegration`, `contextIsolation`, `webSecurity`).
    - Discovers IPC attack surface (`ipcMain.handle`, `ipcMain.on`, `ipcRenderer.invoke`, `contextBridge`).
    - Optionally searches source files for `search_pattern` or extracts files into `extract_path`.

    Args:
        file_path: Path to the `.asar` file (e.g. `app.asar`).
        extract_path: Optional workspace directory path to unpack archive files into.
        search_pattern: Optional regex or substring pattern to search across bundled JS/JSON files.
        detail: Detail level ('summary' or 'full'). Default: 'summary'.

    Returns:
        ToolResult with package metadata, IPC channels, security findings, file inventory, and `evidence_id`.
    """
    validated = validate_file_path(file_path)
    file_bytes = validated.read_bytes()

    try:
        tree, payload_offset = _parse_asar_header(file_bytes)
    except Exception as exc:
        return failure(
            "INVALID_ASAR_FORMAT",
            f"Failed to parse Electron ASAR header from '{validated.name}': {exc}",
            hint="Verify the target is an unencrypted Electron .asar archive (starts with 0x04000000).",
        )

    files = _flatten_asar_tree(tree)
    package_info: dict[str, Any] = {}
    ipc_channels: set[str] = set()
    api_endpoints: set[str] = set()
    security_findings: list[dict[str, str]] = []
    pattern_matches: list[dict[str, Any]] = []

    compiled_search = None
    if search_pattern and search_pattern.strip():
        try:
            compiled_search = re.compile(search_pattern, re.IGNORECASE)
        except re.error:
            compiled_search = re.compile(re.escape(search_pattern), re.IGNORECASE)

    # Scan in-archive JS/JSON/HTML files
    for entry in files:
        if entry["unpacked"] or entry["size"] <= 0:
            continue
        start = payload_offset + entry["offset"]
        end = start + entry["size"]
        if end > len(file_bytes):
            continue

        p_lower = entry["path"].lower()
        if p_lower == "package.json" or (not package_info and p_lower.endswith("/package.json")):
            try:
                pkg_raw = json.loads(file_bytes[start:end].decode("utf-8", errors="replace"))
                if isinstance(pkg_raw, dict):
                    package_info = {
                        "name": pkg_raw.get("name"),
                        "version": pkg_raw.get("version"),
                        "main": pkg_raw.get("main"),
                        "author": pkg_raw.get("author"),
                        "dependencies": list((pkg_raw.get("dependencies") or {}).keys())[:50],
                        "devDependencies": list((pkg_raw.get("devDependencies") or {}).keys())[:30],
                    }
            except Exception:
                pass

        # Scan code/config files up to 2MB each
        if (
            p_lower.endswith((".js", ".mjs", ".cjs", ".ts", ".json", ".html"))
            and entry["size"] <= 2 * 1024 * 1024
        ):
            text = file_bytes[start:end].decode("utf-8", errors="replace")

            # IPC channel detection
            for ipc_m in re.finditer(
                r"(?:ipcMain|ipcRenderer)\.(?:on|once|handle|send|invoke|sendSync)\(\s*['\"]([^'\"]{1,80})['\"]",
                text,
            ):
                ipc_channels.add(ipc_m.group(1))

            for bridge_m in re.finditer(
                r"contextBridge\.exposeInMainWorld\(\s*['\"]([^'\"]{1,60})['\"]", text
            ):
                ipc_channels.add(f"contextBridge:{bridge_m.group(1)}")

            # Security flag audit
            if re.search(r"nodeIntegration\s*:\s*(?:true|!0)", text):
                security_findings.append(
                    {
                        "file": entry["path"],
                        "issue": "nodeIntegration: true",
                        "severity": "high",
                        "description": "Renderer process has direct Node.js access, increasing RCE risk on XSS.",
                    }
                )
            if re.search(r"contextIsolation\s*:\s*(?:false|!1)", text):
                security_findings.append(
                    {
                        "file": entry["path"],
                        "issue": "contextIsolation: false",
                        "severity": "high",
                        "description": "Preload context is shared with untrusted renderer DOM scripts.",
                    }
                )
            if re.search(r"webSecurity\s*:\s*(?:false|!1)", text):
                security_findings.append(
                    {
                        "file": entry["path"],
                        "issue": "webSecurity: false",
                        "severity": "medium",
                        "description": "Same-origin policy disabled in BrowserWindow.",
                    }
                )

            # Endpoints
            for url_m in re.finditer(
                r"https?://[a-zA-Z0-9\.\-]+(?::\d+)?(?:/[a-zA-Z0-9_\-\./]*)?", text
            ):
                url_str = url_m.group(0)
                if not any(
                    ignore in url_str for ignore in ("w3.org", "reactjs.org", "github.com/electron")
                ):
                    api_endpoints.add(url_str)

            # User search pattern
            if compiled_search:
                for m in compiled_search.finditer(text):
                    snippet_start = max(0, m.start() - 40)
                    snippet_end = min(len(text), m.end() + 60)
                    pattern_matches.append(
                        {
                            "file": entry["path"],
                            "match": m.group(0)[:100],
                            "context": text[snippet_start:snippet_end].replace("\n", " "),
                        }
                    )
                    if len(pattern_matches) >= 200:
                        break

    # Optional extraction to workspace
    extracted_count = 0
    resolved_extract_dir: str | None = None
    if extract_path:
        workspace_root = get_config().workspace.resolve()
        target_dir = Path(extract_path).expanduser().resolve()
        if not target_dir.is_relative_to(workspace_root):
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                f"extract_path '{extract_path}' must reside inside workspace '{workspace_root}'.",
            )
        target_dir.mkdir(parents=True, exist_ok=True)
        resolved_extract_dir = str(target_dir)

        for entry in files:
            if entry["unpacked"]:
                continue
            dest_file = (target_dir / entry["path"]).resolve()
            if not dest_file.is_relative_to(target_dir):
                continue
            start = payload_offset + entry["offset"]
            end = start + entry["size"]
            if end <= len(file_bytes):
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                dest_file.write_bytes(file_bytes[start:end])
                extracted_count += 1

    sorted_ipc = sorted(ipc_channels)
    sorted_urls = sorted(api_endpoints)
    native_addons = [f["path"] for f in files if f["path"].lower().endswith(".node")]
    js_files = [f for f in files if f["path"].lower().endswith((".js", ".mjs", ".cjs"))]

    summary_data = {
        "total_files": len(files),
        "js_files_count": len(js_files),
        "native_node_addons_count": len(native_addons),
        "ipc_channels_count": len(sorted_ipc),
        "api_endpoints_count": len(sorted_urls),
        "security_findings_count": len(security_findings),
        "pattern_matches_count": len(pattern_matches),
        "extracted_files_count": extracted_count,
    }

    ev_id = get_evidence_cache().store(
        tool_name="inspect_electron_asar",
        target_path=str(validated),
        facets={
            "files": files,
            "ipc_channels": sorted_ipc,
            "api_endpoints": sorted_urls,
            "security_findings": security_findings,
            "pattern_matches": pattern_matches,
            "native_addons": native_addons,
        },
        summary=summary_data,
    )

    if detail == "summary":
        return success(
            data={
                "status": "success",
                "file_path": str(validated),
                "detail_level": "summary",
                "evidence_id": ev_id,
                "parent_evidence_id": ev_id,
                "package_json": package_info,
                "summary": summary_data,
                "sample_files": [f["path"] for f in files[:15]],
                "ipc_channels_preview": sorted_ipc[:15],
                "api_endpoints_preview": sorted_urls[:10],
                "security_findings": security_findings[:10],
                "pattern_matches_preview": pattern_matches[:10],
                "extract_dir": resolved_extract_dir,
                "hint": (
                    f"Use inspect_analysis_view(evidence_id='{ev_id}', facet='files' | 'ipc_channels' | 'api_endpoints') "
                    "to paginate full ASAR contents."
                ),
            },
            message=f"Inspected Electron ASAR '{validated.name}': {len(files)} files, {len(sorted_ipc)} IPC channels (evidence_id={ev_id}).",
        )

    return success(
        data={
            "status": "success",
            "file_path": str(validated),
            "detail_level": "full",
            "evidence_id": ev_id,
            "parent_evidence_id": ev_id,
            "package_json": package_info,
            "summary": summary_data,
            "files": files[:500],
            "native_addons": native_addons,
            "ipc_channels": sorted_ipc,
            "api_endpoints": sorted_urls[:200],
            "security_findings": security_findings,
            "pattern_matches": pattern_matches,
            "extract_dir": resolved_extract_dir,
        },
        message=f"Completed full Electron ASAR analysis for '{validated.name}' (evidence_id={ev_id}).",
    )


# ==============================================================================
# 3. Unity IL2CPP Metadata Parser
# ==============================================================================
_IL2CPP_SANITY_MAGIC = 0xFAB11BAF


@log_execution(tool_name="inspect_unity_il2cpp")
@track_metrics("inspect_unity_il2cpp")
@handle_tool_errors
async def inspect_unity_il2cpp(
    metadata_path: str,
    binary_path: str | None = None,
    detail: str = "summary",
    limit: int = 100,
) -> ToolResult:
    """Parse Unity IL2CPP ``global-metadata.dat`` and optional ``libil2cpp.so`` / ``GameAssembly.dll``.

    Recovers managed C# string literals, namespaces, class names, and method identifiers
    directly from Unity's ``global-metadata.dat`` without requiring Unity or Il2CppDumper:
    - Validates header magic (`0xFAB11BAF`) and metadata format version (v24, v27, v29, v31+).
    - Detects encrypted/obfuscated metadata headers via entropy and magic diagnostics.
    - Extracts the C# `stringLiteral` table and identifier `string` table.
    - Optionally correlates native exports and registration routines in `binary_path`.

    Args:
        metadata_path: Path to `global-metadata.dat`.
        binary_path: Optional path to `libil2cpp.so` or `GameAssembly.dll`.
        detail: Detail level ('summary' or 'full'). Default: 'summary'.
        limit: Maximum items per table when detail='full' (default: 100, max: 1000).

    Returns:
        ToolResult with IL2CPP metadata header, recovered literals, class/method identifiers,
        epistemic ledger, and `evidence_id`.
    """
    validated_meta = validate_file_path(metadata_path)
    meta_bytes = validated_meta.read_bytes()

    if len(meta_bytes) < 32:
        return failure(
            "INVALID_IL2CPP_METADATA",
            f"File '{validated_meta.name}' is too small ({len(meta_bytes)} bytes) to be a Unity global-metadata.dat.",
        )

    sanity, version = struct.unpack("<II", meta_bytes[:8])
    entropy = _shannon_entropy(meta_bytes[:65536])

    observations: list[str] = []
    inferences: list[str] = []
    residual_unknowns: list[str] = []

    if sanity != _IL2CPP_SANITY_MAGIC:
        observations.append(
            f"Header magic is {hex(sanity)} (expected 0xfab11baf); first-64KB Shannon entropy is {entropy} bits/byte."
        )
        inferences.append(
            "global-metadata.dat header is obfuscated, XOR/AES encrypted, or uses a custom Unity loader."
        )
        residual_unknowns.append(
            "Cannot parse metadata tables until the header is decrypted via `il2cpp::vm::MetadataLoader::LoadMetadataFile`."
        )
        return success(
            data={
                "status": "encrypted_or_nonstandard_magic",
                "metadata_path": str(validated_meta),
                "header_magic": hex(sanity),
                "expected_magic": hex(_IL2CPP_SANITY_MAGIC),
                "reported_version_field": version,
                "entropy_bits_per_byte": entropy,
                "observations": observations,
                "inferences": inferences,
                "residual_unknowns": residual_unknowns,
                "hint": (
                    "Decompile 'MetadataLoader::LoadMetadataFile' in libil2cpp.so / GameAssembly.dll "
                    "using r2_decompile or reconstruct_feature_code to recover the decryption routine."
                ),
            },
            message=f"Unity global-metadata.dat has non-standard magic {hex(sanity)} (likely encrypted).",
        )

    observations.append(
        f"Verified Unity IL2CPP sanity magic 0xfab11baf and metadata version {version}."
    )

    # Standard Il2CppGlobalMetadataHeader layout (offsets 8..28):
    # [8]  stringLiteralOffset (int32)
    # [12] stringLiteralSize (int32)
    # [16] stringLiteralDataOffset (int32)
    # [20] stringLiteralDataSize (int32)
    # [24] stringOffset (int32)
    # [28] stringSize (int32)
    (
        str_lit_offset,
        str_lit_size,
        str_lit_data_offset,
        str_lit_data_size,
        str_offset,
        str_size,
    ) = struct.unpack("<iiiiii", meta_bytes[8:32])

    # 1. Recover C# String Literals
    string_literals: list[str] = []
    if (
        0 < str_lit_offset < len(meta_bytes)
        and str_lit_size >= 8
        and str_lit_offset + str_lit_size <= len(meta_bytes)
        and 0 < str_lit_data_offset < len(meta_bytes)
        and str_lit_data_offset + str_lit_data_size <= len(meta_bytes)
    ):
        num_literals = str_lit_size // 8
        for i in range(min(num_literals, 20000)):
            entry_pos = str_lit_offset + (i * 8)
            lit_len, data_idx = struct.unpack("<II", meta_bytes[entry_pos : entry_pos + 8])
            abs_start = str_lit_data_offset + data_idx
            abs_end = abs_start + lit_len
            if 0 < lit_len <= 4096 and abs_end <= str_lit_data_offset + str_lit_data_size:
                val = meta_bytes[abs_start:abs_end].decode("utf-8", errors="replace").strip()
                if val:
                    string_literals.append(val)

    # 2. Recover Identifier Strings (Namespaces, Classes, Methods, Fields)
    identifiers: list[str] = []
    if (
        0 < str_offset < len(meta_bytes)
        and str_size > 0
        and str_offset + str_size <= len(meta_bytes)
    ):
        raw_ident_blob = meta_bytes[str_offset : str_offset + str_size]
        for raw_token in raw_ident_blob.split(b"\x00"):
            if 1 <= len(raw_token) <= 200:
                tok = raw_token.decode("utf-8", errors="ignore").strip()
                if tok and tok.isprintable():
                    identifiers.append(tok)

    # Classify identifiers heuristically into namespaces, classes, and methods
    namespaces = sorted(
        {
            ident
            for ident in identifiers
            if "." in ident
            and not ident.startswith("<")
            and all(part[:1].isupper() for part in ident.split(".") if part)
        }
    )
    class_candidates = [
        ident
        for ident in identifiers
        if "." not in ident
        and ident[:1].isupper()
        and any(
            ident.endswith(suffix)
            for suffix in (
                "Controller",
                "Manager",
                "Service",
                "Client",
                "Config",
                "Crypto",
                "Cipher",
                "Player",
                "Network",
                "Handler",
                "System",
                "Behavior",
                "Behaviour",
            )
        )
    ]
    if not class_candidates:
        class_candidates = [
            ident
            for ident in identifiers
            if "." not in ident and ident[:1].isupper() and ident.isalnum() and len(ident) >= 4
        ]

    method_candidates = [
        ident
        for ident in identifiers
        if "." not in ident
        and (
            ident.startswith(
                (
                    "get_",
                    "set_",
                    "On",
                    "Update",
                    "Start",
                    "Awake",
                    "Init",
                    "Decrypt",
                    "Encrypt",
                    "Verify",
                )
            )
            or ("_" in ident and ident.isidentifier())
        )
    ]

    # 3. Optional Native Binary (`libil2cpp.so` / `GameAssembly.dll`) correlation
    binary_correlation: dict[str, Any] | None = None
    if binary_path:
        validated_bin = validate_file_path(binary_path)
        bin_bytes = validated_bin.read_bytes()[:_MAX_SCAN_BYTES]
        il2cpp_exports = sorted(
            {
                m.decode("ascii", errors="ignore")
                for m in re.findall(rb"\bil2cpp_[a-z0-9_]{3,60}\b", bin_bytes)
            }
        )
        binary_correlation = {
            "binary_path": str(validated_bin),
            "il2cpp_exports_count": len(il2cpp_exports),
            "sample_exports": il2cpp_exports[:25],
        }
        observations.append(
            f"Correlated native binary '{validated_bin.name}' with {len(il2cpp_exports)} il2cpp_* API symbols."
        )
    else:
        residual_unknowns.append(
            "Native binary (libil2cpp.so / GameAssembly.dll) was not supplied; method RVA virtual addresses remain unlinked."
        )

    summary_metrics = {
        "metadata_version": version,
        "header_magic": hex(sanity),
        "string_literals_count": len(string_literals),
        "identifiers_count": len(identifiers),
        "namespaces_count": len(namespaces),
        "class_candidates_count": len(class_candidates),
        "method_candidates_count": len(method_candidates),
    }

    ev_id = get_evidence_cache().store(
        tool_name="inspect_unity_il2cpp",
        target_path=str(validated_meta),
        facets={
            "string_literals": string_literals,
            "identifiers": identifiers,
            "namespaces": namespaces,
            "class_candidates": class_candidates,
            "method_candidates": method_candidates,
        },
        summary=summary_metrics,
    )

    safe_limit = max(1, min(limit, 1000))
    if detail == "summary":
        return success(
            data={
                "status": "success",
                "metadata_path": str(validated_meta),
                "detail_level": "summary",
                "evidence_id": ev_id,
                "parent_evidence_id": ev_id,
                "summary": summary_metrics,
                "preview": {
                    "sample_string_literals": string_literals[:15],
                    "sample_namespaces": namespaces[:15],
                    "sample_classes": class_candidates[:15],
                    "sample_methods": method_candidates[:15],
                },
                "binary_correlation": binary_correlation,
                "observations": observations,
                "inferences": inferences,
                "residual_unknowns": residual_unknowns,
                "hint": (
                    f"Use inspect_analysis_view(evidence_id='{ev_id}', facet='string_literals' | 'class_candidates' | 'method_candidates') "
                    "to paginate and filter Unity IL2CPP metadata."
                ),
            },
            message=f"Parsed Unity IL2CPP metadata v{version}: {len(string_literals)} literals, {len(identifiers)} identifiers (evidence_id={ev_id}).",
        )

    return success(
        data={
            "status": "success",
            "metadata_path": str(validated_meta),
            "detail_level": "full",
            "evidence_id": ev_id,
            "parent_evidence_id": ev_id,
            "summary": summary_metrics,
            "string_literals": string_literals[:safe_limit],
            "namespaces": namespaces[:safe_limit],
            "class_candidates": class_candidates[:safe_limit],
            "method_candidates": method_candidates[:safe_limit],
            "identifiers": identifiers[:safe_limit],
            "binary_correlation": binary_correlation,
            "observations": observations,
            "inferences": inferences,
            "residual_unknowns": residual_unknowns,
        },
        message=f"Completed full Unity IL2CPP metadata extraction (v{version}, evidence_id={ev_id}).",
    )
