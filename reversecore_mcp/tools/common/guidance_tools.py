"""On-Demand Documentation & Reverse Engineering Guidance Tools for Reversecore_MCP.

Provides ``search_guidance`` and ``read_guidance_section`` so AI agents can
discover and read target-specific reverse engineering methodologies, tool recipes,
and architecture guides on demand without inflating the system prompt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success


@dataclass(frozen=True)
class GuidanceSection:
    """Represents an addressable section of documentation or a built-in playbook."""

    locator: str
    title: str
    category: str
    tags: tuple[str, ...]
    content: str


_BUILTIN_PLAYBOOKS: tuple[GuidanceSection, ...] = (
    GuidanceSection(
        locator="playbook:target-routing#overview",
        title="Target Routing & First-Tool Selection Guide",
        category="workflow",
        tags=("routing", "overview", "native", "asar", "go", "rust", "il2cpp", "unity", "triage"),
        content=(
            "## Target Routing & First-Tool Selection\n\n"
            "Always route the investigation based on the artifact format first:\n\n"
            "1. **Unknown Binary / File Identification**:\n"
            "   - Run `run_file(file_path)` and `parse_binary_with_lief(file_path)` to identify format (PE/ELF/Mach-O), architecture, and security mitigations.\n"
            "2. **Go or Rust Native Binaries (even when stripped)**:\n"
            "   - Call `inspect_go_rust_binary(file_path, detail='summary')` to recover `gopclntab` function names, Go buildinfo modules, Rust crate dependencies (`.dep-v0`), and demangled symbols without needing a disassembler.\n"
            "3. **Electron Desktop Applications (`app.asar`)**:\n"
            "   - Call `inspect_electron_asar(file_path, detail='summary')` to parse the Chromium Pickle header, list bundled JS/JSON files, inspect `package.json`, detect `ipcMain`/`ipcRenderer` channels, and optionally unpack sources.\n"
            "4. **Unity IL2CPP Games (`global-metadata.dat` + `libil2cpp.so` / `GameAssembly.dll`)**:\n"
            "   - Call `inspect_unity_il2cpp(metadata_path, binary_path=..., detail='summary')` to recover managed namespaces, class definitions, method names, and decrypted string literals.\n"
            "5. **Native C/C++ Functions & Feature Reconstruction**:\n"
            "   - Start with `Radare2_decompile_function(file_path, address, detail='summary')` or `r2_decompile(file_path, address, detail='summary')`.\n"
            "   - To rebuild a binary feature in modern C or Python with ESIL behavioral verification, call `reconstruct_feature_code(file_path, address_or_symbol, target_language='python')`.\n"
            "6. **Network PCAP & Memory Dumps**:\n"
            "   - Use `pcap_analyze` / `pcap_extract_c2` for network captures and `memory_analyze` / `memory_extract_strings(dump_path, detail='summary')` for RAM dumps."
        ),
    ),
    GuidanceSection(
        locator="playbook:summary-first-paging#workflow",
        title="Summary-First Paging & Retained Evidence Workflow",
        category="context-optimization",
        tags=(
            "summary",
            "paging",
            "evidence_id",
            "inspect_analysis_view",
            "context",
            "large-binary",
        ),
        content=(
            "## Summary-First Paging Workflow\n\n"
            "When analyzing large binaries (10MB+ executables, thousands of strings, or huge functions), "
            "requesting full output immediately can overflow the MCP transport or LLM context window.\n\n"
            "### Step-by-Step Recipe\n"
            "1. **Request Summary First**:\n"
            "   Pass `detail='summary'` to `Radare2_disassemble`, `Radare2_disassemble_function`, "
            "`Radare2_decompile_function`, `r2_decompile`, `Radare2_list_strings`, `memory_extract_strings`, "
            "`inspect_go_rust_binary`, `inspect_electron_asar`, or `inspect_unity_il2cpp`.\n"
            "2. **Capture the `evidence_id`**:\n"
            '   The summary response includes a retained handle such as `"evidence_id": "ev_8f3a92b1c4d0"` '
            "along with high-level metrics (branch counts, loop counts, string categories, preview items).\n"
            "3. **Paginate & Filter On-Demand**:\n"
            "   Call `inspect_analysis_view(evidence_id='ev_8f3a92b1c4d0', facet='strings', offset=0, limit=50, filter_query='http')` "
            "to retrieve only the exact page or filtered subset needed to answer the user's question.\n"
            "4. **List Active Evidence Handles**:\n"
            "   Call `inspect_analysis_view(evidence_id='list')` at any time to see all retained evidence records in the current session."
        ),
    ),
    GuidanceSection(
        locator="playbook:go-rust-reversing#gopclntab-and-crates",
        title="Go & Rust Stripped Binary Analysis Guide",
        category="modern-runtimes",
        tags=("golang", "go", "rust", "gopclntab", "pclntab", "cargo", "demangle", "stripped"),
        content=(
            "## Reversing Stripped Go & Rust Binaries\n\n"
            "Go and Rust binaries are notoriously challenging in traditional disassemblers because they use "
            "custom ABI conventions, static linking, and non-null-terminated strings.\n\n"
            "### Go Binary Recovery (`inspect_go_rust_binary`)\n"
            "- **Magic Signatures**: Even when `strip` removes the ELF/PE symbol table, Go binaries retain "
            "the `.gopclntab` runtime table (magic bytes `0xfffffffb`, `0xfffffffa`, `0xfffffff0`, or `0xfffffff1` for Go 1.2–1.22+).\n"
            "- **Module Metadata**: Go embeds `\\xff Go buildinf:` and module dependency tables (`path`, `mod`, `dep`, `build`).\n"
            "- **Workflow**: Run `inspect_go_rust_binary(file_path, detail='summary')` first, then filter user packages "
            "via `inspect_analysis_view(evidence_id, facet='functions', filter_query='main.')`.\n\n"
            "### Rust Binary Recovery (`inspect_go_rust_binary`)\n"
            "- **Compiler Identification**: Extracts `/rustc/<40-hex-commit>/` commit hashes and standard library version indicators.\n"
            "- **Crate Dependency Graph**: Decodes `.dep-v0` (`cargo-auditable` zlib-compressed JSON) when present, "
            "and extracts `/cargo/registry/src/.../<crate>-<version>/` panic source paths.\n"
            "- **Symbol Demangling**: Automatically demangles legacy (`_ZN...E`) and v0 (`_R...`) Rust symbols into `crate::module::fn` format."
        ),
    ),
    GuidanceSection(
        locator="playbook:electron-asar#unpacking-and-ipc",
        title="Electron ASAR Archive Unpacking & Security Audit Guide",
        category="modern-runtimes",
        tags=("electron", "asar", "javascript", "node", "ipc", "pickle", "unpack", "fuses"),
        content=(
            "## Electron Application (`app.asar`) Reverse Engineering\n\n"
            "Electron applications bundle their main process, preload scripts, and renderer web assets into "
            "an `app.asar` archive using Chromium's binary Pickle format.\n\n"
            "### Workflow with `inspect_electron_asar`\n"
            "1. **Inventory & Security Triage**:\n"
            "   Call `inspect_electron_asar(file_path, detail='summary')`. This parses the 16-byte Pickle header and JSON file index in pure Python.\n"
            "2. **Audit Electron Security Configurations**:\n"
            "   Check `security_findings` for dangerous `BrowserWindow` flags (`nodeIntegration: true`, `contextIsolation: false`, `webSecurity: false`).\n"
            "3. **Trace IPC Attack Surface**:\n"
            "   Inspect `ipc_channels` (`ipcMain.handle`, `ipcMain.on`, `ipcRenderer.invoke`, `contextBridge.exposeInMainWorld`) to find privileged native bridges.\n"
            "4. **Search or Extract Specific Sources**:\n"
            "   Pass `search_pattern='api_key'` to scan bundled JS files, or pass `extract_path='/workspace/asar_unpacked'` to extract the source tree for `audit_source_code`."
        ),
    ),
    GuidanceSection(
        locator="playbook:unity-il2cpp#metadata-recovery",
        title="Unity IL2CPP Metadata (`global-metadata.dat`) Recovery Guide",
        category="modern-runtimes",
        tags=("unity", "il2cpp", "global-metadata", "gamedev", "csharp", "android", "gameassembly"),
        content=(
            "## Unity IL2CPP Metadata & Binary Analysis\n\n"
            "Unity IL2CPP compiles C# assemblies into native machine code (`libil2cpp.so` on Android/Linux or `GameAssembly.dll` on Windows) "
            "while storing all reflection metadata, class names, method signatures, and string literals in `global-metadata.dat`.\n\n"
            "### Workflow with `inspect_unity_il2cpp`\n"
            "1. **Validate Header & Version**:\n"
            "   `inspect_unity_il2cpp(metadata_path)` checks the `0xFAB11BAF` sanity magic and metadata version (v24–v31+). "
            "If the magic does not match, the metadata file is likely XOR/AES encrypted or obfuscated (e.g., BeeByte/Obfuscator) — "
            "in that case, decompile `il2cpp::vm::MetadataLoader::LoadMetadataFile` in `libil2cpp.so` using `r2_decompile`.\n"
            "2. **Recover Classes, Methods, and String Literals**:\n"
            "   Use `inspect_analysis_view(evidence_id, facet='string_literals', filter_query='http')` to find API endpoints, "
            "or `facet='identifiers'` to locate gameplay/crypto classes (`PlayerController`, `Decrypt`, `License`)."
        ),
    ),
    GuidanceSection(
        locator="playbook:feature-reconstruction#equivalence-loop",
        title="Feature Code Reconstruction & ESIL Equivalence Verification",
        category="reconstruction",
        tags=(
            "reconstruct",
            "reconstruct_feature_code",
            "equivalence",
            "esil",
            "decompile",
            "python",
            "c",
        ),
        content=(
            "## Reconstructing Binary Features with Equivalence Proofs\n\n"
            "When a user asks to understand how an app feature, hash function, or algorithm works and rebuild it:\n\n"
            "1. **Run `reconstruct_feature_code`**:\n"
            "   `reconstruct_feature_code(file_path, address_or_symbol, target_language='python', test_inputs=[{'eax': 0x10}])`\n"
            "2. **Inspect the Verification Ledger**:\n"
            "   - `decompilation_completeness`: Confirms r2ghidra/pdc recovered instructions without badop gaps.\n"
            "   - `structural_branch_parity`: Compares control-flow branches between original binary and synthesized code.\n"
            "   - `api_call_preservation`: Verifies external library calls are preserved.\n"
            "   - `esil_behavioral_equivalence`: Executes test vectors on the binary via Radare2 ESIL emulation.\n"
            "3. **Respect Epistemological Boundaries**:\n"
            "   Always report `observations`, `inferences`, and `residual_unknowns` distinctly."
        ),
    ),
    GuidanceSection(
        locator="playbook:epistemological-discipline#anti-hallucination",
        title="Epistemological Discipline: Observations vs Inferences vs Unknowns",
        category="methodology",
        tags=(
            "epistemology",
            "observations",
            "inferences",
            "unknowns",
            "evidence",
            "hallucination",
        ),
        content=(
            "## The Anti-Hallucination Evidence Contract\n\n"
            "Every reverse engineering conclusion must separate three epistemic tiers:\n\n"
            "1. **Observations (Proven Facts)**:\n"
            "   Direct byte/tool outputs (e.g. 'Function at 0x401000 contains 42 instructions and calls `CryptEncrypt` at 0x40105a').\n"
            "2. **Inferences (Analytical Hypotheses)**:\n"
            "   Interpretations derived from observations (e.g. 'Based on the constants 0x67452301 and 0xefcdab89, this routine likely implements MD5 or SHA-1').\n"
            "3. **Residual Unknowns (Explicit Gaps)**:\n"
            "   Unresolved indirect jumps (`call rax`), stripped external dependencies, unexecuted dynamic paths, or truncated pages.\n"
            "4. **No Proof of Absence**:\n"
            "   Absence of evidence in a truncated/summary view MUST NEVER be reported as proof that a capability or vulnerability does not exist."
        ),
    ),
)


def _slugify(heading: str) -> str:
    """Convert a markdown heading into a clean URL/locator slug."""
    cleaned = re.sub(r"[^a-zA-Z0-9\s\-_]", "", heading).strip().lower()
    return re.sub(r"[\s_]+", "-", cleaned) or "overview"


def _discover_markdown_sections() -> list[GuidanceSection]:
    """Scan local ``docs/`` and ``.agents/skills/`` directories for markdown sections."""
    sections: list[GuidanceSection] = list(_BUILTIN_PLAYBOOKS)
    repo_root = Path(__file__).resolve().parents[3]

    search_roots: list[tuple[Path, str]] = [
        (repo_root / "docs", "docs"),
        (repo_root / ".agents" / "skills", "skill"),
    ]

    for root_dir, default_cat in search_roots:
        if not root_dir.is_dir():
            continue
        for md_path in sorted(root_dir.rglob("*.md")):
            try:
                rel_path = md_path.relative_to(repo_root).as_posix()
                raw_text = md_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Split markdown by ## headings
            parts = re.split(r"(?m)^(?=##\s+)", raw_text)
            for idx, part in enumerate(parts):
                part_stripped = part.strip()
                if not part_stripped:
                    continue
                lines = part_stripped.splitlines()
                first_line = lines[0].lstrip("#").strip() if lines else md_path.stem
                slug = _slugify(first_line) if idx > 0 else "overview"
                locator = f"{rel_path}#{slug}"
                category = md_path.parent.name if md_path.parent != root_dir else default_cat
                tags = tuple(
                    w for w in re.findall(r"[a-z0-9_]{3,}", f"{rel_path} {first_line}".lower())
                )
                sections.append(
                    GuidanceSection(
                        locator=locator,
                        title=f"{md_path.stem}: {first_line}",
                        category=category,
                        tags=tags,
                        content=part_stripped,
                    )
                )

    return sections


@log_execution(tool_name="search_guidance")
@track_metrics("search_guidance")
@handle_tool_errors
async def search_guidance(
    query: str,
    category: str | None = None,
    limit: int = 10,
) -> ToolResult:
    """Search reverse engineering playbooks, tool recipes, and documentation on demand.

    Use this tool when encountering an unfamiliar target format (e.g. Go/Rust binaries,
    Electron ASAR bundles, Unity IL2CPP metadata), workflow (summary-first paging,
    feature reconstruction), or architecture question instead of guessing parameters.

    Args:
        query: Search keywords (e.g. 'go binary', 'asar', 'il2cpp', 'paging', 'reconstruct', 'emulation').
        category: Optional category filter (e.g. 'workflow', 'modern-runtimes', 'user-guide', 'api').
        limit: Maximum number of matching sections to return (default: 10, max: 30).

    Returns:
        ToolResult with ranked guidance locators, titles, categories, and snippets.
    """
    sections = _discover_markdown_sections()
    q_clean = (query or "").strip().lower()
    tokens = [t for t in re.split(r"[\s,;/\-]+", q_clean) if t]
    cat_filter = category.strip().lower() if category else None

    matches: list[dict[str, Any]] = []
    for sec in sections:
        if (
            cat_filter
            and cat_filter not in sec.category.lower()
            and cat_filter not in sec.locator.lower()
        ):
            continue

        if not tokens:
            score = 10 if sec.locator.startswith("playbook:") else 5
        else:
            score = 0
            title_lower = sec.title.lower()
            loc_lower = sec.locator.lower()
            body_lower = sec.content.lower()

            if q_clean in title_lower:
                score += 60
            if q_clean in loc_lower:
                score += 50

            for tok in tokens:
                if tok in sec.tags:
                    score += 30
                if tok in title_lower:
                    score += 25
                if tok in loc_lower:
                    score += 20
                if tok in body_lower:
                    score += 10

            if score > 0 and sec.locator.startswith("playbook:"):
                score += 15  # Prioritize curated playbooks

        if score > 0:
            preview_lines = [
                line.strip()
                for line in sec.content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            snippet = " ".join(preview_lines)[:220]
            matches.append(
                {
                    "locator": sec.locator,
                    "title": sec.title,
                    "category": sec.category,
                    "score": score,
                    "char_length": len(sec.content),
                    "snippet": snippet,
                }
            )

    matches.sort(key=lambda x: x["score"], reverse=True)
    safe_limit = max(1, min(limit, 30))
    top_matches = matches[:safe_limit]

    return success(
        data={
            "query": query,
            "category_filter": category,
            "total_matches": len(matches),
            "returned_matches": len(top_matches),
            "results": top_matches,
            "hint": "Call read_guidance_section(locator='...') to read the full content of a section.",
        },
        message=f"Found {len(matches)} guidance section(s) matching '{query}'.",
    )


@log_execution(tool_name="read_guidance_section")
@track_metrics("read_guidance_section")
@handle_tool_errors
async def read_guidance_section(
    locator: str,
    max_chars: int = 4000,
) -> ToolResult:
    """Read the full markdown content of a specific guidance section by its locator.

    Args:
        locator: Section locator returned by ``search_guidance``
            (e.g. 'playbook:go-rust-reversing#gopclntab-and-crates' or 'docs/EMULATION.md#overview').
        max_chars: Maximum characters to return (default: 4000, max: 20000).

    Returns:
        ToolResult with the markdown section content and related section locators.
    """
    clean_loc = (locator or "").strip()
    if not clean_loc:
        return failure("VALIDATION_ERROR", "locator is required.")

    sections = _discover_markdown_sections()
    safe_max = max(200, min(max_chars, 20000))

    # 1. Exact locator match
    target: GuidanceSection | None = None
    for sec in sections:
        if sec.locator.lower() == clean_loc.lower():
            target = sec
            break

    # 2. Prefix or substring fallback (e.g. 'playbook:go-rust-reversing' without '#slug')
    if target is None:
        for sec in sections:
            if (
                sec.locator.lower().startswith(clean_loc.lower())
                or clean_loc.lower() in sec.locator.lower()
            ):
                target = sec
                break

    if target is None:
        available_playbooks = [s.locator for s in _BUILTIN_PLAYBOOKS]
        return failure(
            "GUIDANCE_NOT_FOUND",
            f"Guidance section '{clean_loc}' not found.",
            hint=f"Use search_guidance(query='...') or choose a built-in playbook: {', '.join(available_playbooks)}",
        )

    content = target.content
    truncated = len(content) > safe_max
    if truncated:
        content = content[:safe_max] + "\n... [truncated]"

    # Find sibling sections in the same file/playbook prefix
    prefix = target.locator.split("#")[0]
    related = [
        s.locator
        for s in sections
        if s.locator != target.locator
        and (s.locator.startswith(prefix) or s.category == target.category)
    ][:8]

    return success(
        data={
            "locator": target.locator,
            "title": target.title,
            "category": target.category,
            "content": content,
            "char_length": len(target.content),
            "truncated": truncated,
            "related_locators": related,
        },
        message=f"Loaded guidance section '{target.title}' ({len(content)} chars).",
    )
