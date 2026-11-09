# Modern Runtime Targets Reference (Go, Rust, Electron ASAR, Unity IL2CPP)

## 1. Stripped Go & Rust Binaries (`inspect_go_rust_binary`)

- **Go (`gopclntab` & `buildinfo`)**:
  - Even when stripped (`strip -s`), Go binaries keep `.gopclntab` (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`).
  - Start with `inspect_go_rust_binary(file_path, detail="summary")`.
  - Filter recovered user functions with `inspect_analysis_view(evidence_id, facet="go_user_functions", filter_query="main.")`.
- **Rust (`.dep-v0` & Symbol Demangling)**:
  - Extracts `/rustc/<40-hex>/` commit provenance, `/cargo/registry/src/` crate versions, and `.dep-v0` (`cargo-auditable`) zlib JSON dependency graphs.
  - Automatically demangles `_ZN...E` symbols into `crate::module::function`.

## 2. Electron ASAR Archives (`inspect_electron_asar`)

- Parses Chromium's 16-byte Pickle header and JSON virtual file tree in pure Python.
- Audits `BrowserWindow` configurations for `nodeIntegration: true`, `contextIsolation: false`, and `webSecurity: false`.
- Extracts `ipcMain.handle` / `ipcRenderer.invoke` / `contextBridge.exposeInMainWorld` channels.
- Pass `extract_path="/app/workspace/unpacked_asar"` to extract bundled source files for deeper AST auditing via `audit_source_code`.

## 3. Unity IL2CPP (`inspect_unity_il2cpp`)

- Checks `0xFAB11BAF` sanity magic and metadata version (v24–v31+).
- Extracts C# `string_literals` and `identifiers` (`namespaces`, `class_candidates`, `method_candidates`).
- If `status == "encrypted_or_nonstandard_magic"`, decompile `il2cpp::vm::MetadataLoader::LoadMetadataFile` in `libil2cpp.so` using `r2_decompile`.
