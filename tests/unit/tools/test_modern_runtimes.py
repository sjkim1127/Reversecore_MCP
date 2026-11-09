"""Unit tests for Modern Application Runtime Analyzers (Go/Rust, Electron ASAR, Unity IL2CPP)."""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reversecore_mcp.core.result import ToolSuccess
from reversecore_mcp.tools.analysis.modern_runtimes import (
    _demangle_rust_symbol,
    inspect_electron_asar,
    inspect_go_rust_binary,
    inspect_unity_il2cpp,
)
from reversecore_mcp.tools.common.evidence_view_tools import inspect_analysis_view


@pytest.mark.unit
def test_demangle_rust_symbol():
    """Verify legacy Rust symbol demangling and escape decoding."""
    mangled = "_ZN5tokio7runtime4task17h1234567890abcdefE"
    assert _demangle_rust_symbol(mangled) == "tokio::runtime::task"

    escaped = "_ZN4core3fmt9Arguments17new_v1$LT$str$GT$17habcdef0123456789E"
    assert _demangle_rust_symbol(escaped) == "core::fmt::Arguments::new_v1<str>"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_inspect_go_binary(tmp_path: Path):
    """Verify stripped Go binary pclntab, build ID, module, and function recovery."""
    go_bin = tmp_path / "stripped_go_app"
    payload = (
        b"\x7fELF"
        + b"\x00" * 32
        + b'\xff Go build ID: "a1b2c3d4/e5f6g7h8"\x00'
        + b"go1.22.3\x00"
        + b"\xf1\xff\xff\xff\x00\x00\x01\x08"  # Go 1.20+ pclntab magic (ptr_size=8)
        + b"\npath\tgithub.com/acme/c2agent\n"
        + b"mod\tgithub.com/acme/c2agent\tv1.2.0\n"
        + b"dep\tgolang.org/x/crypto\tv0.21.0\n"
        + b"main.main\x00main.handleBeacon\x00main.encryptPayload\x00runtime.gopanic\x00"
        + b"/Users/dev/go/src/acme/c2agent/main.go\x00"
    )
    go_bin.write_bytes(payload)

    with patch(
        "reversecore_mcp.tools.analysis.modern_runtimes.validate_file_path",
        return_value=go_bin,
    ):
        res = await inspect_go_rust_binary(str(go_bin), detail="summary")
        assert isinstance(res, ToolSuccess)
        data = res.data
        assert data["detected_runtime"] == "go"
        assert data["summary"]["go_build_id"] == "a1b2c3d4/e5f6g7h8"
        assert data["summary"]["go_pclntab_count"] >= 1
        assert "main.handleBeacon" in data["go_preview"]["sample_user_functions"]
        ev_id = data["evidence_id"]
        assert ev_id.startswith("ev_")

        # Verify pagination via inspect_analysis_view
        view_res = await inspect_analysis_view(
            evidence_id=ev_id, facet="go_user_functions", filter_query="Beacon"
        )
        assert isinstance(view_res, ToolSuccess)
        assert "main.handleBeacon" in view_res.data["items"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_inspect_rust_binary(tmp_path: Path):
    """Verify Rust binary rustc commit, cargo-auditable .dep-v0, and symbol demangling."""
    rust_bin = tmp_path / "rust_agent"
    audit_json = json.dumps(
        {
            "packages": [
                {"name": "reqwest", "version": "0.11.24"},
                {"name": "tokio", "version": "1.36.0"},
            ]
        }
    ).encode("utf-8")
    compressed_audit = zlib.compress(audit_json)

    payload = (
        b"\x7fELF"
        + b"/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce/library/core/src/panicking.rs\x00"
        + b"/cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.197/src/lib.rs\x00"
        + b".dep-v0\x00"
        + compressed_audit
        + b"\x00_ZN7reqwest6Client3get17h1234567890abcdefE\x00"
        + b"_ZN5tokio7runtime7Builder17habcdef1234567890E\x00"
        + b"_ZN4core3fmt5write17h1122334455667788E\x00"
    )
    rust_bin.write_bytes(payload)

    with patch(
        "reversecore_mcp.tools.analysis.modern_runtimes.validate_file_path",
        return_value=rust_bin,
    ):
        res = await inspect_go_rust_binary(str(rust_bin), detail="full")
        assert isinstance(res, ToolSuccess)
        data = res.data
        assert data["detected_runtime"] == "rust"
        crate_names = [c["name"] for c in data["rust"]["crates"]]
        assert "reqwest" in crate_names
        assert "tokio" in crate_names
        assert "serde" in crate_names
        demangled = [s["demangled"] for s in data["rust"]["demangled_symbols"]]
        assert "reqwest::Client::get" in demangled


def _build_test_asar(files_map: dict[str, bytes]) -> bytes:
    """Construct a valid Chromium Pickle Electron .asar archive from a file dict."""
    tree_files: dict[str, dict] = {}
    payload_chunks: list[bytes] = []
    current_offset = 0

    for name, content in files_map.items():
        tree_files[name] = {
            "size": len(content),
            "offset": str(current_offset),
        }
        payload_chunks.append(content)
        current_offset += len(content)

    header_json = json.dumps({"files": tree_files}).encode("utf-8")
    json_len = len(header_json)
    # Pad JSON to 4-byte alignment
    padding = (4 - (json_len % 4)) % 4
    padded_json = header_json + (b"\x00" * padding)

    header_obj_size = 4 + len(padded_json)
    header_size = 4 + header_obj_size
    pickle_header = struct.pack("<IIII", 4, header_size, header_obj_size, json_len)
    return pickle_header + padded_json + b"".join(payload_chunks)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_inspect_electron_asar(tmp_path: Path):
    """Verify Electron .asar parsing, IPC extraction, security flags, and extraction."""
    asar_file = tmp_path / "app.asar"
    pkg_json = json.dumps(
        {
            "name": "secret-desktop-app",
            "version": "2.4.1",
            "main": "main.js",
            "dependencies": {"electron-updater": "^6.0.0"},
        }
    ).encode("utf-8")
    main_js = (
        b"const { app, BrowserWindow, ipcMain } = require('electron');\n"
        b"const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n"
        b"ipcMain.handle('execute-shell-cmd', async (e, cmd) => {});\n"
        b"const endpoint = 'https://api.secret-app.io/v1/telemetry';\n"
        b"const ADMIN_TOKEN = 'bearer_token_9988776655';\n"
    )
    asar_file.write_bytes(_build_test_asar({"package.json": pkg_json, "main.js": main_js}))

    extract_dir = tmp_path / "unpacked"
    mock_cfg = MagicMock()
    mock_cfg.workspace = tmp_path

    with patch(
        "reversecore_mcp.tools.analysis.modern_runtimes.validate_file_path",
        return_value=asar_file,
    ):
        with patch(
            "reversecore_mcp.tools.analysis.modern_runtimes.get_config",
            return_value=mock_cfg,
        ):
            res = await inspect_electron_asar(
                str(asar_file),
                extract_path=str(extract_dir),
                search_pattern="bearer_token_",
                detail="summary",
            )
            assert isinstance(res, ToolSuccess)
            data = res.data
            assert data["package_json"]["name"] == "secret-desktop-app"
            assert "execute-shell-cmd" in data["ipc_channels_preview"]
            assert "https://api.secret-app.io/v1/telemetry" in data["api_endpoints_preview"]
            assert len(data["security_findings"]) >= 2
            assert len(data["pattern_matches_preview"]) == 1
            assert (extract_dir / "main.js").is_file()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_inspect_unity_il2cpp_valid_and_encrypted(tmp_path: Path):
    """Verify Unity IL2CPP global-metadata.dat parsing and encrypted magic detection."""
    # 1. Valid global-metadata.dat
    meta_file = tmp_path / "global-metadata.dat"

    lit1 = b"https://game.example.com/api/login"
    lit2 = b"AES_MASTER_KEY_2026"
    lit_data = lit1 + lit2
    lit_table = struct.pack("<II", len(lit1), 0) + struct.pack("<II", len(lit2), len(lit1))

    ident_blob = (
        b"AcmeGame.Security\x00"
        b"AcmeGame.Network\x00"
        b"CryptoManager\x00"
        b"PlayerController\x00"
        b"DecryptAssetBundle\x00"
        b"get_AuthToken\x00"
    )

    header_size = 32
    str_lit_offset = header_size
    str_lit_size = len(lit_table)
    str_lit_data_offset = str_lit_offset + str_lit_size
    str_lit_data_size = len(lit_data)
    str_offset = str_lit_data_offset + str_lit_data_size
    str_size = len(ident_blob)

    header = struct.pack(
        "<IIiiiiii",
        0xFAB11BAF,
        29,
        str_lit_offset,
        str_lit_size,
        str_lit_data_offset,
        str_lit_data_size,
        str_offset,
        str_size,
    )
    meta_file.write_bytes(header + lit_table + lit_data + ident_blob)

    with patch(
        "reversecore_mcp.tools.analysis.modern_runtimes.validate_file_path",
        return_value=meta_file,
    ):
        res = await inspect_unity_il2cpp(str(meta_file), detail="full")
        assert isinstance(res, ToolSuccess)
        data = res.data
        assert data["summary"]["metadata_version"] == 29
        assert "https://game.example.com/api/login" in data["string_literals"]
        assert "AcmeGame.Security" in data["namespaces"]
        assert "CryptoManager" in data["class_candidates"]
        assert "DecryptAssetBundle" in data["method_candidates"]

    # 2. Encrypted / Obfuscated global-metadata.dat
    enc_meta = tmp_path / "encrypted-metadata.dat"
    enc_meta.write_bytes(struct.pack("<II", 0xDEADBEEF, 99) + b"\xaa\x55" * 64)

    with patch(
        "reversecore_mcp.tools.analysis.modern_runtimes.validate_file_path",
        return_value=enc_meta,
    ):
        res_enc = await inspect_unity_il2cpp(str(enc_meta))
        assert isinstance(res_enc, ToolSuccess)
        assert res_enc.data["status"] == "encrypted_or_nonstandard_magic"
        assert res_enc.data["header_magic"] == "0xdeadbeef"
