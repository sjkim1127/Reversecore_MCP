"""Unit tests for Summary-First Paging across disassembly, decompilation, and strings tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import FastMCP

from reversecore_mcp.core.result import success
from reversecore_mcp.tools.forensics.memory import memory_extract_strings
from reversecore_mcp.tools.radare2.r2ghidra_tools import r2_decompile
from reversecore_mcp.tools.radare2.radare2_mcp_tools import Radare2ToolsPlugin


@pytest.fixture
def registered_plugin():
    mcp = FastMCP("test_paging")
    plugin = Radare2ToolsPlugin()
    plugin._tools = {}

    orig_tool = mcp.tool

    def recording_tool(*args, **kwargs):
        decorator = orig_tool(*args, **kwargs)

        def wrapper(fn):
            plugin._tools[fn.__name__] = fn
            return decorator(fn)

        return wrapper

    mcp.tool = recording_tool
    plugin.register(mcp)
    return plugin


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.is_open = True
    session.cmd = MagicMock(return_value="")
    return session


@pytest.mark.unit
@pytest.mark.asyncio
async def test_radare2_disassemble_summary(registered_plugin, mock_session):
    plugin = registered_plugin
    mock_session.cmd.return_value = (
        "0x401000  mov eax, 1\n0x401005  call 0x402000\n0x40100a  jmp 0x401010\n0x401010  ret\n"
    )

    with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
        tool = plugin._tools["Radare2_disassemble"]

        # 1. Full mode
        res_full = await tool("/app/test.bin", address="0x401000", detail="full")
        assert res_full["status"] == "success"
        assert "disassembly" in res_full
        assert "detail_level" not in res_full

        # 2. Summary mode
        res_sum = await tool("/app/test.bin", address="0x401000", detail="summary")
        assert res_sum["status"] == "success"
        assert res_sum["detail_level"] == "summary"
        assert res_sum["total_instructions"] == 4
        assert res_sum["metrics"]["calls"] == 1
        assert res_sum["metrics"]["branches"] == 1
        assert res_sum["metrics"]["returns"] == 1
        assert len(res_sum["preview"]) == 3
        assert "hint" in res_sum


@pytest.mark.unit
@pytest.mark.asyncio
async def test_radare2_disassemble_function_summary(registered_plugin, mock_session):
    plugin = registered_plugin
    mock_session.cmd.return_value = """{
        "ops": [
            {"offset": 4198400, "mnemonic": "push", "operands": "rbp"},
            {"offset": 4198401, "mnemonic": "mov", "operands": "rbp, rsp"},
            {"offset": 4198404, "mnemonic": "call", "operands": "sym.imp.malloc"},
            {"offset": 4198409, "mnemonic": "jmp", "operands": "0x401020"},
            {"offset": 4198414, "mnemonic": "ret", "operands": ""}
        ]
    }"""

    with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
        tool = plugin._tools["Radare2_disassemble_function"]

        res_sum = await tool(
            "/app/test.bin", address="0x401000", format="compact", detail="summary"
        )
        assert res_sum["status"] == "success"
        assert res_sum["detail_level"] == "summary"
        assert res_sum["total_instructions"] == 5
        assert res_sum["metrics"]["calls"] == 1
        assert res_sum["metrics"]["branches"] == 1
        assert res_sum["metrics"]["returns"] == 1
        assert len(res_sum["preview"]) == 3


@pytest.mark.unit
@pytest.mark.asyncio
async def test_radare2_decompile_function_summary(registered_plugin, mock_session):
    plugin = registered_plugin
    mock_session.cmd.return_value = """int main(int argc, char **argv) {
        int x = 0;
        while (x < 10) {
            printf("Value: %d", x);
            x++;
        }
        if (x == 10) {
            return 0;
        }
        return 1;
    }"""

    with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
        tool = plugin._tools["Radare2_decompile_function"]

        # 1. Full mode
        res_full = await tool("/app/test.bin", address="main", detail="full")
        assert res_full["status"] == "success"
        assert "decompiled" in res_full
        assert "detail_level" not in res_full

        # 2. Summary mode
        res_sum = await tool("/app/test.bin", address="main", detail="summary")
        assert res_sum["status"] == "success"
        assert res_sum["detail_level"] == "summary"
        assert res_sum["signature"].startswith("int main")
        assert res_sum["control_flow_metrics"]["loops"] >= 1
        assert res_sum["control_flow_metrics"]["conditionals"] >= 1
        assert "preview" in res_sum


@pytest.mark.unit
@pytest.mark.asyncio
async def test_radare2_list_strings_summary(registered_plugin, mock_session):
    plugin = registered_plugin
    mock_session.cmd.return_value = (
        "0x402000 12 11 .rodata ascii https://api.threat.com/c2\n"
        "0x402010 16 15 .rodata ascii 192.168.1.100\n"
        "0x402025 20 19 .rodata ascii C:\\Windows\\System32\\cmd.exe\n"
        "0x402040 14 13 .rodata ascii secret_api_key_12345\n"
        "0x402055 8 7 .rodata ascii Hello\n"
    )

    with patch.object(plugin, "_get_or_create_session", return_value=mock_session):
        tool = plugin._tools["Radare2_list_strings"]

        res_sum = await tool("/app/test.bin", detail="summary")
        assert res_sum["status"] == "success"
        assert res_sum["detail_level"] == "summary"
        assert res_sum["total_strings"] == 5
        assert res_sum["categories"]["urls"] == 1
        assert res_sum["categories"]["ip_addresses"] == 1
        assert res_sum["categories"]["file_paths"] == 1
        assert res_sum["categories"]["secrets_or_keys"] == 1
        assert len(res_sum["sample_strings"]) == 5


@pytest.mark.unit
@pytest.mark.asyncio
async def test_r2_decompile_summary(tmp_path):
    target = tmp_path / "dummy.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 100)

    pseudo_c = """void target_func(void) {
        for (int i = 0; i < 5; i++) {
            do_something();
        }
        return;
    }"""

    with patch("reversecore_mcp.tools.radare2.r2ghidra_tools._validate_addr", return_value=None):
        with patch(
            "reversecore_mcp.tools.radare2.r2ghidra_tools.validate_file_path", return_value=target
        ):
            with patch(
                "reversecore_mcp.tools.radare2.r2ghidra_tools.get_cached_decompile",
                new_callable=AsyncMock,
            ) as m_cache:
                m_cache.return_value = success({"pseudo_c": pseudo_c, "full_pseudo_c": pseudo_c})

                res_sum = await r2_decompile(str(target), "target_func", detail="summary")
                assert res_sum.status == "success"
                assert res_sum.data["detail_level"] == "summary"
                assert res_sum.data["control_flow_metrics"]["loops"] == 1
                assert "preview" in res_sum.data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_memory_extract_strings_summary(tmp_path):
    dump_file = tmp_path / "memdump.raw"
    dump_file.write_bytes(
        b"A" * 50
        + b"https://example.com"
        + b"\x00"
        + b"10.0.0.1"
        + b"\x00"
        + b"normal_string_here\x00"
    )

    with patch("reversecore_mcp.tools.forensics.memory.validate_file_path", return_value=dump_file):
        with patch("shutil.which", return_value=None):  # Python fallback
            res_sum = await memory_extract_strings(str(dump_file), min_length=4, detail="summary")
            assert res_sum.status == "success"
            assert res_sum.data["detail_level"] == "summary"
            assert res_sum.data["string_count"] > 0
            assert "sample_strings" in res_sum.data
            assert "notable" in res_sum.data
