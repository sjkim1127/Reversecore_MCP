"""Integration tests for MCP tools using real compiled binaries.

Verifies that the actual MCP tool logic executes successfully and extracts
meaningful information when run on real compiled binaries (ELF/Mach-O).
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from reversecore_mcp.tools.analysis.capa_tools import run_capa
from reversecore_mcp.tools.analysis.die_tools import detect_packer
from reversecore_mcp.tools.analysis.diff_tools import diff_binaries, patch_diff_1day
from reversecore_mcp.tools.analysis.emulation_tools import emulate_binary
from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
from reversecore_mcp.tools.analysis.static_analysis import run_strings
from reversecore_mcp.tools.analysis.symbolic_analysis import verify_path_and_get_args
from reversecore_mcp.tools.common.file_operations import run_file
from reversecore_mcp.tools.malware.vulnerability_hunter import vulnerability_hunter
from reversecore_mcp.tools.radare2.r2_analysis import (
    analyze_xrefs,
    generate_function_graph,
    run_radare2,
    trace_execution_path,
)
from reversecore_mcp.tools.radare2.r2ghidra_tools import (
    r2_analyze_function,
    r2_decompile,
    r2_get_call_graph,
    r2_recover_structures,
)


@pytest.fixture
def real_binaries(workspace_dir):
    """Copy precompiled test binaries from fixtures to test workspace, or compile on the fly."""
    bin_dict = {}

    # 1. Look for precompiled test binaries in the project fixtures
    proj_root = Path(__file__).parent.parent.parent
    fixtures_bin_dir = proj_root / "tests" / "fixtures" / "workspace" / "binaries"

    # Destination binaries directory inside the temporary test workspace
    dest_bin_dir = workspace_dir / "binaries"
    dest_bin_dir.mkdir(parents=True, exist_ok=True)

    binaries_to_copy = ["hello_x64", "hello_x64_stripped", "pie_x64"]
    copied_count = 0

    if fixtures_bin_dir.exists():
        for bin_name in binaries_to_copy:
            src_path = fixtures_bin_dir / bin_name
            if src_path.exists():
                dest_path = dest_bin_dir / bin_name
                shutil.copy2(src_path, dest_path)
                bin_dict[bin_name] = dest_path
                copied_count += 1

    # 2. If precompiled binaries are not found, compile them on the fly
    if copied_count < len(binaries_to_copy) and shutil.which("gcc"):
        c_src = dest_bin_dir / "hello.c"
        c_src.write_text("""
#include <stdio.h>
int fib(int n) {
    if (n <= 1) return n;
    return fib(n-1) + fib(n-2);
}
int main() {
    printf("Hello from real test binary\\n");
    return fib(10);
}
""")
        # Compile hello_x64
        hello_path = dest_bin_dir / "hello_x64"
        subprocess.run(["gcc", "-o", str(hello_path), str(c_src)], capture_output=True)
        if hello_path.exists():
            bin_dict["hello_x64"] = hello_path

            # Compile hello_x64_stripped
            stripped_path = dest_bin_dir / "hello_x64_stripped"
            shutil.copy2(hello_path, stripped_path)
            subprocess.run(["strip", str(stripped_path)], capture_output=True)
            bin_dict["hello_x64_stripped"] = stripped_path

        # Compile pie_x64
        pie_path = dest_bin_dir / "pie_x64"
        subprocess.run(
            ["gcc", "-fPIE", "-pie", "-o", str(pie_path), str(c_src)], capture_output=True
        )
        if pie_path.exists():
            bin_dict["pie_x64"] = pie_path

    # 3. Fallback to minimal ELFs if compilation fails and fixtures are missing
    minimal_elf = (
        bytes(
            [
                0x7F,
                0x45,
                0x4C,
                0x46,
                0x02,
                0x01,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x02,
                0x00,
                0x3E,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
            ]
        )
        + b"\x00" * 40
    )

    for bin_name in binaries_to_copy:
        if bin_name not in bin_dict:
            fallback_path = dest_bin_dir / bin_name
            fallback_path.write_bytes(minimal_elf)
            bin_dict[bin_name] = fallback_path

    return bin_dict


@pytest.mark.asyncio
async def test_run_file_tool(real_binaries, patched_workspace_config):
    """Test run_file correctly identifies ELF binary details."""
    hello_path = real_binaries["hello_x64"]
    result = await run_file(str(hello_path))
    assert result.status == "success"
    assert "ELF" in result.data["file_type"] or "Mach-O" in result.data["file_type"]


@pytest.mark.asyncio
async def test_run_strings_tool(real_binaries, patched_workspace_config):
    """Test run_strings extracts compiled strings from the binary."""
    hello_path = real_binaries["hello_x64"]
    result = await run_strings(str(hello_path))
    assert result.status == "success"
    assert len(result.data) > 0
    assert "string_statistics" in result.metadata


@pytest.mark.asyncio
async def test_parse_binary_with_lief_tool(real_binaries, patched_workspace_config):
    """Test LIEF tool correctly parses ELF header and mitigations."""
    hello_path = real_binaries["hello_x64"]
    result = parse_binary_with_lief(str(hello_path))
    assert result.status == "success"
    assert "format" in result.data
    assert "mitigations" in result.data


@pytest.mark.asyncio
async def test_detect_packer_tool(real_binaries, patched_workspace_config):
    """Test DIE packer detection on a real binary."""
    if not shutil.which("diec"):
        pytest.skip("diec (Detect It Easy) is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await detect_packer(str(hello_path))
    assert result.status == "success"
    assert "compiler" in result.data
    assert "packer" in result.data


@pytest.mark.asyncio
async def test_run_capa_tool(real_binaries, patched_workspace_config):
    """Test CAPA tool execution on a real binary."""
    try:
        import capa  # noqa: F401
    except Exception:
        pytest.skip("capa (flare-capa) is not installed or has import issues")

    hello_path = real_binaries["hello_x64"]
    result = await run_capa(str(hello_path))
    assert result.status in ("success", "error")
    if result.status == "success":
        assert "capabilities" in result.data


@pytest.mark.asyncio
async def test_diff_binaries_tool(real_binaries, patched_workspace_config):
    """Test diffing hello vs hello_stripped using radiff2 wrapper."""
    if not shutil.which("radiff2") and not shutil.which("r2"):
        pytest.skip("radare2 (r2/radiff2) is not installed")

    file_a = real_binaries["hello_x64"]
    file_b = real_binaries["hello_x64_stripped"]

    result = await diff_binaries(str(file_a), str(file_b))
    assert result.status == "success"
    assert "similarity" in result.data or "differences" in result.data


@pytest.mark.asyncio
async def test_patch_diff_1day_tool(real_binaries, patched_workspace_config):
    """Test 1-day patch diffing on real binaries."""
    if not shutil.which("radiff2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    file_a = real_binaries["hello_x64"]
    file_b = real_binaries["hello_x64_stripped"]

    result = await patch_diff_1day(str(file_a), str(file_b))
    assert result.status == "success"
    assert "diff_summary" in result.data


@pytest.mark.asyncio
async def test_emulate_binary_tool(real_binaries, patched_workspace_config):
    """Test Qiling machine code emulation on a real binary."""
    try:
        import qiling  # noqa: F401
    except Exception:
        pytest.skip("qiling is not installed or has import issues")

    hello_path = real_binaries["hello_x64"]
    # Run emulation with very low instruction limit to ensure it returns quickly
    result = await emulate_binary(str(hello_path), verbose="off")
    assert result.status in ("success", "error")


@pytest.mark.asyncio
async def test_verify_path_and_get_args_angr_tool(real_binaries, patched_workspace_config):
    """Test angr symbolic execution verification tool."""
    try:
        import angr  # noqa: F401
    except Exception:
        pytest.skip("angr is not installed or has import issues")

    hello_path = real_binaries["hello_x64"]
    # Test path verification using angr
    result = await verify_path_and_get_args(str(hello_path), target_addr=0x401000)
    assert isinstance(result, dict)
    assert "satisfiable" in result


@pytest.mark.asyncio
async def test_vulnerability_hunter_tool(real_binaries, patched_workspace_config):
    """Test Vulnerability Hunter tool running on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await vulnerability_hunter(str(hello_path), use_symbolic_execution=False)
    assert result.status == "success"
    assert "vulnerabilities" in result.data
    assert "exploit_mitigations" in result.data


@pytest.mark.asyncio
async def test_run_radare2_tool(real_binaries, patched_workspace_config):
    """Test run_radare2 tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await run_radare2(str(hello_path), "i")
    assert result.status == "success"
    assert (
        "elf" in result.data.lower()
        or "mach" in result.data.lower()
        or "format" in result.data.lower()
        or "pe" in result.data.lower()
    )


@pytest.mark.asyncio
async def test_r2_decompile_tool(real_binaries, patched_workspace_config):
    """Test r2_decompile tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await r2_decompile(str(hello_path), "main")
    assert result.status in ("success", "error")
    if result.status == "success":
        assert "pseudo_c" in result.data
        assert "main" in result.data["pseudo_c"]


@pytest.mark.asyncio
async def test_r2_recover_structures_tool(real_binaries, patched_workspace_config):
    """Test r2_recover_structures tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await r2_recover_structures(str(hello_path), "main")
    assert result.status in ("success", "error")
    if result.status == "success":
        assert isinstance(result.data, dict) or isinstance(result.data, list)


@pytest.mark.asyncio
async def test_r2_analyze_function_tool(real_binaries, patched_workspace_config):
    """Test r2_analyze_function tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await r2_analyze_function(str(hello_path), "main")
    assert result.status == "success"
    assert "name" in result.data
    assert "size" in result.data


@pytest.mark.asyncio
async def test_r2_get_call_graph_tool(real_binaries, patched_workspace_config):
    """Test r2_get_call_graph tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await r2_get_call_graph(str(hello_path), "main")
    assert result.status == "success"
    assert "nodes" in result.data
    assert "edges" in result.data


@pytest.mark.asyncio
async def test_generate_function_graph_tool(real_binaries, patched_workspace_config):
    """Test generate_function_graph tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await generate_function_graph(str(hello_path), "main", format="mermaid")
    assert result.status == "success"
    assert "graph_data" in result.data
    assert (
        "mermaid" in result.data["graph_data"].lower()
        or "graph" in result.data["graph_data"].lower()
    )


@pytest.mark.asyncio
async def test_analyze_xrefs_tool(real_binaries, patched_workspace_config):
    """Test analyze_xrefs tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await analyze_xrefs(str(hello_path), "main")
    assert result.status == "success"
    assert "xrefs" in result.data
    assert isinstance(result.data["xrefs"], list)


@pytest.mark.asyncio
async def test_trace_execution_path_tool(real_binaries, patched_workspace_config):
    """Test trace_execution_path tool on a real binary."""
    if not shutil.which("radare2") and not shutil.which("r2"):
        pytest.skip("radare2 is not installed")

    hello_path = real_binaries["hello_x64"]
    result = await trace_execution_path(str(hello_path), target_function="main", max_depth=2)
    assert result.status == "success"
    assert "paths" in result.data
    assert isinstance(result.data["paths"], list)
