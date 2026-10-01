"""Integration checks against the installed Volatility3 command line."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from reversecore_mcp.tools.forensics import memory as memory_tools


@pytest.mark.integration
@pytest.mark.parametrize("plugin", ["windows.pslist", "linux.pslist", "mac.pslist"])
def test_volatility_cli_resolves_os_qualified_process_plugins(plugin):
    """Run the real Volatility3 CLI parser for each supported OS process plugin."""
    vol_executable = shutil.which("vol")
    if vol_executable is None:
        pytest.skip("Volatility3 CLI is not installed")

    result = subprocess.run(
        [vol_executable, plugin, "--help"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout


@pytest.mark.integration
def test_windows_dlllist_cli_supports_confined_dump_arguments(tmp_path):
    """Check the real CLI accepts global output and DLL extraction options."""
    vol_executable = shutil.which("vol")
    if vol_executable is None:
        pytest.skip("Volatility3 CLI is not installed")

    dump_path = tmp_path / "memory.raw"
    dump_path.write_bytes(b"\x00")
    result = subprocess.run(
        [
            vol_executable,
            "-f",
            str(dump_path),
            "-r",
            "json",
            "-o",
            str(tmp_path),
            "windows.dlllist",
            "--help",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    for option in ("--pid", "--dump", "--name", "--ignore-case"):
        assert option in result.stdout


@pytest.mark.integration
@pytest.mark.asyncio
async def test_memory_dump_module_extracts_requested_dll_from_real_image(
    monkeypatch, workspace_dir, patched_workspace_config
):
    """Run real extraction when a Windows image and known process/DLL are supplied.

    Set REVERSECORE_VOLATILITY_TEST_IMAGE, REVERSECORE_VOLATILITY_TEST_PROCESS,
    and REVERSECORE_VOLATILITY_TEST_MODULE to enable this test. The input image
    stays outside the temporary output workspace; path validation is patched
    only for that external fixture, while output confinement remains real.
    """
    vol_executable = shutil.which("vol")
    if vol_executable is None:
        pytest.skip("Volatility3 CLI is not installed")

    image = os.environ.get("REVERSECORE_VOLATILITY_TEST_IMAGE")
    process_name = os.environ.get("REVERSECORE_VOLATILITY_TEST_PROCESS")
    module_name = os.environ.get("REVERSECORE_VOLATILITY_TEST_MODULE")
    if image is None or process_name is None or module_name is None:
        pytest.skip("Set the Volatility test image, process, and module environment variables")

    image_path = Path(image).expanduser().resolve()
    assert image_path.is_file(), f"Volatility test image does not exist: {image_path}"
    monkeypatch.setattr(memory_tools, "validate_file_path", lambda _path: image_path)

    output_dir = workspace_dir / "volatility-integration-output"
    result = await memory_tools.memory_dump_module(
        str(image_path),
        process_name,
        module_name=module_name,
        output_dir=str(output_dir),
    )

    assert result.status == "success", result.error
    dumped_files = [Path(path).resolve() for path in result.data["dumped_files"]]
    assert dumped_files
    for dumped_file in dumped_files:
        assert dumped_file.is_relative_to(workspace_dir.resolve())
        assert dumped_file.stat().st_size > 0
        assert module_name.casefold() in dumped_file.name.casefold()
