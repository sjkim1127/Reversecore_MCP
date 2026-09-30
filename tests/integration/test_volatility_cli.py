"""Integration checks against the installed Volatility3 command line."""

import shutil
import subprocess

import pytest


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
