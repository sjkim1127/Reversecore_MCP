import asyncio
import os
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from reversecore_mcp.tools.analysis.die_tools import detect_packer_deep

# Import the target tools
from reversecore_mcp.tools.analysis.lief_tools import parse_binary_with_lief
from reversecore_mcp.tools.analysis.static_analysis import run_strings
from reversecore_mcp.tools.malware.yara_tools import run_yara

# -----------------------------------------------------------------------------
# Hypothesis Profiles Configuration
# -----------------------------------------------------------------------------

# 'ci' profile is used for quick PR blocking runs (Quick Fuzz)
settings.register_profile("ci", max_examples=20, deadline=10000)

# 'nightly' profile is used for deep, long-running night cron jobs (Deep Fuzz)
settings.register_profile("nightly", max_examples=1000, deadline=None)

# Load profile from environment variable, default to 'ci'
current_profile = os.environ.get("HYPOTHESIS_PROFILE", "ci")
settings.load_profile(current_profile)

# We ignore certain health checks because binary analysis tools can take
# unpredictable amounts of time on randomly generated garbage data.
SUPPRESSED_CHECKS = [
    HealthCheck.too_slow,
    HealthCheck.function_scoped_fixture,
    HealthCheck.filter_too_much,
]

# -----------------------------------------------------------------------------
# Fuzzing Test Cases
# -----------------------------------------------------------------------------
# We fuzz with random binary blobs ranging from 0 bytes up to 500 KB to
# prevent out-of-memory errors in the fuzzer itself, while heavily testing
# the parsers' ability to handle malformed inputs.
# -----------------------------------------------------------------------------


@given(binary_data=st.binary(min_size=0, max_size=1024 * 500))
@settings(suppress_health_check=SUPPRESSED_CHECKS)
def test_fuzz_parse_binary_with_lief(binary_data):
    """
    Fuzz the LIEF binary parser. LIEF is written in C++ and can segfault if
    input is highly malformed. This ensures our Python wrapper doesn't crash
    the entire MCP server.
    """
    workspace = Path(os.environ["REVERSECORE_WORKSPACE"])
    test_file = workspace / "fuzz_lief.bin"
    test_file.write_bytes(binary_data)

    # parse_binary_with_lief is synchronous
    result = parse_binary_with_lief(str(test_file))

    # Assert that a ToolResult was returned safely (success or handled failure)
    assert hasattr(result, "status"), "LIEF parser did not return a valid ToolResult"
    assert result.status in ("success", "error")


@given(binary_data=st.binary(min_size=0, max_size=1024 * 500))
@settings(suppress_health_check=SUPPRESSED_CHECKS)
def test_fuzz_detect_packer_deep(binary_data):
    """
    Fuzz the Deep Packer Detection (Detect It Easy / diec).
    """
    workspace = Path(os.environ["REVERSECORE_WORKSPACE"])
    test_file = workspace / "fuzz_die.bin"
    test_file.write_bytes(binary_data)

    # detect_packer_deep is asynchronous
    result = asyncio.run(detect_packer_deep(str(test_file)))

    assert hasattr(result, "status")
    assert result.status in ("success", "error")


@given(binary_data=st.binary(min_size=0, max_size=1024 * 500))
@settings(suppress_health_check=SUPPRESSED_CHECKS)
def test_fuzz_run_yara(binary_data):
    """
    Fuzz the YARA scanner by passing malformed binaries.
    (Note: This fuzzes the binary being scanned, not the YARA rule syntax itself).
    """
    workspace = Path(os.environ["REVERSECORE_WORKSPACE"])
    test_file = workspace / "fuzz_yara.bin"
    test_file.write_bytes(binary_data)

    # run_yara is asynchronous
    result = asyncio.run(run_yara(str(test_file)))

    assert hasattr(result, "status")
    assert result.status in ("success", "error")


@given(binary_data=st.binary(min_size=0, max_size=1024 * 500))
@settings(suppress_health_check=SUPPRESSED_CHECKS)
def test_fuzz_run_strings(binary_data):
    """
    Fuzz the strings extraction tool.
    """
    workspace = Path(os.environ["REVERSECORE_WORKSPACE"])
    test_file = workspace / "fuzz_strings.bin"
    test_file.write_bytes(binary_data)

    # run_strings is asynchronous
    result = asyncio.run(run_strings(str(test_file)))

    assert hasattr(result, "status")
    assert result.status in ("success", "error")
