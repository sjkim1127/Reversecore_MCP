"""Unit tests for run_fuzzing_campaign tool."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.tools.analysis.fuzzing_campaign import (
    _afl_available,
    _collect_crashes,
    _crash_signature,
    run_fuzzing_campaign,
)


class TestCrashSignature:
    """Tests for _crash_signature helper."""

    def test_returns_hex_string(self, tmp_path):
        crash = tmp_path / "crash1"
        crash.write_bytes(b"AAAA" * 10)
        sig = _crash_signature(crash)
        assert isinstance(sig, str)
        assert len(sig) == 12  # SHA1 truncated to 12 chars
        assert all(c in "0123456789abcdef" for c in sig)

    def test_different_contents_differ(self, tmp_path):
        c1 = tmp_path / "c1"
        c1.write_bytes(b"A" * 50)
        c2 = tmp_path / "c2"
        c2.write_bytes(b"B" * 50)
        assert _crash_signature(c1) != _crash_signature(c2)

    def test_same_contents_same_sig(self, tmp_path):
        c1 = tmp_path / "c1"
        c1.write_bytes(b"PAYLOAD")
        c2 = tmp_path / "c2"
        c2.write_bytes(b"PAYLOAD")
        assert _crash_signature(c1) == _crash_signature(c2)

    def test_missing_file_returns_name(self, tmp_path):
        ghost = tmp_path / "ghost_crash"
        # File doesn't exist
        sig = _crash_signature(ghost)
        assert "ghost_crash" in sig


class TestCollectCrashes:
    """Tests for _collect_crashes helper."""

    def test_returns_empty_for_nonexistent(self, tmp_path):
        assert _collect_crashes(tmp_path) == []

    def test_collects_from_default_crashes_dir(self, tmp_path):
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        # Create 3 unique crash files
        (crashes_dir / "crash1").write_bytes(b"A" * 100)
        (crashes_dir / "crash2").write_bytes(b"B" * 100)
        (crashes_dir / "crash3").write_bytes(b"C" * 100)
        # README should be ignored
        (crashes_dir / "README.txt").write_text("AFL++ crashes")

        result = _collect_crashes(tmp_path)
        assert len(result) == 3
        assert all(f.name != "README.txt" for f in result)

    def test_collects_from_afl_default_subdir(self, tmp_path):
        crashes_dir = tmp_path / "default" / "crashes"
        crashes_dir.mkdir(parents=True)
        for i in range(5):
            (crashes_dir / f"id:00000{i}").write_bytes(bytes([i]) * 20)

        result = _collect_crashes(tmp_path)
        assert len(result) == 5

    def test_deduplicates_by_content(self, tmp_path):
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        # Two files with same content = 1 unique
        (crashes_dir / "crash1").write_bytes(b"DUPLICATE")
        (crashes_dir / "crash2").write_bytes(b"DUPLICATE")
        (crashes_dir / "crash3").write_bytes(b"UNIQUE")

        result = _collect_crashes(tmp_path)
        assert len(result) == 2  # 2 unique content

    def test_respects_max_crashes(self, tmp_path):
        crashes_dir = tmp_path / "crashes"
        crashes_dir.mkdir()
        for i in range(20):
            (crashes_dir / f"crash{i:02d}").write_bytes(bytes([i]) * 10)

        result = _collect_crashes(tmp_path, max_crashes=5)
        assert len(result) == 5


class TestAflAvailable:
    """Tests for _afl_available."""

    def test_returns_bool(self):
        result = _afl_available()
        assert isinstance(result, bool)


class TestRunFuzzingCampaign:
    """Tests for run_fuzzing_campaign MCP tool."""

    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    def test_fails_when_afl_not_available(self, mock_afl, mock_validate, tmp_path):
        mock_afl.return_value = False
        binary = tmp_path / "vuln"
        binary.write_bytes(b"ELF")
        mock_validate.return_value = binary

        result = asyncio.run(run_fuzzing_campaign(str(binary)))
        assert result.status == "error"
        assert "DEPENDENCY_ERROR" in str(result) or "error" in result.status

    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._run_afl")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._triage_crashes")
    def test_success_no_crashes(
        self, mock_triage, mock_afl_run, mock_avail, mock_validate, tmp_path
    ):
        """When AFL finds no crashes, should return success with 0 crashes."""

        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        mock_validate.return_value = binary
        mock_avail.return_value = True
        # AFL runs, returns success, no crashes
        mock_afl_run.return_value = (0, "AFL finished")
        mock_triage.return_value = []

        result = asyncio.run(run_fuzzing_campaign(str(binary), timeout_seconds=1))
        assert result.status == "success"
        assert result.data["unique_crashes"] == 0
        assert result.data["exploitable_count"] == 0

    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._run_afl")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._triage_crashes")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._collect_crashes")
    def test_success_with_exploitable_crashes(
        self, mock_collect, mock_triage, mock_afl_run, mock_avail, mock_validate, tmp_path
    ):
        """When crashes are found and exploitable, report should reflect them."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        mock_validate.return_value = binary
        mock_avail.return_value = True
        mock_afl_run.return_value = (0, "")

        crash_file = tmp_path / "crash1"
        crash_file.write_bytes(b"AAAA" * 50)
        mock_collect.return_value = [crash_file]

        mock_triage.return_value = [
            {
                "crash_file": "crash1",
                "crash_signature": "abc123",
                "exploitability": "CONFIRMED",
                "exploitability_score": 100,
                "signal": "SIGSEGV",
                "crash_address": "0x41414141",
                "backtrace": [],
                "is_exploitable": True,
            }
        ]

        result = asyncio.run(run_fuzzing_campaign(str(binary), timeout_seconds=1))
        assert result.status == "success"
        assert result.data["exploitable_count"] == 1
        assert result.data["confirmed_exploitable"] == 1
        top = result.data["top_crash"]
        assert top["exploitability"] == "CONFIRMED"

    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._run_afl")
    def test_afl_launch_error(self, mock_afl_run, mock_avail, mock_validate, tmp_path):
        """If afl-fuzz cannot be launched, return error."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        mock_validate.return_value = binary
        mock_avail.return_value = True
        mock_afl_run.return_value = (-1, "afl-fuzz not found in PATH")

        result = asyncio.run(run_fuzzing_campaign(str(binary), timeout_seconds=1))
        assert result.status == "error"

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._run_afl")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._triage_crashes")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._collect_crashes")
    async def test_next_steps_populated(
        self, mock_collect, mock_triage, mock_afl_run, mock_avail, mock_validate, tmp_path
    ):
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)
        mock_validate.return_value = binary
        mock_avail.return_value = True
        mock_afl_run.return_value = (0, "")
        mock_collect.return_value = []
        mock_triage.return_value = []

        result = await run_fuzzing_campaign(str(binary), timeout_seconds=1)
        assert result.status == "success"
        assert isinstance(result.data["next_steps"], list)
        assert len(result.data["next_steps"]) > 0

    @pytest.mark.asyncio
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign.validate_file_path")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._afl_available")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._run_afl")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._triage_crashes")
    @patch("reversecore_mcp.tools.analysis.fuzzing_campaign._collect_crashes")
    @patch("reversecore_mcp.tools.analysis.fuzz_tools.generate_fuzzing_harness")
    async def test_automatic_harness_generation(
        self,
        mock_gen_harness,
        mock_collect,
        mock_triage,
        mock_afl_run,
        mock_avail,
        mock_validate,
        tmp_path,
    ):
        """Test if providing target_function_or_addr generates a harness and passes it to AFL++."""
        binary = tmp_path / "vuln"
        binary.write_bytes(b"\x7fELF")
        binary.chmod(0o755)

        # Mock successful binary validation
        mock_validate.side_effect = lambda x: Path(x)
        mock_avail.return_value = True
        mock_afl_run.return_value = (0, "")
        mock_collect.return_value = []
        mock_triage.return_value = []

        # Mock successful harness generation
        harness_path = tmp_path / "fuzz_vuln.py"
        harness_path.write_text("dummy")

        from reversecore_mcp.core.result import success

        mock_gen_harness.return_value = success(
            {"harness_code": "dummy", "saved_path": str(harness_path)}
        )

        result = await run_fuzzing_campaign(
            str(binary), timeout_seconds=1, target_function_or_addr="0x401000"
        )

        if result.status == "error":
            print(f"FAILED WITH: {result.message}")
        assert result.status == "success"
        mock_gen_harness.assert_called_once()
        kwargs = mock_gen_harness.call_args.kwargs
        assert kwargs["target_function_or_addr"] == "0x401000"
        assert kwargs["save_to_workspace"] is True
