"""Unit tests for ToolchainCapabilities and CapabilityDetector."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from reversecore_mcp.benchmarks.capabilities import (
    CapabilityDetector,
    ToolchainCapabilities,
    detect_capabilities,
)


@pytest.mark.unit
class TestToolchainCapabilitiesModel:
    """Tests for ToolchainCapabilities dataclass and properties."""

    def test_live_fuzzing_ready_property(self):
        """Test live_fuzzing_ready property calculation."""
        caps_ready = ToolchainCapabilities(
            clang_available=True,
            clang_path=Path("/usr/bin/clang"),
            clang_version="Clang 18.0.0",
            asan_supported=True,
            ubsan_supported=True,
            libfuzzer_supported=False,
            llvm_symbolizer_available=True,
            llvm_symbolizer_path=Path("/usr/bin/llvm-symbolizer"),
            afl_available=False,
            afl_path=None,
            docker_available=True,
            angr_available=True,
            radare2_available=True,
        )
        assert caps_ready.live_fuzzing_ready is True
        assert caps_ready.full_libfuzzer_ready is False

        caps_not_ready = ToolchainCapabilities(
            clang_available=True,
            clang_path=Path("/usr/bin/clang"),
            clang_version="Clang 18.0.0",
            asan_supported=False,
            ubsan_supported=False,
            libfuzzer_supported=False,
            llvm_symbolizer_available=False,
            llvm_symbolizer_path=None,
            afl_available=False,
            afl_path=None,
            docker_available=False,
            angr_available=False,
            radare2_available=False,
        )
        assert caps_not_ready.live_fuzzing_ready is False
        assert caps_not_ready.full_libfuzzer_ready is False

    def test_full_libfuzzer_ready_property(self):
        """Test full_libfuzzer_ready property calculation."""
        caps_full = ToolchainCapabilities(
            clang_available=True,
            clang_path=Path("/usr/bin/clang"),
            clang_version="Clang 18.0.0",
            asan_supported=True,
            ubsan_supported=True,
            libfuzzer_supported=True,
            llvm_symbolizer_available=True,
            llvm_symbolizer_path=Path("/usr/bin/llvm-symbolizer"),
            afl_available=True,
            afl_path=Path("/usr/bin/afl-fuzz"),
            docker_available=True,
            angr_available=True,
            radare2_available=True,
        )
        assert caps_full.live_fuzzing_ready is True
        assert caps_full.full_libfuzzer_ready is True

    def test_to_dict_serialization(self):
        """Test to_dict produces complete and correctly formatted dictionary."""
        caps = ToolchainCapabilities(
            clang_available=True,
            clang_path=Path("/usr/bin/clang"),
            clang_version="Clang 18.0.0",
            asan_supported=True,
            ubsan_supported=True,
            libfuzzer_supported=True,
            llvm_symbolizer_available=True,
            llvm_symbolizer_path=Path("/usr/bin/llvm-symbolizer"),
            afl_available=False,
            afl_path=None,
            docker_available=True,
            angr_available=True,
            radare2_available=True,
        )
        d = caps.to_dict()
        assert d["clang_available"] is True
        assert d["clang_path"] == "/usr/bin/clang"
        assert d["clang_version"] == "Clang 18.0.0"
        assert d["asan_supported"] is True
        assert d["ubsan_supported"] is True
        assert d["libfuzzer_supported"] is True
        assert d["llvm_symbolizer_available"] is True
        assert d["llvm_symbolizer_path"] == "/usr/bin/llvm-symbolizer"
        assert d["afl_available"] is False
        assert d["afl_path"] is None
        assert d["docker_available"] is True
        assert d["angr_available"] is True
        assert d["radare2_available"] is True
        assert d["live_fuzzing_ready"] is True
        assert d["full_libfuzzer_ready"] is True


@pytest.mark.unit
class TestCapabilityDetector:
    """Tests for CapabilityDetector probing and caching."""

    def test_find_clang_binary_with_override(self, tmp_path: Path):
        """Verify override path takes highest priority."""
        fake_clang = tmp_path / "custom_clang"
        fake_clang.write_text("#!/bin/sh\necho clang", encoding="utf-8")
        fake_clang.chmod(0o755)

        found = CapabilityDetector.find_clang_binary(override_path=fake_clang)
        assert found == fake_clang.resolve()

    def test_find_clang_binary_with_env_var(self, tmp_path: Path):
        """Verify REVERSECORE_CLANG_PATH environment variable is honored."""
        fake_clang = tmp_path / "env_clang"
        fake_clang.write_text("#!/bin/sh\necho clang", encoding="utf-8")
        fake_clang.chmod(0o755)

        with patch.dict(os.environ, {"REVERSECORE_CLANG_PATH": str(fake_clang)}):
            found = CapabilityDetector.find_clang_binary()
            assert found == fake_clang.resolve()

    def test_probe_compiler_flag_timeout(self, tmp_path: Path):
        """Verify probe_compiler_flag handles timeouts gracefully without throwing."""
        fake_clang = tmp_path / "hanging_clang"
        fake_clang.write_text("#!/bin/sh\nsleep 10", encoding="utf-8")
        fake_clang.chmod(0o755)

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["clang"], timeout=3.0),
        ):
            res = CapabilityDetector._probe_compiler_flag(
                fake_clang, ["-fsanitize=address"], "int main() { return 0; }"
            )
            assert res is False

    def test_probe_compiler_flag_oserror(self, tmp_path: Path):
        """Verify probe_compiler_flag handles OS errors gracefully."""
        fake_clang = tmp_path / "non_existent_clang"
        res = CapabilityDetector._probe_compiler_flag(
            fake_clang, ["-fsanitize=address"], "int main() { return 0; }"
        )
        assert res is False

    def test_caching_and_force_refresh(self):
        """Verify detect_capabilities caches results and respects force_refresh."""
        caps1 = detect_capabilities(force_refresh=True)
        caps2 = detect_capabilities(force_refresh=False)
        assert caps1 is caps2

        caps3 = detect_capabilities(force_refresh=True)
        assert isinstance(caps3, ToolchainCapabilities)

    def test_clang_override_does_not_corrupt_cache(self, tmp_path: Path):
        """Verify explicit clang_path_override produces custom caps without overwriting global cache."""
        normal_caps = detect_capabilities(force_refresh=True)

        fake_clang = tmp_path / "custom_probe_clang"
        fake_clang.write_text("#!/bin/sh\necho fake", encoding="utf-8")
        fake_clang.chmod(0o755)

        override_caps = detect_capabilities(clang_path_override=fake_clang)
        assert override_caps.clang_path == fake_clang.resolve()

        cached_caps = detect_capabilities(force_refresh=False)
        assert cached_caps.clang_path == normal_caps.clang_path

    def test_real_system_detection(self):
        """Verify real host capability detection returns valid dataclass."""
        caps = detect_capabilities(force_refresh=True)
        assert isinstance(caps.clang_available, bool)
        assert isinstance(caps.asan_supported, bool)
        assert isinstance(caps.ubsan_supported, bool)
        assert isinstance(caps.libfuzzer_supported, bool)
        assert isinstance(caps.docker_available, bool)
        assert isinstance(caps.angr_available, bool)
        assert isinstance(caps.radare2_available, bool)
        assert isinstance(caps.live_fuzzing_ready, bool)
        assert isinstance(caps.full_libfuzzer_ready, bool)
