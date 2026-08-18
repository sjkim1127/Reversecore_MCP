"""Toolchain Capability Auto-Detection and Probing Subsystem.

Provides immutable capability snapshots (ToolchainCapabilities) and safe compiler
probing (CapabilityDetector) for Clang, AddressSanitizer, UBSan, LibFuzzer,
llvm-symbolizer, AFL++, Docker, angr, and Radare2.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reversecore_mcp.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ToolchainCapabilities:
    """Immutable snapshot of host compiler and dynamic analysis tool capabilities."""

    clang_available: bool
    clang_path: Path | None
    clang_version: str | None
    asan_supported: bool
    ubsan_supported: bool
    libfuzzer_supported: bool
    llvm_symbolizer_available: bool
    llvm_symbolizer_path: Path | None
    afl_available: bool
    afl_path: Path | None
    docker_available: bool
    angr_available: bool
    radare2_available: bool

    @property
    def live_fuzzing_ready(self) -> bool:
        """Return True if host can compile and execute ASan-instrumented harnesses."""
        return self.clang_available and self.asan_supported

    @property
    def full_libfuzzer_ready(self) -> bool:
        """Return True if host supports LibFuzzer in-process engine."""
        return self.live_fuzzing_ready and self.libfuzzer_supported

    def to_dict(self) -> dict[str, Any]:
        """Serialize capabilities to a dictionary."""
        return {
            "clang_available": self.clang_available,
            "clang_path": str(self.clang_path) if self.clang_path else None,
            "clang_version": self.clang_version,
            "asan_supported": self.asan_supported,
            "ubsan_supported": self.ubsan_supported,
            "libfuzzer_supported": self.libfuzzer_supported,
            "llvm_symbolizer_available": self.llvm_symbolizer_available,
            "llvm_symbolizer_path": (
                str(self.llvm_symbolizer_path) if self.llvm_symbolizer_path else None
            ),
            "afl_available": self.afl_available,
            "afl_path": str(self.afl_path) if self.afl_path else None,
            "docker_available": self.docker_available,
            "angr_available": self.angr_available,
            "radare2_available": self.radare2_available,
            "live_fuzzing_ready": self.live_fuzzing_ready,
            "full_libfuzzer_ready": self.full_libfuzzer_ready,
        }


class CapabilityDetector:
    """Thread-safe capability detection engine with memoization and safe probing."""

    _cached: ToolchainCapabilities | None = None
    _lock = threading.Lock()

    # Standard candidate installation locations
    _STANDARD_CLANG_PATHS = (
        Path("/opt/homebrew/opt/llvm/bin/clang"),
        Path("/usr/local/opt/llvm/bin/clang"),
        Path("/usr/lib/llvm-18/bin/clang"),
        Path("/usr/lib/llvm-17/bin/clang"),
        Path("/usr/lib/llvm-16/bin/clang"),
        Path("/usr/lib/llvm-15/bin/clang"),
        Path("/usr/lib/llvm-14/bin/clang"),
        Path("/usr/bin/clang"),
        Path("/usr/local/bin/clang"),
    )

    @classmethod
    def find_clang_binary(cls, override_path: str | Path | None = None) -> Path | None:
        """Locate Clang compiler executable with precedence hierarchy."""
        # 1. Explicit override passed to function
        if override_path:
            p = Path(override_path).expanduser().resolve()
            if p.exists() and os.access(p, os.X_OK):
                return p

        # 2. Environment variable override
        env_clang = os.environ.get("REVERSECORE_CLANG_PATH")
        if env_clang:
            p = Path(env_clang).expanduser().resolve()
            if p.exists() and os.access(p, os.X_OK):
                return p

        # 3. Application config (lazy import to avoid circular dependencies)
        try:
            from reversecore_mcp.core.config import get_config

            cfg_clang = get_config().clang_path
            if cfg_clang:
                p = Path(cfg_clang).expanduser().resolve()
                if p.exists() and os.access(p, os.X_OK):
                    return p
        except Exception:
            pass

        # 4. PATH lookup
        which_clang = shutil.which("clang")
        if which_clang:
            p = Path(which_clang).resolve()
            if p.exists() and os.access(p, os.X_OK):
                return p

        # 5. Standard candidate locations
        for cand in cls._STANDARD_CLANG_PATHS:
            if cand.exists() and os.access(cand, os.X_OK):
                return cand

        return None

    @staticmethod
    def _probe_compiler_flag(clang_bin: Path, flags: list[str], code: str) -> bool:
        """Safely compile and link a minimal C test snippet with strict timeout."""
        with tempfile.TemporaryDirectory(prefix="rcmcp_probe_") as tmpdir:
            src = Path(tmpdir) / "probe.c"
            out = Path(tmpdir) / "probe_bin"
            src.write_text(code, encoding="utf-8")
            cmd = [str(clang_bin), *flags, "-o", str(out), str(src)]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3.0,
                )
                return res.returncode == 0 and out.exists()
            except (subprocess.TimeoutExpired, OSError, Exception):
                return False

    @classmethod
    def _get_clang_version(cls, clang_bin: Path) -> str | None:
        """Retrieve version string from Clang executable."""
        try:
            res = subprocess.run(
                [str(clang_bin), "--version"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if res.returncode == 0 and res.stdout:
                first_line = res.stdout.strip().splitlines()[0]
                return first_line
        except Exception:
            pass
        return None

    @classmethod
    def detect(
        cls,
        force_refresh: bool = False,
        clang_path_override: str | Path | None = None,
    ) -> ToolchainCapabilities:
        """Detect host toolchain capabilities with caching and thread safety."""
        if not force_refresh and clang_path_override is None and cls._cached is not None:
            return cls._cached

        with cls._lock:
            if not force_refresh and clang_path_override is None and cls._cached is not None:
                return cls._cached

            # 1. Detect Clang
            clang_path = cls.find_clang_binary(clang_path_override)
            clang_available = clang_path is not None
            clang_version = cls._get_clang_version(clang_path) if clang_path else None

            # 2. Probe Sanitizer capabilities if Clang is available
            asan_supported = False
            ubsan_supported = False
            libfuzzer_supported = False

            if clang_path:
                probe_c = "int main(void) { return 0; }\n"
                asan_supported = cls._probe_compiler_flag(
                    clang_path, ["-fsanitize=address"], probe_c
                )
                ubsan_supported = cls._probe_compiler_flag(
                    clang_path, ["-fsanitize=undefined"], probe_c
                )
                fuzzer_c = (
                    "#include <stdint.h>\n"
                    "#include <stddef.h>\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }\n"
                )
                libfuzzer_supported = cls._probe_compiler_flag(
                    clang_path, ["-fsanitize=fuzzer,address"], fuzzer_c
                ) or cls._probe_compiler_flag(clang_path, ["-fsanitize=fuzzer"], fuzzer_c)

            # 3. Detect llvm-symbolizer
            llvm_symbolizer_path: Path | None = None
            if clang_path:
                cand_sym = clang_path.parent / "llvm-symbolizer"
                if cand_sym.exists() and os.access(cand_sym, os.X_OK):
                    llvm_symbolizer_path = cand_sym
            if not llvm_symbolizer_path:
                which_sym = shutil.which("llvm-symbolizer")
                if which_sym:
                    llvm_symbolizer_path = Path(which_sym).resolve()
            llvm_symbolizer_available = llvm_symbolizer_path is not None

            # 4. Detect AFL++
            which_afl = shutil.which("afl-fuzz")
            afl_path = Path(which_afl).resolve() if which_afl else None
            afl_available = afl_path is not None

            # 5. Detect Docker
            which_docker = shutil.which("docker")
            docker_available = which_docker is not None

            # 6. Detect angr
            try:
                angr_available = importlib.util.find_spec("angr") is not None
            except Exception:
                angr_available = False

            # 7. Detect Radare2
            which_r2 = shutil.which("radare2") or shutil.which("r2")
            radare2_available = which_r2 is not None

            caps = ToolchainCapabilities(
                clang_available=clang_available,
                clang_path=clang_path,
                clang_version=clang_version,
                asan_supported=asan_supported,
                ubsan_supported=ubsan_supported,
                libfuzzer_supported=libfuzzer_supported,
                llvm_symbolizer_available=llvm_symbolizer_available,
                llvm_symbolizer_path=llvm_symbolizer_path,
                afl_available=afl_available,
                afl_path=afl_path,
                docker_available=docker_available,
                angr_available=angr_available,
                radare2_available=radare2_available,
            )

            if clang_path_override is None:
                cls._cached = caps

            logger.debug("Detected toolchain capabilities: %s", caps.to_dict())
            return caps


def detect_capabilities(
    force_refresh: bool = False,
    clang_path_override: str | Path | None = None,
) -> ToolchainCapabilities:
    """Query and return host toolchain capabilities."""
    return CapabilityDetector.detect(
        force_refresh=force_refresh, clang_path_override=clang_path_override
    )
