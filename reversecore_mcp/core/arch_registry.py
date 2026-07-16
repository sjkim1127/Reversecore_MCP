"""Architecture registry for multi-arch binary analysis support.

Maps standard architecture names to radare2 internal names, supported bits,
and critical registers (PC, SP) for emulation and analysis.
"""

from __future__ import annotations

from typing import Any

# Registry of supported architectures
ARCH_REGISTRY: dict[str, dict[str, Any]] = {
    "x86": {"r2_arch": "x86", "bits": [32], "pc": "eip", "sp": "esp"},
    "x86_64": {"r2_arch": "x86", "bits": [64], "pc": "rip", "sp": "rsp"},
    "arm32": {"r2_arch": "arm", "bits": [16, 32], "pc": "r15", "sp": "r13"},
    "arm64": {"r2_arch": "arm", "bits": [64], "pc": "pc", "sp": "sp"},
    "mips": {"r2_arch": "mips", "bits": [32, 64], "pc": "pc", "sp": "sp"},
    "riscv": {"r2_arch": "riscv", "bits": [32, 64], "pc": "pc", "sp": "sp"},
    "ppc": {"r2_arch": "ppc", "bits": [32, 64], "pc": "pc", "sp": "r1"},
}


def _normalize_arch(arch: str, bits: int | None = None) -> str:
    """Normalize architecture name to registry key."""
    arch = arch.lower()

    # Handle aliases
    if arch == "amd64" or (arch == "x86" and bits == 64):
        return "x86_64"
    if arch == "arm" and bits == 64:
        return "arm64"
    if arch == "arm" and bits in (16, 32):
        return "arm32"
    if arch == "aarch64":
        return "arm64"

    return arch


def get_arch_init_cmds(arch: str, bits: int | None = None) -> list[str]:
    """Return r2 commands to initialize architecture before analysis.

    Args:
        arch: Architecture name (e.g., 'mips', 'arm64')
        bits: Architecture bits (e.g., 32, 64)

    Returns:
        List of r2 initialization commands, or empty list if arch is unknown.
    """
    normalized = _normalize_arch(arch, bits)
    if normalized not in ARCH_REGISTRY:
        return []

    entry = ARCH_REGISTRY[normalized]
    cmds = [f"e asm.arch={entry['r2_arch']}"]

    if bits and bits in entry["bits"]:
        cmds.append(f"e asm.bits={bits}")
    elif len(entry["bits"]) == 1:
        # Default to the only supported bit width if not specified
        cmds.append(f"e asm.bits={entry['bits'][0]}")

    return cmds


def get_pc_register(arch: str, bits: int | None = None) -> str | None:
    """Return the Program Counter (PC) register name for the architecture.

    Args:
        arch: Architecture name (e.g., 'x86_64', 'arm')
        bits: Architecture bits (e.g., 32, 64)

    Returns:
        Register name (e.g., 'rip', 'pc') or None if architecture is unknown.
    """
    normalized = _normalize_arch(arch, bits)
    if normalized not in ARCH_REGISTRY:
        return None

    return str(ARCH_REGISTRY[normalized]["pc"])


def get_sp_register(arch: str, bits: int | None = None) -> str | None:
    """Return the Stack Pointer (SP) register name for the architecture."""
    normalized = _normalize_arch(arch, bits)
    if normalized not in ARCH_REGISTRY:
        return None

    return str(ARCH_REGISTRY[normalized]["sp"])
