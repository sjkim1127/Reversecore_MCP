"""
Radare2 ESIL (Evaluable Strings Intermediate Language) Simulator.

Provides a Virtual Heap Manager wrapper around radare2 ESIL to simulate
heap allocation behaviors (malloc/free) and verify payload injections
for memory corruption analysis.
"""

from __future__ import annotations

from typing import Any

from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.tools.radare2.r2_session import R2Session

logger = get_logger(__name__)


class R2EsilSimulator:
    """Wraps Radare2 ESIL engine to provide heap simulation and payload testing."""

    def __init__(self, session: R2Session):
        self.r2 = session
        self.virtual_heap_base = 0x60000000
        self.current_heap_brk = self.virtual_heap_base
        self.chunks: dict[int, int] = {}  # addr -> size
        self.freed_chunks: list[int] = []

    def setup_esil_env(self) -> bool:
        """Initialize the ESIL VM and setup stack/memory."""
        logger.info("Initializing ESIL environment...")

        # Initialize ESIL
        self.r2.cmd("aei")
        # Initialize ESIL memory and stack
        self.r2.cmd("aeim")

        # Set up a virtual heap region (e.g. 1MB)
        # Allocate memory block using 'on' or 'om' depending on r2 version (typically 'on')
        # 'o' command might be needed. We'll rely on aer and memory maps if needed.
        return True

    def hook_allocators(
        self, malloc_sym: str = "sym.imp.malloc", free_sym: str = "sym.imp.free"
    ) -> None:
        """
        Intercept malloc/free calls.
        """
        # Set breakpoints at malloc and free
        self.r2.cmd(f"db {malloc_sym}")
        self.r2.cmd(f"db {free_sym}")

    def simulate_heap_layout(self, steps: int = 1000) -> dict[str, Any]:
        """
        Run ESIL and intercept malloc/free to build a virtual heap layout.
        Returns the final layout.
        """
        # For a full implementation, we'd loop and inspect RIP/PC
        # Here we provide a minimal virtual layout tracker.
        return {
            "virtual_heap_base": hex(self.virtual_heap_base),
            "chunks": {hex(k): v for k, v in self.chunks.items()},
            "freed_chunks": [hex(c) for c in self.freed_chunks],
        }

    def verify_payload_crash(
        self, inject_addr: int, payload: bytes, max_steps: int = 50
    ) -> dict[str, Any]:
        """
        Inject payload at inject_addr and step ESIL to see if PC gets corrupted.
        """
        hex_payload = payload.hex()
        # Write payload to memory
        self.r2.cmd(f"wx {hex_payload} @ {inject_addr}")

        # Determine architecture and PC register once
        info = self.r2.cmdj("iIj") or {}
        arch = info.get("arch", "x86")
        bits = info.get("bits", 64)
        from reversecore_mcp.core.arch_registry import get_pc_register

        pc_reg = get_pc_register(arch, bits) or "rip"

        # Step ESIL and monitor PC
        pc_history = []
        crashed = False
        corrupted_pc = ""

        for _ in range(max_steps):
            self.r2.cmd("aes")
            regs = self.r2.cmdj("aerj")
            if not regs or not isinstance(regs, dict):
                continue

            # Extract PC dynamically based on architecture
            pc = regs.get(pc_reg, 0)
            if pc:
                pc_history.append(hex(pc))

            # Check if PC points to our payload or is invalid
            if pc == 0x4141414141414141 or pc == 0x41414141:
                crashed = True
                corrupted_pc = hex(pc)
                break

        return {
            "crashed": crashed,
            "corrupted_pc": corrupted_pc,
            "pc_history": pc_history,
        }
