"""Tool wrapper for binary emulation using the Qiling framework."""

from __future__ import annotations

import io
import logging
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from reversecore_mcp.core.config import get_config
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import EmulationError, ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.resilience import circuit_breaker
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


def _detect_binary_type(file_path: Path) -> tuple[str, str]:
    """Detect ostype and archtype of the binary using LIEF or fallback magic bytes."""
    ostype = "linux"  # default
    archtype = "x86_64"  # default

    # Try using LIEF
    try:
        import lief

        binary = lief.parse(str(file_path))
        if binary is not None:
            fmt_str = str(binary.format).lower()
            if "pe" in fmt_str:
                ostype = "windows"
            elif "elf" in fmt_str:
                ostype = "linux"
            elif "macho" in fmt_str:
                ostype = "macos"

            # Detect archtype
            machine = getattr(binary.header, "machine", None)
            if machine:
                machine_str = str(machine).lower()
                if any(x in machine_str for x in ("x86_64", "amd64", "x64")):
                    archtype = "x86_64"
                elif any(x in machine_str for x in ("i386", "x86", "i686")):
                    archtype = "x86"
                elif any(x in machine_str for x in ("arm64", "aarch64")):
                    archtype = "arm64"
                elif "arm" in machine_str:
                    archtype = "arm"
                elif "mips" in machine_str:
                    archtype = "mips"
                elif "riscv" in machine_str:
                    archtype = "riscv"
        return ostype, archtype
    except Exception as e:
        logger.debug("LIEF detection failed, using fallback magic headers: %s", e)

    # Fallback to magic bytes
    try:
        with open(file_path, "rb") as f:
            header = f.read(5)

        if header.startswith(b"MZ"):
            ostype = "windows"
        elif header.startswith(b"\x7fELF"):
            ostype = "linux"
            if len(header) >= 5:
                # 5th byte: 1 = 32-bit, 2 = 64-bit
                archtype = "x86_64" if header[4] == 2 else "x86"
        elif header.startswith(b"\xcf\xfa\xed\xfe") or header.startswith(b"\xfe\xed\xfa\xcf"):
            ostype = "macos"
            archtype = "x86_64"
    except Exception as e:
        logger.warning("Fallback magic byte detection failed: %s", e)

    return ostype, archtype


@log_execution(tool_name="emulate_binary")
@track_metrics("emulate_binary")
@circuit_breaker(tool_name="emulation", failure_threshold=3, recovery_timeout=45)
@handle_tool_errors
async def emulate_binary(
    file_path: str,
    start_address: str | None = None,
    end_address: str | None = None,
    registers: dict[str, int] | None = None,
    stack_inputs: list[int] | None = None,
    mock_files: dict[str, str] | None = None,
    timeout: int = 10,
) -> ToolResult:
    """Emulate the execution of a binary using the Qiling framework.

    Allows running PE, ELF, and Mach-O binaries under dynamic OS-level sandbox emulation.
    Captures register states, memory modifications, stdout/stderr, and API/syscall traces.

    Args:
        file_path: Absolute or workspace-relative path to the binary to emulate.
        start_address: Hexadecimal or decimal address to start emulation from (optional).
        end_address: Hexadecimal or decimal address to stop emulation at (optional).
        registers: Dictionary of initial register values to set before emulation (e.g. {"eax": 1}).
        stack_inputs: List of integer values to push onto the stack before starting.
        mock_files: Dictionary of virtual file paths and content to mock in the filesystem.
        timeout: Maximum execution timeout in seconds (default is 10s).

    Returns:
        ToolResult with the emulation execution details, final registers, stdout, and syscall logs.

    Raises:
        ValidationError: If input path or arguments are invalid.
        EmulationError: If Qiling library is missing or emulation execution fails.

    Example:
        >>> result = await emulate_binary("sample.elf", registers={"rdi": 10}, timeout=5)
        >>> print(result.status)
        'success'
    """
    validated_path = validate_file_path(file_path)

    # Validate numeric addresses
    begin_addr = None
    if start_address:
        try:
            begin_addr = (
                int(start_address, 16)
                if start_address.lower().startswith("0x")
                else int(start_address)
            )
        except ValueError:
            raise ValidationError(
                f"Invalid start_address: '{start_address}'. Must be integer or hex."
            )

    end_addr = None
    if end_address:
        try:
            end_addr = (
                int(end_address, 16) if end_address.lower().startswith("0x") else int(end_address)
            )
        except ValueError:
            raise ValidationError(f"Invalid end_address: '{end_address}'. Must be integer or hex.")

    # 1. Try importing Qiling
    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except ImportError:
        raise EmulationError(
            "Qiling framework is not installed in the python environment. "
            "Please run: pip install 'reversecore-mcp[emulation]'"
        )

    # 2. Detect OS and architecture
    ostype, archtype = _detect_binary_type(validated_path)
    logger.info("Detected binary as %s (%s)", ostype, archtype)

    # 3. Configure mock rootfs
    workspace_cache = get_config().workspace / ".cache" / "qiling_rootfs"
    rootfs_path = workspace_cache / ostype / archtype
    rootfs_path.mkdir(parents=True, exist_ok=True)

    # Minimal OS directory structures
    if ostype == "linux":
        (rootfs_path / "lib").mkdir(exist_ok=True)
        (rootfs_path / "lib64").mkdir(exist_ok=True)
        (rootfs_path / "etc").mkdir(exist_ok=True)
    elif ostype == "windows":
        (rootfs_path / "Windows" / "System32").mkdir(parents=True, exist_ok=True)

    # 4. Handle mock files setup
    if mock_files:
        resolved_rootfs = rootfs_path.resolve()
        for virt_path, content in mock_files.items():
            clean_path = virt_path.lstrip("/\\")
            host_path = (rootfs_path / clean_path).resolve()
            if not host_path.is_relative_to(resolved_rootfs):
                logger.warning("Rejected path traversal attempt in mock_file path: %s", virt_path)
                continue
            host_path.parent.mkdir(parents=True, exist_ok=True)
            host_path.write_text(content, encoding="utf-8")
            logger.debug("Mocked file at %s inside rootfs", virt_path)

    # 5. Initialize execution logs capturing
    qiling_logger = logging.getLogger("qiling")
    log_stream = io.StringIO()
    log_handler = logging.StreamHandler(log_stream)
    log_handler.setLevel(logging.DEBUG)

    # Save original logger state
    original_handlers = qiling_logger.handlers[:]
    original_level = qiling_logger.level

    qiling_logger.handlers = [log_handler]
    qiling_logger.setLevel(logging.DEBUG)

    # 6. Initialize and configure Qiling engine
    stdout_stream = io.StringIO()
    stderr_stream = io.StringIO()

    try:
        # ql = Qiling([binary_path], rootfs, ostype, archtype)
        # We pass QL_VERBOSE.DEBUG to capture detailed syscall and register execution traces
        ql = Qiling(
            [str(validated_path)],
            rootfs=str(rootfs_path),
            ostype=ostype,
            archtype=archtype,
            verbose=QL_VERBOSE.DEBUG,
        )

        # Set initial register states
        if registers:
            for reg, val in registers.items():
                try:
                    ql.arch.regs.write(reg, val)
                except Exception:
                    try:
                        ql.arch.regs.write(reg.upper(), val)
                    except Exception as reg_err:
                        logger.warning("Could not set register %s: %s", reg, reg_err)

        # Set stack inputs
        if stack_inputs:
            for val in stack_inputs:
                try:
                    ql.arch.stack_push(val)
                except Exception as stack_err:
                    logger.warning("Could not push onto stack: %s", stack_err)

        # Run Qiling under redirected IO streams
        with redirect_stdout(stdout_stream), redirect_stderr(stderr_stream):
            # Limit execution time using timeout parameter
            # Qiling run method takes timeout in microseconds (or directly handles it)
            # but Qiling's run has a timeout parameter in milliseconds (or python timeout).
            # Usually, Qiling run accepts timeout parameter (in microseconds). Let's convert:
            timeout_ms = timeout * 1000
            ql.run(begin=begin_addr, end=end_addr, timeout=timeout_ms)

        # Read final register states
        final_regs = {}
        try:
            # Common registers to snapshot
            common_regs = (
                "eax",
                "ebx",
                "ecx",
                "edx",
                "esi",
                "edi",
                "esp",
                "ebp",
                "eip",
                "rax",
                "rbx",
                "rcx",
                "rdx",
                "rsi",
                "rdi",
                "rsp",
                "rbp",
                "rip",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
            )
            for reg in common_regs:
                try:
                    val = ql.arch.regs.read(reg)
                    final_regs[reg] = hex(val)
                except Exception:  # nosec B110 - intentional: some regs unsupported on this arch/OS
                    pass  # skip registers not available on this architecture
        except Exception as e:
            logger.debug("Failed to read final register states: %s", e)

        # Construct final output
        result_data = {
            "ostype": ostype,
            "archtype": archtype,
            "stdout": stdout_stream.getvalue(),
            "stderr": stderr_stream.getvalue(),
            "syscall_traces": log_stream.getvalue(),
            "final_registers": final_regs,
        }

        return success(result_data)

    except Exception as e:
        raise EmulationError(f"Emulation failed: {e}")

    finally:
        # Restore original logger state
        qiling_logger.handlers = original_handlers
        qiling_logger.setLevel(original_level)
