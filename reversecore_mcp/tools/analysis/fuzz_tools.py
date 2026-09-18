"""Fuzzing harness generator for dynamic vulnerability verification."""

import re
import textwrap

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, failure, success
from reversecore_mcp.core.security import validate_file_path

QILING_HARNESS_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"
Generated Qiling Fuzzing Harness for {binary_name}
Target Address: {target_addr}

Dependencies:
pip install qiling afl

Usage (with AFL++):
afl-fuzz -i ./in -o ./out -Q -m none -- python3 {script_name} @@
\"\"\"

import sys
import os
from qiling import Qiling
from qiling.const import QL_VERBOSE

def start_afl(ql: Qiling):
    \"\"\"Start AFL forkserver and fuzzing loop.\"\"\"
    import afl
    afl.init()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 %s <input_file>" % sys.argv[0])
        sys.exit(1)

    input_file = sys.argv[1]
    binary_path = {binary_path_str}

    # Setup Qiling engine
    # Adjust rootfs to match the binary's OS/Arch
    ql = Qiling(
        [binary_path],
        rootfs="{rootfs_path}",
        verbose=QL_VERBOSE.OFF
    )

    # ---------------------------------------------------------
    # TODO: Hook the target function or setup memory state here.
    # For example, to read the mutated input from AFL:
    #
    # with open(input_file, 'rb') as f:
    #     data = f.read()
    #
    # ql.mem.write(ql.arch.regs.rdi, data) # Write to buffer args
    # ---------------------------------------------------------

    # Initialize AFL
    start_afl(ql)

    try:
        # Run execution from entry point or specific address
        ql.run(begin={target_addr_val})
    except Exception as e:
        # Crash detected! Let AFL know.
        os.abort()

if __name__ == "__main__":
    main()
"""


@log_execution(tool_name="generate_fuzzing_harness")
@track_metrics("generate_fuzzing_harness")
@handle_tool_errors
def generate_fuzzing_harness(
    file_path: str,
    target_function_or_addr: str,
    fuzzer_type: str = "qiling",
    save_to_workspace: bool = False,
) -> ToolResult:
    """Generate a dynamic fuzzing harness (Qiling + AFL++) for a vulnerable function.

    Instead of running a heavy fuzzer within the MCP server, this tool generates
    a ready-to-use Python script that the user can run with AFL++ to prove
    vulnerability exploitability.

    Args:
        file_path: Path to the vulnerable binary.
        target_function_or_addr: The function name or hex address to fuzz (e.g. 0x401234).
        fuzzer_type: The type of harness to generate (default: "qiling").
        save_to_workspace: If True, saves the generated harness to the workspace.

    Returns:
        ToolResult with the generated Python script content.
    """
    validated_path = validate_file_path(file_path)

    if fuzzer_type.lower() != "qiling":
        return failure(
            "UNSUPPORTED_FUZZER",
            f"Fuzzer type '{fuzzer_type}' is not supported yet. Use 'qiling'.",
        )

    # Validate and sanitize target address / function name
    target_clean = target_function_or_addr.strip()
    if not target_clean:
        raise ValidationError("target_function_or_addr cannot be empty")

    if any(c in target_clean for c in ('"', "'", "\n", "\r", "`", "$", ";", "\\")):
        raise ValidationError(
            f"target_function_or_addr contains forbidden characters: {target_clean!r}"
        )

    # Format the target address
    try:
        target_val = (
            int(target_clean, 16) if target_clean.startswith(("0x", "0X")) else int(target_clean)
        )
        target_str = hex(target_val)
        target_addr_val = target_str
    except ValueError:
        # If not an integer, validate as a safe symbol/function identifier
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.:]*$", target_clean):
            raise ValidationError(
                f"Invalid function name format: {target_clean!r}. "
                "Must be a valid symbol name or hex/decimal address."
            )
        target_str = target_clean
        target_addr_val = "ql.os.entry_point"

    # Default rootfs placeholder (user should adjust based on their setup)
    rootfs_placeholder = "/qiling/examples/rootfs/x8664_linux"

    safe_binary_name = re.sub(r'["\'\r\n]', "", validated_path.name)
    script_name = f"fuzz_{safe_binary_name}.py"
    harness_code = QILING_HARNESS_TEMPLATE.format(
        binary_name=safe_binary_name,
        target_addr=target_str,
        script_name=script_name,
        binary_path_str=repr(str(validated_path)),
        rootfs_path=rootfs_placeholder,
        target_addr_val=target_addr_val,
    )

    saved_path = None
    if save_to_workspace:
        from reversecore_mcp.core.config import get_config

        workspace = get_config().workspace.resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^\w.-]", "_", validated_path.name)
        target_file = (workspace / f"fuzz_{safe_name}.py").resolve()
        if not target_file.is_relative_to(workspace):
            return failure(
                "PATH_TRAVERSAL_DETECTED",
                "Target script path must reside within the workspace directory",
            )
        target_file.write_text(harness_code, encoding="utf-8")
        saved_path = str(target_file)

    return success(
        {
            "harness_code": harness_code,
            "saved_path": saved_path,
            "instructions": textwrap.dedent(f"""
                1. Save the generated code to a Python file{(" (already saved to " + saved_path + ")") if saved_path else ""}.
                2. Install dependencies: pip install qiling afl
                3. Update the TODO section in the script to map the fuzzer input to the vulnerable buffer.
                4. Run AFL++: afl-fuzz -i in/ -o out/ -Q -m none -- python3 {script_name} @@
                """).strip(),
        }
    )
