"""CLI tool wrappers that return structured ToolResult payloads."""

import json
import re
import shutil
from pathlib import Path

from fastmcp import FastMCP

from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.validators import validate_tool_parameters


def register_cli_tools(mcp: FastMCP) -> None:
    """
    Register all CLI tool wrappers with the FastMCP server.

    Args:
        mcp: The FastMCP server instance to register tools with
    """
    mcp.tool(run_file)
    mcp.tool(run_strings)
    mcp.tool(run_radare2)
    mcp.tool(run_binwalk)
    mcp.tool(copy_to_workspace)
    mcp.tool(list_workspace)
    mcp.tool(generate_function_graph)
    mcp.tool(emulate_machine_code)
    mcp.tool(get_pseudo_code)
    mcp.tool(generate_signature)
    mcp.tool(extract_rtti_info)
    mcp.tool(smart_decompile)
    mcp.tool(generate_yara_rule)
    mcp.tool(analyze_xrefs)
    mcp.tool(recover_structures)
    mcp.tool(diff_binaries)
    mcp.tool(match_libraries)


@log_execution(tool_name="run_file")
@track_metrics("run_file")
@handle_tool_errors
async def run_file(file_path: str, timeout: int = 30) -> ToolResult:
    """Identify file metadata using the ``file`` CLI utility."""

    validated_path = validate_file_path(file_path)
    cmd = ["file", str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )
    return success(output.strip(), bytes_read=bytes_read)


@log_execution(tool_name="run_strings")
@track_metrics("run_strings")
@handle_tool_errors
async def run_strings(
    file_path: str,
    min_length: int = 4,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Extract printable strings using the ``strings`` CLI."""

    validate_tool_parameters(
        "run_strings",
        {"min_length": min_length, "max_output_size": max_output_size},
    )
    validated_path = validate_file_path(file_path)
    cmd = ["strings", "-n", str(min_length), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_radare2")
@track_metrics("run_radare2")
@handle_tool_errors
async def run_radare2(
    file_path: str,
    r2_command: str,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Execute vetted radare2 commands for binary triage."""

    validate_tool_parameters("run_radare2", {"r2_command": r2_command})
    validated_path = validate_file_path(file_path)
    validated_command = validate_r2_command(r2_command)
    cmd = ["r2", "-q", "-c", validated_command, str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="run_binwalk")
@track_metrics("run_binwalk")
@handle_tool_errors
async def run_binwalk(
    file_path: str,
    depth: int = 8,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """Analyze binaries for embedded content using binwalk."""

    validated_path = validate_file_path(file_path)
    cmd = ["binwalk", "-A", "-d", str(depth), str(validated_path)]
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=max_output_size,
        timeout=timeout,
    )
    return success(output, bytes_read=bytes_read)


@log_execution(tool_name="copy_to_workspace")
@track_metrics("copy_to_workspace")
@handle_tool_errors
def copy_to_workspace(
    source_path: str,
    destination_name: str = None,
) -> ToolResult:
    """
    Copy any accessible file to the workspace directory.

    This tool allows copying files from any location (including AI agent upload directories)
    to the workspace where other reverse engineering tools can access them.

    Supports files from:
    - Claude Desktop uploads (/mnt/user-data/uploads)
    - Cursor uploads
    - Windsurf uploads
    - Local file paths
    - Any other accessible location

    Args:
        source_path: Absolute or relative path to the source file
        destination_name: Optional custom filename in workspace (defaults to original name)

    Returns:
        ToolResult with the new file path in workspace
    """
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.exceptions import ValidationError

    # Convert to Path and resolve (but don't require strict=True for external files)
    try:
        source = Path(source_path).expanduser().resolve()
    except Exception as e:
        raise ValidationError(
            f"Invalid source path: {source_path}",
            details={"source_path": source_path, "error": str(e)},
        )

    # Validate source exists and is a file
    if not source.exists():
        raise ValidationError(
            f"Source file does not exist: {source}",
            details={"source_path": str(source)},
        )

    if not source.is_file():
        raise ValidationError(
            f"Source path is not a file: {source}", details={"source_path": str(source)}
        )

    # Check file size (prevent copying extremely large files)
    max_file_size = 5 * 1024 * 1024 * 1024  # 5GB
    file_size = source.stat().st_size
    if file_size > max_file_size:
        raise ValidationError(
            f"File too large to copy: {file_size} bytes (max: {max_file_size} bytes)",
            details={"file_size": file_size, "max_size": max_file_size},
        )

    # Determine destination filename
    if destination_name:
        # Sanitize destination name (remove path separators and dangerous chars)
        dest_name = Path(destination_name).name
        # Additional sanitization for security - check if sanitization changed the name
        if dest_name != destination_name or not dest_name:
            raise ValidationError(
                f"Invalid destination name: {destination_name}",
                details={"destination_name": destination_name},
            )
    else:
        dest_name = source.name

    # Build destination path in workspace
    config = get_config()
    destination = config.workspace / dest_name

    # Check if file already exists
    if destination.exists():
        raise ValidationError(
            f"File already exists in workspace: {dest_name}",
            details={
                "destination": str(destination),
                "hint": "Use a different destination_name or remove the existing file first",
            },
        )

    # Copy file to workspace
    try:
        shutil.copy2(source, destination)
        copied_size = destination.stat().st_size

        return success(
            str(destination),
            source_path=str(source),
            destination_path=str(destination),
            file_size=copied_size,
            message=f"File copied successfully to workspace: {dest_name}",
        )
    except PermissionError as e:
        raise ValidationError(
            f"Permission denied when copying file: {e}",
            details={"source": str(source), "destination": str(destination)},
        )
    except Exception as e:
        raise ValidationError(
            f"Failed to copy file: {e}",
            details={
                "source": str(source),
                "destination": str(destination),
                "error": str(e),
            },
        )


@log_execution(tool_name="list_workspace")
@track_metrics("list_workspace")
@handle_tool_errors
def list_workspace() -> ToolResult:
    """
    List all files in the workspace directory.

    Returns:
        ToolResult with list of files in workspace
    """
    from reversecore_mcp.core.config import get_config

    config = get_config()
    workspace = config.workspace

    if not workspace.exists():
        return success(
            {"files": [], "message": "Workspace is empty"},
            file_count=0,
            workspace_path=str(workspace),
        )

    files = []
    for item in workspace.iterdir():
        if item.is_file():
            files.append(
                {"name": item.name, "size": item.stat().st_size, "path": str(item)}
            )

    return success(
        {"files": files}, file_count=len(files), workspace_path=str(workspace)
    )


def _radare2_json_to_mermaid(json_str: str) -> str:
    """
    Convert Radare2 'agfj' JSON output to Mermaid Flowchart syntax.
    Optimized for LLM context efficiency.

    Args:
        json_str: JSON output from radare2 agfj command

    Returns:
        Mermaid flowchart syntax string
    """
    try:
        graph_data = json.loads(json_str)
        if not graph_data:
            return "graph TD;\n    Error[No graph data found]"

        # agfj returns list format for function graph
        blocks = (
            graph_data[0].get("blocks", [])
            if isinstance(graph_data, list)
            else graph_data.get("blocks", [])
        )

        mermaid_lines = ["graph TD"]

        for block in blocks:
            # 1. Generate node ID from offset
            node_id = f"N_{hex(block.get('offset', 0))}"

            # 2. Generate node label from assembly opcodes
            ops = block.get("ops", [])
            op_codes = [op.get("opcode", "") for op in ops]

            # Token efficiency: limit to 5 lines per block
            if len(op_codes) > 5:
                op_codes = op_codes[:5] + ["..."]

            # Escape Mermaid special characters
            label_content = (
                "\\n".join(op_codes)
                .replace('"', "'")
                .replace("(", "[")
                .replace(")", "]")
            )

            # Define node
            mermaid_lines.append(f'    {node_id}["{label_content}"]')

            # 3. Create edges
            # True branch (jump)
            if "jump" in block:
                target_id = f"N_{hex(block['jump'])}"
                mermaid_lines.append(f"    {node_id} -->|True| {target_id}")

            # False branch (fail)
            if "fail" in block:
                target_id = f"N_{hex(block['fail'])}"
                mermaid_lines.append(f"    {node_id} -.->|False| {target_id}")

        return "\n".join(mermaid_lines)

    except Exception as e:
        return f"graph TD;\n    Error[Parse Error: {str(e)}]"


@log_execution(tool_name="generate_function_graph")
@track_metrics("generate_function_graph")
@handle_tool_errors
async def generate_function_graph(
    file_path: str,
    function_address: str,
    format: str = "mermaid",
    timeout: int = 300,
) -> ToolResult:
    """
    Generate a Control Flow Graph (CFG) for a specific function.

    This tool uses radare2 to analyze the function structure and returns
    a visualization code (Mermaid by default) that helps AI understand
    the code flow without reading thousands of lines of assembly.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address (e.g., 'main', '0x140001000', 'sym.foo')
        format: Output format ('mermaid', 'json', or 'dot'). Default is 'mermaid'.
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with CFG visualization or JSON data
    """
    from reversecore_mcp.core.result import failure

    # 1. Parameter validation
    validate_tool_parameters(
        "generate_function_graph",
        {"function_address": function_address, "format": format},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    if not re.match(r"^[a-zA-Z0-9_.]+$", function_address.replace("0x", "")):
        return failure("VALIDATION_ERROR", "Invalid function address format")

    # 3. Build radare2 command
    r2_cmd_str = f"agfj @ {function_address}"

    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Automatic analysis
        "-c",
        r2_cmd_str,  # Extract graph JSON
        str(validated_path),
    ]

    # 4. Execute subprocess asynchronously
    # Large graphs need higher output limit
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=50_000_000,
        timeout=timeout,
    )

    # 5. Format conversion and return
    if format.lower() == "json":
        return success(output, bytes_read=bytes_read, format="json")

    elif format.lower() == "mermaid":
        mermaid_code = _radare2_json_to_mermaid(output)
        return success(
            mermaid_code,
            bytes_read=bytes_read,
            format="mermaid",
            description="Render this using Mermaid to see the control flow.",
        )

    elif format.lower() == "dot":
        # For DOT format, call radare2 with agfd command
        dot_cmd = [
            "r2",
            "-q",
            "-c",
            "aaa",
            "-c",
            f"agfd @ {function_address}",
            str(validated_path),
        ]
        dot_output, dot_bytes = await execute_subprocess_async(
            dot_cmd,
            max_output_size=50_000_000,
            timeout=timeout,
        )
        return success(dot_output, bytes_read=dot_bytes, format="dot")

    return failure("INVALID_FORMAT", f"Unsupported format: {format}")


def _parse_register_state(ar_output: str) -> dict:
    """
    Parse radare2 'ar' command output into structured register state.

    Args:
        ar_output: Raw output from 'ar' command

    Returns:
        Dictionary mapping register names to values

    Example output from 'ar':
        rax = 0x00000000
        rbx = 0x00401000
        ...
    """
    registers = {}

    for line in ar_output.strip().split("\n"):
        if "=" in line:
            parts = line.split("=")
            if len(parts) == 2:
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers[reg_name] = reg_value

    return registers


@log_execution(tool_name="emulate_machine_code")
@track_metrics("emulate_machine_code")
@handle_tool_errors
async def emulate_machine_code(
    file_path: str,
    start_address: str,
    instructions: int = 50,
    timeout: int = 300,
) -> ToolResult:
    """
    Emulate machine code execution using radare2 ESIL (Evaluable Strings Intermediate Language).

    This tool provides safe, sandboxed emulation of binary code without actual execution.
    Perfect for analyzing obfuscated code, understanding register states, and predicting
    execution outcomes without security risks.

    **Key Use Cases:**
    - De-obfuscation: Reveal hidden strings by emulating XOR/shift operations
    - Register Analysis: See final register values after code execution
    - Safe Malware Analysis: Predict behavior without running malicious code

    **Safety Features:**
    - Virtual CPU simulation (no real execution)
    - Instruction count limit (max 1000) prevents infinite loops
    - Memory sandboxing (changes don't affect host system)

    Args:
        file_path: Path to the binary file (must be in workspace)
        start_address: Address to start emulation (e.g., 'main', '0x401000', 'sym.decrypt')
        instructions: Number of instructions to execute (default 50, max 1000)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with register states and emulation summary
    """
    from reversecore_mcp.core.result import failure

    # 1. Parameter validation
    validate_tool_parameters(
        "emulate_machine_code",
        {"start_address": start_address, "instructions": instructions},
    )
    validated_path = validate_file_path(file_path)

    # 2. Security check for start address (prevent shell injection)
    if not re.match(r"^[a-zA-Z0-9_.]+$", start_address.replace("0x", "")):
        return failure("VALIDATION_ERROR", "Invalid start address format")

    # 3. Build radare2 ESIL emulation command chain
    # Note: Commands must be executed in specific order for ESIL to work correctly
    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Analyze all
        "-c",
        f"s {start_address}",  # Seek to start address
        "-c",
        "aei",  # Initialize ESIL VM
        "-c",
        "aeim",  # Initialize ESIL memory (stack)
        "-c",
        "aeip",  # Initialize program counter to current seek
        "-c",
        f"aes {instructions}",  # Step through N instructions
        "-c",
        "ar",  # Show all registers
        str(validated_path),
    ]

    # 4. Execute emulation
    try:
        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=10_000_000,  # Register output is typically small
            timeout=timeout,
        )

        # 5. Parse register state
        register_state = _parse_register_state(output)

        if not register_state:
            return failure(
                "EMULATION_ERROR",
                "Failed to extract register state from emulation output",
                hint="The binary may not be compatible with ESIL emulation, or the start address is invalid",
            )

        # 6. Build result with metadata
        return success(
            register_state,
            bytes_read=bytes_read,
            format="register_state",
            instructions_executed=instructions,
            start_address=start_address,
            description=f"Emulated {instructions} instructions starting at {start_address}",
        )

    except Exception as e:
        return failure(
            "EMULATION_ERROR",
            f"ESIL emulation failed: {str(e)}",
            hint="Check that the binary architecture is supported and the start address is valid",
        )


@log_execution(tool_name="get_pseudo_code")
@track_metrics("get_pseudo_code")
@handle_tool_errors
async def get_pseudo_code(
    file_path: str,
    address: str = "main",
    timeout: int = 300,
) -> ToolResult:
    """
    Generate pseudo C code (decompilation) for a function using radare2's pdc command.

    This tool decompiles binary code into C-like pseudocode, making it much easier
    to understand program logic compared to raw assembly. The output can be further
    refined by AI for better readability.

    **Use Cases:**
    - Quick function understanding without reading assembly
    - AI-assisted code analysis and refactoring
    - Documentation generation from binaries
    - Reverse engineering workflow optimization

    **Note:** The output is "pseudo C" - it may not be syntactically perfect C,
    but provides a high-level representation of the function logic.

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function address to decompile (e.g., 'main', '0x401000', 'sym.foo')
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with pseudo C code string

    Example:
        get_pseudo_code("/app/workspace/sample.exe", "main")
        # Returns C-like code representation of the main function
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate file path
    validated_path = validate_file_path(file_path)

    # 2. Security check for address (prevent shell injection)
    if not re.match(r"^[a-zA-Z0-9_.]+$", address.replace("0x", "")):
        return failure(
            "VALIDATION_ERROR",
            "Invalid address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Build radare2 command to decompile
    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Analyze all
        "-c",
        f"pdc @ {address}",  # Print Decompiled C code at address
        str(validated_path),
    ]

    # 4. Execute decompilation
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=10_000_000,  # Decompiled code can be large
        timeout=timeout,
    )

    # 5. Check if output is valid
    if not output or output.strip() == "":
        return failure(
            "DECOMPILATION_ERROR",
            f"No decompilation output for address: {address}",
            hint="Verify the address exists and points to a valid function. Try analyzing with 'afl' first.",
        )

    # 6. Return pseudo C code
    return success(
        output,
        bytes_read=bytes_read,
        address=address,
        format="pseudo_c",
        description=f"Pseudo C code decompiled from address {address}",
    )


@log_execution(tool_name="generate_signature")
@track_metrics("generate_signature")
@handle_tool_errors
async def generate_signature(
    file_path: str,
    address: str,
    length: int = 32,
    timeout: int = 300,
) -> ToolResult:
    """
    Generate a YARA signature from opcode bytes at a specific address.

    This tool extracts opcode bytes from a function or code section and formats
    them as a YARA rule, enabling automated malware detection. It attempts to
    mask variable values (addresses, offsets) to create more flexible signatures.

    **Use Cases:**
    - Generate detection signatures for malware samples
    - Create YARA rules for threat hunting
    - Automate IOC (Indicator of Compromise) generation
    - Build malware family signatures

    **Workflow:**
    1. Extract opcode bytes from specified address
    2. Apply basic masking for variable values (optional)
    3. Format as YARA rule template
    4. Return ready-to-use YARA rule

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Start address for signature extraction (e.g., 'main', '0x401000')
        length: Number of bytes to extract (default 32, recommended 16-64)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string

    Example:
        generate_signature("/app/workspace/malware.exe", "0x401000", 48)
        # Returns a YARA rule with extracted byte pattern
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if not isinstance(length, int) or length < 1 or length > 1024:
        return failure(
            "VALIDATION_ERROR",
            "Length must be between 1 and 1024 bytes",
            hint="Typical signature lengths are 16-64 bytes for good detection accuracy",
        )

    # 2. Security check for address
    if not re.match(r"^[a-zA-Z0-9_.]+$", address.replace("0x", "")):
        return failure(
            "VALIDATION_ERROR",
            "Invalid address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Extract hex bytes using radare2's p8 command
    cmd = [
        "r2",
        "-q",
        "-c",
        f"s {address}",  # Seek to address
        "-c",
        f"p8 {length}",  # Print hex bytes
        str(validated_path),
    ]

    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )

    # 4. Validate output
    hex_bytes = output.strip()
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "SIGNATURE_ERROR",
            f"Failed to extract valid hex bytes from address: {address}",
            hint="Verify the address is valid and contains executable code",
        )

    # 5. Format as YARA hex string (space-separated pairs)
    # Convert: "4883ec20" -> "48 83 ec 20"
    formatted_bytes = " ".join(
        [hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)]
    )

    # 6. Generate YARA rule template
    # Extract filename for rule name
    file_name = Path(file_path).stem.replace("-", "_").replace(".", "_")
    rule_name = f"suspicious_{file_name}_{address.replace('0x', 'x')}"

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated signature for {file_name}"
        address = "{address}"
        length = {length}
        author = "Reversecore_MCP"
        date = "auto-generated"
        
    strings:
        $code = {{ {formatted_bytes} }}
        
    condition:
        $code
}}"""

    # 7. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        address=address,
        length=length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA signature generated from {length} bytes at {address}",
    )


@log_execution(tool_name="extract_rtti_info")
@track_metrics("extract_rtti_info")
@handle_tool_errors
async def extract_rtti_info(
    file_path: str,
    timeout: int = 300,
) -> ToolResult:
    """
    Extract C++ RTTI (Run-Time Type Information) and class structure information.

    This tool analyzes C++ binaries to recover class names, methods, and inheritance
    hierarchies using RTTI metadata and symbol tables. Essential for reverse engineering
    large C++ applications like games and commercial software.

    **Use Cases:**
    - Recover class structure from C++ binaries
    - Map out object hierarchies in games/applications
    - Identify virtual function tables (vtables)
    - Understand C++ software architecture
    - Generate class diagrams from binaries

    **Extracted Information:**
    - Class names and namespaces
    - Virtual methods and vtables
    - Type descriptors
    - Symbol information
    - Import/export functions

    **Note:** RTTI recovery works best with binaries compiled with RTTI enabled
    (typically the default). Stripped or heavily obfuscated binaries may have
    limited RTTI information.

    Args:
        file_path: Path to the binary file (must be in workspace)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with structured RTTI information including classes, symbols, and methods

    Example:
        extract_rtti_info("/app/workspace/game.exe")
        # Returns JSON with class hierarchy and method information
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate file path
    validated_path = validate_file_path(file_path)

    # 2. Build radare2 command chain to extract RTTI and symbols
    # We'll use multiple commands to get comprehensive information
    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Analyze all (includes class analysis)
        "-c",
        "icj",  # List classes in JSON format
        str(validated_path),
    ]

    # 3. Execute class extraction
    classes_output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=50_000_000,  # Class info can be large for complex binaries
        timeout=timeout,
    )

    # 4. Extract symbols
    symbols_cmd = [
        "r2",
        "-q",
        "-c",
        "isj",  # List symbols in JSON format
        str(validated_path),
    ]

    symbols_output, symbols_bytes = await execute_subprocess_async(
        symbols_cmd,
        max_output_size=50_000_000,
        timeout=timeout,
    )

    # 5. Parse JSON outputs
    try:
        classes = json.loads(classes_output) if classes_output.strip() else []
        symbols = json.loads(symbols_output) if symbols_output.strip() else []
    except json.JSONDecodeError as e:
        return failure(
            "PARSE_ERROR",
            f"Failed to parse RTTI output: {str(e)}",
            hint="The binary may not contain valid RTTI information or is not a C++ binary",
        )

    # 6. Filter and organize C++ specific symbols
    cpp_classes = []
    cpp_methods = []
    vtables = []

    # Process classes
    for cls in classes:
        if isinstance(cls, dict):
            cpp_classes.append(
                {
                    "name": cls.get("classname", "unknown"),
                    "address": cls.get("addr", "0x0"),
                    "methods": cls.get("methods", []),
                    "vtable": cls.get("vtable", None),
                }
            )

    # Process symbols to find C++ related items
    for sym in symbols:
        if isinstance(sym, dict):
            name = sym.get("name", "")
            sym_type = sym.get("type", "")

            # Detect C++ mangled names (start with _Z or ??)
            if name.startswith("_Z") or name.startswith("??"):
                cpp_methods.append(
                    {
                        "name": name,
                        "address": sym.get("vaddr", sym.get("paddr", "0x0")),
                        "type": sym_type,
                        "size": sym.get("size", 0),
                    }
                )

            # Detect vtables
            if "vtable" in name.lower() or name.startswith("vtable"):
                vtables.append(
                    {"name": name, "address": sym.get("vaddr", sym.get("paddr", "0x0"))}
                )

    # 7. Build comprehensive RTTI report
    rtti_info = {
        "classes": cpp_classes,
        "class_count": len(cpp_classes),
        "methods": cpp_methods[:100],  # Limit to first 100 for readability
        "method_count": len(cpp_methods),
        "vtables": vtables,
        "vtable_count": len(vtables),
        "has_rtti": len(cpp_classes) > 0 or len(vtables) > 0,
        "binary_type": (
            "C++" if (len(cpp_classes) > 0 or len(cpp_methods) > 0) else "Unknown"
        ),
    }

    # 8. Add summary message
    if not rtti_info["has_rtti"]:
        description = "No RTTI information found. Binary may be stripped, not C++, or compiled without RTTI."
    else:
        description = f"Found {rtti_info['class_count']} classes, {rtti_info['method_count']} methods, {rtti_info['vtable_count']} vtables"

    # 9. Return structured RTTI information
    return success(
        rtti_info,
        bytes_read=bytes_read + symbols_bytes,
        format="rtti_info",
        description=description,
    )


@log_execution(tool_name="smart_decompile")
@track_metrics("smart_decompile")
@handle_tool_errors
async def smart_decompile(
    file_path: str,
    function_address: str,
    timeout: int = 300,
    use_ghidra: bool = True,
) -> ToolResult:
    """
    Decompile a function to pseudo C code using Ghidra or radare2.

    This tool provides decompilation for a specific function in a binary,
    making it easier to understand the logic without reading raw assembly.

    **Decompiler Selection:**
    - Ghidra (default): More accurate, better type recovery, industry-standard
    - radare2 (fallback): Faster, lighter weight, good for quick analysis

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to decompile (e.g., 'main', '0x401000')
        timeout: Execution timeout in seconds (default 300)
        use_ghidra: Use Ghidra decompiler if available (default True)

    Returns:
        ToolResult with decompiled pseudo C code
    """
    from reversecore_mcp.core.result import failure
    from reversecore_mcp.core.logging_config import get_logger

    logger = get_logger(__name__)

    # 1. Validate parameters
    validate_tool_parameters("smart_decompile", {"function_address": function_address})
    validated_path = validate_file_path(file_path)

    # 2. Security check for function address (prevent shell injection)
    if not re.match(r"^[a-zA-Z0-9_.]+$", function_address.replace("0x", "")):
        return failure(
            "VALIDATION_ERROR",
            "Invalid function address format",
            hint="Function address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 3. Try Ghidra first if requested and available
    if use_ghidra:
        try:
            from reversecore_mcp.core.ghidra_helper import (
                ensure_ghidra_available,
                decompile_function_with_ghidra,
            )

            if ensure_ghidra_available():
                logger.info(f"Using Ghidra decompiler for {function_address}")

                # Run Ghidra decompilation
                try:
                    c_code, metadata = decompile_function_with_ghidra(
                        validated_path, function_address, timeout
                    )

                    return success(
                        c_code,
                        function_address=function_address,
                        format="pseudo_c",
                        decompiler="ghidra",
                        **metadata,
                    )

                except Exception as ghidra_error:
                    logger.warning(
                        f"Ghidra decompilation failed: {ghidra_error}. "
                        "Falling back to radare2"
                    )
                    # Fall through to radare2
            else:
                logger.info("Ghidra not available, using radare2")

        except ImportError:
            logger.info("PyGhidra not installed, using radare2")

    # 4. Fallback to radare2 (original implementation)
    logger.info(f"Using radare2 decompiler for {function_address}")

    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Analyze all
        "-c",
        f"pdc @ {function_address}",  # Print Decompiled C code at address
        str(validated_path),
    ]

    # 5. Execute decompilation
    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=10_000_000,
        timeout=timeout,
    )

    # 6. Return result
    return success(
        output,
        bytes_read=bytes_read,
        function_address=function_address,
        format="pseudo_c",
        decompiler="radare2",
        description=f"Decompiled code from function {function_address}",
    )


@log_execution(tool_name="generate_yara_rule")
@track_metrics("generate_yara_rule")
@handle_tool_errors
async def generate_yara_rule(
    file_path: str,
    function_address: str,
    rule_name: str = "auto_generated_rule",
    byte_length: int = 64,
    timeout: int = 300,
) -> ToolResult:
    """
    Generate a YARA rule from function bytes.

    This tool extracts bytes from a function and generates a ready-to-use
    YARA rule for malware detection and threat hunting.

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function address to extract bytes from (e.g., 'main', '0x401000')
        rule_name: Name for the YARA rule (default 'auto_generated_rule')
        byte_length: Number of bytes to extract (default 64, max 1024)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with YARA rule string
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validate_tool_parameters(
        "generate_yara_rule",
        {
            "function_address": function_address,
            "rule_name": rule_name,
            "byte_length": byte_length,
        },
    )
    validated_path = validate_file_path(file_path)

    # 2. Validate rule_name format
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", rule_name):
        return failure(
            "VALIDATION_ERROR",
            "rule_name must start with a letter and contain only alphanumeric characters and underscores",
        )

    # 3. Security check for function address (prevent shell injection)
    if not re.match(r"^[a-zA-Z0-9_.]+$", function_address.replace("0x", "")):
        return failure(
            "VALIDATION_ERROR",
            "Invalid function address format",
            hint="Function address must contain only alphanumeric characters, dots, underscores, and '0x' prefix",
        )

    # 4. Extract hex bytes using radare2's p8 command
    cmd = [
        "r2",
        "-q",
        "-c",
        f"s {function_address}",  # Seek to address
        "-c",
        f"p8 {byte_length}",  # Print hex bytes
        str(validated_path),
    ]

    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=1_000_000,
        timeout=timeout,
    )

    # 5. Validate output
    hex_bytes = output.strip()
    if not hex_bytes or not re.match(r"^[0-9a-fA-F]+$", hex_bytes):
        return failure(
            "YARA_GENERATION_ERROR",
            f"Failed to extract valid hex bytes from address: {function_address}",
            hint="Verify the address is valid and contains executable code",
        )

    # 6. Format as YARA hex string (space-separated pairs)
    formatted_bytes = " ".join(
        [hex_bytes[i : i + 2] for i in range(0, len(hex_bytes), 2)]
    )

    # 7. Generate YARA rule
    file_name = Path(file_path).stem.replace("-", "_").replace(".", "_")

    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule for {file_name}"
        address = "{function_address}"
        byte_length = {byte_length}
        author = "Reversecore_MCP"
        
    strings:
        $code = {{ {formatted_bytes} }}
        
    condition:
        $code
}}"""

    # 8. Return YARA rule
    return success(
        yara_rule,
        bytes_read=bytes_read,
        function_address=function_address,
        rule_name=rule_name,
        byte_length=byte_length,
        format="yara",
        hex_bytes=formatted_bytes,
        description=f"YARA rule '{rule_name}' generated from {byte_length} bytes at {function_address}",
    )


@log_execution(tool_name="analyze_xrefs")
@track_metrics("analyze_xrefs")
@handle_tool_errors
async def analyze_xrefs(
    file_path: str,
    address: str,
    xref_type: str = "all",
    timeout: int = 300,
) -> ToolResult:
    """
    Analyze cross-references (X-Refs) for a function or data address.

    This tool identifies all references TO and FROM a given address, providing
    critical context for understanding code behavior. Essential for malware
    analysis, vulnerability research, and understanding program flow.

    **Why Cross-References Matter:**
    - **Callers**: Who calls this function? (Find entry points to suspicious code)
    - **Callees**: What does this function call? (Understand behavior and APIs used)
    - **Data Refs**: What data does this access? (Find strings, configs, crypto keys)
    - **Context**: Understand the "why" behind code execution

    **Use Cases:**
    - Malware analysis: "Who calls this Connect function?" reveals C2 behavior
    - Password hunting: "What functions reference this 'Password' string?"
    - Vulnerability research: "What uses this vulnerable API?"
    - Game hacking: "Where is Player health accessed from?"

    **AI Collaboration:**
    AI can use xrefs to:
    - Build call graphs automatically
    - Identify code patterns (e.g., "all functions that write files")
    - Focus token budget on relevant functions only
    - Reduce hallucination by providing real relationships

    Args:
        file_path: Path to the binary file (must be in workspace)
        address: Function or data address (e.g., 'main', '0x401000', 'sym.decrypt')
        xref_type: Type of references to analyze:
            - "all" (default): Both callers and callees
            - "to": References TO this address (callers, data reads)
            - "from": References FROM this address (callees, data writes)
        timeout: Execution timeout in seconds (default 300)

    Returns:
        ToolResult with cross-reference information in structured format:
        {
            "address": "0x401000",
            "function_name": "main",
            "xrefs_to": [
                {"from": "0x401234", "type": "call", "function": "entry0"},
                {"from": "0x401567", "type": "call", "function": "init"}
            ],
            "xrefs_from": [
                {"to": "0x401100", "type": "call", "function": "sub_401100"},
                {"to": "0x403000", "type": "data_read", "data": "str.password"}
            ],
            "total_refs_to": 2,
            "total_refs_from": 2
        }

    Example:
        # Find who calls the suspicious 'decrypt' function
        analyze_xrefs("/app/workspace/malware.exe", "sym.decrypt", "to")

        # Find what APIs a malware function uses
        analyze_xrefs("/app/workspace/malware.exe", "0x401000", "from")

        # Get complete relationship map
        analyze_xrefs("/app/workspace/malware.exe", "main", "all")
    """
    from reversecore_mcp.core.result import failure

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    if xref_type not in ["all", "to", "from"]:
        return failure(
            "VALIDATION_ERROR",
            f"Invalid xref_type: {xref_type}",
            hint="Valid options are: 'all', 'to', 'from'",
        )

    # 2. Validate address format
    if not re.match(
        r"^[a-zA-Z0-9_.]+$",
        address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, and prefixes like '0x', 'sym.', 'fcn.'",
        )

    # 3. Build radare2 commands to get xrefs
    # axj = analyze xrefs in JSON format
    commands = []

    if xref_type in ["all", "to"]:
        # axtj = xrefs TO this address (callers)
        commands.append(f"axtj @ {address}")

    if xref_type in ["all", "from"]:
        # axfj = xrefs FROM this address (callees)
        commands.append(f"axfj @ {address}")

    # Build command string
    r2_commands = "; ".join(commands)

    # 4. Execute analysis
    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",  # Analyze all first
        "-c",
        r2_commands,
        str(validated_path),
    ]

    output, bytes_read = await execute_subprocess_async(
        cmd,
        max_output_size=10_000_000,
        timeout=timeout,
    )

    # 5. Parse JSON output
    try:
        # Output may contain multiple JSON arrays if both "to" and "from" were requested
        # Split by lines and parse each JSON array
        lines = [line.strip() for line in output.strip().split("\n") if line.strip()]

        xrefs_to = []
        xrefs_from = []

        for line in lines:
            if line.startswith("["):
                try:
                    refs = json.loads(line)
                    if isinstance(refs, list) and len(refs) > 0:
                        # Determine if this is "to" or "from" based on field names
                        first_ref = refs[0]
                        if "from" in first_ref:
                            # This is xrefs TO (callers)
                            xrefs_to = refs
                        elif "addr" in first_ref or "fcn_addr" in first_ref:
                            # This is xrefs FROM (callees)
                            xrefs_from = refs
                except json.JSONDecodeError:
                    continue

        # 6. Format results
        result = {
            "address": address,
            "xref_type": xref_type,
            "xrefs_to": xrefs_to,
            "xrefs_from": xrefs_from,
            "total_refs_to": len(xrefs_to),
            "total_refs_from": len(xrefs_from),
        }

        # Add human-readable summary
        summary_parts = []
        if xrefs_to:
            summary_parts.append(
                f"{len(xrefs_to)} reference(s) TO this address (callers)"
            )
        if xrefs_from:
            summary_parts.append(
                f"{len(xrefs_from)} reference(s) FROM this address (callees)"
            )

        if not summary_parts:
            summary = "No cross-references found"
        else:
            summary = ", ".join(summary_parts)

        result["summary"] = summary

        # 7. Return structured result
        return success(
            result,
            bytes_read=bytes_read,
            address=address,
            xref_type=xref_type,
            total_refs=len(xrefs_to) + len(xrefs_from),
            description=f"Cross-reference analysis for {address}: {summary}",
        )

    except Exception as e:
        return failure(
            "XREF_ANALYSIS_ERROR",
            f"Failed to parse cross-reference data: {str(e)}",
            hint="The address may not exist or the binary may not have been analyzed. Try running 'afl' first to see available functions.",
        )


@log_execution(tool_name="recover_structures")
@track_metrics("recover_structures")
@handle_tool_errors
async def recover_structures(
    file_path: str,
    function_address: str,
    use_ghidra: bool = True,
    timeout: int = 600,
) -> ToolResult:
    """
    Recover C++ class structures and data types from binary code.

    This is THE game-changer for C++ reverse engineering. Transforms cryptic
    "this + 0x4" memory accesses into meaningful "Player.health" structure fields.
    Uses Ghidra's powerful data type propagation and structure recovery algorithms.

    **Why Structure Recovery Matters:**
    - **C++ Analysis**: 99% of game clients and commercial apps are C++
    - **Understanding**: "this + 0x4" means nothing, "Player.health = 100" tells a story
    - **AI Comprehension**: AI can't understand raw offsets, but understands named fields
    - **Scale**: One structure definition can clarify thousands of lines of code

    **How It Works:**
    1. Analyze memory access patterns in the function
    2. Identify structure layouts from offset usage
    3. Use data type propagation to infer field types
    4. Generate C structure definitions with meaningful names

    **Use Cases:**
    - Game hacking: Recover Player, Entity, Weapon structures
    - Malware analysis: Understand malware configuration structures
    - Vulnerability research: Find buffer overflow candidates in structs
    - Software auditing: Document undocumented data structures

    **AI Collaboration:**
    - AI: "This offset pattern looks like Vector3 (x, y, z)"
    - You: Apply structure definition in Ghidra
    - Result: All "this + 0x0/0x4/0x8" become "vec.x/vec.y/vec.z"

    **Ghidra vs Radare2:**
    - Ghidra (default): Superior type recovery, structure propagation, C++ support
    - Radare2 (fallback): Basic structure definition, faster but less intelligent

    Args:
        file_path: Path to the binary file (must be in workspace)
        function_address: Function to analyze for structure usage (e.g., 'main', '0x401000')
        use_ghidra: Use Ghidra for advanced recovery (default True), or radare2 for basic
        timeout: Execution timeout in seconds (default 600 for Ghidra analysis)

    Returns:
        ToolResult with recovered structures in C format:
        {
            "structures": [
                {
                    "name": "Player",
                    "size": 64,
                    "fields": [
                        {"offset": "0x0", "type": "int", "name": "health"},
                        {"offset": "0x4", "type": "int", "name": "armor"},
                        {"offset": "0x8", "type": "Vector3", "name": "position"}
                    ]
                }
            ],
            "c_definitions": "struct Player { int health; int armor; Vector3 position; };"
        }

    Example:
        # Recover structures used in main function
        recover_structures("/app/workspace/game.exe", "main")

        # Analyze specific class method
        recover_structures("/app/workspace/game.exe", "Player::update")

        # Use radare2 for quick analysis
        recover_structures("/app/workspace/binary", "0x401000", use_ghidra=False)
    """
    from reversecore_mcp.core.result import failure
    from reversecore_mcp.core.ghidra_helper import ensure_ghidra_available

    # 1. Validate parameters
    validated_path = validate_file_path(file_path)

    # 2. Validate address format
    if not re.match(
        r"^[a-zA-Z0-9_.:<>]+$",
        function_address.replace("0x", "").replace("sym.", "").replace("fcn.", ""),
    ):
        return failure(
            "VALIDATION_ERROR",
            "Invalid function address format",
            hint="Address must contain only alphanumeric characters, dots, underscores, colons, angle brackets, and prefixes like '0x', 'sym.'",
        )

    # 3. Check if Ghidra is available when requested
    if use_ghidra:
        if not ensure_ghidra_available():
            return failure(
                "DEPENDENCY_MISSING",
                "Ghidra (PyGhidra) is not available",
                hint="Install with: pip install pyghidra. Alternatively, set use_ghidra=False to use radare2 (basic recovery).",
            )

        # 4a. Use Ghidra for advanced structure recovery
        try:
            from reversecore_mcp.core.ghidra_helper import (
                recover_structures_with_ghidra,
            )

            structures, metadata = recover_structures_with_ghidra(
                validated_path, function_address, timeout
            )

            return success(
                {"structures": structures},
                **metadata,
                function_address=function_address,
                method="ghidra",
                description=f"Structures recovered from {function_address} using Ghidra",
            )

        except Exception as e:
            return failure(
                "STRUCTURE_RECOVERY_ERROR",
                f"Ghidra structure recovery failed: {str(e)}",
                hint="Try with use_ghidra=False for basic radare2 recovery, or verify Ghidra installation.",
            )
    else:
        # 4b. Use radare2 for basic structure recovery
        # radare2's 'afvt' command shows variable types and offsets
        cmd = [
            "r2",
            "-q",
            "-c",
            "aaa",  # Analyze all
            "-c",
            f"s {function_address}",  # Seek to function
            "-c",
            "afvj",  # Get function variables in JSON
            str(validated_path),
        ]

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=10_000_000,
            timeout=timeout,
        )

        # 5. Parse radare2 output
        try:
            variables = json.loads(output) if output.strip() else []

            # Extract structure-like patterns
            # Group variables by their base pointer (e.g., rbp, rsp)
            structures = {}

            for var in variables:
                if isinstance(var, dict):
                    var_type = var.get("type", "unknown")
                    var_name = var.get("name", "unnamed")
                    offset = var.get("delta", 0)

                    # Simple heuristic: group by base register
                    base = (
                        var.get("ref", {}).get("base", "unknown")
                        if "ref" in var
                        else "stack"
                    )

                    if base not in structures:
                        structures[base] = {"name": f"struct_{base}", "fields": []}

                    structures[base]["fields"].append(
                        {
                            "offset": f"0x{abs(offset):x}",
                            "type": var_type,
                            "name": var_name,
                        }
                    )

            # 6. Generate C structure definitions
            c_definitions = []
            for struct_name, struct_data in structures.items():
                fields_str = "\n    ".join(
                    [
                        f"{field['type']} {field['name']}; // offset {field['offset']}"
                        for field in struct_data["fields"]
                    ]
                )

                c_def = f"struct {struct_data['name']} {{\n    {fields_str}\n}};"
                c_definitions.append(c_def)

            result = {
                "structures": list(structures.values()),
                "c_definitions": "\n\n".join(c_definitions),
                "count": len(structures),
            }

            return success(
                result,
                bytes_read=bytes_read,
                function_address=function_address,
                method="radare2",
                structure_count=len(structures),
                description=f"Basic structure recovery from {function_address} using radare2 (found {len(structures)} structure(s))",
            )

        except json.JSONDecodeError as e:
            return failure(
                "STRUCTURE_RECOVERY_ERROR",
                f"Failed to parse structure data: {str(e)}",
                hint="The function may not exist or may not use structures. Verify the address with 'afl' command.",
            )


@log_execution(tool_name="diff_binaries")
@track_metrics("diff_binaries")
@handle_tool_errors
async def diff_binaries(
    file_path_a: str,
    file_path_b: str,
    function_name: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """
    Compare two binary files to identify code changes and modifications.

    This tool uses radiff2 to perform binary diffing, which is essential for:
    - **Patch Analysis (1-day Exploits)**: Compare pre-patch and post-patch binaries
      to identify security vulnerabilities fixed in updates
    - **Game Hacking**: Find offset changes after game updates to maintain functionality
    - **Malware Variant Analysis**: Identify code differences between malware variants
      (e.g., "90% similar to Lazarus malware, but C2 address generation changed")

    The tool provides:
    - Similarity score (0.0-1.0) between binaries
    - List of code changes with addresses and descriptions
    - Optional function-level comparison for targeted analysis

    Args:
        file_path_a: Path to the first binary file (e.g., pre-patch version)
        file_path_b: Path to the second binary file (e.g., post-patch version)
        function_name: Optional function name to compare (e.g., "main", "sym.decrypt").
                      If None, performs whole-binary comparison.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - similarity: Float between 0.0 and 1.0 indicating code similarity
        - changes: List of detected changes with addresses and descriptions
        - function_specific: Boolean indicating if function-level diff was performed

    Example:
        # Compare two versions of a patched binary
        diff_binaries("/app/workspace/app_v1.0.exe", "/app/workspace/app_v1.1.exe")

        # Compare specific function between versions
        diff_binaries("/app/workspace/malware_old.exe", "/app/workspace/malware_new.exe", "main")

    Output Format:
        {
          "similarity": 0.95,
          "function_specific": false,
          "changes": [
            {
              "address": "0x401050",
              "type": "code_change",
              "description": "Instruction changed from JNZ to JZ"
            },
            {
              "address": "0x401080",
              "type": "new_block",
              "description": "Added security check"
            }
          ],
          "total_changes": 2
        }
    """
    from reversecore_mcp.core.result import failure

    # Validate both file paths
    validated_path_a = validate_file_path(file_path_a)
    validated_path_b = validate_file_path(file_path_b)

    # Validate tool parameters
    validate_tool_parameters(
        "diff_binaries",
        {
            "function_name": function_name,
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Build radiff2 command
        # -s: similarity score
        # -C: code comparison
        # -g: graph diff (if function specified)

        if function_name:
            # Function-specific comparison using graph diff
            cmd = [
                "radiff2",
                "-g",
                function_name,
                str(validated_path_a),
                str(validated_path_b),
            ]
        else:
            # Whole-binary comparison with similarity scoring
            cmd = [
                "radiff2",
                "-C",
                str(validated_path_a),
                str(validated_path_b),
            ]

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=max_output_size,
            timeout=timeout,
        )

        # Also get similarity score separately
        similarity_cmd = ["radiff2", "-s", str(validated_path_a), str(validated_path_b)]
        similarity_output, _ = await execute_subprocess_async(
            similarity_cmd,
            max_output_size=1_000_000,
            timeout=60,
        )

        # Parse similarity score (format: "similarity: 0.95")
        similarity = 0.0
        similarity_match = re.search(r"similarity:\s*(\d+\.?\d*)", similarity_output)
        if similarity_match:
            similarity = float(similarity_match.group(1))

        # Parse changes from output
        changes = []

        # Parse the diff output to extract meaningful changes
        # radiff2 output varies, so we'll capture the raw output and structure it
        lines = output.strip().split("\n")

        for line in lines:
            if not line.strip():
                continue

            # Look for common patterns in radiff2 output
            # Address patterns: 0x... or addresses
            addr_match = re.search(r"(0x[0-9a-fA-F]+)", line)

            if addr_match:
                address = addr_match.group(1)

                # Determine change type based on line content
                change_type = "unknown"
                description = line.strip()

                if "new" in line.lower():
                    change_type = "new_block"
                elif "removed" in line.lower() or "deleted" in line.lower():
                    change_type = "removed_block"
                elif "modified" in line.lower() or "changed" in line.lower():
                    change_type = "code_change"
                elif (
                    "jmp" in line.lower()
                    or "call" in line.lower()
                    or "jnz" in line.lower()
                ):
                    change_type = "control_flow_change"

                changes.append(
                    {
                        "address": address,
                        "type": change_type,
                        "description": description,
                    }
                )

        # If no structured changes found, include summary info
        if not changes and output.strip():
            changes.append(
                {
                    "type": "summary",
                    "description": "Binary comparison completed. See raw output for details.",
                }
            )

        # Build result
        result_data = {
            "similarity": similarity,
            "function_specific": bool(function_name),
            "changes": changes,
            "total_changes": len(changes),
            "raw_output": (
                output if len(output) < 5000 else output[:5000] + "... (truncated)"
            ),
        }

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            similarity=similarity,
            total_changes=len(changes),
            function_specific=bool(function_name),
        )

    except Exception as e:
        return failure(
            "DIFF_ERROR",
            f"Binary diff failed: {str(e)}",
            hint="Ensure both files are valid binaries and radiff2 is available. For function-level diff, verify function name exists in both binaries.",
        )


@log_execution(tool_name="match_libraries")
@track_metrics("match_libraries")
@handle_tool_errors
async def match_libraries(
    file_path: str,
    signature_db: str = None,
    max_output_size: int = 10_000_000,
    timeout: int = 300,
) -> ToolResult:
    """
    Match and filter known library functions to focus on user code.

    This tool uses radare2's zignatures (FLIRT-compatible signature matching) to:
    - **Reduce Analysis Noise**: Skip analysis of known library functions (strcpy, malloc, etc.)
    - **Focus on User Code**: Identify which functions are original vs library code
    - **Save Time & Tokens**: Reduce analysis scope by 80% by filtering out standard libraries
    - **Improve Accuracy**: Focus AI analysis on the actual malicious/interesting code

    Common use cases:
    - Analyzing large binaries (>25MB) where most code is OpenSSL, zlib, MFC, etc.
    - Game client reverse engineering (filter out Unreal Engine / Unity standard library)
    - Malware analysis (focus on custom malware code, skip Windows API wrappers)

    The tool automatically uses built-in signature databases for common libraries
    and can optionally use custom signature databases for specialized analysis.

    Args:
        file_path: Path to the binary file to analyze
        signature_db: Optional path to custom signature database file (.sig format).
                     If None, uses radare2's built-in signature databases.
        max_output_size: Maximum output size in bytes (default: 10MB)
        timeout: Timeout in seconds (default: 300s)

    Returns:
        ToolResult with structured JSON containing:
        - total_functions: Total number of functions found
        - library_functions: Number of matched library functions
        - user_functions: Number of unmatched (user) functions to analyze
        - library_matches: List of matched library functions with details
        - user_function_list: List of user function addresses/names for further analysis
        - noise_reduction_percentage: Percentage of functions filtered out

    Example:
        # Auto-detect standard libraries
        match_libraries("/app/workspace/large_app.exe")

        # Use custom signature database
        match_libraries("/app/workspace/game.exe", "/app/rules/game_engine.sig")

    Output Format:
        {
          "total_functions": 1250,
          "library_functions": 1000,
          "user_functions": 250,
          "noise_reduction_percentage": 80.0,
          "library_matches": [
            {
              "address": "0x401000",
              "name": "strcpy",
              "library": "msvcrt"
            },
            {
              "address": "0x401050",
              "name": "malloc",
              "library": "msvcrt"
            }
          ],
          "user_function_list": [
            "0x402000",
            "0x402100",
            "sym.custom_decrypt"
          ]
        }
    """
    from reversecore_mcp.core.result import failure

    # Validate file path
    validated_path = validate_file_path(file_path)

    # Validate optional signature database path
    if signature_db:
        validated_sig_path = validate_file_path(signature_db)

    # Validate tool parameters
    validate_tool_parameters(
        "match_libraries",
        {
            "max_output_size": max_output_size,
            "timeout": timeout,
        },
    )

    try:
        # Step 1: Load binary and analyze
        # Use radare2 to get function list with signature matching

        # Build command to apply signatures and get function list
        if signature_db:
            # Load custom signature database
            r2_commands = f"aaa; zg {validated_sig_path}; aflj"
        else:
            # Use built-in signatures
            r2_commands = "aaa; zg; aflj"

        cmd = [
            "r2",
            "-q",
            "-c",
            r2_commands,
            str(validated_path),
        ]

        output, bytes_read = await execute_subprocess_async(
            cmd,
            max_output_size=max_output_size,
            timeout=timeout,
        )

        # Parse JSON output from aflj (function list JSON)
        try:
            functions = json.loads(output)
        except json.JSONDecodeError:
            # If JSON parsing fails, fall back to text parsing
            return failure(
                "PARSE_ERROR",
                "Failed to parse function list from radare2",
                hint="The binary may not be analyzable or may be packed/obfuscated. Try running 'aaa' analysis first.",
            )

        # Categorize functions into library vs user code
        library_functions = []
        user_functions = []

        for func in functions:
            name = func.get("name", "")
            offset = func.get("offset", 0)

            # Heuristic: library functions typically have names like:
            # - sym.imp.* (imports)
            # - sym.std::* (C++ standard library)
            # - Known library prefixes
            is_library = (
                name.startswith("sym.imp.")
                or name.startswith("sym.std::")
                or name.startswith("fcn.imp.")
                or "libc" in name.lower()
                or "msvcrt" in name.lower()
                or "kernel32" in name.lower()
            )

            if is_library:
                library_functions.append(
                    {
                        "address": f"0x{offset:x}",
                        "name": name,
                        "library": _extract_library_name(name),
                    }
                )
            else:
                user_functions.append({"address": f"0x{offset:x}", "name": name})

        total_functions = len(functions)
        library_count = len(library_functions)
        user_count = len(user_functions)

        # Calculate noise reduction percentage
        noise_reduction = (
            (library_count / total_functions * 100) if total_functions > 0 else 0.0
        )

        # Build result
        result_data = {
            "total_functions": total_functions,
            "library_functions": library_count,
            "user_functions": user_count,
            "noise_reduction_percentage": round(noise_reduction, 2),
            "library_matches": library_functions[
                :50
            ],  # Limit to first 50 for readability
            "user_function_list": [
                f["address"] for f in user_functions[:100]
            ],  # First 100 user functions
            "summary": f"Filtered out {library_count} library functions ({noise_reduction:.1f}% noise reduction). Focus analysis on {user_count} user functions.",
            "signature_db_used": signature_db if signature_db else "built-in",
        }

        return success(
            json.dumps(result_data, indent=2),
            bytes_read=bytes_read,
            total_functions=total_functions,
            library_functions=library_count,
            user_functions=user_count,
            noise_reduction=round(noise_reduction, 2),
        )

    except Exception as e:
        return failure(
            "LIBRARY_MATCH_ERROR",
            f"Library signature matching failed: {str(e)}",
            hint="Ensure the binary is valid and radare2 signature databases are available. For custom databases, verify the .sig file format.",
        )


def _extract_library_name(function_name: str) -> str:
    """
    Extract library name from function name.

    Args:
        function_name: Function name (e.g., "sym.imp.strcpy")

    Returns:
        Extracted library name or "unknown"
    """
    # Simple heuristic extraction
    if "kernel32" in function_name.lower():
        return "kernel32"
    elif "msvcrt" in function_name.lower() or "libc" in function_name.lower():
        return "libc/msvcrt"
    elif "std::" in function_name:
        return "libstdc++"
    elif "imp." in function_name:
        return "import"
    else:
        return "unknown"
