"""
Ghost Trace: Hybrid Reverse Engineering Tool.

This tool combines static analysis and partial emulation to detect hidden malicious behaviors
(Logic Bombs, Dormant Malware) that are often missed by traditional dynamic analysis.
"""

import asyncio
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

from fastmcp import FastMCP, Context
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.security import validate_file_path
from reversecore_mcp.core.command_spec import validate_r2_command
from reversecore_mcp.core import json_utils as json  # Use optimized JSON (3-5x faster)

logger = get_logger(__name__)


def _extract_json_safely(output: str) -> Optional[Any]:
    """Extract JSON from radare2 output with multiple fallback strategies."""
    if not output or not output.strip():
        return None
    
    # Strategy 1: Try to find JSON array/object with proper nesting
    json_patterns = [
        (r'\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]', 'array'),  # Nested arrays
        (r'\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}', 'object'),  # Nested objects
    ]
    
    for pattern, pattern_type in json_patterns:
        matches = re.findall(pattern, output, re.DOTALL)
        # Try from last to first (radare2 usually puts command output at the end)
        for match in reversed(matches):
            try:
                parsed = json.loads(match)
                logger.debug(f"Successfully parsed {pattern_type} JSON")
                return parsed
            except json.JSONDecodeError:
                continue
    
    # Strategy 2: Try line-by-line from the end
    lines = output.strip().split('\n')
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        # Check if line looks like JSON
        if (line.startswith('[') and line.endswith(']')) or \
           (line.startswith('{') and line.endswith('}')):
            try:
                parsed = json.loads(line)
                logger.debug("Successfully parsed single-line JSON")
                return parsed
            except json.JSONDecodeError:
                continue
    
    logger.warning("Failed to extract valid JSON from radare2 output")
    return None


def _validate_r2_identifier(identifier: str) -> str:
    """Validate and sanitize radare2 function/address identifier."""
    # Allow: hex addresses (0x...), symbols (sym.*), function names
    valid_patterns = [
        r'^0x[0-9a-fA-F]+$',  # Hex address
        r'^sym\.[a-zA-Z0-9_\.]+$',  # Symbol
        r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # Simple function name
    ]
    
    for pattern in valid_patterns:
        if re.match(pattern, identifier):
            return identifier
    
    raise ValidationError(
        f"Invalid radare2 identifier: '{identifier}'. "
        "Must be hex address (0x...) or valid symbol name."
    )


def register_ghost_trace(mcp: FastMCP) -> None:
    """Register the Ghost Trace tool with the FastMCP server."""
    mcp.tool(ghost_trace)


async def _run_r2_cmd(file_path: str, cmd: str, timeout: int = 30) -> str:
    """Helper to run a single radare2 command."""
    # Use -q for quiet mode, -n for no analysis (we'll do it manually if needed)
    # But for some commands we need analysis. We'll assume the caller handles 'aaa' if needed
    # or we use a persistent session (not supported here yet, so we use one-shot)
    # Actually, for 'afl' we need analysis.
    # We will use 'radare2 -A' (analyze all) or just run 'aaa' in the command chain.
    
    full_cmd = ["radare2", "-q", "-c", cmd, str(file_path)]
    output, _ = await execute_subprocess_async(full_cmd, timeout=timeout)
    return output


@log_execution(tool_name="ghost_trace")
async def ghost_trace(
    file_path: str,
    focus_function: Optional[str] = None,
    hypothesis: Optional[Dict[str, Any]] = None,
    timeout: int = 300,
    ctx: Context = None,
) -> ToolResult:
    """
    Detect hidden malicious behaviors using "Ghost Trace" (Static + Emulation).

    This tool performs a hybrid analysis:
    1. **Scan**: Finds "Orphan Functions" (not called by main) and "Suspicious Logic" (magic value checks).
    2. **Hypothesize**: (Optional) If `hypothesis` is provided, it sets up emulation conditions.
    3. **Emulate**: (Optional) If `focus_function` is provided, it emulates that specific function
       to verify the hypothesis (e.g., "If register eax=0x1234, does it call system()?").

    Args:
        file_path: Path to the binary.
        focus_function: (Optional) Name or address of a specific function to emulate.
        hypothesis: (Optional) Dictionary defining emulation parameters:
                    {
                        "registers": {"eax": "0x1234", "zf": "1"},
                        "args": ["arg1", "arg2"],
                        "max_steps": 100
                    }
        timeout: Execution timeout.

    Returns:
        ToolResult containing suspicious candidates or emulation results.
    """
    validated_path = validate_file_path(file_path)
    
    # 1. If focus_function is provided, run emulation (Verification Phase)
    if focus_function and hypothesis:
        if ctx:
            await ctx.info(f"👻 Ghost Trace: Emulating {focus_function} with hypothesis...")
        return await _verify_hypothesis_with_emulation(
            validated_path, focus_function, hypothesis, timeout
        )

    # 2. Otherwise, run full scan (Discovery Phase)
    if ctx:
        await ctx.info("👻 Ghost Trace: Scanning for suspicious logic...")
    
    # Run analysis
    # We chain commands: aaa (analyze), aflj (list functions json), axj (xrefs json)
    # Note: 'aaa' can be slow.
    cmd = "aaa; aflj"
    output = await _run_r2_cmd(validated_path, cmd, timeout=timeout)
    
    # Parse functions with safe JSON extraction
    functions = _extract_json_safely(output)
    if not functions or not isinstance(functions, list):
        logger.error(f"Invalid function list format. Output preview: {output[:200]}...")
        return failure(
            f"Failed to parse function list from radare2. "
            f"Output may be corrupted or analysis failed."
        )

    # Find orphans and suspicious logic
    orphans = []
    suspicious_logic = []
    
    # We need xrefs to find orphans. 'aflj' doesn't give xrefs count reliably in all versions.
    # We'll do a quick pass.
    # Actually, 'aflj' has 'noreturn', 'stack', etc.
    # Let's use a heuristic: if name is not 'main' and not 'entry' and not exported,
    # and we can't easily see xrefs (we'd need 'ax' for all, which is slow).
    
    # Better approach for orphans:
    # 1. Get all functions.
    # 2. Get entry points (ie).
    # 3. For a subset of "interesting" functions (large size, specific strings), check xrefs.
    
    # For this MVP, let's focus on "Suspicious Logic" (Magic Values) in ALL functions.
    # We'll search for 'cmp' instructions with immediate values.
    
    # Search for magic value checks: '/m' command in r2 finds "magic" signatures, but we want code logic.
    # We'll search for instructions like 'cmp reg, 0x...'
    # cmd: "aaa; /aj cmp,0x" (search for 'cmp' instructions with '0x' operand)
    # This is a bit raw.
    
    # Let's implement `find_orphan_functions` and `identify_conditional_paths` properly.
    
    if ctx:
        await ctx.report_progress(30, 100)
        await ctx.info("👻 Ghost Trace: Identifying orphan functions...")

    orphans = await _find_orphan_functions(validated_path, functions)

    if ctx:
        await ctx.report_progress(60, 100)
        await ctx.info("👻 Ghost Trace: Analyzing conditional logic...")

    suspicious_logic = await _identify_conditional_paths(validated_path, functions[:20], ctx) # Limit to top 20 for speed in MVP
    
    if ctx:
        await ctx.report_progress(100, 100)

    return success({
        "scan_type": "discovery",
        "orphan_functions": orphans,
        "suspicious_logic": suspicious_logic,
        "description": "Found potential logic bombs. Use 'focus_function' and 'hypothesis' to verify."
    })


async def _find_orphan_functions(file_path: Path, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify functions with no direct XREFs (potential dead code/backdoors)."""
    orphans = []
    # Heuristic: Check if 'nrefs' (number of references) is 0
    # Note: 'aflj' output usually contains 'nrefs' or 'refs'.
    
    for func in functions:
        name = func.get("name", "")
        if name.startswith("sym.imp"): # Skip imports
            continue
        if "main" in name or "entry" in name:
            continue
            
        # Check refs
        # Some r2 versions use 'codexrefs', some 'refs'.
        refs = func.get("codexrefs", [])
        if not refs and func.get("size", 0) > 50: # Only care about non-trivial functions
            orphans.append({
                "name": name,
                "address": hex(func.get("offset", 0)),
                "size": func.get("size"),
                "reason": "No code cross-references found (potential dormant code)"
            })
            
    return orphans


async def _identify_conditional_paths(file_path: Path, functions: List[Dict[str, Any]], ctx: Context = None) -> List[Dict[str, Any]]:
    """Identify functions with suspicious conditional logic (Magic Values)."""
    suspicious = []
    
    # Batch process functions for better performance
    # Build a single command chain to analyze multiple functions
    batch_size = 10
    total_functions = len(functions)
    for i in range(0, total_functions, batch_size):
        if ctx:
             await ctx.report_progress(60 + int((i / total_functions) * 30), 100)

        batch = functions[i:i + batch_size]
        
        # Create batch command
        cmds = []
        for func in batch:
            addr = func.get("offset")
            if addr:
                cmds.append(f"pdfj @ {addr}")
        
        if not cmds:
            continue
            
        # Execute batch command
        batch_cmd = "; ".join(cmds)
        try:
            out = await _run_r2_cmd(file_path, batch_cmd, timeout=60)
            
            # Parse each function's output
            # Note: with multiple pdfj, output contains multiple JSON objects
            # We need to split them carefully
            json_outputs = re.findall(r'\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}', out, re.DOTALL)
            
            for func, json_str in zip(batch, json_outputs):
                try:
                    func_data = json.loads(json_str)
                    ops = func_data.get("ops", [])
                    name = func.get("name")
                    
                    for op in ops:
                        disasm = op.get("disasm", "")
                        # Heuristic: cmp [reg], 0x[large_value]
                        if "cmp" in disasm and "0x" in disasm:
                            # Check if value is "magic" (not small loop counter)
                            # Simple check: length of hex string > 4 (e.g. 0x12)
                            args = disasm.split(",")
                            if len(args) > 1:
                                val = args[1].strip()
                                if val.startswith("0x") and len(val) > 4:
                                    suspicious.append({
                                        "function": name,
                                        "address": hex(op.get("offset", 0)),
                                        "instruction": disasm,
                                        "reason": "Magic value comparison detected (potential logic bomb trigger)"
                                    })
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse function disassembly: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Failed to analyze batch: {e}")
            continue
            
    return suspicious


async def _verify_hypothesis_with_emulation(
    file_path: Path,
    function_name: str,
    hypothesis: Dict[str, Any],
    timeout: int
) -> ToolResult:
    """
    Verify a hypothesis using partial emulation (ESIL).
    
    Hypothesis format:
    {
        "registers": {"eax": "0xCAFEBABE"},
        "max_steps": 100
    }
    """
    # Validate function name to prevent command injection
    try:
        validated_func = _validate_r2_identifier(function_name)
    except ValidationError as e:
        return failure(str(e))
    
    # Construct ESIL script
    # 1. Initialize ESIL (aei)
    # 2. Initialize Stack (aeim)
    # 3. Seek to function (s <func>)
    # 4. Set registers (aer <reg>=<val>)
    # 5. Step (aes) and trace
    
    regs = hypothesis.get("registers", {})
    max_steps = min(hypothesis.get("max_steps", 50), 1000)  # Cap at 1000 for safety
    
    cmds = [
        "aaa", # Analyze
        "aei", # Init ESIL
        "aeim", # Init Stack
        f"s {validated_func}", # Seek to function (validated)
    ]
    
    # Set registers (validate register names and values)
    for reg, val in regs.items():
        # Basic validation: register names should be alphanumeric
        if not re.match(r'^[a-z0-9]+$', reg.lower()):
            logger.warning(f"Skipping invalid register name: {reg}")
            continue
        # Validate value format (hex or decimal)
        if not re.match(r'^(0x[0-9a-fA-F]+|\d+)$', str(val)):
            logger.warning(f"Skipping invalid register value: {val}")
            continue
        cmds.append(f"aer {reg}={val}")
        
    # Step and record
    # We'll use a loop in r2 or just run 'aes' N times and print registers
    # 'aes <steps>' runs N steps.
    # We want to see if it reaches a certain state or calls a function.
    # For this MVP, we'll run steps and return the final register state and visited addresses.
    
    # Run N steps and print disassembly of current instruction
    # 'aes <max_steps>; aerj' (run steps, then print registers json)
    cmds.append(f"aes {max_steps}")
    cmds.append("aerj") # Get registers
    
    full_cmd = "; ".join(cmds)
    output = await _run_r2_cmd(file_path, full_cmd, timeout=timeout)
    
    # Parse result (last json is registers) with safe extraction
    final_regs = _extract_json_safely(output)
    
    if final_regs is None:
        logger.error(f"Failed to parse emulation results. Output: {output[:500]}")
        return failure(
            "Emulation completed but failed to parse register state. "
            "The function may have crashed or radare2 output was corrupted."
        )
    
    return success({
        "status": "emulation_complete",
        "steps_executed": max_steps,
        "final_registers": final_regs,
        "hypothesis_verification": "Check final_registers to see if expected state was reached.",
        "raw_output_preview": output[:200] + "..." if len(output) > 200 else output
    })
