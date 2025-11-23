"""
Adaptive Vaccine: Automated Defense Generation Tool.

This tool generates defensive measures against detected threats:
1. YARA rule generation from threat patterns
2. Binary patching (NOP injection, JMP override)
3. Safety checks and backups
"""

import re
import shutil
import lief
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

from fastmcp import FastMCP, Context
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.result import ToolResult, success, failure
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)


def register_adaptive_vaccine(mcp: FastMCP) -> None:
    """Register the Adaptive Vaccine tool with the FastMCP server."""
    mcp.tool(adaptive_vaccine)


@log_execution(tool_name="adaptive_vaccine")
async def adaptive_vaccine(
    threat_report: Dict[str, Any],
    action: str = "yara",
    file_path: Optional[str] = None,
    dry_run: bool = True,
    ctx: Context = None,
) -> ToolResult:
    """
    Generate automated defenses against detected threats.

    Actions:
    - "yara": Generate YARA detection rule
    - "patch": Generate binary patch (requires file_path)
    - "both": Generate both YARA rule and patch

    Args:
        threat_report: Threat information from Ghost Trace or Trinity Defense
                      Format: {
                          "function": "func_name",
                          "address": "0x401000",
                          "instruction": "cmp eax, 0xDEADBEEF",
                          "reason": "Magic value detected",
                          "refined_code": "if (magic_val == 0xDEADBEEF) ..." (optional)
                      }
        action: Type of defense to generate
        file_path: Path to binary (required for "patch" action)
        dry_run: If True, only preview patch without applying

    Returns:
        ToolResult containing generated defenses
    """
    if ctx:
        await ctx.info(f"🛡️ Adaptive Vaccine: Generating {action} defense...")

    result = {"action": action, "dry_run": dry_run}

    # Detect architecture if file_path provided
    arch = "x86"  # default
    if file_path:
        try:
            validated_path = validate_file_path(file_path)
            arch = _detect_architecture(validated_path)
        except:
            pass  # Use default if detection fails
    
    # Generate YARA rule
    if action in ["yara", "both"]:
        yara_rule = _generate_yara_rule(threat_report, arch)
        result["yara_rule"] = yara_rule
        result["architecture"] = arch
        if ctx:
            await ctx.info(f"✅ YARA rule generated (arch: {arch})")

    # Generate binary patch
    if action in ["patch", "both"]:
        if not file_path:
            return failure("file_path is required for patch action")

        validated_path = validate_file_path(file_path)
        
        try:
            patch_info = _create_binary_patch(
                validated_path,
                threat_report,
                dry_run=dry_run
            )
            result["patch"] = patch_info
            
            if ctx:
                if dry_run:
                    await ctx.info("✅ Patch preview generated (dry-run, not applied)")
                else:
                    await ctx.info("✅ Patch applied successfully")
        except Exception as e:
            return failure(f"Patch generation failed: {e}")

    return success(result)


def _detect_architecture(file_path: Path) -> str:
    """Detect binary architecture using LIEF."""
    try:
        binary = lief.parse(str(file_path))
        if binary is None:
            return "unknown"
        
        # Detect architecture from binary type
        if isinstance(binary, lief.PE.Binary):
            machine = binary.header.machine
            if machine == lief.PE.MACHINE_TYPES.I386:
                return "x86"
            elif machine == lief.PE.MACHINE_TYPES.AMD64:
                return "x86_64"
            elif machine == lief.PE.MACHINE_TYPES.ARM:
                return "arm"
        elif isinstance(binary, lief.ELF.Binary):
            arch = binary.header.machine_type
            if arch == lief.ELF.ARCH.i386:
                return "x86"
            elif arch == lief.ELF.ARCH.x86_64:
                return "x86_64"
            elif arch == lief.ELF.ARCH.ARM:
                return "arm"
        
        return "unknown"
    except Exception as e:
        logger.warning(f"Failed to detect architecture: {e}")
        return "unknown"


def _hex_to_yara_bytes(hex_val: str, arch: str = "x86") -> str:
    """Convert hex value to YARA byte pattern with proper endianness."""
    # Pad to even length
    if len(hex_val) % 2 != 0:
        hex_val = '0' + hex_val
    
    try:
        # Convert to bytes
        byte_array = bytes.fromhex(hex_val)
        
        # Reverse if little-endian architecture
        if arch in ["x86", "x86_64"]:
            byte_array = byte_array[::-1]
        
        return ' '.join(f'{b:02x}' for b in byte_array)
    except ValueError:
        # If conversion fails, return as-is
        return hex_val


def _generate_yara_rule(threat_report: Dict[str, Any], arch: str = "x86") -> str:
    """
    Generate YARA rule from threat information.
    
    Args:
        threat_report: Threat information including instruction, reason, etc.
        arch: Target architecture for endianness handling
    
    Returns:
        YARA rule as string
    """
    function_name = threat_report.get("function", "unknown")
    address = threat_report.get("address", "0x0")
    instruction = threat_report.get("instruction", "")
    reason = threat_report.get("reason", "Suspicious behavior detected")
    
    # Sanitize rule name (alphanumeric only)
    rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', function_name)
    if not rule_name or rule_name[0].isdigit():
        rule_name = f"Threat_{address.replace('0x', '')}"
    
    # Extract hex patterns from instruction
    hex_patterns = re.findall(r'0x([0-9a-fA-F]+)', instruction)
    
    # Build strings section with proper endianness
    strings_section = []
    for i, hex_val in enumerate(hex_patterns[:5]):  # Limit to 5 patterns
        byte_str = _hex_to_yara_bytes(hex_val, arch)
        strings_section.append(f'        $hex_{i} = {{ {byte_str} }}')
    
    # Extract string literals if present in refined code
    refined_code = threat_report.get("refined_code", "")
    string_literals = re.findall(r'"([^"]+)"', refined_code)
    for i, literal in enumerate(string_literals[:3]):  # Limit to 3 strings
        strings_section.append(f'        $str_{i} = "{literal}" ascii')
    
    # Build condition
    if strings_section:
        condition = " or ".join([s.split(" = ")[0].strip() for s in strings_section])
    else:
        condition = "true  // Manual review required"
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Build YARA rule
    yara_rule = f"""rule {rule_name} {{
    meta:
        description = "{reason}"
        address = "{address}"
        architecture = "{arch}"
        generated = "{timestamp}"
        source = "Reversecore TDS - Adaptive Vaccine"
        
    strings:
{chr(10).join(strings_section) if strings_section else '        // No patterns extracted'}
        
    condition:
        {condition}
}}"""
    
    return yara_rule


def _va_to_file_offset(file_path: Path, va: int) -> Tuple[int, str]:
    """Convert virtual address to file offset using LIEF.
    
    Args:
        file_path: Path to binary
        va: Virtual address
    
    Returns:
        Tuple of (file_offset, section_name)
    """
    try:
        binary = lief.parse(str(file_path))
        if binary is None:
            raise ValueError("Failed to parse binary with LIEF")
        
        # Handle PE format
        if isinstance(binary, lief.PE.Binary):
            for section in binary.sections:
                va_start = section.virtual_address + binary.optional_header.imagebase
                va_end = va_start + section.virtual_size
                if va_start <= va < va_end:
                    offset = va - va_start + section.offset
                    return offset, section.name
        
        # Handle ELF format
        elif isinstance(binary, lief.ELF.Binary):
            for segment in binary.segments:
                va_start = segment.virtual_address
                va_end = va_start + segment.virtual_size
                if va_start <= va < va_end:
                    offset = va - va_start + segment.file_offset
                    # Find section name
                    section_name = "unknown"
                    for section in binary.sections:
                        if section.virtual_address <= va < section.virtual_address + section.size:
                            section_name = section.name
                            break
                    return offset, section_name
        
        raise ValueError(f"VA {hex(va)} not found in any section")
    
    except Exception as e:
        logger.error(f"VA to offset conversion failed: {e}")
        raise


def _create_binary_patch(
    file_path: Path,
    threat_report: Dict[str, Any],
    dry_run: bool = True
) -> Dict[str, Any]:
    """
    Create binary patch to neutralize threat.
    
    Args:
        file_path: Path to binary file
        threat_report: Threat information
        dry_run: If True, only preview without applying
    
    Returns:
        Dictionary with patch information
    """
    address_str = threat_report.get("address", "0x0")
    
    try:
        # Parse virtual address
        if address_str.startswith("0x"):
            va = int(address_str, 16)
        else:
            va = int(address_str)
    except ValueError:
        raise ValueError(f"Invalid address format: {address_str}")
    
    # Convert VA to file offset
    try:
        file_offset, section_name = _va_to_file_offset(file_path, va)
        logger.info(f"Converted VA {address_str} to file offset {hex(file_offset)} (section: {section_name})")
    except Exception as e:
        raise ValueError(f"Failed to convert VA to file offset: {e}")
    
    # Determine patch type based on instruction
    instruction = threat_report.get("instruction", "").lower()
    
    if "cmp" in instruction or "test" in instruction:
        # For comparisons, NOP them out
        patch_type = "NOP"
        patch_bytes = b'\x90' * 6  # 6-byte NOP (typical cmp instruction length)
        description = "Replace comparison with NOPs"
    elif "jne" in instruction or "je" in instruction or "jz" in instruction:
        # For conditional jumps, convert to unconditional JMP or NOP
        patch_type = "NOP_JUMP"
        patch_bytes = b'\x90' * 2  # 2-byte NOP (typical short jump length)
        description = "Neutralize conditional jump"
    else:
        # Generic NOP patch
        patch_type = "NOP"
        patch_bytes = b'\x90' * 4
        description = "Generic NOP patch"
    
    patch_info = {
        "type": patch_type,
        "virtual_address": address_str,
        "file_offset": hex(file_offset),
        "section": section_name,
        "bytes": patch_bytes.hex(),
        "length": len(patch_bytes),
        "description": description,
        "applied": False
    }
    
    if not dry_run:
        # Create backup
        backup_path = file_path.with_suffix(file_path.suffix + '.backup')
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
        
        # Apply patch using file offset (not VA!)
        try:
            with open(file_path, 'r+b') as f:
                f.seek(file_offset)  # Use file offset, not VA
                f.write(patch_bytes)
            
            patch_info["applied"] = True
            patch_info["backup"] = str(backup_path)
            logger.info(f"Applied patch at file offset {hex(file_offset)} (VA: {address_str})")
        except Exception as e:
            # Restore from backup
            shutil.copy2(backup_path, file_path)
            raise RuntimeError(f"Patch failed, restored from backup: {e}")
    
    return patch_info
