"""
Command specification and validation with regex patterns.

This module provides strict command validation using regular expressions
to prevent command injection attacks. It addresses the vulnerability where
commands like "pdf @ main; w hello" could bypass simple prefix matching.
"""

import re
from dataclasses import dataclass
from typing import Literal, List, NewType
from reversecore_mcp.core.exceptions import ValidationError


CommandType = Literal["read", "write", "analyze", "system"]
ValidatedR2Command = NewType("ValidatedR2Command", str)


@dataclass
class CommandSpec:
    """
    Specification for a command with strict regex validation.

    Attributes:
        name: Human-readable command name
        type: Command type (read, write, analyze, system)
        regex: Compiled regex pattern for strict validation
        description: Optional description of what the command does
    """

    name: str
    type: CommandType
    regex: re.Pattern
    description: str = ""

    def validate(self, cmd: str) -> bool:
        """
        Validate a command string against this spec's regex.

        Args:
            cmd: Command string to validate

        Returns:
            True if command matches, False otherwise
        """
        return self.regex.match(cmd.strip()) is not None


# Radare2 command specifications with strict regex patterns
R2_COMMAND_SPECS: List[CommandSpec] = [
    # Disassembly commands
    CommandSpec(
        name="pdf",
        type="read",
        regex=re.compile(r"^pdf(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print disassembly function",
    ),
    CommandSpec(
        name="pd",
        type="read",
        regex=re.compile(r"^pd(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print disassembly",
    ),
    CommandSpec(
        name="pdfj",
        type="read",
        regex=re.compile(r"^pdfj(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print disassembly function (JSON)",
    ),
    CommandSpec(
        name="pdj",
        type="read",
        regex=re.compile(r"^pdj(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print disassembly (JSON)",
    ),
    CommandSpec(
        name="pdc",
        type="read",
        regex=re.compile(r"^pdc(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print C-like pseudo code",
    ),
    # Analysis commands
    CommandSpec(
        name="aaa",
        type="analyze",
        regex=re.compile(r"^aaa$"),
        description="Analyze all referenced code",
    ),
    CommandSpec(
        name="aa",
        type="analyze",
        regex=re.compile(r"^aa[a]?$"),
        description="Analyze all",
    ),
    CommandSpec(
        name="afl",
        type="read",
        regex=re.compile(r"^afl[j]?(\s*~.+)?$"),
        description="Analyze functions list",
    ),
    CommandSpec(
        name="aflj",
        type="read",
        regex=re.compile(r"^aflj(\s*~.+)?$"),
        description="Analyze functions list (JSON)",
    ),
    CommandSpec(
        name="af",
        type="analyze",
        regex=re.compile(r"^af(\s+@\s+[a-zA-Z0-9_.]+)?$"),
        description="Analyze function",
    ),
    CommandSpec(
        name="afi",
        type="read",
        regex=re.compile(r"^afi(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Analyze function info",
    ),
    CommandSpec(
        name="afv",
        type="read",
        regex=re.compile(r"^afv[j]?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Analyze function variables",
    ),
    # Graph commands
    CommandSpec(
        name="agfj",
        type="read",
        regex=re.compile(r"^agfj(\s+@\s+[a-zA-Z0-9_.]+)?$"),
        description="Print function graph in JSON format",
    ),
    # ESIL emulation commands
    CommandSpec(
        name="aei",
        type="analyze",
        regex=re.compile(r"^aei$"),
        description="Initialize ESIL VM",
    ),
    CommandSpec(
        name="aeim",
        type="analyze",
        regex=re.compile(r"^aeim$"),
        description="Initialize ESIL VM memory (stack)",
    ),
    CommandSpec(
        name="aeip",
        type="analyze",
        regex=re.compile(r"^aeip$"),
        description="Initialize ESIL VM program counter",
    ),
    CommandSpec(
        name="aes",
        type="analyze",
        regex=re.compile(r"^aes(\s+\d+)?$"),
        description="ESIL step execution",
    ),
    CommandSpec(
        name="ar",
        type="read",
        regex=re.compile(r"^ar[j]?$"),
        description="Show all register values",
    ),
    CommandSpec(
        name="s",
        type="analyze",
        regex=re.compile(r"^s(\s+[a-zA-Z0-9_.]+)?$"),
        description="Seek to address",
    ),
    # Information commands
    CommandSpec(
        name="i",
        type="read",
        regex=re.compile(r"^i[IiSszeEhj]?(\s*~.+)?$"),
        description="File information",
    ),
    CommandSpec(
        name="iI",
        type="read",
        regex=re.compile(r"^iI(\s*~.+)?$"),
        description="Binary info",
    ),
    CommandSpec(
        name="ii",
        type="read",
        regex=re.compile(r"^ii[j]?(\s*~.+)?$"),
        description="Imports",
    ),
    CommandSpec(
        name="iS",
        type="read",
        regex=re.compile(r"^iS[j]?(\s*~.+)?$"),
        description="Sections",
    ),
    CommandSpec(
        name="iz",
        type="read",
        regex=re.compile(r"^iz[j]?(\s*~.+)?$"),
        description="Strings in data sections",
    ),
    CommandSpec(
        name="izz",
        type="read",
        regex=re.compile(r"^izz[j]?(\s*~.+)?$"),
        description="All strings",
    ),
    CommandSpec(
        name="ie",
        type="read",
        regex=re.compile(r"^ie[j]?(\s*~.+)?$"),
        description="Entry points",
    ),
    CommandSpec(
        name="iE",
        type="read",
        regex=re.compile(r"^iE[j]?(\s*~.+)?$"),
        description="Exports",
    ),
    # Hexdump commands
    CommandSpec(
        name="px",
        type="read",
        regex=re.compile(r"^px[wqd]?(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print hexdump",
    ),
    CommandSpec(
        name="pxw",
        type="read",
        regex=re.compile(r"^pxw(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print hexdump (words)",
    ),
    CommandSpec(
        name="pxq",
        type="read",
        regex=re.compile(r"^pxq(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print hexdump (qwords)",
    ),
    CommandSpec(
        name="p8",
        type="read",
        regex=re.compile(r"^p8(\s+\d+)?(\s+@\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Print raw bytes in hexadecimal",
    ),
    # Seek commands (read-only navigation)
    CommandSpec(
        name="s",
        type="read",
        regex=re.compile(r"^s(\s+[a-zA-Z0-9_.+\-]+)?(\s*~.+)?$"),
        description="Seek to address",
    ),
    # Flag commands (read-only)
    CommandSpec(
        name="f",
        type="read",
        regex=re.compile(r"^f[sj]?(\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Flags",
    ),
    CommandSpec(
        name="fs",
        type="read",
        regex=re.compile(r"^fs(\s+[a-zA-Z0-9_.]+)?(\s*~.+)?$"),
        description="Flag spaces",
    ),
]


# Dangerous patterns that should always be blocked
DANGEROUS_PATTERNS = [
    re.compile(r";\s*\w"),  # Semicolon followed by command (command chaining)
    re.compile(r"\|\s*\w"),  # Pipe to another command
    re.compile(r"`.*`"),  # Backticks (command substitution)
    re.compile(r"\$\(.*\)"),  # Command substitution
    re.compile(r"&&"),  # Logical AND (command chaining)
    re.compile(r"\|\|"),  # Logical OR (command chaining)
    re.compile(r"^w[oxa]?\s"),  # Write commands
    re.compile(r"^!"),  # System commands
    re.compile(r"^#!"),  # Scripts
]


def validate_r2_command(cmd: str, allow_write: bool = False) -> ValidatedR2Command:
    """
    Validate a radare2 command using strict regex patterns.

    This function provides comprehensive validation to prevent command injection:
    1. Checks for dangerous patterns (semicolons, pipes, command substitution)
    2. Validates against known safe command patterns
    3. Blocks write commands unless explicitly allowed

    Args:
        cmd: Radare2 command string to validate
        allow_write: If True, allow write commands (default: False)

    Returns:
        ValidatedR2Command: Command string marked as validated

    Raises:
        ValidationError: If command is invalid, dangerous, or not in allowlist

    Example:
        >>> validate_r2_command("pdf @ main")
        ValidatedR2Command('pdf @ main')

        >>> validate_r2_command("pdf @ main; w hello")
        ValidationError: Dangerous command pattern detected
    """
    if not cmd or not cmd.strip():
        raise ValidationError(
            "Command string cannot be empty", details={"command": cmd}
        )

    cmd_stripped = cmd.strip()

    # Check for dangerous patterns first
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(cmd_stripped):
            raise ValidationError(
                f"Dangerous command pattern detected: {pattern.pattern}. "
                "Command chaining, pipes, and command substitution are not allowed.",
                details={"command": cmd_stripped, "pattern": pattern.pattern},
            )

    # Try to match against command specifications
    for spec in R2_COMMAND_SPECS:
        if spec.validate(cmd_stripped):
            # Check if write command when not allowed
            if spec.type == "write" and not allow_write:
                raise ValidationError(
                    f"Write commands are not allowed: {spec.name}",
                    details={"command": cmd_stripped, "command_type": spec.type},
                )
            return ValidatedR2Command(cmd_stripped)

    # No match found
    raise ValidationError(
        f"Command not in allowlist: {cmd_stripped}. "
        "Only read-only and analysis commands are allowed.",
        details={
            "command": cmd_stripped,
            "allowed_commands": [spec.name for spec in R2_COMMAND_SPECS],
        },
    )


def is_safe_r2_command(cmd: str) -> bool:
    """
    Check if a radare2 command is safe (non-blocking validation).

    Args:
        cmd: Command string to check

    Returns:
        True if command is safe, False otherwise
    """
    try:
        validate_r2_command(cmd, allow_write=False)
        return True
    except ValidationError:
        return False
