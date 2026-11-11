"""Syscall filtering profiles and Seccomp sandbox policy generator.

Provides sandboxing profiles to contain untrusted binaries and simulate execution boundaries:
- Standard containment profiles: 'strict', 'no_network', 'read_only', and 'minimal_sandbox'
- Exports industry-standard Docker/OCI Seccomp JSON profiles and systemd filters
- Supplies syscall fault-injection rules for strace enforcement during runtime tracing
"""

from __future__ import annotations

import json
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.exceptions import ValidationError
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)

# Curated syscall groupings
NETWORK_SYSCALLS: list[str] = [
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "socketpair",
    "setsockopt",
    "getsockopt",
]

MUTATING_FS_SYSCALLS: list[str] = [
    "creat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "rmdir",
    "mkdir",
    "mkdirat",
    "truncate",
    "ftruncate",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "fchownat",
]

PROCESS_EXEC_SYSCALLS: list[str] = [
    "execve",
    "execveat",
    "clone",
    "clone3",
    "fork",
    "vfork",
]

DANGEROUS_SYSTEM_SYSCALLS: list[str] = [
    "ptrace",
    "bpf",
    "mount",
    "umount2",
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "chroot",
]

# Standard profiles
PROFILES: dict[str, dict[str, Any]] = {
    "strict": {
        "description": "Strict isolation: blocks all network, process spawning, filesystem mutations, and privileged calls.",
        "blocked_syscalls": list(
            dict.fromkeys(
                NETWORK_SYSCALLS
                + MUTATING_FS_SYSCALLS
                + PROCESS_EXEC_SYSCALLS
                + DANGEROUS_SYSTEM_SYSCALLS
            )
        ),
    },
    "no_network": {
        "description": "Network containment: blocks all socket creation, connections, and network I/O.",
        "blocked_syscalls": list(dict.fromkeys(NETWORK_SYSCALLS)),
    },
    "read_only": {
        "description": "Read-only filesystem: blocks modifying or deleting files while permitting reads and network.",
        "blocked_syscalls": list(dict.fromkeys(MUTATING_FS_SYSCALLS)),
    },
    "minimal_sandbox": {
        "description": "Kernel protection: blocks privileged actions (ptrace, bpf, modules, mount, reboot).",
        "blocked_syscalls": list(dict.fromkeys(DANGEROUS_SYSTEM_SYSCALLS)),
    },
}


def get_profile_blocked_syscalls(
    profile_name: str, custom_blocked: list[str] | None = None
) -> list[str]:
    """Retrieve the deduplicated list of blocked syscalls for a given profile."""
    norm_name = profile_name.strip().lower()
    if norm_name not in PROFILES:
        raise ValidationError(
            f"Unknown seccomp profile '{profile_name}'. Available: {list(PROFILES.keys())}"
        )

    base = list(PROFILES[norm_name]["blocked_syscalls"])
    if custom_blocked:
        for sc in custom_blocked:
            clean_sc = sc.strip().lower()
            if clean_sc and clean_sc not in base:
                base.append(clean_sc)
    return base


def build_oci_seccomp_profile(
    profile_name: str,
    blocked_syscalls: list[str],
    default_action: str = "SCMP_ACT_ALLOW",
    errno_code: int = 1,  # EPERM
) -> dict[str, Any]:
    """Build an OCI / Docker compliant Seccomp JSON profile."""
    return {
        "defaultAction": default_action,
        "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_AARCH64",
            "SCMP_ARCH_ARM",
        ],
        "syscalls": [
            {
                "names": sorted(blocked_syscalls),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": errno_code,
            }
        ],
        "metadata": {
            "profile_name": profile_name,
            "generated_by": "Reversecore_MCP",
            "blocked_count": len(blocked_syscalls),
        },
    }


def build_systemd_seccomp_filter(blocked_syscalls: list[str]) -> str:
    """Build systemd service unit SystemCallFilter directives."""
    lines = [
        "# Reversecore MCP Generated Systemd Seccomp Sandbox Filter",
        "[Service]",
        f"SystemCallFilter=~{' '.join(sorted(blocked_syscalls))}",
        "SystemCallErrorNumber=EPERM",
    ]
    return "\n".join(lines) + "\n"


@log_execution(tool_name="generate_seccomp_profile")
@track_metrics("generate_seccomp_profile")
@handle_tool_errors
async def generate_seccomp_profile(
    profile_type: str = "no_network",
    custom_blocked_syscalls: list[str] | None = None,
    output_filename: str | None = None,
    output_format: str = "oci_json",
) -> ToolResult:
    """Generate an OCI/Docker Seccomp JSON profile or systemd filter for sandbox isolation.

    Creates production-grade syscall filtering policies for containing untrusted binaries
    during dynamic analysis, malware triage, and sandbox execution.

    Args:
        profile_type: Built-in profile ('strict', 'no_network', 'read_only', 'minimal_sandbox').
        custom_blocked_syscalls: Optional extra syscall names to block.
        output_filename: Optional name for the output profile file.
        output_format: Output policy format ('oci_json' for Docker/Podman or 'systemd').

    Returns:
        ToolResult with output file path, blocked syscall list, and container run examples.

    Example:
        >>> result = await generate_seccomp_profile(profile_type="no_network")
        >>> print(result.status)
        'success'
    """
    clean_type = profile_type.strip().lower()
    blocked = get_profile_blocked_syscalls(clean_type, custom_blocked_syscalls)

    workspace = get_workspace_config().workspace.resolve()
    seccomp_dir = workspace / "seccomp"
    seccomp_dir.mkdir(parents=True, exist_ok=True)

    fmt = output_format.strip().lower()
    if fmt == "oci_json":
        fname = output_filename or f"seccomp_{clean_type}.json"
        out_path = seccomp_dir / fname
        oci_doc = build_oci_seccomp_profile(clean_type, blocked)
        out_path.write_text(json.dumps(oci_doc, indent=2), encoding="utf-8")
        docker_cmd = f"docker run --security-opt seccomp={out_path} --rm -it <image>"
    elif fmt == "systemd":
        fname = output_filename or f"seccomp_{clean_type}.conf"
        out_path = seccomp_dir / fname
        conf_text = build_systemd_seccomp_filter(blocked)
        out_path.write_text(conf_text, encoding="utf-8")
        docker_cmd = f"systemd-run -p SystemCallFilter=~{' '.join(blocked[:5])} <binary>"
    else:
        raise ValidationError(f"Unsupported format '{output_format}'. Use 'oci_json' or 'systemd'.")

    # Validate output path safely within workspace
    validated_out = validate_file_path(str(out_path))

    result_data = {
        "status": "success",
        "profile_type": clean_type,
        "format": fmt,
        "profile_path": str(validated_out),
        "blocked_syscall_count": len(blocked),
        "blocked_syscalls": blocked,
        "docker_usage_example": docker_cmd,
    }

    msg = (
        f"Generated '{clean_type}' seccomp profile ({fmt}) with {len(blocked)} blocked syscall(s) "
        f"at '{validated_out.name}'."
    )
    return success(data=result_data, message=msg)
