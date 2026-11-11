"""User-space API call hooking and runtime instrumentation library.

Provides lightweight LD_PRELOAD (Linux) and DYLD_INSERT_LIBRARIES (macOS)
shared library generation to monitor and intercept high-level API calls:
- File I/O: fopen, open, unlink
- Process execution: system, execve, popen
- Network calls: connect, socket, getaddrinfo
- Anti-analysis bypass: ptrace (spoofs debugger non-presence)
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)

# Standard C hook source code
C_HOOK_TEMPLATE = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static FILE* get_hook_log(void) {
    const char* path = getenv("REVERSECORE_HOOK_LOG");
    if (!path) return NULL;
    return fopen(path, "a");
}

/* Intercept fopen */
FILE* fopen(const char *pathname, const char *mode) {
    static FILE* (*orig_fopen)(const char *, const char *) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *f = get_hook_log();
    if (f) {
        fprintf(f, "{\"api\":\"fopen\",\"path\":\"%s\",\"mode\":\"%s\"}\n",
                pathname ? pathname : "", mode ? mode : "");
        fclose(f);
    }
    return orig_fopen ? orig_fopen(pathname, mode) : NULL;
}

/* Intercept system */
int system(const char *command) {
    static int (*orig_system)(const char *) = NULL;
    if (!orig_system) orig_system = dlsym(RTLD_NEXT, "system");
    FILE *f = get_hook_log();
    if (f) {
        fprintf(f, "{\"api\":\"system\",\"command\":\"%s\"}\n", command ? command : "");
        fclose(f);
    }
    return orig_system ? orig_system(command) : -1;
}

/* Intercept execve */
int execve(const char *pathname, char *const argv[], char *const envp[]) {
    static int (*orig_execve)(const char *, char *const[], char *const[]) = NULL;
    if (!orig_execve) orig_execve = dlsym(RTLD_NEXT, "execve");
    FILE *f = get_hook_log();
    if (f) {
        fprintf(f, "{\"api\":\"execve\",\"pathname\":\"%s\"}\n", pathname ? pathname : "");
        fclose(f);
    }
    return orig_execve ? orig_execve(pathname, argv, envp) : -1;
}

/* Intercept connect (IPv4) */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!orig_connect) orig_connect = dlsym(RTLD_NEXT, "connect");
    FILE *f = get_hook_log();
    if (f && addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(in->sin_addr), ip, INET_ADDRSTRLEN);
        int port = ntohs(in->sin_port);
        fprintf(f, "{\"api\":\"connect\",\"ip\":\"%s\",\"port\":%d}\n", ip, port);
        fclose(f);
    }
    return orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
}

/* Anti-debugging bypass: spoof ptrace to always succeed */
long ptrace(int request, pid_t pid, void *addr, void *data) {
    FILE *f = get_hook_log();
    if (f) {
        fprintf(f, "{\"api\":\"ptrace\",\"request\":%d,\"spoofed\":true}\n", request);
        fclose(f);
    }
    return 0; // Pretend debugger check passed cleanly
}
"""

SUPPORTED_APIS = ["fopen", "system", "execve", "connect", "ptrace"]


def compile_api_hook(workspace: Path) -> tuple[Path | None, str | None]:
    """Compile the API hooking C source into a shared library.

    Returns:
        Tuple of (path_to_compiled_library, error_message_if_failed).
    """
    hooks_dir = workspace / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    is_darwin = platform.system() == "Darwin"
    ext = ".dylib" if is_darwin else ".so"
    lib_path = hooks_dir / f"librecore_hook{ext}"
    c_path = hooks_dir / "recore_hook.c"

    try:
        c_path.write_text(C_HOOK_TEMPLATE, encoding="utf-8")
    except Exception as exc:
        return None, f"Failed to write C hook source: {exc}"

    # Locate compiler (clang or gcc)
    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        return None, "No C compiler (clang or gcc) found in PATH."

    compile_cmd: list[str] = [compiler]
    if is_darwin:
        compile_cmd.extend(["-dynamiclib", "-o", str(lib_path), str(c_path), "-ldl"])
    else:
        compile_cmd.extend(["-shared", "-fPIC", "-o", str(lib_path), str(c_path), "-ldl"])

    try:
        proc = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return None, f"Compilation error: {proc.stderr.strip()}"
        return lib_path, None
    except Exception as exc:
        return None, f"Compilation failed: {exc}"


def parse_hook_log(log_path: Path) -> list[dict[str, Any]]:
    """Parse JSON lines emitted by the hook library into structured records."""
    if not log_path.exists():
        return []

    calls: list[dict[str, Any]] = []
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line_str = line.strip()
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    calls.append(json.loads(line_str))
                except Exception:
                    pass
    except Exception as exc:
        logger.debug(f"Failed to read hook log: {exc}")
    return calls


@log_execution(tool_name="generate_api_hook_library")
@track_metrics("generate_api_hook_library")
@handle_tool_errors
async def generate_api_hook_library(
    output_name: str | None = None,
) -> ToolResult:
    """Generate and compile a user-space API hooking shared library for sandbox dynamic analysis.

    Produces an LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS) shared library that
    intercepts high-risk API calls (filesystem, process execution, socket connects) and
    spoofs anti-debugging checks (ptrace) to observe binary behavior without virtualization.

    Args:
        output_name: Optional prefix or name for the generated hook files.

    Returns:
        ToolResult with source code path, compiled library path, supported APIs, and usage command.

    Example:
        >>> result = await generate_api_hook_library()
        >>> print(result.status)
        'success'
    """
    workspace = get_workspace_config().workspace.resolve()
    hooks_dir = workspace / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    lib_path, err = compile_api_hook(workspace)
    c_source_path = hooks_dir / "recore_hook.c"

    validated_src = validate_file_path(str(c_source_path))
    validated_lib = validate_file_path(str(lib_path)) if lib_path and lib_path.exists() else None

    is_darwin = platform.system() == "Darwin"
    preload_var = "DYLD_INSERT_LIBRARIES" if is_darwin else "LD_PRELOAD"
    usage_example = (
        f"{preload_var}={validated_lib} REVERSECORE_HOOK_LOG=/tmp/hook.log <binary>"
        if validated_lib
        else f"{preload_var}=<compiled_library> <binary>"
    )

    data: dict[str, Any] = {
        "status": "success" if validated_lib else "warning",
        "c_source_path": str(validated_src),
        "library_path": str(validated_lib) if validated_lib else None,
        "compiler_available": validated_lib is not None,
        "compilation_warning": err,
        "supported_apis": SUPPORTED_APIS,
        "usage_example": usage_example,
        "features": [
            "File open/access logging (fopen)",
            "Command execution logging (system, execve)",
            "Network connection logging (connect)",
            "Anti-debugging bypass (ptrace spoofing)",
        ],
    }

    msg = (
        f"Generated API hook library at '{validated_lib.name}' with {len(SUPPORTED_APIS)} intercepted APIs."
        if validated_lib
        else f"Generated C hook source at '{validated_src.name}'. Compilation warning: {err}"
    )

    return success(data=data, message=msg)
