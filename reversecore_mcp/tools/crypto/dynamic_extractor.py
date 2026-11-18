"""Dynamic cryptographic key and IV extraction via user-space API hooking.

Extends LD_PRELOAD (Linux) and DYLD_INSERT_LIBRARIES (macOS) instrumentation
to intercept cryptographic library APIs (OpenSSL EVP/AES, Apple CommonCrypto
CCCrypt/CCCryptorCreate) and capture runtime keys, IVs, and payload buffers.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import get_workspace_config, validate_file_path

logger = get_logger(__name__)

CRYPTO_HOOK_TEMPLATE = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>

static FILE* get_crypto_log(void) {
    const char* path = getenv("REVERSECORE_CRYPTO_LOG");
    if (!path) return NULL;
    return fopen(path, "a");
}

static void write_hex_field(FILE* f, const unsigned char* buf, size_t len, size_t max_len) {
    if (!buf || len == 0) {
        fprintf(f, "\"\"");
        return;
    }
    size_t n = len < max_len ? len : max_len;
    fprintf(f, "\"");
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", buf[i]);
    }
    fprintf(f, "\"");
}

/* OpenSSL EVP_EncryptInit_ex / EVP_DecryptInit_ex / EVP_CipherInit_ex */
static int handle_evp_init(
    const char* api_name,
    int (*orig_fn)(void*, const void*, void*, const unsigned char*, const unsigned char*),
    void* ctx, const void* type, void* impl,
    const unsigned char* key, const unsigned char* iv
) {
    int ret = orig_fn ? orig_fn(ctx, type, impl, key, iv) : 0;
    FILE* f = get_crypto_log();
    if (f) {
        int key_len = 32;
        int iv_len = 16;
        int (*fn_keylen)(const void*) = dlsym(RTLD_NEXT, "EVP_CIPHER_key_length");
        int (*fn_ivlen)(const void*) = dlsym(RTLD_NEXT, "EVP_CIPHER_iv_length");
        const char* (*fn_cipher_name)(const void*) = dlsym(RTLD_NEXT, "EVP_CIPHER_name");
        if (type && fn_keylen) {
            int kl = fn_keylen(type);
            if (kl > 0 && kl <= 64) key_len = kl;
        }
        if (type && fn_ivlen) {
            int il = fn_ivlen(type);
            if (il >= 0 && il <= 32) iv_len = il;
        }
        const char* cname = (type && fn_cipher_name) ? fn_cipher_name(type) : "EVP_CIPHER";

        fprintf(f, "{\"api\":\"%s\",\"algorithm\":\"%s\",\"key_bits\":%d,\"key_hex\":",
                api_name, cname ? cname : "EVP_CIPHER", key_len * 8);
        write_hex_field(f, key, key ? (size_t)key_len : 0, 64);
        fprintf(f, ",\"iv_hex\":");
        write_hex_field(f, iv, iv ? (size_t)iv_len : 0, 32);
        fprintf(f, "}\n");
        fclose(f);
    }
    return ret;
}

int EVP_EncryptInit_ex(void* ctx, const void* type, void* impl, const unsigned char* key, const unsigned char* iv) {
    static int (*orig_fn)(void*, const void*, void*, const unsigned char*, const unsigned char*) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "EVP_EncryptInit_ex");
    return handle_evp_init("EVP_EncryptInit_ex", orig_fn, ctx, type, impl, key, iv);
}

int EVP_DecryptInit_ex(void* ctx, const void* type, void* impl, const unsigned char* key, const unsigned char* iv) {
    static int (*orig_fn)(void*, const void*, void*, const unsigned char*, const unsigned char*) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "EVP_DecryptInit_ex");
    return handle_evp_init("EVP_DecryptInit_ex", orig_fn, ctx, type, impl, key, iv);
}

int EVP_CipherInit_ex(void* ctx, const void* type, void* impl, const unsigned char* key, const unsigned char* iv, int enc) {
    static int (*orig_fn)(void*, const void*, void*, const unsigned char*, const unsigned char*, int) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "EVP_CipherInit_ex");
    int ret = orig_fn ? orig_fn(ctx, type, impl, key, iv, enc) : 0;
    FILE* f = get_crypto_log();
    if (f) {
        fprintf(f, "{\"api\":\"EVP_CipherInit_ex\",\"algorithm\":\"EVP_CIPHER\",\"enc\":%d,\"key_hex\":", enc);
        write_hex_field(f, key, key ? 32 : 0, 64);
        fprintf(f, ",\"iv_hex\":");
        write_hex_field(f, iv, iv ? 16 : 0, 32);
        fprintf(f, "}\n");
        fclose(f);
    }
    return ret;
}

int EVP_EncryptUpdate(void* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) {
    static int (*orig_fn)(void*, unsigned char*, int*, const unsigned char*, int) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "EVP_EncryptUpdate");
    FILE* f = get_crypto_log();
    if (f && in && inl > 0) {
        fprintf(f, "{\"api\":\"EVP_EncryptUpdate\",\"data_len\":%d,\"data_preview_hex\":", inl);
        write_hex_field(f, in, (size_t)inl, 64);
        fprintf(f, "}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(ctx, out, outl, in, inl) : 0;
}

int EVP_DecryptUpdate(void* ctx, unsigned char* out, int* outl, const unsigned char* in, int inl) {
    static int (*orig_fn)(void*, unsigned char*, int*, const unsigned char*, int) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "EVP_DecryptUpdate");
    FILE* f = get_crypto_log();
    if (f && in && inl > 0) {
        fprintf(f, "{\"api\":\"EVP_DecryptUpdate\",\"data_len\":%d,\"data_preview_hex\":", inl);
        write_hex_field(f, in, (size_t)inl, 64);
        fprintf(f, "}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(ctx, out, outl, in, inl) : 0;
}

/* OpenSSL low-level AES key schedule */
int AES_set_encrypt_key(const unsigned char* userKey, const int bits, void* key) {
    static int (*orig_fn)(const unsigned char*, const int, void*) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "AES_set_encrypt_key");
    FILE* f = get_crypto_log();
    if (f && userKey && bits > 0) {
        size_t bytes = (size_t)(bits / 8);
        fprintf(f, "{\"api\":\"AES_set_encrypt_key\",\"algorithm\":\"AES\",\"key_bits\":%d,\"key_hex\":", bits);
        write_hex_field(f, userKey, bytes, 64);
        fprintf(f, ",\"iv_hex\":\"\"}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(userKey, bits, key) : -1;
}

int AES_set_decrypt_key(const unsigned char* userKey, const int bits, void* key) {
    static int (*orig_fn)(const unsigned char*, const int, void*) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "AES_set_decrypt_key");
    FILE* f = get_crypto_log();
    if (f && userKey && bits > 0) {
        size_t bytes = (size_t)(bits / 8);
        fprintf(f, "{\"api\":\"AES_set_decrypt_key\",\"algorithm\":\"AES\",\"key_bits\":%d,\"key_hex\":", bits);
        write_hex_field(f, userKey, bytes, 64);
        fprintf(f, ",\"iv_hex\":\"\"}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(userKey, bits, key) : -1;
}

/* Apple CommonCrypto CCCrypt / CCCryptorCreate */
static const char* cc_alg_name(uint32_t alg) {
    switch (alg) {
        case 0: return "AES";
        case 1: return "DES";
        case 2: return "3DES";
        case 3: return "CAST";
        case 4: return "RC4";
        case 5: return "RC2";
        case 6: return "Blowfish";
        default: return "CommonCrypto";
    }
}

int32_t CCCrypt(
    uint32_t op, uint32_t alg, uint32_t options,
    const void* key, size_t keyLength, const void* iv,
    const void* dataIn, size_t dataInLength,
    void* dataOut, size_t dataOutAvailable, size_t* dataOutMoved
) {
    static int32_t (*orig_fn)(
        uint32_t, uint32_t, uint32_t,
        const void*, size_t, const void*,
        const void*, size_t, void*, size_t, size_t*
    ) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "CCCrypt");
    FILE* f = get_crypto_log();
    if (f) {
        fprintf(f, "{\"api\":\"CCCrypt\",\"algorithm\":\"%s\",\"op\":%u,\"key_bits\":%zu,\"key_hex\":",
                cc_alg_name(alg), op, keyLength * 8);
        write_hex_field(f, (const unsigned char*)key, keyLength, 64);
        fprintf(f, ",\"iv_hex\":");
        write_hex_field(f, (const unsigned char*)iv, iv ? 16 : 0, 32);
        fprintf(f, ",\"data_len\":%zu,\"data_preview_hex\":", dataInLength);
        write_hex_field(f, (const unsigned char*)dataIn, dataInLength, 64);
        fprintf(f, "}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved) : -1;
}

int32_t CCCryptorCreate(
    uint32_t op, uint32_t alg, uint32_t options,
    const void* key, size_t keyLength, const void* iv, void** cryptorRef
) {
    static int32_t (*orig_fn)(uint32_t, uint32_t, uint32_t, const void*, size_t, const void*, void**) = NULL;
    if (!orig_fn) orig_fn = dlsym(RTLD_NEXT, "CCCryptorCreate");
    FILE* f = get_crypto_log();
    if (f) {
        fprintf(f, "{\"api\":\"CCCryptorCreate\",\"algorithm\":\"%s\",\"op\":%u,\"key_bits\":%zu,\"key_hex\":",
                cc_alg_name(alg), op, keyLength * 8);
        write_hex_field(f, (const unsigned char*)key, keyLength, 64);
        fprintf(f, ",\"iv_hex\":");
        write_hex_field(f, (const unsigned char*)iv, iv ? 16 : 0, 32);
        fprintf(f, "}\n");
        fclose(f);
    }
    return orig_fn ? orig_fn(op, alg, options, key, keyLength, iv, cryptorRef) : -1;
}
"""

HOOKED_CRYPTO_APIS = [
    "EVP_EncryptInit_ex",
    "EVP_DecryptInit_ex",
    "EVP_CipherInit_ex",
    "EVP_EncryptUpdate",
    "EVP_DecryptUpdate",
    "AES_set_encrypt_key",
    "AES_set_decrypt_key",
    "CCCrypt",
    "CCCryptorCreate",
]


def compile_crypto_hook(workspace: Path) -> tuple[Path | None, Path, str | None]:
    """Compile the cryptographic API hooking shared library.

    Returns:
        Tuple of (compiled_lib_path_or_none, c_source_path, error_message_or_none).
    """
    hooks_dir = workspace / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    is_darwin = platform.system() == "Darwin"
    ext = ".dylib" if is_darwin else ".so"
    lib_path = hooks_dir / f"librecore_crypto_hook{ext}"
    c_path = hooks_dir / "recore_crypto_hook.c"

    try:
        c_path.write_text(CRYPTO_HOOK_TEMPLATE, encoding="utf-8")
    except Exception as exc:
        return None, c_path, f"Failed to write crypto hook C source: {exc}"

    compiler = shutil.which("clang") or shutil.which("gcc")
    if not compiler:
        return None, c_path, "No C compiler (clang or gcc) found in PATH."

    compile_cmd: list[str] = [compiler]
    if is_darwin:
        compile_cmd.extend(["-dynamiclib", "-o", str(lib_path), str(c_path), "-ldl"])
    else:
        compile_cmd.extend(["-shared", "-fPIC", "-o", str(lib_path), str(c_path), "-ldl"])

    try:
        proc = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return None, c_path, f"Compilation error: {proc.stderr.strip()}"
        return lib_path, c_path, None
    except Exception as exc:
        return None, c_path, f"Compilation failed: {exc}"


def parse_crypto_log(log_path: Path) -> list[dict[str, Any]]:
    """Parse JSONL records emitted by the crypto hook library."""
    if not log_path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line_str = line.strip()
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    events.append(json.loads(line_str))
                except Exception:
                    pass
    except Exception as exc:
        logger.debug(f"Failed to read crypto hook log: {exc}")
    return events


def _summarize_crypto_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate extracted keys, IVs, and observed algorithms."""
    unique_keys: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str, str]] = set()
    algorithms: set[str] = set()

    for ev in events:
        alg = str(ev.get("algorithm", "") or "")
        if alg:
            algorithms.add(alg)
        key_hex = str(ev.get("key_hex", "") or "")
        iv_hex = str(ev.get("iv_hex", "") or "")
        if key_hex:
            sig = (alg, key_hex, iv_hex)
            if sig not in seen_pairs:
                seen_pairs.add(sig)
                unique_keys.append(
                    {
                        "api": ev.get("api"),
                        "algorithm": alg or "unknown",
                        "key_bits": ev.get("key_bits"),
                        "key_hex": key_hex,
                        "iv_hex": iv_hex or None,
                    }
                )

    return {
        "total_events": len(events),
        "unique_keys_count": len(unique_keys),
        "algorithms_observed": sorted(algorithms),
        "unique_keys": unique_keys,
    }


@log_execution(tool_name="extract_crypto_keys_dynamic")
@track_metrics("extract_crypto_keys_dynamic")
@handle_tool_errors
async def extract_crypto_keys_dynamic(
    file_path: str | None = None,
    arguments: list[str] | str | None = None,
    stdin_input: str | None = None,
    timeout: int = 15,
    compile_only: bool = False,
) -> ToolResult:
    """Extract runtime cryptographic keys, IVs, and buffers using API hooking.

    Compiles an LD_PRELOAD (Linux) or DYLD_INSERT_LIBRARIES (macOS) shared library
    targeting OpenSSL (EVP_EncryptInit_ex, EVP_DecryptInit_ex, EVP_CipherInit_ex,
    EVP_EncryptUpdate, EVP_DecryptUpdate, AES_set_encrypt_key, AES_set_decrypt_key)
    and Apple CommonCrypto (CCCrypt, CCCryptorCreate). When a target binary is
    provided and compile_only is False, executes it under the hook and parses
    captured keys and IVs.

    Args:
        file_path: Optional path to target executable inside the workspace.
        arguments: Optional CLI arguments to pass to the target executable.
        stdin_input: Optional stdin string to feed to the target executable.
        timeout: Maximum execution time in seconds (1-60).
        compile_only: If True, build the crypto hook library without running a binary.

    Returns:
        ToolResult containing extracted keys, IVs, observed algorithms, and raw events.

    Example:
        >>> result = await extract_crypto_keys_dynamic("/app/workspace/ransom_sim")
        >>> print(result.status)
        'success'
    """
    workspace = get_workspace_config().workspace.resolve()
    timeout = max(1, min(timeout, 60))

    lib_path, c_source_path, compile_err = compile_crypto_hook(workspace)
    is_darwin = platform.system() == "Darwin"
    preload_var = "DYLD_INSERT_LIBRARIES" if is_darwin else "LD_PRELOAD"

    if compile_only or file_path is None:
        data: dict[str, Any] = {
            "status": "success" if lib_path else "warning",
            "c_source_path": str(c_source_path),
            "library_path": str(lib_path) if lib_path else None,
            "compiler_available": lib_path is not None,
            "compilation_warning": compile_err,
            "preload_variable": preload_var,
            "hooked_apis": HOOKED_CRYPTO_APIS,
        }
        msg = (
            f"Compiled crypto key extraction hook library at '{lib_path.name}'."
            if lib_path
            else f"Generated crypto hook source at '{c_source_path.name}'. Compilation warning: {compile_err}"
        )
        return success(data=data, message=msg)

    validated_path = validate_file_path(file_path)
    if lib_path is None or not lib_path.exists():
        return success(
            data={
                "status": "error",
                "file_path": str(validated_path),
                "library_path": None,
                "compilation_error": compile_err,
                "hooked_apis": HOOKED_CRYPTO_APIS,
            },
            message=f"Cannot execute dynamic key extraction: hook compilation failed ({compile_err}).",
        )

    args_list: list[str] = []
    if isinstance(arguments, str):
        args_list = shlex.split(arguments)
    elif isinstance(arguments, list):
        args_list = [str(a) for a in arguments]

    tmp_dir = workspace / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    log_file = tmp_dir / f"crypto_hook_{os.getpid()}_{int(time.time() * 1000)}.log"

    safe_env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(workspace),
        "TMPDIR": str(tmp_dir),
        "LANG": "C.UTF-8",
        preload_var: str(lib_path),
        "REVERSECORE_CRYPTO_LOG": str(log_file),
    }
    if is_darwin:
        safe_env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"

    cmd = [str(validated_path), *args_list]
    timed_out = False
    exit_code = -1
    stdout_text = ""
    stderr_text = ""

    t_start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_input is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(workspace),
            env=safe_env,
        )
        input_bytes = stdin_input.encode("utf-8", errors="replace") if stdin_input else None
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(input=input_bytes), timeout=timeout
            )
            stdout_text = (out_b or b"").decode("utf-8", errors="replace")[:2048]
            stderr_text = (err_b or b"").decode("utf-8", errors="replace")[:2048]
            exit_code = proc.returncode if proc.returncode is not None else -1
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
    except Exception as exc:
        return success(
            data={
                "status": "error",
                "file_path": str(validated_path),
                "error": str(exc),
            },
            message=f"Execution failed for '{validated_path.name}': {exc}",
        )

    duration_ms = round((time.perf_counter() - t_start) * 1000, 2)
    events = parse_crypto_log(log_file)
    try:
        log_file.unlink(missing_ok=True)
    except Exception:
        pass

    summary = _summarize_crypto_events(events)

    payload: dict[str, Any] = {
        "file_path": str(validated_path),
        "library_path": str(lib_path),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "hooked_apis": HOOKED_CRYPTO_APIS,
        **summary,
        "events": events[:100],
        "stdout_preview": stdout_text,
        "stderr_preview": stderr_text,
    }

    if summary["unique_keys_count"] > 0:
        msg = (
            f"Extracted {summary['unique_keys_count']} unique cryptographic key(s) "
            f"across {summary['total_events']} intercepted call(s) "
            f"({', '.join(summary['algorithms_observed'])})."
        )
    else:
        msg = (
            f"Executed '{validated_path.name}' in {duration_ms} ms (exit code: {exit_code}); "
            f"no hooked cryptographic API calls were intercepted."
        )

    return success(data=payload, message=msg)
