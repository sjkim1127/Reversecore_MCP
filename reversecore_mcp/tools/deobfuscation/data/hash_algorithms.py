"""
Malware API Hashing Algorithms & Precomputed Symbol Database.

Implements industry-standard hashing algorithms commonly used by malware and shellcode
(Metasploit, Cobalt Strike, Carberp, TrickBot, Emotet) to conceal imported API names,
along with an in-memory database of standard Windows APIs.
"""

from __future__ import annotations

import binascii
from collections.abc import Sequence
from typing import Any, Final, NamedTuple

# ============================================================================
# Hash Algorithm Implementations
# ============================================================================


def ror32(value: int, shift: int) -> int:
    """32-bit right rotation."""
    shift &= 31
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def rol32(value: int, shift: int) -> int:
    """32-bit left rotation."""
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def ror13(data: str | bytes) -> int:
    """Standard ROR13 hash (used in Metasploit, Cobalt Strike, API hashing shellcode).

    Supports null-terminated ASCII strings.
    """
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 0
    for b in raw:
        if b == 0:
            break
        h = (ror32(h, 13) + b) & 0xFFFFFFFF
    return h


def ror7(data: str | bytes) -> int:
    """ROR7 hash variation."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 0
    for b in raw:
        if b == 0:
            break
        h = (ror32(h, 7) + b) & 0xFFFFFFFF
    return h


def crc32_hash(data: str | bytes) -> int:
    """Standard CRC32 hash (POSIX / IEEE 802.3)."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data
    return binascii.crc32(raw) & 0xFFFFFFFF


def djb2_32(data: str | bytes) -> int:
    """DJB2 32-bit hash (Dan Bernstein algorithm: hash * 33 + c)."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 5381
    for b in raw:
        if b == 0:
            break
        h = (((h << 5) + h) + b) & 0xFFFFFFFF
    return h


def sdbm_32(data: str | bytes) -> int:
    """SDBM 32-bit hash algorithm (hash = c + (hash << 6) + (hash << 16) - hash)."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 0
    for b in raw:
        if b == 0:
            break
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def fnv1a_32(data: str | bytes) -> int:
    """FNV-1a 32-bit hash algorithm (Offset: 0x811C9DC5, Prime: 0x01000193)."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 0x811C9DC5
    for b in raw:
        if b == 0:
            break
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1_32(data: str | bytes) -> int:
    """FNV-1 32-bit hash algorithm."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    h = 0x811C9DC5
    for b in raw:
        if b == 0:
            break
        h = ((h * 0x01000193) ^ b) & 0xFFFFFFFF
    return h


def murmurhash3_32(data: str | bytes, seed: int = 0) -> int:
    """MurmurHash3 32-bit implementation."""
    if isinstance(data, str):
        raw = data.encode("latin-1", errors="ignore")
    else:
        raw = data

    length = len(raw)
    h = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Process 4-byte chunks
    nblocks = length // 4
    for i in range(nblocks):
        k = raw[i * 4] | (raw[i * 4 + 1] << 8) | (raw[i * 4 + 2] << 16) | (raw[i * 4 + 3] << 24)
        k = (k * c1) & 0xFFFFFFFF
        k = rol32(k, 15)
        k = (k * c2) & 0xFFFFFFFF

        h = h ^ k
        h = rol32(h, 13)
        h = ((h * 5) + 0xE6546B64) & 0xFFFFFFFF

    # Tail
    tail = raw[nblocks * 4 :]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = rol32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1

    # Finalization mix
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


SUPPORTED_ALGORITHMS: Final[dict[str, Any]] = {
    "ror13": ror13,
    "ror7": ror7,
    "crc32": crc32_hash,
    "djb2": djb2_32,
    "sdbm": sdbm_32,
    "fnv1a": fnv1a_32,
    "fnv1": fnv1_32,
    "murmurhash3": murmurhash3_32,
}


def compute_all_hashes(api_name: str) -> dict[str, int]:
    """Compute 32-bit hashes for an API name across all supported algorithms."""
    results: dict[str, int] = {}
    for name, func in SUPPORTED_ALGORITHMS.items():
        results[name] = func(api_name)
    return results


# ============================================================================
# Precomputed Windows API Database
# ============================================================================


class ApiSymbol(NamedTuple):
    dll: str
    api_name: str
    signature: str


# Comprehensive inventory of top Windows API exports used in reverse engineering & malware analysis
CORE_WINDOWS_APIS: Final[list[ApiSymbol]] = [
    # ntdll.dll (Process & Native APIs)
    ApiSymbol(
        "ntdll.dll",
        "NtAllocateVirtualMemory",
        "NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtProtectVirtualMemory",
        "NTSTATUS NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtWriteVirtualMemory",
        "NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtCreateThreadEx",
        "NTSTATUS NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtQueueApcThread",
        "NTSTATUS NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, ULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtQueryInformationProcess",
        "NTSTATUS NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtQuerySystemInformation",
        "NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtUnmapViewOfSection",
        "NTSTATUS NtUnmapViewOfSection(HANDLE, PVOID)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtMapViewOfSection",
        "NTSTATUS NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtCreateSection",
        "NTSTATUS NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtOpenProcess",
        "NTSTATUS NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "NtTerminateProcess",
        "NTSTATUS NtTerminateProcess(HANDLE, NTSTATUS)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "RtlDecompressBuffer",
        "NTSTATUS RtlDecompressBuffer(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG)",
    ),
    ApiSymbol("ntdll.dll", "RtlMoveMemory", "VOID RtlMoveMemory(VOID*, const VOID*, SIZE_T)"),
    ApiSymbol("ntdll.dll", "RtlZeroMemory", "VOID RtlZeroMemory(VOID*, SIZE_T)"),
    ApiSymbol(
        "ntdll.dll",
        "LdrLoadDll",
        "NTSTATUS LdrLoadDll(PWSTR, PULONG, PUNICODE_STRING, PHANDLE)",
    ),
    ApiSymbol(
        "ntdll.dll",
        "LdrGetProcedureAddress",
        "NTSTATUS LdrGetProcedureAddress(HMODULE, PANSI_STRING, WORD, PVOID*)",
    ),
    # kernel32.dll (Memory & Process Management)
    ApiSymbol(
        "kernel32.dll",
        "VirtualAlloc",
        "LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "VirtualAllocEx",
        "LPVOID VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "VirtualProtect",
        "BOOL VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "VirtualProtectEx",
        "BOOL VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD)",
    ),
    ApiSymbol("kernel32.dll", "VirtualFree", "BOOL VirtualFree(LPVOID, SIZE_T, DWORD)"),
    ApiSymbol(
        "kernel32.dll",
        "WriteProcessMemory",
        "BOOL WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "ReadProcessMemory",
        "BOOL ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateProcessA",
        "BOOL CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateProcessW",
        "BOOL CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateRemoteThread",
        "HANDLE CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateThread",
        "HANDLE CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)",
    ),
    ApiSymbol("kernel32.dll", "OpenProcess", "HANDLE OpenProcess(DWORD, BOOL, DWORD)"),
    ApiSymbol("kernel32.dll", "GetProcAddress", "FARPROC GetProcAddress(HMODULE, LPCSTR)"),
    ApiSymbol("kernel32.dll", "LoadLibraryA", "HMODULE LoadLibraryA(LPCSTR)"),
    ApiSymbol("kernel32.dll", "LoadLibraryW", "HMODULE LoadLibraryW(LPCWSTR)"),
    ApiSymbol(
        "kernel32.dll",
        "LoadLibraryExA",
        "HMODULE LoadLibraryExA(LPCSTR, HANDLE, DWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "LoadLibraryExW",
        "HMODULE LoadLibraryExW(LPCWSTR, HANDLE, DWORD)",
    ),
    ApiSymbol("kernel32.dll", "GetModuleHandleA", "HMODULE GetModuleHandleA(LPCSTR)"),
    ApiSymbol("kernel32.dll", "GetModuleHandleW", "HMODULE GetModuleHandleW(LPCWSTR)"),
    ApiSymbol(
        "kernel32.dll",
        "QueueUserAPC",
        "DWORD QueueUserAPC(PAPCFUNC, HANDLE, ULONG_PTR)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "SetThreadContext",
        "BOOL SetThreadContext(HANDLE, const CONTEXT*)",
    ),
    ApiSymbol("kernel32.dll", "GetThreadContext", "BOOL GetThreadContext(HANDLE, LPCONTEXT)"),
    ApiSymbol("kernel32.dll", "ResumeThread", "DWORD ResumeThread(HANDLE)"),
    ApiSymbol("kernel32.dll", "SuspendThread", "DWORD SuspendThread(HANDLE)"),
    ApiSymbol("kernel32.dll", "IsDebuggerPresent", "BOOL IsDebuggerPresent()"),
    ApiSymbol(
        "kernel32.dll",
        "CheckRemoteDebuggerPresent",
        "BOOL CheckRemoteDebuggerPresent(HANDLE, PBOOL)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateFileA",
        "HANDLE CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateFileW",
        "HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "WriteFile",
        "BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "ReadFile",
        "BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)",
    ),
    ApiSymbol("kernel32.dll", "WinExec", "UINT WinExec(LPCSTR, UINT)"),
    ApiSymbol("kernel32.dll", "Sleep", "VOID Sleep(DWORD)"),
    ApiSymbol("kernel32.dll", "GetTickCount", "DWORD GetTickCount()"),
    ApiSymbol("kernel32.dll", "GetTickCount64", "ULONGLONG GetTickCount64()"),
    ApiSymbol(
        "kernel32.dll",
        "QueryPerformanceCounter",
        "BOOL QueryPerformanceCounter(LARGE_INTEGER*)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "CreateToolhelp32Snapshot",
        "HANDLE CreateToolhelp32Snapshot(DWORD, DWORD)",
    ),
    ApiSymbol(
        "kernel32.dll",
        "Process32First",
        "BOOL Process32First(HANDLE, LPPROCESSENTRY32)",
    ),
    ApiSymbol("kernel32.dll", "Process32Next", "BOOL Process32Next(HANDLE, LPPROCESSENTRY32)"),
    # advapi32.dll (Registry, Token & Service Security)
    ApiSymbol(
        "advapi32.dll",
        "OpenProcessToken",
        "BOOL OpenProcessToken(HANDLE, DWORD, PHANDLE)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "AdjustTokenPrivileges",
        "BOOL AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "LookupPrivilegeValueA",
        "BOOL LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "LookupPrivilegeValueW",
        "BOOL LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegOpenKeyExA",
        "LSTATUS RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegOpenKeyExW",
        "LSTATUS RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegSetValueExA",
        "LSTATUS RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegSetValueExW",
        "LSTATUS RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegQueryValueExA",
        "LSTATUS RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "RegQueryValueExW",
        "LSTATUS RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "OpenSCManagerA",
        "SC_HANDLE OpenSCManagerA(LPCSTR, LPCSTR, DWORD)",
    ),
    ApiSymbol(
        "advapi32.dll",
        "CreateServiceA",
        "SC_HANDLE CreateServiceA(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR)",
    ),
    ApiSymbol("advapi32.dll", "StartServiceA", "BOOL StartServiceA(SC_HANDLE, DWORD, LPCSTR*)"),
    # user32.dll (GUI, Hooks & Input Capture)
    ApiSymbol("user32.dll", "MessageBoxA", "int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT)"),
    ApiSymbol("user32.dll", "MessageBoxW", "int MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT)"),
    ApiSymbol(
        "user32.dll",
        "SetWindowsHookExA",
        "HHOOK SetWindowsHookExA(int, HOOKPROC, HINSTANCE, DWORD)",
    ),
    ApiSymbol(
        "user32.dll",
        "SetWindowsHookExW",
        "HHOOK SetWindowsHookExW(int, HOOKPROC, HINSTANCE, DWORD)",
    ),
    ApiSymbol("user32.dll", "GetAsyncKeyState", "SHORT GetAsyncKeyState(int)"),
    ApiSymbol("user32.dll", "GetKeyState", "SHORT GetKeyState(int)"),
    ApiSymbol("user32.dll", "GetForegroundWindow", "HWND GetForegroundWindow()"),
    # ws2_32.dll (Networking & C2 Sockets)
    ApiSymbol("ws2_32.dll", "WSAStartup", "int WSAStartup(WORD, LPWSADATA)"),
    ApiSymbol("ws2_32.dll", "socket", "SOCKET socket(int, int, int)"),
    ApiSymbol("ws2_32.dll", "connect", "int connect(SOCKET, const struct sockaddr*, int)"),
    ApiSymbol("ws2_32.dll", "send", "int send(SOCKET, const char*, int, int)"),
    ApiSymbol("ws2_32.dll", "recv", "int recv(SOCKET, char*, int, int)"),
    ApiSymbol("ws2_32.dll", "closesocket", "int closesocket(SOCKET)"),
    ApiSymbol(
        "ws2_32.dll",
        "WSASocketA",
        "SOCKET WSASocketA(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD)",
    ),
    ApiSymbol(
        "ws2_32.dll",
        "WSAConnect",
        "int WSAConnect(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS)",
    ),
    # wininet.dll / winhttp.dll (HTTP C2 Communication)
    ApiSymbol(
        "wininet.dll",
        "InternetOpenA",
        "HINTERNET InternetOpenA(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD)",
    ),
    ApiSymbol(
        "wininet.dll",
        "InternetConnectA",
        "HINTERNET InternetConnectA(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)",
    ),
    ApiSymbol(
        "wininet.dll",
        "HttpOpenRequestA",
        "HINTERNET HttpOpenRequestA(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR)",
    ),
    ApiSymbol(
        "wininet.dll",
        "HttpSendRequestA",
        "BOOL HttpSendRequestA(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD)",
    ),
    ApiSymbol(
        "wininet.dll",
        "InternetReadFile",
        "BOOL InternetReadFile(HINTERNET, LPVOID, DWORD, LPDWORD)",
    ),
    ApiSymbol(
        "winhttp.dll",
        "WinHttpOpen",
        "HINTERNET WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD)",
    ),
    ApiSymbol(
        "winhttp.dll",
        "WinHttpConnect",
        "HINTERNET WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD)",
    ),
    ApiSymbol(
        "winhttp.dll",
        "WinHttpOpenRequest",
        "HINTERNET WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD)",
    ),
    ApiSymbol(
        "winhttp.dll",
        "WinHttpSendRequest",
        "BOOL WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR)",
    ),
    ApiSymbol(
        "winhttp.dll",
        "WinHttpReceiveResponse",
        "BOOL WinHttpReceiveResponse(HINTERNET, LPVOID)",
    ),
]


class ApiHashDatabase:
    """Precomputed and custom API hash lookup table."""

    def __init__(self, symbols: Sequence[ApiSymbol] = CORE_WINDOWS_APIS) -> None:
        self._lookup: dict[tuple[str, int], ApiSymbol] = {}
        self._all_hashes_by_val: dict[int, list[tuple[str, ApiSymbol]]] = {}
        self._build_database(symbols)

    def _build_database(self, symbols: Sequence[ApiSymbol]) -> None:
        for sym in symbols:
            hashes = compute_all_hashes(sym.api_name)
            for algo, hval in hashes.items():
                self._lookup[(algo, hval)] = sym
                if hval not in self._all_hashes_by_val:
                    self._all_hashes_by_val[hval] = []
                self._all_hashes_by_val[hval].append((algo, sym))

    def register_custom_symbol(self, dll: str, api_name: str, signature: str = "") -> None:
        """Dynamically add custom API names to the hash database."""
        sym = ApiSymbol(dll, api_name, signature)
        hashes = compute_all_hashes(api_name)
        for algo, hval in hashes.items():
            self._lookup[(algo, hval)] = sym
            if hval not in self._all_hashes_by_val:
                self._all_hashes_by_val[hval] = []
            self._all_hashes_by_val[hval].append((algo, sym))

    def lookup(self, hash_val: int, algorithm: str | None = None) -> list[dict[str, Any]]:
        """Lookup an API symbol by its hash value.

        Args:
            hash_val: 32-bit integer hash value.
            algorithm: Specific algorithm (e.g. 'ror13', 'crc32') or None for all.

        Returns:
            List of matching records with algorithm, dll, api_name, signature.
        """
        results: list[dict[str, Any]] = []
        if algorithm and algorithm.lower() in SUPPORTED_ALGORITHMS:
            algo_key = algorithm.lower()
            sym = self._lookup.get((algo_key, hash_val))
            if sym:
                results.append(
                    {
                        "algorithm": algo_key,
                        "dll": sym.dll,
                        "api_name": sym.api_name,
                        "full_symbol": f"{sym.dll}!{sym.api_name}",
                        "signature": sym.signature,
                    }
                )
        else:
            matches = self._all_hashes_by_val.get(hash_val, [])
            for algo, sym in matches:
                results.append(
                    {
                        "algorithm": algo,
                        "dll": sym.dll,
                        "api_name": sym.api_name,
                        "full_symbol": f"{sym.dll}!{sym.api_name}",
                        "signature": sym.signature,
                    }
                )
        return results


# Global singleton instance
_GLOBAL_HASH_DB: ApiHashDatabase | None = None


def get_api_hash_db() -> ApiHashDatabase:
    """Retrieve the global API Hash Database instance."""
    global _GLOBAL_HASH_DB
    if _GLOBAL_HASH_DB is None:
        _GLOBAL_HASH_DB = ApiHashDatabase()
    return _GLOBAL_HASH_DB
