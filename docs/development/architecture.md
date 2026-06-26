# Architecture Guide

This document describes the design, components, and internal workflows of the Reversecore MCP platform, an integrated static and dynamic analysis server.

---

## 1. System Topology

Reversecore MCP uses a layered design. It exposes Prompts, Resources, and Tools to the client via the Model Context Protocol (stdio or HTTP transport). The core infrastructure manages validation, connection pooling, resilience wrappers, background task queues, and DB connections, delegating to specialized security engines.

```
                  ┌──────────────────────────────┐
                  │          AI Client           │
                  │  (Claude, Cursor, custom)    │
                  └──────────────┬───────────────┘
                                 │ JSON-RPC
                                 ▼
                  ┌──────────────────────────────┐
                  │    Reversecore MCP Server    │
                  │         (server.py)          │
                  ├──────────────────────────────┤
                  │                              │
                  │   Prompts        Resources   │
                  │                              │
                  │   Unified Tool Registry      │
                  │   (PluginLoader, Plugins)    │
                  │                              │
                  └──────────────┬───────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │      Core Infrastructure     │
                  │                              │
                  │  Config · Security · Resil.  │
                  │  R2 Pool · Memory (SQLite)   │
                  │  Metrics · Task Queue (arq)  │
                  └──────────────┬───────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌────────────────┐      ┌────────────────┐      ┌────────────────┐
│    Radare2     │      │   YARA / LIEF  │      │   Volatility   │
│  r2ghidra      │      │   DIE / CAPA   │      │   Scapy / TSK  │
│  (JVM-free)    │      │                │      │                │
└────────────────┘      └────────────────┘      └────────────────┘
```

---

## 2. Directory Tree

The workspace is organized into a clear boundary between core system infrastructure and modular tool packages:

```
reversecore_mcp/
├── core/                      # Infrastructure layer
│   ├── config.py              # Centralized configuration (pydantic-settings)
│   ├── exceptions.py          # Platform exceptions (RCMCP-E* error codes)
│   ├── security.py            # Sanitization and workspace path boundaries
│   ├── validators.py          # Input validation helpers
│   ├── r2_pool.py             # Thread-safe Radare2 connection pool
│   ├── r2_helpers.py          # Structured output parsing for Radare2
│   ├── metrics.py             # Tool latency and error execution metrics
│   ├── decorators.py          # @log_execution, @track_metrics wrappers
│   ├── error_handling.py      # @handle_tool_errors decorator
│   ├── error_formatting.py    # Standardized response formatters
│   ├── memory.py              # Async SQLite store for AI memory items
│   ├── mitre_mapper.py        # Maps binary capabilities to MITRE ATT&CK
│   ├── evidence.py            # Evidence engine (OBSERVED/INFERRED/POSSIBLE)
│   ├── resilience.py          # Resilient execution wrappers (timeouts, retries)
│   ├── task_queue.py          # Async background worker tasks (Redis/arq)
│   ├── extension_registry.py  # Dynamically loaded local extension tools
│   ├── loader.py              # Modularity discovery
│   └── sast/                  # C/C++ and Python code AST scanners
│
├── tools/                     # Modular tool plugins
│   ├── analysis/              # Static & binary comparison (LIEF, DIE, CAPA, angr)
│   ├── radare2/               # State/stateless Radare2 & r2ghidra pseudo-C
│   ├── malware/               # Dormant detector, YARA rules, vaccines, vulns
│   ├── forensics/             # Volatility3 RAM, Scapy PCAP, Disk/Artifacts
│   ├── report/                # Standardized report generators
│   └── common/                # File utilities and server status
│
├── prompts/                   # chain-of-thought analysis prompts
├── resources.py               # Dynamic MCP resource URIs
└── server.py                  # Server setup and tool registration entrypoint
```

---

## 3. Core Modules

### 📂 Configuration Management (`core/config.py`)

Configuration uses Pydantic Settings to load and type-validate variables from env or local `.env` files. Access the cached singleton using `get_settings()` (or `get_config()` for legacy compatibility).

### 🔒 Security Boundary (`core/security.py` & `core/validators.py`)

To prevent arbitrary execution and system compromise when analyzing malicious samples:
1. **Path Isolation**: Files are restricted to the workspace folder (`REVERSECORE_WORKSPACE`). Attempting traversal (`../../etc/passwd`) raises a `SecurityViolationError`.
2. **Subprocess Safety**: Command arguments are passed as list structures (`subprocess.run(["cmd", "arg"])`), completely avoiding `shell=True` strings to prevent shell injection.
3. **MIME Validation**: File uploads (in HTTP mode) are analyzed via libmagic headers to prevent renaming executable files to safe extensions (e.g. `malware.exe` renamed to `readme.txt`).

### ⚙️ Connection Pooling (`core/r2_pool.py`)

Spawning a new Radare2 subprocess for every command is slow. `R2Pool` holds a cache of open Radare2 processes, recycling them across tool invocations:

```python
# Acquire a radare2 wrapper from the pool
from reversecore_mcp.core.r2_pool import get_r2_pool

pool = get_r2_pool()
async with pool.acquire(file_path) as r2:
    # Executes immediately on recycled process
    funcs = r2.cmd("afl")
```

### ⚡ Resilience & Timeouts (`core/resilience.py`)

External processes can hang or crash when analyzing broken/malformed binary code. The resilience module wraps execution calls in configured timeout blocks and logs crash states without bringing down the main server process.

### 💾 Async AI Memory Store (`core/memory.py`)

AI agents can store session notes, binary offsets, and custom types inside a local SQLite database that is queried asynchronously via `aiosqlite`.

### 📊 Background Task Queue (`core/task_queue.py`)

Long-running tasks (like symbolic execution or large memory dump analysis) are offloaded to an embedded Redis-backed `arq` queue to avoid blocking the main async event loop.

---

## 4. Tool Registry & Loader

The platform uses `PluginLoader` to automatically scan subdirectories in `reversecore_mcp/tools` for classes that inherit from `Plugin`:

```python
# reversecore_mcp/core/plugin.py
class Plugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: pass

    @abstractmethod
    def register(self, mcp_server: Any) -> None: pass
```

At server startup:
1. The loader scans directories and dynamically imports modules.
2. It locates classes extending `Plugin` and instantiates them.
3. `server.py` calls `.register(mcp)` on each instance, mounting the tools to the FastMCP server.
