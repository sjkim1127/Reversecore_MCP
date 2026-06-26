# Configuration

Reversecore MCP is configured using environment variables. When the server boots, it uses Pydantic Settings to load, validate, and type-convert these variables. You can also place them in a `.env` file in the directory where you start the server.

---

## Environment Variables

### 📂 Workspace & File Security

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `REVERSECORE_WORKSPACE` | Current directory | The path to the root folder where binaries can be read, written, and analyzed. |
| `REVERSECORE_READ_DIRS` | Empty | A comma-separated list of additional directories that the server is allowed to read from (read-only). |
| `REVERSECORE_STRICT_PATHS` | `false` | If enabled (`true`), the server will raise validation errors and refuse to startup if the workspace directory does not exist. |
| `FILE_RETENTION_MINUTES` | `1440` (24 hours) | The duration in minutes after which temporary uploads and session files will be automatically reaped. |
| `MAX_UPLOAD_SIZE` | `100000000` (100MB) | Maximum file size in bytes allowed for the `/upload` endpoint (HTTP mode). |

### 📝 Server & Transport

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | Transport protocol to use: `stdio` (standard input/output, for Cursor/Claude Desktop) or `http` (SSE-based HTTP server). |
| `MCP_HOST` | `0.0.0.0` | Bind IP interface for the HTTP server. |
| `MCP_PORT` | `8000` | Port on which the HTTP server listens. |
| `MCP_API_KEY` | *(unset)* | An API key used to protect HTTP endpoints. If set, clients must include the header `X-API-Key: <key>` or query param `api_key=<key>`. |
| `REVERSECORE_RATE_LIMIT` | `60` | Maximum requests allowed per minute per client in HTTP transport mode. |

### 🔍 Logging & Error Handling

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Output logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `LOG_FILE` | `<tempdir>/reversecore/app.log` | Location of the application log file. |
| `LOG_FORMAT` | `human` | Formatter style: `human` (console colorized log strings) or `json` (structured JSON logging for Elastic/Splunk ingestion). |
| `REVERSECORE_STRUCTURED_ERRORS` | `false` | If enabled (`true`), error responses will contain specific code identifiers (e.g. `RCMCP-E001`) and context detail structures. |

### ⚙️ Engine Settings

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `REVERSECORE_DEFAULT_TOOL_TIMEOUT` | `120` | Default timeout in seconds for executing external CLI commands (e.g., `file`, `strings`, `yara`). |
| `REVERSECORE_R2_POOL_SIZE` | `3` | Number of concurrent Radare2 subprocess connections to keep open in the thread pool. |
| `REVERSECORE_R2_POOL_TIMEOUT` | `30` | Timeout in seconds to wait for acquiring an idle Radare2 connection from the pool. |
| `REVERSECORE_LIEF_MAX_FILE_SIZE` | `1000000000` (1GB) | Safety limit in bytes for files parsed by the LIEF parser. |
| `MAX_EMULATION_INSTRUCTIONS` | `1000` | Safety limit on instructions to execute during Radare2 ESIL emulation. |
| `REVERSECORE_GHIDRA_MAX_PROJECTS` | `3` | Maximum number of Ghidra projects to cache for multi-malware analysis. |

### 💾 Memory & Queue Infrastructure

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `MEMORY_DB_PATH` | `~/.reversecore_mcp/memory.db` | The path to the SQLite database file where AI agent memory items are stored. |
| `REDIS_URL` | `redis://localhost:6379/0` | Connection URL for Redis, used for background task queues (arq) and result caching. |

### 🔌 Extension Plugins

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `REVERSECORE_PLUGIN_DIRS` | Empty | A comma-separated list of directories to scan for local extension plugins. Each `.py` file is scanned for `R2ExtensionPoint`/`GhidraExtensionPoint` subclasses. |
| `REVERSECORE_SAST_RULES_PATH` | Empty | Path to a custom YAML file defining SAST rules for source auditing. |
| `REVERSECORE_R2_EXTENSIONS` | Empty | Comma-separated list of R2 extension classes in `module:ClassName` format. |
| `REVERSECORE_GHIDRA_EXTENSIONS` | Empty | Comma-separated list of Ghidra extension classes in `module:ClassName` format. |

---

## Example Configurations

### 1. Simple Cursor/Desktop Local Setup (`.env`)

For standard local usage integrated with Cursor or Claude Desktop (stdio mode):

```ini
REVERSECORE_WORKSPACE=/Users/yourname/security_analysis
LOG_LEVEL=INFO
LOG_FORMAT=human
MCP_TRANSPORT=stdio
```

### 2. Enterprise Remote Server Setup (`.env`)

For running a centralized HTTP SSE service behind a reverse proxy:

```ini
REVERSECORE_WORKSPACE=/var/lib/reversecore/workspace
REVERSECORE_STRICT_PATHS=true
LOG_LEVEL=WARNING
LOG_FORMAT=json
MCP_TRANSPORT=http
MCP_HOST=127.0.0.1
MCP_PORT=8080
MCP_API_KEY=K8s_secret_generated_key_12345
REVERSECORE_RATE_LIMIT=150
REDIS_URL=redis://redis-server:6379/1
```
