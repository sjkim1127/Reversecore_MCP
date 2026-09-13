# Troubleshooting Runbook

Use this order so that environment, transport, permissions, and tool-specific
failures are separated quickly.

## 1. Confirm the exact installation

Run from the checkout or virtual environment that starts the server:

```bash
python --version
python -m pip check
python -c 'import reversecore_mcp; print(reversecore_mcp.__file__)'
python scripts/check_release_metadata.py
```

The supported Python versions are 3.10, 3.11, and 3.12. If `pip check`
reports packages from an unrelated application, reproduce the issue in a new
virtual environment before changing the project lock files.

## 2. Confirm external analysis tools

```bash
command -v radare2 && radare2 -v
command -v yara && yara --version
command -v dot && dot -V
```

Radare2 is required for Radare2-backed analysis. Graphviz is only required for
rendered CFG output. Missing optional tools should produce a structured tool
error or a documented unavailable result; they should not make the server
process crash.

For the packaged environment, use:

```bash
./scripts/verify-tools.sh
docker compose config
```

## 3. Confirm workspace and permissions

```bash
python -c 'from pathlib import Path; import os; p=Path(os.environ["REVERSECORE_WORKSPACE"]); print(p.resolve()); print(os.access(p, os.R_OK), os.access(p, os.W_OK))'
```

Check that the target file is inside `REVERSECORE_WORKSPACE` or one of the
explicit `REVERSECORE_READ_DIRS`. Do not disable strict path validation to work
around a path error without recording the reason.

## 4. Confirm MCP transport

For stdio clients, verify that stdout is reserved for MCP protocol messages and
that diagnostic logs go to stderr. For HTTP mode, verify the configured bind
address and port:

```bash
MCP_TRANSPORT=http python server.py
curl -i http://127.0.0.1:8000/health
```

If `MCP_API_KEY` is set, include `X-API-Key` in the request. When running
behind a proxy, preserve the MCP session and streaming response headers.

## 5. Collect a reproducible diagnostic bundle

Use JSON logs and capture the correlation ID for the failed call:

```bash
LOG_FORMAT=json LOG_LEVEL=INFO python server.py 2>reversecore.log
python -m pip freeze > reversecore-environment.txt
git rev-parse HEAD > reversecore-revision.txt
```

Include the tool name, correlation ID, input file hash (not the file itself
unless authorized), Python version, operating system, and the complete
structured error. Redact API keys, credentials, and sensitive sample paths.

For a local regression report, run:

```bash
pytest tests/unit/ -v --tb=short
pytest tests/security/ -m security -v --tb=short
python scripts/check_api_schema.py
```

## 6. Interpret common failures

| Symptom | Likely cause | Next check |
|---|---|---|
| `ValidationError` / `RCMCP-E001` | Invalid path or request field | Workspace, allowed directories, and tool schema |
| Timeout error | External tool or binary exceeds configured limit | `REVERSECORE_DEFAULT_TOOL_TIMEOUT`, file size, and correlation ID |
| `radare2 not found` | Missing host binary or PATH mismatch | `command -v radare2`; use the Docker image |
| YARA unavailable | Optional native binding or rule error | `python -c 'import yara; print(yara.__version__)'` and validate the rule |
| Empty or partial output | Tool failure or output-size limit | JSON log error details and tool-specific timeout/output settings |
| HTTP 401/403 | API key or proxy authentication mismatch | `MCP_API_KEY` and `X-API-Key` header |

When opening an issue, attach the redacted diagnostic bundle and the exact
command used. Never attach malware samples, credentials, or private binaries
without explicit authorization.
