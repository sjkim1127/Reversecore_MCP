# Reversecore MCP

<!-- mcp-name: io.github.sjkim1127/reversecore-mcp -->

**Security-first Model Context Protocol server for reverse engineering, malware analysis, digital forensics, vulnerability research, and SAST.**

Reversecore MCP gives MCP-compatible AI agents structured access to Radare2, r2ghidra, YARA, LIEF, Capstone, angr, Qiling harness generation, Volatility3, Scapy, and additional analysis engines. It is designed around explicit workspace boundaries, input validation, non-root containers, and security regression testing.

## Installation

### Full container image — recommended

The container image includes the supported native toolchain and is the most reproducible installation method:

```bash
docker run -i --rm \
  -v /absolute/path/to/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:3.0.2
```

### Python package

Install the MCP server and all supported Python feature extras from PyPI:

```bash
pip install "reversecore-mcp[full]"
```

Native programs such as Radare2, YARA, Graphviz, Binwalk, and The Sleuth Kit must be installed separately when using the Python package directly.

> **Qiling isolation:** the server can generate Qiling/AFL harnesses, but Qiling is intentionally not installed by the `full` extra. Qiling 1.4.6 depends on a legacy Pillow line with known vulnerabilities. Execute generated harnesses only in a separate disposable sandbox; see `docs/EMULATION.md` in the repository.

Run the stdio server with:

```bash
MCP_TRANSPORT=stdio \
REVERSECORE_WORKSPACE=/absolute/path/to/samples \
reversecore-mcp
```

## MCP client configuration

```json
{
  "mcpServers": {
    "reversecore": {
      "command": "reversecore-mcp",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "REVERSECORE_WORKSPACE": "/absolute/path/to/samples"
      }
    }
  }
}
```

## Capabilities

- Static analysis, disassembly, decompilation, cross-references, and CFG recovery
- Malware triage, IOC extraction, YARA scanning, and MITRE ATT&CK mapping
- Symbolic execution, emulation harness generation, fuzzing, and ROP analysis
- Memory, disk, network, and host-artifact forensics
- Python and C/C++ source-code security analysis
- Structured evidence, session tracking, metrics, and report generation

## Security model

Reversecore MCP processes potentially hostile binaries. Use a dedicated workspace and prefer the hardened container configuration for untrusted samples. The project CI includes dependency auditing, CodeQL, secret scanning, container scanning, path-boundary tests, fuzzing, and network-isolation checks.

Detailed configuration, tool documentation, Docker Compose profiles, and client examples are available in the [GitHub repository](https://github.com/sjkim1127/Reversecore_MCP).

## Registry identity

- MCP Registry name: `io.github.sjkim1127/reversecore-mcp`
- PyPI package: `reversecore-mcp`
- OCI image: `ghcr.io/sjkim1127/reversecore_mcp`

## License

MIT
