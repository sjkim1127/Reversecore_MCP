# Reversecore_MCP — Application Image
#
# Inherits all pre-built tooling (YARA, radare2, r2ghidra, Python venv)
# from the base image. This stage ONLY adds application source code.
#
# Cold build time (code-only change): ~30–60 seconds
# Base image rebuild (tool or dependency-lock change): ~12 minutes (rare, done separately)
#
# Base images are built by the `build-base-image` GitHub Actions job. Local builds
# use the versioned tag; CI passes the published manifest digest as BASE_REF.
#
# Supported Features:
# - Basic Analysis: file, strings, binwalk
# - Disassembly & Analysis: radare2 (pdf, afl, ii, iz, etc.)
# - CFG Visualization: radare2 agfj + graphviz
# - ESIL Emulation: radare2 aei/aeim/aes
# - Smart Decompile: r2ghidra (primary, no JVM) and radare2 pdc (fallback)
# - YARA Rule Generation & Pattern Matching
# - Multi-arch Disassembly: Capstone
# - Binary Parsing: LIEF (PE/ELF/Mach-O)
# - FastMCP Advanced: Progress, Logging, Image Content, Dynamic Resources, Sampling

ARG BASE_IMAGE=ghcr.io/sjkim1127/reversecore_mcp/base
ARG BASE_TAG=yara4.3.1-r2-6.0.4-r2ghidra-v7
ARG BASE_REF=${BASE_IMAGE}:${BASE_TAG}
FROM ${BASE_REF}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

LABEL org.opencontainers.image.title="Reversecore MCP" \
      org.opencontainers.image.description="Security-first MCP server for reverse engineering and malware analysis" \
      org.opencontainers.image.source="https://github.com/sjkim1127/Reversecore_MCP" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.sjkim1127/reversecore-mcp"

# ── Application code ─────────────────────────────────────────────────────────
# Ordered from least-frequently-changed to most-frequently-changed
# so Docker layer cache is invalidated as rarely as possible.

WORKDIR /app

# Static resources (AI knowledge base, report templates)
COPY resources/  /app/resources/
COPY templates/  /app/templates/

# Install current Debian security updates for packages inherited from the base
# image. The versioned base image already contains the complete hash-locked
# Python environment; keeping pip out of the runtime image avoids shipping its
# vendored dependencies.
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
        curl libcurl3-gnutls libcurl4 libgraphite2-3 liblzma5 xz-utils libgd3 libssh2-1 libaom3 libpcre2-8-0 libde265-0 libssl3 openssl \
    && rm -rf /var/lib/apt/lists/*

# Application source (invalidates on every code change)
COPY scripts/            ./scripts/
COPY reversecore_mcp/    ./reversecore_mcp/

# Switch to non-root user (already created in base image)
USER appuser

EXPOSE 8000

# Stdio is the default transport and does not open a TCP listener. Treat it as
# healthy immediately; in HTTP mode, verify that the configured port accepts a
# local connection.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import os, socket; mode = os.getenv('MCP_TRANSPORT', 'stdio').lower(); mode == 'stdio' or socket.create_connection(('127.0.0.1', int(os.getenv('MCP_PORT', '8000'))), 5).close()" || exit 1

CMD ["python", "-m", "reversecore_mcp.server"]
