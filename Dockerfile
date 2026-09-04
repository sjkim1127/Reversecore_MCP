# Reversecore_MCP — Application Image
#
# Inherits all pre-built tooling (YARA, radare2, r2ghidra, Python venv)
# from the base image. This stage ONLY adds application source code.
#
# Cold build time (code-only change): ~30–60 seconds
# Base image rebuild (tool version change): ~12 minutes (rare, done separately)
#
# Base image is built by the `build-base-image` GitHub Actions job and stored
# at ghcr.io/sjkim1127/reversecore-mcp/base:<VERSION_TAG>
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
ARG BASE_TAG=latest
FROM ${BASE_IMAGE}:${BASE_TAG}

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
# image, then install only production/runtime Python dependencies. The complete
# all-extras lock remains available as a constraints source so runtime versions
# stay aligned with CI without installing pytest, linters, or documentation tools.
COPY requirements.txt         ./
COPY requirements-runtime.txt ./
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade curl libcurl3-gnutls libcurl4 libgraphite2-3 liblzma5 xz-utils libgd3 \
    && apt-get install -y --no-install-recommends gcc g++ make python3-dev libc-dev \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade "pip>=26.2.0" "setuptools>=83.0.0" "msgpack>=1.2.1" \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements-runtime.txt \
    && apt-get purge -y --auto-remove gcc g++ make python3-dev libc-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip* \
              /usr/local/lib/python3.12/site-packages/setuptools* \
              /usr/local/lib/python3.12/site-packages/msgpack* \
              /root/.cache \
    && find / -name "*msgpack-1.1*" -exec rm -rf {} + 2>/dev/null || true \
    && find / -name "*pip-26.1*" -exec rm -rf {} + 2>/dev/null || true \
    && find / -name "*setuptools-70*" -exec rm -rf {} + 2>/dev/null || true

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
