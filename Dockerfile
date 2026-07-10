# Reversecore_MCP — Application Image
#
# Inherits all pre-built tooling (YARA, radare2, Ghidra, JDK, Python venv)
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
# - Smart Decompile: Ghidra DecompInterface (primary), radare2 pdc (fallback)
# - YARA Rule Generation & Pattern Matching
# - Multi-arch Disassembly: Capstone
# - Binary Parsing: LIEF (PE/ELF/Mach-O)
# - FastMCP Advanced: Progress, Logging, Image Content, Dynamic Resources, Sampling

ARG BASE_IMAGE=ghcr.io/sjkim1127/reversecore_mcp/base
ARG BASE_TAG=latest
FROM ${BASE_IMAGE}:${BASE_TAG}

# ── Application code ─────────────────────────────────────────────────────────
# Ordered from least-frequently-changed to most-frequently-changed
# so Docker layer cache is invalidated as rarely as possible.

WORKDIR /app

# Static resources (AI knowledge base, report templates)
COPY resources/  /app/resources/
COPY templates/  /app/templates/

# Install python dependencies that might have updated in requirements.txt
COPY requirements.txt    ./
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ make python3-dev libc-dev \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc g++ make python3-dev libc-dev \
    && rm -rf /var/lib/apt/lists/*


# Application source (invalidates on every code change)
COPY server.py           ./
COPY scripts/            ./scripts/
COPY reversecore_mcp/    ./reversecore_mcp/

# Switch to non-root user (already created in base image)
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8000)); s.close()" || exit 1

CMD ["python", "server.py"]
