# Reversecore_MCP Dockerfile with Multi-stage Build
#
# This Dockerfile uses a multi-stage build to reduce final image size and improve security.
# Build stage includes compilation tools, while runtime stage only contains necessary dependencies.
#
# Framework: FastMCP v2.13.1+ (Latest MCP server framework)
#
# Note: radare2 is not available in Debian Bookworm main repo, so we skip version pinning for it
# or install it from testing/backports if needed.
#
# Supported Features:
# - Basic Analysis: file, strings, binwalk
# - Disassembly & Analysis: radare2 (pdf, afl, ii, iz, etc.)
# - CFG Visualization: radare2 agfj (graph JSON) + graphviz (PNG generation)
# - ESIL Emulation: radare2 aei/aeim/aes (virtual CPU)
# - Smart Decompile: Ghidra DecompInterface (primary), radare2 pdc (fallback)
# - YARA Rule Generation: radare2 p8 (opcode extraction)
# - Symbolic Execution: angr (path constraint solving)
# - Pattern Matching: YARA scanning
# - Multi-arch Disassembly: Capstone
# - Binary Parsing: LIEF (PE/ELF/Mach-O)
# - FastMCP Advanced: Progress Reporting, Client Logging, Image Content, Dynamic Resources, AI Sampling

# ============================================================================
# Build Stage: Install dependencies that require compilation
# ============================================================================
FROM python:3.14-slim-bookworm AS builder
ARG TARGETARCH
ARG YARA_VERSION=4.3.1
ARG RADARE2_VERSION=6.0.4
ARG GHIDRA_VERSION=11.4.2
ARG GHIDRA_DATE=20250826

# Set working directory
WORKDIR /app

# Install build dependencies for Python packages that may need compilation
# These will NOT be included in the final image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    automake \
    autoconf \
    libtool \
    pkg-config \
    flex \
    bison \
    libssl-dev \
    libffi-dev \
    git \
    patch \
    xz-utils \
    curl \
    ca-certificates \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Build and install native YARA matching the pinned Python binding (4.3.1)
RUN curl -sSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" -o /tmp/yara.tar.gz \
    && tar -xzf /tmp/yara.tar.gz -C /tmp \
    && cd /tmp/yara-${YARA_VERSION} \
    && ./bootstrap.sh \
    && ./configure --disable-cuckoo --disable-magic --disable-dotnet \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/yara*

# Build radare2 from source to ensure availability on Debian bookworm
# Radare2 provides comprehensive reverse engineering capabilities:
# - Standard disassembly (pdf, pd)
# - Control Flow Graph generation (agfj)
# - ESIL emulation engine (aei, aeim, aes, ar)
# - Pseudo-C decompilation (pdc)
# - Binary analysis (aaa, afl, afi)
# - String and import extraction (iz, ii)
# - Hex dump and byte printing (px, p8)
RUN curl -sSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-${RADARE2_VERSION}.tar.xz" -o /tmp/radare2.tar.xz \
    && tar -xJf /tmp/radare2.tar.xz -C /tmp \
    && cd /tmp/radare2-${RADARE2_VERSION} \
    && ./configure --prefix=/opt/radare2 \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/radare2*

# Download and install Ghidra for enhanced decompilation
# Ghidra provides industry-standard decompilation with better type recovery
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    # Remove unnecessary components to reduce image size
    && rm -rf /opt/ghidra/docs \
    && rm -rf /opt/ghidra/Extensions/Eclipse \
    && rm -rf /opt/ghidra/Extensions/sample

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies into a virtual environment
# Using a venv makes it easy to copy only the installed packages to the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Conditional install for ARM64 (skip incompatible packages like angr if needed)
# For now we install standard requirements as angr support improves
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Runtime Stage: Create minimal production image
# ============================================================================
FROM python:3.14-slim-bookworm

# Set working directory
WORKDIR /app

# Create workspace and rules directories
RUN mkdir -p /app/workspace /app/rules

# Install only runtime dependencies (no build tools)
# Versions are pinned to ensure consistent behavior across builds
# To check available versions: apt-cache madison <package-name>
#
# Note: radare2 is built in the builder stage to guarantee availability on bookworm.
# Note: OpenJDK 21 is installed from Adoptium (Eclipse Temurin) for Ghidra 11.4+ compatibility
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    # coreutils "file" command required by run_file tool
    file \
    # Binutils for strings command
    binutils \
    # Binwalk for firmware analysis and file carving
    binwalk \
    # Graphviz for CFG image generation (FastMCP Image support)
    graphviz \
    # Required for Adoptium GPG key
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install Eclipse Temurin (Adoptium) OpenJDK 21 for Ghidra 11.4+
# Ghidra 11.4.2 requires Java 21+ JDK (not just JRE - needs javac for some operations)
RUN wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor -o /usr/share/keyrings/adoptium.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb bookworm main" > /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME environment variable (required for PyGhidra to find Java 21 JDK)
ENV JAVA_HOME="/usr/lib/jvm/temurin-21-jdk-hotspot"
# Note: Debian adoptium package usually links to -hotspot suffix regardless of arch,
# or we can rely on standard java in path.
# Updating PATH guarantees java works.

# Copy native tooling built in the builder stage so CLI tools match Python bindings
RUN mkdir -p /usr/local/include /usr/local/lib/pkgconfig
COPY --from=builder /usr/local/bin/yara /usr/local/bin/yara
COPY --from=builder /usr/local/bin/yarac /usr/local/bin/yarac
COPY --from=builder /usr/local/lib/libyara* /usr/local/lib/
COPY --from=builder /usr/local/include/yara /usr/local/include/yara
COPY --from=builder /usr/local/lib/pkgconfig/yara.pc /usr/local/lib/pkgconfig/yara.pc
COPY --from=builder /opt/radare2 /opt/radare2
COPY --from=builder /opt/ghidra /opt/ghidra
RUN echo "/opt/radare2/lib" > /etc/ld.so.conf.d/radare2.conf && ldconfig

# Copy Python virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY reversecore_mcp/ ./reversecore_mcp/
COPY server.py ./

# Copy resources (AI knowledge base)
COPY resources/ /app/resources/

# Copy templates (Report templates)
COPY templates/ /app/templates/


# Set Python path to use the venv and configure application
ENV PATH="/opt/radare2/bin:/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    REVERSECORE_WORKSPACE=/app/workspace \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    MCP_TRANSPORT=http \
    LOG_LEVEL=INFO \
    LOG_FILE=/var/log/reversecore/app.log \
    MEMORY_DB_PATH=/app/workspace/.memory.db \
    RATE_LIMIT=60

# Create log directory and non-root user
RUN mkdir -p /var/log/reversecore && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app /var/log/reversecore
USER appuser

# Expose port for HTTP transport
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8000)); s.close()" || exit 1

# Run the MCP server
CMD ["python", "server.py"]
