# Reversecore_MCP Dockerfile
# 
# This Dockerfile sets up a containerized environment for the Reversecore_MCP
# server with all required system dependencies and pinned versions for
# reproducibility.

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create workspace and rules directories
RUN mkdir -p /app/workspace /app/rules

# Install system dependencies with pinned versions for reproducibility
# Versions are pinned to ensure consistent behavior across builds
# To check available versions: apt-cache madison <package-name>
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Radare2 reverse engineering framework
    # Version: 5.8.8+dfsg-1 (Debian 12 Bookworm)
    radare2=5.8.8+dfsg-1 \
    # YARA pattern matching tool and development libraries
    # Version: 4.3.2-1 (Debian 12 Bookworm)
    yara=4.3.2-1 \
    libyara-dev=4.3.2-1 \
    # Binutils for strings command
    # Version: 2.40-2 (Debian 12 Bookworm)
    binutils=2.40-2 \
    # Binwalk for firmware analysis and file carving
    # Version: 2.3.3+dfsg-1 (Debian 12 Bookworm)
    binwalk=2.3.3+dfsg-1 \
    # Build dependencies for Python packages that may need compilation
    gcc \
    g++ \
    make \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY reversecore_mcp/ ./reversecore_mcp/

# Set Python path, workspace, and transport mode
ENV PYTHONPATH=/app \
    REVERSECORE_WORKSPACE=/app/workspace \
    MCP_TRANSPORT=http

# Expose port for HTTP transport
EXPOSE 8000

# Run the MCP server
CMD ["python", "-m", "reversecore_mcp.server"]

