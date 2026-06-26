# Installation

This guide covers setting up Reversecore MCP either inside a pre-built Docker container or natively on your system.

---

## Prerequisites

### Local Installation Requirements

If you run the server natively without Docker:

- **Python**: 3.10, 3.11, or 3.12.
- **Radare2**: The core disassembly/emulation engine (`radare2` must be available in your system `PATH`).
- **YARA**: Automated malware signature engine (installed automatically via `yara-python`).
- **Graphviz** (Optional): Required if you plan to generate visual PNG/SVG control flow graphs.
- **Java 11+** (Optional): Only required if you write or load custom Java-based Ghidra scripting extensions. Core pseudo-C decompilation is done via native `r2ghidra` and does **NOT** require a Java Virtual Machine (JVM).

---

## Method 1: Docker (Recommended)

Using Docker is the easiest way to run the server. It packages all dependencies (Python, Radare2, native YARA, and `r2ghidra` plugin) into a single, clean sandbox.

### 1. Run Pre-built Image from GHCR

Pull and run the multi-architecture image (supports both AMD64 and ARM64 / Apple Silicon):

```bash
# Run container in standard interactive stdio mode
docker run -i --rm \
  -v /path/to/your/samples:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  -e MCP_TRANSPORT=stdio \
  ghcr.io/sjkim1127/reversecore_mcp:latest
```

### 2. Build or Run from Source (via scripts)

We provide helper scripts that auto-detect your processor architecture (Intel/Apple Silicon) and run the correct profile:

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP

# Run script (handles arm64 vs x86 automatically)
./scripts/run-docker.sh
```

Or run via Docker Compose manually:

```bash
# On Intel/AMD (x86_64):
docker compose --profile x86 up -d

# On Apple Silicon (M1/M2/M3/ARM64):
docker compose --profile arm64 up -d
```

---

## Method 2: Manual / Native Installation

If you prefer to run the server directly on your host machine:

### 1. Clone the Repository

```bash
git clone https://github.com/sjkim1127/Reversecore_MCP.git
cd Reversecore_MCP
```

### 2. Set Up a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt   # Required for development/testing
```

### 4. Install System Utilities

#### 🍎 macOS (using Homebrew)

```bash
brew install radare2 graphviz
```

#### 🐧 Ubuntu / Debian

```bash
sudo apt-get update
sudo apt-get install -y radare2 graphviz
```

#### 🪟 Windows

1. Download and install [Radare2 Windows installer or zip](https://github.com/radareorg/radare2/releases). Add the installation path to your system `Path` environment variable.
2. Download and install [Graphviz for Windows](https://graphviz.org/download/). Add its `bin` directory to system `Path`.

---

## Verification

To verify that your installation is functional and all dependencies are correctly located:

```bash
# Check system dependencies
radare2 -v
dot -V

# Run unit tests to check the python environment
pytest tests/unit/ -v
```
