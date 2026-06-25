#!/usr/bin/env bash
set -euo pipefail

# Navigate to project root
cd "$(dirname "$0")/.."

# Check if virtual environment is active, if not active but .venv exists, use it
if [ -z "${VIRTUAL_ENV:-}" ] && [ -d ".venv" ]; then
    echo "Activating virtual environment (.venv)..."
    source .venv/bin/activate
fi

# Ensure pip-tools is installed
if ! command -v pip-compile &> /dev/null; then
    echo "pip-tools is not installed. Installing it now..."
    pip install pip-tools
fi

echo "Compiling requirements.txt (including full features)..."
pip-compile --annotation-style=line --extra=full -o requirements.txt pyproject.toml

# Post-process requirements.txt to replace the local absolute file path with relative editable path,
# and downgrade pillow to 10.4.0 to resolve the python-fx/qiling dependency conflict.
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' 's|reversecore-mcp.* @ file:///.*|-e .[analysis,cli,emulation,forensics,ghidra,http,magic,viz]|g' requirements.txt
    sed -i '' 's|pillow==12.2.0|pillow==10.4.0|g' requirements.txt
else
    sed -i 's|reversecore-mcp.* @ file:///.*|-e .[analysis,cli,emulation,forensics,ghidra,http,magic,viz]|g' requirements.txt
    sed -i 's|pillow==12.2.0|pillow==10.4.0|g' requirements.txt
fi

echo "Compiling requirements-dev.txt (including dev features)..."
pip-compile --annotation-style=line --extra=dev -o requirements-dev.txt pyproject.toml

echo "Done! requirements.txt and requirements-dev.txt compiled successfully."
