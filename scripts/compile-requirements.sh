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
pip-compile --upgrade --no-build-isolation --annotation-style=line --extra=full -o requirements.txt pyproject.toml

# Post-process requirements.txt to replace the local absolute file path with relative editable path
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Remove the editable install line entirely — Docker builds copy source directly
    # so `-e .` causes failures since pyproject.toml is not available at pip-install time
    sed -i '' '/^reversecore-mcp.* @ file:\/\/\//d' requirements.txt
    sed -i '' '/^-e \./d' requirements.txt
    # Remove hiredis C extension — Docker base image has no gcc during app layer build
    sed -i '' '/^hiredis==/d' requirements.txt
    sed -i '' 's|redis\[hiredis\]|redis|g' requirements.txt
else
    sed -i '/^reversecore-mcp.* @ file:\/\/\//d' requirements.txt
    sed -i '/^-e \./d' requirements.txt
    sed -i '/^hiredis==/d' requirements.txt
    sed -i 's|redis\[hiredis\]|redis|g' requirements.txt
fi

echo "Compiling requirements-dev.txt (including dev features)..."
pip-compile --upgrade --no-build-isolation --annotation-style=line --extra=dev -o requirements-dev.txt pyproject.toml

echo "Done! requirements.txt and requirements-dev.txt compiled successfully."
