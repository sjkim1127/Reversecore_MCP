#!/usr/bin/env bash
set -euo pipefail

# Navigate to project root
cd "$(dirname "$0")/.."

# Check if virtual environment is active, if not active but .venv exists, use it
if [ -z "${VIRTUAL_ENV:-}" ] && [ -d ".venv" ]; then
    echo "Activating virtual environment (.venv)..."
    # shellcheck source=/dev/null
    source .venv/bin/activate
fi

# Lock generation is itself a development dependency. Do not install an
# unpinned copy of the compiler while generating the dependency locks.
if ! command -v uv &> /dev/null; then
    echo "uv is not installed. Install the development dependencies first." >&2
    exit 1
fi

echo "Compiling requirements.txt (all extras, including development tools)..."
# Resolve from the minimum supported Python version so marker-gated tools such
# as angr remain excluded from Python 3.10/3.11 installs in the universal lock.
# uv preserves compatible pins already in requirements.txt and resolves any
# package whose locked version no longer satisfies pyproject.toml.
uv pip compile --quiet --all-extras --generate-hashes --universal --python-version 3.10 \
    --output-file requirements.txt pyproject.toml

# Post-process requirements.txt to replace the local absolute file path with relative editable path
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Remove the editable install line entirely — Docker builds copy source directly
    # so `-e .` causes failures since pyproject.toml is not available at pip-install time
    sed -i '' '/^reversecore-mcp.* @ file:\/\/\//d' requirements.txt
    sed -i '' '/^-e \./d' requirements.txt
else
    sed -i '/^reversecore-mcp.* @ file:\/\/\//d' requirements.txt
    sed -i '/^-e \./d' requirements.txt
fi

echo "Compiling runtime-only lock..."
uv pip compile --quiet --generate-hashes --universal --python-version 3.10 \
    --output-file requirements-runtime.txt requirements-runtime.in

echo "Compiling core package lock..."
uv pip compile --quiet --generate-hashes --universal --python-version 3.10 \
    --constraint requirements.txt --output-file requirements-core.txt pyproject.toml

echo "Compiling base-image Python toolchain lock..."
uv pip compile --quiet --generate-hashes --universal --python-version 3.10 \
    --output-file requirements-toolchain.txt requirements-toolchain.in

echo "Compiling release-validation tools lock..."
uv pip compile --quiet --generate-hashes --universal --python-version 3.10 \
    --output-file requirements-release.txt requirements-release.in

echo "Compiling isolated Qiling integration-test lock..."
uv pip compile --quiet --generate-hashes --universal --python-version 3.10 \
    --output-file requirements-qiling.txt requirements-qiling.in

echo "Done! All dependency locks were compiled with artifact hashes."
