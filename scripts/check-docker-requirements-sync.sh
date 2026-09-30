#!/usr/bin/env bash
# Verify that the versioned base image installs the hash-locked Python
# environment and that the application image does not need a package installer.
# Package matching supports optional extras such as mcp[cli].

set -euo pipefail

runtime_manifest="requirements-runtime.txt"
runtime_source="requirements-runtime.in"
all_extras_lock="requirements.txt"

echo "🔍 Checking Docker base dependency and installer policy..."

if ! grep -qE 'pip install --require-hashes -r requirements\.txt' Dockerfile.base; then
    echo "❌ Dockerfile.base must install the all-extras hash-locked requirements"
    exit 1
fi

if ! grep -qE 'pip uninstall --yes pip' Dockerfile.base; then
    echo "❌ Dockerfile.base must remove pip from the runtime virtualenv"
    exit 1
fi

if grep -qE 'pip install.*-r requirements-runtime\.txt' Dockerfile; then
    echo "❌ Dockerfile must not reinstall Python dependencies into the runtime image"
    exit 1
fi

for file in "$runtime_manifest" "$all_extras_lock"; do
    if [ ! -s "$file" ]; then
        echo "❌ Required dependency file is missing or empty: $file"
        exit 1
    fi
done

if ! grep -qE '^-c requirements\.txt$' "$runtime_source"; then
    echo "❌ Runtime manifest must constrain versions with requirements.txt"
    exit 1
fi

required_runtime=(
    mcp
    fastmcp
    fastapi
    r2pipe
    yara-python
    lief
    capstone
)

for package in "${required_runtime[@]}"; do
    if ! grep -qiE "^[[:space:]]*${package}(\\[[^]]+\\])?([<>=!~;[:space:]]|$)" "$runtime_manifest"; then
        echo "❌ Runtime manifest is missing required package: $package"
        exit 1
    fi
done

dev_only=(pytest black ruff mypy mkdocs pip-tools hypothesis)
for package in "${dev_only[@]}"; do
    if grep -qiE "^[[:space:]]*${package}(\\[[^]]+\\])?([<>=!~;[:space:]]|$)" "$runtime_manifest"; then
        echo "❌ Development dependency leaked into runtime manifest: $package"
        exit 1
    fi
done

echo "✅ Base image installs pinned Python dependencies and ships without pip"
