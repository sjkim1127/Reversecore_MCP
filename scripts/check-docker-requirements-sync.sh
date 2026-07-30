#!/usr/bin/env bash
# Verify that the production image installs the runtime-only manifest and that
# development tooling does not leak into the runtime dependency set.
# Package matching supports optional extras such as mcp[cli].

set -euo pipefail

runtime_manifest="requirements-runtime.txt"
all_extras_lock="requirements.txt"

echo "🔍 Checking Docker runtime dependency separation..."

if ! grep -qE 'pip install.*-r requirements-runtime\.txt' Dockerfile; then
    echo "❌ Dockerfile must install requirements-runtime.txt"
    exit 1
fi

for file in "$runtime_manifest" "$all_extras_lock"; do
    if [ ! -s "$file" ]; then
        echo "❌ Required dependency file is missing or empty: $file"
        exit 1
    fi
done

if ! grep -qE '^-c requirements\.txt$' "$runtime_manifest"; then
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

echo "✅ Docker installs runtime dependencies without development tooling"
