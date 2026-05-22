#!/usr/bin/env bash
# Verify that packages installed in Dockerfile match requirements.txt

set -euo pipefail

echo "🔍 Checking Dockerfile vs requirements.txt sync..."

# Extract pip install lines from Dockerfile
docker_pkgs=$(grep -oE 'pip install [^;]+' Dockerfile | grep -oE '\b[a-zA-Z0-9_-]+==[0-9.]+' | sort -u || true)

# Extract pinned packages from requirements.txt
req_pkgs=$(grep -E '^[a-zA-Z0-9_-]+==[0-9.]+' requirements.txt | sort -u || true)

mismatch=0

# Check Dockerfile packages exist in requirements.txt
while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    name=$(echo "$pkg" | cut -d= -f1)
    if ! grep -qE "^${name}==" requirements.txt; then
        echo "⚠️  $name (from Dockerfile) not found in requirements.txt"
        mismatch=1
    fi
done <<< "$docker_pkgs"

# Check critical packages in requirements.txt exist in Dockerfile
while IFS= read -r pkg; do
    [ -z "$pkg" ] && continue
    name=$(echo "$pkg" | cut -d= -f1)
    if ! grep -qE "pip install .*${name}" Dockerfile; then
        echo "⚠️  $name (from requirements.txt) not explicitly installed in Dockerfile"
        mismatch=1
    fi
done <<< "$req_pkgs"

if [ "$mismatch" -eq 0 ]; then
    echo "✅ Dockerfile and requirements.txt are in sync"
else
    echo "⚠️  Some package mismatches found (informational)"
fi

exit 0
