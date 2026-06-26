#!/bin/bash
set -e
DIE_VERSION="3.10"
if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ]; then
    echo "Downloading Detect-It-Easy $DIE_VERSION for amd64..."
    wget -qO /tmp/die.deb "https://github.com/horsicq/DIE-engine/releases/download/$DIE_VERSION/die_${DIE_VERSION}_Debian_12_amd64.deb"
    sudo dpkg -i /tmp/die.deb || sudo apt-get install -f -y
    rm /tmp/die.deb
else
    echo "Warning: Detect-It-Easy pre-compiled binary is not available for ARM64 on Linux via GitHub releases."
    echo "Using strings-based fallback or please compile from source."
fi
