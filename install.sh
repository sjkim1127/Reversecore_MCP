#!/usr/bin/env bash
# ==============================================================================
# Reversecore_MCP One-line Installer & Setup Wizard
#
# Usage:
#   curl -fsSL https://reversecore.ai/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/sjkim1127/Reversecore_MCP/main/install.sh | bash
#   ./install.sh [options]
#
# Supported Options:
#   --all         Configure all detected clients automatically
#   --clients     Comma-separated client list (cursor, claude_code, windsurf, etc.)
#   --docker      Use Docker container mode
#   --uvx         Use uvx runner mode
#   --pipx        Use pipx runner mode
#   --tiered      Enable Tiered Tools / Agents Mode (15 tools, >90% lower LLM context tokens)
#   --dry-run     Preview configuration changes without writing
#   --remove      Unregister Reversecore_MCP from clients
#   --list        List detected clients and exit
# ==============================================================================

set -euo pipefail

# Print banner
print_banner() {
    cat << 'EOF'
========================================================================
   ____                                                     __  __  ____ ____
  / __ \___ _   _____  _____________  _________  ________  /  |/  // ___// __ \
 / /_/ / _ \ | / / _ \/ ___/ ___/ _ \/ ___/ __ \/ ___/ _ \/ /|_/ / / /   / /_/ /
/ _, _/  __/ |/ /  __/ /  (__  )  __/ /__/ /_/ / /  /  __/ /  / / / /___/ ____/
/_/ |_|\___/|___/\___/_/  /____/\___/\___/\____/_/   \___/_/  /_/  \____/_/
           Reversecore_MCP One-line Installer & Setup Wizard
========================================================================
EOF
}

# Restore standard input from controlling terminal when script is piped (curl | bash)
restore_tty() {
    if [ ! -t 0 ] && [ -e /dev/tty ]; then
        exec 0< /dev/tty
    fi
}

# Find suitable Python 3.10+ executable
find_python() {
    local candidate
    for candidate in python3 python python3.12 python3.11 python3.10; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
                command -v "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

main() {
    restore_tty

    # If running inside a local git clone with reversecore_mcp available
    if [ -f "reversecore_mcp/setup.py" ]; then
        if [ -x "venv/bin/python" ]; then
            exec venv/bin/python -m reversecore_mcp.setup "$@"
        elif [ -x ".venv/bin/python" ]; then
            exec .venv/bin/python -m reversecore_mcp.setup "$@"
        else
            local local_py
            if local_py="$(find_python)"; then
                exec "$local_py" -m reversecore_mcp.setup "$@"
            fi
        fi
    fi

    # If reversecore-mcp binary is already installed and in PATH
    if command -v reversecore-mcp >/dev/null 2>&1; then
        exec reversecore-mcp setup "$@"
    fi

    # If uvx is available
    if command -v uvx >/dev/null 2>&1; then
        echo "🚀 Running Reversecore setup via uvx..."
        exec uvx --from reversecore-mcp reversecore-setup "$@"
    fi

    # If pipx is available
    if command -v pipx >/dev/null 2>&1; then
        echo "🚀 Running Reversecore setup via pipx..."
        exec pipx run reversecore-mcp setup "$@"
    fi

    # Fallback: check for Python 3.10+ and install in an isolated user environment
    local py_bin
    if py_bin="$(find_python)"; then
        local install_dir="$HOME/.reversecore-mcp"
        local venv_dir="$install_dir/venv"

        echo "📦 Installing Reversecore_MCP into isolated environment: $venv_dir"
        mkdir -p "$install_dir"
        if [ ! -d "$venv_dir" ]; then
            "$py_bin" -m venv "$venv_dir"
        fi

        echo "⬇️  Fetching reversecore-mcp package..."
        "$venv_dir/bin/pip" install --upgrade --quiet pip reversecore-mcp

        # Try to symlink executable to ~/.local/bin if directory exists or is in PATH
        if [ -d "$HOME/.local/bin" ]; then
            ln -sf "$venv_dir/bin/reversecore-mcp" "$HOME/.local/bin/reversecore-mcp" || true
            ln -sf "$venv_dir/bin/reversecore-setup" "$HOME/.local/bin/reversecore-setup" || true
        fi

        exec "$venv_dir/bin/python" -m reversecore_mcp.setup "$@"
    fi

    # If Docker is available and user wants Docker mode
    for arg in "$@"; do
        if [ "$arg" = "--docker" ] && command -v docker >/dev/null 2>&1; then
            echo "🐳 Running setup via Docker container..."
            exec docker run --rm -it \
                -v "$HOME:$HOME" \
                -e "HOME=$HOME" \
                ghcr.io/sjkim1127/reversecore-mcp:latest \
                python -m reversecore_mcp.setup "$@"
        fi
    done

    print_banner
    echo "❌ Error: Python 3.10+ or uv / pipx is required to install Reversecore_MCP." >&2
    echo "Please install Python 3.10+ (https://www.python.org/) or uv (https://astral.sh/uv)." >&2
    exit 1
}

main "$@"
