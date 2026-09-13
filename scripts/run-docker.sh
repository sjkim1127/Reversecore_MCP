#!/bin/bash
# Run Reversecore MCP Docker container with architecture auto-detection
#
# Usage:
#   ./scripts/run-docker.sh          # Auto-detect architecture
#   ./scripts/run-docker.sh x86      # Force x86_64
#   ./scripts/run-docker.sh arm64    # Force ARM64
#   ./scripts/run-docker.sh build    # Build only (auto-detect)
#   ./scripts/run-docker.sh stop     # Stop containers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Detect architecture
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        arm64|aarch64)
            echo "arm64"
            ;;
        x86_64|amd64)
            echo "x86"
            ;;
        *)
            echo "Unknown architecture: $arch" >&2
            echo "x86"  # Default fallback
            ;;
    esac
}

# Parse arguments
ACTION="${1:-run}"
ARCH="${2:-auto}"

if [[ "$ACTION" == "x86" || "$ACTION" == "arm64" ]]; then
    ARCH="$ACTION"
    ACTION="run"
fi

if [[ "$ARCH" == "auto" ]]; then
    ARCH=$(detect_arch)
fi

echo "🔧 Architecture: $ARCH"
echo "📁 Project directory: $PROJECT_DIR"

case "$ACTION" in
    run)
        echo "🚀 Starting Reversecore MCP ($ARCH)..."
        # Map arch to docker platform
        PLATFORM="linux/amd64"
        if [[ "$ARCH" == "arm64" ]]; then
            PLATFORM="linux/arm64"
        fi

        # Use simple docker run for now since we consolidated Dockerfile
        # Note: In a real environment, you'd update docker-compose.yml to use platform: linux/arm64
        # but for simplicity we rely on buildx/platform handling.

        if [[ "$ARCH" == "arm64" ]]; then
            echo "🍎 Running for Apple Silicon"
            docker compose --profile arm64 up -d
        else
            echo "🖥️ Running for Intel/AMD"
            docker compose --profile x86 up -d
        fi

        echo ""
        echo "📡 Server running at: http://localhost:8000"
        echo "📂 Workspace mounted: ./workspace"
        echo ""
        echo "To view logs:  docker compose logs -f"
        echo "To stop:       ./scripts/run-docker.sh stop"
        ;;

    build)
        echo "🔨 Building Docker image ($ARCH)..."

        PLATFORM="linux/amd64"
        TAG="latest"
        if [[ "$ARCH" == "arm64" ]]; then
            PLATFORM="linux/arm64"
            TAG="arm64"
        fi

        # Enable BuildKit for multi-arch support
        export DOCKER_BUILDKIT=1

        docker build --platform $PLATFORM -f Dockerfile -t reversecore-mcp:$TAG .

        echo "✅ Build complete: reversecore-mcp:$TAG"
        ;;

    stop)
        echo "🛑 Stopping containers..."
        docker compose --profile arm64 --profile x86 down
        echo "✅ Containers stopped"
        ;;

    logs)
        docker compose logs -f
        ;;

    shell)
        echo "🐚 Opening shell in container..."
        if [[ "$ARCH" == "arm64" ]]; then
            docker exec -it reversecore-mcp-arm64 /bin/bash
        else
            docker exec -it reversecore-mcp /bin/bash
        fi
        ;;

    *)
        echo "Usage: $0 [action] [arch]"
        echo ""
        echo "Actions:"
        echo "  run     - Start the container (default)"
        echo "  build   - Build the Docker image"
        echo "  stop    - Stop all containers"
        echo "  logs    - View container logs"
        echo "  shell   - Open shell in container"
        echo ""
        echo "Architectures:"
        echo "  auto    - Auto-detect (default)"
        echo "  x86     - Force x86_64"
        echo "  arm64   - Force ARM64 (Apple Silicon)"
        exit 1
        ;;
esac
