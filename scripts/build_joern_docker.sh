#!/usr/bin/env bash
# Build the Joern Docker image for agies.
#
# Usage:
#   bash scripts/build_joern_docker.sh              # direct build
#   bash scripts/build_joern_docker.sh --proxy      # build with Japan proxy
#   bash scripts/build_joern_docker.sh --proxy http://127.0.0.1:1080

set -euo pipefail

IMAGE_TAG="agies/joern:latest"
DOCKERFILE="docker/joern/Dockerfile"
JOERN_VERSION="v4.0.551"

echo "==> Building Joern Docker image: ${IMAGE_TAG}"
echo "    Joern version: ${JOERN_VERSION}"
echo ""

BUILD_ARGS=(
    -t "${IMAGE_TAG}"
    -f "${DOCKERFILE}"
)

case "${1:-}" in
    --proxy)
        # Uses --network=host so 127.0.0.1:1080 reaches the host's proxy
        echo "    Using host network proxy (127.0.0.1:1080)"
        BUILD_ARGS+=(--network host)
        BUILD_ARGS+=(--build-arg "HTTP_PROXY=http://127.0.0.1:1080")
        BUILD_ARGS+=(--build-arg "HTTPS_PROXY=http://127.0.0.1:1080")
        BUILD_ARGS+=(--build-arg "NO_PROXY=dl-cdn.alpinelinux.org,*.alpinelinux.org,localhost,127.0.0.1")
        ;;
    -h|--help)
        echo "Usage: bash $0 [--proxy [URL]]"
        echo ""
        echo "  --proxy [URL]  Build with HTTP proxy (default: http://host.docker.internal:1080)"
        exit 0
        ;;
esac

echo ""
echo "==> Starting Docker build..."
echo "    This downloads ~2GB from GitHub. Grab a coffee."
echo ""

docker build "${BUILD_ARGS[@]}" .

echo ""
echo "==> Done!"
echo ""
echo "Verify with:"
echo "  docker run --rm ${IMAGE_TAG} --version"
echo ""
echo "Parse a project:"
echo "  docker run --rm -v /path/to/project:/app:ro ${IMAGE_TAG} \\"
echo "    joern-parse /app"
echo ""
echo "Use from agies:"
echo '  python3 -c "from agies.engine.graph.joern import JoernGraphGenerator;'
echo '  g = JoernGraphGenerator();'
echo '  pg = g.build_program_graph(\"/path/to/project\");'
echo '  print(f\"{pg.total_nodes} nodes, {pg.total_edges} edges\")"'
