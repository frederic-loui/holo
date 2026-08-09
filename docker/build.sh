#!/usr/bin/env bash
#
# Build the holod and holo-bundle images.
#

set -euo pipefail

PROFILE="dev"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--profile PROFILE]

Options:
  --profile PROFILE  Cargo profile used to build holod (default: dev).
                     Supported profiles: dev, release, small.
  -h, --help         Show this help message.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --profile)
            if [ $# -lt 2 ]; then
                echo "error: --profile requires an argument" >&2
                exit 1
            fi
            PROFILE="$2"
            shift 2
            ;;
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
GIT_HASH="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"

export DOCKER_BUILDKIT=1

echo ">>> Building holod (profile: $PROFILE)"
docker build \
    --build-arg "BUILD_PROFILE=$PROFILE" \
    --build-arg "GIT_HASH=$GIT_HASH" \
    -t holod \
    -f "$SCRIPT_DIR/Dockerfile.holod" \
    "$ROOT_DIR"

echo ">>> Building holo-bundle"
docker build \
    --build-arg "HOLOD_IMAGE=holod" \
    -t holo-bundle \
    -f "$SCRIPT_DIR/Dockerfile.holo-bundle" \
    "$ROOT_DIR"

echo ">>> Done: holod, holo-bundle"
