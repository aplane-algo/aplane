#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_OS=""
TARGET_ARCH=""
SOURCE_ROOT="$ROOT_DIR/dist/bundled-plugins"

usage() {
    cat <<'EOF'
Usage: scripts/stage-bundled-plugins.sh [--os <linux|darwin>] [--arch <amd64|arm64>] [--source-root <dir>] <dest-plugins-available-dir>

Copies bundled runtime plugin payloads into a release staging plugins.available
catalog directory. They are not loaded by apshell until named in plugins.yaml.
Only manifest.json, checksums.sha256, README.md when present, and the standalone
executable are copied.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

detect_host_os() {
    case "$(uname -s)" in
        Linux) printf '%s\n' linux ;;
        Darwin) printf '%s\n' darwin ;;
        *) printf '%s\n' unknown ;;
    esac
}

detect_host_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' amd64 ;;
        aarch64|arm64) printf '%s\n' arm64 ;;
        *) printf '%s\n' unknown ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --os)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            TARGET_OS="$2"
            shift 2
            ;;
        --arch)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            TARGET_ARCH="$2"
            shift 2
            ;;
        --source-root)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
            SOURCE_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            usage >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done

if [ $# -ne 1 ]; then
    usage >&2
    exit 2
fi

AVAILABLE_ROOT="${1%/}"
HOST_OS="$(detect_host_os)"
HOST_ARCH="$(detect_host_arch)"

TARGET_OS="${TARGET_OS:-$HOST_OS}"
TARGET_ARCH="${TARGET_ARCH:-$HOST_ARCH}"

LOCALNET_SRC="$SOURCE_ROOT/$TARGET_OS-$TARGET_ARCH/algokit-localnet"
if [ ! -d "$LOCALNET_SRC" ]; then
    if [ "$TARGET_OS" = "$HOST_OS" ] && [ "$TARGET_ARCH" = "$HOST_ARCH" ]; then
        LOCALNET_SRC="$ROOT_DIR/plugins/algokit-localnet"
    else
        echo "Bundled algokit-localnet plugin payload not found for $TARGET_OS/$TARGET_ARCH; skipping available plugin stage."
        exit 0
    fi
fi
for file in manifest.json checksums.sha256 algokit-localnet; do
    if [ ! -f "$LOCALNET_SRC/$file" ]; then
        die "Bundled algokit-localnet plugin is incomplete for $TARGET_OS/$TARGET_ARCH; missing $LOCALNET_SRC/$file."
    fi
done

LOCALNET_DEST="$AVAILABLE_ROOT/algokit-localnet"
mkdir -p "$LOCALNET_DEST"
cp "$LOCALNET_SRC/manifest.json" "$LOCALNET_SRC/checksums.sha256" "$LOCALNET_SRC/algokit-localnet" "$LOCALNET_DEST/"
if [ -f "$LOCALNET_SRC/README.md" ]; then
    cp "$LOCALNET_SRC/README.md" "$LOCALNET_DEST/"
    chmod 644 "$LOCALNET_DEST/README.md"
fi
chmod 755 "$LOCALNET_DEST/algokit-localnet"
chmod 644 "$LOCALNET_DEST/manifest.json" "$LOCALNET_DEST/checksums.sha256"
echo "Staged available algokit-localnet plugin at $LOCALNET_DEST."
