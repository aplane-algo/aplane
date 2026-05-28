#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RETI_DIR="$ROOT_DIR/examples/external_plugins/reti"
TARGET_OS=""
TARGET_ARCH=""
OUT_DIR=""
DEFAULT_NODE_VERSION="22.22.0"
NODE_VERSION="${NODE_VERSION:-$DEFAULT_NODE_VERSION}"

usage() {
    cat <<'EOF'
Usage: scripts/build-reti-plugin-target.sh --os <linux|darwin> --arch <amd64|arm64> --out-dir <dir>

Builds a target-specific standalone Reti plugin runtime payload:
  <dir>/manifest.json
  <dir>/checksums.sha256
  <dir>/reti

The script downloads the matching official Node.js runtime for the requested
target and injects the Reti SEA blob into that executable. The target Node.js
runtime defaults to the pinned version in this script; set NODE_VERSION to
override it intentionally.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

sha256_value() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        die "no checksum tool found (need sha256sum or shasum)"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --os)
            [ $# -ge 2 ] || die "--os requires a value"
            TARGET_OS="$2"
            shift 2
            ;;
        --arch)
            [ $# -ge 2 ] || die "--arch requires a value"
            TARGET_ARCH="$2"
            shift 2
            ;;
        --out-dir)
            [ $# -ge 2 ] || die "--out-dir requires a value"
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

[ -n "$TARGET_OS" ] || die "--os is required"
[ -n "$TARGET_ARCH" ] || die "--arch is required"
[ -n "$OUT_DIR" ] || die "--out-dir is required"
[ -f "$RETI_DIR/manifest.json" ] || die "Reti manifest not found: $RETI_DIR/manifest.json"
[ -d "$RETI_DIR/node_modules" ] || die "Reti npm dependencies not installed; run npm ci in $RETI_DIR"
command -v node >/dev/null 2>&1 || die "node not found"
command -v curl >/dev/null 2>&1 || die "curl not found"
command -v tar >/dev/null 2>&1 || die "tar not found"

case "$TARGET_OS" in
    linux|darwin) ;;
    *) die "unsupported target OS: $TARGET_OS" ;;
esac

case "$TARGET_ARCH" in
    amd64) NODE_ARCH="x64" ;;
    arm64) NODE_ARCH="arm64" ;;
    *) die "unsupported target arch: $TARGET_ARCH" ;;
esac

NODE_VERSION="${NODE_VERSION#v}"

NODE_DIST="node-v${NODE_VERSION}-${TARGET_OS}-${NODE_ARCH}"
NODE_TARBALL="${NODE_DIST}.tar.xz"
NODE_BASE_URL="https://nodejs.org/dist/v${NODE_VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Node.js $NODE_VERSION for $TARGET_OS/$TARGET_ARCH..."
curl -fsSL "$NODE_BASE_URL/$NODE_TARBALL" -o "$TMP_DIR/$NODE_TARBALL"
curl -fsSL "$NODE_BASE_URL/SHASUMS256.txt" -o "$TMP_DIR/SHASUMS256.txt"

EXPECTED="$(awk -v file="$NODE_TARBALL" '$2 == file {print $1}' "$TMP_DIR/SHASUMS256.txt")"
[ -n "$EXPECTED" ] || die "checksum not found for $NODE_TARBALL"
ACTUAL="$(sha256_value "$TMP_DIR/$NODE_TARBALL")"
[ "$ACTUAL" = "$EXPECTED" ] || die "checksum mismatch for $NODE_TARBALL"

tar -xJf "$TMP_DIR/$NODE_TARBALL" -C "$TMP_DIR"
TARGET_NODE="$TMP_DIR/$NODE_DIST/bin/node"
[ -f "$TARGET_NODE" ] || die "target Node binary not found in $NODE_TARBALL"

mkdir -p "$OUT_DIR"
cp "$RETI_DIR/manifest.json" "$OUT_DIR/manifest.json"

node "$RETI_DIR/scripts/build-sea.mjs" \
    --node "$TARGET_NODE" \
    --output "$OUT_DIR/reti" \
    --target-os "$TARGET_OS" \
    --target-arch "$TARGET_ARCH" \
    --target-label "$TARGET_OS-$TARGET_ARCH"

chmod 755 "$OUT_DIR/reti"
chmod 644 "$OUT_DIR/manifest.json"

{
    printf '%s\n' "# checksums.sha256"
    printf '# Generated: %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '%s\n' "#"
    printf '%s  manifest.json\n' "$(sha256_value "$OUT_DIR/manifest.json")"
    printf '%s  reti\n' "$(sha256_value "$OUT_DIR/reti")"
} > "$OUT_DIR/checksums.sha256"
chmod 644 "$OUT_DIR/checksums.sha256"

echo "Built Reti plugin payload for $TARGET_OS/$TARGET_ARCH at $OUT_DIR."
