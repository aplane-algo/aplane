#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="$ROOT_DIR/plugins/algokit-localnet"

TARGET_OS=""
TARGET_ARCH=""
OUT_DIR=""

usage() {
    cat <<'EOF'
Usage: scripts/build-algokit-localnet-plugin-target.sh --os <linux|darwin> --arch <amd64|arm64> --out-dir <dir>

Builds the algokit-localnet plugin for a release target.
Output:
  <dir>/algokit-localnet
  <dir>/manifest.json
  <dir>/checksums.sha256
  <dir>/README.md
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

sha256_value() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
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
        --out-dir)
            [ $# -ge 2 ] || { usage >&2; exit 2; }
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

case "$TARGET_OS" in
    linux|darwin) ;;
    *) die "unsupported target OS: $TARGET_OS" ;;
esac

case "$TARGET_ARCH" in
    amd64|arm64) ;;
    *) die "unsupported target arch: $TARGET_ARCH" ;;
esac

[ -d "$PLUGIN_DIR" ] || die "plugin source not found: $PLUGIN_DIR"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

(
    cd "$PLUGIN_DIR"
    CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
        go build -trimpath -o "$OUT_DIR/algokit-localnet" ./algokit-localnet.go
)

cp "$PLUGIN_DIR/manifest.json" "$PLUGIN_DIR/README.md" "$OUT_DIR/"
chmod 755 "$OUT_DIR/algokit-localnet"
chmod 644 "$OUT_DIR/manifest.json" "$OUT_DIR/README.md"

{
    printf '%s  manifest.json\n' "$(sha256_value "$OUT_DIR/manifest.json")"
    printf '%s  algokit-localnet\n' "$(sha256_value "$OUT_DIR/algokit-localnet")"
} > "$OUT_DIR/checksums.sha256"
chmod 644 "$OUT_DIR/checksums.sha256"

echo "Built algokit-localnet plugin for $TARGET_OS/$TARGET_ARCH at $OUT_DIR."
