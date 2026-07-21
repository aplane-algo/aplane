#!/usr/bin/env bash
# Assemble a local release tarball with the same layout bootstrap-install.sh
# expects from GitHub releases.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
BUILD_BINARIES=1
ARCH=""
VERSION=""
RELEASE_VERSION=""
OS_NAME="linux"

usage() {
    cat <<'EOF'
Usage: scripts/package-bootstrap-release.sh [options]

Options:
  --arch <amd64|arm64>   Architecture to package (default: host arch)
  --version <version>    Version string for archive name (default: git describe, without leading v)
  --release-version <v>  Version string for release.json (default: --version/git describe)
  --skip-build           Use existing bin/<arch>/ binaries
  --dist-dir <path>      Output directory (default: ./dist)
  -h, --help             Show this help

Output:
  dist/aplane_<version>_linux_<arch>.tar.gz
  dist/checksums.txt

The tarball extracts to ./aplane/ and includes bin/, installer/, library/,
plugins.available/ as the bundled plugin catalog, install.sh, and uninstall.sh.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' "amd64" ;;
        aarch64|arm64) printf '%s\n' "arm64" ;;
        *) die "unsupported host architecture: $(uname -m)" ;;
    esac
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path"
    else
        die "no checksum tool found (need sha256sum or shasum)"
    fi
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --arch)
                [ $# -ge 2 ] || die "--arch requires a value"
                ARCH="$2"
                shift 2
                ;;
            --version)
                [ $# -ge 2 ] || die "--version requires a value"
                VERSION="$2"
                shift 2
                ;;
            --release-version)
                [ $# -ge 2 ] || die "--release-version requires a value"
                RELEASE_VERSION="$2"
                shift 2
                ;;
            --skip-build)
                BUILD_BINARIES=0
                shift
                ;;
            --dist-dir)
                [ $# -ge 2 ] || die "--dist-dir requires a value"
                DIST_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
    done
}

require_file() {
    local path="$1"
    [ -f "$path" ] || die "required file missing: $path"
}

copy_required_binaries() {
    local src_dir="$1"
    local dest_dir="$2"
    local binaries=(
        apshell
        aprekey
        apsigner
        apadmin
        apconsole
        apapprover
        apstore
        appass
        aplocalnet
        appass-file
        appass-systemd-creds
        approbe
        applugin-checksum
    )

    for binary in "${binaries[@]}"; do
        require_file "$src_dir/$binary"
        cp "$src_dir/$binary" "$dest_dir/"
    done
}

write_release_metadata() {
    local root="$1"
    local release_version="$2"
    local commit="$3"
    local built_at="$4"

    cat > "$root/release.json" <<EOF
{
  "schema_version": 1,
  "version": "$release_version",
  "commit": "$commit",
  "built_at": "$built_at"
}
EOF
}

main() {
    parse_args "$@"

    [ "$(uname -s)" = "Linux" ] || die "this script currently packages linux bootstrap archives only"
    command -v tar >/dev/null 2>&1 || die "tar not found"

    if [ -z "$ARCH" ]; then
        ARCH="$(detect_arch)"
    fi
    case "$ARCH" in
        amd64|arm64) ;;
        *) die "unsupported arch: $ARCH" ;;
    esac

    if [ -z "$VERSION" ]; then
        VERSION="$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)"
        VERSION="${VERSION#v}"
    else
        VERSION="${VERSION#v}"
    fi
    if [ -z "$RELEASE_VERSION" ]; then
        RELEASE_VERSION="$VERSION"
    fi
    local release_version="$RELEASE_VERSION"
    case "$release_version" in
        [0-9]*) release_version="v$release_version" ;;
    esac
    local git_commit
    git_commit="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    local built_at
    built_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    if [ "$BUILD_BINARIES" = "1" ]; then
        make -C "$ROOT_DIR" "bin-$ARCH"
        rm -rf "$ROOT_DIR/dist/bundled-plugins/$OS_NAME-$ARCH/algokit-localnet"
        "$ROOT_DIR/scripts/build-algokit-localnet-plugin-target.sh" \
            --os "$OS_NAME" \
            --arch "$ARCH" \
            --out-dir "$ROOT_DIR/dist/bundled-plugins/$OS_NAME-$ARCH/algokit-localnet"
    fi

    local bin_src="$ROOT_DIR/bin/$ARCH"
    [ -d "$bin_src" ] || die "binary directory missing: $bin_src (run with build enabled or make bin-$ARCH)"

    local archive="aplane_${VERSION}_${OS_NAME}_${ARCH}.tar.gz"
    local staging="$DIST_DIR/staging"
    rm -rf "$staging"
    mkdir -p "$staging/aplane/bin" \
        "$staging/aplane/installer/scripts" \
        "$staging/aplane/library/templates" \
        "$staging/aplane/plugins.available" \
        "$DIST_DIR"

    copy_required_binaries "$bin_src" "$staging/aplane/bin"

    cp "$ROOT_DIR/installer/apsigner.service" \
        "$ROOT_DIR/installer/apsigner.service.template" \
        "$ROOT_DIR/installer/sudoers.template" \
        "$staging/aplane/installer/"
    cp "$ROOT_DIR/installer/scripts/systemd-setup.sh" \
        "$ROOT_DIR/installer/scripts/aplane-env-audit.sh" \
        "$ROOT_DIR/installer/scripts/config-mcp.sh" \
        "$staging/aplane/installer/scripts/"
    cp "$ROOT_DIR"/library/templates/README.md \
        "$ROOT_DIR"/library/templates/*.yaml \
        "$staging/aplane/library/templates/"
    "$ROOT_DIR/scripts/stage-bundled-plugins.sh" --os "$OS_NAME" --arch "$ARCH" "$staging/aplane/plugins.available"
    cp "$ROOT_DIR/install.sh" \
        "$ROOT_DIR/uninstall.sh" \
        "$staging/aplane/"
    write_release_metadata "$staging/aplane" "$release_version" "$git_commit" "$built_at"

    chmod 755 "$staging/aplane/install.sh" \
        "$staging/aplane/uninstall.sh" \
        "$staging/aplane/installer/scripts/"*.sh
    chmod 755 "$staging/aplane/bin/"*

    tar -czf "$DIST_DIR/$archive" -C "$staging" aplane
    rm -rf "$staging"

    (
        cd "$DIST_DIR"
        sha256_file "$archive" > checksums.txt
    )

    printf 'Created %s\n' "$DIST_DIR/$archive"
    printf 'Created %s\n' "$DIST_DIR/checksums.txt"
    printf '\nInspect with:\n'
    printf '  tar -tzf %q | sort\n' "$DIST_DIR/$archive"
    printf '\nTest extraction with:\n'
    printf '  mkdir -p /tmp/aplane-package-test && tar -xzf %q -C /tmp/aplane-package-test\n' "$DIST_DIR/$archive"
}

main "$@"
