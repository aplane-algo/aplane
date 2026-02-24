#!/bin/sh
# aPlane installer
# Usage: curl -sSfL https://raw.githubusercontent.com/aplane-algo/aplane/main/install.sh | sh
#
# Environment variables:
#   APLANE_VERSION     - version to install (default: latest)
#   APLANE_INSTALL_DIR - installation directory (default: ~/.aplane/bin)

set -eu

REPO="aplane-algo/aplane"
INSTALL_DIR="${APLANE_INSTALL_DIR:-$HOME/.aplane/bin}"

# Embedded minisign public key for signature verification
MINISIGN_PUBKEY="RWQOLhio7R0OS5qnDscyJm5JEarSemT7K687rs65qLMShetqD7cXOxA8"

log() {
    printf '%s\n' "$@"
}

error() {
    log "Error: $1" >&2
    exit 1
}

cleanup() {
    if [ -n "${TMPDIR_CREATED:-}" ] && [ -d "${TMPDIR_CREATED}" ]; then
        rm -rf "$TMPDIR_CREATED"
    fi
}

trap cleanup EXIT

detect_os() {
    os="$(uname -s)"
    case "$os" in
        Linux)  echo "linux" ;;
        Darwin) echo "darwin" ;;
        *)      error "Unsupported OS: $os. aPlane supports Linux and macOS." ;;
    esac
}

detect_arch() {
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              error "Unsupported architecture: $arch" ;;
    esac
}

# Download a URL to a file. Tries curl first, falls back to wget.
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
}

get_latest_version() {
    url="https://api.github.com/repos/${REPO}/releases/latest"
    if command -v curl >/dev/null 2>&1; then
        version=$(curl -fsSL "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    elif command -v wget >/dev/null 2>&1; then
        version=$(wget -qO- "$url" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    else
        error "Neither curl nor wget found."
    fi
    if [ -z "$version" ]; then
        error "Could not determine latest version. Check https://github.com/${REPO}/releases"
    fi
    echo "$version"
}

verify_checksum() {
    checksums_file="$1"
    tarball_file="$2"
    tarball_name="$3"

    if command -v sha256sum >/dev/null 2>&1; then
        expected=$(grep "$tarball_name" "$checksums_file" | awk '{print $1}')
        actual=$(sha256sum "$tarball_file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        expected=$(grep "$tarball_name" "$checksums_file" | awk '{print $1}')
        actual=$(shasum -a 256 "$tarball_file" | awk '{print $1}')
    else
        error "Neither sha256sum nor shasum found. Cannot verify checksum."
    fi

    if [ -z "$expected" ]; then
        error "Could not find checksum for $tarball_name in checksums.txt"
    fi

    if [ "$expected" != "$actual" ]; then
        error "Checksum mismatch for $tarball_name\n  expected: $expected\n  actual:   $actual"
    fi

    log "Checksum verified."
}

verify_signature() {
    checksums_file="$1"
    sig_file="$2"

    if ! command -v minisign >/dev/null 2>&1; then
        log "Warning: minisign not installed, skipping signature verification."
        log "  Install minisign for stronger integrity guarantees."
        return
    fi

    if minisign -V -P "$MINISIGN_PUBKEY" -m "$checksums_file" -x "$sig_file" >/dev/null 2>&1; then
        log "Signature verified."
    else
        error "Signature verification failed! The release may have been tampered with."
    fi
}

main() {
    os="$(detect_os)"
    arch="$(detect_arch)"

    version="${APLANE_VERSION:-}"
    if [ -z "$version" ]; then
        log "Fetching latest version..."
        version="$(get_latest_version)"
    fi

    # Strip leading 'v' for the archive name (goreleaser convention)
    version_num="${version#v}"

    tarball_name="aplane_${version_num}_${os}_${arch}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/${version}"

    log "Installing aPlane ${version} (${os}/${arch})..."

    # Create temp directory
    tmpdir="$(mktemp -d)"
    TMPDIR_CREATED="$tmpdir"

    # Download release artifacts
    log "Downloading ${tarball_name}..."
    download "${base_url}/${tarball_name}" "${tmpdir}/${tarball_name}"
    download "${base_url}/checksums.txt" "${tmpdir}/checksums.txt"
    download "${base_url}/checksums.txt.minisig" "${tmpdir}/checksums.txt.minisig" 2>/dev/null || true

    # Verify integrity
    verify_checksum "${tmpdir}/checksums.txt" "${tmpdir}/${tarball_name}" "$tarball_name"

    if [ -f "${tmpdir}/checksums.txt.minisig" ]; then
        verify_signature "${tmpdir}/checksums.txt" "${tmpdir}/checksums.txt.minisig"
    fi

    # Install
    mkdir -p "$INSTALL_DIR"
    tar -xzf "${tmpdir}/${tarball_name}" -C "$INSTALL_DIR"

    log ""
    log "aPlane ${version} installed to ${INSTALL_DIR}"
    log ""
    log "Installed binaries:"
    for bin in apshell apsignerd apadmin apapprover apstore passfile; do
        if [ -f "${INSTALL_DIR}/${bin}" ]; then
            log "  ${bin}"
        fi
    done

    # Check if install dir is in PATH
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            log ""
            log "Add aPlane to your PATH by adding this to your shell profile:"
            log ""
            log "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            log ""
            ;;
    esac
}

main
