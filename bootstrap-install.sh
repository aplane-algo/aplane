#!/bin/bash
# bootstrap-install.sh - Download a release tarball from GitHub and install aplane on Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
#     bash -s -- --user aplane --group aplane --bindir /usr/local/bin --version latest
#
# Environment overrides:
#   APLANE_USER, APLANE_GROUP, APLANE_BINDIR, APLANE_VERSION
#   APLANE_ENABLE_SERVICE (1|0), APLANE_START_SERVICE (1|0)
#   APLANE_REQUIRE_MINISIGN (1|0) - require minisign binary and signature file

set -euo pipefail

REPO="aplane-algo/aplane"
MINISIGN_PUBKEY="RWQOLhio7R0OS5qnDscyJm5JEarSemT7K687rs65qLMShetqD7cXOxA8"

SVC_USER="${APLANE_USER:-aplane}"
SVC_GROUP="${APLANE_GROUP:-aplane}"
BINDIR="${APLANE_BINDIR:-/usr/local/bin}"
REQUESTED_VERSION="${APLANE_VERSION:-latest}"
ENABLE_SERVICE="${APLANE_ENABLE_SERVICE:-1}"
START_SERVICE="${APLANE_START_SERVICE:-1}"
REQUIRE_MINISIGN="${APLANE_REQUIRE_MINISIGN:-0}"
AUTO_UNLOCK="${APLANE_AUTO_UNLOCK:-0}"

TMPDIR_CREATED=""

usage() {
    cat <<'EOF'
Usage: bootstrap-install.sh [options]

Options:
  --user <name>       Service user to install/run as (default: aplane)
  --group <name>      Service group to install/run as (default: aplane)
  --bindir <path>     Binary install directory (default: /usr/local/bin)
  --version <tag>     Release tag (e.g. v1.2.3) or "latest" (default: latest)
  --auto-unlock       Enable auto-unlock via systemd-creds (requires systemd 250+)
  --no-enable         Do not run systemctl enable
  --no-start          Do not run systemctl start
  --require-minisign  Fail if minisign is unavailable or signature file is missing
  -h, --help          Show this help

By default, the service starts in locked state. Use apadmin to unlock after
starting. Pass --auto-unlock to enable automatic unlock via systemd-creds
(requires systemd 250+ and systemd-creds).
EOF
}

log() {
    printf '%s\n' "$*"
}

warn() {
    printf 'Warning: %s\n' "$*" >&2
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [ -n "$TMPDIR_CREATED" ] && [ -d "$TMPDIR_CREATED" ]; then
        rm -rf "$TMPDIR_CREATED"
    fi
}

run_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        if ! command -v sudo >/dev/null 2>&1; then
            die "sudo is required when not running as root"
        fi
        sudo "$@"
    fi
}

download() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        die "neither curl nor wget found"
    fi
}

fetch_latest_tag() {
    local url="https://api.github.com/repos/${REPO}/releases/latest"
    local tag
    if command -v curl >/dev/null 2>&1; then
        tag="$(curl -fsSL -H 'Accept: application/vnd.github+json' "$url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    elif command -v wget >/dev/null 2>&1; then
        tag="$(wget -qO- "$url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    else
        die "neither curl nor wget found"
    fi
    [ -n "$tag" ] || die "failed to detect latest release tag from GitHub API"
    printf '%s\n' "$tag"
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) printf '%s\n' "amd64" ;;
        aarch64|arm64) printf '%s\n' "arm64" ;;
        *) die "unsupported architecture: $arch" ;;
    esac
}

require_linux_systemd() {
    local os
    os="$(uname -s)"
    [ "$os" = "Linux" ] || die "this bootstrap installer supports Linux only"
    command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
}

require_systemd_250_creds() {
    local version
    version="$(systemctl --version | awk 'NR==1 {print $2}')"
    case "$version" in
        ''|*[!0-9]*) die "failed to parse systemd version from 'systemctl --version'" ;;
    esac
    if [ "$version" -lt 250 ]; then
        die "systemd ${version} detected; --auto-unlock requires systemd 250+"
    fi
    command -v systemd-creds >/dev/null 2>&1 || die "systemd-creds not found (required for --auto-unlock)"
}

require_prereqs() {
    command -v tar >/dev/null 2>&1 || die "tar not found"
    command -v getent >/dev/null 2>&1 || die "getent not found"
    command -v systemd-escape >/dev/null 2>&1 || die "systemd-escape not found"
}

verify_checksum() {
    local checksums_file="$1"
    local tarball_file="$2"
    local tarball_name="$3"
    local expected actual

    expected="$(awk -v f="$tarball_name" '$2 == f {print $1; exit}' "$checksums_file")"
    [ -n "$expected" ] || die "no checksum entry found for $tarball_name"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$tarball_file" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$tarball_file" | awk '{print $1}')"
    else
        die "no checksum tool found (need sha256sum or shasum)"
    fi

    [ "$expected" = "$actual" ] || die "checksum mismatch for $tarball_name"
}

verify_signature() {
    local checksums_file="$1"
    local sig_file="$2"

    if ! command -v minisign >/dev/null 2>&1; then
        if [ "$REQUIRE_MINISIGN" = "1" ]; then
            die "minisign is required but not installed"
        fi
        warn "minisign not installed; skipping signature verification (set APLANE_REQUIRE_MINISIGN=1 to enforce)"
        return
    fi

    minisign -V -P "$MINISIGN_PUBKEY" -m "$checksums_file" -x "$sig_file" >/dev/null 2>&1 || \
        die "minisign verification failed for checksums.txt"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --user)
                [ $# -ge 2 ] || die "--user requires a value"
                SVC_USER="$2"
                shift 2
                ;;
            --group)
                [ $# -ge 2 ] || die "--group requires a value"
                SVC_GROUP="$2"
                shift 2
                ;;
            --bindir)
                [ $# -ge 2 ] || die "--bindir requires a value"
                BINDIR="$2"
                shift 2
                ;;
            --version)
                [ $# -ge 2 ] || die "--version requires a value"
                REQUESTED_VERSION="$2"
                shift 2
                ;;
            --no-enable)
                ENABLE_SERVICE="0"
                shift
                ;;
            --no-start)
                START_SERVICE="0"
                shift
                ;;
            --auto-unlock)
                AUTO_UNLOCK="1"
                shift
                ;;
            --require-minisign)
                REQUIRE_MINISIGN="1"
                shift
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

main() {
    trap cleanup EXIT
    parse_args "$@"

    require_linux_systemd
    if [ "$AUTO_UNLOCK" = "1" ]; then
        require_systemd_250_creds
    fi
    require_prereqs
    local arch
    arch="$(detect_arch)"

    local tag
    if [ "$REQUESTED_VERSION" = "latest" ]; then
        log "Resolving latest release tag..."
        tag="$(fetch_latest_tag)"
    else
        case "$REQUESTED_VERSION" in
            v*) tag="$REQUESTED_VERSION" ;;
            *)  tag="v$REQUESTED_VERSION" ;;
        esac
    fi
    local version_num="${tag#v}"
    local tarball_name="aplane_${version_num}_linux_${arch}.tar.gz"
    local base_url="https://github.com/${REPO}/releases/download/${tag}"

    TMPDIR_CREATED="$(mktemp -d)"
    local tarball_path="${TMPDIR_CREATED}/${tarball_name}"
    local checksums_path="${TMPDIR_CREATED}/checksums.txt"
    local minisig_path="${TMPDIR_CREATED}/checksums.txt.minisig"
    local minisig_available="0"

    log "Downloading release ${tag} (${arch})..."
    download "${base_url}/${tarball_name}" "$tarball_path"
    download "${base_url}/checksums.txt" "$checksums_path"
    if download "${base_url}/checksums.txt.minisig" "$minisig_path"; then
        minisig_available="1"
    else
        if [ "$REQUIRE_MINISIGN" = "1" ]; then
            die "checksums.txt.minisig is missing for ${tag} and minisign is required"
        fi
        warn "checksums.txt.minisig not found for ${tag}; skipping signature verification"
    fi

    log "Verifying checksums..."
    verify_checksum "$checksums_path" "$tarball_path" "$tarball_name"
    if [ "$minisig_available" = "1" ]; then
        verify_signature "$checksums_path" "$minisig_path"
    fi

    log "Extracting archive..."
    tar -xzf "$tarball_path" -C "$TMPDIR_CREATED"
    [ -x "${TMPDIR_CREATED}/aplane/install.sh" ] || die "installer script not found in archive"

    log "Running bundled installer..."
    if [ "$AUTO_UNLOCK" = "1" ]; then
        run_root "${TMPDIR_CREATED}/aplane/install.sh" --auto-unlock "$SVC_USER" "$SVC_GROUP" "$BINDIR"
    else
        run_root "${TMPDIR_CREATED}/aplane/install.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR"
    fi

    local data_dir
    data_dir="$(getent passwd "$SVC_USER" | cut -d: -f6)"
    [ -n "$data_dir" ] || die "failed to resolve data directory for user $SVC_USER"
    local escaped_data_dir
    escaped_data_dir="$(systemd-escape "$data_dir")"

    if [ "$ENABLE_SERVICE" = "1" ]; then
        log "Enabling service aplane@${escaped_data_dir}..."
        run_root systemctl enable "aplane@${escaped_data_dir}"
    else
        log "Skipping service enable (--no-enable)."
    fi

    if [ "$START_SERVICE" = "1" ]; then
        log "Starting service aplane@${escaped_data_dir}..."
        run_root systemctl start "aplane@${escaped_data_dir}"
    else
        log "Skipping service start (--no-start)."
    fi

    log ""
    log "Installation complete."
    log "Data directory: ${data_dir}"
    log "Check status: systemctl status aplane@${escaped_data_dir}"
    if [ "$AUTO_UNLOCK" = "1" ]; then
        log "Mode: auto-unlock (systemd-creds)"
    else
        log "Mode: locked-start (unlock via apadmin)"
        log "Unlock: sudo -u ${SVC_USER} apadmin -d ${data_dir}"
    fi
}

main "$@"
