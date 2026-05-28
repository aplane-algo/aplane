#!/bin/bash
# bootstrap-install.sh - Download a release tarball from GitHub and install aplane.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
#     bash -s -- /path/to/aplane
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
#     bash -s -- --bindir /usr/local/bin --version latest
#   curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | \
#     bash -s -- --client
#
# Environment overrides:
#   APSIGNER_BINDIR, APSIGNER_VERSION
#   APSIGNER_LOCAL (path or "1" for $PWD)
#   APSIGNER_ENABLE_SERVICE (1|0), APSIGNER_START_SERVICE (1|0)
#   APSIGNER_REQUIRE_MINISIGN (1|0) - require minisign binary and signature file

# Refuse to run when sourced. Do not compare BASH_SOURCE[0] with $0 here:
# BASH_SOURCE[0] is empty when the supported `curl ... | bash` form is used.
if (return 0 2>/dev/null); then
    echo "Error: this script must be executed, not sourced." >&2
    return 1
fi

set -euo pipefail

REPO="aplane-algo/aplane"
MINISIGN_PUBKEY="RWSTA8cMsOQuE+UHxDpCoqg0D8/lFCciIOWZcBgJTMMwXpqa0ovdJvYF"

BINDIR="${APSIGNER_BINDIR:-/usr/local/bin}"
REQUESTED_VERSION="${APSIGNER_VERSION:-latest}"
ENABLE_SERVICE="${APSIGNER_ENABLE_SERVICE:-1}"
START_SERVICE="${APSIGNER_START_SERVICE:-1}"
REQUIRE_MINISIGN="${APSIGNER_REQUIRE_MINISIGN:-0}"
LOCAL_MODE="${APSIGNER_LOCAL:-}"
CLIENT_MODE=""
PROD_MODE=""
INSTALL_ROOT_ARG=""
POSITIONAL=()

# Track explicitly passed flags for incompatibility checks
OPT_PROD=""
OPT_BINDIR=""
OPT_NO_ENABLE=""
OPT_NO_START=""

TMPDIR_CREATED=""

usage() {
    cat <<'EOF'
Usage: bootstrap-install.sh [options] [install-root]

Options:
  --version <tag>     Release tag (e.g. v1.2.3) or "latest" (default: latest)
  --client            Install apshell only (no signer, for remote signer use)
EOF
    if [ "$(uname -s)" = "Linux" ]; then
        cat <<'EOF'
  --bindir <path>     Binary install directory (default: /usr/local/bin)
  --systemd          Systemd-managed install (requires sudo)
  --no-enable         Do not run systemctl enable (--systemd only)
  --no-start          Do not run systemctl start (--systemd only)
EOF
    fi
    cat <<'EOF'
  --require-minisign  Fail if minisign is unavailable or signature file is missing
  -h, --help          Show this help

EOF
    if [ "$(uname -s)" = "Linux" ]; then
        cat <<'EOF'
By default, installs locally without systemd. Pass --systemd for a
systemd-managed install. Optional install-root is the local/client install
root, or the operator root in --systemd mode. The signer starts in locked
state; use apadmin to unlock after starting.
EOF
    else
        cat <<'EOF'
By default, installs locally without systemd. Optional install-root is the
local/client install root.
EOF
    fi
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
        if [ -r /dev/tty ]; then
            sudo APLANE_BOOTSTRAP_RERUN="${APLANE_BOOTSTRAP_RERUN:-}" "$@" </dev/tty
        else
            sudo APLANE_BOOTSTRAP_RERUN="${APLANE_BOOTSTRAP_RERUN:-}" "$@"
        fi
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

detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux)  printf '%s\n' "linux" ;;
        Darwin) printf '%s\n' "darwin" ;;
        *)      die "unsupported operating system: $os" ;;
    esac
}

require_linux_systemd() {
    [ "$OS" = "linux" ] || die "systemd mode requires Linux"
    command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
}

require_prereqs() {
    command -v tar >/dev/null 2>&1 || die "tar not found"
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
        warn "minisign not installed; skipping optional signature verification"
        return
    fi

    minisign -V -P "$MINISIGN_PUBKEY" -m "$checksums_file" -x "$sig_file" >/dev/null 2>&1 || \
        die "minisign verification failed for checksums.txt"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --bindir)
                [ $# -ge 2 ] || die "--bindir requires a value"
                BINDIR="$2"
                OPT_BINDIR=1
                shift 2
                ;;
            --version)
                [ $# -ge 2 ] || die "--version requires a value"
                REQUESTED_VERSION="$2"
                shift 2
                ;;
            --client)
                CLIENT_MODE=1
                shift
                ;;
            --systemd)
                PROD_MODE=1
                OPT_PROD=1
                shift
                ;;
            --no-enable)
                ENABLE_SERVICE="0"
                OPT_NO_ENABLE=1
                shift
                ;;
            --no-start)
                START_SERVICE="0"
                OPT_NO_START=1
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
            --)
                shift
                while [ $# -gt 0 ]; do
                    POSITIONAL+=("$1")
                    shift
                done
                break
                ;;
            -*)
                die "unknown option: $1"
                ;;
            *)
                POSITIONAL+=("$1")
                shift
                ;;
        esac
    done
}

main() {
    trap cleanup EXIT

    # Build a rerun hint passed down to install.sh. The bundled installer
    # lives in a temp dir we delete on EXIT, so its own $0-based hint would
    # point at a path that no longer exists. The curl one-liner plus the
    # original bootstrap args is always re-runnable.
    local rerun_cmd="curl -fsSL https://raw.githubusercontent.com/${REPO}/main/bootstrap-install.sh | bash"
    if [ "$#" -gt 0 ]; then
        rerun_cmd="$rerun_cmd -s --"
        for a in "$@"; do
            rerun_cmd="$rerun_cmd $(printf '%q' "$a")"
        done
    fi
    export APLANE_BOOTSTRAP_RERUN="$rerun_cmd"

    parse_args "$@"

    if [ "${#POSITIONAL[@]}" -gt 1 ]; then
        die "too many positional arguments"
    fi
    if [ "${#POSITIONAL[@]}" -eq 1 ]; then
        INSTALL_ROOT_ARG="${POSITIONAL[0]}"
    fi

    local is_client=0
    if [ -n "$CLIENT_MODE" ]; then
        is_client=1
    fi
    local is_prod=0
    if [ -n "$PROD_MODE" ]; then
        is_prod=1
    fi

    # Default to local mode unless --systemd or --client
    local is_local=0
    if [ "$is_prod" = "0" ] && [ "$is_client" = "0" ]; then
        is_local=1
        if [ -n "$INSTALL_ROOT_ARG" ]; then
            LOCAL_MODE="$INSTALL_ROOT_ARG"
        elif [ -z "$LOCAL_MODE" ]; then
            LOCAL_MODE="1"
        fi
    fi

    # --client is incompatible with systemd/signer options
    if [ "$is_client" = "1" ]; then
        if [ -n "$OPT_PROD" ] || [ -n "$OPT_BINDIR" ] || \
           [ -n "$OPT_NO_ENABLE" ] || [ -n "$OPT_NO_START" ]; then
            die "--client is incompatible with --systemd, --bindir, --no-enable, and --no-start"
        fi
        if [ "$(id -u)" -eq 0 ]; then
            die "--client must not be run as root"
        fi
    fi

    OS="$(detect_os)"

    if [ "$is_prod" = "1" ]; then
        require_linux_systemd
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
    local tarball_name="aplane_${version_num}_${OS}_${arch}.tar.gz"
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
    if [ "$is_client" = "1" ]; then
        install_args=(--client)
        if [ -n "$INSTALL_ROOT_ARG" ]; then
            install_args+=("$INSTALL_ROOT_ARG")
        fi
        "${TMPDIR_CREATED}/aplane/install.sh" "${install_args[@]}"
    elif [ "$is_prod" = "1" ]; then
        install_args=(--systemd)
        if [ -n "$INSTALL_ROOT_ARG" ]; then
            install_args+=("$INSTALL_ROOT_ARG")
        fi
        install_args+=(--bindir "$BINDIR")
        if [ "$ENABLE_SERVICE" != "1" ]; then
            install_args+=(--no-enable)
        fi
        if [ "$START_SERVICE" != "1" ]; then
            install_args+=(--no-start)
        fi
        run_root "${TMPDIR_CREATED}/aplane/install.sh" "${install_args[@]}"
    else
        # Local mode: "1" means $PWD, otherwise use the specified path
        if [ "$LOCAL_MODE" = "1" ]; then
            "${TMPDIR_CREATED}/aplane/install.sh"
        else
            "${TMPDIR_CREATED}/aplane/install.sh" "$LOCAL_MODE"
        fi
    fi

    # Post-install summary (systemd mode only)
    if [ "$is_prod" = "1" ]; then
        local data_dir
        data_dir="$(getent passwd aplane | cut -d: -f6)"
        [ -n "$data_dir" ] || die "failed to resolve data directory for user aplane"

        log ""
        log "Installation complete."
        log "Data directory: ${data_dir}"
        if [ "$START_SERVICE" = "1" ]; then
            log "Check status: systemctl status apsigner"
        else
            log "Service start was skipped (--no-start)."
        fi
        if [ "$START_SERVICE" = "1" ]; then
            log "Mode: locked-start (unlock via apadmin)"
        fi
        log "Unlock: sudo -u aplane apadmin -d ${data_dir}"
    fi
}

main "$@"
