#!/bin/bash
# install.sh - Install aplane binaries and configure the system
#
# Local mode (default, rootless, no systemd):
#   ./install.sh [--role signer|sentry] [path]
#
# Client-only mode (apshell only, no signer):
#   ./install.sh --client [path]
#
# Systemd mode (systemd service):
#   sudo ./install.sh --systemd [--role signer|sentry] [operator-root] [--bindir <path>] [--no-enable] [--no-start]
#
# Arguments (local mode):
#   path      Parent directory for apsigner/ and apclient/ (default: ~/aplane)
#
# Arguments (systemd mode):
#   operator-root  Parent directory for apclient/ and apconsole.yaml
#                  (default: installing user's ~/aplane)
#   --bindir  Where to install binaries (default: /usr/local/bin)
#
# Environment overrides:
#   APLANE_INSTALL_ROOT  Default [path] / [operator-root] when omitted
#   APLANE_BINDIR        Default --systemd --bindir when omitted
#
# Works from both a repo checkout and an extracted release tarball.

# Refuse to run when sourced. Do not compare BASH_SOURCE[0] with $0 here:
# BASH_SOURCE[0] is empty when the supported `curl ... | bash` form is used.
if (return 0 2>/dev/null); then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: $0 [--role signer|sentry] [path]" >&2
    echo "       $0 --client [path]" >&2
    if [ "$(uname -s)" = "Linux" ]; then
        echo "       sudo $0 --systemd [--role signer|sentry] [operator-root] [--bindir <path>] [--no-enable] [--no-start]" >&2
    fi
    return 1
fi

set -euo pipefail

# Track how the user invoked us so the Ctrl+C trap can tell them how to
# re-run. Starts as the literal invocation, but prompt_install_mode may
# update it after the user picks systemd mode. If we were launched
# through sudo (either by the user or by a prior re-exec from this script),
# prepend "sudo" so the rerun hint actually re-elevates privileges.
RERUN_CMD="$0"
for arg in "$@"; do
    RERUN_CMD="$RERUN_CMD $(printf '%q' "$arg")"
done
if [ -n "${SUDO_USER:-}" ]; then
    RERUN_CMD="sudo $RERUN_CMD"
fi
# When launched by bootstrap-install.sh, $0 lives in a temp dir that gets
# rm -rf'd on bootstrap exit. Prefer the bootstrap-supplied curl one-liner.
if [ -n "${APLANE_BOOTSTRAP_RERUN:-}" ]; then
    RERUN_CMD="$APLANE_BOOTSTRAP_RERUN"
fi

bootstrap_rerun_with_args() {
    local cmd="${APLANE_BOOTSTRAP_RERUN:-}"
    [ -n "$cmd" ] || return 1
    if [ "$#" -gt 0 ]; then
        case " $cmd " in
            *" -s -- "*) ;;
            *) cmd="$cmd -s --" ;;
        esac
        local a
        for a in "$@"; do
            cmd="$cmd $(printf '%q' "$a")"
        done
    fi
    printf '%s\n' "$cmd"
}

on_interrupt() {
    echo "" >&2
    echo "Install cancelled." >&2
    echo "Re-run with:" >&2
    echo "  $RERUN_CMD" >&2
    exit 130
}
trap on_interrupt INT

is_linux() {
    [ "$(uname -s)" = "Linux" ]
}

print_usage() {
    cat <<'EOF'
Usage:
  ./install.sh [-f|--force] [--role signer|sentry] [path]
  ./install.sh --client [-f|--force] [path]
EOF
    if is_linux; then
        cat <<'EOF'
  sudo ./install.sh --systemd [-f|--force] [--role signer|sentry] [operator-root] [--bindir <path>] [--no-enable] [--no-start]
EOF
    fi

    cat <<'EOF'
Modes:
  local (default)   Install signer + client under a user directory.
  --client          Install client binaries under [path]/apclient (default: ~/aplane).
EOF
    if is_linux; then
        cat <<'EOF'
  --systemd       Install system-wide and configure systemd service files.
                    Optional operator-root defaults to the installing user's ~/aplane.

Options:
  --role <role>     Initialize the signer data root as signer or sentry (default: signer).
  --bindir <path>   Binary directory for --systemd (default: /usr/local/bin).
  -f, --force       Override the in-place upgrade version check.
  --no-enable       Do not run systemctl enable in --systemd mode.
  --no-start        Do not run systemctl start in --systemd mode.
EOF
    else
        cat <<'EOF'

Options:
  --role <role>     Initialize the signer data root as signer or sentry (default: signer).
  -f, --force       Override the in-place upgrade version check.
EOF
    fi

    cat <<'EOF'
  -h, --help        Show this help.

Environment:
  APLANE_INSTALL_ROOT  Default [path] / [operator-root] when omitted.
  APLANE_BINDIR        Default --systemd --bindir when omitted.
  APLANE_SKIP_LOCALNET_SETUP=1
                       Skip the optional LocalNet setup prompt.

Explicit command-line arguments override environment values.
EOF
}

# Parse flags
CLIENT_MODE=0
PROD_MODE=0
SVC_USER="aplane"
SVC_GROUP="aplane"
BINDIR="${APLANE_BINDIR:-/usr/local/bin}"
BINDIR_FLAG=0
ENABLE_SERVICE=1
START_SERVICE=1
GROUP_MEMBERSHIP_CHANGED=0
INSTALL_ROOT_ENV="${APLANE_INSTALL_ROOT:-}"
NODE_ROLE="signer"
NODE_ROLE_FLAG=0
FORCE_UPGRADE=0
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        --systemd)
            PROD_MODE=1
            shift
            ;;
        --client)
            CLIENT_MODE=1
            shift
            ;;
        -f|--force)
            FORCE_UPGRADE=1
            shift
            ;;
        --role)
            if [ $# -lt 2 ]; then
                echo "Error: --role requires signer or sentry." >&2
                exit 2
            fi
            case "$2" in
                signer|sentry)
                    NODE_ROLE="$2"
                    NODE_ROLE_FLAG=1
                    ;;
                *)
                    echo "Error: invalid --role '$2' (expected signer or sentry)." >&2
                    exit 2
                    ;;
            esac
            shift 2
            ;;
        --bindir)
            if [ $# -lt 2 ]; then
                echo "Error: --bindir requires a value." >&2
                exit 2
            fi
            BINDIR="$2"
            BINDIR_FLAG=1
            shift 2
            ;;
        --no-enable)
            ENABLE_SERVICE=0
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
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
            echo "Error: unknown option: $1" >&2
            echo "" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# Validate mutually exclusive flags
if [ "$PROD_MODE" = "1" ] && [ "$CLIENT_MODE" = "1" ]; then
    echo "Error: --systemd and --client are mutually exclusive." >&2
    exit 2
fi
if [ "$CLIENT_MODE" = "1" ] && [ "$BINDIR_FLAG" = "1" ]; then
    echo "Error: --client cannot be combined with --bindir." >&2
    exit 2
fi
if [ "$CLIENT_MODE" = "1" ] && [ "$NODE_ROLE_FLAG" = "1" ]; then
    echo "Error: --client cannot be combined with --role; client-only installs do not initialize a node." >&2
    exit 2
fi
if [ "$PROD_MODE" = "1" ] && ! is_linux; then
    echo "Error: --systemd is only supported on Linux." >&2
    exit 2
fi

LOCAL_MODE=0
LOCAL_PATH=""

detect_shell_rc() {
    local user_home="$1"
    local user="${2:-}"
    local login_shell
    if [ -n "$user" ]; then
        login_shell="$(getent passwd "$user" 2>/dev/null | cut -d: -f7)"
    fi
    login_shell="$(basename "${login_shell:-${SHELL:-/bin/bash}}")"
    case "$login_shell" in
        zsh)  printf '%s\n' "$user_home/.zshrc" ;;
        *)    printf '%s\n' "$user_home/.bashrc" ;;
    esac
}

expand_user_path() {
    local path="$1"
    case "$path" in
        "~")   printf '%s\n' "$HOME" ;;
        "~/"*) printf '%s\n' "$HOME/${path#~/}" ;;
        *)     printf '%s\n' "$path" ;;
    esac
}

expand_path_for_home() {
    local path="$1"
    local user_home="$2"
    case "$path" in
        "~")   printf '%s\n' "$user_home" ;;
        "~/"*) printf '%s\n' "$user_home/${path#~/}" ;;
        *)     printf '%s\n' "$path" ;;
    esac
}

prompt_install_path() {
    local default_path="$1"
    local answer
    read -rp "Install to (default $default_path): " answer </dev/tty
    if [ -z "$answer" ]; then
        answer="$default_path"
    fi
    expand_user_path "$answer"
}

prompt_prod_operator_root() {
    local default_path="$1"
    local user_home="$2"
    local answer path reuse
    while true; do
        read -rp "Install APlane operator files to (default $default_path): " answer </dev/tty
        if [ -z "$answer" ]; then
            answer="$default_path"
        fi
        path="$(expand_path_for_home "$answer" "$user_home")"
        if [ "${path#/}" = "$path" ]; then
            path="$(pwd)/$path"
        fi

        if [ -e "$path" ] && [ ! -d "$path" ]; then
            echo "Error: operator root exists but is not a directory: $path" >&2
            echo "Choose another directory." >&2
            echo "" >&2
            continue
        fi

        if [ -d "$path" ] && ! dir_is_empty "$path"; then
            echo "" >&2
            echo "Warning: operator root already exists and is not empty: $path" >&2
            echo "Systemd install will reuse it." >&2
            echo "Existing apclient/config.yaml, .mcp.json, and .codex/config.toml are left in place;" >&2
            echo "apenv.sh and apconsole.yaml are rewritten." >&2
            read -rp "Reuse this directory? [y/N] " reuse </dev/tty
            if [ "$reuse" = "y" ] || [ "$reuse" = "Y" ]; then
                OPERATOR_ROOT="$path"
                OPERATOR_ROOT_REUSE_CONFIRMED=1
                return 0
            fi
            echo "Choose another directory." >&2
            echo "" >&2
            continue
        fi

        OPERATOR_ROOT="$path"
        return 0
    done
}

shell_quote() {
    local value="$1"
    printf "'%s'" "$(printf '%s' "$value" | sed "s/'/'\\\\''/g")"
}

MIN_SUPPORTED_UPGRADE_VERSION="v0.25.0"

release_metadata_version() {
    local path="$1"
    sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$path" | head -n 1
}

normalize_release_version() {
    local raw="$1"
    local core major minor patch extra
    local IFS=.
    core="${raw#v}"
    core="${core%%+*}"
    core="${core%%-*}"
    read -r major minor patch extra <<EOF
$core
EOF
    [ -z "${extra:-}" ] || return 1
    case "${major:-}.${minor:-}.${patch:-}" in
        *[!0-9.]*|.*|*..*|*.) return 1 ;;
    esac
    [ -n "${major:-}" ] && [ -n "${minor:-}" ] && [ -n "${patch:-}" ] || return 1
    printf '%s %s %s\n' "$major" "$minor" "$patch"
}

version_ge() {
    local left="$1"
    local right="$2"
    local left_norm right_norm
    local lmj lmn lpt rmj rmn rpt

    left_norm="$(normalize_release_version "$left")" || return 2
    right_norm="$(normalize_release_version "$right")" || return 2

    read -r lmj lmn lpt <<EOF
$left_norm
EOF
    read -r rmj rmn rpt <<EOF
$right_norm
EOF

    if ((10#$lmj > 10#$rmj)); then return 0; fi
    if ((10#$lmj < 10#$rmj)); then return 1; fi
    if ((10#$lmn > 10#$rmn)); then return 0; fi
    if ((10#$lmn < 10#$rmn)); then return 1; fi
    if ((10#$lpt >= 10#$rpt)); then return 0; fi
    return 1
}

require_supported_upgrade() {
    local metadata_path="$1"
    local install_label="$2"
    local install_path="$3"
    local installed_version

    if [ ! -f "$metadata_path" ]; then
        if [ "$FORCE_UPGRADE" = "1" ]; then
            echo "Warning: forcing upgrade of $install_label without release metadata." >&2
            echo "Expected: $metadata_path" >&2
            return 0
        fi
        echo "Error: cannot upgrade this $install_label because release metadata is missing." >&2
        echo "Expected: $metadata_path" >&2
        echo "This installer supports in-place upgrades only from APlane $MIN_SUPPORTED_UPGRADE_VERSION or newer." >&2
        echo "Use a fresh install root, then restore or re-enroll any state you still need." >&2
        echo "Existing path: $install_path" >&2
        exit 1
    fi

    installed_version="$(release_metadata_version "$metadata_path")"
    if [ -z "$installed_version" ]; then
        if [ "$FORCE_UPGRADE" = "1" ]; then
            echo "Warning: forcing upgrade of $install_label with unreadable release metadata: $metadata_path" >&2
            return 0
        fi
        echo "Error: cannot determine installed APlane version from $metadata_path." >&2
        echo "This installer supports in-place upgrades only from APlane $MIN_SUPPORTED_UPGRADE_VERSION or newer." >&2
        echo "Use a fresh install root, then restore or re-enroll any state you still need." >&2
        exit 1
    fi

    if ! version_ge "$installed_version" "$MIN_SUPPORTED_UPGRADE_VERSION"; then
        if [ "$FORCE_UPGRADE" = "1" ]; then
            echo "Warning: forcing upgrade of $install_label from unsupported APlane version $installed_version." >&2
            echo "Minimum supported upgrade version: $MIN_SUPPORTED_UPGRADE_VERSION" >&2
            echo "Existing path: $install_path" >&2
            return 0
        fi
        echo "Error: installed APlane version $installed_version is too old for in-place upgrade." >&2
        echo "Minimum supported upgrade version: $MIN_SUPPORTED_UPGRADE_VERSION" >&2
        echo "Use a fresh install root, then restore or re-enroll any state you still need." >&2
        echo "Existing path: $install_path" >&2
        exit 1
    fi
}

toml_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "$value"
}

require_prod_service_stopped() {
    command -v systemctl >/dev/null 2>&1 || {
        echo "Error: --systemd requires systemctl." >&2
        exit 1
    }

    local state
    state="$(systemctl is-active apsigner.service 2>/dev/null || true)"
    case "$state" in
        active|activating|reloading|deactivating)
            echo "Error: apsigner.service is currently $state." >&2
            echo "" >&2
            echo "Stop the systemd service before installing or upgrading:" >&2
            echo "  sudo systemctl stop apsigner" >&2
            echo "  $RERUN_CMD" >&2
            exit 1
            ;;
    esac
}

require_local_signer_stopped() {
    local data_dir="$1"
    local install_mode="$2"

    [ "$install_mode" = "fresh install" ] && return 0

    local probe="$BIN_SRC/approbe"
    if [ ! -x "$probe" ]; then
        echo "Error: approbe binary not found at $probe." >&2
        echo "Build it with 'make approbe' or use a current release archive before upgrading this install." >&2
        exit 1
    fi

    local output status
    if output="$("$probe" signer-running -d "$data_dir" 2>&1)"; then
        echo "Error: apsigner appears to be running for this local install." >&2
        echo "" >&2
        echo "$output" >&2
        echo "" >&2
        echo "Stop the signer before installing or upgrading, then rerun the same install command." >&2
        exit 1
    else
        status=$?
    fi

    if [ "$status" = "1" ]; then
        return 0
    fi

    echo "Error: could not determine whether apsigner is running for this local install." >&2
    echo "" >&2
    echo "$output" >&2
    echo "" >&2
    echo "Stop any running APlane processes for this install, then rerun the installer." >&2
    exit 1
}

# prompt_install_mode offers an interactive choice between local and
# systemd install when no mode flag was passed. Only fires on Linux
# with a usable TTY so that curl|bash and CI paths still take the
# flag-driven defaults.
prompt_install_mode() {
    [ "$PROD_MODE" = "0" ] || return 0
    [ "$CLIENT_MODE" = "0" ] || return 0
    is_linux || return 0
    [ -r /dev/tty ] || return 0

    echo "APlane install modes:"
    echo "  [L]ocal       — rootless user-directory install, no systemd (default)"
    echo "  [S]ystemd     — systemd-managed apsigner service (requires sudo)"
    echo ""
    local answer
    read -rp "Choose mode [L/s]: " answer </dev/tty
    case "${answer:-L}" in
        l|L|local|Local|LOCAL)
            return 0
            ;;
        s|S|systemd|Systemd|SYSTEMD)
            echo ""
            echo "Systemd mode selected."
            local -a reexec_args=(--systemd)
            if [ "$NODE_ROLE" != "signer" ]; then
                reexec_args+=(--role "$NODE_ROLE")
            fi
            if [ "$BINDIR" != "/usr/local/bin" ]; then
                reexec_args+=(--bindir "$BINDIR")
            fi
            [ "$ENABLE_SERVICE" = "0" ] && reexec_args+=(--no-enable)
            [ "$START_SERVICE" = "0" ] && reexec_args+=(--no-start)

            # Update the rerun hint so Ctrl+C from this point on points
            # at the systemd invocation.
            local reexec_str="$0"
            for a in "${reexec_args[@]}"; do
                reexec_str="$reexec_str $(printf '%q' "$a")"
            done
            if [ -n "${APLANE_BOOTSTRAP_RERUN:-}" ]; then
                RERUN_CMD="$(bootstrap_rerun_with_args "${reexec_args[@]}")"
                export APLANE_BOOTSTRAP_RERUN="$RERUN_CMD"
            else
                RERUN_CMD="sudo $reexec_str"
            fi

            if [ "$(id -u)" -eq 0 ]; then
                PROD_MODE=1
                LOCAL_MODE=0
                return 0
            fi
            if ! command -v sudo >/dev/null 2>&1; then
                echo "Error: systemd install requires sudo, but sudo was not found on PATH." >&2
                echo "Install sudo (e.g. 'apt-get install sudo') and re-run, or start a root shell" >&2
                echo "and run:  $0 --systemd" >&2
                exit 1
            fi
            if [ -n "${APLANE_BOOTSTRAP_RERUN:-}" ]; then
                echo "Re-running extracted systemd installer with sudo."
                echo "For retries after this command exits, use:"
                echo "  $RERUN_CMD"
            else
                echo "Re-running with sudo:"
                echo "  $RERUN_CMD"
            fi
            echo ""
            if [ -n "${APLANE_BOOTSTRAP_RERUN:-}" ]; then
                exec sudo APLANE_BOOTSTRAP_RERUN="$APLANE_BOOTSTRAP_RERUN" "$0" "${reexec_args[@]}" </dev/tty
            fi
            exec sudo "$0" "${reexec_args[@]}" </dev/tty
            ;;
        *)
            echo "Unrecognized choice: $answer" >&2
            echo "Expected L (local) or S (systemd)." >&2
            exit 2
            ;;
    esac
}

# Default to local mode unless --systemd or --client. On Linux, with a
# usable TTY and no positional path given, offer an interactive mode prompt
# so users don't have to know the flag names. This runs after the prompt
# helpers are defined because bash resolves function names at call time.
if [ "$PROD_MODE" = "0" ] && [ "$CLIENT_MODE" = "0" ]; then
    if [ ${#POSITIONAL[@]} -eq 0 ] && [ -z "$INSTALL_ROOT_ENV" ]; then
        prompt_install_mode
    fi
    if [ "$PROD_MODE" = "0" ] && [ "$CLIENT_MODE" = "0" ]; then
        LOCAL_MODE=1
        LOCAL_PATH="${POSITIONAL[0]:-${INSTALL_ROOT_ENV:-}}"
    fi
fi

prompt_linux_memory_lock() {
    local answer
    is_linux || return 1
    echo ""
    echo "Memory locking prevents unlocked key material from being swapped to disk."
    echo "Enabling it requires root privileges and will set require_memory_protection: true."
    read -rp "Enable enforced memory locking for apsigner? [y/N] " answer </dev/tty
    [ "$answer" = "y" ] || [ "$answer" = "Y" ]
}

enable_binary_memory_lock() {
    local binary="$1"
    if ! command -v setcap >/dev/null 2>&1; then
        echo "Warning: setcap not found; leaving memory locking unenforced."
        return 1
    fi

    echo "Granting CAP_IPC_LOCK to $binary..."
    if [ "$(id -u)" -eq 0 ]; then
        setcap cap_ipc_lock+ep "$binary"
    elif command -v sudo >/dev/null 2>&1; then
        sudo setcap cap_ipc_lock+ep "$binary"
    else
        echo "Warning: sudo not found; leaving memory locking unenforced."
        return 1
    fi
}

set_require_memory_protection_true() {
    local path="$1"
    local tmp
    [ -f "$path" ] || return 0

    tmp="$(mktemp "$path.tmp.XXXXXX")"
    awk '
        BEGIN { done = 0 }
        /^[[:space:]]*require_memory_protection[[:space:]]*:/ {
            print "require_memory_protection: true"
            done = 1
            next
        }
        { print }
        END {
            if (!done) {
                print ""
                print "# Security settings"
                print "require_memory_protection: true"
            }
        }
    ' "$path" > "$tmp"
    mv "$tmp" "$path"
}

ensure_dir_or_missing() {
    local path="$1"
    local label="$2"
    if [ -e "$path" ] && [ ! -d "$path" ]; then
        echo "Error: $label exists but is not a directory: $path" >&2
        exit 1
    fi
}

ensure_writable_dir() {
    local path="$1"
    local label="$2"
    if [ -d "$path" ] && [ ! -w "$path" ]; then
        echo "Error: $label is not writable: $path" >&2
        exit 1
    fi
}

dir_is_empty() {
    local path="$1"
    [ -d "$path" ] || return 0
    [ -z "$(find "$path" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

classify_local_install() {
    local install_root="$1"
    local signer_dir="$2"
    local client_dir="$3"
    local identity_dir="$signer_dir/identities/default"
    local keystore_file="$identity_dir/.keystore"
    local has_existing_state=0

    ensure_dir_or_missing "$install_root" "install root"
    ensure_dir_or_missing "$signer_dir" "signer data directory"
    ensure_dir_or_missing "$client_dir" "client data directory"
    ensure_writable_dir "$install_root" "install root"
    ensure_writable_dir "$signer_dir" "signer data directory"
    ensure_writable_dir "$client_dir" "client data directory"

    if [ -e "$identity_dir" ] && [ ! -d "$identity_dir" ]; then
        echo "Error: identity path exists but is not a directory: $identity_dir" >&2
        exit 1
    fi

    if [ -f "$keystore_file" ]; then
        printf '%s\n' "upgrade"
        return
    fi

    if [ -d "$identity_dir" ] && ! dir_is_empty "$identity_dir"; then
        echo "Error: found partial keystore state at $identity_dir" >&2
        echo "The keystore is not initialized, but the identity directory contains files." >&2
        echo "" >&2
        echo "Inspect the directory, move it aside if it is from a failed install, then re-run the installer." >&2
        exit 1
    fi

    if [ -d "$signer_dir" ] || [ -d "$client_dir" ]; then
        has_existing_state=1
    fi
    if [ "$has_existing_state" = "1" ]; then
        printf '%s\n' "repair"
    else
        printf '%s\n' "fresh install"
    fi
}

print_local_install_plan() {
    local mode="$1"
    local local_path="$2"
    local signer_dir="$3"
    local client_dir="$4"
    local signer_port="$5"
    local ssh_port="$6"
    local node_role="$7"
    local keystore_file="$signer_dir/identities/default/.keystore"

    echo "=== apsigner installer (local mode) ==="
    echo ""
    echo "  Mode:        $mode"
    echo "  Node role:   $node_role"
    echo "  Install to:  $local_path"
    echo "  Signer:      $signer_dir"
    echo "  Client:      $client_dir"
    if [ "$mode" = "upgrade" ]; then
        echo "  Binaries:    will be replaced"
        echo "  Config:      existing config files will be preserved"
        echo "  Keystore:    initialized, will be preserved"
    else
        echo "  Signer port: $signer_port"
        echo "  SSH port:    $ssh_port"
        if [ -f "$keystore_file" ]; then
            echo "  Keystore:    initialized, will be preserved"
        else
            echo "  Keystore:    will be initialized"
        fi
    fi
    echo ""
}

find_available_port() {
    local port
    while true; do
        port=$(( (RANDOM % 16383) + 49152 ))
        if ! (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null; then
            echo "$port"
            return
        fi
    done
}

read_top_level_int() {
    local path="$1"
    local key="$2"
    [ -f "$path" ] || return 0
    awk -F: -v key="$key" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            print value
            exit
        }
    ' "$path"
}

read_ssh_port() {
    local path="$1"
    [ -f "$path" ] || return 0
    awk -F: '
        /^[[:space:]]*ssh[[:space:]]*:[[:space:]]*($|#)/ {
            in_ssh = 1
            next
        }
        /^[^[:space:]#][^:]*:/ {
            in_ssh = 0
        }
        in_ssh && /^[[:space:]]*port[[:space:]]*:/ {
            value = $2
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            print value
            exit
        }
    ' "$path"
}

read_signer_endpoint_signer_port() {
    local path="$1"
    [ -f "$path" ] || return 0
    awk -F: '
        function indent_width(line) {
            match(line, /^[[:space:]]*/)
            return RLENGTH
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            next
        }
        {
            indent = indent_width($0)
            if (indent == 0 && $0 ~ /^endpoint[[:space:]]*:/) {
                in_endpoint = 1
                next
            }
            if (in_endpoint && indent == 0 && $0 !~ /^endpoint[[:space:]]*:/) {
                in_endpoint = 0
            }
            if (in_endpoint && indent == 2 && $0 ~ /^[[:space:]]*signer_port[[:space:]]*:/) {
                value = $2
                sub(/[[:space:]]*#.*/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
                exit
            }
        }
    ' "$path"
}

read_signer_endpoint_ssh_port() {
    local path="$1"
    [ -f "$path" ] || return 0
    awk -F: '
        function indent_width(line) {
            match(line, /^[[:space:]]*/)
            return RLENGTH
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            next
        }
        {
            indent = indent_width($0)
            if (indent == 0 && $0 ~ /^endpoint[[:space:]]*:/) {
                in_endpoint = 1
                next
            }
            if (in_endpoint && indent == 2 && $0 ~ /^[[:space:]]*ssh[[:space:]]*:/) {
                in_endpoint_ssh = 1
                next
            }
            if (in_endpoint_ssh && indent <= 2 && $0 !~ /^[[:space:]]*ssh[[:space:]]*:/) {
                in_endpoint_ssh = 0
            }
            if (in_endpoint && indent == 0 && $0 !~ /^endpoint[[:space:]]*:/) {
                in_endpoint = 0
                in_endpoint_ssh = 0
            }
            if (in_endpoint_ssh && indent == 4 && $0 ~ /^[[:space:]]*port[[:space:]]*:/) {
                value = $2
                sub(/[[:space:]]*#.*/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
                exit
            }
        }
    ' "$path"
}

read_primary_endpoint_signer_port() {
    local path="$1"
    [ -f "$path" ] || return 0
    awk -F: '
        function indent_width(line) {
            match(line, /^[[:space:]]*/)
            return RLENGTH
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            next
        }
        {
            indent = indent_width($0)
            if (indent == 0 && $0 ~ /^endpoints[[:space:]]*:/) {
                in_endpoints = 1
                next
            }
            if (in_endpoints && indent == 2 && $0 ~ /^[[:space:]]*primary[[:space:]]*:/) {
                in_primary = 1
                next
            }
            if (in_primary && indent <= 2 && $0 !~ /^[[:space:]]*primary[[:space:]]*:/) {
                in_primary = 0
            }
            if (in_primary && $0 ~ /^[[:space:]]*signer_port[[:space:]]*:/) {
                value = $2
                sub(/[[:space:]]*#.*/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
                exit
            }
        }
    ' "$path"
}

read_primary_endpoint_ssh_port() {
    local path="$1"
    [ -f "$path" ] || return 0
    awk -F: '
        function trim_endpoint_url(value, quote) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            quote = sprintf("%c", 39)
            if (substr(value, 1, 1) == "\"" || substr(value, 1, 1) == quote) {
                value = substr(value, 2)
            }
            if (substr(value, length(value), 1) == "\"" || substr(value, length(value), 1) == quote) {
                value = substr(value, 1, length(value) - 1)
            }
            return value
        }
        function indent_width(line) {
            match(line, /^[[:space:]]*/)
            return RLENGTH
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ {
            next
        }
        {
            indent = indent_width($0)
            if (indent == 0 && $0 ~ /^endpoints[[:space:]]*:/) {
                in_endpoints = 1
                next
            }
            if (in_endpoints && indent == 2 && $0 ~ /^[[:space:]]*primary[[:space:]]*:/) {
                in_primary = 1
                next
            }
            if (in_primary && indent <= 2 && $0 !~ /^[[:space:]]*primary[[:space:]]*:/) {
                in_primary = 0
            }
            if (in_primary && $0 ~ /^[[:space:]]*url[[:space:]]*:/) {
                value = $0
                sub(/^[[:space:]]*url[[:space:]]*:[[:space:]]*/, "", value)
                sub(/[[:space:]]*#.*/, "", value)
                value = trim_endpoint_url(value)
                n = split(value, parts, ":")
                if (n >= 3) {
                    print parts[n]
                }
                exit
            }
        }
    ' "$path"
}

check_local_config_consistency() {
    local signer_config="$1"
    local client_config="$2"
    [ -f "$signer_config" ] || return 0
    [ -f "$client_config" ] || return 0

    local signer_signer_port signer_ssh_port client_signer_port client_ssh_port client_ports_source
    client_ports_source="config"
    signer_signer_port="$(read_signer_endpoint_signer_port "$signer_config")"
    signer_ssh_port="$(read_signer_endpoint_ssh_port "$signer_config")"
    client_signer_port="$(read_top_level_int "$client_config" "signer_port")"
    client_ssh_port="$(read_ssh_port "$client_config")"
    if [ -z "$client_signer_port" ] || [ -z "$client_ssh_port" ]; then
        local client_endpoints
        client_endpoints="$(dirname "$client_config")/endpoints.yaml"
        client_signer_port="$(read_primary_endpoint_signer_port "$client_endpoints")"
        client_ssh_port="$(read_primary_endpoint_ssh_port "$client_endpoints")"
        client_ports_source="endpoints"
    fi

    if [ -z "$signer_signer_port" ] || [ -z "$signer_ssh_port" ] || [ -z "$client_signer_port" ] || [ -z "$client_ssh_port" ]; then
        echo "Warning: could not verify local signer/client port consistency."
        echo "  Signer config: $signer_config"
        echo "  Client config: $client_config"
        return 0
    fi

    if [ "$signer_signer_port" = "$client_signer_port" ] && [ "$signer_ssh_port" = "$client_ssh_port" ]; then
        return 0
    fi

    echo ""
    echo "WARNING: local signer/client config ports do not match."
    echo "  Signer config: $signer_config"
    echo "    endpoint.signer_port: $signer_signer_port"
    echo "    endpoint.ssh.port:    $signer_ssh_port"
    echo "  Client config: $client_config"
    echo "    signer_port: $client_signer_port"
    echo "    ssh.port:    $client_ssh_port"
    echo ""
    if [ "$client_ports_source" = "endpoints" ]; then
        echo "'apshell request-token' and 'connect' use $client_endpoints."
        echo "Edit $client_endpoints manually before connecting."
        return 0
    fi
    echo "Client config still uses legacy signer settings in $client_config."
    echo "apshell now requires $client_endpoints for default signer routing."
    echo "Write $client_endpoints manually (the legacy migrate-config-v1 utility is obsolete and no longer shipped)."
    return 0
}

# Resolve script directory (works from repo checkout and extracted tarball)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$SCRIPT_DIR/bin"
RELEASE_METADATA_SRC="$SCRIPT_DIR/release.json"

if [ ! -d "$BIN_SRC" ]; then
    echo "Error: bin/ directory not found at $BIN_SRC" >&2
    exit 1
fi

install_release_metadata() {
    local install_dir="$1"
    local owner="${2:-}"
    local group="${3:-}"
    local dir_mode="${4:-755}"
    local file_mode="${5:-644}"
    local dest="$install_dir/release.json"

    [ -f "$RELEASE_METADATA_SRC" ] || return 0

    mkdir -p "$install_dir"
    cp "$RELEASE_METADATA_SRC" "$dest"
    chmod "$dir_mode" "$install_dir"
    chmod "$file_mode" "$dest"
    if [ -n "$owner" ] && [ -n "$group" ]; then
        chown "$owner:$group" "$install_dir" "$dest"
    fi
}

# --- Shared config templates ---

write_signer_config() {
    local target="$1"
    local signer_port="${2:-11270}"
    local ssh_port="${3:-1127}"
    local require_memory_protection="${4:-false}"
    cat > "$target" <<EOF
# apsigner configuration
# See docs/USER_CONFIG.md for full documentation.

# Signer endpoint exposure settings.
endpoint:
  # Optional client-reachable URL used by "apstore endpoint export" when --host/--url are omitted.
  # Set this to a real DNS name or IP clients can reach.
  # advertise_url: ssh://signer.example.com:$ssh_port
  signer_port: $signer_port
  ssh:
    listen_address: 127.0.0.1
    port: $ssh_port
    host_key_path: .ssh/ssh_host_key
    authorized_keys_path: .ssh/authorized_keys

# Inactivity timeout before auto-lock: "0" = never, "15m" = 15 minutes
passphrase_timeout: "15m"

# Lock signer when apadmin disconnects (set to false for headless operation)
lock_on_disconnect: true

# User auto-approve skips operator prompts for non-rejected default-fallback requests (default: false)
user_auto_approve: false

# Network settings (used for algod access, TEAL compilation, policy enforcement, etc.)
networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
  mainnet:
    algod:
      server: https://mainnet-api.4160.nodely.dev
      token: ""
  localnet:
    algod:
      server: http://localhost:4001
      token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
teal_compile_network: testnet

# Security settings
require_memory_protection: $require_memory_protection
EOF
}

write_apshell_local_config() {
    local target="$1"
    cat > "$target" <<EOF
# apshell configuration (local signer)
# See docs/USER_CONFIG.md for full documentation.

network: testnet
networks_allowed:
  - mainnet
  - testnet

signer_status_poll_interval: "10s"

networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
  mainnet:
    algod:
      server: https://mainnet-api.4160.nodely.dev
      token: ""
  localnet:
    algod:
      server: http://localhost:4001
      token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EOF
}

write_apshell_endpoint_registry() {
    local target="$1"
    local host="${2:-127.0.0.1}"
    local signer_port="${3:-11270}"
    local ssh_port="${4:-1127}"
    cat > "$target" <<EOF
# apshell endpoint registry
# See docs/USER_CONFIG.md for full documentation.

schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://$host:$ssh_port
    signer_port: $signer_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
EOF
}

write_apshell_sentry_endpoint_registry() {
    local target="$1"
    local host="${2:-127.0.0.1}"
    local signer_port="${3:-11270}"
    local ssh_port="${4:-1127}"
    cat > "$target" <<EOF
# apshell endpoint registry
# See docs/USER_CONFIG.md for full documentation.

schema_version: 1
endpoints:
  local-sentry:
    role: sentry
    url: ssh://$host:$ssh_port
    signer_port: $signer_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: tokens/local-sentry.token
EOF
}

write_apshell_endpoint_registry_for_role() {
    local target="$1"
    local role="$2"
    local host="${3:-127.0.0.1}"
    local signer_port="${4:-11270}"
    local ssh_port="${5:-1127}"
    case "$role" in
        signer)
            write_apshell_endpoint_registry "$target" "$host" "$signer_port" "$ssh_port"
            ;;
        sentry)
            write_apshell_sentry_endpoint_registry "$target" "$host" "$signer_port" "$ssh_port"
            ;;
        *)
            echo "Error: unsupported endpoint registry role: $role" >&2
            exit 2
            ;;
    esac
}

write_mcp_config() {
    local data_dir="$1"
    local apshell_bin="$2"
    local target="$data_dir/.mcp.json"
    local codex_dir="$data_dir/.codex"
    local codex_config="$codex_dir/config.toml"

    mkdir -p "$data_dir"
    if [ -f "$target" ]; then
        target="$data_dir/.mcp.json.aplane-installer.new"
        echo "MCP config already exists at $data_dir/.mcp.json; leaving it unchanged."
        echo "Writing canonical template to $target..."
    else
        echo "Writing $target..."
    fi

    cat > "$target" <<EOF
{
  "mcpServers": {
    "aplane": {
      "command": "$apshell_bin",
      "args": ["--mcp", "-d", "$data_dir"]
    }
  }
}
EOF

    mkdir -p "$codex_dir"
    target="$codex_config"
    if [ -f "$target" ]; then
        target="$codex_config.aplane-installer.new"
        echo "Codex MCP config already exists at $codex_config; leaving it unchanged."
        echo "Writing canonical Codex template to $target..."
    else
        echo "Writing $target..."
    fi

    local apshell_bin_toml
    local data_dir_toml
    apshell_bin_toml="$(toml_escape "$apshell_bin")"
    data_dir_toml="$(toml_escape "$data_dir")"
    cat > "$target" <<EOF
[mcp_servers.aplane]
command = "$apshell_bin_toml"
args = ["--mcp", "-d", "$data_dir_toml"]
EOF
}

write_apconsole_profile() {
    local target="$1"
    local mode="$2"
    local client_data="$3"
    local signer_data="${4:-}"

    cat > "$target" <<EOF
# apconsole profile
# Paths are relative to this file.
mode: $mode
client_data: $client_data
EOF
    if [ "$mode" = "local" ]; then
        cat >> "$target" <<EOF
signer_data: $signer_data
EOF
    fi
}

install_template_library() {
    local data_dir="$1"
    local owner="${2:-}"
    local group="${3:-}"
    local src="$SCRIPT_DIR/library/templates"
    local library_root="$data_dir/library"
    local dest="$library_root/templates"
    local copied=0

    if [ ! -d "$src" ]; then
        echo "Template library not found at $src; skipping template copy."
        return 0
    fi

    mkdir -p "$dest"
    for file in "$src"/*; do
        [ -f "$file" ] || continue
        case "$(basename "$file")" in
            README.md|*.yaml)
                cp "$file" "$dest/"
                copied=$((copied + 1))
                ;;
        esac
    done

    if [ -n "$owner" ] && [ -n "$group" ]; then
        chown "$owner:$group" "$library_root"
        chmod 750 "$library_root"
        chown -R "$owner:$group" "$dest"
        chmod 750 "$dest"
        for file in "$dest"/*; do
            [ -f "$file" ] || continue
            chmod 640 "$file"
        done
    else
        chmod 755 "$library_root"
        chmod 755 "$dest"
        for file in "$dest"/*; do
            [ -f "$file" ] || continue
            chmod 644 "$file"
        done
    fi

    echo "Installed template library to $dest ($copied file(s))."
}

install_plugin_payload() {
    local src="$1"
    local dest="$2"
    local executable="$3"
    local label="$4"
    local owner="${5:-}"
    local group="${6:-}"
    local parent
    local tmp
    local file

    for file in manifest.json checksums.sha256 "$executable"; do
        if [ ! -f "$src/$file" ]; then
            echo "Error: $label is missing $file at $src." >&2
            return 1
        fi
    done

    parent="$(dirname "$dest")"
    tmp="$parent/.$(basename "$dest").aplane-installer.tmp"
    mkdir -p "$parent"
    rm -rf "$tmp"
    mkdir -p "$tmp"
    cp "$src/manifest.json" "$src/checksums.sha256" "$src/$executable" "$tmp/"
    if [ -f "$src/README.md" ]; then
        cp "$src/README.md" "$tmp/"
        chmod 644 "$tmp/README.md"
    fi
    chmod 755 "$tmp/$executable"
    chmod 644 "$tmp/manifest.json" "$tmp/checksums.sha256"

    rm -rf "$dest"
    mv "$tmp" "$dest"

    if [ -n "$owner" ] && [ -n "$group" ]; then
        chown -R "$owner:$group" "$dest"
    elif [ -n "$owner" ]; then
        chown -R "$owner" "$dest"
    fi

    echo "Installed $label to $dest."
}

plugin_payload_complete() {
    local src="$1"
    local executable="$2"

    [ -f "$src/manifest.json" ] &&
    [ -f "$src/checksums.sha256" ] &&
    [ -f "$src/$executable" ]
}

plugin_payload_missing_summary() {
    local src="$1"
    local executable="$2"
    local missing=""
    local file

    for file in manifest.json checksums.sha256 "$executable"; do
        if [ ! -f "$src/$file" ]; then
            if [ -n "$missing" ]; then
                missing="$missing, "
            fi
            missing="$missing$file"
        fi
    done

    printf '%s\n' "$missing"
}

sha256_file_value() {
    local path="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        echo "Error: no checksum tool found (need sha256sum or shasum)." >&2
        return 1
    fi
}

plugin_payload_checksums_match() {
    local src="$1"
    local executable="$2"
    local checksums="$src/checksums.sha256"
    local line
    local expected
    local filename
    local actual
    local saw_entry=0
    local saw_manifest=0
    local saw_executable=0

    [ -f "$checksums" ] || return 1

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ""|\#*) continue ;;
        esac

        set -- $line
        if [ "$#" -lt 2 ]; then
            return 1
        fi
        expected="$1"
        filename="${2#\*}"
        filename="${filename#./}"

        case "$filename" in
            ""|/*|../*|*/../*|*/..)
                return 1
                ;;
        esac
        if [ ! -f "$src/$filename" ]; then
            return 1
        fi

        actual="$(sha256_file_value "$src/$filename")" || return 1
        if [ "$actual" != "$expected" ]; then
            return 1
        fi

        saw_entry=1
        [ "$filename" = "manifest.json" ] && saw_manifest=1
        [ "$filename" = "$executable" ] && saw_executable=1
    done < "$checksums"

    [ "$saw_entry" = "1" ] && [ "$saw_manifest" = "1" ] && [ "$saw_executable" = "1" ]
}

installer_host_os() {
    case "$(uname -s)" in
        Linux)  printf '%s\n' linux ;;
        Darwin) printf '%s\n' darwin ;;
        *)
            echo "Error: unsupported plugin build OS: $(uname -s)" >&2
            return 1
            ;;
    esac
}

installer_host_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  printf '%s\n' amd64 ;;
        aarch64|arm64) printf '%s\n' arm64 ;;
        *)
            echo "Error: unsupported plugin build architecture: $(uname -m)" >&2
            return 1
            ;;
    esac
}

build_builtin_plugin_payload() {
    local plugin="$1"
    local host_os="$2"
    local host_arch="$3"
    local out_dir="$SCRIPT_DIR/dist/bundled-plugins/$host_os-$host_arch/$plugin"

    if [ "$(id -u)" -eq 0 ]; then
        echo "Error: bundled $plugin plugin payload is not built." >&2
        echo "Run this from the repo checkout as the checkout owner, then rerun install.sh:" >&2
        echo "  make -C $(printf '%q' "$SCRIPT_DIR") bundled-plugins-$host_os" >&2
        return 1
    fi

    case "$plugin" in
        algokit-localnet)
            "$SCRIPT_DIR/scripts/build-algokit-localnet-plugin-target.sh" \
                --os "$host_os" \
                --arch "$host_arch" \
                --out-dir "$out_dir"
            ;;
        *)
            echo "Error: unknown bundled plugin: $plugin" >&2
            return 1
            ;;
    esac
}

RESOLVED_PLUGIN_SRC=""

resolve_builtin_plugin_source() {
    local plugin="$1"
    local executable="$2"
    local label="$3"
    local host_os
    local host_arch
    local candidate
    local incomplete=""
    local incomplete_reason=""

    RESOLVED_PLUGIN_SRC=""
    host_os="$(installer_host_os)" || return 1
    host_arch="$(installer_host_arch)" || return 1

    # In-tree source first so a stale plugins.available/ next to install.sh
    # (e.g. left over from a release tarball extracted on top of the checkout)
    # cannot shadow a fresh build.
    for candidate in \
        "$SCRIPT_DIR/plugins/$plugin" \
        "$SCRIPT_DIR/plugins.available/$plugin" \
        "$SCRIPT_DIR/dist/bundled-plugins/$host_os-$host_arch/$plugin"
    do
        [ -d "$candidate" ] || continue
        if ! plugin_payload_complete "$candidate" "$executable"; then
            incomplete="$candidate"
            incomplete_reason="missing"
            continue
        fi
        if ! plugin_payload_checksums_match "$candidate" "$executable"; then
            echo "$label payload at $candidate failed checksum verification; trying next source." >&2
            incomplete="$candidate"
            incomplete_reason="checksum"
            continue
        fi
        RESOLVED_PLUGIN_SRC="$candidate"
        return 0
    done

    if [ -d "$SCRIPT_DIR/plugins/$plugin" ]; then
        echo "$label source exists but the runtime payload is incomplete or invalid; building $host_os/$host_arch payload..."
        build_builtin_plugin_payload "$plugin" "$host_os" "$host_arch" || return 1
        candidate="$SCRIPT_DIR/dist/bundled-plugins/$host_os-$host_arch/$plugin"
        if plugin_payload_complete "$candidate" "$executable" \
            && plugin_payload_checksums_match "$candidate" "$executable"; then
            RESOLVED_PLUGIN_SRC="$candidate"
            return 0
        fi
        if ! plugin_payload_complete "$candidate" "$executable"; then
            echo "Error: built $label payload is incomplete at $candidate." >&2
            echo "Missing: $(plugin_payload_missing_summary "$candidate" "$executable")" >&2
        else
            echo "Error: built $label payload at $candidate failed checksum verification." >&2
        fi
        return 1
    fi

    if [ -n "$incomplete" ]; then
        if [ "$incomplete_reason" = "checksum" ]; then
            echo "Error: $label payload at $incomplete failed checksum verification." >&2
        else
            echo "Error: $label payload is incomplete at $incomplete." >&2
            echo "Missing: $(plugin_payload_missing_summary "$incomplete" "$executable")" >&2
        fi
        return 1
    fi

    echo "$label not found; skipping plugin install."
    return 0
}

prepare_builtin_plugin_payloads() {
    resolve_builtin_plugin_source algokit-localnet algokit-localnet "Bundled algokit-localnet plugin" || return 1
}

ensure_plugins_config() {
    local client_data="$1"
    local owner="${2:-}"
    local group="${3:-}"
    local config_path="$client_data/plugins.yaml"
    local plugin
    shift 3

    if [ -f "$config_path" ]; then
        echo "Plugin activation config already exists at $config_path; leaving it unchanged."
        return 0
    fi

    cat > "$config_path" <<'EOF'
# apshell plugin activation.
# Bundled plugin payloads are installed under plugins.available/.
# Add plugin directory names here to enable them.
EOF
    if [ "$#" -eq 0 ]; then
        cat >> "$config_path" <<'EOF'
enabled_plugins: []
EOF
    else
        printf '%s\n' "enabled_plugins:" >> "$config_path"
        for plugin in "$@"; do
            printf '  - %s\n' "$plugin" >> "$config_path"
        done
    fi
    chmod 644 "$config_path"

    if [ -n "$owner" ] && [ -n "$group" ]; then
        chown "$owner:$group" "$config_path"
    elif [ -n "$owner" ]; then
        chown "$owner" "$config_path"
    fi

    echo "Installed plugin activation config at $config_path."
}

install_builtin_plugins() {
    local client_data="$1"
    local owner="${2:-}"
    local group="${3:-}"
    local available_root="$client_data/plugins.available"
    local src

    mkdir -p "$available_root"

    resolve_builtin_plugin_source algokit-localnet algokit-localnet "Bundled algokit-localnet plugin" || return 1
    src="$RESOLVED_PLUGIN_SRC"
    if [ -n "$src" ]; then
        install_plugin_payload "$src" "$available_root/algokit-localnet" algokit-localnet "available algokit-localnet plugin" "$owner" "$group" || return 1
    fi
    ensure_plugins_config "$client_data" "$owner" "$group"

    return 0
}

run_as_service_user() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$SVC_USER" -- "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -u "$SVC_USER" -- "$@"
    else
        echo "Error: need runuser or sudo to initialize the keystore as $SVC_USER." >&2
        return 1
    fi
}

ensure_prod_data_dir_permissions() {
    local data_dir="$1"
    mkdir -p "$data_dir"
    chown "$SVC_USER:$SVC_GROUP" "$data_dir"
    chmod 2770 "$data_dir"
}

ensure_prod_backup_permissions() {
    local data_dir="$1"
    local backup_dir="$data_dir/backups"

    if [ -L "$backup_dir" ]; then
        echo "Error: systemd backup directory must not be a symlink: $backup_dir" >&2
        return 1
    fi
    if [ -e "$backup_dir" ] && [ ! -d "$backup_dir" ]; then
        echo "Error: systemd backup path exists but is not a directory: $backup_dir" >&2
        return 1
    fi

    mkdir -p "$backup_dir"
    find "$backup_dir" -type d -exec chown "$SVC_USER:$SVC_GROUP" {} + -exec chmod 2770 {} +
    find "$backup_dir" -type f -exec chown "$SVC_USER:$SVC_GROUP" {} + -exec chmod 660 {} +
}

repair_prod_store_lock_permissions() {
    local data_dir="$1"
    local lock_path="$data_dir/.apstore.lock"
    if [ -e "$lock_path" ]; then
        chown "$SVC_USER:$SVC_GROUP" "$lock_path"
        chmod 660 "$lock_path"
    fi
}

ensure_policy_integrity_sidecar() {
    local data_dir="$1"
    local apstore_bin="$2"
    local identity_dir="$data_dir/identities/default"
    local keystore_file="$identity_dir/.keystore"
    local policy_file="$identity_dir/policy.yaml"
    local sidecar_file="$policy_file.hmac"
    local answer
    local policy_missing=0

    [ -f "$keystore_file" ] || return 0

    echo ""
    echo "=== Policy integrity ==="
    echo ""

    if [ -f "$sidecar_file" ]; then
        echo "Policy integrity sidecar present; skipping."
        return 0
    fi

    if [ -e "$sidecar_file" ]; then
        echo "Error: policy integrity sidecar exists but is not a regular file: $sidecar_file" >&2
        exit 1
    fi

    echo "Policy integrity sidecar missing:"
    echo "  $sidecar_file"
    echo ""
    echo "APlane now requires policy.yaml to be signed before the signer can unlock or reload."
    echo "The installer can sign the current policy file using your store passphrase."
    echo ""

    if [ ! -r /dev/tty ]; then
        echo "Error: cannot sign policy without a TTY." >&2
        echo "Run this manually before starting apsigner:" >&2
        if [ ! -f "$policy_file" ]; then
            echo "  printf '\\n' > $(shell_quote "$policy_file")" >&2
        fi
        echo "  $(shell_quote "$apstore_bin") -d $(shell_quote "$data_dir") policy sign" >&2
        exit 1
    fi

    if [ ! -f "$policy_file" ]; then
        if [ -e "$policy_file" ]; then
            echo "Error: policy path exists but is not a regular file: $policy_file" >&2
            exit 1
        fi
        echo "No policy.yaml found; an empty policy baseline will be created before signing."
        policy_missing=1
    else
        "$apstore_bin" -d "$data_dir" policy check
    fi

    read -rp "Sign policy.yaml now? [Y/n] " answer </dev/tty
    if [ -n "$answer" ] && [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "Policy was not signed. Run this before starting apsigner:" >&2
        echo "  $(shell_quote "$apstore_bin") -d $(shell_quote "$data_dir") policy sign" >&2
        exit 1
    fi

    if [ "$policy_missing" = "1" ]; then
        echo "Creating empty policy baseline."
        mkdir -p "$identity_dir"
        : > "$policy_file"
        chmod 600 "$policy_file"
        "$apstore_bin" -d "$data_dir" policy check
    fi

    "$apstore_bin" -d "$data_dir" policy sign </dev/tty
}

install_prod_uninstaller() {
    local data_dir="$1"
    local install_dir="$data_dir/install"
    local src="$SCRIPT_DIR/uninstall.sh"
    local dest="$install_dir/uninstall.sh"

    if [ ! -f "$src" ]; then
        echo "Error: uninstall.sh not found at $src" >&2
        return 1
    fi

    mkdir -p "$install_dir"
    cp "$src" "$dest"
    chown root:"$SVC_GROUP" "$install_dir" "$dest"
    chmod 2750 "$install_dir"
    chmod 750 "$dest"
    echo "Installed systemd uninstaller to $dest"
}

write_prod_operator_root_metadata() {
    local data_dir="$1"
    local operator_root="$2"
    local install_dir="$data_dir/install"
    local target="$install_dir/operator-root"

    mkdir -p "$install_dir"
    printf '%s\n' "$operator_root" > "$target"
    chown root:"$SVC_GROUP" "$target"
    chmod 640 "$target"
}

abort_if_macos_install_processes_running() {
    local install_root="$1"
    [ "$(uname -s)" = "Darwin" ] || return 0
    command -v pgrep >/dev/null 2>&1 || return 0

    install_root="${install_root%/}"
    local found=0
    local pid exe
    for name in apsigner apadmin apconsole apshell apstore apapprover appass aplocalnet; do
        while IFS= read -r pid; do
            [ -n "$pid" ] || continue
            exe="$(ps -p "$pid" -o comm= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || true)"
            if [ "${exe#/}" = "$exe" ] && command -v lsof >/dev/null 2>&1; then
                exe="$(lsof -nP -p "$pid" -a -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1 || true)"
            fi
            if [ "${exe#/}" = "$exe" ]; then
                exe="$(ps -p "$pid" -o command= 2>/dev/null | awk '{print $1}' || true)"
            fi
            case "$exe" in
                "$install_root"/*)
                    if [ "$found" = "0" ]; then
                        echo "Error: APlane processes from this install are still running:" >&2
                        found=1
                    fi
                    echo "  pid $pid: $exe" >&2
                    ;;
            esac
        done <<EOF
$(pgrep -x "$name" 2>/dev/null || true)
EOF
    done

    if [ "$found" = "1" ]; then
        echo "" >&2
        echo "Installation terminating due to running APlane processes." >&2
        echo "Please stop those processes and restart the installation with:" >&2
        echo "  ./install.sh" >&2
        echo "" >&2
        echo "If you installed from the bootstrap command, you can restart with:" >&2
        echo "  curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash" >&2
        echo "" >&2
        echo "For the default local install, the common long-running process is usually stopped with:" >&2
        echo "  pkill apsigner 2>/dev/null || true" >&2
        echo "" >&2
        echo "If you use a custom path or flags, pass the same arguments again, for example:" >&2
        echo "  curl -fsSL https://raw.githubusercontent.com/aplane-algo/aplane/main/bootstrap-install.sh | bash -s -- /path/to/aplane" >&2
        exit 1
    fi
}

repair_macos_binary() {
    local path="$1"
    [ "$(uname -s)" = "Darwin" ] || return 0

    xattr -d com.apple.quarantine "$path" >/dev/null 2>&1 || true
    if command -v codesign >/dev/null 2>&1; then
        codesign --force --sign - "$path" >/dev/null 2>&1 || true
    fi
}

LOCALNET_SETUP_APPLIED=0

offer_localnet_setup() {
    local aplocalnet_bin="$1"
    local client_data="${2:-}"
    local signer_data="${3:-}"

    LOCALNET_SETUP_APPLIED=0
    [ -x "$aplocalnet_bin" ] || return 0
    [ -n "$client_data" ] || [ -n "$signer_data" ] || return 0
    [ -r /dev/tty ] || return 0
    if [ "${APLANE_SKIP_LOCALNET_SETUP:-}" = "1" ]; then
        echo "Skipping LocalNet setup (APLANE_SKIP_LOCALNET_SETUP=1)."
        return 0
    fi

    local check_output
    if ! check_output="$("$aplocalnet_bin" --check 2>&1)"; then
        return 0
    fi

    echo ""
    echo "=== AlgoKit LocalNet detected ==="
    printf '%s\n' "$check_output" | while IFS= read -r line; do
        echo "  $line"
    done
    echo ""
    local target_text=""
    if [ -n "$client_data" ]; then
        target_text="client data at $client_data"
    fi
    if [ -n "$signer_data" ]; then
        if [ -n "$target_text" ]; then
            target_text="$target_text and signer data at $signer_data"
        else
            target_text="signer data at $signer_data"
        fi
    fi
    read -rp "Apply LocalNet setup to this install ($target_text)? [Y/n] " answer </dev/tty
    if [ "$answer" = "n" ] || [ "$answer" = "N" ]; then
        echo "Skipped LocalNet setup. You can run aplocalnet later."
        return 0
    fi

    local args=(--apply)
    if [ -n "$client_data" ]; then
        args+=(--client-data "$client_data")
    fi
    if [ -n "$signer_data" ]; then
        args+=(--signer-data "$signer_data")
    fi
    if "$aplocalnet_bin" "${args[@]}"; then
        LOCALNET_SETUP_APPLIED=1
    else
        echo "Warning: LocalNet setup failed; continuing installation." >&2
    fi
}

# --- Client-only mode ---
if [ "$CLIENT_MODE" = "1" ]; then
    # Guard: refuse to run as root in client mode
    if [ "$(id -u)" -eq 0 ]; then
        echo "Error: --client must not be run as root." >&2
        echo "Client mode installs client binaries under a user directory." >&2
        exit 1
    fi

    if [ ${#POSITIONAL[@]} -gt 1 ]; then
        echo "Error: --client accepts at most one optional path argument." >&2
        echo "Usage: $0 --client [-f|--force] [path]" >&2
        exit 2
    fi

    # Verify client binaries exist in source
    if [ ! -f "$BIN_SRC/apshell" ]; then
        echo "Error: apshell binary not found at $BIN_SRC/apshell" >&2
        exit 1
    fi
    if [ ${#POSITIONAL[@]} -gt 0 ]; then
        CLIENT_PATH="${POSITIONAL[0]}"
    elif [ -n "$INSTALL_ROOT_ENV" ]; then
        CLIENT_PATH="$INSTALL_ROOT_ENV"
    else
        CLIENT_PATH="$(prompt_install_path "$HOME/aplane")"
    fi
    mkdir -p -- "$CLIENT_PATH"
    CLIENT_PATH="$(cd "$CLIENT_PATH" && pwd)"

    APCLIENT_DIR="$CLIENT_PATH/apclient"
    BINDIR="$APCLIENT_DIR/bin"
    abort_if_macos_install_processes_running "$CLIENT_PATH"
    if [ -d "$APCLIENT_DIR" ] && ! dir_is_empty "$APCLIENT_DIR"; then
        require_supported_upgrade "$CLIENT_PATH/install/release.json" "client install" "$CLIENT_PATH"
    fi

    echo "=== aplane client installer (client-only mode) ==="
    echo ""
    echo "  Source:    $SCRIPT_DIR"
    echo "  Root:      $CLIENT_PATH"
    echo "  Binaries:  $APCLIENT_DIR/bin/apshell"
    echo "  Config:    $APCLIENT_DIR/config.yaml"
    echo ""

    # Resolve/build bundled plugin payloads before mutating the install.
    prepare_builtin_plugin_payloads

    # Install client binaries
    mkdir -p "$BINDIR" "$APCLIENT_DIR/.ssh" "$APCLIENT_DIR/plugins.available" "$APCLIENT_DIR/scripts"
    install_release_metadata "$CLIENT_PATH/install"
    echo "Installing client binaries to $BINDIR..."
    cp "$BIN_SRC/apshell" "$BINDIR/apshell"
    chmod 755 "$BINDIR/apshell"
    repair_macos_binary "$BINDIR/apshell"
    if [ -f "$BIN_SRC/aplocalnet" ]; then
        cp "$BIN_SRC/aplocalnet" "$BINDIR/aplocalnet"
        chmod 755 "$BINDIR/aplocalnet"
        repair_macos_binary "$BINDIR/aplocalnet"
    fi
    install_builtin_plugins "$APCLIENT_DIR"

    # Bootstrap [path]/apclient/
    echo ""
    echo "=== apshell configuration ==="
    echo ""
    APCLIENT_CONFIG="$APCLIENT_DIR/config.yaml"
    APCLIENT_ENDPOINTS="$APCLIENT_DIR/endpoints.yaml"
    WROTE_APCLIENT_CONFIG=0
    if [ -f "$APCLIENT_CONFIG" ]; then
        echo "Config already exists at $APCLIENT_CONFIG; leaving it unchanged."
    else
        echo "Writing $APCLIENT_CONFIG..."
        cat > "$APCLIENT_CONFIG" <<'EOF'
# apshell configuration (remote signer)
# See docs/USER_CONFIG.md for full documentation.

network: testnet
networks_allowed:
  - mainnet
  - testnet

signer_status_poll_interval: "10s"

networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
  mainnet:
    algod:
      server: https://mainnet-api.4160.nodely.dev
      token: ""
  localnet:
    algod:
      server: http://localhost:4001
      token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EOF
        WROTE_APCLIENT_CONFIG=1
    fi
    if [ -f "$APCLIENT_ENDPOINTS" ]; then
        echo "Endpoint registry already exists at $APCLIENT_ENDPOINTS; leaving it unchanged."
    elif [ "$WROTE_APCLIENT_CONFIG" = "1" ]; then
        echo "Writing $APCLIENT_ENDPOINTS..."
        write_apshell_endpoint_registry "$APCLIENT_ENDPOINTS" "CHANGE_ME" 11270 1127
    fi

    # Generate SSH key for signer tunnel (optional, skip if ssh-keygen not available)
    SSH_KEY="$APCLIENT_DIR/.ssh/id_ed25519"
    if [ -f "$SSH_KEY" ]; then
        echo "SSH key already exists at $SSH_KEY; skipping generation."
    elif ! command -v ssh-keygen >/dev/null 2>&1; then
        echo "Note: ssh-keygen not found; skipping SSH key generation."
        echo "  Install OpenSSH client tools and run manually:"
        echo "  ssh-keygen -t ed25519 -f $SSH_KEY -N \"\""
    else
        echo "Generating SSH key for signer tunnel..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
        echo "  Created $SSH_KEY"
    fi

    # Write apenv.sh
    ENV_SH="$APCLIENT_DIR/apenv.sh"
    cat > "$ENV_SH" <<ENVEOF
# Source this file to set up apshell environment:
#   source $ENV_SH

case ":\$PATH:" in
  *":$BINDIR:"*) ;;
  *) export PATH="$BINDIR:\$PATH" ;;
esac
export APLANE_INSTALL_ROOT="$CLIENT_PATH"
export APCLIENT_DATA="$APCLIENT_DIR"
ENVEOF
    bash -n "$ENV_SH"
    write_mcp_config "$APCLIENT_DIR" "$BINDIR/apshell"

    offer_localnet_setup "$BINDIR/aplocalnet" "$APCLIENT_DIR" ""

    # Offer to add apenv.sh to shell rc
    SHELL_RC="$(detect_shell_rc "$HOME")"
    GUARD="# aplane env"
    if [ -f "$SHELL_RC" ] && grep -qF "$GUARD" "$SHELL_RC"; then
        echo "apenv.sh already sourced in $SHELL_RC; skipping."
    else
        echo ""
        read -rp "Add apenv.sh to $SHELL_RC for automatic setup? [Y/n] " answer </dev/tty
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            echo "" >> "$SHELL_RC"
            echo "$GUARD" >> "$SHELL_RC"
            echo ". $(shell_quote "$ENV_SH")" >> "$SHELL_RC"
            echo "Added apenv.sh to $SHELL_RC"
        else
            echo "Skipped. To set up manually, run:"
            echo "  source $(shell_quote "$ENV_SH")"
        fi
    fi

    echo ""
    echo "=== Installation complete ==="
    echo ""
    echo "Next steps:"
    echo "  1. Start a new shell, or run: source $(shell_quote "$ENV_SH")"
    echo "  2. Edit $APCLIENT_CONFIG to set your signer host"
    if [ -f "$SSH_KEY.pub" ]; then
        echo "  3. Give your public key to the signer operator:"
        echo "     cat $SSH_KEY.pub"
        echo "  4. Run apshell, then use 'request-token' to get an API token"
    else
        echo "  3. Generate an SSH key and give the public key to the signer operator"
        echo "  4. Run apshell, then use 'request-token' to get an API token"
    fi
    exit 0
fi

# --- Local mode ---
if [ "$LOCAL_MODE" = "1" ]; then
    # Guard: refuse to run as root in local mode
    if [ "$(id -u)" -eq 0 ]; then
        echo "Error: local mode must not be run as root." >&2
        echo "Local mode installs into a user directory without systemd or system users." >&2
        echo "For systemd installs, use: sudo $0 --systemd" >&2
        exit 1
    fi
    if [ ${#POSITIONAL[@]} -gt 1 ]; then
        echo "Error: local mode accepts at most one optional path argument." >&2
        echo "Usage: $0 [-f|--force] [--role signer|sentry] [path]" >&2
        exit 2
    fi

    # Resolve install root
    if [ -n "$LOCAL_PATH" ]; then
        LOCAL_PATH="$(expand_user_path "$LOCAL_PATH")"
        ensure_dir_or_missing "$LOCAL_PATH" "install root"
        mkdir -p -- "$LOCAL_PATH"
        LOCAL_PATH="$(cd "$LOCAL_PATH" && pwd)"
    else
        LOCAL_PATH="$(prompt_install_path "$HOME/aplane")"
        ensure_dir_or_missing "$LOCAL_PATH" "install root"
        mkdir -p -- "$LOCAL_PATH"
        LOCAL_PATH="$(cd "$LOCAL_PATH" && pwd)"
    fi
    INSTALL_ROOT="$LOCAL_PATH/apsigner"
    SIGNER_BINDIR="$INSTALL_ROOT/bin"
    DATA_DIR="$INSTALL_ROOT"

    APCLIENT_DIR="$LOCAL_PATH/apclient"
    CLIENT_BINDIR="$APCLIENT_DIR/bin"
    LOCAL_SIGNER_STOP_CHECKED=0
    if [ -x "$BIN_SRC/approbe" ] &&
       { [ -d "$INSTALL_ROOT" ] || [ -d "$APCLIENT_DIR" ]; }; then
        require_local_signer_stopped "$DATA_DIR" "repair"
        LOCAL_SIGNER_STOP_CHECKED=1
    fi
    INSTALL_MODE="$(classify_local_install "$LOCAL_PATH" "$INSTALL_ROOT" "$APCLIENT_DIR")"
    if [ "$INSTALL_MODE" = "upgrade" ]; then
        require_supported_upgrade "$LOCAL_PATH/install/release.json" "local install" "$LOCAL_PATH"
    fi
    if [ "$LOCAL_SIGNER_STOP_CHECKED" != "1" ]; then
        require_local_signer_stopped "$DATA_DIR" "$INSTALL_MODE"
    fi
    abort_if_macos_install_processes_running "$LOCAL_PATH"

    # Pick random available ports for this install
    SIGNER_PORT="$(find_available_port)"
    SSH_PORT="$(find_available_port)"
    MEMORY_LOCK_REQUESTED=0

    print_local_install_plan "$INSTALL_MODE" "$LOCAL_PATH" "$INSTALL_ROOT" "$APCLIENT_DIR" "$SIGNER_PORT" "$SSH_PORT" "$NODE_ROLE"
    read -rp "Proceed with installation? [Y/n] " answer </dev/tty
    if [ -n "$answer" ] && [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "Cancelled."
        echo "Re-run with: $RERUN_CMD"
        exit 0
    fi
    if prompt_linux_memory_lock; then
        MEMORY_LOCK_REQUESTED=1
    fi
    echo ""

    # Resolve/build bundled plugin payloads before replacing binaries.
    prepare_builtin_plugin_payloads

    # Create directories
    mkdir -p "$SIGNER_BINDIR" "$CLIENT_BINDIR"

    # Copy binaries (apshell/aplocalnet → apclient/bin, everything else → apsigner/bin)
    echo "Installing binaries..."
    for bin in "$BIN_SRC"/*; do
        [ -f "$bin" ] || continue
        name="$(basename "$bin")"
        if [ "$name" = "apkey-migrate" ] || [ "$name" = "migrate-config-v1" ]; then
            echo "  skipping obsolete $name"
            continue
        fi
        if [ "$name" = "apshell" ] || [ "$name" = "aplocalnet" ]; then
            cp "$bin" "$CLIENT_BINDIR/"
            chmod 755 "$CLIENT_BINDIR/$name"
            repair_macos_binary "$CLIENT_BINDIR/$name"
            echo "  $name → $CLIENT_BINDIR"
        else
            cp "$bin" "$SIGNER_BINDIR/"
            chmod 755 "$SIGNER_BINDIR/$name"
            repair_macos_binary "$SIGNER_BINDIR/$name"
            echo "  $name → $SIGNER_BINDIR"
        fi
    done

    MEMORY_LOCK_ENABLED=0
    if [ "$MEMORY_LOCK_REQUESTED" = "1" ]; then
        if enable_binary_memory_lock "$SIGNER_BINDIR/apsigner"; then
            MEMORY_LOCK_ENABLED=1
        else
            echo "Memory locking was requested but could not be enabled; config will not require it."
        fi
    fi

    # Copy optional template library into APSIGNER_DATA for apstore imports.
    echo ""
    echo "Installing template library..."
    install_template_library "$DATA_DIR"

    # Generate signer config
    CONFIG_PATH="$DATA_DIR/config.yaml"
    echo ""
    if [ -f "$CONFIG_PATH" ]; then
        CONFIG_NEW_PATH="$CONFIG_PATH.aplane-installer.new"
        echo "Config already exists at $CONFIG_PATH; leaving it unchanged."
        echo "Writing canonical template to $CONFIG_NEW_PATH..."
        write_signer_config "$CONFIG_NEW_PATH" "$SIGNER_PORT" "$SSH_PORT" "$([ "$MEMORY_LOCK_ENABLED" = "1" ] && echo true || echo false)"
        if [ "$MEMORY_LOCK_ENABLED" = "1" ]; then
            echo "Updating $CONFIG_PATH to require memory protection."
            set_require_memory_protection_true "$CONFIG_PATH"
        fi
    else
        echo "Writing $CONFIG_PATH..."
        write_signer_config "$CONFIG_PATH" "$SIGNER_PORT" "$SSH_PORT" "$([ "$MEMORY_LOCK_ENABLED" = "1" ] && echo true || echo false)"
    fi

    # Write apenv.sh at the parent level
    ENV_SH="$LOCAL_PATH/apenv.sh"
    cat > "$ENV_SH" <<ENVEOF
# Source this file to set up aplane environment:
#   source $ENV_SH

case ":\$PATH:" in
  *":$SIGNER_BINDIR:"*) ;;
  *) export PATH="$SIGNER_BINDIR:\$PATH" ;;
esac
case ":\$PATH:" in
  *":$CLIENT_BINDIR:"*) ;;
  *) export PATH="$CLIENT_BINDIR:\$PATH" ;;
esac
export APLANE_INSTALL_ROOT="$LOCAL_PATH"
export APSIGNER_DATA="$DATA_DIR"
export APCLIENT_DATA="$APCLIENT_DIR"
ENVEOF
    bash -n "$ENV_SH"

    APCONSOLE_CONFIG="$LOCAL_PATH/apconsole.yaml"
    echo "Writing $APCONSOLE_CONFIG..."
    write_apconsole_profile "$APCONSOLE_CONFIG" local ./apclient ./apsigner

    # Write start.sh unified console launcher.
    START_SH="$LOCAL_PATH/start.sh"
    cat > "$START_SH" <<'STARTEOF'
#!/bin/bash
# APlane unified console launcher.

if [ -n "${BASH_SOURCE[0]}" ] && [ "${BASH_SOURCE[0]}" != "$0" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi
. "$SCRIPT_DIR/apenv.sh"

if [ -z "$APSIGNER_DATA" ] || [ ! -d "$APSIGNER_DATA" ]; then
    echo "Error: APSIGNER_DATA is not set or does not exist" >&2
    exit 1
fi
if [ -z "$APCLIENT_DATA" ] || [ ! -d "$APCLIENT_DATA" ]; then
    echo "Error: APCLIENT_DATA is not set or does not exist" >&2
    exit 1
fi

exec apconsole -config "$SCRIPT_DIR/apconsole.yaml"
STARTEOF
    chmod +x "$START_SH"
    bash -n "$START_SH"
    rm -f "$LOCAL_PATH/start-tmux.sh" "$LOCAL_PATH/start-screen.sh"

    # Copy uninstall helper
    if [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
        cp "$SCRIPT_DIR/uninstall.sh" "$LOCAL_PATH/uninstall.sh"
        chmod +x "$LOCAL_PATH/uninstall.sh"
    fi
    install_release_metadata "$LOCAL_PATH/install"

    # Initialize keystore (skip if already initialized)
    echo ""
    echo "=== Keystore initialization ==="
    echo ""
    if [ -f "$DATA_DIR/identities/default/.keystore" ]; then
        echo "Keystore already initialized; skipping."
    else
        "$SIGNER_BINDIR/apstore" -d "$DATA_DIR" initialize --role "$NODE_ROLE" </dev/tty
    fi
    ensure_policy_integrity_sidecar "$DATA_DIR" "$SIGNER_BINDIR/apstore"

    # Configure apshell
    echo ""
    echo "=== apshell configuration ==="
    echo ""
    mkdir -p "$APCLIENT_DIR" "$APCLIENT_DIR/plugins.available" "$APCLIENT_DIR/scripts"
    install_builtin_plugins "$APCLIENT_DIR"

    APCLIENT_CONFIG="$APCLIENT_DIR/config.yaml"
    APCLIENT_ENDPOINTS="$APCLIENT_DIR/endpoints.yaml"
    WROTE_APCLIENT_CONFIG=0
    if [ -f "$APCLIENT_CONFIG" ]; then
        echo "Config already exists at $APCLIENT_CONFIG; leaving it unchanged."
    else
        echo "Writing $APCLIENT_CONFIG..."
        write_apshell_local_config "$APCLIENT_CONFIG" "$SIGNER_PORT" "$SSH_PORT"
        WROTE_APCLIENT_CONFIG=1
    fi
    if [ -f "$APCLIENT_ENDPOINTS" ]; then
        echo "Endpoint registry already exists at $APCLIENT_ENDPOINTS; leaving it unchanged."
    elif [ "$WROTE_APCLIENT_CONFIG" = "1" ]; then
        echo "Writing $APCLIENT_ENDPOINTS..."
        write_apshell_endpoint_registry_for_role "$APCLIENT_ENDPOINTS" "$NODE_ROLE" 127.0.0.1 "$SIGNER_PORT" "$SSH_PORT"
    fi

    if [ "$NODE_ROLE" = "signer" ]; then
        check_local_config_consistency "$CONFIG_PATH" "$APCLIENT_CONFIG"
    fi
    write_mcp_config "$APCLIENT_DIR" "$CLIENT_BINDIR/apshell"

    offer_localnet_setup "$CLIENT_BINDIR/aplocalnet" "$APCLIENT_DIR" "$DATA_DIR"

    if [ "$NODE_ROLE" = "signer" ]; then
        echo "Token setup uses SSH provisioning; run 'request-token' from apshell after install."
    else
        echo "Token setup uses SSH provisioning; after unlocking the sentry, run"
        echo "'request-token --endpoint local-sentry' from apshell in another terminal."
    fi

    # Offer to add apenv.sh to shell rc
    SHELL_RC="$(detect_shell_rc "$HOME")"
    GUARD="# aplane env"
    if [ -f "$SHELL_RC" ] && grep -qF "$GUARD" "$SHELL_RC"; then
        echo "apenv.sh already sourced in $SHELL_RC; skipping."
    else
        echo ""
        read -rp "Add apenv.sh to $SHELL_RC for automatic setup? [Y/n] " answer </dev/tty
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            echo "" >> "$SHELL_RC"
            echo "$GUARD" >> "$SHELL_RC"
            echo ". $(shell_quote "$ENV_SH")" >> "$SHELL_RC"
            echo "Added apenv.sh to $SHELL_RC"
        else
            echo "Skipped. To set up manually, run:"
            echo "  source $(shell_quote "$ENV_SH")"
        fi
    fi

    echo ""
    echo "=== Installation complete ==="
    echo ""
    echo "Launch the unified console:"
    echo "  $(shell_quote "$START_SH")"
    echo ""
    if [ "$NODE_ROLE" = "signer" ]; then
        echo "On first launch, unlock the signer pane, run 'request-token' in the shell pane,"
        echo "and approve the request in the signer pane."
    else
        echo "On first launch, unlock the sentry admin pane. Then open another terminal,"
        echo "source $(shell_quote "$ENV_SH"), start apshell, and run"
        echo "  request-token --endpoint local-sentry"
        echo "Approve the request in the sentry admin pane."
    fi
    echo ""
    echo "To uninstall: $(shell_quote "$LOCAL_PATH/uninstall.sh")"
    exit 0
fi

# --- Systemd mode ---
if [ "$PROD_MODE" != "1" ]; then
    echo "Error: unexpected state." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: --systemd must be run as root (use sudo)." >&2
    exit 1
fi

if [ ${#POSITIONAL[@]} -gt 1 ]; then
    echo "Usage: sudo $0 --systemd [-f|--force] [--role signer|sentry] [operator-root] [--bindir <path>] [--no-enable] [--no-start]" >&2
    exit 2
fi
PROD_OPERATOR_ROOT_INPUT="${POSITIONAL[0]:-${INSTALL_ROOT_ENV:-}}"
require_prod_service_stopped

# Ensure bindir exists and resolve to absolute path
mkdir -p -- "$BINDIR"
BINDIR="$(cd "$BINDIR" && pwd)"

OPERATOR_ROOT=""
OPERATOR_ROOT_REUSE_CONFIRMED=0
if [ -n "${SUDO_USER:-}" ]; then
    SUDO_USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [ -z "$SUDO_USER_HOME" ]; then
        echo "Error: could not determine home directory for $SUDO_USER" >&2
        exit 1
    fi
    if [ -n "$PROD_OPERATOR_ROOT_INPUT" ]; then
        OPERATOR_ROOT="$(expand_path_for_home "$PROD_OPERATOR_ROOT_INPUT" "$SUDO_USER_HOME")"
    elif [ -r /dev/tty ]; then
        prompt_prod_operator_root "$SUDO_USER_HOME/aplane" "$SUDO_USER_HOME"
    else
        OPERATOR_ROOT="$SUDO_USER_HOME/aplane"
    fi
    ensure_dir_or_missing "$OPERATOR_ROOT" "operator root"
    if [ "${OPERATOR_ROOT#/}" = "$OPERATOR_ROOT" ]; then
        OPERATOR_ROOT="$(pwd)/$OPERATOR_ROOT"
    fi
    if [ "$OPERATOR_ROOT_REUSE_CONFIRMED" != "1" ] &&
       [ -d "$OPERATOR_ROOT" ] && ! dir_is_empty "$OPERATOR_ROOT"; then
        echo "Note: operator root already exists and is not empty: $OPERATOR_ROOT"
        echo "Existing apclient/config.yaml, .mcp.json, and .codex/config.toml are left in place;"
        echo "apenv.sh and apconsole.yaml are rewritten."
    fi
elif [ -n "$PROD_OPERATOR_ROOT_INPUT" ]; then
    echo "Error: operator-root requires sudo with SUDO_USER set; omit it when running directly as root." >&2
    exit 2
fi

echo "=== apsigner installer ==="
echo ""
echo "  Source:    $SCRIPT_DIR"
echo "  Bindir:    $BINDIR"
echo "  Data dir:  /var/lib/apsigner"
if [ -n "$OPERATOR_ROOT" ]; then
    echo "  Operator:  $OPERATOR_ROOT"
fi
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo "  Service:   apsigner.service (systemd)"
echo "  Mode:      locked-start (unlock via apadmin)"
echo "  Memory:    enforced memory locking enabled"
echo ""
if [ -r /dev/tty ]; then
    read -rp "Proceed with systemd install? [Y/n] " answer </dev/tty
    if [ -n "$answer" ] && [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "Cancelled."
        echo "Re-run with: $RERUN_CMD"
        exit 0
    fi
fi

MEMORY_LOCK_ENABLED=1

# Resolve/build bundled plugin payloads before replacing binaries or service files.
prepare_builtin_plugin_payloads

# Step 1: Create service group/user if they don't exist
if ! getent group "$SVC_GROUP" >/dev/null 2>&1; then
    echo "Creating system group $SVC_GROUP..."
    groupadd --system "$SVC_GROUP"
    echo "  Created group $SVC_GROUP"
else
    echo "Group $SVC_GROUP already exists, skipping creation."
fi

if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    echo "Creating system user $SVC_USER..."
    useradd -r -m -d /var/lib/apsigner -g "$SVC_GROUP" -s /usr/sbin/nologin "$SVC_USER"
    echo "  Created user $SVC_USER with home /var/lib/apsigner"
else
    echo "User $SVC_USER already exists, skipping creation."
fi

# Add the installing user to the service group (for apsigner access)
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "$SVC_USER" ]; then
    if ! id -nG "$SUDO_USER" 2>/dev/null | grep -qw "$SVC_GROUP"; then
        usermod -aG "$SVC_GROUP" "$SUDO_USER"
        GROUP_MEMBERSHIP_CHANGED=1
        echo "  Added $SUDO_USER to group $SVC_GROUP (log out and back in to take effect)"
    fi
fi

# Resolve data directory (needed for script installation and later steps)
DATA_DIR="$(getent passwd "$SVC_USER" | cut -d: -f6)"
if [ -z "$DATA_DIR" ]; then
    echo "Error: could not determine home directory for $SVC_USER" >&2
    exit 1
fi
if [ ! -d "$DATA_DIR" ]; then
    echo "Recreating missing data directory $DATA_DIR..."
fi
if [ -f "$DATA_DIR/identities/default/.keystore" ]; then
    require_supported_upgrade "$DATA_DIR/install/release.json" "systemd install" "$DATA_DIR"
fi
ensure_prod_data_dir_permissions "$DATA_DIR"
ensure_prod_backup_permissions "$DATA_DIR"
repair_prod_store_lock_permissions "$DATA_DIR"

PROD_MARKER_PATH="$DATA_DIR/.prod"
printf 'systemd-managed\n' > "$PROD_MARKER_PATH"
chown "$SVC_USER:$SVC_GROUP" "$PROD_MARKER_PATH"
chmod 640 "$PROD_MARKER_PATH"

# Step 2: Copy uninstall helper into the systemd-managed data directory
echo ""
echo "Installing systemd management scripts..."
install_prod_uninstaller "$DATA_DIR"
install_release_metadata "$DATA_DIR/install" root "$SVC_GROUP" 2750 640
if [ -n "$OPERATOR_ROOT" ]; then
    mkdir -p -- "$OPERATOR_ROOT"
    OPERATOR_ROOT="$(cd "$OPERATOR_ROOT" && pwd)"
    write_prod_operator_root_metadata "$DATA_DIR" "$OPERATOR_ROOT"
fi

# Step 3: Copy binaries
echo "Installing binaries to $BINDIR..."
for bin in "$BIN_SRC"/*; do
    [ -f "$bin" ] || continue
    name="$(basename "$bin")"
    if [ "$name" = "apkey-migrate" ] || [ "$name" = "migrate-config-v1" ]; then
        echo "  skipping obsolete $name"
        continue
    fi
    cp "$bin" "$BINDIR/"
    # Passphrase helpers must be executable by the unprivileged service user.
    # The appass-file secret itself stays protected by identity-scoped 0600 files.
    case "$name" in
        appass-file)          chmod 755 "$BINDIR/$name" ;;
        appass-systemd-creds) chmod 755 "$BINDIR/$name" ;;
        *)                  chmod 755 "$BINDIR/$name" ;;
    esac
    echo "  $name"
done

# Step 3b: Copy optional template library
echo ""
echo "Installing template library..."
install_template_library "$DATA_DIR" "$SVC_USER" "$SVC_GROUP"

# Step 4: Run systemd setup
echo ""
echo "Running systemd setup..."
SYSTEMD_SETUP_ARGS=("$SVC_USER" "$SVC_GROUP" "$BINDIR" --data-dir "$DATA_DIR")
if [ "$MEMORY_LOCK_ENABLED" = "1" ]; then
    SYSTEMD_SETUP_ARGS+=(--memory-lock)
fi
"$SCRIPT_DIR/installer/scripts/systemd-setup.sh" "${SYSTEMD_SETUP_ARGS[@]}"

# Step 5: Generate canonical signer config for this installation
CONFIG_PATH="$DATA_DIR/config.yaml"

echo ""
write_prod_signer_config() {
    local target="$1"
    write_signer_config "$target" 11270 1127 "$([ "$MEMORY_LOCK_ENABLED" = "1" ] && echo true || echo false)"
    chown "$SVC_USER:$SVC_GROUP" "$target"
    chmod 640 "$target"
}

if [ -f "$CONFIG_PATH" ]; then
    CONFIG_NEW_PATH="$CONFIG_PATH.aplane-installer.new"
    echo "Config already exists at $CONFIG_PATH; leaving it unchanged."
    echo "Writing canonical template to $CONFIG_NEW_PATH..."
    write_prod_signer_config "$CONFIG_NEW_PATH"
    if [ "$MEMORY_LOCK_ENABLED" = "1" ]; then
        echo "Updating $CONFIG_PATH to require memory protection."
        set_require_memory_protection_true "$CONFIG_PATH"
        chown "$SVC_USER:$SVC_GROUP" "$CONFIG_PATH"
        chmod 640 "$CONFIG_PATH"
    fi
else
    echo "Writing $CONFIG_PATH..."
    write_prod_signer_config "$CONFIG_PATH"
fi

# Step 6: Initialize keystore (before systemd starts the service)
echo ""
echo "=== Keystore initialization ==="
echo ""
if [ -f "$DATA_DIR/identities/default/.keystore" ]; then
    echo "Keystore already initialized; skipping."
    repair_prod_store_lock_permissions "$DATA_DIR"
else
    "$BINDIR/apstore" -d "$DATA_DIR" initialize --role "$NODE_ROLE" </dev/tty
    repair_prod_store_lock_permissions "$DATA_DIR"
fi
ensure_policy_integrity_sidecar "$DATA_DIR" "$BINDIR/apstore"

# Step 7: Configure apshell for the installing user
if [ -n "$SUDO_USER" ]; then
    APCLIENT_DIR="$OPERATOR_ROOT/apclient"
    echo ""
    echo "=== apshell configuration (for $SUDO_USER) ==="
    echo ""
    mkdir -p "$OPERATOR_ROOT" "$APCLIENT_DIR" "$APCLIENT_DIR/plugins.available" "$APCLIENT_DIR/scripts"
    install_builtin_plugins "$APCLIENT_DIR" "$SUDO_USER"

    APCLIENT_CONFIG="$APCLIENT_DIR/config.yaml"
    APCLIENT_ENDPOINTS="$APCLIENT_DIR/endpoints.yaml"
    WROTE_APCLIENT_CONFIG=0
    if [ -f "$APCLIENT_CONFIG" ]; then
        echo "Config already exists at $APCLIENT_CONFIG; leaving it unchanged."
    else
        echo "Writing $APCLIENT_CONFIG..."
        write_apshell_local_config "$APCLIENT_CONFIG"
        WROTE_APCLIENT_CONFIG=1
    fi
    if [ -f "$APCLIENT_ENDPOINTS" ]; then
        echo "Endpoint registry already exists at $APCLIENT_ENDPOINTS; leaving it unchanged."
    elif [ "$WROTE_APCLIENT_CONFIG" = "1" ]; then
        echo "Writing $APCLIENT_ENDPOINTS..."
        write_apshell_endpoint_registry_for_role "$APCLIENT_ENDPOINTS" "$NODE_ROLE" 127.0.0.1 11270 1127
    fi
    write_mcp_config "$APCLIENT_DIR" "$BINDIR/apshell"

    if [ "$NODE_ROLE" = "signer" ]; then
        echo "Token setup uses SSH provisioning; run 'request-token' from apshell after install."
    else
        echo "Token setup uses SSH provisioning; after unlocking the sentry, run"
        echo "'request-token --endpoint local-sentry' from apshell."
    fi

    APCONSOLE_CONFIG="$OPERATOR_ROOT/apconsole.yaml"
    echo "Writing $APCONSOLE_CONFIG..."
    write_apconsole_profile "$APCONSOLE_CONFIG" local ./apclient "$DATA_DIR"

    chown "$SUDO_USER" "$OPERATOR_ROOT" "$APCONSOLE_CONFIG"
    chown -R "$SUDO_USER" "$APCLIENT_DIR"
fi

# Step 8: Write apenv.sh for the installing user
if [ -n "$SUDO_USER" ]; then
    APCLIENT_DIR="${APCLIENT_DIR:-$OPERATOR_ROOT/apclient}"
    ENV_SH="$OPERATOR_ROOT/apenv.sh"
    echo ""
    echo "Writing $ENV_SH..."
    cat > "$ENV_SH" <<ENVEOF
# Source this file to set up aplane environment:
#   source $ENV_SH

case ":\$PATH:" in
  *":$BINDIR:"*) ;;
  *) export PATH="$BINDIR:\$PATH" ;;
esac
export APLANE_INSTALL_ROOT="$OPERATOR_ROOT"
export APLANE_BINDIR="$BINDIR"
export APSIGNER_DATA="$DATA_DIR"
export APCLIENT_DATA="$APCLIENT_DIR"
ENVEOF
    bash -n "$ENV_SH"
    chown "$SUDO_USER" "$ENV_SH"

    # Offer to add apenv.sh to shell rc
    SHELL_RC="$(detect_shell_rc "$SUDO_USER_HOME" "$SUDO_USER")"
    GUARD="# aplane env"
    if [ -f "$SHELL_RC" ] && grep -qF "$GUARD" "$SHELL_RC"; then
        echo "apenv.sh already sourced in $SHELL_RC; skipping."
    else
        echo ""
        read -rp "Add apenv.sh to $SHELL_RC for $SUDO_USER? [Y/n] " answer </dev/tty
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            echo "" >> "$SHELL_RC"
            echo "$GUARD" >> "$SHELL_RC"
            echo ". $(shell_quote "$ENV_SH")" >> "$SHELL_RC"
            chown "$SUDO_USER" "$SHELL_RC"
            echo "Added apenv.sh to $SHELL_RC"
        else
            echo "Skipped. To set up manually, run:"
            echo "  source $(shell_quote "$ENV_SH")"
        fi
    fi
fi

offer_localnet_setup "$BINDIR/aplocalnet" "${APCLIENT_DIR:-}" "$DATA_DIR"
if [ "$LOCALNET_SETUP_APPLIED" = "1" ]; then
    if [ -n "${SUDO_USER:-}" ] && [ -n "${APCLIENT_DIR:-}" ]; then
        chown -R "$SUDO_USER" "$APCLIENT_DIR"
        [ -n "${ENV_SH:-}" ] && chown "$SUDO_USER" "$ENV_SH"
    fi
    if [ -f "$DATA_DIR/config.yaml" ]; then
        chown "$SVC_USER:$SVC_GROUP" "$DATA_DIR/config.yaml"
        chmod 640 "$DATA_DIR/config.yaml"
    fi
fi

# Step 9: Enable and start the service
echo ""
if [ "$ENABLE_SERVICE" = "1" ]; then
    echo "Enabling apsigner service..."
    systemctl enable apsigner
else
    echo "Skipping service enable (--no-enable)."
fi

if [ "$START_SERVICE" = "1" ]; then
    echo "Starting apsigner service..."
    systemctl start apsigner
    echo "  apsigner service started"
else
    echo "Skipping service start (--no-start)."
fi

echo ""
echo "=== Installation complete ==="
echo ""
if [ "$GROUP_MEMBERSHIP_CHANGED" = "1" ]; then
    echo "Your user was added to the $SVC_GROUP group during this install."
    echo "Log out and back in before running apadmin, or start a group-enabled shell with:"
    echo "  newgrp $SVC_GROUP"
    echo ""
fi
if [ "$NODE_ROLE" = "signer" ]; then
    echo "The signer is running but locked. To unlock and manage keys:"
else
    echo "The sentry is running but locked. To unlock and manage component keys:"
fi
echo "  apadmin"
echo ""
echo "Start a new shell, or run:"
echo "  source $(shell_quote "${ENV_SH:-~/aplane/apenv.sh}")"
echo "If apadmin cannot access $DATA_DIR, refresh your login session for $SVC_GROUP group access."
echo ""
echo "The systemd uninstaller is available at:"
echo "  $DATA_DIR/install/uninstall.sh"
echo ""
echo "apshell is configured at ${APCLIENT_DIR:-\$HOME/aplane/apclient}."
if [ "$NODE_ROLE" = "signer" ]; then
    echo "Use 'request-token' in apshell to obtain an API token via SSH provisioning."
else
    echo "Use 'request-token --endpoint local-sentry' in apshell to obtain a sentry API token via SSH provisioning."
fi
if [ "$NODE_ROLE" = "signer" ]; then
    echo "After token enrollment has written aplane.token and known_hosts, use apconsole for the unified secure-machine console."
else
    echo "After token enrollment has written tokens/local-sentry.token and known_hosts, use apconsole for the unified secure-machine console."
fi
