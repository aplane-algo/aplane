#!/bin/bash
# uninstall.sh - Remove an aplane installation
#
# Local mode (default, preserves apsigner/ and apclient/ state):
#   ./uninstall.sh [path]
#   ./uninstall.sh --local [path]
#
# Client-only mode:
#   ./uninstall.sh --client [path]
#
# Systemd mode:
#   sudo ./uninstall.sh [--systemd] [operator-root] [--bindir <path>]
#
# Local uninstall preserves signer/client state by default. Systemd uninstall
# preserves signer data and removes operator client files only from an explicit
# or installer-recorded operator root.

# Refuse to run when sourced
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: $0 [path]" >&2
    echo "       $0 --local [path]" >&2
    echo "       $0 --client [path]" >&2
    if [ "$(uname -s)" = "Linux" ]; then
        echo "       sudo $0 [--systemd] [operator-root] [--bindir <path>]" >&2
    fi
    return 1
fi

set -euo pipefail

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

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

expand_path_for_home() {
    local path="$1"
    local user_home="$2"
    case "$path" in
        "~")   printf '%s\n' "$user_home" ;;
        "~/"*) printf '%s\n' "$user_home/${path#~/}" ;;
        *)     printf '%s\n' "$path" ;;
    esac
}

sed_inplace() {
    if [ "$(uname -s)" = "Darwin" ]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

shell_quote() {
    local value="$1"
    printf "'%s'" "$(printf '%s' "$value" | sed "s/'/'\\\\''/g")"
}

toml_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "$value"
}

codex_mcp_config_matches_install() {
    local config="$1"
    local apshell_bin="$2"
    local data_dir="$3"
    local apshell_bin_toml
    local data_dir_toml
    apshell_bin_toml="$(toml_escape "$apshell_bin")"
    data_dir_toml="$(toml_escape "$data_dir")"

    [ -f "$config" ] &&
        grep -qF '[mcp_servers.aplane]' "$config" &&
        grep -qF "command = \"$apshell_bin_toml\"" "$config" &&
        grep -qF "args = [\"--mcp\", \"-d\", \"$data_dir_toml\"]" "$config"
}

is_linux() {
    [ "$(uname -s)" = "Linux" ]
}

canonical_dir() {
    local path="$1"
    if [ -d "$path" ]; then
        (cd "$path" && pwd)
    else
        printf '%s\n' "$path"
    fi
}

is_prod_data_dir() {
    local data_dir="$1"
    [ -n "$data_dir" ] && [ -f "$data_dir/.prod" ]
}

script_dir_looks_like_local_install() {
    [ -d "$SCRIPT_DIR/apsigner" ] ||
    [ -d "$SCRIPT_DIR/apclient" ] ||
    [ -f "$SCRIPT_DIR/apenv.sh" ] ||
    [ -f "$SCRIPT_DIR/apconsole.yaml" ] ||
    [ -f "$SCRIPT_DIR/start.sh" ]
}

default_local_uninstall_path() {
    if script_dir_looks_like_local_install; then
        printf '%s\n' "$SCRIPT_DIR"
    else
        printf '%s\n' "$HOME/aplane"
    fi
}

remove_shell_rc_env_block() {
    local shell_rc="$1"
    local env_path="$2"
    local expected_line=". $(shell_quote "$env_path")"
    local tmp="${shell_rc}.aplane-uninstall.$$"

    [ -f "$shell_rc" ] || return 1
    if awk -v expected="$expected_line" '
        $0 == "# aplane env" {
            if ((getline nextline) > 0) {
                if (nextline == expected) {
                    removed = 1
                    next
                }
                print $0
                print nextline
                next
            }
        }
        { print }
        END { exit removed ? 0 : 1 }
    ' "$shell_rc" > "$tmp"; then
        mv "$tmp" "$shell_rc"
        return 0
    fi

    rm -f "$tmp"
    return 1
}

die_prod_mode_required() {
    die "systemd install detected at $PROD_DATA_DIR_INPUT; uninstall mode required. Rerun with --systemd. To uninstall a local installation, use the --local flag"
}

prompt_uninstall_mode() {
    if ! is_linux; then
        return 0
    fi

    if ! : 2>/dev/null >/dev/tty; then
        if [ -n "$PROD_DATA_DIR_INPUT" ]; then
            die_prod_mode_required
        fi
        die "uninstall mode required; rerun with --local, --client, or --systemd"
    fi

    if [ -n "$PROD_DATA_DIR_INPUT" ]; then
        echo "Systemd install detected at $PROD_DATA_DIR_INPUT."
    fi

    echo "APlane uninstall modes:"
    echo "  [L]ocal       — remove local binaries/helpers, preserve local state"
    echo "  [S]ystemd     — remove systemd-managed apsigner service (requires sudo)"
    echo ""

    local answer default prompt
    if [ -n "$PROD_DATA_DIR_INPUT" ]; then
        default="S"
        prompt="Choose mode [l/S]: "
    else
        default="L"
        prompt="Choose mode [L/s]: "
    fi

    if ! read -rp "$prompt" answer </dev/tty; then
        if [ -n "$PROD_DATA_DIR_INPUT" ]; then
            die_prod_mode_required
        fi
        die "uninstall mode required; rerun with --local, --client, or --systemd"
    fi

    case "${answer:-$default}" in
        local|Local|LOCAL|l|L)
            EXPLICIT_LOCAL_MODE=1
            return 0
            ;;
        systemd|Systemd|SYSTEMD|s|S)
            PROD_MODE=1
            return 0
            ;;
        *)
            echo "Unrecognized choice: $answer" >&2
            echo "Expected L (local) or S (systemd)." >&2
            exit 2
            ;;
    esac
}

CLIENT_MODE=0
EXPLICIT_LOCAL_MODE=0
PROD_MODE=0
EXPLICIT_PROD_MODE=0
SVC_USER="aplane"
SVC_GROUP="aplane"
BINDIR="/usr/local/bin"
POSITIONAL=()

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            cat <<'EOF'
Usage: uninstall.sh [options] [path]

Modes:
  [path]                    Remove local binaries/helpers while preserving state
                            (default root: $HOME/aplane, or this script's
                            directory when run from an installed local helper)
  --local [path]            Force local uninstall mode. If [path] is omitted,
                            prompts for the local APlane directory.
  --client [path]           Remove a client-only installation under [path]/apclient
                            (default root: $HOME/aplane)
EOF
            if is_linux; then
                cat <<'EOF'
  --systemd [operator-root]
                            Remove a Systemd installation (requires sudo;
                            preserves /var/lib/apsigner). operator-root defaults
                            to the install-recorded value. If no value is
                            recorded, operator client files are left untouched.
                            If no mode flag is provided, uninstall.sh prompts
                            for local or systemd.

Options:
  --bindir <path>           Binary directory for --systemd (default: /usr/local/bin)
EOF
            else
                cat <<'EOF'

Options:
EOF
            fi
            cat <<'EOF'
  -h, --help                Show this help
EOF
            exit 0
            ;;
        --systemd)
            PROD_MODE=1
            EXPLICIT_PROD_MODE=1
            shift
            ;;
        --local)
            EXPLICIT_LOCAL_MODE=1
            shift
            ;;
        --client)
            CLIENT_MODE=1
            shift
            ;;
        --bindir)
            [ $# -ge 2 ] || die "--bindir requires a value"
            BINDIR="$2"
            shift 2
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

# Validate mutually exclusive flags
if [ "$PROD_MODE" = "1" ] && [ "$CLIENT_MODE" = "1" ]; then
    die "--systemd and --client are mutually exclusive"
fi
if [ "$EXPLICIT_LOCAL_MODE" = "1" ] && [ "$PROD_MODE" = "1" ]; then
    die "--local and --systemd are mutually exclusive"
fi
if [ "$EXPLICIT_LOCAL_MODE" = "1" ] && [ "$CLIENT_MODE" = "1" ]; then
    die "--local and --client are mutually exclusive"
fi
if [ "$PROD_MODE" = "1" ] && ! is_linux; then
    die "--systemd is only supported on Linux"
fi

PROD_DATA_DIR_INPUT=""
if [ -n "${APSIGNER_DATA:-}" ]; then
    APSIGNER_DATA_CANON="$(canonical_dir "$APSIGNER_DATA")"
    if is_prod_data_dir "$APSIGNER_DATA_CANON"; then
        PROD_DATA_DIR_INPUT="$APSIGNER_DATA_CANON"
    fi
fi

SCRIPT_DIR="$(canonical_dir "$(dirname "${BASH_SOURCE[0]}")")"
SCRIPT_PARENT="$(dirname "$SCRIPT_DIR")"
if [ -z "$PROD_DATA_DIR_INPUT" ] &&
   [ "$(basename "$SCRIPT_DIR")" = "install" ] &&
   is_prod_data_dir "$SCRIPT_PARENT"; then
    PROD_DATA_DIR_INPUT="$SCRIPT_PARENT"
fi
if [ -z "$PROD_DATA_DIR_INPUT" ] && [ "$(id -u)" -eq 0 ]; then
    SVC_HOME_FOR_DETECTION="$(getent passwd "$SVC_USER" 2>/dev/null | cut -d: -f6)"
    if is_prod_data_dir "$SVC_HOME_FOR_DETECTION"; then
        PROD_DATA_DIR_INPUT="$(canonical_dir "$SVC_HOME_FOR_DETECTION")"
    fi
fi

if [ "$EXPLICIT_PROD_MODE" = "0" ] && [ "$EXPLICIT_LOCAL_MODE" = "0" ] && [ "$CLIENT_MODE" = "0" ]; then
    prompt_uninstall_mode
fi

# Default to local mode unless --systemd or --client.
LOCAL_MODE=0
LOCAL_PATH=""
if [ "$EXPLICIT_LOCAL_MODE" = "1" ] || { [ "$PROD_MODE" = "0" ] && [ "$CLIENT_MODE" = "0" ]; }; then
    LOCAL_MODE=1
    LOCAL_PATH="${POSITIONAL[0]:-}"
fi

# --- Client-only mode ---
if [ "$CLIENT_MODE" = "1" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        die "--client must not be run as root"
    fi

    if [ ${#POSITIONAL[@]} -gt 1 ]; then
        die "--client accepts at most one optional path argument"
    fi

    CLIENT_PATH="${POSITIONAL[0]:-$HOME/aplane}"
    if [ -d "$CLIENT_PATH" ]; then
        CLIENT_PATH="$(cd "$CLIENT_PATH" && pwd)"
    fi
    APCLIENT_DIR="$CLIENT_PATH/apclient"
    CLIENT_BINDIR="$APCLIENT_DIR/bin"

    # Remove client binaries from client bindir
    if [ -f "$CLIENT_BINDIR/apshell" ]; then
        rm -f "$CLIENT_BINDIR/apshell"
        echo "Removed $CLIENT_BINDIR/apshell"
    else
        echo "No apshell found at $CLIENT_BINDIR/apshell"
    fi
    rmdir "$CLIENT_BINDIR" 2>/dev/null || true

    # Clean up shell rc
    SHELL_RC="$(detect_shell_rc "$HOME")"
    if grep -qF '# aplane env' "$SHELL_RC" 2>/dev/null; then
        read -rp "Remove aplane env lines from $SHELL_RC? [Y/n] " answer </dev/tty
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            sed_inplace '/# aplane env/,+1d' "$SHELL_RC"
            echo "Removed aplane env lines from $SHELL_RC"
        fi
    fi

    # Remove only installer-created assets from [path]/apclient/
    if [ -d "$APCLIENT_DIR" ]; then
        # Remove apenv.sh
        rm -f "$APCLIENT_DIR/apenv.sh"

        # Remove installer-generated MCP config only if it still points at this install.
        if [ -f "$APCLIENT_DIR/.mcp.json" ] &&
           grep -qF '"--mcp"' "$APCLIENT_DIR/.mcp.json" &&
           grep -qF "\"$CLIENT_BINDIR/apshell\"" "$APCLIENT_DIR/.mcp.json" &&
           grep -qF "\"$APCLIENT_DIR\"" "$APCLIENT_DIR/.mcp.json"; then
            rm -f "$APCLIENT_DIR/.mcp.json"
            echo "Removed $APCLIENT_DIR/.mcp.json (installer template)"
        fi
        rm -f "$APCLIENT_DIR/.mcp.json.aplane-installer.new"
        if codex_mcp_config_matches_install "$APCLIENT_DIR/.codex/config.toml" "$CLIENT_BINDIR/apshell" "$APCLIENT_DIR"; then
            rm -f "$APCLIENT_DIR/.codex/config.toml"
            echo "Removed $APCLIENT_DIR/.codex/config.toml (installer template)"
        fi
        rm -f "$APCLIENT_DIR/.codex/config.toml.aplane-installer.new"
        rmdir "$APCLIENT_DIR/.codex" 2>/dev/null || true

        # Remove installer-generated SSH keys
        rm -f "$APCLIENT_DIR/.ssh/id_ed25519" "$APCLIENT_DIR/.ssh/id_ed25519.pub"
        rmdir "$APCLIENT_DIR/.ssh" 2>/dev/null || true
        rmdir "$APCLIENT_DIR/scripts" 2>/dev/null || true

        # Remove config only if it still matches the installer template
        if [ -f "$APCLIENT_DIR/config.yaml" ]; then
            if grep -q '# apshell configuration (remote signer)' "$APCLIENT_DIR/config.yaml" 2>/dev/null; then
                rm -f "$APCLIENT_DIR/config.yaml"
                echo "Removed $APCLIENT_DIR/config.yaml (installer template)"
            else
                echo "Kept $APCLIENT_DIR/config.yaml (modified by user)"
            fi
        fi

        # Remove directory only if empty; warn otherwise
        if rmdir "$APCLIENT_DIR" 2>/dev/null; then
            echo "Removed $APCLIENT_DIR/"
        else
            echo "$APCLIENT_DIR/ still contains user data; leaving it in place."
            ls -A "$APCLIENT_DIR" | sed 's/^/  /'
        fi
    else
        echo "No client directory found at $APCLIENT_DIR"
    fi

    echo "Client uninstall complete."
    exit 0
fi

# --- Local mode ---
if [ "$LOCAL_MODE" = "1" ]; then
    if [ ${#POSITIONAL[@]} -gt 1 ]; then
        die "local mode accepts at most one optional path argument"
    fi

    DEFAULT_LOCAL_PATH="$(default_local_uninstall_path)"
    if [ "$EXPLICIT_LOCAL_MODE" = "1" ] && [ -z "$LOCAL_PATH" ]; then
        TTY_PATH="$(tty 2>/dev/null || true)"
        if [ -n "$TTY_PATH" ] && [ "$TTY_PATH" != "not a tty" ]; then
            if ! read -rp "APlane local install directory [$DEFAULT_LOCAL_PATH]: " LOCAL_PATH < "$TTY_PATH"; then
                LOCAL_PATH="$DEFAULT_LOCAL_PATH"
            fi
        else
            LOCAL_PATH="$DEFAULT_LOCAL_PATH"
        fi
        LOCAL_PATH="${LOCAL_PATH:-$DEFAULT_LOCAL_PATH}"
    fi

    LOCAL_PATH="${LOCAL_PATH:-$DEFAULT_LOCAL_PATH}"
    LOCAL_PATH="$(expand_path_for_home "$LOCAL_PATH" "$HOME")"
    if [ "${LOCAL_PATH#/}" = "$LOCAL_PATH" ]; then
        LOCAL_PATH="$(pwd)/$LOCAL_PATH"
    fi
    if [ -d "$LOCAL_PATH" ]; then
        LOCAL_PATH="$(cd "$LOCAL_PATH" && pwd)"
    fi
    INSTALL_ROOT="$LOCAL_PATH/apsigner"
    if [ "$EXPLICIT_LOCAL_MODE" = "0" ] && is_prod_data_dir "$INSTALL_ROOT"; then
        die "$INSTALL_ROOT is marked as a systemd-managed data directory; rerun with sudo $0 --systemd. To uninstall a local installation, use the --local flag"
    fi

    LOCAL_PARENT="$(dirname "$INSTALL_ROOT")"
    SIGNER_BINDIR="$INSTALL_ROOT/bin"
    APCLIENT_DIR="$LOCAL_PARENT/apclient"
    CLIENT_BINDIR="$APCLIENT_DIR/bin"
    ENV_SH="$LOCAL_PARENT/apenv.sh"

    SIGNER_BINARIES_REMOVED=0
    CLIENT_BINARY_REMOVED=0
    ROOT_ARTIFACTS_REMOVED=0
    MCP_CONFIG_REMOVED=0
    MCP_TEMPLATE_REMOVED=0
    CODEX_MCP_CONFIG_REMOVED=0
    CODEX_MCP_TEMPLATE_REMOVED=0
    ENV_RC_CLEANED=0
    REMOVED_SIGNER_BINARIES=()
    REMOVED_ROOT_ARTIFACTS=()

    # Remove installed local binaries but keep signer configuration, identities,
    # token material, audit logs, client config, caches, plugins, and scripts.
    for binary in apsigner apconsole apadmin apapprover apstore appolicy appass appass-file appass-systemd-creds approbe applugin-checksum; do
        binary_path="$SIGNER_BINDIR/$binary"
        if [ -e "$binary_path" ]; then
            rm -f "$binary_path"
            REMOVED_SIGNER_BINARIES+=("$binary")
            SIGNER_BINARIES_REMOVED=1
        fi
    done
    rmdir "$SIGNER_BINDIR" 2>/dev/null || true

    if [ -e "$CLIENT_BINDIR/apshell" ]; then
        rm -f "$CLIENT_BINDIR/apshell"
        CLIENT_BINARY_REMOVED=1
    fi
    rmdir "$CLIENT_BINDIR" 2>/dev/null || true

    # Remove installer-generated MCP config only if it still points at this
    # install. User-authored .mcp.json files and all client state remain.
    if [ -d "$APCLIENT_DIR" ]; then
        if [ -f "$APCLIENT_DIR/.mcp.json" ] &&
           grep -qF '"--mcp"' "$APCLIENT_DIR/.mcp.json" &&
           grep -qF "\"$CLIENT_BINDIR/apshell\"" "$APCLIENT_DIR/.mcp.json" &&
           grep -qF "\"$APCLIENT_DIR\"" "$APCLIENT_DIR/.mcp.json"; then
            rm -f "$APCLIENT_DIR/.mcp.json"
            MCP_CONFIG_REMOVED=1
        fi
        if [ -f "$APCLIENT_DIR/.mcp.json.aplane-installer.new" ]; then
            rm -f "$APCLIENT_DIR/.mcp.json.aplane-installer.new"
            MCP_TEMPLATE_REMOVED=1
        fi
        if codex_mcp_config_matches_install "$APCLIENT_DIR/.codex/config.toml" "$CLIENT_BINDIR/apshell" "$APCLIENT_DIR"; then
            rm -f "$APCLIENT_DIR/.codex/config.toml"
            CODEX_MCP_CONFIG_REMOVED=1
        fi
        if [ -f "$APCLIENT_DIR/.codex/config.toml.aplane-installer.new" ]; then
            rm -f "$APCLIENT_DIR/.codex/config.toml.aplane-installer.new"
            CODEX_MCP_TEMPLATE_REMOVED=1
        fi
        rmdir "$APCLIENT_DIR/.codex" 2>/dev/null || true
    fi

    for artifact in apenv.sh apconsole.yaml start.sh start-tmux.sh start-screen.sh; do
        artifact_path="$LOCAL_PARENT/$artifact"
        if [ -e "$artifact_path" ]; then
            rm -f "$artifact_path"
            REMOVED_ROOT_ARTIFACTS+=("$artifact")
            ROOT_ARTIFACTS_REMOVED=1
        fi
    done
    if [ -f "$LOCAL_PARENT/uninstall.sh" ] &&
       [ ! -f "$LOCAL_PARENT/install.sh" ] &&
       grep -qF "uninstall.sh - Remove an aplane installation" "$LOCAL_PARENT/uninstall.sh"; then
        rm -f "$LOCAL_PARENT/uninstall.sh"
        REMOVED_ROOT_ARTIFACTS+=("uninstall.sh")
        ROOT_ARTIFACTS_REMOVED=1
    fi

    # Clean up only the source block for this install's apenv.sh. Do not remove
    # other local installs that use the same "# aplane env" marker.
    SHELL_RC="$(detect_shell_rc "$HOME")"
    if grep -qF "$ENV_SH" "$SHELL_RC" 2>/dev/null; then
        answer="y"
        TTY_PATH="$(tty 2>/dev/null || true)"
        if [ -n "$TTY_PATH" ] && [ "$TTY_PATH" != "not a tty" ]; then
            if ! read -rp "Remove aplane env lines from $SHELL_RC? [Y/n] " answer < "$TTY_PATH"; then
                answer="y"
            fi
        fi
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            if remove_shell_rc_env_block "$SHELL_RC" "$ENV_SH"; then
                ENV_RC_CLEANED=1
            else
                echo "No matching aplane env block for $ENV_SH found in $SHELL_RC"
            fi
        fi
    fi

    echo ""
    echo "=== Local uninstall summary ==="
    echo ""
    echo "Actions completed:"
    if [ "$SIGNER_BINARIES_REMOVED" = "1" ]; then
        echo "  - removed signer-side binaries from $SIGNER_BINDIR: ${REMOVED_SIGNER_BINARIES[*]}"
    else
        echo "  - no signer-side binaries were present in $SIGNER_BINDIR"
    fi
    if [ "$CLIENT_BINARY_REMOVED" = "1" ]; then
        echo "  - removed client binary from $CLIENT_BINDIR/apshell"
    else
        echo "  - no client binary was present at $CLIENT_BINDIR/apshell"
    fi
    if [ "$MCP_CONFIG_REMOVED" = "1" ]; then
        echo "  - removed installer-generated MCP config at $APCLIENT_DIR/.mcp.json"
    fi
    if [ "$MCP_TEMPLATE_REMOVED" = "1" ]; then
        echo "  - removed installer-generated MCP config template at $APCLIENT_DIR/.mcp.json.aplane-installer.new"
    fi
    if [ "$CODEX_MCP_CONFIG_REMOVED" = "1" ]; then
        echo "  - removed installer-generated Codex MCP config at $APCLIENT_DIR/.codex/config.toml"
    fi
    if [ "$CODEX_MCP_TEMPLATE_REMOVED" = "1" ]; then
        echo "  - removed installer-generated Codex MCP config template at $APCLIENT_DIR/.codex/config.toml.aplane-installer.new"
    fi
    if [ "$ROOT_ARTIFACTS_REMOVED" = "1" ]; then
        echo "  - removed generated local helper files from $LOCAL_PARENT: ${REMOVED_ROOT_ARTIFACTS[*]}"
    fi
    if [ "$ENV_RC_CLEANED" = "1" ]; then
        echo "  - removed this install's apenv.sh source block from $SHELL_RC"
    fi

    echo ""
    echo "Left behind:"
    if [ -d "$INSTALL_ROOT" ]; then
        echo "  Signer data directory: $INSTALL_ROOT"
        echo "    Preserved signer configuration, identities, keys, audit logs, and template library."
    else
        echo "  - signer data directory was not present at $INSTALL_ROOT"
    fi
    if [ -d "$APCLIENT_DIR" ]; then
        echo "  Client data directory: $APCLIENT_DIR"
        echo "    Preserved client configuration, token, SSH trust, caches, plugins, scripts, and swap state."
    else
        echo "  - client data directory was not present at $APCLIENT_DIR"
    fi
    echo ""
    echo "  To remove preserved local state manually (irreversible -- destroys keys/tokens):"
    echo "    rm -rf $(shell_quote "$INSTALL_ROOT")"
    echo "    rm -rf $(shell_quote "$APCLIENT_DIR")"
    echo ""
    echo "Local uninstall complete."
    exit 0
fi

# --- Systemd mode ---
if [ "$PROD_MODE" != "1" ]; then
    die "unexpected state"
fi
if [ "$(id -u)" -ne 0 ]; then
    die "--systemd uninstall must be run as root (use sudo)"
fi
if [ ${#POSITIONAL[@]} -gt 1 ]; then
    die "--systemd accepts at most one optional operator-root path"
fi
PROD_OPERATOR_ROOT_INPUT="${POSITIONAL[0]:-}"

SERVICE_REMOVED=0
SUDOERS_REMOVED=0
CLIENT_REMOVED=0
CLIENT_SKIPPED_NO_OPERATOR_ROOT=0
ENV_RC_CLEANED=0
UNINSTALLER_REMOVED=0
BINARIES_REMOVED=0
USER_GROUP_PRESERVED=0
SERVICE_STOPPED=0
SERVICE_ALREADY_INACTIVE=0
SERVICE_DISABLED=0
SERVICE_ALREADY_DISABLED=0
SERVICE_ALREADY_ABSENT=0
SUDOERS_ALREADY_ABSENT=0
CLIENT_ALREADY_ABSENT=0
UNINSTALLER_ALREADY_ABSENT=0
DATA_DIR_ALREADY_ABSENT=0
REMOVED_BINARIES=()
MISSING_BINARIES=()
REMOVED_SERVICE_UNITS=()

if [ -n "$PROD_DATA_DIR_INPUT" ]; then
    DATA_DIR="$PROD_DATA_DIR_INPUT"
else
    DATA_DIR="$(getent passwd "$SVC_USER" 2>/dev/null | cut -d: -f6)"
fi
if [ -n "$DATA_DIR" ]; then
    DATA_DIR="$(canonical_dir "$DATA_DIR")"
fi
SUDO_USER_HOME=""
OPERATOR_ROOT=""
OPERATOR_ROOT_SOURCE=""
if [ -n "${SUDO_USER:-}" ]; then
    SUDO_USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    [ -n "$SUDO_USER_HOME" ] || die "could not determine home directory for $SUDO_USER"
    if [ -n "$PROD_OPERATOR_ROOT_INPUT" ]; then
        OPERATOR_ROOT="$(expand_path_for_home "$PROD_OPERATOR_ROOT_INPUT" "$SUDO_USER_HOME")"
        OPERATOR_ROOT_SOURCE="explicit"
    elif [ -n "$DATA_DIR" ] && [ -f "$DATA_DIR/install/operator-root" ]; then
        OPERATOR_ROOT="$(sed -n '1p' "$DATA_DIR/install/operator-root")"
        OPERATOR_ROOT_SOURCE="recorded"
    fi
    if [ -n "$OPERATOR_ROOT" ] && [ "${OPERATOR_ROOT#/}" = "$OPERATOR_ROOT" ]; then
        OPERATOR_ROOT="$(pwd)/$OPERATOR_ROOT"
    fi
elif [ -n "$PROD_OPERATOR_ROOT_INPUT" ]; then
    die "operator-root requires sudo with SUDO_USER set; omit it when running directly as root"
fi

# Stop and disable service
if systemctl is-active apsigner >/dev/null 2>&1; then
    systemctl stop apsigner
    SERVICE_STOPPED=1
    echo "Stopped apsigner service"
else
    SERVICE_ALREADY_INACTIVE=1
fi
if systemctl is-enabled apsigner >/dev/null 2>&1; then
    systemctl disable apsigner
    SERVICE_DISABLED=1
    echo "Disabled apsigner service"
else
    SERVICE_ALREADY_DISABLED=1
fi

# Remove service file and sudoers. Check both the current local-admin unit path
# and the legacy packaged-unit path used by older installers.
for service_unit in /etc/systemd/system/apsigner.service /lib/systemd/system/apsigner.service; do
    if [ -f "$service_unit" ]; then
        rm -f "$service_unit"
        REMOVED_SERVICE_UNITS+=("$service_unit")
        SERVICE_REMOVED=1
    fi
done
if [ "$SERVICE_REMOVED" != "1" ]; then
    SERVICE_ALREADY_ABSENT=1
fi
if [ -f /etc/sudoers.d/99-apsigner-systemctl ]; then
    rm -f /etc/sudoers.d/99-apsigner-systemctl
    SUDOERS_REMOVED=1
else
    SUDOERS_ALREADY_ABSENT=1
fi
systemctl daemon-reload
echo "Removed systemd service and sudoers rules"

# Remove apshell config for the invoking user
if [ -n "${SUDO_USER:-}" ]; then
    if [ -n "$OPERATOR_ROOT" ]; then
        APCLIENT_DIR="$OPERATOR_ROOT/apclient"
        if [ -d "$APCLIENT_DIR" ]; then
            rm -rf "$APCLIENT_DIR"
            rm -f "$OPERATOR_ROOT/apenv.sh" "$OPERATOR_ROOT/apconsole.yaml"
            rmdir "$OPERATOR_ROOT" 2>/dev/null || true
            CLIENT_REMOVED=1
            echo "Removed $APCLIENT_DIR"
        else
            CLIENT_ALREADY_ABSENT=1
        fi
    else
        CLIENT_SKIPPED_NO_OPERATOR_ROOT=1
        echo "No systemd operator root was provided or recorded; leaving user client directories untouched."
    fi

    # Clean up shell rc
    SHELL_RC="$(detect_shell_rc "$SUDO_USER_HOME" "$SUDO_USER")"
    if grep -qF '# aplane env' "$SHELL_RC" 2>/dev/null; then
        read -rp "Remove aplane env lines from $SHELL_RC? [Y/n] " answer </dev/tty
        if [ -z "$answer" ] || [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
            sed_inplace '/# aplane env/,+1d' "$SHELL_RC"
            ENV_RC_CLEANED=1
            echo "Removed aplane env lines from $SHELL_RC"
        fi
    fi
fi

# Preserve signer data directory and remove only installer-managed markers.
DATA_DIR_RETAINED=0
if [ -n "$DATA_DIR" ] && [ -d "$DATA_DIR" ]; then
    rm -f "$DATA_DIR/.prod"
    rm -f "$DATA_DIR/install/operator-root"
    if [ -f "$DATA_DIR/install/uninstall.sh" ]; then
        rm -f "$DATA_DIR/install/uninstall.sh"
        rmdir "$DATA_DIR/install" 2>/dev/null || true
        UNINSTALLER_REMOVED=1
        echo "Removed $DATA_DIR/install/uninstall.sh"
    else
        UNINSTALLER_ALREADY_ABSENT=1
    fi
    DATA_DIR_RETAINED=1
    echo "Preserved $DATA_DIR (signer keys and configuration)."
else
    DATA_DIR_ALREADY_ABSENT=1
fi

# Remove binaries
for binary in apsigner apshell apconsole apadmin apapprover apstore appolicy appass appass-file appass-systemd-creds approbe applugin-checksum; do
    binary_path="$BINDIR/$binary"
    if [ -e "$binary_path" ]; then
        rm -f "$binary_path"
        REMOVED_BINARIES+=("$binary")
        BINARIES_REMOVED=1
    else
        MISSING_BINARIES+=("$binary")
    fi
done
echo "Removed binaries from $BINDIR"

# Remove user and group only when no signer data directory remains. Keeping the
# account preserves readable ownership names for retained key material.
if [ "$DATA_DIR_RETAINED" = "1" ]; then
    USER_GROUP_PRESERVED=1
    echo "Kept user/group $SVC_USER:$SVC_GROUP for retained signer data."
elif id -u "$SVC_USER" >/dev/null 2>&1; then
    userdel -r "$SVC_USER" 2>/dev/null || true
    echo "Removed user $SVC_USER"
    if getent group "$SVC_GROUP" >/dev/null 2>&1; then
        groupdel "$SVC_GROUP" 2>/dev/null || true
        echo "Removed group $SVC_GROUP"
    fi
fi

echo ""
echo "=== Systemd uninstall summary ==="
echo ""
echo "Actions completed:"
if [ "$SERVICE_STOPPED" = "1" ]; then
    echo "  - stopped active apsigner service"
elif [ "$SERVICE_ALREADY_INACTIVE" = "1" ]; then
    echo "  - apsigner service was already inactive"
fi
if [ "$SERVICE_DISABLED" = "1" ]; then
    echo "  - disabled apsigner service"
elif [ "$SERVICE_ALREADY_DISABLED" = "1" ]; then
    echo "  - apsigner service was already disabled or not installed"
fi
if [ "$SERVICE_REMOVED" = "1" ]; then
    echo "  - removed apsigner systemd unit: ${REMOVED_SERVICE_UNITS[*]}"
elif [ "$SERVICE_ALREADY_ABSENT" = "1" ]; then
    echo "  - systemd unit was already absent"
fi
if [ "$SUDOERS_REMOVED" = "1" ]; then
    echo "  - removed sudoers rule at /etc/sudoers.d/99-apsigner-systemctl"
elif [ "$SUDOERS_ALREADY_ABSENT" = "1" ]; then
    echo "  - sudoers rule was already absent"
fi
if [ "$BINARIES_REMOVED" = "1" ]; then
    echo "  - removed binaries from $BINDIR: ${REMOVED_BINARIES[*]}"
else
    echo "  - no APlane binaries were present in $BINDIR"
fi
if [ "$CLIENT_REMOVED" = "1" ]; then
    echo "  - removed client install at $APCLIENT_DIR ($OPERATOR_ROOT_SOURCE operator root)"
elif [ "$CLIENT_ALREADY_ABSENT" = "1" ]; then
    echo "  - client install was already absent at $APCLIENT_DIR ($OPERATOR_ROOT_SOURCE operator root)"
elif [ "$CLIENT_SKIPPED_NO_OPERATOR_ROOT" = "1" ]; then
    echo "  - skipped operator client cleanup because no systemd operator root was provided or recorded"
fi
if [ "$ENV_RC_CLEANED" = "1" ]; then
    echo "  - removed aplane env source lines from $SHELL_RC"
fi
if [ "$UNINSTALLER_REMOVED" = "1" ]; then
    echo "  - removed bundled systemd uninstaller from $DATA_DIR/install/uninstall.sh"
elif [ "$UNINSTALLER_ALREADY_ABSENT" = "1" ]; then
    echo "  - bundled systemd uninstaller was already absent"
fi
echo ""
echo "Left behind:"
HAS_SYSTEMD_CREDS=0
if [ "$DATA_DIR_RETAINED" = "1" ]; then
    echo "  Signer data directory: $DATA_DIR"
    contents="$(ls -A "$DATA_DIR" 2>/dev/null | sort || true)"
    if [ -n "$contents" ]; then
        echo "  Contents:"
        while IFS= read -r entry; do
            case "$entry" in
                identities)                       note="signing keys and product-store unlock material" ;;
                backups)                          note="encrypted backup tarballs" ;;
                library)                          note="LogicSig template library" ;;
                audit.log)                        note="audit trail" ;;
                config.yaml)                      note="signer configuration" ;;
                config.yaml.aplane-installer.new) note="installer template (safe to remove)" ;;
                .ssh)                             note="SSH tunnel host keys" ;;
                .apstore.lock)                    note="keystore lock file" ;;
                .prod)                            note="managed install marker" ;;
                install)                          note="installer state" ;;
                .bashrc|.bash_logout|.bash_history|.profile) note="shell skeleton (no signer data)" ;;
                *)                                note="" ;;
            esac
            if [ -n "$note" ]; then
                printf '    %-36s  %s\n' "$entry" "$note"
            else
                printf '    %s\n' "$entry"
            fi
            if [ "$entry" = "identities" ] && [ -d "$DATA_DIR/identities" ]; then
                for id_dir in "$DATA_DIR/identities"/*/; do
                    [ -d "$id_dir" ] || continue
                    id_name="$(basename "$id_dir")"
                    printf '      %s/\n' "$id_name"
                    sub_contents="$(ls -A "$id_dir" 2>/dev/null | sort || true)"
                    [ -n "$sub_contents" ] || continue
                    while IFS= read -r sub_entry; do
                        case "$sub_entry" in
                            .keystore)        sub_note="keystore metadata (master salt, verifier)" ;;
                            aplane.token)     sub_note="HTTP API token" ;;
                            keys)             sub_note="encrypted private keys" ;;
                            passphrase.cred)  sub_note="systemd-creds passphrase (host-bound TPM2/host key)"
                                              HAS_SYSTEMD_CREDS=1 ;;
                            unlock.yaml)      sub_note="passphrase helper configuration" ;;
                            config.yaml)      sub_note="product runtime configuration" ;;
                            .ssh)             sub_note="product SSH keys" ;;
                            *)                sub_note="" ;;
                        esac
                        if [ -n "$sub_note" ]; then
                            printf '        %-32s  %s\n' "$sub_entry" "$sub_note"
                        else
                            printf '        %s\n' "$sub_entry"
                        fi
                    done <<< "$sub_contents"
                done
            fi
        done <<< "$contents"
    fi
elif [ "$DATA_DIR_ALREADY_ABSENT" = "1" ]; then
    echo "  - signer data directory was not present"
fi
if [ "$USER_GROUP_PRESERVED" = "1" ]; then
    echo "  Service account: $SVC_USER:$SVC_GROUP (kept so retained files have readable ownership)"
fi
if [ "$HAS_SYSTEMD_CREDS" = "1" ]; then
    echo ""
    echo "  Note: passphrase.cred is encrypted to this host's TPM2/host key, but the"
    echo "  systemd unit's LoadCredentialEncrypted= binding was removed with the unit."
    echo "  On reinstall, the installer should detect the existing .cred and rebind it."
    echo "  If needed, run 'sudo appass -d $DATA_DIR' and select Systemd credentials."
fi
if [ "$DATA_DIR_RETAINED" = "1" ]; then
    echo ""
    echo "  To remove everything manually (irreversible -- destroys keys):"
    echo "    sudo rm -rf $DATA_DIR"
    if [ "$USER_GROUP_PRESERVED" = "1" ]; then
        echo "    sudo userdel -r $SVC_USER && sudo groupdel $SVC_GROUP"
    fi
fi
echo ""
echo "Systemd uninstall complete."
