#!/bin/bash
# install.sh - Install aplane binaries and configure the system
#
# Production mode (default):
#   sudo ./install.sh <username> <group> [bindir]
#
# Local mode (rootless, no systemd):
#   ./install.sh --local [path]
#
# Arguments (prod mode):
#   username  User to run apsignerd as
#   group     Group to run apsignerd as
#   bindir    Where to install binaries (default: /usr/local/bin)
#
# Arguments (local mode):
#   path      Parent directory for apsigner/ (default: $HOME)
#
# Works from both a repo checkout and an extracted release tarball.

# Refuse to run when sourced
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: sudo $0 <username> <group> [bindir]" >&2
    echo "       $0 --local [path]" >&2
    return 1
fi

set -euo pipefail

# Parse flags
LOCAL_MODE=0
LOCAL_PATH=""
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --local)
            LOCAL_MODE=1
            shift
            # Optional path argument (next arg if it doesn't start with --)
            if [ $# -gt 0 ] && [ "${1:0:2}" != "--" ]; then
                LOCAL_PATH="$1"
                shift
            fi
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

# Resolve script directory (works from repo checkout and extracted tarball)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$SCRIPT_DIR/bin"

if [ ! -d "$BIN_SRC" ]; then
    echo "Error: bin/ directory not found at $BIN_SRC" >&2
    exit 1
fi

# --- Local mode ---
if [ "$LOCAL_MODE" = "1" ]; then
    # Guard: refuse to run as root in local mode
    if [ "$(id -u)" -eq 0 ]; then
        echo "Error: --local must not be run as root." >&2
        echo "Local mode installs into a user directory without systemd or system users." >&2
        exit 1
    fi

    # Mutually exclusive with prod args
    if [ ${#POSITIONAL[@]} -gt 0 ]; then
        echo "Error: --local is mutually exclusive with <username> <group> arguments." >&2
        echo "Usage: $0 --local [path]" >&2
        exit 2
    fi

    # Resolve install root
    if [ -n "$LOCAL_PATH" ]; then
        LOCAL_PATH="$(cd "$LOCAL_PATH" && pwd)"
    else
        LOCAL_PATH="$HOME"
    fi
    INSTALL_ROOT="$LOCAL_PATH/apsigner"
    BINDIR="$INSTALL_ROOT/bin"
    DATA_DIR="$INSTALL_ROOT"

    echo "=== apsigner installer (local mode) ==="
    echo ""
    echo "  Source:    $SCRIPT_DIR"
    echo "  Install:   $INSTALL_ROOT"
    echo "  Bindir:    $BINDIR"
    echo "  Data dir:  $DATA_DIR"
    echo ""

    # Create directories
    mkdir -p "$BINDIR" "$INSTALL_ROOT/store"

    # Copy binaries
    echo "Installing binaries to $BINDIR..."
    for bin in "$BIN_SRC"/*; do
        [ -f "$bin" ] || continue
        cp "$bin" "$BINDIR/"
        name="$(basename "$bin")"
        chmod 755 "$BINDIR/$name"
        echo "  $name"
    done

    # Generate signer config
    CONFIG_PATH="$DATA_DIR/config.yaml"
    echo ""
    if [ -f "$CONFIG_PATH" ]; then
        CONFIG_NEW_PATH="$CONFIG_PATH.apsigner-installer.new"
        echo "Config already exists at $CONFIG_PATH; leaving it unchanged."
        echo "Writing canonical template to $CONFIG_NEW_PATH..."
        cat > "$CONFIG_NEW_PATH" <<'EOF'
# apsignerd configuration
# See doc/USER_CONFIG.md for full documentation.

# Store directory (relative to $APSIGNER_DATA)
store: store

# REST API port (bound to localhost when SSH is enabled)
signer_port: 11270

# SSH tunnel settings for remote access (uncomment to enable)
# ssh:
#   port: 1127
#   host_key_path: .ssh/ssh_host_key
#   authorized_keys_path: .ssh/authorized_keys
#   auto_register: true

# Inactivity timeout before auto-lock: "0" = never, "15m" = 15 minutes
passphrase_timeout: "15m"

# Lock signer when apadmin disconnects
lock_on_disconnect: false

# Approval policy settings (all default to false)
# txn_auto_approve: false
# group_auto_approve: false
# allow_group_modification: false

# TEAL compiler for LogicSig generation (e.g., Falcon-1024 timelocks)
teal_compiler_algod_url: https://testnet-api.4160.nodely.dev
teal_compiler_algod_token: ""

# Security settings
require_memory_protection: false
EOF
    else
        echo "Writing $CONFIG_PATH..."
        cat > "$CONFIG_PATH" <<'EOF'
# apsignerd configuration
# See doc/USER_CONFIG.md for full documentation.

# Store directory (relative to $APSIGNER_DATA)
store: store

# REST API port (bound to localhost when SSH is enabled)
signer_port: 11270

# SSH tunnel settings for remote access (uncomment to enable)
# ssh:
#   port: 1127
#   host_key_path: .ssh/ssh_host_key
#   authorized_keys_path: .ssh/authorized_keys
#   auto_register: true

# Inactivity timeout before auto-lock: "0" = never, "15m" = 15 minutes
passphrase_timeout: "15m"

# Lock signer when apadmin disconnects
lock_on_disconnect: false

# Approval policy settings (all default to false)
# txn_auto_approve: false
# group_auto_approve: false
# allow_group_modification: false

# TEAL compiler for LogicSig generation (e.g., Falcon-1024 timelocks)
teal_compiler_algod_url: https://testnet-api.4160.nodely.dev
teal_compiler_algod_token: ""

# Security settings
require_memory_protection: false
EOF
    fi

    # Write env.sh for easy sourcing
    APCLIENT_DIR="$HOME/.apclient"
    cat > "$INSTALL_ROOT/env.sh" <<ENVEOF
# Source this file to set up apsigner environment:
#   source $INSTALL_ROOT/env.sh
# Or add to ~/.bashrc:
#   . $INSTALL_ROOT/env.sh

export PATH="$BINDIR:\$PATH"
export APSIGNER_DATA="$DATA_DIR"
export APCLIENT_DATA="$APCLIENT_DIR"
ENVEOF

    echo ""
    echo "=== Installation complete ==="
    echo ""
    echo "Set up your environment:"
    echo "  source $INSTALL_ROOT/env.sh"
    echo ""
    echo "Or add to ~/.bashrc for persistence:"
    echo "  echo '. $INSTALL_ROOT/env.sh' >> ~/.bashrc"
    echo ""
    echo "Then:"
    echo "  apstore init          # Initialize keystore"
    echo "  apsignerd              # Start signer"
    echo "  apadmin                # Unlock and manage keys"
    echo ""
    echo "For apshell, create $APCLIENT_DIR/config.yaml with your client settings."
    exit 0
fi

# --- Prod mode ---
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

if [ ${#POSITIONAL[@]} -lt 2 ]; then
    echo "Usage: $0 <username> <group> [bindir]" >&2
    echo "       $0 --local [path]" >&2
    echo "" >&2
    echo "  username       User to run apsignerd as" >&2
    echo "  group          Group to run apsignerd as" >&2
    echo "  bindir         Where to install binaries (default: /usr/local/bin)" >&2
    echo "  --local [path] Install locally without systemd (default path: \$PWD)" >&2
    exit 2
fi

SVC_USER="${POSITIONAL[0]}"
SVC_GROUP="${POSITIONAL[1]}"
BINDIR="${POSITIONAL[2]:-/usr/local/bin}"

# Ensure bindir exists and resolve to absolute path
mkdir -p "$BINDIR"
BINDIR="$(cd "$BINDIR" && pwd)"

echo "=== apsigner installer ==="
echo ""
echo "  Source:    $SCRIPT_DIR"
echo "  Bindir:    $BINDIR"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo "  Mode:      locked-start (unlock via apadmin)"
echo ""

# Step 1: Create service user/group if they don't exist
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    echo "Creating system user $SVC_USER..."
    useradd -r -m -d /var/lib/apsigner -s /usr/sbin/nologin "$SVC_USER"
    chmod 750 /var/lib/apsigner
    echo "  Created user $SVC_USER with home /var/lib/apsigner"
else
    echo "User $SVC_USER already exists, skipping creation."
fi

# Add the installing user to the service group (for apadmin access)
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "$SVC_USER" ]; then
    if ! id -nG "$SUDO_USER" 2>/dev/null | grep -qw "$SVC_GROUP"; then
        usermod -aG "$SVC_GROUP" "$SUDO_USER"
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
    mkdir -p "$DATA_DIR"
    chown "$SVC_USER:$SVC_GROUP" "$DATA_DIR"
    chmod 750 "$DATA_DIR"
fi

# Step 2: Copy binaries
echo "Installing binaries to $BINDIR..."
for bin in "$BIN_SRC"/*; do
    [ -f "$bin" ] || continue
    cp "$bin" "$BINDIR/"
    name="$(basename "$bin")"
    # pass-systemd-creds must be executable by the unprivileged service user
    case "$name" in
        pass-file)          chmod 700 "$BINDIR/$name" ;;
        pass-systemd-creds) chmod 755 "$BINDIR/$name" ;;
        *)                  chmod 755 "$BINDIR/$name" ;;
    esac
    echo "  $name"
done

# Step 3: Run systemd setup
echo ""
echo "Running systemd setup..."
"$SCRIPT_DIR/scripts/systemd-setup.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR"

# Step 4: Generate canonical signer config for this installation
CONFIG_PATH="$DATA_DIR/config.yaml"

echo ""
write_canonical_config() {
    local target="$1"
    cat > "$target" <<'EOF'
# apsignerd configuration
# See doc/USER_CONFIG.md for full documentation.

# Store directory (relative to $APSIGNER_DATA)
store: store

# REST API port (bound to localhost when SSH is enabled)
signer_port: 11270

# SSH tunnel settings for remote access (uncomment to enable)
# ssh:
#   port: 1127
#   host_key_path: .ssh/ssh_host_key
#   authorized_keys_path: .ssh/authorized_keys
#   auto_register: true

# Inactivity timeout before auto-lock: "0" = never, "15m" = 15 minutes
passphrase_timeout: "15m"

# Lock signer when apadmin disconnects
lock_on_disconnect: false

# Approval policy settings (all default to false)
# txn_auto_approve: false
# group_auto_approve: false
# allow_group_modification: false

# TEAL compiler for LogicSig generation (e.g., Falcon-1024 timelocks)
teal_compiler_algod_url: https://testnet-api.4160.nodely.dev
teal_compiler_algod_token: ""

# Security settings
require_memory_protection: false
EOF
    chown "$SVC_USER:$SVC_GROUP" "$target"
    chmod 640 "$target"
}

if [ -f "$CONFIG_PATH" ]; then
    CONFIG_NEW_PATH="$CONFIG_PATH.apsigner-installer.new"
    echo "Config already exists at $CONFIG_PATH; leaving it unchanged."
    echo "Writing canonical template to $CONFIG_NEW_PATH..."
    write_canonical_config "$CONFIG_NEW_PATH"
else
    echo "Writing $CONFIG_PATH..."
    write_canonical_config "$CONFIG_PATH"
fi

# Step 5: Pre-create store directory so apstore init doesn't disrupt a running apsignerd
STORE_DIR="$DATA_DIR/store"
if [ ! -d "$STORE_DIR" ]; then
    mkdir -p "$STORE_DIR"
    chown "$SVC_USER:$SVC_GROUP" "$STORE_DIR"
    chmod 2770 "$STORE_DIR"
    echo "  Created $STORE_DIR"
fi

# Step 6: Install /etc/profile.d drop-in for APSIGNER_DATA
PROFILE_DROP="/etc/profile.d/apsigner.sh"
echo ""
echo "Writing $PROFILE_DROP..."
cat > "$PROFILE_DROP" <<PROFEOF
# apsigner environment (installed by apsigner installer)
export APSIGNER_DATA="$DATA_DIR"
PROFEOF
chmod 644 "$PROFILE_DROP"
echo "  APSIGNER_DATA=$DATA_DIR"

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Enable and start:"
echo "       sudo systemctl enable apsigner"
echo "       sudo systemctl start apsigner"
echo "  2. Unlock the signer after starting:"
echo "       sudo -u $SVC_USER apadmin"
echo "  3. Generate keys:"
echo "       sudo -u $SVC_USER apadmin"
echo ""
echo "APSIGNER_DATA is set in $PROFILE_DROP (active on next login)."
echo "To use immediately: source $PROFILE_DROP"
echo ""
echo "For apshell, each user should set up ~/.apclient/config.yaml"
echo "and set APCLIENT_DATA=~/.apclient (or use apshell -d)."
