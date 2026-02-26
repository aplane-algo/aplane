#!/bin/bash
# install.sh - Install aplane binaries and systemd service from a release tarball
#
# Usage:
#   sudo ./install.sh [--auto-unlock] <username> <group> [bindir]
#
# Options:
#   --auto-unlock  Enable automatic unlock via systemd-creds (requires systemd 250+)
#
# Arguments:
#   username  User to run apsignerd as
#   group     Group to run apsignerd as
#   bindir    Where to install binaries (default: /usr/local/bin)
#
# Without --auto-unlock (default):
#   Installs binaries and systemd service. The service starts in locked state;
#   unlock via apadmin after starting.
#
# With --auto-unlock:
#   Additionally initializes the keystore with a random passphrase encrypted via
#   systemd-creds (TPM2/host key). The service auto-unlocks on start.
#
# Works from both a repo checkout and an extracted release tarball.

# Refuse to run when sourced
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: sudo $0 [--auto-unlock] <username> <group> [bindir]" >&2
    return 1
fi

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

# Parse flags
AUTO_UNLOCK=0
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --auto-unlock)
            AUTO_UNLOCK=1
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ ${#POSITIONAL[@]} -lt 2 ]; then
    echo "Usage: $0 [--auto-unlock] <username> <group> [bindir]" >&2
    echo "" >&2
    echo "  --auto-unlock  Enable automatic unlock via systemd-creds" >&2
    echo "  username       User to run apsignerd as" >&2
    echo "  group          Group to run apsignerd as" >&2
    echo "  bindir         Where to install binaries (default: /usr/local/bin)" >&2
    exit 2
fi

SVC_USER="${POSITIONAL[0]}"
SVC_GROUP="${POSITIONAL[1]}"
BINDIR="${POSITIONAL[2]:-/usr/local/bin}"

# Verify systemd-creds availability when --auto-unlock is requested
if [ "$AUTO_UNLOCK" = "1" ]; then
    if ! command -v systemd-creds >/dev/null 2>&1; then
        echo "Error: --auto-unlock requires systemd-creds, which was not found." >&2
        echo "Install without --auto-unlock for locked-start mode, or install systemd 250+." >&2
        exit 1
    fi
fi

# Resolve script directory (works from repo checkout and extracted tarball)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$SCRIPT_DIR/bin"

# Ensure bindir exists and resolve to absolute path
mkdir -p "$BINDIR"
BINDIR="$(cd "$BINDIR" && pwd)"

if [ ! -d "$BIN_SRC" ]; then
    echo "Error: bin/ directory not found at $BIN_SRC" >&2
    exit 1
fi

echo "=== aplane installer ==="
echo ""
echo "  Source:    $SCRIPT_DIR"
echo "  Bindir:    $BINDIR"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
if [ "$AUTO_UNLOCK" = "1" ]; then
    echo "  Mode:      auto-unlock (systemd-creds)"
else
    echo "  Mode:      locked-start (unlock via apadmin)"
fi
echo ""

# Step 1: Create service user/group if they don't exist
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    echo "Creating system user $SVC_USER..."
    useradd -r -m -d /var/lib/aplane -s /usr/sbin/nologin "$SVC_USER"
    echo "  Created user $SVC_USER with home /var/lib/aplane"
else
    echo "User $SVC_USER already exists, skipping creation."
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
if [ "$AUTO_UNLOCK" = "1" ]; then
    "$SCRIPT_DIR/scripts/systemd-setup.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR" --auto-unlock
else
    "$SCRIPT_DIR/scripts/systemd-setup.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR"
fi

# Step 4: Generate canonical signer config for this installation
DATA_DIR="$(getent passwd "$SVC_USER" | cut -d: -f6)"
if [ -z "$DATA_DIR" ]; then
    echo "Error: could not determine home directory for $SVC_USER" >&2
    exit 1
fi
CONFIG_PATH="$DATA_DIR/config.yaml"
STORE_PATH="$DATA_DIR/store"

echo ""
write_canonical_config() {
    local target="$1"
    if [ "$AUTO_UNLOCK" = "1" ]; then
        cat > "$target" <<EOF
store: $STORE_PATH
passphrase_command_argv: ["$BINDIR/pass-systemd-creds", "passphrase.cred"]
passphrase_timeout: "0"
lock_on_disconnect: false
EOF
    else
        cat > "$target" <<EOF
store: $STORE_PATH
lock_on_disconnect: false
EOF
    fi
    chown "$SVC_USER:$SVC_GROUP" "$target"
    chmod 600 "$target"
}

if [ -f "$CONFIG_PATH" ]; then
    CONFIG_NEW_PATH="$CONFIG_PATH.aplane-installer.new"
    echo "Config already exists at $CONFIG_PATH; leaving it unchanged."
    echo "Writing canonical template to $CONFIG_NEW_PATH..."
    write_canonical_config "$CONFIG_NEW_PATH"
else
    echo "Writing $CONFIG_PATH..."
    write_canonical_config "$CONFIG_PATH"
fi

# Step 5: Initialize keystore (only with --auto-unlock)
if [ "$AUTO_UNLOCK" = "1" ]; then
    echo ""
    echo "Checking keystore initialization state..."
    export PATH="$BINDIR:$PATH"
    ACTIVE_STORE_PATH="$STORE_PATH"
    if [ -f "$CONFIG_PATH" ]; then
        CONFIG_STORE="$(awk '
            /^[[:space:]]*#/ {next}
            /^[[:space:]]*store:[[:space:]]*/ {
                sub(/^[[:space:]]*store:[[:space:]]*/, "", $0)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
                gsub(/^"/, "", $0)
                gsub(/"$/, "", $0)
                gsub(/^'\''/, "", $0)
                gsub(/'\''$/, "", $0)
                print $0
                exit
            }' "$CONFIG_PATH")"
        if [ -n "$CONFIG_STORE" ]; then
            if [[ "$CONFIG_STORE" = /* ]]; then
                ACTIVE_STORE_PATH="$CONFIG_STORE"
            else
                ACTIVE_STORE_PATH="$DATA_DIR/$CONFIG_STORE"
            fi
        fi
    fi

    if [ -f "$ACTIVE_STORE_PATH/.keystore" ]; then
        echo "Keystore already initialized at $ACTIVE_STORE_PATH; skipping init."
    else
        echo "Initializing keystore in $DATA_DIR..."
        "$SCRIPT_DIR/scripts/init-signer.sh" "$DATA_DIR" "$SVC_USER:$SVC_GROUP"
    fi
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Enable and start:"
echo "       sudo systemctl enable aplane@\$(systemd-escape $DATA_DIR)"
echo "       sudo systemctl start aplane@\$(systemd-escape $DATA_DIR)"
if [ "$AUTO_UNLOCK" = "1" ]; then
    echo "  2. The service will auto-unlock using systemd-creds."
else
    echo "  2. Unlock the signer after starting:"
    echo "       sudo -u $SVC_USER apadmin -d $DATA_DIR"
fi
echo "  3. Generate keys:"
echo "       sudo -u $SVC_USER apadmin -d $DATA_DIR"
echo ""
echo "Tip: export APSIGNER_DATA=$DATA_DIR to avoid passing -d every time."
