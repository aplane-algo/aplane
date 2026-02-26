#!/bin/bash
# systemcreds-install.sh - Upgrade a locked-start apsignerd installation to use systemd-creds auto-unlock
#
# This script upgrades an existing apsignerd installation (created without --auto-unlock)
# to use systemd-creds for automatic passphrase management. It:
#   1. Regenerates the service file with LoadCredentialEncrypted
#   2. Adds passphrase_command_argv to config.yaml
#   3. Initializes or re-encrypts the keystore with a random passphrase
#
# Usage:
#   sudo ./scripts/systemcreds-install.sh [data-dir]
#
# Arguments:
#   data-dir    apsignerd data directory (default: /var/lib/aplane)

# Refuse to run when sourced
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: sudo $0 [data-dir]" >&2
    return 1
fi

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

DATA_DIR="${1:-/var/lib/aplane}"

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Prerequisites ---

if ! command -v systemd-creds >/dev/null 2>&1; then
    echo "Error: systemd-creds not found. Requires systemd >= 250." >&2
    exit 1
fi

SERVICE_FILE="/lib/systemd/system/aplane@.service"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "Error: service file not found at $SERVICE_FILE" >&2
    echo "Run the installer first to create a base installation." >&2
    exit 1
fi

# --- Extract configuration from installed service file ---

BINDIR="$(grep -m1 '^ExecStart=' "$SERVICE_FILE" | sed 's|^ExecStart=||; s|/apsignerd.*||')"
if [ -z "$BINDIR" ]; then
    echo "Error: could not extract binary directory from $SERVICE_FILE" >&2
    exit 1
fi

if [ ! -f "$BINDIR/pass-systemd-creds" ]; then
    echo "Error: pass-systemd-creds not found at $BINDIR/pass-systemd-creds" >&2
    echo "Ensure pass-systemd-creds is installed alongside apsignerd." >&2
    exit 1
fi

SVC_USER="$(grep -m1 '^User=' "$SERVICE_FILE" | sed 's|^User=||')"
if [ -z "$SVC_USER" ]; then
    echo "Error: could not extract User= from $SERVICE_FILE" >&2
    exit 1
fi

SVC_GROUP="$(grep -m1 '^Group=' "$SERVICE_FILE" | sed 's|^Group=||')"
if [ -z "$SVC_GROUP" ]; then
    echo "Error: could not extract Group= from $SERVICE_FILE" >&2
    exit 1
fi

# --- Guard: already configured ---

if grep -q 'LoadCredentialEncrypted' "$SERVICE_FILE"; then
    echo "Error: $SERVICE_FILE already contains LoadCredentialEncrypted." >&2
    echo "systemd-creds auto-unlock is already configured." >&2
    exit 1
fi

echo "=== systemd-creds auto-unlock upgrade ==="
echo ""
echo "  Data dir:  $DATA_DIR"
echo "  Binary:    $BINDIR/apsignerd"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo ""

# --- Step 1: Regenerate service file with LoadCredentialEncrypted ---

echo "Regenerating service file with LoadCredentialEncrypted..."
"$SCRIPT_DIR/systemd-setup.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR" --auto-unlock

# --- Step 2: Update config.yaml ---

CONFIG_PATH="$DATA_DIR/config.yaml"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: config file not found at $CONFIG_PATH" >&2
    exit 1
fi

if grep -q 'passphrase_command_argv' "$CONFIG_PATH"; then
    echo "Config already has passphrase_command_argv; skipping config update."
else
    echo "Adding passphrase_command_argv to $CONFIG_PATH..."
    cat >> "$CONFIG_PATH" <<EOF
passphrase_command_argv: ["$BINDIR/pass-systemd-creds", "passphrase.cred"]
passphrase_timeout: "0"
EOF
    echo "Updated $CONFIG_PATH"
fi

# --- Step 3: Handle keystore ---

STORE_DIR="$DATA_DIR/store"
KEYSTORE_FILE="$STORE_DIR/.keystore"

if [ ! -f "$KEYSTORE_FILE" ]; then
    echo ""
    echo "No existing keystore found. Initializing new keystore..."
    "$SCRIPT_DIR/init-signer.sh" "$DATA_DIR" "$SVC_USER:$SVC_GROUP"
else
    echo ""
    echo "Existing keystore found. Re-encrypting with random passphrase..."
    apstore -d "$DATA_DIR" changepass --random
fi

# --- Step 4: Fix permissions ---

# passphrase.cred must be root-owned (systemd reads it via LoadCredentialEncrypted)
if [ -f "$DATA_DIR/passphrase.cred" ]; then
    chown root:root "$DATA_DIR/passphrase.cred"
    chmod 600 "$DATA_DIR/passphrase.cred"
fi

# store/ must be owned by the service user
if [ -d "$STORE_DIR" ]; then
    chown -R "$SVC_USER:$SVC_GROUP" "$STORE_DIR"
fi

# --- Done ---

echo ""
echo "=== Upgrade complete ==="
echo ""
echo "Next steps:"
echo "  1. Restart the service:"
ESCAPED_DIR="$(systemd-escape "$DATA_DIR")"
echo "       sudo systemctl restart aplane@$ESCAPED_DIR"
echo "  2. Check status:"
echo "       systemctl status aplane@$ESCAPED_DIR"
