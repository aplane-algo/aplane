#!/bin/bash
# DEPRECATED: Use 'sudo appass -d <data-dir> set passfile' instead.
#
# passphrase-install.sh - Upgrade a locked-start apsignerd installation to use pass-file auto-unlock
#
# This script upgrades an existing apsignerd installation (created without --auto-unlock)
# to use a plaintext passphrase file for automatic passphrase management. It:
#   1. Prompts for the passphrase and writes it to a file
#   2. Adds passphrase_command_argv to config.yaml
#
# The keystore must already be initialized (via apstore init). This script
# does not create or modify the keystore — it only sets up auto-unlock.
#
# WARNING: The passphrase is stored in a plaintext file. This method is suitable
# for development and testing environments only. For production, use systemd-creds
# (systemcreds-install.sh) which encrypts the passphrase via TPM2/host key.
#
# Usage:
#   sudo ./scripts/passphrase-install.sh [data-dir]
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

# --- Prerequisites ---

SERVICE_FILE="/lib/systemd/system/aplane.service"

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

if [ ! -f "$BINDIR/pass-file" ]; then
    echo "Error: pass-file not found at $BINDIR/pass-file" >&2
    echo "Ensure pass-file is installed alongside apsignerd." >&2
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

# --- Guard: don't downgrade from systemd-creds ---

if grep -q 'LoadCredentialEncrypted' "$SERVICE_FILE"; then
    echo "Error: $SERVICE_FILE contains LoadCredentialEncrypted." >&2
    echo "This installation uses systemd-creds auto-unlock, which is more secure." >&2
    echo "Use systemcreds-install.sh to manage systemd-creds installations." >&2
    exit 1
fi

# --- Guard: already configured ---

CONFIG_PATH="$DATA_DIR/config.yaml"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: config file not found at $CONFIG_PATH" >&2
    exit 1
fi

if grep -q 'passphrase_command_argv' "$CONFIG_PATH"; then
    echo "Error: $CONFIG_PATH already contains passphrase_command_argv." >&2
    echo "Auto-unlock is already configured." >&2
    exit 1
fi

echo "=== pass-file auto-unlock upgrade ==="
echo ""
echo "  WARNING: This stores the passphrase in a plaintext file."
echo "  Suitable for development/testing only. For production, use"
echo "  systemcreds-install.sh (TPM2-backed encryption) instead."
echo ""
echo "  Data dir:  $DATA_DIR"
echo "  Binary:    $BINDIR/apsignerd"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo ""

# --- Step 1: Prompt for passphrase ---

PASSPHRASE_FILE="$DATA_DIR/passphrase"

echo "Enter the passphrase for the keystore."
echo "This must match the passphrase used (or to be used) with apstore init."
echo ""
read -rsp "Passphrase: " PASSPHRASE
echo ""
read -rsp "Confirm:    " PASSPHRASE_CONFIRM
echo ""

if [ "$PASSPHRASE" != "$PASSPHRASE_CONFIRM" ]; then
    echo "Error: passphrases do not match." >&2
    exit 1
fi

if [ -z "$PASSPHRASE" ]; then
    echo "Error: passphrase must not be empty." >&2
    exit 1
fi

# --- Step 2: Write passphrase file ---

echo "Writing passphrase file..."
printf '%s' "$PASSPHRASE" > "$PASSPHRASE_FILE"
chown "$SVC_USER:$SVC_GROUP" "$PASSPHRASE_FILE"
chmod 600 "$PASSPHRASE_FILE"

# --- Step 3: Update config.yaml ---

echo "Adding passphrase_command_argv to $CONFIG_PATH..."
cat >> "$CONFIG_PATH" <<EOF
passphrase_command_argv: ["$BINDIR/pass-file", "$PASSPHRASE_FILE"]
passphrase_timeout: "0"
EOF
echo "Updated $CONFIG_PATH"

# --- Done ---

echo ""
echo "=== Upgrade complete ==="
echo ""
echo "Next steps:"
echo "  1. If the keystore is not yet initialized:"
echo "       sudo apstore -d $DATA_DIR init"
echo "     Use the same passphrase you entered above."
echo "  2. Start (or restart) the service:"
echo "       sudo systemctl restart aplane"
echo "  3. Check status:"
echo "       systemctl status aplane"
