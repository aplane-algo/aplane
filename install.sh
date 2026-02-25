#!/bin/bash
# install.sh - Install aplane binaries and systemd service from a release tarball
#
# Usage:
#   sudo ./install.sh <username> <group> [bindir]
#
# Arguments:
#   username  User to run apsignerd as
#   group     Group to run apsignerd as
#   bindir    Where to install binaries (default: /usr/local/bin)
#
# Works from both a repo checkout and an extracted release tarball.

# Refuse to run when sourced
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: sudo $0 <username> <group> [bindir]" >&2
    return 1
fi

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <group> [bindir]" >&2
    echo "" >&2
    echo "  username  User to run apsignerd as" >&2
    echo "  group     Group to run apsignerd as" >&2
    echo "  bindir    Where to install binaries (default: /usr/local/bin)" >&2
    exit 2
fi

SVC_USER="$1"
SVC_GROUP="$2"
BINDIR="${3:-/usr/local/bin}"

# Resolve script directory (works from repo checkout and extracted tarball)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_SRC="$SCRIPT_DIR/bin"

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
    # pass-file and pass-systemd-creds need restricted permissions
    case "$name" in
        pass-file|pass-systemd-creds) chmod 700 "$BINDIR/$name" ;;
        *)                            chmod 755 "$BINDIR/$name" ;;
    esac
    echo "  $name"
done

# Step 3: Run systemd setup
echo ""
echo "Running systemd setup..."
"$SCRIPT_DIR/scripts/systemd-setup.sh" "$SVC_USER" "$SVC_GROUP" "$BINDIR"

# Step 4: Initialize keystore (apstore must be on PATH — we just installed it)
DATA_DIR="$(getent passwd "$SVC_USER" | cut -d: -f6)"
if [ -z "$DATA_DIR" ]; then
    echo "Error: could not determine home directory for $SVC_USER" >&2
    exit 1
fi
echo ""
echo "Initializing keystore in $DATA_DIR..."
export PATH="$BINDIR:$PATH"
"$SCRIPT_DIR/scripts/init-signer.sh" "$DATA_DIR" "$SVC_USER:$SVC_GROUP"

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Configure headless mode:"
echo "       sudo -u $SVC_USER tee $DATA_DIR/config.yaml <<'EOF'"
echo "       passphrase_command_argv: [\"pass-systemd-creds\", \"passphrase.cred\"]"
echo "       lock_on_disconnect: false"
echo "       EOF"
echo "  2. Enable and start:"
echo "       sudo systemctl enable aplane@\$(systemd-escape $DATA_DIR)"
echo "       sudo systemctl start aplane@\$(systemd-escape $DATA_DIR)"
echo "  3. Generate keys:"
echo "       sudo -u $SVC_USER apadmin -d $DATA_DIR"
echo ""
echo "Tip: export APSIGNER_DATA=$DATA_DIR to avoid passing -d every time."
