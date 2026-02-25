#!/bin/bash
# install-service.sh - Install the apsignerd systemd unit file
#
# Generates and installs /etc/systemd/system/apsignerd.service using
# the caller's user/group and APSIGNER_DATA environment variable.
#
# Run as your normal user (not sudo). The script uses sudo internally
# to write the unit file and reload systemd.
#
# Usage:
#   APSIGNER_DATA=/home/user/avrun ./scripts/install-service.sh
#
# After installing, initialize the keystore and start the service:
#   sudo ./scripts/init-signer.sh "$APSIGNER_DATA" user:group
#   sudo systemctl start apsignerd
#   sudo systemctl enable apsignerd

# Refuse to run when sourced (". script" or "source script" would kill the shell on exit/error)
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: APSIGNER_DATA=/home/user/avrun ./scripts/install-service.sh" >&2
    return 1
fi

set -euo pipefail

if [ -z "${APSIGNER_DATA:-}" ]; then
    echo "Error: APSIGNER_DATA environment variable must be set." >&2
    echo "Usage: APSIGNER_DATA=/home/user/avrun $0" >&2
    exit 1
fi

# Resolve APSIGNER_DATA to an absolute path
APSIGNER_DATA="$(cd "$APSIGNER_DATA" && pwd)"

# Detect user/group
SVC_USER="$(whoami)"
SVC_GROUP="$(id -gn "$SVC_USER")"

# Resolve binary path relative to this script (../bin/apsignerd)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APSIGNERD_BIN="$SCRIPT_DIR/../bin/apsignerd"
if [ ! -f "$APSIGNERD_BIN" ]; then
    echo "Error: apsignerd binary not found at $APSIGNERD_BIN" >&2
    echo "Build it first with: make apsignerd" >&2
    exit 1
fi
APSIGNERD_BIN="$(cd "$(dirname "$APSIGNERD_BIN")" && pwd)/$(basename "$APSIGNERD_BIN")"

UNIT_FILE="/etc/systemd/system/apsignerd.service"
CRED_FILE="$APSIGNER_DATA/passphrase.cred"

echo "=== apsignerd service installer ==="
echo ""
echo "  Unit file:    $UNIT_FILE"
echo "  Binary:       $APSIGNERD_BIN"
echo "  Data dir:     $APSIGNER_DATA"
echo "  User:         $SVC_USER"
echo "  Group:        $SVC_GROUP"
echo "  Credential:   $CRED_FILE"
echo ""

read -r -p "Install this unit file? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Generate the unit file to a temp file, then sudo move it into place
TMPFILE="$(mktemp)"
cat > "$TMPFILE" <<EOF
[Unit]
Description=apsignerd - Signing Server
After=network.target

[Service]
User=$SVC_USER
Group=$SVC_GROUP
WorkingDirectory=$APSIGNER_DATA
Environment=APSIGNER_DATA=$APSIGNER_DATA
LoadCredentialEncrypted=aplane-passphrase:$CRED_FILE
ExecStart=$APSIGNERD_BIN
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo mv "$TMPFILE" "$UNIT_FILE"
sudo chmod 644 "$UNIT_FILE"
echo "Wrote $UNIT_FILE"

sudo systemctl daemon-reload
echo "Ran systemctl daemon-reload"

echo ""
echo "Next steps:"
echo "  1. Initialize the keystore (if not already done):"
echo "       sudo $SCRIPT_DIR/init-signer.sh $APSIGNER_DATA $SVC_USER:$SVC_GROUP"
echo "  2. Start the service:"
echo "       sudo systemctl start apsignerd"
echo "  3. Enable on boot:"
echo "       sudo systemctl enable apsignerd"
