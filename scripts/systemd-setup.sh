#!/bin/bash
# systemd-setup.sh - Install the aplane systemd template service and sudoers rules
#
# Installs:
#   /lib/systemd/system/aplane@.service  (from installer/aplane@.service.template)
#   /etc/sudoers.d/99-aplane-systemctl   (from installer/sudoers.template)
#
# Usage:
#   sudo ./scripts/systemd-setup.sh <username> <group> [bindir]
#
# After installing, initialize the keystore and start the service:
#   sudo ./scripts/init-signer.sh /var/lib/aplane username:group
#   sudo systemctl enable aplane@$(systemd-escape /var/lib/aplane)
#   sudo systemctl start  aplane@$(systemd-escape /var/lib/aplane)

# Refuse to run when sourced (". script" or "source script" would kill the shell on exit/error)
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
    echo "  bindir    Directory containing apsignerd binary (default: ../bin relative to script)" >&2
    exit 2
fi

SVC_USER="$1"
SVC_GROUP="$2"

# Validate user exists
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    echo "Error: user '$SVC_USER' does not exist." >&2
    exit 1
fi

# Validate group exists
if ! getent group "$SVC_GROUP" >/dev/null 2>&1; then
    echo "Error: group '$SVC_GROUP' does not exist." >&2
    exit 1
fi

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER_DIR="$SCRIPT_DIR/../installer"

if [ $# -ge 3 ]; then
    BINDIR="$3"
else
    BINDIR="$SCRIPT_DIR/../bin"
fi

# Resolve bindir to absolute path
BINDIR="$(cd "$BINDIR" && pwd)"

if [ ! -f "$BINDIR/apsignerd" ]; then
    echo "Error: apsignerd binary not found at $BINDIR/apsignerd" >&2
    echo "Build it first with: make apsignerd" >&2
    exit 1
fi

TEMPLATE="$INSTALLER_DIR/aplane@.service.template"
SUDOERS_TEMPLATE="$INSTALLER_DIR/sudoers.template"

if [ ! -f "$TEMPLATE" ]; then
    echo "Error: service template not found at $TEMPLATE" >&2
    exit 1
fi

if [ ! -f "$SUDOERS_TEMPLATE" ]; then
    echo "Error: sudoers template not found at $SUDOERS_TEMPLATE" >&2
    exit 1
fi

SERVICE_DEST="/lib/systemd/system/aplane@.service"
SUDOERS_DEST="/etc/sudoers.d/99-aplane-systemctl"

echo "=== aplane systemd setup ==="
echo ""
echo "  Service:   $SERVICE_DEST"
echo "  Sudoers:   $SUDOERS_DEST"
echo "  Binary:    $BINDIR/apsignerd"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo ""

# Install service template with placeholder substitution
sed -e "s|@@BINDIR@@|${BINDIR}|g" \
    -e "s|@@USER@@|${SVC_USER}|g" \
    -e "s|@@GROUP@@|${SVC_GROUP}|g" \
    "$TEMPLATE" > "$SERVICE_DEST"
chmod 644 "$SERVICE_DEST"
echo "Installed $SERVICE_DEST"

# Install sudoers rules
sed -e "s|@@USER@@|${SVC_USER}|g" \
    "$SUDOERS_TEMPLATE" > "$SUDOERS_DEST"
chmod 440 "$SUDOERS_DEST"
echo "Installed $SUDOERS_DEST"

systemctl daemon-reload
echo "Ran systemctl daemon-reload"

echo ""
echo "Next steps:"
echo "  1. Initialize the keystore (if not already done):"
echo "       sudo $SCRIPT_DIR/init-signer.sh /var/lib/aplane $SVC_USER:$SVC_GROUP"
echo "  2. Enable on boot:"
echo "       sudo systemctl enable aplane@\$(systemd-escape /var/lib/aplane)"
echo "  3. Start the service:"
echo "       sudo systemctl start aplane@\$(systemd-escape /var/lib/aplane)"
echo "  4. Check status:"
echo "       systemctl status aplane@\$(systemd-escape /var/lib/aplane)"
