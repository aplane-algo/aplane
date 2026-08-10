#!/bin/bash
# systemd-setup.sh - Install the apsigner systemd service and sudoers rules
#
# Installs:
#   /etc/systemd/system/apsigner.service  (from installer/apsigner.service.template)
#   /etc/sudoers.d/99-apsigner-systemctl  (from installer/sudoers.template)
#
# Usage:
#   sudo ./installer/scripts/systemd-setup.sh <username> <group> [bindir] [--data-dir <path>] [--memory-lock]
#
# After installing, enable and start the service:
#   sudo systemctl enable apsigner
#   sudo systemctl start  apsigner

# Refuse to run when sourced (". script" or "source script" would kill the shell on exit/error)
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    echo "Error: this script must be executed, not sourced." >&2
    echo "Usage: sudo $0 <username> <group> [bindir] [--data-dir <path>] [--memory-lock]" >&2
    return 1
fi

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (use sudo)." >&2
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <group> [bindir] [--data-dir <path>] [--memory-lock]" >&2
    echo "" >&2
    echo "  username      User to run apsigner as" >&2
    echo "  group         Group to run apsigner as" >&2
    echo "  bindir        Directory containing apsigner binary (default: ../../bin relative to script)" >&2
    echo "  --data-dir    Data directory for apsigner (default: /var/lib/apsigner)" >&2
    echo "  --memory-lock Allow apsigner to lock memory with CAP_IPC_LOCK" >&2
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
INSTALLER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DATA_DIR="/var/lib/apsigner"
MEMORY_LOCK=0
if [ $# -ge 3 ] && [ "${3#--}" = "$3" ]; then
    BINDIR="$3"
    shift 3
else
    BINDIR="$SCRIPT_DIR/../../bin"
    shift 2
fi

# Check remaining args for --data-dir
while [ $# -gt 0 ]; do
    case "$1" in
        --data-dir)
            if [ $# -lt 2 ]; then
                echo "Error: --data-dir requires a value" >&2
                exit 2
            fi
            DATA_DIR="$2"
            shift 2
            ;;
        --memory-lock)
            MEMORY_LOCK=1
            shift
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            echo "Usage: $0 <username> <group> [bindir] [--data-dir <path>] [--memory-lock]" >&2
            exit 2
            ;;
    esac
done

# Resolve bindir to absolute path
BINDIR="$(cd "$BINDIR" && pwd)"

if [ ! -f "$BINDIR/apsigner" ]; then
    echo "Error: apsigner binary not found at $BINDIR/apsigner" >&2
    echo "Build it first with: make apsigner" >&2
    exit 1
fi

TEMPLATE="$INSTALLER_DIR/apsigner.service.template"
SUDOERS_TEMPLATE="$INSTALLER_DIR/sudoers.template"

if [ ! -f "$TEMPLATE" ]; then
    echo "Error: service template not found at $TEMPLATE" >&2
    exit 1
fi

if [ ! -f "$SUDOERS_TEMPLATE" ]; then
    echo "Error: sudoers template not found at $SUDOERS_TEMPLATE" >&2
    exit 1
fi

SERVICE_DEST="/etc/systemd/system/apsigner.service"
SUDOERS_DEST="/etc/sudoers.d/99-apsigner-systemctl"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "Error: systemctl is required for systemd setup." >&2
    exit 1
fi
if systemctl is-active --quiet apsigner.service; then
    echo "Error: stop apsigner.service before running systemd setup or signer-store migration." >&2
    exit 1
fi

# A production data root contains signer state only. Reject local-install
# layouts before writing .prod or changing any existing store permissions;
# migration would otherwise strip execute bits and Linux file capabilities.
if [ -L "$DATA_DIR" ]; then
    echo "Error: signer data directory must not be a symlink: $DATA_DIR" >&2
    exit 1
fi
mkdir -p "$DATA_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd -P)"
case "$BINDIR" in
    "$DATA_DIR"|"$DATA_DIR"/*)
        echo "Error: systemd service binaries must be outside the signer data directory." >&2
        echo "  Binary directory: $BINDIR" >&2
        echo "  Data directory:   $DATA_DIR" >&2
        exit 1
        ;;
esac
if [ -e "$DATA_DIR/bin" ]; then
    echo "Error: signer data directory contains a local-install bin/ subtree: $DATA_DIR/bin" >&2
    echo "Install service binaries outside the data directory and remove the old bin/ subtree before conversion." >&2
    exit 1
fi

echo "=== apsigner systemd setup ==="
echo ""
echo "  Service:   $SERVICE_DEST"
echo "  Sudoers:   $SUDOERS_DEST"
echo "  Binary:    $BINDIR/apsigner"
echo "  User:      $SVC_USER"
echo "  Group:     $SVC_GROUP"
echo "  Data dir:  $DATA_DIR"
if [ "$MEMORY_LOCK" = "1" ]; then
    echo "  Memory:    CAP_IPC_LOCK enabled"
else
    echo "  Memory:    CAP_IPC_LOCK disabled"
fi
echo ""

# The runtime socket is the group's only filesystem-facing capability. Close
# traversal of the persistent store before inspecting any credential paths.
chown "$SVC_USER:$SVC_GROUP" "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Install service with placeholder substitution
if [ "$MEMORY_LOCK" = "1" ]; then
    MEMORY_LOCK_SERVICE_LINES=$'CapabilityBoundingSet=CAP_IPC_LOCK\nAmbientCapabilities=CAP_IPC_LOCK\nLimitMEMLOCK=infinity'
else
    MEMORY_LOCK_SERVICE_LINES='CapabilityBoundingSet='
fi

sed -e "s|@@BINDIR@@|${BINDIR}|g" \
    -e "s|@@USER@@|${SVC_USER}|g" \
    -e "s|@@GROUP@@|${SVC_GROUP}|g" \
    -e "s|@@DATA_DIR@@|${DATA_DIR}|g" \
    "$TEMPLATE" | awk -v memory_lock_lines="$MEMORY_LOCK_SERVICE_LINES" '
        {
            gsub(/@@MEMORY_LOCK_SERVICE_LINES@@/, memory_lock_lines)
            print
        }
    ' > "$SERVICE_DEST"
chmod 644 "$SERVICE_DEST"
echo "Installed $SERVICE_DEST"

# If any identity has a passphrase.cred from a previous install, re-add the
# matching LoadCredentialEncrypted= directive so apsigner can auto-unlock without
# requiring the operator to re-run 'appass set systemd-creds' after reinstall.
SYSTEMD_CREDENTIAL_NAME="aplane-passphrase"
existing_cred_files=()
for f in "$DATA_DIR"/identities/*/passphrase.cred; do
    [ -f "$f" ] && existing_cred_files+=("$f")
done
if [ "${#existing_cred_files[@]}" -gt 0 ]; then
    if [ "${#existing_cred_files[@]}" -gt 1 ]; then
        echo "Warning: multiple identities have passphrase.cred; only the first will be bound:" >&2
        printf '  %s\n' "${existing_cred_files[@]}" >&2
        echo "  Re-run 'appass set systemd-creds' for the intended identity if this is wrong." >&2
    fi
    cred_file="${existing_cred_files[0]}"
    load_line="LoadCredentialEncrypted=${SYSTEMD_CREDENTIAL_NAME}:${cred_file}"
    awk -v line="$load_line" '
        { print }
        /^\[Service\]$/ && !inserted { print line; inserted = 1 }
    ' "$SERVICE_DEST" > "$SERVICE_DEST.tmp"
    mv "$SERVICE_DEST.tmp" "$SERVICE_DEST"
    chmod 644 "$SERVICE_DEST"
    echo "Re-bound systemd-creds passphrase from $cred_file"
fi

PROD_MARKER_PATH="$DATA_DIR/.prod"
printf 'systemd-managed\n' > "$PROD_MARKER_PATH"
chown "$SVC_USER:$SVC_GROUP" "$PROD_MARKER_PATH"
chmod 600 "$PROD_MARKER_PATH"
echo "Marked $DATA_DIR as a systemd-managed data directory"

if [ ! -x "$BINDIR/apstore" ]; then
    echo "Error: apstore binary not found at $BINDIR/apstore; cannot migrate signer-store permissions" >&2
    exit 1
fi
"$BINDIR/apstore" -d "$DATA_DIR" permissions migrate
"$BINDIR/apstore" -d "$DATA_DIR" permissions audit

# Install sudoers rules
sed -e "s|@@USER@@|${SVC_USER}|g" \
    "$SUDOERS_TEMPLATE" > "$SUDOERS_DEST"
chmod 440 "$SUDOERS_DEST"
echo "Installed $SUDOERS_DEST"

systemctl daemon-reload
echo "Ran systemctl daemon-reload"

echo ""
echo "Next steps:"
echo "  1. Enable on boot:"
echo "       sudo systemctl enable apsigner"
echo "  2. Start the service:"
echo "       sudo systemctl start apsigner"
echo "  3. Check status:"
echo "       systemctl status apsigner"
