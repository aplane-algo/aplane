#!/bin/bash
# init-signer.sh - Initialize apsignerd keystore with TPM2-encrypted passphrase
#
# Must be run as root (systemd-creds encrypt requires TPM2/host key access).
# After creating the keystore, fixes store permissions so apsignerd can run
# as a non-root service user.
#
# Usage:
#   sudo ./init-signer.sh <data-dir> <user:group>
#
# Example:
#   sudo ./init-signer.sh /home/thong/avrun thong:thong

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root. Run with: sudo $0 $*" >&2
    exit 1
fi

DATA_DIR="${1:?Usage: init-signer.sh <data-dir> <user:group>}"
OWNER="${2:?Usage: init-signer.sh <data-dir> <user:group>}"

# Validate owner format
if ! echo "$OWNER" | grep -q ':'; then
    echo "Error: owner must be user:group (e.g., thong:thong)" >&2
    exit 1
fi

apstore -d "$DATA_DIR" init --random

# passphrase.cred stays root-owned (only systemd reads it via LoadCredentialEncrypted)
# store/ must be owned by the service user
chown -R "$OWNER" "$DATA_DIR/store"

echo ""
echo "Done. Start the service with: systemctl start apsignerd"
