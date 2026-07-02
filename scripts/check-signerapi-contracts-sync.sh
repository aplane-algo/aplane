#!/usr/bin/env bash
# Compare the committed signer API contract fixtures with an aplanesdk checkout.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_DIR="${APLANESDK_DIR:-"$ROOT_DIR/../aplanesdk"}"
APLANE_CONTRACT_DIR="$ROOT_DIR/test/contracts/signerapi"
SDK_CONTRACT_DIR="$SDK_DIR/contracts/signerapi"

if [ ! -d "$SDK_CONTRACT_DIR" ]; then
    cat >&2 <<EOF
Error: aplanesdk signer API contract directory not found:
  $SDK_CONTRACT_DIR

Set APLANESDK_DIR=/path/to/aplanesdk or place the SDK checkout next to this
repo as ../aplanesdk.
EOF
    exit 2
fi

diff -ruN "$APLANE_CONTRACT_DIR" "$SDK_CONTRACT_DIR"
printf 'Signer API contract fixtures match: %s\n' "$SDK_CONTRACT_DIR"
