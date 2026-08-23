#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 APlane Project LLC
#
# Create an isolated test environment for integration tests.
#
# Usage:
#   ./test/setup-test-env.sh
#
# This creates a temporary signer data directory and writes a .env.test
# file that integration tests can source. The environment is fully
# self-contained — it does not depend on any existing signer installation.
#
# Prerequisites:
#   - testnet mode: TEST_FUNDING_MNEMONIC must identify a funded native
#     Falcon-1024 account (requires the v42 network upgrade)
#   - localnet mode: a v42-capable AlgoKit LocalNet algod/KMD must be running;
#     setup bootstraps a disposable native Falcon funding account from KMD
#   - ssh-keygen must be available
#
# Output:
#   - Creates /tmp/aplane-test-env/ with signer data
#   - Writes .env.test in the project root
#   - Prints eval-able export commands

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Validate prerequisites
# ---------------------------------------------------------------------------

INTEGRATION_NETWORK="${APLANE_INTEGRATION_NETWORK:-}"
case "$INTEGRATION_NETWORK" in
    testnet|localnet)
        ;;
    "")
        echo "ERROR: APLANE_INTEGRATION_NETWORK must be set to 'testnet' or 'localnet'" >&2
        echo "  Example: APLANE_INTEGRATION_NETWORK=testnet make integration-test" >&2
        echo "  Example: APLANE_INTEGRATION_NETWORK=localnet make integration-test" >&2
        echo "  Setup only: APLANE_INTEGRATION_NETWORK=localnet ./test/setup-test-env.sh" >&2
        exit 1
        ;;
    *)
        echo "ERROR: APLANE_INTEGRATION_NETWORK must be 'testnet' or 'localnet' (got '$INTEGRATION_NETWORK')" >&2
        exit 1
        ;;
esac

if [ "$INTEGRATION_NETWORK" = "testnet" ] &&
   [ -z "${TEST_FUNDING_MNEMONIC:-}" ]; then
    MNEMONIC_FILE="$PROJECT_ROOT/test-mnemonic.sh"
    if [ -f "$MNEMONIC_FILE" ]; then
        # shellcheck source=/dev/null
        source "$MNEMONIC_FILE"
    fi
fi

if [ "$INTEGRATION_NETWORK" = "testnet" ] &&
   [ -z "${TEST_FUNDING_MNEMONIC:-}" ]; then
    echo "ERROR: TEST_FUNDING_MNEMONIC must be set" >&2
    echo "  The native Falcon-1024 account must be funded on $INTEGRATION_NETWORK." >&2
    echo "  Either create test-mnemonic.sh with: export TEST_FUNDING_MNEMONIC='your 25 word mnemonic here'" >&2
    echo "  Or set the variable directly before running this script" >&2
    echo "  Or run against localnet with: APLANE_INTEGRATION_NETWORK=localnet make integration-test" >&2
    exit 1
fi

if ! command -v ssh-keygen &>/dev/null; then
    echo "ERROR: ssh-keygen is required" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Create test environment
# ---------------------------------------------------------------------------

TEST_ENV="/tmp/aplane-test-env"
SIGNER_DATA="$TEST_ENV/apsigner"
CLIENT_DATA="$TEST_ENV/apclient"
SIGNER_RUNTIME_DIR="$SIGNER_DATA/run"
TEST_PASSPHRASE="test-passphrase-$(date +%s)"
LOCALNET_GENESIS_ID=""
LOCALNET_GENESIS_HASH=""
LOCALNET_KMD_URL="${APLANE_LOCALNET_KMD_URL:-http://localhost:4002}"
LOCALNET_WALLET="${APLANE_LOCALNET_WALLET:-unencrypted-default-wallet}"
LOCALNET_WALLET_PASSWORD="${APLANE_LOCALNET_WALLET_PASSWORD:-}"
INTEGRATION_GENESIS_ID=""
INTEGRATION_GENESIS_HASH=""
FUNDING_ADDRESS=""

if [ "$INTEGRATION_NETWORK" = "localnet" ]; then
    ALGOD_URL="${ALGOD_URL:-${APLANE_LOCALNET_ALGOD_URL:-http://localhost:4001}}"
    ALGOD_TOKEN="${ALGOD_TOKEN:-${APLANE_LOCALNET_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}}"
    export APLANE_LOCALNET_ALGOD_URL="$ALGOD_URL"
    export APLANE_LOCALNET_KMD_URL="$LOCALNET_KMD_URL"
    export APLANE_LOCALNET_TOKEN="$ALGOD_TOKEN"
    export APLANE_LOCALNET_WALLET="$LOCALNET_WALLET"
    export APLANE_LOCALNET_WALLET_PASSWORD="$LOCALNET_WALLET_PASSWORD"

    echo "Discovering LocalNet funding account via KMD..."
    LOCALNET_FUNDING_OUTPUT="$(go run "$PROJECT_ROOT/test/integration/cmd/localnet-funding")"
    while IFS= read -r line; do
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            FUNDING_ADDRESS)
                FUNDING_ADDRESS="$value"
                ;;
            TEST_FUNDING_MNEMONIC)
                TEST_FUNDING_MNEMONIC="$value"
                ;;
            LOCALNET_GENESIS_ID)
                LOCALNET_GENESIS_ID="$value"
                ;;
            LOCALNET_GENESIS_HASH)
                LOCALNET_GENESIS_HASH="$value"
                ;;
        esac
    done <<< "$LOCALNET_FUNDING_OUTPUT"

    if [ -z "${TEST_FUNDING_MNEMONIC:-}" ] || [ -z "$FUNDING_ADDRESS" ] || [ -z "$LOCALNET_GENESIS_HASH" ]; then
        echo "ERROR: failed to discover complete LocalNet funding/genesis metadata" >&2
        exit 1
    fi
    echo "  Selected LocalNet funding account $FUNDING_ADDRESS"
    echo "  LocalNet genesis: ${LOCALNET_GENESIS_ID:-unknown}"
    INTEGRATION_GENESIS_ID="$LOCALNET_GENESIS_ID"
    INTEGRATION_GENESIS_HASH="$LOCALNET_GENESIS_HASH"
else
    ALGOD_URL="${ALGOD_URL:-https://testnet-api.4160.nodely.dev}"
    ALGOD_TOKEN="${ALGOD_TOKEN:-}"
    INTEGRATION_GENESIS_ID="testnet-v1.0"
    INTEGRATION_GENESIS_HASH="SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="
    FUNDING_ADDRESS="$(TEST_FUNDING_MNEMONIC="$TEST_FUNDING_MNEMONIC" go run "$PROJECT_ROOT/test/integration/cmd/native-funding-address")"
    echo "  Using native Falcon TestNet funding account $FUNDING_ADDRESS"
fi

ENV_LOCALNET_ALGOD_URL=""
ENV_LOCALNET_KMD_URL=""
ENV_LOCALNET_TOKEN=""
ENV_LOCALNET_WALLET=""
ENV_LOCALNET_WALLET_PASSWORD=""
if [ "$INTEGRATION_NETWORK" = "localnet" ]; then
    ENV_LOCALNET_ALGOD_URL="$ALGOD_URL"
    ENV_LOCALNET_KMD_URL="$LOCALNET_KMD_URL"
    ENV_LOCALNET_TOKEN="$ALGOD_TOKEN"
    ENV_LOCALNET_WALLET="$LOCALNET_WALLET"
    ENV_LOCALNET_WALLET_PASSWORD="$LOCALNET_WALLET_PASSWORD"
fi

# Pick random available ports to avoid collisions with running services
SIGNER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
SSH_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# Clean up any previous test env
rm -rf "$TEST_ENV"
mkdir -p "$SIGNER_DATA/.ssh"
mkdir -p "$SIGNER_RUNTIME_DIR"
mkdir -p "$CLIENT_DATA/.ssh"
chmod 700 "$TEST_ENV" "$SIGNER_DATA" "$SIGNER_RUNTIME_DIR"

echo "Creating test environment in $TEST_ENV"

# ---------------------------------------------------------------------------
# Generate SSH host key for signer
# ---------------------------------------------------------------------------

ssh-keygen -t ed25519 -f "$SIGNER_DATA/.ssh/ssh_host_key" -N "" -q
echo "  Generated SSH host key"

# ---------------------------------------------------------------------------
# Generate client SSH key and authorize it
# ---------------------------------------------------------------------------

ssh-keygen -t ed25519 -f "$CLIENT_DATA/.ssh/id_ed25519" -N "" -q
cp "$CLIENT_DATA/.ssh/id_ed25519.pub" "$SIGNER_DATA/.ssh/authorized_keys"
echo "  Generated client SSH key and authorized it"

# ---------------------------------------------------------------------------
# Write signer config.yaml
# ---------------------------------------------------------------------------

SIGNER_GENESIS_CONFIG=""
if [ "$INTEGRATION_NETWORK" = "localnet" ]; then
    SIGNER_GENESIS_CONFIG="    genesis_hash: \"$LOCALNET_GENESIS_HASH\""
fi

cat > "$SIGNER_DATA/config.yaml" << YAML
# Test environment config — auto-generated by setup-test-env.sh
ipc_path: run/aplane.sock

endpoint:
  signer_port: $SIGNER_PORT
  ssh:
    port: $SSH_PORT
    host_key_path: .ssh/ssh_host_key
    authorized_keys_path: .ssh/authorized_keys

passphrase_timeout: "0m"
lock_on_disconnect: false

# Auto-approve for non-interactive testing
user_auto_approve: true

networks:
  $INTEGRATION_NETWORK:
    algod:
      server: $ALGOD_URL
      token: "$ALGOD_TOKEN"
$SIGNER_GENESIS_CONFIG
teal_compile_network: $INTEGRATION_NETWORK

require_memory_protection: false
YAML
echo "  Wrote signer config.yaml (port $SIGNER_PORT, SSH $SSH_PORT)"

# ---------------------------------------------------------------------------
# Write client config.yaml
# ---------------------------------------------------------------------------

cat > "$CLIENT_DATA/config.yaml" << YAML
# Test environment client config
network: $INTEGRATION_NETWORK
networks_allowed: [$INTEGRATION_NETWORK]

networks:
  $INTEGRATION_NETWORK:
    algod:
      server: $ALGOD_URL
      token: "$ALGOD_TOKEN"
YAML
echo "  Wrote client config.yaml"

cat > "$CLIENT_DATA/endpoints.yaml" << YAML
# Test environment endpoint registry
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://localhost:$SSH_PORT
    signer_port: $SIGNER_PORT
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
YAML
echo "  Wrote client endpoints.yaml"

# ---------------------------------------------------------------------------
# Write passphrase file
# ---------------------------------------------------------------------------

echo -n "$TEST_PASSPHRASE" > "$SIGNER_DATA/passphrase"
chmod 600 "$SIGNER_DATA/passphrase"
echo "  Wrote passphrase file"

# ---------------------------------------------------------------------------
# Initialize keystore (local bootstrap before apsigner is started)
# ---------------------------------------------------------------------------

printf '%s\n%s\n' "$TEST_PASSPHRASE" "$TEST_PASSPHRASE" | APSIGNER_DATA="$SIGNER_DATA" \
    go run "$PROJECT_ROOT/cmd/apstore" initialize
echo "  Keystore initialized"

# Authorize the client key for the initialized default identity as well.
mkdir -p "$SIGNER_DATA/identities/default/.ssh"
cp "$CLIENT_DATA/.ssh/id_ed25519.pub" "$SIGNER_DATA/identities/default/.ssh/authorized_keys"
echo "  Authorized client key for default identity"

# Write permissive test policy for the default identity.
# Production defaults reject rekey/close/clawback, but integration tests need
# these operations to succeed for cleanup and workflow verification.
# Tests that specifically verify policy rejection create their own fixtures.
cat > "$SIGNER_DATA/identities/default/policy.yaml" << YAML
reject_foreign_rekey: false
reject_close_remainder: false
reject_asset_close: false
reject_clawback: false
YAML
echo "  Wrote permissive test policy for default identity"
printf '%s\n' "$TEST_PASSPHRASE" | APSIGNER_DATA="$SIGNER_DATA" \
    go run "$PROJECT_ROOT/cmd/apstore" policy sign
echo "  Signed permissive test policy"

# Populate the plaintext template library used by apadmin's template browser.
mkdir -p "$SIGNER_DATA/library/templates"
cp "$PROJECT_ROOT"/library/templates/*.yaml "$SIGNER_DATA/library/templates/"
cp "$PROJECT_ROOT/library/templates/README.md" "$SIGNER_DATA/library/templates/"
echo "  Copied template library"

# Copy token to client data directory
cp "$SIGNER_DATA/identities/default/aplane.token" "$CLIENT_DATA/aplane.token"
echo "  Copied token to client data"

# Pre-populate client known_hosts with the signer's SSH host key
# This avoids TOFU prompts during non-interactive testing
HOST_PUB_KEY=$(cat "$SIGNER_DATA/.ssh/ssh_host_key.pub")
echo "[localhost]:$SSH_PORT $HOST_PUB_KEY" > "$CLIENT_DATA/.ssh/known_hosts"
echo "  Pre-populated known_hosts with signer host key"

# ---------------------------------------------------------------------------
# Write .env.test
# ---------------------------------------------------------------------------

cat > "$PROJECT_ROOT/.env.test" << EOF
# Auto-generated by test/setup-test-env.sh — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this file before running integration tests:
#   set -a && . .env.test && set +a && make integration-test

APLANE_INTEGRATION_NETWORK="$INTEGRATION_NETWORK"
APLANE_INTEGRATION_GENESIS_ID="$INTEGRATION_GENESIS_ID"
APLANE_INTEGRATION_GENESIS_HASH="$INTEGRATION_GENESIS_HASH"
TEST_FUNDING_MNEMONIC="$TEST_FUNDING_MNEMONIC"
TEST_PASSPHRASE="$TEST_PASSPHRASE"
APSIGNER_DATA="$SIGNER_DATA"
APCLIENT_DATA="$CLIENT_DATA"
ALGOD_URL="$ALGOD_URL"
ALGOD_TOKEN="$ALGOD_TOKEN"
APLANE_LOCALNET_ALGOD_URL="$ENV_LOCALNET_ALGOD_URL"
APLANE_LOCALNET_KMD_URL="$ENV_LOCALNET_KMD_URL"
APLANE_LOCALNET_TOKEN="$ENV_LOCALNET_TOKEN"
APLANE_LOCALNET_WALLET="$ENV_LOCALNET_WALLET"
APLANE_LOCALNET_WALLET_PASSWORD="$ENV_LOCALNET_WALLET_PASSWORD"
LOCALNET_GENESIS_ID="$LOCALNET_GENESIS_ID"
LOCALNET_GENESIS_HASH="$LOCALNET_GENESIS_HASH"
DISABLE_MEMORY_LOCK=1
EOF
chmod 600 "$PROJECT_ROOT/.env.test"
echo "  Wrote .env.test"

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------

echo ""
echo "Test environment ready:"
echo "  Network:     $INTEGRATION_NETWORK"
echo "  Signer data: $SIGNER_DATA"
echo "  Client data: $CLIENT_DATA"
echo "  Signer port: $SIGNER_PORT"
echo "  SSH port:    $SSH_PORT"
echo ""
echo "To use:"
echo "  source .env.test"
echo "  make integration-test"
echo ""
echo "Or export directly:"
echo "  export APSIGNER_DATA=$SIGNER_DATA"
echo "  export APCLIENT_DATA=$CLIENT_DATA"
echo "  export APLANE_INTEGRATION_NETWORK=$INTEGRATION_NETWORK"
echo "  export TEST_PASSPHRASE=$TEST_PASSPHRASE"
echo "  export ALGOD_URL=$ALGOD_URL"
echo "  export ALGOD_TOKEN=$ALGOD_TOKEN"
echo "  export DISABLE_MEMORY_LOCK=1"
