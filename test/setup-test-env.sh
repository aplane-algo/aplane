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
# Fixture root:
#   - The primary checkout uses /tmp/aplane-test-env.
#   - A linked git worktree uses /tmp/aplane-test-env-<checksum of its path>,
#     so worktrees can run integration tests at the same time.
#   - APLANE_TEST_ENV overrides either default. A separate clone needs it,
#     because git cannot tell a second clone from the first.
#   - Setup records the owning checkout in the root and refuses to replace a
#     root it did not generate or one that another checkout owns.
#
# Output:
#   - Creates the fixture root with signer data
#   - Writes .env.test in the project root
#   - Prints eval-able export commands

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEFAULT_TEST_ENV="/tmp/aplane-test-env"
TEST_ENV_OWNER_FILE=".aplane-test-env-owner"

# Print the fixture root for this checkout when APLANE_TEST_ENV is not set.
default_test_env_root() {
    local git_dir common_dir
    git_dir="$(git -C "$PROJECT_ROOT" rev-parse --git-dir 2>/dev/null || true)"
    common_dir="$(git -C "$PROJECT_ROOT" rev-parse --git-common-dir 2>/dev/null || true)"
    if [ "$git_dir" != "$common_dir" ]; then
        echo "$DEFAULT_TEST_ENV-$(printf '%s' "$PROJECT_ROOT" | cksum | cut -d' ' -f1)"
    else
        echo "$DEFAULT_TEST_ENV"
    fi
}

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

TEST_ENV="${APLANE_TEST_ENV:-$(default_test_env_root)}"
case "$TEST_ENV" in
    /*)
        ;;
    *)
        echo "ERROR: APLANE_TEST_ENV must be an absolute path (got '$TEST_ENV')" >&2
        exit 1
        ;;
esac
if [ -e "$TEST_ENV" ]; then
    TEST_ENV_OWNER=""
    if [ -f "$TEST_ENV/$TEST_ENV_OWNER_FILE" ]; then
        TEST_ENV_OWNER="$(cat "$TEST_ENV/$TEST_ENV_OWNER_FILE")"
    fi
    if [ -z "$TEST_ENV_OWNER" ] && [ "$TEST_ENV" != "$DEFAULT_TEST_ENV" ]; then
        echo "ERROR: refusing to replace $TEST_ENV: it is not a generated test environment" >&2
        echo "  Choose a path that does not exist yet." >&2
        exit 1
    fi
    if [ -n "$TEST_ENV_OWNER" ] && [ "$TEST_ENV_OWNER" != "$PROJECT_ROOT" ] && [ -d "$TEST_ENV_OWNER" ]; then
        echo "ERROR: refusing to replace $TEST_ENV: it belongs to $TEST_ENV_OWNER" >&2
        echo "  Set APLANE_TEST_ENV to a path for this checkout, and check that the" >&2
        echo "  shell has not inherited it from another checkout's .env.test." >&2
        exit 1
    fi
fi
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
printf '%s\n' "$PROJECT_ROOT" > "$TEST_ENV/$TEST_ENV_OWNER_FILE"
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
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
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

# Replace the node default with a permissive test policy. The shipped default
# rejects foreign rekeys and reviews warnings; integration tests need rekey,
# close, and clawback to succeed for cleanup and workflow verification, and
# every route miss to fall through to the operator default. Tests that verify
# policy rejection apply their own documents.
APSIGNER_PASSPHRASE="$TEST_PASSPHRASE" \
    go run "$PROJECT_ROOT/cmd/apadmin" -d "$SIGNER_DATA" policy rescue apply --yes - << JSON
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": false,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": false,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "operator_default",
    "close_on_no_route": "operator_default",
    "clawback_on_no_route": "operator_default",
    "routes": []
  }
}
JSON
echo "  Applied permissive test default policy for default identity"

# Populate the plaintext template library used by apadmin's template browser.
mkdir -p "$SIGNER_DATA/library/templates"
cp "$PROJECT_ROOT"/library/templates/*.yaml "$SIGNER_DATA/library/templates/"
cp "$PROJECT_ROOT/library/templates/README.md" "$SIGNER_DATA/library/templates/"
echo "  Copied template library"

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
APLANE_TEST_ENV="$TEST_ENV"
APLANE_SHARED_APSIGNER_DATA="$SIGNER_DATA"
APLANE_SHARED_APCLIENT_DATA="$CLIENT_DATA"
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
echo "  Root:        $TEST_ENV"
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
