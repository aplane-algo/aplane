#!/usr/bin/env bash
# Smoke-test a local four-container Docker topology:
#   1. signer apsigner node
#   2. sentry apsigner node
#   3. client/admin node with apshell and apadmin
#   4. AlgoKit-style LocalNet algod/KMD node
#
# The test keeps the existing docker-local behavior surface focused on install,
# SSH token provisioning, client reachability, and shared LocalNet wiring. It
# starts a sentry node and wires the client endpoint registry to it, but does
# not yet exercise sentry signing flows.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH=""
DIST_DIR=""
VERSION="docker-smoke"
TARBALL=""
SKIP_BUILD=0
KEEP_CONTAINER=0
IMAGE_NAME=""
RUN_ID="$$"
NETWORK_NAME="aplane-local-smoke-net-$RUN_ID"
ALGOD_CONTAINER="aplane-local-algod-$RUN_ID"
SIGNER_CONTAINER="aplane-local-signer-$RUN_ID"
SENTRY_CONTAINER="aplane-local-sentry-$RUN_ID"
CLIENT_CONTAINER="aplane-local-client-$RUN_ID"
TEST_USER="tester"
TEST_PASSPHRASE="passphrase-for-docker-smoke"
ALGOD_IMAGE="algorand/algod:latest"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ALGOD_URL="http://algod:8080"
KMD_URL="http://algod:7833"
FALCON_FUND_AMOUNT=100000000
ALGOD_CONFIG_DIR=""
LOCALNET_GENESIS_HASH=""
FALCON_ADDRESS=""

usage() {
    cat <<'EOF'
Usage: scripts/docker-local-four-node-smoke.sh [options]

Options:
  --tarball <path>      Use an existing aplane_<version>_linux_<arch>.tar.gz
  --version <version>   Version string for locally built tarball (default: docker-smoke)
  --arch <amd64|arm64>  Architecture to package/test (default: host arch)
  --skip-build          Reuse existing bin/<arch> binaries when building the tarball
  --keep-container      Leave containers and network running for debugging
  -h, --help            Show this help

This test requires Docker privileges. It starts four containers on one Docker
network: signer, sentry, client/admin, and an AlgoKit-style LocalNet algod/KMD
node. The signer and sentry run local apsigner installs bound to 0.0.0.0 inside
the Docker network. All APlane nodes use the shared LocalNet algod endpoint.
The client runs a client-only install plus apadmin, points endpoints.yaml at the
signer and sentry container DNS names, requests a signer API token, and verifies
apshell can connect to the signer with that token. Sentry signing is not tested
yet.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '\n==> %s\n' "$*"
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) printf '%s\n' "amd64" ;;
        aarch64|arm64) printf '%s\n' "arm64" ;;
        *) die "unsupported host architecture: $(uname -m)" ;;
    esac
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --tarball)
                [ $# -ge 2 ] || die "--tarball requires a value"
                TARBALL="$2"
                shift 2
                ;;
            --version)
                [ $# -ge 2 ] || die "--version requires a value"
                VERSION="${2#v}"
                shift 2
                ;;
            --arch)
                [ $# -ge 2 ] || die "--arch requires a value"
                ARCH="$2"
                shift 2
                ;;
            --skip-build)
                SKIP_BUILD=1
                shift
                ;;
            --keep-container)
                KEEP_CONTAINER=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
    done
}

docker_exec() {
    local container="$1"
    shift
    docker exec "$container" "$@"
}

docker_exec_bash() {
    local container="$1"
    local script="$2"
    docker exec "$container" bash -lc "$script"
}

docker_exec_as_tester() {
    local container="$1"
    local script="$2"
    docker exec --user "$TEST_USER" "$container" bash -lc "$script"
}

cleanup() {
    if [ "$KEEP_CONTAINER" = "1" ]; then
        printf '\nKept containers for debugging:\n'
        printf '  %s\n' "$ALGOD_CONTAINER" "$SIGNER_CONTAINER" "$SENTRY_CONTAINER" "$CLIENT_CONTAINER"
        printf 'Kept Docker network: %s\n' "$NETWORK_NAME"
        if [ -n "$ALGOD_CONFIG_DIR" ]; then
            printf 'Kept LocalNet config dir: %s\n' "$ALGOD_CONFIG_DIR"
        fi
        return
    fi
    docker rm -f "$ALGOD_CONTAINER" "$SIGNER_CONTAINER" "$SENTRY_CONTAINER" "$CLIENT_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
    if [ -n "$ALGOD_CONFIG_DIR" ]; then
        rm -rf "$ALGOD_CONFIG_DIR"
    fi
}

build_image() {
    IMAGE_NAME="aplane-local-smoke:ubuntu-24.04"
    local dockerfile
    dockerfile="$(mktemp)"
    cat > "$dockerfile" <<'DOCKERFILE'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl expect gzip openssh-client passwd procps sudo tar && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
DOCKERFILE
    docker build -t "$IMAGE_NAME" -f "$dockerfile" "$ROOT_DIR"
    rm -f "$dockerfile"
}

build_or_resolve_tarball() {
    if [ -n "$TARBALL" ]; then
        TARBALL="$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")"
        [ -f "$TARBALL" ] || die "tarball not found: $TARBALL"
        return
    fi

    if [ -z "$ARCH" ]; then
        ARCH="$(detect_arch)"
    fi
    DIST_DIR="$(mktemp -d)"
    local args=(--version "$VERSION" --arch "$ARCH" --dist-dir "$DIST_DIR")
    if [ "$SKIP_BUILD" = "1" ]; then
        args+=(--skip-build)
    fi
    "$ROOT_DIR/scripts/package-bootstrap-release.sh" "${args[@]}"
    TARBALL="$DIST_DIR/aplane_${VERSION}_linux_${ARCH}.tar.gz"
    [ -f "$TARBALL" ] || die "expected tarball not found: $TARBALL"
}

write_algod_localnet_files() {
    ALGOD_CONFIG_DIR="$(mktemp -d)"
    mkdir -p "$ALGOD_CONFIG_DIR/goal_mount"

    cat > "$ALGOD_CONFIG_DIR/config.json" <<'JSON'
{
  "GossipFanout": 1,
  "EndpointAddress": "0.0.0.0:8080",
  "DNSBootstrapID": "",
  "IncomingConnectionsLimit": 0,
  "Archival": true,
  "isIndexerActive": false,
  "EnableDeveloperAPI": true,
  "EnablePrivateNetworkAccessHeader": true
}
JSON

    cat > "$ALGOD_CONFIG_DIR/template.json" <<'JSON'
{
  "Genesis": {
    "NetworkName": "followermodenet",
    "RewardsPoolBalance": 0,
    "FirstPartKeyRound": 0,
    "LastPartKeyRound": NUM_ROUNDS,
    "Wallets": [
      {
        "Name": "Wallet1",
        "Stake": 40,
        "Online": true
      },
      {
        "Name": "Wallet2",
        "Stake": 40,
        "Online": true
      },
      {
        "Name": "Wallet3",
        "Stake": 20,
        "Online": true
      }
    ],
    "DevMode": true
  },
  "Nodes": [
    {
      "Name": "data",
      "IsRelay": true,
      "Wallets": [
        {
          "Name": "Wallet1",
          "ParticipationOnly": false
        },
        {
          "Name": "Wallet2",
          "ParticipationOnly": false
        },
        {
          "Name": "Wallet3",
          "ParticipationOnly": false
        }
      ]
    },
    {
      "Name": "follower",
      "IsRelay": false,
      "ConfigJSONOverride": "{\"EnableFollowMode\":true,\"EndpointAddress\":\"0.0.0.0:8081\",\"MaxAcctLookback\":64,\"CatchupParallelBlocks\":64,\"CatchupBlockValidateMode\":3}"
    }
  ]
}
JSON
}

start_containers() {
    docker network create "$NETWORK_NAME" >/dev/null
    write_algod_localnet_files
    docker run \
        --name "$ALGOD_CONTAINER" \
        --network "$NETWORK_NAME" \
        --network-alias algod \
        --init \
        -e KMD_TOKEN="$ALGOD_TOKEN" \
        -e TOKEN="$ALGOD_TOKEN" \
        -e ADMIN_TOKEN="$ALGOD_TOKEN" \
        -e GOSSIP_PORT=10000 \
        -e START_KMD=1 \
        -e ALGOD_PORT=8080 \
        -e KMD_PORT=7833 \
        -e ALGORAND_DATA=/algod/data \
        -v "$ALGOD_CONFIG_DIR/config.json:/etc/algorand/config.json:ro" \
        -v "$ALGOD_CONFIG_DIR/template.json:/etc/algorand/template.json:ro" \
        -v "$ALGOD_CONFIG_DIR/goal_mount:/root/goal_mount" \
        -d "$ALGOD_IMAGE" >/dev/null
    docker run --name "$SIGNER_CONTAINER" --network "$NETWORK_NAME" --network-alias signer -d "$IMAGE_NAME" >/dev/null
    docker run --name "$SENTRY_CONTAINER" --network "$NETWORK_NAME" --network-alias sentry -d "$IMAGE_NAME" >/dev/null
    docker run --name "$CLIENT_CONTAINER" --network "$NETWORK_NAME" --network-alias client -d "$IMAGE_NAME" >/dev/null
}

create_test_user() {
    local container="$1"
    docker_exec "$container" useradd -m -s /bin/bash "$TEST_USER"
    docker_exec_as_tester "$container" "touch /home/$TEST_USER/.bashrc"
}

stage_release() {
    local container="$1"
    docker cp "$TARBALL" "$container:/tmp/aplane.tar.gz"
    docker_exec "$container" chmod 644 /tmp/aplane.tar.gz
    docker_exec_as_tester "$container" "mkdir -p /home/$TEST_USER/src && tar -xzf /tmp/aplane.tar.gz -C /home/$TEST_USER/src"
}

run_node_installer() {
    local container="$1"
    local role="$2"

    stage_release "$container"
    docker_exec_as_tester "$container" "cd /home/$TEST_USER/src/aplane && expect <<'EXPECT'
set timeout 180
set completed 0
spawn ./install.sh --role $role /home/$TEST_USER/aplane
expect {
  \"Proceed with installation?*\" { send \"\r\" }
  timeout { exit 11 }
}
expect {
  \"Enable enforced memory locking for apsigner?*\" { send \"n\r\" }
  timeout { exit 12 }
}
expect {
  \"Enter passphrase:\" { send \"$TEST_PASSPHRASE\r\" }
  timeout { exit 14 }
}
expect {
  \"Confirm passphrase:\" { send \"$TEST_PASSPHRASE\r\" }
  timeout { exit 15 }
}
expect {
  \"Add apenv.sh to *\" { send \"y\r\"; exp_continue }
  \"=== Installation complete ===\" { set completed 1; exp_continue }
  timeout { exit 16 }
  eof {}
}
set result [wait]
set rc [lindex \$result 3]
if {\$completed != 1} {
  exit 17
}
exit \$rc
EXPECT"
}

run_client_installer() {
    stage_release "$CLIENT_CONTAINER"
    docker_exec_as_tester "$CLIENT_CONTAINER" "cd /home/$TEST_USER/src/aplane && expect <<'EXPECT'
set timeout 120
set completed 0
spawn ./install.sh --client /home/$TEST_USER/aplane
expect {
  \"Add apenv.sh to *\" { send \"y\r\"; exp_continue }
  \"=== Installation complete ===\" { set completed 1; exp_continue }
  timeout { exit 16 }
  eof {}
}
set result [wait]
set rc [lindex \$result 3]
if {\$completed != 1} {
  exit 17
}
exit \$rc
EXPECT"

    # Client-only installs intentionally copy only apshell/aplocalnet. This
    # topology also needs apadmin on the client/admin node.
    docker_exec_as_tester "$CLIENT_CONTAINER" "cp /home/$TEST_USER/src/aplane/bin/apadmin /home/$TEST_USER/aplane/apclient/bin/apadmin && chmod 755 /home/$TEST_USER/aplane/apclient/bin/apadmin"
}

read_node_endpoint_field() {
    local container="$1"
    local field="$2"
    docker_exec_as_tester "$container" "awk '
        function indent_width(line) { match(line, /^[[:space:]]*/); return RLENGTH }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            indent = indent_width(\$0)
            if (indent == 0 && \$0 ~ /^endpoint[[:space:]]*:/) { in_endpoint=1; next }
            if (in_endpoint && indent == 0 && \$0 !~ /^endpoint[[:space:]]*:/) { in_endpoint=0 }
            if (in_endpoint && indent == 2 && \$0 ~ /^[[:space:]]*ssh[[:space:]]*:/) { in_ssh=1; next }
            if (in_ssh && indent <= 2 && \$0 !~ /^[[:space:]]*ssh[[:space:]]*:/) { in_ssh=0 }
            if (\"$field\" == \"signer_port\" && in_endpoint && indent == 2 && \$0 ~ /^[[:space:]]*signer_port[[:space:]]*:/) { print \$2; exit }
            if (\"$field\" == \"ssh_port\" && in_ssh && indent == 4 && \$0 ~ /^[[:space:]]*port[[:space:]]*:/) { print \$2; exit }
        }
    ' /home/$TEST_USER/aplane/apsigner/config.yaml"
}

configure_node_network() {
    local container="$1"
    local advertised_host="$2"
    local config_path="/home/$TEST_USER/aplane/apsigner/config.yaml"
    local ssh_port
    ssh_port="$(read_node_endpoint_field "$container" ssh_port)"
    [ -n "$ssh_port" ] || die "could not read SSH port for $container"

    docker_exec_as_tester "$container" "sed -i \
        -e 's/listen_address: 127\\.0\\.0\\.1/listen_address: 0.0.0.0/' \
        -e '/# advertise_url:/a\\  advertise_url: ssh://$advertised_host:$ssh_port' \
        '$config_path'"
}

wait_for_localnet() {
    local i
    for i in $(seq 1 120); do
        if docker_exec_as_tester "$CLIENT_CONTAINER" "curl -fsS -H 'X-Algo-API-Token: $ALGOD_TOKEN' '$ALGOD_URL/v2/status' >/tmp/algod-status.json"; then
            return 0
        fi
        sleep 1
    done
    docker logs --tail 160 "$ALGOD_CONTAINER" >&2 || true
    die "LocalNet algod did not become reachable from the client container within 120s"
}

discover_localnet() {
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        aplocalnet --check --algod-url '$ALGOD_URL' --algod-token '$ALGOD_TOKEN'")"; then
        die "aplocalnet could not read LocalNet metadata from $ALGOD_URL"
    fi
    printf '%s\n' "$out"
    LOCALNET_GENESIS_HASH="$(printf '%s\n' "$out" | awk -F': ' '/^Genesis hash:/ { print $2; exit }')"
    [ -n "$LOCALNET_GENESIS_HASH" ] || die "could not parse LocalNet genesis hash"
}

configure_node_localnet() {
    local container="$1"
    local config_path="/home/$TEST_USER/aplane/apsigner/config.yaml"
    [ -n "$LOCALNET_GENESIS_HASH" ] || die "LocalNet genesis hash is not set"

    docker_exec_as_tester "$container" "awk -v algod_url='$ALGOD_URL' -v hash='$LOCALNET_GENESIS_HASH' '
        /^  localnet:/ {
            in_localnet = 1
            added_hash = 0
            print
            next
        }
        in_localnet && /^  [a-z0-9_-]+:/ {
            if (!added_hash) {
                print \"    genesis_hash: \\\"\" hash \"\\\"\"
                added_hash = 1
            }
            in_localnet = 0
        }
        in_localnet && /^[[:space:]]*server: / {
            print \"      server: \" algod_url
            next
        }
        in_localnet && /^[[:space:]]*token: / {
            print
            if (!added_hash) {
                print \"    genesis_hash: \\\"\" hash \"\\\"\"
                added_hash = 1
            }
            next
        }
        in_localnet && /^[[:space:]]*genesis_hash: / {
            next
        }
        /^teal_compile_network:/ {
            print \"teal_compile_network: localnet\"
            next
        }
        { print }
        END {
            if (in_localnet && !added_hash) {
                print \"    genesis_hash: \\\"\" hash \"\\\"\"
            }
        }
    ' '$config_path' > '$config_path.tmp' && mv '$config_path.tmp' '$config_path'"
}

configure_client_localnet() {
    local config_path="/home/$TEST_USER/aplane/apclient/config.yaml"
    local env_path="/home/$TEST_USER/aplane/apclient/apenv.sh"
    docker_exec_as_tester "$CLIENT_CONTAINER" "sed -i \
        -e 's/^network:.*/network: localnet/' \
        -e 's|server: http://localhost:4001|server: $ALGOD_URL|' \
        '$config_path' && \
        grep -qx '  - localnet' '$config_path' || sed -i '/^  - testnet$/a\\  - localnet' '$config_path'"

    docker_exec_as_tester "$CLIENT_CONTAINER" "cat > /home/$TEST_USER/aplane/apclient/plugins.yaml <<YAML
enabled_plugins:
  - algokit-localnet
YAML
        grep -q '^export APLANE_LOCALNET_ALGOD_URL=' '$env_path' || \
            printf \"\\nexport APLANE_LOCALNET_ALGOD_URL='%s'\\nexport APLANE_LOCALNET_KMD_URL='%s'\\nexport APLANE_LOCALNET_TOKEN='%s'\\n\" \
                '$ALGOD_URL' '$KMD_URL' '$ALGOD_TOKEN' >> '$env_path'"
}

verify_localnet_reachable_from_nodes() {
    local container
    for container in "$SIGNER_CONTAINER" "$SENTRY_CONTAINER" "$CLIENT_CONTAINER"; do
        docker_exec_as_tester "$container" "curl -fsS -H 'X-Algo-API-Token: $ALGOD_TOKEN' '$ALGOD_URL/v2/status' >/tmp/algod-status.json"
    done
}

configure_client_endpoints() {
    local signer_ssh_port signer_port sentry_ssh_port sentry_port
    signer_ssh_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" ssh_port)"
    signer_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" signer_port)"
    sentry_ssh_port="$(read_node_endpoint_field "$SENTRY_CONTAINER" ssh_port)"
    sentry_port="$(read_node_endpoint_field "$SENTRY_CONTAINER" signer_port)"
    [ -n "$signer_ssh_port" ] && [ -n "$signer_port" ] || die "could not read signer endpoint ports"
    [ -n "$sentry_ssh_port" ] && [ -n "$sentry_port" ] || die "could not read sentry endpoint ports"

    docker_exec_as_tester "$CLIENT_CONTAINER" "mkdir -p /home/$TEST_USER/aplane/apclient/tokens && cat > /home/$TEST_USER/aplane/apclient/endpoints.yaml <<YAML
schema_version: 1
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer:$signer_ssh_port
    signer_port: $signer_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
  local-sentry:
    role: sentry
    url: ssh://sentry:$sentry_ssh_port
    signer_port: $sentry_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: tokens/local-sentry.token
YAML"
}

verify_layout() {
    docker_exec_as_tester "$SIGNER_CONTAINER" "test -x /home/$TEST_USER/aplane/apsigner/bin/apsigner && test -f /home/$TEST_USER/aplane/apsigner/config.yaml"
    docker_exec_as_tester "$SENTRY_CONTAINER" "test -x /home/$TEST_USER/aplane/apsigner/bin/apsigner && test -f /home/$TEST_USER/aplane/apsigner/config.yaml"
    docker_exec_as_tester "$CLIENT_CONTAINER" "test -x /home/$TEST_USER/aplane/apclient/bin/apshell && test -x /home/$TEST_USER/aplane/apclient/bin/apadmin && test -f /home/$TEST_USER/aplane/apclient/endpoints.yaml"
}

generate_client_ssh_key() {
    local client_dir="/home/$TEST_USER/aplane/apclient"
    docker_exec_as_tester "$CLIENT_CONTAINER" "mkdir -p $client_dir/.ssh && chmod 700 $client_dir/.ssh && \
        if [ ! -f $client_dir/.ssh/id_ed25519 ]; then \
            ssh-keygen -t ed25519 -f $client_dir/.ssh/id_ed25519 -N '' -q; \
        fi"
}

start_node() {
    local container="$1"
    local log_path="$2"
    docker exec -d --user "$TEST_USER" "$container" bash -lc \
        ". /home/$TEST_USER/aplane/apenv.sh && exec apsigner > $log_path 2>&1"

    local i
    for i in $(seq 1 30); do
        if docker_exec_as_tester "$container" "grep -q 'SSH server listening' $log_path 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "$container" "cat $log_path" >&2 || true
    die "$container apsigner did not become ready within 30s"
}

populate_known_hosts_for() {
    local source_container="$1"
    local host_alias="$2"
    local ssh_port="$3"
    local pub
    pub="$(docker_exec_as_tester "$source_container" "ssh-keygen -y -f /home/$TEST_USER/aplane/apsigner/.ssh/ssh_host_key")"
    docker_exec_as_tester "$CLIENT_CONTAINER" "mkdir -p /home/$TEST_USER/aplane/apclient/.ssh && chmod 700 /home/$TEST_USER/aplane/apclient/.ssh && \
        printf '[%s]:%s %s\n' '$host_alias' '$ssh_port' '$pub' >> /home/$TEST_USER/aplane/apclient/.ssh/known_hosts && \
        chmod 600 /home/$TEST_USER/aplane/apclient/.ssh/known_hosts"
}

populate_known_hosts() {
    local signer_ssh_port sentry_ssh_port
    signer_ssh_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" ssh_port)"
    sentry_ssh_port="$(read_node_endpoint_field "$SENTRY_CONTAINER" ssh_port)"
    docker_exec_as_tester "$CLIENT_CONTAINER" "rm -f /home/$TEST_USER/aplane/apclient/.ssh/known_hosts"
    populate_known_hosts_for "$SIGNER_CONTAINER" signer "$signer_ssh_port"
    populate_known_hosts_for "$SENTRY_CONTAINER" sentry "$sentry_ssh_port"
}

start_signer_apapprover() {
    local exp_file
    exp_file="$(mktemp)"
    cat > "$exp_file" <<EXPECT_SCRIPT
#!/usr/bin/env expect -f
set timeout 30
spawn apapprover
expect {
  "Enter passphrase:" { send "$TEST_PASSPHRASE\r" }
  timeout { exit 1 }
}
expect {
  "authenticated and signer unlocked" { }
  timeout { exit 2 }
}
set timeout -1
while {1} {
    expect {
        -re {Approve current request\?.*} { send "y\r" }
        eof { exit 0 }
    }
}
EXPECT_SCRIPT
    docker cp "$exp_file" "$SIGNER_CONTAINER:/tmp/apapprover.exp"
    rm -f "$exp_file"
    docker_exec "$SIGNER_CONTAINER" chmod 755 /tmp/apapprover.exp
    docker_exec "$SIGNER_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/apapprover.exp

    docker exec -d --user "$TEST_USER" "$SIGNER_CONTAINER" bash -lc \
        ". /home/$TEST_USER/aplane/apenv.sh && exec expect /tmp/apapprover.exp > /tmp/apapprover.log 2>&1"

    local i
    for i in $(seq 1 20); do
        if docker_exec_as_tester "$SIGNER_CONTAINER" "grep -q 'authenticated and signer unlocked' /tmp/apapprover.log 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "$SIGNER_CONTAINER" "cat /tmp/apapprover.log" >&2 || true
    die "signer apapprover did not authenticate within 20s"
}

run_request_token() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "echo 'request-token' > /tmp/req-token.script"
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/req-token.script 2>&1 | tee /tmp/req-token.log"
    docker_exec_as_tester "$CLIENT_CONTAINER" "test -s /home/$TEST_USER/aplane/apclient/aplane.token" \
        || die "request-token did not produce a client token file"
}

generate_falcon_key() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\ngenerate falcon1024.v1\n' > /tmp/generate-falcon.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-falcon.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate Falcon key through client/signer flow"
    fi
    printf '%s\n' "$out"
    FALCON_ADDRESS="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$FALCON_ADDRESS" ] || die "could not parse generated Falcon address"
}

fund_falcon_key_from_localnet() {
    [ -n "$FALCON_ADDRESS" ] || die "Falcon address is not set"

    local funding_address
    funding_address="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal account list -d /algod/data | awk 'NR == 1 { print \$2; exit }'")"
    [ -n "$funding_address" ] || die "could not find a LocalNet funding account"

    local out
    if ! out="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal clerk send \
        -d /algod/data \
        -w unencrypted-default-wallet \
        -f '$funding_address' \
        -t '$FALCON_ADDRESS' \
        -a '$FALCON_FUND_AMOUNT' \
        --note 'aplane docker smoke falcon funding' 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to fund generated Falcon account from LocalNet wallet"
    fi
    printf '%s\n' "$out"
}

verify_falcon_funded() {
    [ -n "$FALCON_ADDRESS" ] || die "Falcon address is not set"

    local balance i
    for i in $(seq 1 20); do
        balance="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal account balance -a '$FALCON_ADDRESS' -d /algod/data 2>/dev/null | awk '{ print \$1; exit }'")"
        if [ -n "$balance" ] && [ "$balance" -ge "$FALCON_FUND_AMOUNT" ]; then
            printf 'Falcon account %s balance: %s microAlgos\n' "$FALCON_ADDRESS" "$balance"
            return 0
        fi
        sleep 1
    done

    die "generated Falcon account was not funded; last balance: ${balance:-unavailable}"
}

verify_signer_reachable() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "echo 'status' > /tmp/status.script"
    local out
    out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/status.script 2>&1")"
    printf '%s\n' "$out"
    printf '%s' "$out" | grep -qE 'Signer:[[:space:]]*Connected' \
        || die "apshell status did not report Signer: Connected"
}

verify_client_admin_node() {
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && apadmin --version"
}

shutdown_nodes() {
    docker_exec_as_tester "$SIGNER_CONTAINER" "pkill expect || true; pkill apapprover || true; pkill apsigner || true"
    docker_exec_as_tester "$SENTRY_CONTAINER" "pkill apsigner || true"
    sleep 1
}

main() {
    parse_args "$@"
    command -v docker >/dev/null 2>&1 || die "docker not found"
    trap cleanup EXIT

    log "Building local release tarball"
    build_or_resolve_tarball

    log "Building Ubuntu test image"
    build_image

    log "Starting four-container Docker network"
    start_containers

    log "Creating test users"
    create_test_user "$SIGNER_CONTAINER"
    create_test_user "$SENTRY_CONTAINER"
    create_test_user "$CLIENT_CONTAINER"

    log "Installing signer node"
    run_node_installer "$SIGNER_CONTAINER" signer

    log "Installing sentry node"
    run_node_installer "$SENTRY_CONTAINER" sentry

    log "Installing client/admin node"
    run_client_installer

    log "Waiting for shared LocalNet algod"
    wait_for_localnet

    log "Discovering LocalNet metadata"
    discover_localnet

    log "Configuring signer and sentry network listeners"
    configure_node_network "$SIGNER_CONTAINER" signer
    configure_node_network "$SENTRY_CONTAINER" sentry

    log "Configuring signer, sentry, and client for shared LocalNet"
    configure_node_localnet "$SIGNER_CONTAINER"
    configure_node_localnet "$SENTRY_CONTAINER"
    configure_client_localnet

    log "Verifying shared LocalNet reachability from APlane nodes"
    verify_localnet_reachable_from_nodes

    log "Configuring client endpoint registry"
    configure_client_endpoints

    log "Verifying installed layouts"
    verify_layout

    log "Generating client SSH key"
    generate_client_ssh_key

    log "Starting signer and sentry apsigner processes"
    start_node "$SIGNER_CONTAINER" /tmp/apsigner.log
    start_node "$SENTRY_CONTAINER" /tmp/apsentry.log

    log "Seeding client known_hosts for signer and sentry"
    populate_known_hosts

    log "Starting signer-side approver for token bootstrap"
    start_signer_apapprover

    log "Requesting signer API token from client container"
    run_request_token

    log "Generating Falcon key through client/signer flow"
    generate_falcon_key

    log "Funding generated Falcon key from shared LocalNet"
    fund_falcon_key_from_localnet
    verify_falcon_funded

    log "Verifying client can reach signer with issued token"
    verify_signer_reachable

    log "Verifying apadmin is present on client/admin node"
    verify_client_admin_node

    log "Shutting down nodes"
    shutdown_nodes

    log "Docker local four-container smoke test passed"
}

main "$@"
