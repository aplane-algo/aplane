#!/usr/bin/env bash
# Smoke-test an APlane Docker topology against LocalNet:
#   1. signer apsigner node
#   2. cosigner apsigner node
#   3. client/admin node with apshell and apadmin
#   4. AlgoKit-style LocalNet algod/KMD node
#
# The test keeps the existing docker-local behavior surface focused on install,
# SSH client enrollment, client reachability, shared LocalNet wiring, cosigner
# endpoint enrollment, local IPC cosigner-reference import, the cosigned flow,
# and corridor allowlist enforcement. A plain host (aplane.falcon1024.v1 with a
# cosigner) signs a 0 ALGO self-send through apshell and through the Python,
# TypeScript and Go SDKs, each with its real cosigner node, and then closes out.
# A bounded aplane.falcon1024.v1 account with the Corridor preset's rules, created
# from a boundary file with no key type setup, carries the cosigned checks. It can
# be rekeyed only to its listed address, with the spending key alone, so once its
# cosigner is gone it can't spend but its listed key still takes it over. A plus
# cosigned account's other rekeys go to the real cosigner node, whose policy
# refuses them until it allows the rekey edge.
# Local mode uses the local aplanesdk checkout for all three SDKs: Python
# installed from source, TypeScript built and packed on the host, and a Go
# program built statically on the host. Release mode uses PyPI, npm and the
# published Go module.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH=""
DIST_DIR=""
VERSION="docker-smoke"
TARBALL=""
SKIP_BUILD=0
RELEASE_INSTALL=0
APLANE_RELEASE_VERSION="${APLANE_RELEASE_VERSION:-latest}"
SDK_VERSION="${APLANE_SDK_VERSION:-}"
KEEP_CONTAINER=0
IMAGE_NAME=""
RUN_ID="$$"
NETWORK_NAME="aplane-local-smoke-net-$RUN_ID"
ALGOD_CONTAINER="aplane-local-algod-$RUN_ID"
SIGNER_CONTAINER="aplane-local-signer-$RUN_ID"
COSIGNER_CONTAINER="aplane-local-cosigner-$RUN_ID"
CLIENT_CONTAINER="aplane-local-client-$RUN_ID"
TEST_USER="tester"
TEST_PASSPHRASE="passphrase-for-docker-smoke"
ALGOD_IMAGE="algorand/algod:latest"
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ALGOD_URL="http://algod:8080"
KMD_URL="http://algod:7833"
ACCOUNT_FUND_AMOUNT=100000000
ALGOD_CONFIG_DIR=""
RELEASE_CACHE_DIR=""
LOCALNET_GENESIS_HASH=""
NETWORK_TOKEN="localnet"
FALCON_ADDRESS=""
ED25519_ADDRESS=""
PLUS_COSIGNED_ADDRESS=""
COSIGNER_COMPONENT_KEY=""
COSIGNER_REFERENCE_NAME="docker-cosigner"
PLAIN_HOST_ADDRESS=""
CLOSE_DESTINATION_ADDRESS=""
CORRIDOR_ADDRESS=""
GENERAL_BOUNDED_ADDRESS=""
CORRIDOR_ALLOWED_ADDRESS=""
CORRIDOR_BLOCKED_ADDRESS=""
SDK_REPO="${APLANE_SDKS_REPO:-${APLANE_SDK_REPO:-}}"
SDK_SOURCE_DIR=""
SDK_CONTAINER_DIR="/home/$TEST_USER/src/aplanesdk-python"
SDK_VENV="/home/$TEST_USER/aplane/apclient/python-sdk-venv"
TS_SDK_DIR="/home/$TEST_USER/aplane/apclient/typescript-sdk"
GO_SDK_BIN=""
GO_SDK_CONTAINER_BIN="/home/$TEST_USER/aplane/apclient/go-sdk-validate"

usage() {
    cat <<'EOF'
Usage: scripts/docker-local-four-node-smoke.sh [options]

Options:
  --tarball <path>      Use an existing aplane_<version>_linux_<arch>.tar.gz
  --version <version>   Archive label for locally built tarball (default: docker-smoke)
  --arch <amd64|arm64>  Architecture to package/test (default: host arch)
  --skip-build          Reuse existing bin/<arch> binaries when building the tarball
  --release-install     Install APlane from GitHub release assets instead of a local tarball
  --aplane-version <v>  APlane release tag/version for --release-install (default: latest)
  --sdk-version <v>     Install SDK packages at this version from PyPI/npm (default: latest)
  --sdk-repo <path>     Path to aplanesdk repo or its python/ dir
                        (default: APLANE_SDKS_REPO, APLANE_SDK_REPO, ../aplanesdk, ~/aplanesdk)
  --keep-container      Leave containers and network running for debugging
  -h, --help            Show this help

This test requires Docker privileges. LocalNet starts signer, cosigner,
client/admin, and an AlgoKit-style algod/KMD node.
The client runs a client-only install plus apadmin, points endpoints.yaml at the
signer container DNS name, adds the cosigner endpoint through apshell, enrolls
the client key at both nodes, generates a cosigner key through the cosigner endpoint,
then exports and imports the public cosigner reference with local IPC apadmin,
uses the default-enabled plain host (aplane.falcon1024.v1), and verifies apshell can create,
fund, and validate a cosigned plain host, Corridor, and native Falcon accounts
against the selected network. The plain host signs the same 0 ALGO self-send
through the Python, TypeScript and Go SDKs' prepared cosigned flow, then closes
out through apshell. It also sends an allowlisted Corridor payment through the
SDK's bounded-base component, cosigner component, and shared assembly choreography,
and proves a non-allowlisted recipient is rejected. The Corridor flow also
proves that cosigner loss blocks spend while the account's listed key can still
take it over, and a plus cosigned account's unlisted rekey waits on the cosigner
node's rekey policy. By default every SDK comes from the local aplanesdk repo
(the host needs go and npm); with --release-install, Python comes from PyPI,
TypeScript from npm and Go from the published module.
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

smoke_release_version() {
    local version
    version="$(sed -n 's/^MIN_SUPPORTED_UPGRADE_VERSION="\([^"]*\)"/\1/p' "$ROOT_DIR/install.sh" | head -n 1)"
    [ -n "$version" ] || die "could not determine minimum supported upgrade version from install.sh"
    printf '%s-docker-smoke\n' "$version"
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
                VERSION="$2"
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
            --release-install)
                RELEASE_INSTALL=1
                shift
                ;;
            --aplane-version)
                [ $# -ge 2 ] || die "--aplane-version requires a value"
                APLANE_RELEASE_VERSION="$2"
                shift 2
                ;;
            --sdk-version)
                [ $# -ge 2 ] || die "--sdk-version requires a value"
                SDK_VERSION="$2"
                shift 2
                ;;
            --sdk-repo)
                [ $# -ge 2 ] || die "--sdk-repo requires a value"
                SDK_REPO="$2"
                shift 2
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

select_network_profile() {
    NETWORK_TOKEN="localnet"
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
    if [ -n "$RELEASE_CACHE_DIR" ]; then
        rm -rf "$RELEASE_CACHE_DIR"
    fi
    if [ "$KEEP_CONTAINER" = "1" ]; then
        printf '\nKept containers for debugging:\n'
        printf '  %s\n' "$ALGOD_CONTAINER"
        printf '  %s\n' "$SIGNER_CONTAINER" "$COSIGNER_CONTAINER" "$CLIENT_CONTAINER"
        printf 'Kept Docker network: %s\n' "$NETWORK_NAME"
        if [ -n "$ALGOD_CONFIG_DIR" ]; then
            printf 'Kept LocalNet config dir: %s\n' "$ALGOD_CONFIG_DIR"
        fi
        return
    fi
    docker rm -f "$ALGOD_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$SIGNER_CONTAINER" "$COSIGNER_CONTAINER" "$CLIENT_CONTAINER" >/dev/null 2>&1 || true
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
      bash ca-certificates curl expect gzip nodejs npm openssh-client passwd procps python3 python3-pip python3-venv sudo tar && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
DOCKERFILE
    docker build -t "$IMAGE_NAME" -f "$dockerfile" "$ROOT_DIR"
    rm -f "$dockerfile"
}

resolve_built_tarball() {
    local matches=("$DIST_DIR"/aplane_*_linux_"$ARCH".tar.gz)
    if [ "${#matches[@]}" -ne 1 ] || [ ! -f "${matches[0]}" ]; then
        die "expected exactly one linux/$ARCH tarball in $DIST_DIR"
    fi
    TARBALL="${matches[0]}"
}

resolve_sdk_repo() {
    local candidate=""
    if [ -n "$SDK_REPO" ]; then
        candidate="$SDK_REPO"
    elif [ -d "$ROOT_DIR/../aplanesdk/python" ]; then
        candidate="$ROOT_DIR/../aplanesdk"
    elif [ -d "$HOME/aplanesdk/python" ]; then
        candidate="$HOME/aplanesdk"
    fi

    [ -n "$candidate" ] || die "could not find aplanesdk; set APLANE_SDKS_REPO or pass --sdk-repo"
    candidate="${candidate/#\~/$HOME}"
    [ -d "$candidate" ] || die "aplanesdk path not found: $candidate"
    candidate="$(cd "$candidate" && pwd)"

    if [ -f "$candidate/pyproject.toml" ] && [ -d "$candidate/aplanesdk" ]; then
        SDK_SOURCE_DIR="$candidate"
        SDK_REPO="$(cd "$candidate/.." && pwd)"
        return
    fi
    if [ -f "$candidate/python/pyproject.toml" ] && [ -d "$candidate/python/aplanesdk" ]; then
        SDK_REPO="$candidate"
        SDK_SOURCE_DIR="$candidate/python"
        return
    fi

    die "aplanesdk Python source not found at $candidate; expected python/pyproject.toml"
}

build_or_resolve_tarball() {
    if [ "$RELEASE_INSTALL" = "1" ]; then
        if [ -n "$TARBALL" ]; then
            die "--tarball cannot be used with --release-install"
        fi
        if [ "$SKIP_BUILD" = "1" ]; then
            die "--skip-build cannot be used with --release-install"
        fi
        if [ -z "$ARCH" ]; then
            ARCH="$(detect_arch)"
        fi
        return
    fi

    if [ -n "$TARBALL" ]; then
        TARBALL="$(cd "$(dirname "$TARBALL")" && pwd)/$(basename "$TARBALL")"
        [ -f "$TARBALL" ] || die "tarball not found: $TARBALL"
        return
    fi

    if [ -z "$ARCH" ]; then
        ARCH="$(detect_arch)"
    fi
    DIST_DIR="$(mktemp -d)"
    local args=(
        --version "$VERSION"
        --release-version "$(smoke_release_version)"
        --arch "$ARCH"
        --dist-dir "$DIST_DIR"
    )
    if [ "$SKIP_BUILD" = "1" ]; then
        args+=(--skip-build)
    fi
    "$ROOT_DIR/scripts/package-bootstrap-release.sh" "${args[@]}"
    resolve_built_tarball
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
    docker run --name "$COSIGNER_CONTAINER" --network "$NETWORK_NAME" --network-alias cosigner -d "$IMAGE_NAME" >/dev/null
    docker run --name "$CLIENT_CONTAINER" --network "$NETWORK_NAME" --network-alias client -d "$IMAGE_NAME" >/dev/null
}

create_test_user() {
    local container="$1"
    docker_exec "$container" useradd -m -s /bin/bash "$TEST_USER"
    docker_exec_as_tester "$container" "touch /home/$TEST_USER/.bashrc"
}

stage_release() {
    local container="$1"
    if [ "$RELEASE_INSTALL" = "1" ]; then
        [ -n "$ARCH" ] || die "release architecture is not set"
        # Download the release once; later nodes reuse the first node's copy
        # instead of each fetching the full archive from GitHub.
        if [ -z "$RELEASE_CACHE_DIR" ]; then
            docker_exec_as_tester "$container" "set -e
                tag='$APLANE_RELEASE_VERSION'
                if [ \"\$tag\" = latest ]; then
                    tag=\$(curl -fsSL -H 'Accept: application/vnd.github+json' https://api.github.com/repos/aplane-algo/aplane/releases/latest | sed -n 's/.*\"tag_name\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' | head -n 1)
                    [ -n \"\$tag\" ] || { echo 'failed to resolve latest APlane release tag' >&2; exit 1; }
                fi
                case \"\$tag\" in v*) ;; *) tag=\"v\$tag\" ;; esac
                version=\"\${tag#v}\"
                base_url=\"https://github.com/aplane-algo/aplane/releases/download/\$tag\"
                archive=\"aplane_\${version}_linux_$ARCH.tar.gz\"
                mkdir -p /tmp/aplane-release
                echo \"Downloading APlane release archive \$archive from \$base_url/\$archive\"
                curl -fsSL \"\$base_url/\$archive\" -o /tmp/aplane-release/aplane.tar.gz
                echo \"Downloading APlane release checksums from \$base_url/checksums.txt\"
                curl -fsSL \"\$base_url/checksums.txt\" -o /tmp/aplane-release/checksums.txt
                printf '%s\\n' \"\$archive\" > /tmp/aplane-release/archive-name"
            RELEASE_CACHE_DIR="$(mktemp -d)"
            docker cp "$container:/tmp/aplane-release/." "$RELEASE_CACHE_DIR/"
        else
            log "Reusing downloaded APlane release archive for $container"
            docker_exec "$container" mkdir -p /tmp/aplane-release
            docker cp "$RELEASE_CACHE_DIR/." "$container:/tmp/aplane-release/"
            docker_exec "$container" chown -R "$TEST_USER:$TEST_USER" /tmp/aplane-release
        fi
        # Every node verifies the archive it extracts, including reused copies.
        docker_exec_as_tester "$container" "set -e
            archive=\$(cat /tmp/aplane-release/archive-name)
            expected=\$(awk -v f=\"\$archive\" '\$2 == f { print \$1; exit }' /tmp/aplane-release/checksums.txt)
            [ -n \"\$expected\" ] || { echo \"missing checksum for \$archive\" >&2; exit 1; }
            actual=\$(sha256sum /tmp/aplane-release/aplane.tar.gz | awk '{ print \$1 }')
            [ \"\$expected\" = \"\$actual\" ] || { echo \"checksum mismatch for \$archive\" >&2; exit 1; }
            echo \"Verified checksum for \$archive\"
            mkdir -p /home/$TEST_USER/src
            tar -xzf /tmp/aplane-release/aplane.tar.gz -C /home/$TEST_USER/src"
        return
    fi

    docker cp "$TARBALL" "$container:/tmp/aplane.tar.gz"
    docker_exec "$container" chmod 644 /tmp/aplane.tar.gz
    docker_exec_as_tester "$container" "mkdir -p /home/$TEST_USER/src && tar -xzf /tmp/aplane.tar.gz -C /home/$TEST_USER/src"
}

run_node_installer() {
    local container="$1"
    local role="$2"
    local advertised_host="${3:-}"

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
  \"Client-reachable cosigner address*\" { send \"$advertised_host\r\"; exp_continue }
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
        -e 's/listen_address: \"\\?127\\.0\\.0\\.1\"\\?/listen_address: 0.0.0.0/' \
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

configure_cosigner_policy() {
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"
    [ -n "$CLOSE_DESTINATION_ADDRESS" ] || die "close destination is not set"
    # A cosigner key without a document of its own follows the node default,
    # which rejects every request. Give the key its own document online once
    # it exists, exercising the apadmin policy verbs an operator uses along
    # the way.
    local script_file
    script_file="$(mktemp)"
    cat > "$script_file" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

key="$1"
data="$2"
close_to="$3"
policy="$(mktemp -d)/$key.json"

fail() {
    printf 'cosigner policy smoke: %s\n' "$*" >&2
    exit 1
}

admin() {
    apadmin -d "$data" "$@"
}

# Capture output before matching it: a matcher that exits early would break
# the pipe and fail the command under pipefail.
expect() {
    local pattern="$1" what="$2" out
    shift 2
    out="$("$@")" || fail "$what: command failed"
    grep -Eq -- "$pattern" <<<"$out" || fail "$what: output did not match '$pattern': $out"
}

cat > "$policy" <<JSON
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "$key",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": true,
  "max_fee_microalgos": "0",
  "transaction_types": {"*": "reject", "pay": "allow", "axfer": "allow"},
  "transfer_policy": {
    "routes": [
      {"id": "docker_smoke_allow_all", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]},
      {"id": "docker_smoke_close", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["$close_to"], "allow_close": true}
    ]
  }
}
JSON

expect "^  $key +default" "status of a new key" admin policy status
expect '^policy OK$' "check" admin policy check "$policy"
expect 'the key gets a policy of its own' "diff of a first policy" admin policy diff "$policy"

# Without --yes and without a terminal, apply refuses and writes nothing.
if admin policy apply "$policy" </dev/null >/dev/null 2>&1; then
    fail "apply without --yes succeeded without a terminal"
fi
expect "^  $key +default" "status after a refused apply" admin policy status

expect '^policy applied as generation ' "apply from a file" admin policy apply --yes "$policy"
expect "^  $key +own policy" "status after apply" admin policy status
admin policy export --key "$key" | cmp -s - "$policy" || fail "export is not the applied file"
expect '"key": "default"' "export without --key prints the node default" admin policy export
expect '^policy unchanged$' "re-applying the active policy" admin policy apply --yes "$policy"

# Removing the document returns the key to the deny-all default; the stdin
# form of apply restores it for the cosigned transactions that follow.
expect '^policy applied as generation ' "remove" admin policy remove --yes "$key"
expect "^  $key +default" "status after remove" admin policy status
out="$(admin policy apply --yes - < "$policy")" || fail "apply from stdin: command failed"
grep -q '^policy applied as generation ' <<<"$out" || fail "apply from stdin: $out"
expect "^  $key +own policy" "status after stdin apply" admin policy status
admin policy export --key "$key" | cmp -s - "$policy" || fail "export after stdin apply is not the applied document"
SCRIPT
    docker cp "$script_file" "$COSIGNER_CONTAINER:/tmp/cosigner-policy-smoke.sh"
    rm -f "$script_file"
    docker_exec "$COSIGNER_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/cosigner-policy-smoke.sh
    docker_exec_as_tester "$COSIGNER_CONTAINER" ". /home/$TEST_USER/aplane/apenv.sh && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' \
        bash /tmp/cosigner-policy-smoke.sh '$COSIGNER_COMPONENT_KEY' /home/$TEST_USER/aplane/apsigner '$CLOSE_DESTINATION_ADDRESS'" \
        || die "cosigner policy CLI checks failed"
}

configure_signer_policy() {
    # A new signer store's default routes self-transfers only and leaves
    # every other route miss to the operator default, which would prompt for
    # the Corridor payments below to other LocalNet accounts. Replace the
    # default with one that routes everything; the allowlist checks that
    # follow belong to the Corridor itself.
    local policy_file out
    policy_file="$(mktemp)"
    cat > "$policy_file" <<'JSON'
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "rekeys": "reject_foreign_rekey",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": false,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": {"*": "allow"},
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "routes": [
      {"id": "docker_smoke_allow_all", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]},
      {"id": "docker_smoke_close", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["__CLOSE_TO__"], "allow_close": true}
    ]
  }
}
JSON
    # A close route must name its destinations: the smoke's closes go to one
    # LocalNet account.
    [ -n "$CLOSE_DESTINATION_ADDRESS" ] || die "close destination is not set"
    sed -i "s/__CLOSE_TO__/$CLOSE_DESTINATION_ADDRESS/" "$policy_file"
    docker cp "$policy_file" "$SIGNER_CONTAINER:/tmp/signer-policy.json"
    rm -f "$policy_file"
    docker_exec "$SIGNER_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/signer-policy.json
    if ! out="$(docker_exec_as_tester "$SIGNER_CONTAINER" ". /home/$TEST_USER/aplane/apenv.sh && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' \
        apadmin -d /home/$TEST_USER/aplane/apsigner policy apply --yes /tmp/signer-policy.json 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "signer policy apply failed"
    fi
    printf '%s\n' "$out"
    grep -q '^policy applied as generation ' <<<"$out" \
        || die "signer policy apply did not report a new generation"
}

verify_localnet_reachable_from_nodes() {
    local container
    for container in "$SIGNER_CONTAINER" "$COSIGNER_CONTAINER" "$CLIENT_CONTAINER"; do
        docker_exec_as_tester "$container" "curl -fsS -H 'X-Algo-API-Token: $ALGOD_TOKEN' '$ALGOD_URL/v2/status' >/tmp/algod-status.json"
    done
}

prepare_selected_network() {
    wait_for_localnet
    discover_localnet
}

configure_selected_network() {
    configure_node_localnet "$SIGNER_CONTAINER"
    configure_node_localnet "$COSIGNER_CONTAINER"
    configure_client_localnet
}

verify_selected_network_reachable() {
    verify_localnet_reachable_from_nodes
}

configure_client_endpoints() {
    local signer_ssh_port
    signer_ssh_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" ssh_port)"
    [ -n "$signer_ssh_port" ] || die "could not read signer SSH port"

    docker_exec_as_tester "$CLIENT_CONTAINER" "cat > /home/$TEST_USER/aplane/apclient/endpoints.yaml <<YAML
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer:$signer_ssh_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
YAML"
}

create_client_cosigner_endpoint() {
    local cosigner_ssh_port out
    cosigner_ssh_port="$(read_node_endpoint_field "$COSIGNER_CONTAINER" ssh_port)"
    [ -n "$cosigner_ssh_port" ] || die "could not read cosigner SSH port"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'endpoints create --alias local-cosigner --endpoint ssh://cosigner:%s\nendpoints show local-cosigner\n' '$cosigner_ssh_port' > /tmp/create-cosigner-endpoint.script"
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/create-cosigner-endpoint.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to add cosigner endpoint through apshell"
    fi
    printf '%s\n' "$out"
    grep -Fq 'Configured cosigner endpoint local-cosigner' <<<"$out" \
        || die "cosigner endpoint creation output did not include success marker"
}

verify_layout() {
    docker_exec_as_tester "$SIGNER_CONTAINER" "test -x /home/$TEST_USER/aplane/apsigner/bin/apsigner && test -f /home/$TEST_USER/aplane/apsigner/config.yaml"
    docker_exec_as_tester "$COSIGNER_CONTAINER" "test -x /home/$TEST_USER/aplane/apsigner/bin/apsigner && test -f /home/$TEST_USER/aplane/apsigner/config.yaml"
    docker_exec_as_tester "$CLIENT_CONTAINER" "test -x /home/$TEST_USER/aplane/apclient/bin/apshell && test -x /home/$TEST_USER/aplane/apclient/bin/apadmin && test -f /home/$TEST_USER/aplane/apclient/endpoints.yaml"
    verify_appolicy "$SIGNER_CONTAINER" signer
    verify_appolicy "$COSIGNER_CONTAINER" cosigner
    docker_exec_as_tester "$CLIENT_CONTAINER" "test ! -e /home/$TEST_USER/aplane/apclient/bin/appolicy" \
        || die "client install contains appolicy; it ships with the signer tools only"
}

# appolicy_check_script prints a script that runs the installed appolicy in a
# scratch workspace, away from any store: the shipped default for role must
# pass check and explain, and a copy with one wrong-typed field must fail
# check with exit 1.
appolicy_check_script() {
    local bin="$1"
    local role="$2"
    cat <<EOF
set -euo pipefail
ws="\$(mktemp -d)"
trap 'rm -rf "\$ws"' EXIT
mkdir "\$ws/good" "\$ws/bad"
$bin/apadmin policy template --embedded $role > "\$ws/good/default.json"
$bin/appolicy check "\$ws/good"
$bin/appolicy explain "\$ws/good/default.json" | grep -q 'default document'
sed 's/"reject_close_remainder": false/"reject_close_remainder": "no"/' "\$ws/good/default.json" > "\$ws/bad/default.json"
grep -q '"reject_close_remainder": "no"' "\$ws/bad/default.json"
rc=0
$bin/appolicy check "\$ws/bad" >/dev/null || rc=\$?
[ "\$rc" -eq 1 ] || { echo "appolicy check on a broken document exited \$rc, want 1" >&2; exit 1; }
EOF
}

# verify_appolicy checks that a node install carries a working appolicy
# beside the signer tools.
verify_appolicy() {
    local container="$1"
    local role="$2"
    local bin="/home/$TEST_USER/aplane/apsigner/bin"
    docker_exec_as_tester "$container" "test -x $bin/appolicy" \
        || die "appolicy missing from the $role install on $container"
    docker_exec_as_tester "$container" "$(appolicy_check_script "$bin" "$role")" \
        || die "installed appolicy failed its $role check on $container"
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
    local signer_ssh_port cosigner_ssh_port
    signer_ssh_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" ssh_port)"
    cosigner_ssh_port="$(read_node_endpoint_field "$COSIGNER_CONTAINER" ssh_port)"
    docker_exec_as_tester "$CLIENT_CONTAINER" "rm -f /home/$TEST_USER/aplane/apclient/.ssh/known_hosts"
    populate_known_hosts_for "$SIGNER_CONTAINER" signer "$signer_ssh_port"
    populate_known_hosts_for "$COSIGNER_CONTAINER" cosigner "$cosigner_ssh_port"
}

start_apapprover() {
    local container="$1"
    local log_path="$2"
    local label="$3"
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
        -re {Approve current request\? \[y ([0-9]+) } { send "y \$expect_out(1,string)\r" }
        eof { exit 0 }
    }
}
EXPECT_SCRIPT
    docker cp "$exp_file" "$container:/tmp/apapprover.exp"
    rm -f "$exp_file"
    docker_exec "$container" chmod 755 /tmp/apapprover.exp
    docker_exec "$container" chown "$TEST_USER:$TEST_USER" /tmp/apapprover.exp
    docker_exec_as_tester "$container" "rm -f '$log_path'"

    docker exec -d --user "$TEST_USER" "$container" bash -lc \
        ". /home/$TEST_USER/aplane/apenv.sh && exec expect /tmp/apapprover.exp > $log_path 2>&1"

    local i
    for i in $(seq 1 20); do
        if docker_exec_as_tester "$container" "grep -q 'authenticated and signer unlocked' '$log_path' 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "$container" "cat '$log_path'" >&2 || true
    die "$label apapprover did not authenticate within 20s"
}

start_signer_apapprover() {
    start_apapprover "$SIGNER_CONTAINER" /tmp/apapprover.log signer
}

start_cosigner_apapprover() {
    start_apapprover "$COSIGNER_CONTAINER" /tmp/apapprover.log cosigner
}

run_request_enrollment() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "echo 'enroll' > /tmp/req-enrollment.script"
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/req-enrollment.script 2>&1 | tee /tmp/req-enrollment.log"
    docker_exec_as_tester "$CLIENT_CONTAINER" "grep -q 'waiting for the operator at endpoint' /tmp/req-enrollment.log" \
        || die "enroll did not report a queued enrollment request"
}

request_cosigner_enrollment() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "echo 'enroll --endpoint local-cosigner' > /tmp/req-cosigner-enrollment.script"
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/req-cosigner-enrollment.script 2>&1 | tee /tmp/req-cosigner-enrollment.log"
    docker_exec_as_tester "$CLIENT_CONTAINER" "grep -q 'waiting for the operator at endpoint local-cosigner' /tmp/req-cosigner-enrollment.log" \
        || die "enroll did not report a queued enrollment request at local-cosigner"
}

install_python_sdk_client() {
    docker_exec "$CLIENT_CONTAINER" rm -rf /tmp/aplanesdk-python "$SDK_CONTAINER_DIR" "$SDK_VENV"

    if [ "$RELEASE_INSTALL" = "1" ]; then
        local package="aplanesdk"
        if [ -n "$SDK_VERSION" ]; then
            package="aplanesdk==$SDK_VERSION"
        fi
        docker_exec_as_tester "$CLIENT_CONTAINER" "python3 -m venv '$SDK_VENV' && \
            . '$SDK_VENV/bin/activate' && \
            python -m pip install --no-input --upgrade pip && \
            python -m pip install --no-input '$package'"
        return
    fi

    [ -n "$SDK_SOURCE_DIR" ] || die "SDK source directory is not set"

    docker_exec "$CLIENT_CONTAINER" mkdir -p /tmp/aplanesdk-python
    docker cp "$SDK_SOURCE_DIR/." "$CLIENT_CONTAINER:/tmp/aplanesdk-python"
    docker_exec "$CLIENT_CONTAINER" chown -R "$TEST_USER:$TEST_USER" /tmp/aplanesdk-python
    docker_exec_as_tester "$CLIENT_CONTAINER" "mkdir -p /home/$TEST_USER/src && \
        mv /tmp/aplanesdk-python '$SDK_CONTAINER_DIR' && \
        python3 -m venv '$SDK_VENV' && \
        . '$SDK_VENV/bin/activate' && \
        python -m pip install --no-input -e '$SDK_CONTAINER_DIR'"
}

install_typescript_sdk_client() {
    local package="aplanesdk"
    if [ "$RELEASE_INSTALL" = "1" ]; then
        if [ -n "$SDK_VERSION" ]; then
            package="aplanesdk@$SDK_VERSION"
        fi
    else
        # Build and pack the local SDK on the host; npm pack runs its prepack
        # build. The container installs the tarball like a published package.
        [ -n "$SDK_REPO" ] || die "SDK repo is not set"
        command -v npm >/dev/null 2>&1 || die "npm not found on the host; local mode packs the TypeScript SDK"
        local pack_dir tarball
        pack_dir="$(mktemp -d)"
        (cd "$SDK_REPO/typescript" && npm pack --pack-destination "$pack_dir" >/dev/null) \
            || die "failed to build and pack the local TypeScript SDK"
        tarball="$(ls "$pack_dir"/aplanesdk-*.tgz 2>/dev/null | head -n 1)"
        [ -n "$tarball" ] || die "npm pack produced no aplanesdk tarball"
        docker cp "$tarball" "$CLIENT_CONTAINER:/tmp/aplanesdk-typescript.tgz"
        docker_exec "$CLIENT_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/aplanesdk-typescript.tgz
        rm -rf "$pack_dir"
        package="/tmp/aplanesdk-typescript.tgz"
    fi

    docker_exec_as_tester "$CLIENT_CONTAINER" "rm -rf '$TS_SDK_DIR' && \
        mkdir -p '$TS_SDK_DIR' && \
        cd '$TS_SDK_DIR' && \
        npm init -y >/dev/null && \
        npm install --no-audit --no-fund '$package' algosdk@^3.0.0"
}

# write_go_sdk_validator writes the Go SDK validation program into a new module
# directory: the plain host's 0 ALGO self-send through the prepared cosigned flow.
write_go_sdk_validator() {
    local dir="$1"
    cat > "$dir/main.go" <<'GO'
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/transaction"

	aplane "github.com/aplane-algo/aplanesdk/go"
)

func requireEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		fmt.Fprintf(os.Stderr, "%s is required\n", name)
		os.Exit(1)
	}
	return value
}

func main() {
	primaryData := requireEnv("APCLIENT_DATA")
	cosignerData := requireEnv("APLANE_COSIGNER_DATA")
	account := requireEnv("APLANE_PLAIN_HOST_ADDRESS")
	cosignerComponentKey := requireEnv("APLANE_COSIGNER_COMPONENT_KEY")
	algodURL := requireEnv("APLANE_ALGOD_URL")
	algodToken := strings.TrimSpace(os.Getenv("APLANE_ALGOD_TOKEN"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fail := func(step string, err error) {
		fmt.Fprintf(os.Stderr, "Go SDK plain host validation: %s: %v\n", step, err)
		os.Exit(1)
	}

	algodClient, err := algod.MakeClient(algodURL, algodToken)
	if err != nil {
		fail("algod client", err)
	}
	userClient, err := aplane.FromEnvWithContext(ctx, &aplane.FromEnvOptions{DataDir: primaryData, Timeout: 180})
	if err != nil {
		fail("connect to the signer", err)
	}
	defer userClient.Close()
	cosignerClient, err := aplane.FromEnvWithContext(ctx, &aplane.FromEnvOptions{DataDir: cosignerData, Timeout: 180})
	if err != nil {
		fail("connect to the cosigner", err)
	}
	defer cosignerClient.Close()

	prepared, err := userClient.PreparePayment(ctx, algodClient, aplane.PaymentPrepParams{
		Sender:   account,
		Receiver: account,
		Amount:   0,
		Note:     []byte("aplane go sdk plain host validate"),
		Fee:      1000,
	})
	if err != nil {
		fail("prepare payment", err)
	}
	result, err := aplane.SignPreparedCosignedGroupWithContext(ctx, aplane.PreparedCosignedGroupOptions{
		UserClient:           userClient,
		CosignerClient:       cosignerClient,
		CosignerComponentKey: cosignerComponentKey,
		PreparedGroup:        aplane.NewPreparedGroup(*prepared),
	})
	if err != nil {
		fail("sign through the cosigned flow", err)
	}
	if len(result.SignedGroup) == 0 {
		fail("sign through the cosigned flow", fmt.Errorf("empty signed group"))
	}
	fmt.Printf("Go SDK plain host validation group size: %d\n", len(result.SignedGroup))

	var raw []byte
	for _, signed := range result.SignedGroup {
		decoded, err := hex.DecodeString(signed)
		if err != nil {
			fail("decode signed transaction", err)
		}
		raw = append(raw, decoded...)
	}
	txid, err := algodClient.SendRawTransaction(raw).Do(ctx)
	if err != nil {
		fail("submit", err)
	}
	if _, err := transaction.WaitForConfirmation(algodClient, txid, 10, ctx); err != nil {
		fail("confirm", err)
	}
	fmt.Printf("Go SDK plain host validation submitted: %s\n", txid)
}
GO
}

# build_go_sdk_validator builds the Go SDK validation program on the host, as a
# static Linux binary for the image's architecture, since the image has no Go
# toolchain. Local mode builds against the local aplanesdk/go checkout; release
# mode against the published module. It leaves GO_SDK_BIN empty when release
# mode can't build it, and the Go check is skipped.
build_go_sdk_validator() {
    GO_SDK_BIN=""
    if ! command -v go >/dev/null 2>&1; then
        # Release mode tests published packages and may run where no Go toolchain is.
        if [ "$RELEASE_INSTALL" = "1" ]; then
            log "Skipping the Go SDK check: go not found on the host"
            return 0
        fi
        die "go not found on the host; the Go SDK check builds its program there"
    fi
    local dir
    dir="$(mktemp -d)"
    write_go_sdk_validator "$dir"
    (cd "$dir" && go mod init aplane-docker-smoke/go-sdk-validate >/dev/null 2>&1) \
        || die "failed to create the Go SDK validation module"
    if [ "$RELEASE_INSTALL" = "1" ]; then
        local version="${SDK_VERSION:-latest}"
        case "$version" in
            latest|v*) ;;
            *) version="v$version" ;;
        esac
        if ! (cd "$dir" && go get "github.com/aplane-algo/aplanesdk/go@$version" >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1); then
            log "Skipping the Go SDK check: github.com/aplane-algo/aplanesdk/go@$version could not be fetched"
            rm -rf "$dir"
            GO_SDK_BIN=""
            return 0
        fi
    else
        [ -n "$SDK_REPO" ] || die "SDK repo is not set"
        (cd "$dir" && \
            go mod edit -require=github.com/aplane-algo/aplanesdk/go@v0.0.0 \
                -replace=github.com/aplane-algo/aplanesdk/go="$SDK_REPO/go" && \
            go mod tidy >/dev/null) \
            || die "failed to resolve the local Go SDK at $SDK_REPO/go"
    fi
    GO_SDK_BIN="$dir/go-sdk-validate"
    if ! (cd "$dir" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$GO_SDK_BIN" .); then
        if [ "$RELEASE_INSTALL" = "1" ]; then
            log "Skipping the Go SDK check: the published Go SDK predates the prepared cosigned flow"
            GO_SDK_BIN=""
            return 0
        fi
        die "failed to build the Go SDK validation program"
    fi
}

install_go_sdk_client() {
    [ -n "$GO_SDK_BIN" ] || return 0
    docker cp "$GO_SDK_BIN" "$CLIENT_CONTAINER:$GO_SDK_CONTAINER_BIN"
    docker_exec "$CLIENT_CONTAINER" chown "$TEST_USER:$TEST_USER" "$GO_SDK_CONTAINER_BIN"
    docker_exec "$CLIENT_CONTAINER" chmod 755 "$GO_SDK_CONTAINER_BIN"
    rm -rf "$(dirname "$GO_SDK_BIN")"
}

write_sdk_data_dir() {
    local data_dir="$1"
    local host="$2"
    local ssh_port="$3"

    # The SDK client reuses the enrolled apshell key: the key is the credential.
    docker_exec_as_tester "$CLIENT_CONTAINER" "rm -rf '$data_dir' && \
        mkdir -p '$data_dir/.ssh' && \
        cp /home/$TEST_USER/aplane/apclient/.ssh/id_ed25519 '$data_dir/.ssh/id_ed25519' && \
        cp /home/$TEST_USER/aplane/apclient/.ssh/known_hosts '$data_dir/.ssh/known_hosts' && \
        chmod 700 '$data_dir/.ssh' && \
        chmod 600 '$data_dir/.ssh/id_ed25519' '$data_dir/.ssh/known_hosts' && \
        cat > '$data_dir/config.yaml' <<YAML
schema_version: 1
YAML
        cat > '$data_dir/endpoints.yaml' <<YAML
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://$host:$ssh_port
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
YAML"
}

configure_python_sdk_client_data() {
    local signer_ssh_port cosigner_ssh_port
    signer_ssh_port="$(read_node_endpoint_field "$SIGNER_CONTAINER" ssh_port)"
    cosigner_ssh_port="$(read_node_endpoint_field "$COSIGNER_CONTAINER" ssh_port)"
    [ -n "$signer_ssh_port" ] || die "could not read signer SSH port"
    [ -n "$cosigner_ssh_port" ] || die "could not read cosigner SSH port"

    write_sdk_data_dir \
        "/home/$TEST_USER/aplane/apclient-sdk-primary" \
        "signer" \
        "$signer_ssh_port"
    write_sdk_data_dir \
        "/home/$TEST_USER/aplane/apclient-sdk-cosigner" \
        "cosigner" \
        "$cosigner_ssh_port"
}

run_python_sdk_plain_host_validate() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"

    local py_file
    py_file="$(mktemp)"
    cat > "$py_file" <<'PY'
import base64
import os
import sys

from algosdk import transaction
from algosdk.v2client import algod

from aplanesdk import (
    PreparedGroup,
    SignerClient,
    send_raw_transaction,
    sign_prepared_cosigned_group,
)

MIN_TXN_FEE = 1000


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def signed_group_b64(signed_hexes: list[str]) -> str:
    return base64.b64encode(b"".join(bytes.fromhex(item) for item in signed_hexes)).decode()


def main() -> int:
    primary_data = require_env("APCLIENT_DATA")
    cosigner_data = require_env("APLANE_COSIGNER_DATA")
    plain_host_address = require_env("APLANE_PLAIN_HOST_ADDRESS")
    cosigner_component_key = require_env("APLANE_COSIGNER_COMPONENT_KEY")
    algod_url = require_env("APLANE_ALGOD_URL")
    algod_token = os.environ.get("APLANE_ALGOD_TOKEN", "").strip()

    algod_client = algod.AlgodClient(algod_token, algod_url)

    with SignerClient.from_env(data_dir=primary_data, timeout=180) as user_client, SignerClient.from_env(
        data_dir=cosigner_data,
        timeout=180,
    ) as cosigner_client:
        prepared = user_client.prepare_payment(
            algod_client,
            sender=plain_host_address,
            receiver=plain_host_address,
            amount=0,
            note=b"aplane python sdk plain host validate",
            fee=MIN_TXN_FEE,
        )
        result = sign_prepared_cosigned_group(
            user_client=user_client,
            cosigner_client=cosigner_client,
            cosigner_component_key=cosigner_component_key,
            prepared_group=PreparedGroup([prepared]),
        )
        if not result.signed_group:
            raise RuntimeError("SDK cosigned signing returned an empty signed group")
        print(f"Python SDK plain host validation group size: {len(result.signed_group)}")

        txid = send_raw_transaction(algod_client, signed_group_b64(result.signed_group))
        transaction.wait_for_confirmation(algod_client, txid, 10)
        print(f"Python SDK plain host validation submitted: {txid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
    docker cp "$py_file" "$CLIENT_CONTAINER:/tmp/sdk-plain-host-validate.py"
    rm -f "$py_file"
    docker_exec "$CLIENT_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/sdk-plain-host-validate.py

    docker_exec_as_tester "$CLIENT_CONTAINER" ". '$SDK_VENV/bin/activate' && \
        APCLIENT_DATA=/home/$TEST_USER/aplane/apclient-sdk-primary \
        APLANE_COSIGNER_DATA=/home/$TEST_USER/aplane/apclient-sdk-cosigner \
        APLANE_PLAIN_HOST_ADDRESS='$PLAIN_HOST_ADDRESS' \
        APLANE_COSIGNER_COMPONENT_KEY='$COSIGNER_COMPONENT_KEY' \
        APLANE_ALGOD_URL='$ALGOD_URL' \
        APLANE_ALGOD_TOKEN='$ALGOD_TOKEN' \
        PYTHONUNBUFFERED=1 \
        python /tmp/sdk-plain-host-validate.py"
}

run_python_sdk_corridor_validate() {
    [ -n "$CORRIDOR_ADDRESS" ] || die "Corridor address is not set"
    [ -n "$CORRIDOR_ALLOWED_ADDRESS" ] || die "Corridor allowed address is not set"
    [ -n "$CORRIDOR_BLOCKED_ADDRESS" ] || die "Corridor blocked address is not set"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"

    local py_file
    py_file="$(mktemp)"
    cat > "$py_file" <<'PY'
import base64
import os
import sys

from algosdk import transaction
from algosdk.v2client import algod

from aplanesdk import (
    PreparedGroup,
    SignerClient,
    SignerError,
    send_raw_transaction,
    sign_prepared_bounded_cosigner_group,
)

MIN_TXN_FEE = 1000


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def signed_group_b64(signed_hexes: list[str]) -> str:
    return base64.b64encode(
        b"".join(bytes.fromhex(item) for item in signed_hexes)
    ).decode()


def main() -> int:
    primary_data = require_env("APCLIENT_DATA")
    cosigner_data = require_env("APLANE_COSIGNER_DATA")
    corridor_address = require_env("APLANE_CORRIDOR_ADDRESS")
    allowed_address = require_env("APLANE_CORRIDOR_ALLOWED_ADDRESS")
    blocked_address = require_env("APLANE_CORRIDOR_BLOCKED_ADDRESS")
    cosigner_component_key = require_env("APLANE_COSIGNER_COMPONENT_KEY")
    algod_url = require_env("APLANE_ALGOD_URL")
    algod_token = os.environ.get("APLANE_ALGOD_TOKEN", "").strip()

    algod_client = algod.AlgodClient(algod_token, algod_url)
    with SignerClient.from_env(
        data_dir=primary_data,
        timeout=180,
    ) as user_client, SignerClient.from_env(
        data_dir=cosigner_data,
        timeout=180,
    ) as cosigner_client:
        allowed = user_client.prepare_payment(
            algod_client,
            sender=corridor_address,
            receiver=allowed_address,
            amount=0,
            note=b"aplane python sdk corridor allow",
            fee=MIN_TXN_FEE,
        )
        result = sign_prepared_bounded_cosigner_group(
            user_client=user_client,
            cosigner_client=cosigner_client,
            cosigner_component_key=cosigner_component_key,
            prepared_group=PreparedGroup([allowed]),
        )
        if not result.signed_group:
            raise RuntimeError(
                "SDK bounded-cosigner signing returned an empty signed group"
            )
        print(
            "Python SDK bounded-cosigner Corridor group size: "
            f"{len(result.signed_group)}"
        )
        txid = send_raw_transaction(
            algod_client,
            signed_group_b64(result.signed_group),
        )
        transaction.wait_for_confirmation(algod_client, txid, 10)
        print(f"Python SDK bounded-cosigner Corridor submitted: {txid}")

        blocked = user_client.prepare_payment(
            algod_client,
            sender=corridor_address,
            receiver=blocked_address,
            amount=0,
            note=b"aplane python sdk corridor deny",
            fee=MIN_TXN_FEE,
        )
        try:
            sign_prepared_bounded_cosigner_group(
                user_client=user_client,
                cosigner_client=cosigner_client,
                cosigner_component_key=cosigner_component_key,
                prepared_group=PreparedGroup([blocked]),
            )
        except SignerError as exc:
            if "not in allowlist" not in str(exc):
                raise RuntimeError(
                    "SDK Corridor denial did not report allowlist rejection"
                ) from exc
            print("Python SDK bounded-cosigner Corridor denial verified")
        else:
            raise RuntimeError(
                "SDK Corridor unexpectedly signed a non-allowlisted payment"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
    docker cp "$py_file" "$CLIENT_CONTAINER:/tmp/sdk-corridor-validate.py"
    rm -f "$py_file"
    docker_exec "$CLIENT_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/sdk-corridor-validate.py

    docker_exec_as_tester "$CLIENT_CONTAINER" ". '$SDK_VENV/bin/activate' && \
        APCLIENT_DATA=/home/$TEST_USER/aplane/apclient-sdk-primary \
        APLANE_COSIGNER_DATA=/home/$TEST_USER/aplane/apclient-sdk-cosigner \
        APLANE_CORRIDOR_ADDRESS='$CORRIDOR_ADDRESS' \
        APLANE_CORRIDOR_ALLOWED_ADDRESS='$CORRIDOR_ALLOWED_ADDRESS' \
        APLANE_CORRIDOR_BLOCKED_ADDRESS='$CORRIDOR_BLOCKED_ADDRESS' \
        APLANE_COSIGNER_COMPONENT_KEY='$COSIGNER_COMPONENT_KEY' \
        APLANE_ALGOD_URL='$ALGOD_URL' \
        APLANE_ALGOD_TOKEN='$ALGOD_TOKEN' \
        PYTHONUNBUFFERED=1 \
        python /tmp/sdk-corridor-validate.py"
}

run_typescript_sdk_plain_host_validate() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"

    local js_file
    js_file="$(mktemp)"
    cat > "$js_file" <<'JS'
import algosdk from "algosdk";
import {
  SignerClient,
  concatenateSignedTxns,
  sendRawTransaction,
  signPreparedCosignedGroup,
} from "aplanesdk";

const MIN_TXN_FEE = 1000;

function requireEnv(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

async function main() {
  const primaryData = requireEnv("APCLIENT_DATA");
  const cosignerData = requireEnv("APLANE_COSIGNER_DATA");
  const plainHostAddress = requireEnv("APLANE_PLAIN_HOST_ADDRESS");
  const cosignerComponentKey = requireEnv("APLANE_COSIGNER_COMPONENT_KEY");
  const algodUrl = requireEnv("APLANE_ALGOD_URL");
  const algodToken = String(process.env.APLANE_ALGOD_TOKEN || "").trim();

  const algodEndpoint = new URL(algodUrl);
  const algodServer = `${algodEndpoint.protocol}//${algodEndpoint.hostname}`;
  const algodPort = algodEndpoint.port || (algodEndpoint.protocol === "https:" ? "443" : "80");
  const algodClient = new algosdk.Algodv2(algodToken, algodServer, algodPort);
  const userClient = await SignerClient.fromEnv({ dataDir: primaryData, timeout: 180 });
  const cosignerClient = await SignerClient.fromEnv({ dataDir: cosignerData, timeout: 180 });
  try {
    const prepared = await userClient.preparePayment(algodClient, {
      sender: plainHostAddress,
      receiver: plainHostAddress,
      amount: 0,
      note: new TextEncoder().encode("aplane typescript sdk plain host validate"),
      fee: MIN_TXN_FEE,
    });
    const result = await signPreparedCosignedGroup({
      userClient,
      cosignerClient,
      cosignerComponentKey,
      preparedGroup: { transactions: [prepared] },
    });
    if (!result.signedGroup || result.signedGroup.length === 0) {
      throw new Error("SDK cosigned signing returned an empty signed group");
    }
    console.log(`TypeScript SDK plain host validation group size: ${result.signedGroup.length}`);

    const txid = await sendRawTransaction(algodClient, concatenateSignedTxns(result.signedGroup));
    await algosdk.waitForConfirmation(algodClient, txid, 10);
    console.log(`TypeScript SDK plain host validation submitted: ${txid}`);
  } finally {
    await cosignerClient.close();
    await userClient.close();
  }
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  if (err && err.cause) {
    console.error("Cause:", err.cause);
  }
  process.exit(1);
});
JS
    docker cp "$js_file" "$CLIENT_CONTAINER:$TS_SDK_DIR/sdk-plain-host-validate.mjs"
    rm -f "$js_file"
    docker_exec "$CLIENT_CONTAINER" chown "$TEST_USER:$TEST_USER" "$TS_SDK_DIR/sdk-plain-host-validate.mjs"

    docker_exec_as_tester "$CLIENT_CONTAINER" "cd '$TS_SDK_DIR' && \
        APCLIENT_DATA=/home/$TEST_USER/aplane/apclient-sdk-primary \
        APLANE_COSIGNER_DATA=/home/$TEST_USER/aplane/apclient-sdk-cosigner \
        APLANE_PLAIN_HOST_ADDRESS='$PLAIN_HOST_ADDRESS' \
        APLANE_COSIGNER_COMPONENT_KEY='$COSIGNER_COMPONENT_KEY' \
        APLANE_ALGOD_URL='$ALGOD_URL' \
        APLANE_ALGOD_TOKEN='$ALGOD_TOKEN' \
        NODE_OPTIONS='--dns-result-order=ipv4first' \
        node ./sdk-plain-host-validate.mjs"
}

run_go_sdk_plain_host_validate() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"
    docker_exec_as_tester "$CLIENT_CONTAINER" "APCLIENT_DATA=/home/$TEST_USER/aplane/apclient-sdk-primary \
        APLANE_COSIGNER_DATA=/home/$TEST_USER/aplane/apclient-sdk-cosigner \
        APLANE_PLAIN_HOST_ADDRESS='$PLAIN_HOST_ADDRESS' \
        APLANE_COSIGNER_COMPONENT_KEY='$COSIGNER_COMPONENT_KEY' \
        APLANE_ALGOD_URL='$ALGOD_URL' \
        APLANE_ALGOD_TOKEN='$ALGOD_TOKEN' \
        '$GO_SDK_CONTAINER_BIN'"
}

generate_cosigner_component_key() {
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'disconnect\nconnect local-cosigner\ngenerate aplane.witness-falcon1024.v1\n' > /tmp/generate-cosigner.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-cosigner.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate cosigner key through client/cosigner flow"
    fi
    printf '%s\n' "$out"
    COSIGNER_COMPONENT_KEY="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "could not parse generated Witness Key ID"
}

enroll_cosigner_reference_to_signer() {
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"
    local public_file out
    public_file="$(mktemp)"
    if ! docker_exec_as_tester "$COSIGNER_CONTAINER" ". /home/$TEST_USER/aplane/apenv.sh && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' apadmin cosigner export '$COSIGNER_COMPONENT_KEY' /tmp/cosigner-public.json"; then
        die "failed to export cosigner public reference over local IPC"
    fi
    # The key file carries the public key only; it goes to the signer. The
    # client is given the cosigner's address by hand in endpoints add.
    docker cp "$COSIGNER_CONTAINER:/tmp/cosigner-public.json" "$public_file"
    docker cp "$public_file" "$SIGNER_CONTAINER:/tmp/cosigner-public.json"
    rm -f "$public_file"
    docker_exec "$SIGNER_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/cosigner-public.json
    if ! out="$(docker_exec_as_tester "$SIGNER_CONTAINER" ". /home/$TEST_USER/aplane/apenv.sh && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' apadmin cosigner import /tmp/cosigner-public.json '$COSIGNER_REFERENCE_NAME' && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' apadmin cosigner show '$COSIGNER_REFERENCE_NAME' 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "local IPC cosigner-reference import failed"
    fi
    printf '%s\n' "$out"
    grep -Fq "$COSIGNER_COMPONENT_KEY" <<<"$out" \
        || die "persisted cosigner reference does not contain the expected Witness Key ID"
}

verify_guided_cosigner_setup() {
    local out client_data add_command cosigner_ssh_port

    client_data="/home/$TEST_USER/aplane/apclient"
    cosigner_ssh_port="$(read_node_endpoint_field "$COSIGNER_CONTAINER" ssh_port)"
    [ -n "$cosigner_ssh_port" ] || die "could not read cosigner SSH port"
    if [ "$RELEASE_INSTALL" = "1" ]; then
        # A release may predate 'endpoints add'; 'cosigner add' works in both.
        add_command="cosigner add"
    else
        add_command="endpoints add"
    fi

    # The client is told the cosigner's address; the key file never reaches it.
    # The client key stays enrolled at the cosigner, so setup reconnects
    # without another approval.
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'endpoints delete local-cosigner\n' > /tmp/delete-cosigner-endpoint.script && \
        . $client_data/apenv.sh && \
        apshell -script /tmp/delete-cosigner-endpoint.script >/tmp/delete-cosigner-endpoint.log 2>&1 && \
        echo '$add_command ssh://cosigner:$cosigner_ssh_port --alias local-cosigner' > /tmp/add-cosigner.script" \
        || die "endpoints delete did not remove the cosigner endpoint"
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". $client_data/apenv.sh && \
        apshell -script /tmp/add-cosigner.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "guided cosigner setup failed"
    fi
    printf '%s\n' "$out"
    if [ "$RELEASE_INSTALL" = "1" ]; then
        grep -Fq -e 'Connection local-cosigner ready' -e 'Connected; expected witness found' <<<"$out" \
            || die "guided cosigner setup did not report a ready connection"
    else
        grep -Fq 'Connection local-cosigner ready' <<<"$out" \
            || die "guided cosigner setup did not report a ready connection"
        grep -Fq 'cosigner key(s) advertised.' <<<"$out" \
            || die "guided cosigner setup did not report the advertised keys"
    fi
}

# generate_plain_host_key creates a cosigned plain host: the plain Falcon
# LogicSig with the cosigner overlay, rekeyed by the spending key and the
# cosigner together. It signs through the cosigned flow.
generate_plain_host_key() {
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\ngenerate aplane.falcon1024.v1 cosigner=%s rekey_authority=spending_key\n' '$COSIGNER_REFERENCE_NAME' > /tmp/generate-plain-host.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-plain-host.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate a cosigned plain host through client/signer flow"
    fi
    printf '%s\n' "$out"
    PLAIN_HOST_ADDRESS="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "could not parse generated plain host address"
}

resolve_corridor_addresses() {
    CORRIDOR_ALLOWED_ADDRESS="$(localnet_account_address 1)"
    CORRIDOR_BLOCKED_ADDRESS="$(localnet_account_address 2)"
    [ -n "$CORRIDOR_ALLOWED_ADDRESS" ] || die "could not resolve corridor allowed account"
    [ -n "$CORRIDOR_BLOCKED_ADDRESS" ] || die "could not resolve corridor blocked account"
    [ "$CORRIDOR_ALLOWED_ADDRESS" != "$CORRIDOR_BLOCKED_ADDRESS" ] || die "corridor allowed and blocked addresses resolved to the same account"
}

# Takes an optional extra boundary line, such as an unlock round, and a rekey
# authority, only_these by default. The rekey-to list is the Falcon key.
generate_general_bounded_key() {
    local extra_line="${1:-}"
    local authority="${2:-only_these}"
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"
    [ -n "$CORRIDOR_ALLOWED_ADDRESS" ] || die "corridor allowed address is not set"
    [ -n "$FALCON_ADDRESS" ] || die "Falcon rekey-to address is not set"

    local boundary_file="/home/$TEST_USER/aplane/boundary.yaml"
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'schema: aplane.boundary.v1\nspend: [pay, axfer, asset_opt_in]\nrecipients:\n  - %s\nencoding: merkle\nrekey:\n  authority: %s\n  to:\n    - %s\ncosigner: %s\n%s\n' \
        '$CORRIDOR_ALLOWED_ADDRESS' '$authority' '$FALCON_ADDRESS' '$COSIGNER_COMPONENT_KEY' '$extra_line' > '$boundary_file'"
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\ngenerate aplane.falcon1024.v1 --boundary=%s\nkeys\n' \
        '$boundary_file' > /tmp/generate-general-bounded.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-general-bounded.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate bounded aplane.falcon1024.v1 account from a boundary file"
    fi
    printf '%s\n' "$out"
    GENERAL_BOUNDED_ADDRESS="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$GENERAL_BOUNDED_ADDRESS" ] || die "could not parse generated bounded aplane.falcon1024.v1 address"
    grep -Fq "Cosigner:       $COSIGNER_COMPONENT_KEY" <<<"$out" \
        || die "bounded aplane.falcon1024.v1 result did not report the requested cosigner"
    grep -Fq 'Merkle allowlist' <<<"$out" \
        || die "keys did not describe the bounded aplane.falcon1024.v1 account"
    local label='rekey to listed only'
    if [ "$authority" = plus_cosigned ]; then
        label='rekey to listed, or cosigned'
    fi
    grep -Fq "$label" <<<"$out" \
        || die "keys did not describe the bounded aplane.falcon1024.v1 account's rekey as '$label'"
}

# run_apshell_rekey rekeys an account through apshell and prints the output. It
# never fails on its own: the callers decide what the output must say.
run_apshell_rekey() {
    local account="$1" target="$2" script="$3"
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nrekey %s to %s\n' '$account' '$target' > /tmp/$script.script"
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/$script.script 2>&1" || true
}

# account_auth_address prints an account's authorizer, empty when it signs for itself.
account_auth_address() {
    local address="$1"
    docker_exec_as_tester "$CLIENT_CONTAINER" "curl -fsS -H 'X-Algo-API-Token: $ALGOD_TOKEN' '$ALGOD_URL/v2/accounts/$address?exclude=all'" \
        | tr -d ' \n' | grep -o '"auth-addr":"[A-Z2-7]*"' | cut -d'"' -f4 || true
}

# wait_for_auth_address waits for an account's authorizer to become target.
wait_for_auth_address() {
    local address="$1" target="$2" what="$3" auth i
    for i in $(seq 1 20); do
        auth="$(account_auth_address "$address")"
        [ "$auth" = "$target" ] && return 0
        sleep 1
    done
    die "$what: authorizer is '${auth:-none}', want $target"
}

# An unlisted rekey is refused at the signer before anything reaches the network
# or the cosigner: the account takes no rekey but to its listed address.
verify_general_bounded_unlisted_rekey_refused() {
    [ -n "$GENERAL_BOUNDED_ADDRESS" ] || die "bounded aplane.falcon1024.v1 address is not set"
    [ -n "$CORRIDOR_BLOCKED_ADDRESS" ] || die "unlisted rekey target is not set"
    local out
    out="$(run_apshell_rekey "$GENERAL_BOUNDED_ADDRESS" "$CORRIDOR_BLOCKED_ADDRESS" rekey-general-unlisted)"
    printf '%s\n' "$out"
    grep -Fq "is not on this account's rekey-to list" <<<"$out" \
        || die "the signer did not refuse an unlisted rekey of an bounded aplane.falcon1024.v1 account"
    [ -z "$(account_auth_address "$GENERAL_BOUNDED_ADDRESS")" ] \
        || die "an bounded aplane.falcon1024.v1 account was rekeyed to an unlisted address"
}

# The listed rekey takes the spending key alone, so the listed key still takes
# the account over after its cosigner is gone.
verify_general_bounded_listed_rekey_without_cosigner() {
    [ -n "$GENERAL_BOUNDED_ADDRESS" ] || die "bounded aplane.falcon1024.v1 address is not set"
    [ -n "$FALCON_ADDRESS" ] || die "Falcon listed key is not set"
    local out
    out="$(run_apshell_rekey "$GENERAL_BOUNDED_ADDRESS" "$FALCON_ADDRESS" rekey-general-listed)"
    printf '%s\n' "$out"
    grep -Fqi 'transaction submitted' <<<"$out" \
        || die "the listed rekey of an bounded aplane.falcon1024.v1 account was not submitted after cosigner deletion"
    wait_for_auth_address "$GENERAL_BOUNDED_ADDRESS" "$FALCON_ADDRESS" "listed rekey without the cosigner"
}

# A plus cosigned account's unlisted rekey goes to the cosigner node, whose
# policy rejects every rekey until it allows this one.
verify_plus_cosigned_rekey_refused_by_cosigner() {
    [ -n "$PLUS_COSIGNED_ADDRESS" ] || die "plus cosigned address is not set"
    [ -n "$ED25519_ADDRESS" ] || die "cosigned rekey target is not set"
    local out
    out="$(run_apshell_rekey "$PLUS_COSIGNED_ADDRESS" "$ED25519_ADDRESS" rekey-plus-refused)"
    printf '%s\n' "$out"
    grep -Fq 'cosigner policy rejected request' <<<"$out" \
        || die "the cosigner node did not refuse a plus cosigned rekey under reject_rekey"
    [ -z "$(account_auth_address "$PLUS_COSIGNED_ADDRESS")" ] \
        || die "a plus cosigned account was rekeyed against the cosigner's policy"
}

# allow_cosigner_rekey_edge replaces the cosigner key's document with one that
# allows exactly the plus cosigned account's rekey to the Ed25519 key.
allow_cosigner_rekey_edge() {
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"
    local policy_file out
    policy_file="$(mktemp)"
    cat > "$policy_file" <<JSON
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "$COSIGNER_COMPONENT_KEY",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": false,
  "max_fee_microalgos": "0",
  "transaction_types": {"*": "reject", "pay": "allow", "axfer": "allow"},
  "transfer_policy": {
    "routes": [
      {"id": "docker_smoke_allow_all", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]},
      {"id": "docker_smoke_close", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["$CLOSE_DESTINATION_ADDRESS"], "allow_close": true}
    ]
  },
  "rekey_policy": {
    "allowed": [
      {"sender": "$PLUS_COSIGNED_ADDRESS", "targets": ["$ED25519_ADDRESS"]}
    ]
  }
}
JSON
    docker cp "$policy_file" "$COSIGNER_CONTAINER:/tmp/cosigner-rekey-edge.json"
    rm -f "$policy_file"
    docker_exec "$COSIGNER_CONTAINER" chown "$TEST_USER:$TEST_USER" /tmp/cosigner-rekey-edge.json
    if ! out="$(docker_exec_as_tester "$COSIGNER_CONTAINER" ". /home/$TEST_USER/aplane/apenv.sh && \
        APSIGNER_PASSPHRASE='$TEST_PASSPHRASE' \
        apadmin -d /home/$TEST_USER/aplane/apsigner policy apply --yes /tmp/cosigner-rekey-edge.json 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "cosigner rekey edge apply failed"
    fi
    printf '%s\n' "$out"
}

# Along the allowed edge the cosigner signs, and the rekey confirms.
verify_plus_cosigned_rekey_along_edge() {
    local out
    out="$(run_apshell_rekey "$PLUS_COSIGNED_ADDRESS" "$ED25519_ADDRESS" rekey-plus-edge)"
    printf '%s\n' "$out"
    grep -Fqi 'transaction submitted' <<<"$out" \
        || die "a plus cosigned rekey along the cosigner's rekey edge was not submitted"
    wait_for_auth_address "$PLUS_COSIGNED_ADDRESS" "$ED25519_ADDRESS" "cosigned rekey along the edge"
}

generate_ed25519_key() {
    local out
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\ngenerate ed25519\n' > /tmp/generate-ed25519.script"
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-ed25519.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate Ed25519 key through client/signer flow"
    fi
    printf '%s\n' "$out"
    ED25519_ADDRESS="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$ED25519_ADDRESS" ] || die "could not parse generated Ed25519 address"
}

# Run the Corridor checks against the general account. Same rules, same results.
with_general_bounded_account() {
    local corridor_address="$CORRIDOR_ADDRESS"
    CORRIDOR_ADDRESS="$GENERAL_BOUNDED_ADDRESS"
    "$@"
    CORRIDOR_ADDRESS="$corridor_address"
}

generate_falcon_key() {
    local out
    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\ngenerate falcon1024\n' > /tmp/generate-falcon.script"
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/generate-falcon.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to generate Falcon key through client/signer flow"
    fi
    printf '%s\n' "$out"
    FALCON_ADDRESS="$(printf '%s\n' "$out" | awk '/Generated .* key:/ { print $NF; exit }')"
    [ -n "$FALCON_ADDRESS" ] || die "could not parse generated Falcon address"
}

localnet_account_address() {
    local row="$1"
    docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal account list -d /algod/data | awk -v row='$row' 'NR == row { print \$2; exit }'"
}

fund_account_from_localnet() {
    local address="$1"
    local label="$2"
    [ -n "$address" ] || die "$label address is not set"

    local funding_address
    funding_address="$(localnet_account_address 1)"
    [ -n "$funding_address" ] || die "could not find a LocalNet funding account"

    local out
    if ! out="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal clerk send \
        -d /algod/data \
        -w unencrypted-default-wallet \
        -f '$funding_address' \
        -t '$address' \
        -a '$ACCOUNT_FUND_AMOUNT' \
        --note 'aplane docker smoke funding' 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "failed to fund generated $label account from LocalNet wallet"
    fi
    printf '%s\n' "$out"
}

fund_account() {
    fund_account_from_localnet "$@"
}

verify_account_funded() {
    local address="$1"
    local label="$2"
    [ -n "$address" ] || die "$label address is not set"

    local balance i
    for i in $(seq 1 20); do
        balance="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal account balance -a '$address' -d /algod/data 2>/dev/null | awk '{ print \$1; exit }'")"
        if [ -n "$balance" ] && [ "$balance" -ge "$ACCOUNT_FUND_AMOUNT" ]; then
            printf '%s account %s balance: %s microAlgos\n' "$label" "$address" "$balance"
            return 0
        fi
        sleep 1
    done

    die "generated $label account was not funded; last balance: ${balance:-unavailable}"
}

fund_falcon_key() {
    fund_account "$FALCON_ADDRESS" "Falcon"
}

verify_falcon_funded() {
    verify_account_funded "$FALCON_ADDRESS" "Falcon"
}

fund_plain_host_key() {
    fund_account "$PLAIN_HOST_ADDRESS" "plain host"
}

verify_plain_host_funded() {
    verify_account_funded "$PLAIN_HOST_ADDRESS" "plain host"
}

fund_corridor_key() {
    fund_account "$CORRIDOR_ADDRESS" "corridor"
}

verify_corridor_funded() {
    verify_account_funded "$CORRIDOR_ADDRESS" "corridor"
}

validate_falcon_self_send() {
    [ -n "$FALCON_ADDRESS" ] || die "Falcon address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nvalidate %s\n' '$FALCON_ADDRESS' > /tmp/validate-falcon.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/validate-falcon.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "Falcon validation self-send failed"
    fi
    printf '%s\n' "$out"
    grep -Fq 'Validated successfully' <<<"$out" \
        || die "Falcon validation output did not include success marker"
}

validate_plain_host_self_send() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nvalidate %s\n' '$PLAIN_HOST_ADDRESS' > /tmp/validate-plain-host.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/validate-plain-host.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "plain host validation self-send failed"
    fi
    printf '%s\n' "$out"
    grep -Fq 'Validated successfully' <<<"$out" \
        || die "plain host validation output did not include success marker"
}

# close_plain_host closes the plain host out to a LocalNet account through
# apshell: a CloseRemainderTo spend, which a plain host signs like any other,
# with the cosigner. The account is then gone from the ledger.
close_plain_host() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"
    local destination="$CLOSE_DESTINATION_ADDRESS"
    [ -n "$destination" ] || die "close destination is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nclose %s to %s\n' '$PLAIN_HOST_ADDRESS' '$destination' > /tmp/close-plain-host.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/close-plain-host.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "plain host close failed"
    fi
    printf '%s\n' "$out"
    if grep -Fq 'Failed:' <<<"$out"; then
        die "plain host close reported failure"
    fi
    local balance
    balance="$(docker_exec "$ALGOD_CONTAINER" sh -lc "/node/bin/goal account balance -a '$PLAIN_HOST_ADDRESS' -d /algod/data 2>/dev/null | awk '{ print \$1; exit }'")"
    [ "$balance" = "0" ] || die "plain host balance after close is ${balance:-unavailable}, want 0"
    printf 'plain host %s closed to %s; balance %s\n' "$PLAIN_HOST_ADDRESS" "$destination" "$balance"
}

validate_corridor_allowed_send() {
    [ -n "$CORRIDOR_ADDRESS" ] || die "corridor address is not set"
    [ -n "$CORRIDOR_ALLOWED_ADDRESS" ] || die "corridor allowed address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nsend 0 algo from %s to %s note=corridor-allow\n' '$CORRIDOR_ADDRESS' '$CORRIDOR_ALLOWED_ADDRESS' > /tmp/send-corridor-allow.script"
    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/send-corridor-allow.script 2>&1")"; then
        printf '%s\n' "$out" >&2
        die "corridor allowlisted send command failed"
    fi
    printf '%s\n' "$out"
    if grep -Fq 'Failed:' <<<"$out"; then
        die "corridor allowlisted send reported failure"
    fi
    grep -Fq 'Transaction submitted:' <<<"$out" \
        || die "corridor allowlisted send did not submit a transaction"
    grep -Fq 'Confirmed: sent' <<<"$out" \
        || die "corridor allowlisted send did not confirm"
}

validate_corridor_blocked_send_fails() {
    [ -n "$CORRIDOR_ADDRESS" ] || die "corridor address is not set"
    [ -n "$CORRIDOR_BLOCKED_ADDRESS" ] || die "corridor blocked address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nsend 0 algo from %s to %s note=corridor-deny\n' '$CORRIDOR_ADDRESS' '$CORRIDOR_BLOCKED_ADDRESS' > /tmp/send-corridor-deny.script"
    local out
    out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/send-corridor-deny.script 2>&1" || true)"
    printf '%s\n' "$out"
    if grep -Fq 'Transaction submitted:' <<<"$out"; then
        die "corridor blocked send unexpectedly submitted a transaction"
    fi
    if grep -Fq 'Confirmed: sent' <<<"$out"; then
        die "corridor blocked send unexpectedly confirmed"
    fi
    grep -Fq 'not in allowlist' <<<"$out" \
        || die "corridor blocked send did not report allowlist rejection"
}

validate_corridor_send_after_cosigner_delete_fails() {
    [ -n "$CORRIDOR_ADDRESS" ] || die "Corridor address is not set"
    [ -n "$CORRIDOR_ALLOWED_ADDRESS" ] || die "Corridor allowed address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nsend 0 algo from %s to %s note=corridor-missing-cosigner\n' \
        '$CORRIDOR_ADDRESS' '$CORRIDOR_ALLOWED_ADDRESS' > /tmp/send-corridor-missing-cosigner.script"
    local out
    out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/send-corridor-missing-cosigner.script 2>&1" || true)"
    printf '%s\n' "$out"
    if grep -Fq 'Transaction submitted:' <<<"$out"; then
        die "Corridor send unexpectedly submitted after cosigner key deletion"
    fi
    grep -Fq 'no live cosigner route for Witness Key ID' <<<"$out" \
        || die "Corridor send failure did not report the missing cosigner key"
}

delete_cosigner_component_key() {
    [ -n "$COSIGNER_COMPONENT_KEY" ] || die "Witness Key ID is not set"

    local out
    if ! out="$(docker_exec_as_tester "$CLIENT_CONTAINER" "set -e
        . '$SDK_VENV/bin/activate'
        python - <<'PY'
from aplanesdk import SignerClient

with SignerClient.from_env(
    data_dir='/home/$TEST_USER/aplane/apclient-sdk-cosigner',
) as client:
    client.delete_key('$COSIGNER_COMPONENT_KEY')
print('{\"success\":true}')
PY")"; then
        printf '%s\n' "$out" >&2
        die "failed to delete cosigner key through cosigner admin API"
    fi
    printf '%s\n' "$out"
    grep -Fq '"success":true' <<<"$out" \
        || die "cosigner key deletion output did not include success marker"
}

validate_plain_host_self_send_after_cosigner_delete_fails() {
    [ -n "$PLAIN_HOST_ADDRESS" ] || die "plain host address is not set"

    docker_exec_as_tester "$CLIENT_CONTAINER" "printf 'connect\nvalidate %s\n' '$PLAIN_HOST_ADDRESS' > /tmp/validate-plain-host-missing-cosigner.script"
    local out
    out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
        apshell -script /tmp/validate-plain-host-missing-cosigner.script 2>&1" || true)"
    printf '%s\n' "$out"
    if grep -Fq 'Validated successfully' <<<"$out"; then
        die "plain host validation unexpectedly succeeded after cosigner key deletion"
    fi
    grep -Fq 'Failed:' <<<"$out" \
        || die "plain host validation did not report a failed transaction after cosigner key deletion"
    grep -Fq 'no live cosigner route for Witness Key ID' <<<"$out" \
        || die "plain host validation failure did not report the missing cosigner key"
}

verify_signer_reachable() {
    # The enrollment request is approved asynchronously by apapprover, so
    # retry until `apshell -script status` prints "Signer: Connected".
    docker_exec_as_tester "$CLIENT_CONTAINER" "echo 'status' > /tmp/status.script"
    local out attempt
    for attempt in $(seq 1 30); do
        out="$(docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && \
            apshell -script /tmp/status.script 2>&1")"
        if grep -qE 'Signer:[[:space:]]*Connected' <<<"$out"; then
            printf '%s\n' "$out"
            return 0
        fi
        sleep 1
    done
    printf '%s\n' "$out"
    die "apshell status did not report Signer: Connected"
}

verify_client_admin_node() {
    docker_exec_as_tester "$CLIENT_CONTAINER" ". /home/$TEST_USER/aplane/apclient/apenv.sh && apadmin --version"
}

shutdown_nodes() {
    docker_exec_as_tester "$SIGNER_CONTAINER" "pkill expect || true; pkill apapprover || true; pkill apsigner || true"
    docker_exec_as_tester "$COSIGNER_CONTAINER" "pkill expect || true; pkill apapprover || true; pkill apsigner || true"
    sleep 1
}

main() {
    parse_args "$@"
    select_network_profile
    command -v docker >/dev/null 2>&1 || die "docker not found"
    if [ "$RELEASE_INSTALL" != "1" ]; then
        resolve_sdk_repo
    fi
    trap cleanup EXIT

    if [ "$RELEASE_INSTALL" = "1" ]; then
        log "Using APlane GitHub release assets ($APLANE_RELEASE_VERSION)"
    else
        log "Building local release tarball"
    fi
    build_or_resolve_tarball

    log "Building the Go SDK validation program on the host"
    build_go_sdk_validator

    log "Building Ubuntu test image"
    build_image

    log "Starting four-container Docker network with shared LocalNet"
    start_containers

    log "Creating test users"
    create_test_user "$SIGNER_CONTAINER"
    create_test_user "$COSIGNER_CONTAINER"
    create_test_user "$CLIENT_CONTAINER"

    log "Installing signer node"
    run_node_installer "$SIGNER_CONTAINER" signer

    log "Installing cosigner node"
    run_node_installer "$COSIGNER_CONTAINER" cosigner cosigner

    log "Installing client/admin node"
    run_client_installer

    log "Preparing $NETWORK_TOKEN network profile"
    prepare_selected_network

    log "Configuring signer network listener"
    configure_node_network "$SIGNER_CONTAINER" signer

    log "Configuring signer, cosigner, and client for $NETWORK_TOKEN"
    configure_selected_network

    log "Verifying $NETWORK_TOKEN reachability from APlane nodes"
    verify_selected_network_reachable

    log "Configuring client endpoint registry"
    configure_client_endpoints

    log "Verifying installed layouts"
    verify_layout

    log "Generating client SSH key"
    generate_client_ssh_key

    log "Starting signer and cosigner apsigner processes"
    start_node "$SIGNER_CONTAINER" /tmp/apsigner.log
    start_node "$COSIGNER_CONTAINER" /tmp/apcosigner.log

    log "Seeding client known_hosts for signer and cosigner"
    populate_known_hosts

    log "Adding cosigner endpoint from client container"
    create_client_cosigner_endpoint

    # The Falcon plain host carries the bounds and the overlays and is enabled
    # by default, so it needs no key type setup.

    log "Starting signer-side approver for client enrollment"
    start_signer_apapprover

    log "Starting cosigner-side approver for client enrollment"
    start_cosigner_apapprover

    log "Enrolling the client key at the signer from the client container"
    run_request_enrollment

    log "Enrolling the client key at the cosigner from the client container"
    request_cosigner_enrollment

    log "Generating cosigner key through client/cosigner flow"
    generate_cosigner_component_key

    log "Importing cosigner public reference through local IPC"
    enroll_cosigner_reference_to_signer

    CLOSE_DESTINATION_ADDRESS="$(localnet_account_address 1)"
    [ -n "$CLOSE_DESTINATION_ADDRESS" ] || die "could not resolve a LocalNet account to close to"

    log "Checking apadmin policy verbs and applying the cosigner key's policy for cosigned smoke transactions"
    configure_cosigner_policy

    log "Applying an open transfer route on the signer for the Corridor smoke transactions"
    configure_signer_policy

    # Local IPC export, import, and policy apply displace the node approval sessions.
    # Re-establish both approval sessions before component signing.
    log "Re-establishing signer and cosigner approval sessions after public-reference import"
    start_signer_apapprover
    start_cosigner_apapprover

    log "Reconfiguring and verifying cosigner through guided apshell setup"
    verify_guided_cosigner_setup

    if [ "$RELEASE_INSTALL" = "1" ]; then
        if [ -n "$SDK_VERSION" ]; then
            log "Installing Python SDK from PyPI (aplanesdk==$SDK_VERSION)"
        else
            log "Installing Python SDK from PyPI (latest)"
        fi
    else
        log "Installing Python SDK from $SDK_SOURCE_DIR"
    fi
    install_python_sdk_client
    if [ "$RELEASE_INSTALL" = "1" ]; then
        if [ -n "$SDK_VERSION" ]; then
            log "Installing TypeScript SDK from npm (aplanesdk@$SDK_VERSION)"
        else
            log "Installing TypeScript SDK from npm (latest)"
        fi
    else
        log "Installing TypeScript SDK packed from $SDK_REPO/typescript"
    fi
    install_typescript_sdk_client
    if [ -n "$GO_SDK_BIN" ]; then
        log "Installing the Go SDK validation program"
        install_go_sdk_client
    fi

    log "Configuring Python SDK client data directories"
    configure_python_sdk_client_data

    log "Generating a cosigned plain host (aplane.falcon1024.v1) through client/signer flow"
    generate_plain_host_key

    log "Funding generated plain host on $NETWORK_TOKEN"
    fund_plain_host_key
    verify_plain_host_funded

    log "Validating the plain host with a 0 ALGO self-send through apshell"
    validate_plain_host_self_send

    log "Validating the plain host through the Python SDK"
    run_python_sdk_plain_host_validate

    log "Validating the plain host through the TypeScript SDK"
    run_typescript_sdk_plain_host_validate

    if [ -n "$GO_SDK_BIN" ]; then
        log "Validating the plain host through the Go SDK"
        run_go_sdk_plain_host_validate
    fi

    log "Closing the plain host out through apshell"
    close_plain_host

    log "Generating Falcon key through client/signer flow"
    generate_falcon_key

    log "Funding generated Falcon key on $NETWORK_TOKEN"
    fund_falcon_key
    verify_falcon_funded

    log "Validating generated Falcon key with 0 ALGO self-send"
    validate_falcon_self_send

    log "Generating Ed25519 key as a cosigned rekey target"
    generate_ed25519_key

    log "Resolving Corridor recipient accounts on $NETWORK_TOKEN"
    resolve_corridor_addresses

    log "Generating bounded aplane.falcon1024.v1 account from a boundary file"
    generate_general_bounded_key

    log "Funding generated bounded aplane.falcon1024.v1 account on $NETWORK_TOKEN"
    with_general_bounded_account fund_corridor_key
    with_general_bounded_account verify_corridor_funded

    log "Validating bounded-cosigner bounded aplane.falcon1024.v1 through Python SDK"
    with_general_bounded_account run_python_sdk_corridor_validate

    log "Verifying bounded aplane.falcon1024.v1 allowlisted recipient succeeds"
    with_general_bounded_account validate_corridor_allowed_send

    log "Verifying bounded aplane.falcon1024.v1 non-allowlisted recipient fails"
    with_general_bounded_account validate_corridor_blocked_send_fails

    log "Generating bounded aplane.falcon1024.v1 timelock account with a passed unlock round"
    generate_general_bounded_key "unlock_round: 1"

    log "Funding generated bounded aplane.falcon1024.v1 timelock account on $NETWORK_TOKEN"
    with_general_bounded_account fund_corridor_key
    with_general_bounded_account verify_corridor_funded

    log "Verifying bounded aplane.falcon1024.v1 timelock allowlisted recipient succeeds"
    with_general_bounded_account validate_corridor_allowed_send

    log "Generating plus cosigned bounded aplane.falcon1024.v1 account"
    generate_general_bounded_key "" plus_cosigned
    PLUS_COSIGNED_ADDRESS="$GENERAL_BOUNDED_ADDRESS"
    with_general_bounded_account fund_corridor_key
    with_general_bounded_account verify_corridor_funded

    log "Verifying the cosigner node refuses a plus cosigned rekey under reject_rekey"
    verify_plus_cosigned_rekey_refused_by_cosigner

    log "Allowing the plus cosigned rekey edge on the cosigner node"
    allow_cosigner_rekey_edge
    # The admin session displaced the cosigner's approval session, which locks it.
    start_cosigner_apapprover

    log "Verifying a plus cosigned rekey along the edge confirms"
    verify_plus_cosigned_rekey_along_edge

    log "Generating a cosigned plain host for the cosigner-loss checks"
    generate_plain_host_key
    fund_plain_host_key
    verify_plain_host_funded

    log "Generating bounded aplane.falcon1024.v1 account for the cosigner-loss checks"
    generate_general_bounded_key

    log "Funding generated bounded aplane.falcon1024.v1 account on $NETWORK_TOKEN"
    with_general_bounded_account fund_corridor_key
    with_general_bounded_account verify_corridor_funded

    log "Verifying client can reach signer with its enrolled key"
    verify_signer_reachable

    log "Verifying apadmin is present on client/admin node"
    verify_client_admin_node

    log "Deleting cosigner key from cosigner node"
    delete_cosigner_component_key

    log "Verifying the plain host's spend fails after cosigner key deletion"
    validate_plain_host_self_send_after_cosigner_delete_fails

    log "Verifying bounded aplane.falcon1024.v1 spend fails after cosigner key deletion"
    with_general_bounded_account validate_corridor_send_after_cosigner_delete_fails

    log "Verifying the signer refuses an unlisted rekey of aplane.falcon1024.v1"
    verify_general_bounded_unlisted_rekey_refused

    log "Verifying the listed key takes aplane.falcon1024.v1 over without the cosigner"
    verify_general_bounded_listed_rekey_without_cosigner

    log "Shutting down nodes"
    shutdown_nodes

    log "Docker $NETWORK_TOKEN topology smoke test passed"
}

main "$@"
