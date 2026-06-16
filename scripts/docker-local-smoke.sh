#!/usr/bin/env bash
# Smoke-test the bootstrap release tarball in a non-systemd Ubuntu container,
# running install.sh in local (rootless, user-directory) mode as a regular
# user. Asserts the install layout, exercises running-install gating, verifies
# stopped in-place upgrade preserves state, and checks
# uninstall state preservation.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH=""
DIST_DIR=""
VERSION="v0.24.0-docker-smoke"
TARBALL=""
SKIP_BUILD=0
KEEP_CONTAINER=0
IMAGE_NAME=""
CONTAINER_NAME="aplane-local-smoke-$$"
TEST_USER="tester"
TEST_PASSPHRASE="passphrase-for-docker-smoke"

usage() {
    cat <<'EOF'
Usage: scripts/docker-local-smoke.sh [options]

Options:
  --tarball <path>      Use an existing aplane_<version>_linux_<arch>.tar.gz
  --version <version>   Version string for locally built tarball (default: v0.24.0-docker-smoke)
  --arch <amd64|arm64>  Architecture to package/test (default: host arch)
  --skip-build          Reuse existing bin/<arch> binaries when building the tarball
  --keep-container      Leave the container running for debugging
  -h, --help            Show this help

This test requires Docker privileges. It starts a stock ubuntu:24.04 container
(no systemd), creates a non-root test user, runs install.sh in local mode,
verifies the install layout, exercises appass --check, starts apsigner,
verifies the installer refuses to run while that signer is running, starts
apapprover, drives `apshell request-token` end-to-end (including the
apapprover-side approval), confirms the client can reach the signer with the
issued token, verifies a stopped in-place upgrade preserves state, then runs the installed uninstaller
and verifies state preservation.
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
    docker exec "$CONTAINER_NAME" "$@"
}

docker_exec_bash() {
    docker exec "$CONTAINER_NAME" bash -lc "$1"
}

docker_exec_as_tester() {
    docker exec --user "$TEST_USER" "$CONTAINER_NAME" bash -lc "$1"
}

cleanup() {
    if [ "$KEEP_CONTAINER" = "1" ]; then
        printf '\nKept container for debugging: %s\n' "$CONTAINER_NAME"
        return
    fi
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
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
      bash ca-certificates expect gzip openssh-client passwd procps sudo tar && \
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

create_test_user() {
    docker_exec useradd -m -s /bin/bash "$TEST_USER"
    # Guarantee a bash login shell and a known .bashrc so install.sh can
    # offer to source apenv.sh from it.
    docker_exec_as_tester "touch /home/$TEST_USER/.bashrc"
}

run_installer() {
    # Copy tarball and hand it to tester. Extract into a source dir distinct
    # from the default install root (~/aplane) so they don't collide.
    docker cp "$TARBALL" "$CONTAINER_NAME:/tmp/aplane.tar.gz"
    docker_exec chmod 644 /tmp/aplane.tar.gz
    docker_exec_as_tester "mkdir -p /home/$TEST_USER/src && tar -xzf /tmp/aplane.tar.gz -C /home/$TEST_USER/src"

docker_exec_as_tester "cd /home/$TEST_USER/src/aplane && expect <<'EXPECT'
set timeout 180
set completed 0
spawn ./install.sh
expect {
  \"Choose mode *\" { send \"\r\" }
  timeout { exit 9 }
}
expect {
  \"Install to (default*\" { send \"\r\" }
  timeout { exit 10 }
}
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

verify_install() {
    local root="/home/$TEST_USER/aplane"
    # Binaries
    docker_exec_as_tester "test -x $root/apsigner/bin/apsigner"
    docker_exec_as_tester "test -x $root/apsigner/bin/apstore"
    docker_exec_as_tester "test -x $root/apsigner/bin/apadmin"
    docker_exec_as_tester "test -x $root/apsigner/bin/appass"
    docker_exec_as_tester "test -x $root/apsigner/bin/approbe"
    docker_exec_as_tester "test -x $root/apclient/bin/apshell"
    # Configs and keystore
    docker_exec_as_tester "test -f $root/apsigner/config.yaml"
    docker_exec_as_tester "test -f $root/apclient/config.yaml"
    docker_exec_as_tester "test -f $root/apsigner/identities/default/.keystore"
    # Launchers and env file
    docker_exec_as_tester "test -x $root/start.sh"
    docker_exec_as_tester "test -f $root/apenv.sh"
    # Everything owned by tester, never root
    docker_exec_as_tester "[ \"\$(stat -c '%U' $root)\" = '$TEST_USER' ]"
    docker_exec_as_tester "[ \"\$(stat -c '%U' $root/apsigner/config.yaml)\" = '$TEST_USER' ]"
    docker_exec_as_tester "[ \"\$(stat -c '%U' $root/apsigner/identities/default/.keystore)\" = '$TEST_USER' ]"
    # apenv.sh was sourced from ~/.bashrc
    docker_exec_as_tester "grep -qF '# aplane env' /home/$TEST_USER/.bashrc"
    # Sourcing apenv.sh sets the expected env
    docker_exec_as_tester ". $root/apenv.sh && \
        [ \"\$APLANE_INSTALL_ROOT\" = '$root' ] && \
        [ \"\$APSIGNER_DATA\" = '$root/apsigner' ] && \
        [ \"\$APCLIENT_DATA\" = '$root/apclient' ] && \
        command -v apsigner >/dev/null && \
        command -v apshell >/dev/null"
}

verify_appass_local_detection() {
    local root="/home/$TEST_USER/aplane"
    # appass --check exits 0 with a one-line verdict naming local mode. No
    # systemd service file exists in this container, so the detector falls
    # through to isLocal=true and the policy walks the tester-owned files.
    local out
    out="$(docker_exec_as_tester ". $root/apenv.sh && appass --check -d $root/apsigner")"
    printf '%s\n' "$out"
    printf '%s' "$out" | grep -q 'consistent with local mode' \
        || die "appass --check did not report local mode: $out"
}

generate_client_ssh_key() {
    # The local install doesn't generate the apshell SSH key (only --client
    # mode does in install.sh). In real use, the user runs ssh-keygen before
    # request-token; we do the same here.
    local client_dir="/home/$TEST_USER/aplane/apclient"
    docker_exec_as_tester "mkdir -p $client_dir/.ssh && chmod 700 $client_dir/.ssh && \
        ssh-keygen -t ed25519 -f $client_dir/.ssh/id_ed25519 -N '' -q"
}

start_apsigner() {
    # apsigner auto-generates its SSH host key on first run
    # (sshtunnel/server.go:loadOrGenerateHostKey). Started detached; the REST
    # endpoint and SSH server both come up locked. apapprover unlocks later.
    docker exec -d --user "$TEST_USER" "$CONTAINER_NAME" bash -lc \
        ". /home/$TEST_USER/aplane/apenv.sh && exec apsigner > /tmp/apsigner.log 2>&1"

    # Wait for the SSH server to report listening.
    local i
    for i in $(seq 1 30); do
        if docker_exec_as_tester "grep -q 'SSH server listening' /tmp/apsigner.log 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "cat /tmp/apsigner.log" >&2 || true
    die "apsigner did not become ready within 30s"
}

verify_approbe_gating_install() {
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "set +e
cd /home/$TEST_USER/src/aplane
./install.sh '$root' > /tmp/approbe-gating-install.log 2>&1
rc=\$?
set -e
cat /tmp/approbe-gating-install.log
if [ \"\$rc\" -eq 0 ]; then
    echo 'install.sh unexpectedly succeeded while apsigner was running' >&2
    exit 1
fi
grep -qF 'apsigner appears to be running for this local install' /tmp/approbe-gating-install.log
grep -qF 'running $root/apsigner/aplane.sock' /tmp/approbe-gating-install.log"
}

populate_known_hosts() {
    # Seed the client's known_hosts with the signer's freshly generated host
    # key so the subsequent `apshell -script` run (which sets AutoConfirm=true
    # and would otherwise reject unknown hosts) connects without prompting.
    docker_exec_as_tester '
        set -e
        root="/home/'"$TEST_USER"'/aplane"
        ssh_url=$(awk "
            \$1 == \"primary:\" { in_primary=1; next }
            in_primary && \$1 == \"url:\" { print \$2; exit }
        " "$root/apclient/endpoints.yaml")
        ssh_port=${ssh_url##*:}
        [ -n "$ssh_port" ] && [ "$ssh_port" != "$ssh_url" ] || { echo "could not read primary endpoint SSH port"; exit 1; }
        # apsigner only persists the private host key (no .pub sidecar), so
        # derive the public half with ssh-keygen -y.
        pub=$(ssh-keygen -y -f "$root/apsigner/.ssh/ssh_host_key")
        mkdir -p "$root/apclient/.ssh"
        chmod 700 "$root/apclient/.ssh"
        printf "[localhost]:%s %s\n" "$ssh_port" "$pub" > "$root/apclient/.ssh/known_hosts"
        chmod 600 "$root/apclient/.ssh/known_hosts"
    '
}

start_apapprover() {
    # apapprover authenticates via IPC (which also unlocks the signer), then
    # auto-answers "y" to every approval prompt — both token provisioning and
    # signing use the same prompt. We write the expect script on the host and
    # copy it in; `docker exec` doesn't forward stdin unless -i is set, so
    # piping a heredoc into a bare `docker exec` produces an empty file.
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
    docker cp "$exp_file" "$CONTAINER_NAME:/tmp/apapprover.exp"
    rm -f "$exp_file"
    docker_exec chmod 755 /tmp/apapprover.exp
    docker_exec chown "$TEST_USER:$TEST_USER" /tmp/apapprover.exp

    docker exec -d --user "$TEST_USER" "$CONTAINER_NAME" bash -lc \
        ". /home/$TEST_USER/aplane/apenv.sh && exec expect /tmp/apapprover.exp > /tmp/apapprover.log 2>&1"

    local i
    for i in $(seq 1 20); do
        if docker_exec_as_tester "grep -q 'authenticated and signer unlocked' /tmp/apapprover.log 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "cat /tmp/apapprover.log" >&2 || true
    die "apapprover did not authenticate within 20s"
}

run_request_token() {
    # Run request-token non-interactively via apshell -script. AutoConfirm=true
    # is set by script mode; known_hosts is pre-populated so no trust prompt.
    docker_exec_as_tester "echo 'request-token' > /tmp/req-token.script"
    docker_exec_as_tester ". /home/$TEST_USER/aplane/apenv.sh && \
        apshell -script /tmp/req-token.script 2>&1 | tee /tmp/req-token.log"
    docker_exec_as_tester "test -s /home/$TEST_USER/aplane/apclient/aplane.token" \
        || die "request-token did not produce a client token file"
}

verify_signer_reachable() {
    # With the token saved, `apshell -script status` should print
    # "Signer: Connected" after attemptStartupConnection succeeds.
    docker_exec_as_tester "echo 'status' > /tmp/status.script"
    local out
    out="$(docker_exec_as_tester ". /home/$TEST_USER/aplane/apenv.sh && \
        apshell -script /tmp/status.script 2>&1")"
    printf '%s\n' "$out"
    printf '%s' "$out" | grep -qE 'Signer:[[:space:]]*Connected' \
        || die "apshell status did not report Signer: Connected"
}

create_local_preserved_state_markers() {
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "mkdir -p '$root/apclient/plugins.available' '$root/apclient/scripts' '$root/apclient/cache' && \
        printf 'custom plugin marker\n' > '$root/apclient/plugins.available/custom-plugin-marker.txt' && \
        printf 'enabled_plugins:\n  - custom-plugin\n' > '$root/apclient/plugins.yaml' && \
        printf 'console.log(\"custom script marker\");\n' > '$root/apclient/scripts/custom-script.js' && \
        printf 'custom cache marker\n' > '$root/apclient/cache/custom-cache-marker.txt'"
}

record_local_state_fingerprint() {
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "set -e
files='
$root/apsigner/config.yaml
$root/apsigner/identities/default/.keystore
$root/apclient/config.yaml
$root/apclient/aplane.token
$root/apclient/.ssh/id_ed25519
$root/apclient/.ssh/known_hosts
$root/apclient/plugins.yaml
$root/apclient/plugins.available/custom-plugin-marker.txt
$root/apclient/scripts/custom-script.js
$root/apclient/cache/custom-cache-marker.txt
'
sha256sum \$files > /tmp/local-state-baseline.sha256
stat -c '%U:%G %a %n' \$files > /tmp/local-state-baseline.stat"
}

verify_local_state_fingerprint() {
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "set -e
files='
$root/apsigner/config.yaml
$root/apsigner/identities/default/.keystore
$root/apclient/config.yaml
$root/apclient/aplane.token
$root/apclient/.ssh/id_ed25519
$root/apclient/.ssh/known_hosts
$root/apclient/plugins.yaml
$root/apclient/plugins.available/custom-plugin-marker.txt
$root/apclient/scripts/custom-script.js
$root/apclient/cache/custom-cache-marker.txt
'
sha256sum \$files > /tmp/local-state-current.sha256
stat -c '%U:%G %a %n' \$files > /tmp/local-state-current.stat
diff -u /tmp/local-state-baseline.sha256 /tmp/local-state-current.sha256
diff -u /tmp/local-state-baseline.stat /tmp/local-state-current.stat"
}

run_local_reinstaller() {
    docker_exec_as_tester "cd /home/$TEST_USER/src/aplane && expect <<'EXPECT'
set timeout 180
set completed 0
spawn ./install.sh /home/$TEST_USER/aplane
expect {
  \"Proceed with installation?*\" { send \"\r\"; exp_continue }
  \"Enable enforced memory locking for apsigner?*\" { send \"n\r\"; exp_continue }
  \"Add apenv.sh to *\" { send \"y\r\"; exp_continue }
  \"=== Installation complete ===\" { set completed 1; exp_continue }
  timeout { exit 18 }
  eof {}
}
set result [wait]
set rc [lindex \$result 3]
if {\$completed != 1} {
  exit 19
}
exit \$rc
EXPECT"
}

shutdown_services() {
    # Uninstall will delete the install tree; stop the daemon and approver
    # cleanly first so no in-flight IPC writes race with the removal. Match
    # by binary name only — `pkill -f /tmp/apapprover.exp` would also match
    # the docker-exec bash shell that carries that path in its own argv and
    # would kill itself (exit 143).
    docker_exec_as_tester "pkill expect || true"
    docker_exec_as_tester "pkill apapprover || true"
    docker_exec_as_tester "pkill apsigner || true"
    sleep 1
}

setup_appass_file_unlock() {
    # After the apapprover-driven happy path, restart apsigner with the
    # appass-file helper as the unlock command. This validates the production
    # `passphrase_command_argv` runtime path (same plumbing exercised by the
    # Go integration test in test/integration/apstore_changepass_test.go) but
    # under a real systemd-free apsigner process started the way operators
    # actually invoke it.
    local root="/home/$TEST_USER/aplane"
    local pass_file="$root/apsigner/identities/default/passphrase"
    local unlock_file="$root/apsigner/identities/default/unlock.yaml"

    docker_exec_as_tester "umask 077 && printf '%s' '$TEST_PASSPHRASE' > '$pass_file'"
    docker_exec_as_tester "cat > '$unlock_file' <<'YAML'
passphrase_command_argv:
    - $root/apsigner/bin/appass-file
    - $pass_file
YAML"

    docker exec -d --user "$TEST_USER" "$CONTAINER_NAME" bash -lc \
        ". $root/apenv.sh && exec apsigner > /tmp/apsigner-passfile.log 2>&1"

    local i
    for i in $(seq 1 30); do
        if docker_exec_as_tester "grep -q 'SSH server listening' /tmp/apsigner-passfile.log 2>/dev/null"; then
            return 0
        fi
        sleep 1
    done
    docker_exec_as_tester "cat /tmp/apsigner-passfile.log" >&2 || true
    die "apsigner did not become ready with appass-file unlock"
}

verify_appass_file_unlock() {
    if ! docker_exec_as_tester "grep -qF 'passphrase loaded via passphrase command' /tmp/apsigner-passfile.log"; then
        docker_exec_as_tester "cat /tmp/apsigner-passfile.log" >&2 || true
        die "appass-file auto-unlock did not log 'passphrase loaded via passphrase command'"
    fi
    if docker_exec_as_tester "grep -qF 'passphrase_command_argv: command failed' /tmp/apsigner-passfile.log"; then
        docker_exec_as_tester "cat /tmp/apsigner-passfile.log" >&2 || true
        die "appass-file helper failed at startup"
    fi
}

teardown_appass_file() {
    docker_exec_as_tester "pkill apsigner || true"
    sleep 1
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "rm -f '$root/apsigner/identities/default/passphrase' '$root/apsigner/identities/default/unlock.yaml'"
}

run_uninstaller() {
    # Use the installed uninstaller, which is the path available to repo-less
    # local installs. Pass --local explicitly to skip the mode-selection prompt.
    docker_exec_as_tester "cd /home/$TEST_USER/aplane && expect <<'EXPECT'
set timeout 120
spawn ./uninstall.sh --local /home/$TEST_USER/aplane
expect {
  \"Remove aplane env lines from *\" { send \"\r\"; exp_continue }
  \"Local uninstall complete.\" { }
  timeout { exit 20 }
  eof {}
}
set result [wait]
exit [lindex \$result 3]
EXPECT"
}

verify_uninstall() {
    local root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "test -d $root/apsigner"
    docker_exec_as_tester "test -f $root/apsigner/config.yaml"
    docker_exec_as_tester "test -f $root/apsigner/identities/default/.keystore"
    docker_exec_as_tester "test ! -e $root/apsigner/bin/apsigner"
    docker_exec_as_tester "test ! -e $root/apsigner/bin/approbe"
    docker_exec_as_tester "test -d $root/apclient"
    docker_exec_as_tester "test -f $root/apclient/config.yaml"
    docker_exec_as_tester "test ! -e $root/apclient/bin/apshell"
    docker_exec_as_tester "test ! -e $root/apenv.sh"
    docker_exec_as_tester "test ! -e $root/apconsole.yaml"
    docker_exec_as_tester "test ! -e $root/start.sh"
    docker_exec_as_tester "! grep -qF '$root/apenv.sh' /home/$TEST_USER/.bashrc"
}

main() {
    parse_args "$@"
    command -v docker >/dev/null 2>&1 || die "docker not found"
    trap cleanup EXIT

    log "Building local release tarball"
    build_or_resolve_tarball

    log "Building Ubuntu test image"
    build_image

    log "Starting container"
    docker run --name "$CONTAINER_NAME" -d "$IMAGE_NAME" >/dev/null

    log "Creating test user"
    create_test_user

    log "Running local installer"
    run_installer

    log "Verifying installed local layout"
    verify_install

    log "Checking appass local-mode detection"
    verify_appass_local_detection

    log "Generating client SSH key"
    generate_client_ssh_key

    log "Starting apsigner (background)"
    start_apsigner

    log "Checking approbe gating blocks local install while signer runs"
    verify_approbe_gating_install

    log "Seeding client known_hosts with signer host key"
    populate_known_hosts

    log "Starting apapprover (unlocks signer, auto-approves requests)"
    start_apapprover

    log "Requesting API token via apshell"
    run_request_token

    log "Verifying client can reach signer with issued token"
    verify_signer_reachable

    log "Creating preserved local state markers"
    create_local_preserved_state_markers

    log "Recording local state fingerprint"
    record_local_state_fingerprint

    log "Shutting down signer and approver"
    shutdown_services

    log "Checking stopped local in-place upgrade"
    run_local_reinstaller

    log "Verifying local layout after stopped in-place upgrade"
    verify_install

    log "Verifying local state survived stopped in-place upgrade"
    verify_local_state_fingerprint

    log "Configuring appass-file auto-unlock"
    setup_appass_file_unlock

    log "Verifying signer auto-unlocks via appass-file"
    verify_appass_file_unlock

    log "Tearing down appass-file artifacts"
    teardown_appass_file

    log "Running local uninstaller"
    run_uninstaller

    log "Verifying uninstall removed the install tree"
    verify_uninstall

    log "Verifying local state survived uninstall"
    verify_local_state_fingerprint

    log "Docker local smoke test passed"
}

main "$@"
