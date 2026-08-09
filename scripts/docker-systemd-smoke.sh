#!/usr/bin/env bash
# Smoke-test the bootstrap release tarball in an Ubuntu systemd container.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH=""
DIST_DIR=""
VERSION="docker-smoke"
TARBALL=""
SKIP_BUILD=0
KEEP_CONTAINER=0
IMAGE_NAME=""
CONTAINER_NAME="aplane-systemd-smoke-$$"
TEST_USER="tester"
TEST_PASSPHRASE="passphrase-for-docker-smoke"
OPERATOR_ROOT="/home/$TEST_USER/aplane-systemd"

usage() {
    cat <<'EOF'
Usage: scripts/docker-systemd-smoke.sh [options]

Options:
  --tarball <path>      Use an existing aplane_<version>_linux_<arch>.tar.gz
  --version <version>   Archive label for locally built tarball (default: docker-smoke)
  --arch <amd64|arm64>  Architecture to package/test (default: host arch)
  --skip-build          Reuse existing bin/<arch> binaries when building the tarball
  --keep-container      Leave the container running for debugging
  -h, --help            Show this help

This test requires Docker privileges. It starts an Ubuntu 24.04 container with
systemd, installs the local release tarball in --systemd mode, verifies the
service/files/permissions, verifies the installer refuses to run while the
systemd service is active, runs appass --check to confirm systemd-mode detection,
drives `apshell request-token` end-to-end as the non-root installing user (with
apapprover unlocking the signer and auto-approving), confirms the client can
reach the signer with the issued token, verifies a stopped in-place systemd
upgrade preserves state, stages the on-disk state of
`appass set systemd-creds` (passphrase.cred + unlock.yaml + unit
LoadCredentialEncrypted= directive), then runs the bundled systemd uninstaller
and verifies signer data is preserved. (Runtime auto-unlock via systemd's
credential namespace is not asserted: LoadCredential[Encrypted]= is silently a
no-op in privileged systemd containers.)
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

wait_for_systemd() {
    local state=""
    for _ in $(seq 1 60); do
        state="$(docker_exec systemctl is-system-running 2>/dev/null || true)"
        case "$state" in
            running|degraded)
                return 0
                ;;
        esac
        sleep 1
    done
    docker logs "$CONTAINER_NAME" >&2 || true
    die "systemd did not become ready (last state: ${state:-unknown})"
}

build_image() {
    IMAGE_NAME="aplane-systemd-smoke:ubuntu-24.04"
    local dockerfile
    dockerfile="$(mktemp)"
    cat > "$dockerfile" <<'DOCKERFILE'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash ca-certificates expect gzip iproute2 openssh-client passwd procps sudo systemd systemd-sysv tar util-linux && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
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

run_installer() {
    docker cp "$TARBALL" "$CONTAINER_NAME:/tmp/aplane.tar.gz"
    docker_exec_bash "cd /tmp && tar -xzf /tmp/aplane.tar.gz"
    docker_exec useradd -m -s /bin/bash "$TEST_USER"

docker_exec_bash "cd /tmp/aplane && expect <<'EXPECT'
set timeout 180
set completed 0
spawn env SUDO_USER=$TEST_USER ./install.sh --systemd $OPERATOR_ROOT
expect {
  \"Proceed with systemd install?*\" { send \"\r\" }
  timeout { exit 10 }
}
expect {
  \"Enter passphrase:\" { send \"$TEST_PASSPHRASE\r\" }
  timeout { exit 12 }
}
expect {
  \"Confirm passphrase:\" { send \"$TEST_PASSPHRASE\r\" }
  timeout { exit 13 }
}
expect {
  \"Add apenv.sh to *\" { send \"y\r\"; exp_continue }
  \"=== Installation complete ===\" { set completed 1; exp_continue }
  timeout { exit 15 }
  eof {}
}
set result [wait]
set rc [lindex \$result 3]
if {\$completed != 1} {
  exit 16
}
exit \$rc
EXPECT"
}

verify_install_layout() {
    docker_exec_bash "test -x /usr/local/bin/apsigner"
    docker_exec_bash "test -x /usr/local/bin/appass"
    docker_exec_bash "test -x /usr/local/bin/approbe"
    docker_exec_bash "test -x /var/lib/apsigner/install/uninstall.sh"
    docker_exec_bash "grep -qx '$OPERATOR_ROOT' /var/lib/apsigner/install/operator-root"
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/.keystore"
    docker_exec_bash "[ \"\$(stat -c '%U:%G %a' /var/lib/apsigner)\" = 'aplane:aplane 700' ]"
    docker_exec_bash "[ \"\$(stat -c '%U:%G %a' /var/lib/apsigner/backups)\" = 'aplane:aplane 700' ]"
    docker_exec_bash "[ \"\$(stat -c '%U:%G %a' /var/lib/apsigner/config.yaml)\" = 'aplane:aplane 600' ]"
    docker_exec_bash "[ \"\$(stat -c '%U:%G %a' /run/apsigner)\" = 'aplane:aplane 750' ]"
    docker_exec_bash "[ \"\$(stat -c '%U:%G %a' /run/apsigner/aplane.sock)\" = 'aplane:aplane 660' ]"
    docker_exec_as_tester "! test -x /var/lib/apsigner && ! test -r /var/lib/apsigner/config.yaml"
    docker_exec_as_tester "test -S /run/apsigner/aplane.sock"
    docker_exec_bash "grep -qx 'require_memory_protection: true' /var/lib/apsigner/config.yaml"
    docker_exec_bash "grep -qx 'AmbientCapabilities=CAP_IPC_LOCK' /etc/systemd/system/apsigner.service"
    docker_exec_bash "grep -qx 'LimitMEMLOCK=infinity' /etc/systemd/system/apsigner.service"
    docker_exec_as_tester "test -f $OPERATOR_ROOT/apclient/config.yaml"
    docker_exec_as_tester "test -f $OPERATOR_ROOT/apenv.sh"
    docker_exec_as_tester "test -f $OPERATOR_ROOT/apconsole.yaml"
    docker_exec_as_tester ". $OPERATOR_ROOT/apenv.sh && \
        [ \"\$APLANE_INSTALL_ROOT\" = '$OPERATOR_ROOT' ] && \
        [ \"\$APLANE_BINDIR\" = '/usr/local/bin' ] && \
        [ \"\$APSIGNER_DATA\" = '/var/lib/apsigner' ] && \
        [ \"\$APCLIENT_DATA\" = '$OPERATOR_ROOT/apclient' ] && \
        command -v apsigner >/dev/null && \
        command -v apshell >/dev/null"
    docker_exec_as_tester "grep -q '^signer_data: /var/lib/apsigner$' $OPERATOR_ROOT/apconsole.yaml"
    docker_exec_bash "systemctl is-enabled apsigner >/dev/null"
}

verify_install() {
    verify_install_layout
    docker_exec_bash "systemctl is-active apsigner >/dev/null"
}

verify_appass_systemd_detection() {
    # appass --check runs the mode-detection / ownership gate non-interactively
    # and exits 0 only when the installed layout is consistent with systemd mode.
    # No TTY, no TUI, no timeout fiddling.
    docker_exec_bash "appass --check -d /var/lib/apsigner"
}

verify_systemd_status_gating_install() {
    docker_exec_bash "set +e
cd /tmp/aplane
env SUDO_USER=$TEST_USER ./install.sh --systemd '$OPERATOR_ROOT' --no-start > /tmp/systemd-gating-install.log 2>&1
rc=\$?
set -e
cat /tmp/systemd-gating-install.log
if [ \"\$rc\" -eq 0 ]; then
    echo 'install.sh unexpectedly succeeded while apsigner.service was active' >&2
    exit 1
fi
systemctl is-active apsigner | grep -qx active
grep -qF 'apsigner.service is currently active' /tmp/systemd-gating-install.log
grep -qF 'sudo systemctl stop apsigner' /tmp/systemd-gating-install.log"
}

run_uninstaller() {
    # Pass --systemd explicitly so the smoke test exercises deterministic
    # systemd uninstall rather than the interactive mode chooser.
    docker_exec_bash "expect <<'EXPECT'
set timeout 120
spawn env SUDO_USER=$TEST_USER /var/lib/apsigner/install/uninstall.sh --systemd
expect {
  \"Remove aplane env lines from *\" { send \"\r\"; exp_continue }
  eof
}
set result [wait]
exit [lindex \$result 3]
EXPECT"
}

verify_uninstaller_does_not_guess_operator_root() {
    local fallback_root="/home/$TEST_USER/aplane"
    docker_exec_as_tester "mkdir -p '$fallback_root/apclient' && touch '$fallback_root/apclient/separate-local-client'"
    docker_exec_as_tester "mkdir -p '$OPERATOR_ROOT/apclient' && touch '$OPERATOR_ROOT/apclient/no-operator-root-client'"
    docker_exec_bash "rm -f /var/lib/apsigner/install/operator-root"

    docker_exec_bash "cd /tmp/aplane && expect <<'EXPECT'
set timeout 120
spawn env SUDO_USER=$TEST_USER ./uninstall.sh --systemd
expect {
  \"Remove aplane env lines from *\" { send \"\r\"; exp_continue }
  eof
}
set result [wait]
exit [lindex \$result 3]
EXPECT"

    docker_exec_as_tester "test -f '$fallback_root/apclient/separate-local-client'"
    docker_exec_as_tester "test -f '$OPERATOR_ROOT/apclient/no-operator-root-client'"
}

run_repo_uninstaller_with_operator_root() {
    docker_exec_bash "cd /tmp/aplane && expect <<'EXPECT'
set timeout 120
spawn env SUDO_USER=$TEST_USER ./uninstall.sh --systemd $OPERATOR_ROOT
expect {
  \"Remove aplane env lines from *\" { send \"\r\"; exp_continue }
  eof
}
set result [wait]
exit [lindex \$result 3]
EXPECT"
}

generate_client_ssh_key() {
    # systemd install writes the per-user aplane/apclient dir plus apenv.sh
    # and apconsole.yaml, but does NOT generate an SSH client key. Do it now.
    docker_exec_as_tester "mkdir -p $OPERATOR_ROOT/apclient/.ssh && \
        chmod 700 $OPERATOR_ROOT/apclient/.ssh && \
        ssh-keygen -t ed25519 -f $OPERATOR_ROOT/apclient/.ssh/id_ed25519 -N '' -q"
}

populate_known_hosts() {
    # Signer's host key lives at /var/lib/apsigner/.ssh/ssh_host_key (mode 0600
    # aplane:aplane) — tester is in the aplane group but group bits are 0, so
    # only root can read the private key. Derive the public half as root via
    # ssh-keygen -y, then append it to tester's known_hosts.
    local pub
    pub="$(docker_exec_bash "ssh-keygen -y -f /var/lib/apsigner/.ssh/ssh_host_key")"
    [ -n "$pub" ] || die "could not derive signer host pubkey"
    docker_exec_as_tester "ssh_url=\$(awk '
            \$1 == \"primary:\" { in_primary=1; next }
            in_primary && \$1 == \"url:\" { print \$2; exit }
        ' $OPERATOR_ROOT/apclient/endpoints.yaml)
        ssh_port=\${ssh_url##*:}
        [ -n \"\$ssh_port\" ] && [ \"\$ssh_port\" != \"\$ssh_url\" ] || { echo 'could not read primary endpoint SSH port'; exit 1; }
        { printf '[localhost]:%s %s\n' \"\$ssh_port\" '$pub'; \
          printf '[127.0.0.1]:%s %s\n' \"\$ssh_port\" '$pub'; } > $OPERATOR_ROOT/apclient/.ssh/known_hosts && \
        chmod 600 $OPERATOR_ROOT/apclient/.ssh/known_hosts"
}

start_apapprover() {
    # apapprover runs as tester over IPC at /run/apsigner/aplane.sock.
    # tester is in the aplane group (added by install.sh), and `docker exec
    # --user tester` creates a fresh session whose supplementary groups are
    # resolved at exec-time — so aplane membership is live even though the
    # install never logged out.
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
        ". $OPERATOR_ROOT/apenv.sh && exec expect /tmp/apapprover.exp > /tmp/apapprover.log 2>&1"

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
    # AutoConfirm=true in script mode rejects unknown hosts; known_hosts is
    # seeded, so request-token proceeds without interactive prompts. The
    # issued token lands at $APCLIENT_DATA/aplane.token.
    docker_exec_as_tester "echo 'request-token' > /tmp/req-token.script"
    docker_exec_as_tester ". $OPERATOR_ROOT/apenv.sh && \
        apshell -script /tmp/req-token.script 2>&1 | tee /tmp/req-token.log"
    docker_exec_as_tester "test -s $OPERATOR_ROOT/apclient/aplane.token" \
        || die "request-token did not produce a client token file"
}

verify_signer_reachable() {
    docker_exec_as_tester "echo 'status' > /tmp/status.script"
    local out
    out="$(docker_exec_as_tester ". $OPERATOR_ROOT/apenv.sh && \
        apshell -script /tmp/status.script 2>&1")"
    printf '%s\n' "$out"
    printf '%s' "$out" | grep -qE 'Signer:[[:space:]]*Connected' \
        || die "apshell status did not report Signer: Connected"
}

create_systemd_preserved_state_markers() {
    docker_exec_as_tester "mkdir -p '$OPERATOR_ROOT/apclient/plugins.available' '$OPERATOR_ROOT/apclient/scripts' '$OPERATOR_ROOT/apclient/cache' && \
        printf 'custom plugin marker\n' > '$OPERATOR_ROOT/apclient/plugins.available/custom-plugin-marker.txt' && \
        printf 'enabled_plugins:\n  - custom-plugin\n' > '$OPERATOR_ROOT/apclient/plugins.yaml' && \
        printf 'console.log(\"custom script marker\");\n' > '$OPERATOR_ROOT/apclient/scripts/custom-script.js' && \
        printf 'custom cache marker\n' > '$OPERATOR_ROOT/apclient/cache/custom-cache-marker.txt'"
}

record_systemd_in_place_state_fingerprint() {
    docker_exec_bash "set -e
files='
/var/lib/apsigner/config.yaml
/var/lib/apsigner/identities/default/.keystore
$OPERATOR_ROOT/apclient/config.yaml
$OPERATOR_ROOT/apclient/aplane.token
$OPERATOR_ROOT/apclient/.ssh/id_ed25519
$OPERATOR_ROOT/apclient/.ssh/known_hosts
$OPERATOR_ROOT/apclient/plugins.yaml
$OPERATOR_ROOT/apclient/plugins.available/custom-plugin-marker.txt
$OPERATOR_ROOT/apclient/scripts/custom-script.js
$OPERATOR_ROOT/apclient/cache/custom-cache-marker.txt
'
sha256sum \$files > /tmp/systemd-in-place-state-baseline.sha256
stat -c '%U:%G %a %n' \$files > /tmp/systemd-in-place-state-baseline.stat"
}

verify_systemd_in_place_state_fingerprint() {
    docker_exec_bash "set -e
files='
/var/lib/apsigner/config.yaml
/var/lib/apsigner/identities/default/.keystore
$OPERATOR_ROOT/apclient/config.yaml
$OPERATOR_ROOT/apclient/aplane.token
$OPERATOR_ROOT/apclient/.ssh/id_ed25519
$OPERATOR_ROOT/apclient/.ssh/known_hosts
$OPERATOR_ROOT/apclient/plugins.yaml
$OPERATOR_ROOT/apclient/plugins.available/custom-plugin-marker.txt
$OPERATOR_ROOT/apclient/scripts/custom-script.js
$OPERATOR_ROOT/apclient/cache/custom-cache-marker.txt
'
sha256sum \$files > /tmp/systemd-in-place-state-current.sha256
stat -c '%U:%G %a %n' \$files > /tmp/systemd-in-place-state-current.stat
diff -u /tmp/systemd-in-place-state-baseline.sha256 /tmp/systemd-in-place-state-current.sha256
diff -u /tmp/systemd-in-place-state-baseline.stat /tmp/systemd-in-place-state-current.stat"
}

run_stopped_systemd_reinstaller() {
    docker_exec systemctl stop apsigner
docker_exec_bash "cd /tmp/aplane && expect <<'EXPECT'
set timeout 180
set completed 0
spawn env SUDO_USER=$TEST_USER ./install.sh --systemd $OPERATOR_ROOT
expect {
  \"Proceed with systemd install?*\" { send \"\r\"; exp_continue }
  \"Add apenv.sh to *\" { send \"y\r\"; exp_continue }
  \"=== Installation complete ===\" { set completed 1; exp_continue }
  timeout { exit 17 }
  eof {}
}
set result [wait]
set rc [lindex \$result 3]
if {\$completed != 1} {
  exit 18
}
exit \$rc
EXPECT"
}

shutdown_client_services() {
    # apsigner is systemd-managed and uninstall will stop it; only kill the
    # apapprover expect wrapper we started. Match by binary name, not -f,
    # to avoid pkill signalling the docker-exec bash (see local-smoke fix).
    docker_exec_as_tester "pkill expect || true"
    docker_exec_as_tester "pkill apapprover || true"
    sleep 1
}

verify_uninstall() {
    docker_exec_bash "test ! -e /usr/local/bin/apsigner"
    docker_exec_bash "test ! -e /usr/local/bin/approbe"
    docker_exec_bash "test ! -e /etc/systemd/system/apsigner.service"
    docker_exec_bash "test ! -e /lib/systemd/system/apsigner.service"
    docker_exec_bash "test ! -e /etc/sudoers.d/99-apsigner-systemctl"
    docker_exec_bash "test ! -e /var/lib/apsigner/install/uninstall.sh"
    docker_exec_as_tester "test ! -e $OPERATOR_ROOT/apclient"
    docker_exec_as_tester "test ! -e $OPERATOR_ROOT/apenv.sh"
    docker_exec_as_tester "test ! -e $OPERATOR_ROOT/apconsole.yaml"
    docker_exec_as_tester "test -f /home/$TEST_USER/aplane/apclient/separate-local-client"
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/.keystore"
    docker_exec_bash "id aplane >/dev/null"
}

setup_appass_file_unlock() {
    # Restart apsigner with the appass-file helper as the unlock command.
    # Validates the systemd `passphrase_command_argv` runtime path under
    # systemd. Independent of systemd-creds, so this works in containers where
    # LoadCredential[Encrypted]= silently doesn't materialize.
    local pass_file="/var/lib/apsigner/identities/default/passphrase"
    local unlock_file="/var/lib/apsigner/identities/default/unlock.yaml"

    docker_exec systemctl stop apsigner

    docker_exec_bash "printf '%s' '$TEST_PASSPHRASE' > '$pass_file'"
    docker_exec chown aplane:aplane "$pass_file"
    docker_exec chmod 600 "$pass_file"

    docker_exec_bash "cat > '$unlock_file' <<'YAML'
passphrase_command_argv:
    - /usr/local/bin/appass-file
    - $pass_file
YAML"
    docker_exec chown aplane:aplane "$unlock_file"
    docker_exec chmod 640 "$unlock_file"

    docker_exec systemctl start apsigner

    local i
    for i in $(seq 1 15); do
        if docker_exec systemctl is-active apsigner >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    if ! docker_exec systemctl is-active apsigner >/dev/null 2>&1; then
        docker_exec_bash "journalctl -u apsigner --no-pager -n 30" >&2 || true
        die "apsigner did not become active with appass-file unlock"
    fi
}

verify_appass_file_unlock() {
    local i
    for i in $(seq 1 10); do
        if docker_exec_bash "journalctl -u apsigner --no-pager -n 100 | grep -qF 'passphrase loaded via passphrase command'"; then
            break
        fi
        sleep 1
    done
    if ! docker_exec_bash "journalctl -u apsigner --no-pager -n 100 | grep -qF 'passphrase loaded via passphrase command'"; then
        docker_exec_bash "journalctl -u apsigner --no-pager -n 50" >&2 || true
        die "appass-file auto-unlock did not log 'passphrase loaded via passphrase command'"
    fi
    if docker_exec_bash "journalctl -u apsigner --no-pager -n 100 | grep -qF 'passphrase_command_argv: command failed'"; then
        docker_exec_bash "journalctl -u apsigner --no-pager -n 50" >&2 || true
        die "appass-file helper failed at startup"
    fi
}

teardown_appass_file() {
    docker_exec systemctl stop apsigner
    docker_exec rm -f /var/lib/apsigner/identities/default/passphrase /var/lib/apsigner/identities/default/unlock.yaml
}

setup_systemd_creds_artifacts() {
    # Simulate the on-disk state left by `appass set systemd-creds`: encrypt
    # the passphrase via the systemd helper, write unlock.yaml, and inject
    # the matching LoadCredentialEncrypted= directive into the unit. We do
    # NOT restart the daemon: systemd's credential-namespace mounting at
    # /run/credentials/<service>/ is unreliable in privileged containers
    # (LoadCredential[Encrypted]= is silently a no-op), so runtime auto-unlock
    # is not testable here. This smoke test only validates that the public
    # uninstall flow preserves those files.
    local cred_file="/var/lib/apsigner/identities/default/passphrase.cred"
    local unlock_file="/var/lib/apsigner/identities/default/unlock.yaml"

    docker_exec systemctl stop apsigner

    docker_exec_bash "printf '%s' '$TEST_PASSPHRASE' | /usr/local/bin/appass-systemd-creds write '$cred_file' >/dev/null"
    docker_exec chown root:root "$cred_file"
    docker_exec chmod 600 "$cred_file"

    docker_exec_bash "cat > '$unlock_file' <<'YAML'
passphrase_command_argv:
    - /usr/local/bin/appass-systemd-creds
    - $cred_file
YAML"
    docker_exec chown aplane:aplane "$unlock_file"
    docker_exec chmod 640 "$unlock_file"

    docker_exec_bash "sed -i '/^\\[Service\\]\$/a LoadCredentialEncrypted=aplane-passphrase:$cred_file' /etc/systemd/system/apsigner.service"
    docker_exec systemctl daemon-reload
}

verify_systemd_creds_artifacts() {
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/passphrase.cred"
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/unlock.yaml"
    docker_exec_bash "grep -qF 'LoadCredentialEncrypted=aplane-passphrase:/var/lib/apsigner/identities/default/passphrase.cred' /etc/systemd/system/apsigner.service"
}

record_systemd_signer_state_fingerprint() {
    docker_exec_bash "set -e
files='
/var/lib/apsigner/config.yaml
/var/lib/apsigner/identities/default/.keystore
/var/lib/apsigner/identities/default/passphrase.cred
/var/lib/apsigner/identities/default/unlock.yaml
'
sha256sum \$files > /tmp/systemd-signer-state-baseline.sha256
stat -c '%U:%G %a %n' \$files > /tmp/systemd-signer-state-baseline.stat"
}

verify_systemd_signer_state_fingerprint() {
    docker_exec_bash "set -e
files='
/var/lib/apsigner/config.yaml
/var/lib/apsigner/identities/default/.keystore
/var/lib/apsigner/identities/default/passphrase.cred
/var/lib/apsigner/identities/default/unlock.yaml
'
sha256sum \$files > /tmp/systemd-signer-state-current.sha256
stat -c '%U:%G %a %n' \$files > /tmp/systemd-signer-state-current.stat
diff -u /tmp/systemd-signer-state-baseline.sha256 /tmp/systemd-signer-state-current.sha256
diff -u /tmp/systemd-signer-state-baseline.stat /tmp/systemd-signer-state-current.stat"
}

verify_cred_preserved_after_uninstall() {
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/passphrase.cred"
    docker_exec_bash "test -f /var/lib/apsigner/identities/default/unlock.yaml"
    docker_exec_bash "test ! -e /etc/systemd/system/apsigner.service"
}

main() {
    parse_args "$@"
    command -v docker >/dev/null 2>&1 || die "docker not found"
    trap cleanup EXIT

    log "Building local release tarball"
    build_or_resolve_tarball

    log "Building Ubuntu systemd test image"
    build_image

    log "Starting systemd container"
    docker run --name "$CONTAINER_NAME" \
        --privileged \
        --cgroupns=host \
        --tmpfs /run \
        --tmpfs /run/lock \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -d "$IMAGE_NAME" >/dev/null
    wait_for_systemd

    log "Running systemd installer"
    run_installer

    log "Verifying installed systemd layout"
    verify_install

    log "Checking systemd status gating blocks systemd install while service runs"
    verify_systemd_status_gating_install

    log "Checking appass systemd-mode detection"
    verify_appass_systemd_detection

    log "Generating client SSH key for $TEST_USER"
    generate_client_ssh_key

    log "Seeding client known_hosts with signer host key"
    populate_known_hosts

    log "Starting apapprover as $TEST_USER (unlocks signer, auto-approves)"
    start_apapprover

    log "Requesting API token via apshell (as $TEST_USER)"
    run_request_token

    log "Verifying client can reach signer with issued token"
    verify_signer_reachable

    log "Creating preserved systemd operator state markers"
    create_systemd_preserved_state_markers

    log "Recording systemd in-place state fingerprint"
    record_systemd_in_place_state_fingerprint

    log "Shutting down client-side services"
    shutdown_client_services

    log "Checking stopped systemd in-place upgrade"
    run_stopped_systemd_reinstaller

    log "Verifying systemd layout after stopped in-place upgrade"
    verify_install_layout

    log "Verifying systemd state survived stopped in-place upgrade"
    verify_systemd_in_place_state_fingerprint

    log "Configuring appass-file auto-unlock"
    setup_appass_file_unlock

    log "Verifying signer auto-unlocks via appass-file"
    verify_appass_file_unlock

    log "Tearing down appass-file artifacts"
    teardown_appass_file

    log "Setting up systemd-creds artifacts (passphrase.cred + unit binding)"
    setup_systemd_creds_artifacts

    log "Verifying systemd-creds artifacts in place before round-trip"
    verify_systemd_creds_artifacts

    log "Recording systemd signer state fingerprint"
    record_systemd_signer_state_fingerprint

    log "Running first uninstall (round-trip)"
    run_uninstaller

    log "Verifying passphrase.cred preserved after uninstall"
    verify_cred_preserved_after_uninstall

    log "Verifying signer state survived systemd uninstall"
    verify_systemd_signer_state_fingerprint

    log "Verifying uninstall without recorded operator root leaves user clients untouched"
    verify_uninstaller_does_not_guess_operator_root

    log "Running explicit systemd uninstaller cleanup"
    run_repo_uninstaller_with_operator_root

    log "Verifying uninstall preserves signer data"
    verify_uninstall

    log "Verifying signer state survived final systemd uninstall"
    verify_systemd_signer_state_fingerprint

    log "Docker systemd smoke test passed"
}

main "$@"
