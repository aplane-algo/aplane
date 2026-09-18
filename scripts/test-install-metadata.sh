#!/bin/bash
# Exercise installer metadata without touching a real installation or daemon.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT

# Load only the version helpers and metadata functions from the real installer.
source /dev/stdin <<< "$(sed -n '/^MIN_SUPPORTED_UPGRADE_VERSION=/,/^toml_escape() {/p' "$repo_root/install.sh" | sed '$d')"
source /dev/stdin <<< "$(sed -n '/^prepare_release_metadata() {/,/^# --- Shared config templates ---/p' "$repo_root/install.sh" | sed '/^prepare_release_metadata$/d; $d')"

SCRIPT_DIR="$test_root/source"
BIN_SRC="$SCRIPT_DIR/bin"
RELEASE_METADATA_SRC="$SCRIPT_DIR/release.json"
CLIENT_MODE=0
FORCE_UPGRADE=0
mkdir -p "$BIN_SRC" "$SCRIPT_DIR/.git"

fake_binary() {
    local name="$1" version="$2"
    printf '#!/bin/bash\nprintf "%%s\\n" "%s %s (commit: abc12345, built: 2026-09-17T23:45:43Z, linux/amd64)"\n' "$name" "$version" > "$BIN_SRC/$name"
    chmod +x "$BIN_SRC/$name"
}
expect_failure() {
    if ( "$@" ) >"$test_root/error" 2>&1; then
        echo "Expected failure: $*" >&2
        exit 1
    fi
}

fake_binary apsigner v0.37.0-15-gabc12345-dirty
fake_binary apshell v0.37.0-15-gabc12345-dirty
prepare_release_metadata
install_release_metadata "$test_root/installed/install"
test "$(release_metadata_version "$test_root/installed/install/release.json")" = v0.37.0-15-gabc12345-dirty
# The second run passes the ordinary upgrade gate and preserves unrelated state.
printf 'existing state\n' > "$test_root/installed/state"
require_supported_upgrade "$test_root/installed/install/release.json" 'local install' "$test_root/installed"
prepare_release_metadata
install_release_metadata "$test_root/installed/install"
test "$(cat "$test_root/installed/state")" = 'existing state'

expect_failure require_supported_upgrade "$test_root/missing.json" 'local install' "$test_root/legacy"
FORCE_UPGRADE=1
require_supported_upgrade "$test_root/missing.json" 'local install' "$test_root/legacy"
prepare_release_metadata
install_release_metadata "$test_root/legacy/install"
FORCE_UPGRADE=0
require_supported_upgrade "$test_root/legacy/install/release.json" 'local install' "$test_root/legacy"

fake_binary apshell v0.36.0
expect_failure prepare_release_metadata
CLIENT_MODE=1
prepare_release_metadata
test "$(printf '%s\n' "$RELEASE_METADATA_JSON" | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')" = v0.36.0
fake_binary apshell dev
expect_failure prepare_release_metadata

# Archives require their own metadata; supplied metadata takes precedence.
rmdir "$SCRIPT_DIR/.git"
expect_failure prepare_release_metadata
cp "$test_root/installed/install/release.json" "$RELEASE_METADATA_SRC"
prepare_release_metadata
install_release_metadata "$test_root/archive-install/install"
cmp "$RELEASE_METADATA_SRC" "$test_root/archive-install/install/release.json"
printf '{"version":"dev"}\n' > "$RELEASE_METADATA_SRC"
expect_failure prepare_release_metadata
echo 'Installer metadata tests passed.'
