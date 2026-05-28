#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="$ROOT_DIR/examples/external_plugins"
DATA_DIR="${APCLIENT_DATA:-$HOME/aplane/apclient}"
TARGET_DIR="$DATA_DIR/plugins.available"
CONFIG_PATH="$DATA_DIR/plugins.yaml"

echo "Installing example plugins from $EXAMPLES_DIR"
echo "Target plugin catalog directory: $TARGET_DIR"

if [[ ! -d "$EXAMPLES_DIR" ]]; then
  echo "Error: example plugins directory not found: $EXAMPLES_DIR" >&2
  exit 1
fi

cd "$ROOT_DIR"

echo "Installing example plugin dependencies..."
make install-example-plugins

echo "Building example plugins..."
make build-example-plugins

echo "Removing existing plugin catalog directory..."
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

echo "Copying example plugins..."
enabled_plugins=()
for plugin_dir in "$EXAMPLES_DIR"/*/; do
  if [[ -f "$plugin_dir/manifest.json" ]]; then
    plugin_name="$(basename "$plugin_dir")"
    missing_payload=0
    for payload_file in manifest.json checksums.sha256 "$plugin_name"; do
      if [[ ! -f "$plugin_dir/$payload_file" ]]; then
        echo "  Skipped $plugin_name (missing runtime payload file: $payload_file)"
        missing_payload=1
        break
      fi
    done
    if [[ "$missing_payload" -ne 0 ]]; then
      continue
    fi
    cp -R "$plugin_dir" "$TARGET_DIR/$plugin_name"
    enabled_plugins+=("$plugin_name")
    echo "  Installed and enabled $plugin_name"
  fi
done

{
  if [[ ${#enabled_plugins[@]} -eq 0 ]]; then
    echo "enabled_plugins: []"
  else
    echo "enabled_plugins:"
    for plugin_name in "${enabled_plugins[@]}"; do
      echo "  - $plugin_name"
    done
  fi
} > "$CONFIG_PATH"

echo "Example plugins installed to $TARGET_DIR"
echo "Enabled default example plugins in $CONFIG_PATH"
