#!/usr/bin/env bash
set -euo pipefail

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
  shift
fi

DATA_DIR="${1:-${APCLIENT_DATA:-}}"
if [[ -z "$DATA_DIR" ]]; then
  echo "Error: client data directory must be provided." >&2
  echo "Usage: APCLIENT_DATA=\$HOME/aplane/apclient ./scripts/config-mcp.sh [--force]" >&2
  echo "       ./scripts/config-mcp.sh [--force] \$HOME/aplane/apclient [/path/to/apshell]" >&2
  exit 1
fi

MCP_CONFIG="$DATA_DIR/.mcp.json"
APSHELL_BIN="${2:-${APSHELL_BIN:-$DATA_DIR/bin/apshell}}"
TARGET="$MCP_CONFIG"

mkdir -p "$DATA_DIR"

if [[ -f "$MCP_CONFIG" && "$FORCE" != "1" ]]; then
  TARGET="$MCP_CONFIG.aplane-installer.new"
  echo "MCP config already exists at $MCP_CONFIG; leaving it unchanged."
fi

cat >"$TARGET" <<EOF
{
  "mcpServers": {
    "aplane": {
      "command": "$APSHELL_BIN",
      "args": ["--mcp", "-d", "$DATA_DIR"]
    }
  }
}
EOF

echo "Wrote MCP config to $TARGET"
