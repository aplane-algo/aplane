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
CODEX_DIR="$DATA_DIR/.codex"
CODEX_CONFIG="$CODEX_DIR/config.toml"
APSHELL_BIN="${2:-${APSHELL_BIN:-$DATA_DIR/bin/apshell}}"

mkdir -p "$DATA_DIR"

toml_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

TARGET="$MCP_CONFIG"
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

mkdir -p "$CODEX_DIR"
TARGET="$CODEX_CONFIG"
if [[ -f "$CODEX_CONFIG" && "$FORCE" != "1" ]]; then
  TARGET="$CODEX_CONFIG.aplane-installer.new"
  echo "Codex MCP config already exists at $CODEX_CONFIG; leaving it unchanged."
fi

APSHELL_BIN_TOML="$(toml_escape "$APSHELL_BIN")"
DATA_DIR_TOML="$(toml_escape "$DATA_DIR")"
cat >"$TARGET" <<EOF
[mcp_servers.aplane]
command = "$APSHELL_BIN_TOML"
args = ["--mcp", "-d", "$DATA_DIR_TOML"]
EOF

echo "Wrote Codex MCP config to $TARGET"
