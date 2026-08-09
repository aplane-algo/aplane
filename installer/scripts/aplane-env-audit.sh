#!/usr/bin/env bash
set -euo pipefail

SIGNER_DATA_OVERRIDE=""
CLIENT_DATA_OVERRIDE=""

usage() {
  cat <<'EOF'
Usage: scripts/aplane-env-audit.sh [--signer-data <path>] [--client-data <path>]

Read-only audit of a local APlane environment. The script inspects config files,
ports, listeners, token/key permissions, IPC socket state, and common partial
install issues. It does not modify files.

Defaults:
  signer data: $APSIGNER_DATA, then ~/aplane/apsigner if present, then ~/apsigner
  client data: $APCLIENT_DATA, then ~/aplane/apclient if present, then ~/apclient
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --signer-data)
      [ $# -ge 2 ] || { echo "Error: --signer-data requires a path" >&2; exit 2; }
      SIGNER_DATA_OVERRIDE="$2"
      shift 2
      ;;
    --client-data)
      [ $# -ge 2 ] || { echo "Error: --client-data requires a path" >&2; exit 2; }
      CLIENT_DATA_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

INFO_COUNT=0
PASS_COUNT=0
WARN_COUNT=0

info() {
  INFO_COUNT=$((INFO_COUNT + 1))
  printf 'INFO %-22s %s\n' "$1" "$2"
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS %-22s %s\n' "$1" "$2"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  printf 'WARN %-22s %s\n' "$1" "$2"
}

section() {
  printf '\n== %s ==\n' "$1"
}

expand_user_path() {
  local path="$1"
  case "$path" in
    "~")   printf '%s\n' "$HOME" ;;
    "~/"*) printf '%s\n' "$HOME/${path#~/}" ;;
    *)     printf '%s\n' "$path" ;;
  esac
}

resolve_data_dir() {
  local override="$1"
  local env_value="$2"
  local local_candidate="$3"
  local fallback="$4"
  if [ -n "$override" ]; then
    expand_user_path "$override"
  elif [ -n "$env_value" ]; then
    expand_user_path "$env_value"
  elif [ -d "$local_candidate" ]; then
    printf '%s\n' "$local_candidate"
  else
    printf '%s\n' "$fallback"
  fi
}

resolve_path() {
  local path="$1"
  local base="$2"
  if [ -z "$path" ] || [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s\n' "$base/$path"
  fi
}

read_top_level_value() {
  local path="$1"
  local key="$2"
  [ -f "$path" ] || return 0
  awk -F: -v key="$key" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
      value = substr($0, index($0, ":") + 1)
      sub(/[[:space:]]*#.*/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' "$path"
}

read_section_value() {
  local path="$1"
  local section_name="$2"
  local key="$3"
  [ -f "$path" ] || return 0
  awk -F: -v section_name="$section_name" -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ {
      next
    }
    $0 ~ "^[[:space:]]*" section_name "[[:space:]]*:[[:space:]]*($|#)" {
      in_section = 1
      next
    }
    /^[^[:space:]#][^:]*:/ {
      in_section = 0
    }
    in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
      value = substr($0, index($0, ":") + 1)
      sub(/[[:space:]]*#.*/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' "$path"
}

file_mode() {
  local path="$1"
  if stat -c '%a' "$path" >/dev/null 2>&1; then
    stat -c '%a' "$path"
  else
    stat -f '%Lp' "$path"
  fi
}

check_file_exists() {
  local label="$1"
  local path="$2"
  if [ -f "$path" ]; then
    pass "$label" "$path"
  else
    warn "$label" "missing: $path"
  fi
}

check_dir_exists() {
  local label="$1"
  local path="$2"
  if [ -d "$path" ]; then
    pass "$label" "$path"
  else
    warn "$label" "missing: $path"
  fi
}

check_mode_exact() {
  local label="$1"
  local path="$2"
  local expected="$3"
  if [ ! -e "$path" ]; then
    warn "$label" "missing: $path"
    return
  fi
  local mode
  mode="$(file_mode "$path" 2>/dev/null || true)"
  if [ "$mode" = "$expected" ]; then
    pass "$label" "$path mode $mode"
  else
    warn "$label" "$path mode $mode, expected $expected"
  fi
}

find_binary() {
  local name="$1"
  local data_bin="$2"
  if [ -x "$data_bin/$name" ]; then
    printf '%s\n' "$data_bin/$name"
  elif command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
  fi
}

print_binary() {
  local name="$1"
  local data_bin="$2"
  local bin
  bin="$(find_binary "$name" "$data_bin")"
  if [ -n "$bin" ]; then
    local version=""
    if "$bin" --version >/tmp/aplane-audit-version.$$ 2>/dev/null; then
      version="$(head -n 1 /tmp/aplane-audit-version.$$)"
    fi
    rm -f /tmp/aplane-audit-version.$$
    if [ -n "$version" ]; then
      pass "$name" "$bin ($version)"
    else
      pass "$name" "$bin"
    fi
  else
    warn "$name" "not found in $data_bin or PATH"
  fi
}

listener_lines() {
  local port="$1"
  if [ -z "$port" ]; then
    return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 {print}'
  elif command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | awk -v port=":$port" '$4 ~ port "$" {print}'
  elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | awk -v port=".$port" '$0 ~ /LISTEN/ && $4 ~ port "$" {print}'
  fi
}

check_listener() {
  local label="$1"
  local port="$2"
  if [ -z "$port" ]; then
    warn "$label" "port not configured"
    return
  fi
  local lines
  lines="$(listener_lines "$port" || true)"
  if [ -n "$lines" ]; then
    pass "$label" "port $port is listening"
    printf '%s\n' "$lines" | sed 's/^/  /'
  else
    warn "$label" "no listener found on port $port"
  fi
}

print_processes() {
  local pattern="$1"
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -fl "$pattern" 2>/dev/null || true
  else
    ps aux 2>/dev/null | awk -v pattern="$pattern" '$0 ~ pattern && $0 !~ /awk/ {print}'
  fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SIGNER_DATA="$(resolve_data_dir "$SIGNER_DATA_OVERRIDE" "${APSIGNER_DATA:-}" "$HOME/aplane/apsigner" "$HOME/apsigner")"
CLIENT_DATA="$(resolve_data_dir "$CLIENT_DATA_OVERRIDE" "${APCLIENT_DATA:-}" "$HOME/aplane/apclient" "$HOME/apclient")"

SIGNER_CONFIG="$SIGNER_DATA/config.yaml"
CLIENT_CONFIG="$CLIENT_DATA/config.yaml"

SIGNER_STORE_TRAVERSABLE=0
if [ -x "$SIGNER_DATA" ]; then
  SIGNER_STORE_TRAVERSABLE=1
fi

signer_port=""
signer_ssh_port=""
signer_ipc_path=""
if [ -S /run/apsigner/aplane.sock ]; then
  signer_ipc_path="/run/apsigner/aplane.sock"
elif [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  signer_ipc_path="$(read_top_level_value "$SIGNER_CONFIG" "ipc_path")"
fi
signer_host_key_path=""
signer_authorized_keys_path=""
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  signer_port="$(read_top_level_value "$SIGNER_CONFIG" "signer_port")"
  signer_ssh_port="$(read_section_value "$SIGNER_CONFIG" "ssh" "port")"
  signer_host_key_path="$(read_section_value "$SIGNER_CONFIG" "ssh" "host_key_path")"
  signer_authorized_keys_path="$(read_section_value "$SIGNER_CONFIG" "ssh" "authorized_keys_path")"
fi

client_signer_port="$(read_top_level_value "$CLIENT_CONFIG" "signer_port")"
client_ssh_host="$(read_section_value "$CLIENT_CONFIG" "ssh" "host")"
client_ssh_port="$(read_section_value "$CLIENT_CONFIG" "ssh" "port")"
client_identity_file="$(read_section_value "$CLIENT_CONFIG" "ssh" "identity_file")"
client_known_hosts_path="$(read_section_value "$CLIENT_CONFIG" "ssh" "known_hosts_path")"

[ -n "$signer_ipc_path" ] || signer_ipc_path="$SIGNER_DATA/aplane.sock"
[ -n "$signer_host_key_path" ] || signer_host_key_path=".ssh/ssh_host_key"
[ -n "$signer_authorized_keys_path" ] || signer_authorized_keys_path=".ssh/authorized_keys"
[ -n "$client_identity_file" ] || client_identity_file=".ssh/id_ed25519"
[ -n "$client_known_hosts_path" ] || client_known_hosts_path=".ssh/known_hosts"

signer_host_key_path="$(resolve_path "$signer_host_key_path" "$SIGNER_DATA")"
signer_authorized_keys_path="$(resolve_path "$signer_authorized_keys_path" "$SIGNER_DATA")"
client_identity_file="$(resolve_path "$client_identity_file" "$CLIENT_DATA")"
client_known_hosts_path="$(resolve_path "$client_known_hosts_path" "$CLIENT_DATA")"

echo "APlane Environment Audit"
echo "Repository: $REPO_ROOT"
echo "Read-only: no files will be modified"

section "Data Directories"
info "APSIGNER_DATA" "$SIGNER_DATA"
info "APCLIENT_DATA" "$CLIENT_DATA"
check_dir_exists "signer dir" "$SIGNER_DATA"
check_dir_exists "client dir" "$CLIENT_DATA"

section "Binaries"
print_binary "apsigner" "$SIGNER_DATA/bin"
print_binary "apadmin" "$SIGNER_DATA/bin"
print_binary "apconsole" "$SIGNER_DATA/bin"
print_binary "apstore" "$SIGNER_DATA/bin"
print_binary "approbe" "$SIGNER_DATA/bin"
print_binary "apshell" "$CLIENT_DATA/bin"

section "Configuration"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_file_exists "signer config" "$SIGNER_CONFIG"
else
  pass "signer store private" "$SIGNER_DATA is not traversable by this operator"
fi
check_file_exists "client config" "$CLIENT_CONFIG"
info "signer_port" "${signer_port:-not configured}"
info "signer ssh.port" "${signer_ssh_port:-not configured}"
info "client signer_port" "${client_signer_port:-not configured}"
info "client ssh.host" "${client_ssh_host:-not configured}"
info "client ssh.port" "${client_ssh_port:-not configured}"

if [ -n "$signer_port" ] && [ -n "$client_signer_port" ]; then
  if [ "$signer_port" = "$client_signer_port" ]; then
    pass "REST port match" "$signer_port"
  else
    warn "REST port mismatch" "signer=$signer_port client=$client_signer_port"
  fi
fi

if [ -n "$signer_ssh_port" ] && [ -n "$client_ssh_port" ]; then
  if [ "$signer_ssh_port" = "$client_ssh_port" ]; then
    pass "SSH port match" "$signer_ssh_port"
  else
    warn "SSH port mismatch" "signer=$signer_ssh_port client=$client_ssh_port"
  fi
fi

if [ "$(uname -s)" = "Darwin" ] && [ "${client_ssh_host:-}" = "localhost" ]; then
  info "macOS localhost" "client uses localhost; current apshell dials IPv4 for localhost"
fi

section "Runtime State"
processes="$(print_processes "apsigner" || true)"
if [ -n "$processes" ]; then
  pass "apsigner process" "found"
  printf '%s\n' "$processes" | sed 's/^/  /'
else
  warn "apsigner process" "not found"
fi
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_listener "signer REST" "$signer_port"
  check_listener "signer SSH" "$signer_ssh_port"
else
  info "signer listeners" "private config not inspected; use the service account or root for port checks"
fi

section "IPC"
info "socket path" "$signer_ipc_path"
if [ -S "$signer_ipc_path" ]; then
  pass "IPC socket" "$signer_ipc_path"
  mode="$(file_mode "$signer_ipc_path" 2>/dev/null || true)"
  [ -n "$mode" ] && info "socket mode" "$mode"
else
  warn "IPC socket" "missing or not a socket: $signer_ipc_path"
fi

section "Tokens And SSH Keys"
check_mode_exact "client token" "$CLIENT_DATA/aplane.token" "600"
check_mode_exact "client SSH key" "$client_identity_file" "600"
if [ -f "$client_identity_file.pub" ]; then
  pass "client SSH pubkey" "$client_identity_file.pub"
else
  info "client SSH pubkey" "missing: $client_identity_file.pub (not required for normal client use)"
fi
check_file_exists "known_hosts" "$client_known_hosts_path"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_mode_exact "signer token" "$SIGNER_DATA/identities/default/aplane.token" "600"
  check_mode_exact "signer host key" "$signer_host_key_path" "600"
  check_file_exists "authorized_keys" "$signer_authorized_keys_path"
else
  info "signer credentials" "private store contents not inspected"
fi

section "Keystore"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_file_exists "keystore" "$SIGNER_DATA/identities/default/.keystore"
  if [ -d "$SIGNER_DATA/identities/default/keys" ]; then
    account_count="$(find "$SIGNER_DATA/identities/default/keys" -type f -name '*.key' 2>/dev/null | wc -l | tr -d ' ')"
    sentry_count="$(find "$SIGNER_DATA/identities/default/keys" -type f -name '*.sen' 2>/dev/null | wc -l | tr -d ' ')"
    managed_count="$((account_count + sentry_count))"
    pass "key directory" "$SIGNER_DATA/identities/default/keys ($managed_count managed credentials: $account_count account .key, $sentry_count sentry .sen)"
  else
    warn "key directory" "missing: $SIGNER_DATA/identities/default/keys"
  fi
else
  info "keystore" "private store contents not inspected"
fi

if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  if [ -f "$SIGNER_CONFIG" ] && [ ! -f "$SIGNER_DATA/identities/default/.keystore" ]; then
    warn "partial install" "signer config exists but default keystore is missing"
  fi
  if [ -f "$SIGNER_CONFIG" ] && [ ! -f "$CLIENT_CONFIG" ]; then
    warn "partial install" "signer config exists but client config is missing"
  fi
fi

section "Summary"
printf 'PASS: %d\n' "$PASS_COUNT"
printf 'WARN: %d\n' "$WARN_COUNT"
printf 'INFO: %d\n' "$INFO_COUNT"
if [ "$WARN_COUNT" -gt 0 ]; then
  echo "Result: review warnings above. This script made no changes."
else
  echo "Result: no warnings found. This script made no changes."
fi
