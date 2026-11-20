#!/usr/bin/env bash
set -euo pipefail

SIGNER_DATA_OVERRIDE=""
CLIENT_DATA_OVERRIDE=""

usage() {
  cat <<'EOF'
Usage: installer/scripts/aplane-env-audit.sh [--signer-data <path>] [--client-data <path>]

Read-only audit of a local APlane environment. The script inspects config files,
the client endpoint registry, ports, listeners, SSH key permissions, IPC socket
state, and common partial install issues. It does not modify files.

Defaults:
  signer data: $APSIGNER_DATA, then ~/aplane/apsigner
  client data: $APCLIENT_DATA, then ~/aplane/apclient
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
  local default="$3"
  if [ -n "$override" ]; then
    expand_user_path "$override"
  elif [ -n "$env_value" ]; then
    expand_user_path "$env_value"
  else
    printf '%s\n' "$default"
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

# yaml_scalars prints one "<key path>\037<value>" line per key in a block-style
# YAML file. The keys of a path are joined by \036, since an endpoint alias may
# contain a dot. Any indentation width works: Go rewrites endpoints.yaml with
# four spaces, where the installers write two.
yaml_scalars() {
  local path="$1"
  [ -f "$path" ] || return 0
  awk '
    /^[[:space:]]*(#|$)/ {
      next
    }
    {
      match($0, /^[[:space:]]*/)
      indent = RLENGTH
      line = substr($0, indent + 1)
      if (index(line, ":") == 0) {
        next
      }
      key = line
      sub(/[[:space:]]*:.*/, "", key)
      gsub(/^"|"$/, "", key)
      value = line
      sub(/^[^:]*:/, "", value)
      sub(/[[:space:]]+#.*/, "", value)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      while (depth > 0 && indents[depth] >= indent) {
        depth--
      }
      depth++
      indents[depth] = indent
      keys[depth] = key
      key_path = keys[1]
      for (i = 2; i <= depth; i++) {
        key_path = key_path "\036" keys[i]
      }
      print key_path "\037" value
    }
  ' "$path"
}

# yaml_value prints the value at the key path its remaining arguments name.
yaml_value() {
  local path="$1"
  shift
  local want line
  want="$(IFS=$'\036'; printf '%s' "$*")"
  while IFS= read -r line; do
    if [ "${line%%$'\037'*}" = "$want" ]; then
      printf '%s\n' "${line#*$'\037'}"
      return 0
    fi
  done < <(yaml_scalars "$path")
}

# load_client_endpoints fills the endpoint_* arrays from endpoints.yaml, in file
# order, applying apshell's identity and known_hosts defaults.
endpoint_aliases=()
endpoint_roles=()
endpoint_urls=()
endpoint_identities=()
endpoint_known_hosts=()
load_client_endpoints() {
  local path="$1"
  local line key_path value rest alias field i
  while IFS= read -r line; do
    key_path="${line%%$'\037'*}"
    value="${line#*$'\037'}"
    case "$key_path" in
      endpoints$'\036'*) ;;
      *) continue ;;
    esac
    rest="${key_path#endpoints$'\036'}"
    alias="${rest%%$'\036'*}"
    if [ "$rest" = "$alias" ]; then
      endpoint_aliases+=("$alias")
      endpoint_roles+=("")
      endpoint_urls+=("")
      endpoint_identities+=(".ssh/id_ed25519")
      endpoint_known_hosts+=(".ssh/known_hosts")
      continue
    fi
    field="${rest#*$'\036'}"
    i=$((${#endpoint_aliases[@]} - 1))
    case "$field" in
      role) endpoint_roles[i]="$value" ;;
      url) endpoint_urls[i]="$value" ;;
      identity_file) [ -z "$value" ] || endpoint_identities[i]="$value" ;;
      known_hosts_path) [ -z "$value" ] || endpoint_known_hosts[i]="$value" ;;
    esac
  done < <(yaml_scalars "$path")
}

# endpoint_host and endpoint_port split an ssh://host[:port] URL; the port
# defaults to 1127, as apshell's does.
endpoint_authority() {
  local authority="${1#ssh://}"
  authority="${authority%%/*}"
  printf '%s\n' "${authority##*@}"
}

endpoint_host() {
  local authority
  authority="$(endpoint_authority "$1")"
  case "$authority" in
    \[*) authority="${authority#[}"; printf '%s\n' "${authority%%]*}" ;;
    *) printf '%s\n' "${authority%%:*}" ;;
  esac
}

endpoint_port() {
  local authority
  authority="$(endpoint_authority "$1")"
  authority="${authority##*]}"
  case "$authority" in
    *:*) printf '%s\n' "${authority##*:}" ;;
    *) printf '%s\n' "1127" ;;
  esac
}

is_loopback_host() {
  case "$1" in
    localhost|127.*|::1) return 0 ;;
  esac
  return 1
}

# Endpoints usually share one SSH key and one known_hosts file; check each
# file once.
checked_paths=$'\n'
first_check() {
  case "$checked_paths" in
    *$'\n'"$1"$'\n'*) return 1 ;;
  esac
  checked_paths="$checked_paths$1"$'\n'
}

check_client_ssh_files() {
  local identity_file known_hosts_path
  identity_file="$(resolve_path "$1" "$CLIENT_DATA")"
  known_hosts_path="$(resolve_path "$2" "$CLIENT_DATA")"
  if first_check "$identity_file"; then
    check_mode_exact "client SSH key" "$identity_file" "600"
    if [ -f "$identity_file.pub" ]; then
      pass "client SSH pubkey" "$identity_file.pub"
    else
      info "client SSH pubkey" "missing: $identity_file.pub (not required for normal client use)"
    fi
  fi
  if first_check "$known_hosts_path"; then
    check_file_exists "known_hosts" "$known_hosts_path"
  fi
}

file_mode() {
  local path="$1"
  if stat -c '%a' "$path" >/dev/null 2>&1; then
    stat -c '%a' "$path"
  else
    stat -f '%Lp' "$path"
  fi
}

file_owner() {
  local path="$1"
  if stat -c '%U:%G' "$path" >/dev/null 2>&1; then
    stat -c '%U:%G' "$path"
  else
    stat -f '%Su:%Sg' "$path"
  fi
}

check_real_dir_mode_owner() {
  local label="$1"
  local path="$2"
  local expected_mode="$3"
  local expected_owner="$4"
  if [ -L "$path" ]; then
    warn "$label" "$path is a symlink, expected a real directory"
    return
  fi
  if [ ! -d "$path" ]; then
    warn "$label" "missing or not a directory: $path"
    return
  fi
  local mode owner
  mode="$(file_mode "$path" 2>/dev/null || true)"
  owner="$(file_owner "$path" 2>/dev/null || true)"
  if [ "$mode" = "$expected_mode" ] && [ "$owner" = "$expected_owner" ]; then
    pass "$label" "$path owner $owner mode $mode"
  else
    warn "$label" "$path owner ${owner:-unknown} mode ${mode:-unknown}, expected $expected_owner $expected_mode"
  fi
}

check_socket_mode_owner() {
  local label="$1"
  local path="$2"
  local expected_mode="$3"
  local expected_owner="$4"
  if [ -L "$path" ]; then
    warn "$label" "$path is a symlink, expected a Unix socket"
    return
  fi
  if [ ! -S "$path" ]; then
    warn "$label" "missing or not a socket: $path"
    return
  fi
  local mode owner
  mode="$(file_mode "$path" 2>/dev/null || true)"
  owner="$(file_owner "$path" 2>/dev/null || true)"
  if [ "$mode" = "$expected_mode" ] && [ "$owner" = "$expected_owner" ]; then
    pass "$label" "$path owner $owner mode $mode"
  else
    warn "$label" "$path owner ${owner:-unknown} mode ${mode:-unknown}, expected $expected_owner $expected_mode"
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
    local version_output=""
    if version_output="$("$bin" --version 2>/dev/null)"; then
      version="${version_output%%$'\n'*}"
    fi
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
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SIGNER_DATA="$(resolve_data_dir "$SIGNER_DATA_OVERRIDE" "${APSIGNER_DATA:-}" "$HOME/aplane/apsigner")"
CLIENT_DATA="$(resolve_data_dir "$CLIENT_DATA_OVERRIDE" "${APCLIENT_DATA:-}" "$HOME/aplane/apclient")"

SIGNER_CONFIG="$SIGNER_DATA/config.yaml"
CLIENT_CONFIG="$CLIENT_DATA/config.yaml"
CLIENT_ENDPOINTS="$CLIENT_DATA/endpoints.yaml"

SIGNER_SERVICE_USER="aplane"
SIGNER_SERVICE_GROUP="aplane"
if command -v systemctl >/dev/null 2>&1; then
  configured_user="$(systemctl show apsigner.service -p User --value 2>/dev/null || true)"
  configured_group="$(systemctl show apsigner.service -p Group --value 2>/dev/null || true)"
  [ -n "$configured_user" ] && SIGNER_SERVICE_USER="$configured_user"
  [ -n "$configured_group" ] && SIGNER_SERVICE_GROUP="$configured_group"
fi
SIGNER_SERVICE_OWNER="$SIGNER_SERVICE_USER:$SIGNER_SERVICE_GROUP"

SIGNER_STORE_TRAVERSABLE=0
if [ ! -L "$SIGNER_DATA" ] && [ -x "$SIGNER_DATA" ]; then
  SIGNER_STORE_TRAVERSABLE=1
fi
SIGNER_PROD_MANAGED=0
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ] && [ -f "$SIGNER_DATA/.prod" ]; then
  SIGNER_PROD_MANAGED=1
fi
SIGNER_EXPECTED_OWNER="$SIGNER_SERVICE_OWNER"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ] && [ "$SIGNER_PROD_MANAGED" -eq 0 ]; then
  SIGNER_EXPECTED_OWNER="$(id -un):$(id -gn)"
fi

signer_port=""
signer_ssh_port=""
signer_ipc_path=""
signer_ipc_resolution_warning=""
approbe_bin="$(find_binary "approbe" "$SIGNER_DATA/bin")"
if [ -z "$approbe_bin" ]; then
  signer_ipc_resolution_warning="approbe not found in $SIGNER_DATA/bin or PATH"
else
  approbe_ipc_args=(signer-ipc-path -d "$SIGNER_DATA")
  if [ -z "$SIGNER_DATA_OVERRIDE" ]; then
    approbe_ipc_args+=(--honor-ipc-env)
  fi
  if ! signer_ipc_path="$("$approbe_bin" "${approbe_ipc_args[@]}" 2>&1)"; then
    signer_ipc_resolution_warning="$signer_ipc_path"
    signer_ipc_path=""
  fi
fi
signer_host_key_path=""
# The enrolled-client registry has a fixed location in the product store;
# the daemon is its only writer.
signer_authorized_keys_path="$SIGNER_DATA/identities/default/.ssh/authorized_keys"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  signer_port="$(yaml_value "$SIGNER_CONFIG" endpoint signer_port)"
  signer_ssh_port="$(yaml_value "$SIGNER_CONFIG" endpoint ssh port)"
  signer_host_key_path="$(yaml_value "$SIGNER_CONFIG" endpoint ssh host_key_path)"
fi
[ -n "$signer_host_key_path" ] || signer_host_key_path=".ssh/ssh_host_key"
signer_host_key_path="$(resolve_path "$signer_host_key_path" "$SIGNER_DATA")"

load_client_endpoints "$CLIENT_ENDPOINTS"

echo "APlane Environment Audit"
echo "Repository: $REPO_ROOT"
echo "Read-only: no files will be modified"

section "Data Directories"
info "APSIGNER_DATA" "$SIGNER_DATA"
info "APCLIENT_DATA" "$CLIENT_DATA"
check_dir_exists "signer dir" "$SIGNER_DATA"
check_dir_exists "client dir" "$CLIENT_DATA"
if [ -e "$SIGNER_DATA" ] || [ -L "$SIGNER_DATA" ]; then
  check_real_dir_mode_owner "signer store boundary" "$SIGNER_DATA" "700" "$SIGNER_EXPECTED_OWNER"
fi

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
check_file_exists "client endpoints" "$CLIENT_ENDPOINTS"
info "signer_port" "${signer_port:-not configured}"
info "signer ssh.port" "${signer_ssh_port:-not configured}"
if [ "${#endpoint_aliases[@]}" -eq 0 ]; then
  info "client endpoints" "none configured"
fi
for ((i = 0; i < ${#endpoint_aliases[@]}; i++)); do
  info "endpoint ${endpoint_aliases[i]}" "${endpoint_roles[i]:-no role} ${endpoint_urls[i]:-no url}"
done

# One of the endpoints on this machine must reach this node. The others may
# reach other nodes installed beside it, each on its own port.
loopback_endpoints=""
matching_endpoints=""
for ((i = 0; i < ${#endpoint_aliases[@]}; i++)); do
  endpoint_url="${endpoint_urls[i]}"
  [ -n "$endpoint_url" ] || continue
  endpoint_ssh_host="$(endpoint_host "$endpoint_url")"
  is_loopback_host "$endpoint_ssh_host" || continue
  endpoint_ssh_port="$(endpoint_port "$endpoint_url")"
  loopback_endpoints="$loopback_endpoints ${endpoint_aliases[i]}=$endpoint_ssh_port"
  if [ "$endpoint_ssh_port" = "$signer_ssh_port" ]; then
    matching_endpoints="$matching_endpoints ${endpoint_aliases[i]}"
  fi
  if [ "$(uname -s)" = "Darwin" ] && [ "$endpoint_ssh_host" = "localhost" ]; then
    info "macOS localhost" "${endpoint_aliases[i]} uses localhost; current apshell dials IPv4 for localhost"
  fi
done
if [ -n "$signer_ssh_port" ] && [ -n "$loopback_endpoints" ]; then
  if [ -n "$matching_endpoints" ]; then
    pass "SSH port match" "${matching_endpoints# }: $signer_ssh_port"
  else
    warn "SSH port mismatch" "no endpoint on this machine uses signer port $signer_ssh_port:$loopback_endpoints"
  fi
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
if [ -n "$signer_ipc_resolution_warning" ]; then
  warn "IPC resolver" "$signer_ipc_resolution_warning"
else
  info "socket path" "$signer_ipc_path"
fi
if [ -z "$signer_ipc_path" ]; then
  warn "IPC socket" "path was not resolved"
elif [ "$signer_ipc_path" = "/run/apsigner/aplane.sock" ]; then
  check_real_dir_mode_owner "IPC runtime dir" "/run/apsigner" "750" "$SIGNER_SERVICE_OWNER"
  check_socket_mode_owner "IPC socket" "$signer_ipc_path" "660" "$SIGNER_SERVICE_OWNER"
elif [ -S "$signer_ipc_path" ]; then
  check_socket_mode_owner "IPC socket" "$signer_ipc_path" "660" "$SIGNER_EXPECTED_OWNER"
else
  warn "IPC socket" "missing or not a socket: $signer_ipc_path"
fi

section "SSH Keys"
if [ "${#endpoint_aliases[@]}" -eq 0 ]; then
  check_client_ssh_files ".ssh/id_ed25519" ".ssh/known_hosts"
fi
for ((i = 0; i < ${#endpoint_aliases[@]}; i++)); do
  check_client_ssh_files "${endpoint_identities[i]}" "${endpoint_known_hosts[i]}"
done
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_mode_exact "signer host key" "$signer_host_key_path" "600"
  check_file_exists "enrolled clients registry" "$signer_authorized_keys_path"
else
  info "signer credentials" "private store contents not inspected"
fi

section "Keystore"
if [ "$SIGNER_STORE_TRAVERSABLE" -eq 1 ]; then
  check_file_exists "keystore" "$SIGNER_DATA/identities/default/.keystore"
  check_file_exists "store root" "$SIGNER_DATA/identities/default/store-root.enc"
  # The encrypted store root selects the current generation, so the audit
  # counts generations rather than guessing which one holds the keys.
  generations_dir="$SIGNER_DATA/identities/default/generations"
  generation_count="$(find "$generations_dir" -mindepth 1 -maxdepth 1 -type d ! -name '.*' 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$generation_count" -gt 0 ]; then
    pass "generations" "$generations_dir ($generation_count)"
  else
    warn "generations" "missing or empty: $generations_dir"
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
