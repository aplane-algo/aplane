# Configuration Reference

Auto-generated from Go struct tags. Do not edit manually.

---

## apshell Configuration

File: `config.yaml` in apshell data directory (`-d` or `APCLIENT_DATA`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network` | string | `testnet` | Default network context token |
| `networks_allowed` | []string | `[]` | Restrict allowed networks (empty = all) |
| `theme` | string | `auto` | Local client UI theme: auto, dark, or light (auto detects terminal) |
| `signer_status_poll_interval` | string | `10s` | Background /status polling interval for signer keyset refresh (0=disabled) |
| `networks` | map | (none) | Grouped settings per network context token |
| `networks.<network>.algod` | object | (none) | Algod settings for this network context token |
| `networks.<network>.algod.server` | string | `(none)` | Algod server URL |
| `networks.<network>.algod.token` | string | `(none)` | Algod API token |

## apshell Endpoint Registry

File: `endpoints.yaml` in apshell data directory (`-d` or `APCLIENT_DATA`)

Signer and sentry endpoint routing lives here, not in `config.yaml`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schema_version` | int | `1` | Endpoint registry schema version |
| `default` | string | `primary` | Default signer endpoint alias |
| `endpoints.<alias>.role` | string | `(none)` | Endpoint role: `signer` or `sentry` |
| `endpoints.<alias>.url` | string | `(none)` | Endpoint URL: `ssh://host[:port]`, loopback `http://...`, `https://...`, or `self` where supported |
| `endpoints.<alias>.signer_port` | int | `11270` | Remote apsigner REST port for `ssh://` endpoints |
| `endpoints.<alias>.local_port` | int | `0` | Local tunnel port for `ssh://` endpoints; `0` chooses automatically |
| `endpoints.<alias>.identity_file` | string | `.ssh/id_ed25519` | SSH private key path, resolved relative to `APCLIENT_DATA` |
| `endpoints.<alias>.known_hosts_path` | string | `.ssh/known_hosts` | SSH known-hosts path, resolved relative to `APCLIENT_DATA` |
| `endpoints.<alias>.token_file` | string | `aplane.token` or `tokens/<alias>.token` | Endpoint API token file, resolved relative to `APCLIENT_DATA` |
| `endpoints.<alias>.published_sentries` | map | `(none)` | Sentry endpoint inventory learned from authenticated `/keys` discovery; routing metadata, not trust proof |

## apsigner Configuration

File: `config.yaml` in apsigner data directory (`-d` or `APSIGNER_DATA`, required)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | object | default endpoint settings | Signer endpoint exposure settings |
| `endpoint.advertise_url` | string | `(none)` | Client-reachable public endpoint URL used by apstore endpoint export when --host/--url are omitted |
| `endpoint.signer_port` | int | `11270` | Loopback REST API port behind the endpoint |
| `endpoint.ssh` | object | default SSH settings | SSH tunnel settings for apsigner endpoint access |
| `endpoint.ssh.listen_address` | string | `127.0.0.1` | SSH listen address to bind |
| `endpoint.ssh.port` | int | `1127` | SSH port to listen on |
| `endpoint.ssh.host_key_path` | string | `.ssh/ssh_host_key` | Server's private host key path |
| `endpoint.ssh.authorized_keys_path` | string | `.ssh/authorized_keys` | Legacy/global authorized client public keys file |
| `passphrase_timeout` | string | `15m` | Admin idle disconnect timeout (0=never) |
| `approval_wait` | string | `60s` | Maximum time to wait for operator approval of a signing request |
| `ipc_path` | string | `$APSIGNER_DATA/aplane.sock` | Unix socket path for admin IPC |
| `lock_on_disconnect` | *bool | `true` | Lock signer when admin disconnects |
| `passphrase_command_argv` | []string | `[]` | Command to run to obtain/store the passphrase (all paths resolved relative to data directory; verb 'read' or 'write' is injected as argv[1]) |
| `passphrase_command_env` | map | (none) | Environment variables to pass to the passphrase command; the process env is not inherited except for the systemd CREDENTIALS_DIRECTORY passthrough |
| `networks` | map | (none) | Grouped settings per network context token |
| `networks.<network>.algod` | object | (none) | Algod settings for this network context token |
| `networks.<network>.algod.server` | string | `(none)` | Algod server URL |
| `networks.<network>.algod.token` | string | `(none)` | Algod API token |
| `networks.<network>.genesis_hash` | string | `(none)` | Custom signer policy genesis hash for this network context token |
| `teal_compile_network` | string | `testnet` | Network context token whose algod is used for TEAL compilation |
| `require_memory_protection` | bool | `false` | Fail startup if memory protection unavailable |
| `user_auto_approve` | bool | `false` | User default to sign non-rejected requests without operator approval unless policy forces review |
| `theme` | string | `auto` | Signer-admin UI theme: auto, dark, or light (auto detects terminal) |

Identity-scoped `identities/<identity>/config.yaml` contains settings
only. Node role is stored separately in root `node.yaml`.

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `APCLIENT_DATA` | Data directory for apshell (config, plugin catalog, and scripts) | apshell, aplocalnet |
| `APSIGNER_DATA` | Data directory for apsigner (config, keys, IPC socket) | apsigner, apadmin, apapprover, apstore, appass, aplocalnet |
| `APCONSOLE_CONFIG` | Optional explicit apconsole.yaml path for the unified console; explicit path/env/flag values must agree | apconsole |
| `APLANE_LOCALNET_ALGOD_URL` | Optional AlgoKit LocalNet algod override | aplocalnet, algokit-localnet plugin |
| `APLANE_LOCALNET_KMD_URL` | Optional AlgoKit LocalNet KMD override | aplocalnet, algokit-localnet plugin |
| `APLANE_LOCALNET_TOKEN` | Optional AlgoKit LocalNet algod/KMD token override | aplocalnet, algokit-localnet plugin |
| `APLANE_LOCALNET_WALLET` | Optional KMD wallet name for LocalNet funding | algokit-localnet plugin |
| `APLANE_LOCALNET_WALLET_PASSWORD` | Optional KMD wallet password for LocalNet funding | algokit-localnet plugin |
| `TEST_PASSPHRASE` | Passphrase for automated testing (auto-unlocks apsigner) | apsigner, apadmin |
| `TEST_FUNDING_MNEMONIC` | 25-word mnemonic for funding integration test accounts | integration tests |
| `TEST_FUNDING_ACCOUNT` | Testnet address for balance checking in integration tests | integration tests |
| `DISABLE_MEMORY_LOCK` | Set to any value to disable memory locking (for debugging) | apsigner |
| `APSHELL_DEBUG` | Set to any value to enable debug logging | apshell |
| `XDG_RUNTIME_DIR` | Standard private runtime directory useful for custom ipc_path placement | apsigner |

### Data Directory Configuration

Both apshell and apsigner require a data directory to be specified.

**apshell:**
- `-d <path>` flag, or
- `APCLIENT_DATA` environment variable

**apsigner/apadmin/apapprover/apstore/appass:**
- `-d <path>` flag, or
- `APSIGNER_DATA` environment variable
- no default data directory is assumed

### Passphrase Precedence

For apsigner passphrase sources:
1. `TEST_PASSPHRASE` environment variable (highest priority)
2. identity `unlock.yaml` passphrase command, falling back to legacy `passphrase_command_argv` in config.yaml (headless mode)
3. Interactive prompt via apadmin IPC (default)
