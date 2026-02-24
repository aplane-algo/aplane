# Configuration Reference

Auto-generated from Go struct tags. Do not edit manually.

---

## apshell Configuration

File: `config.yaml` in apshell data directory (`-d` or `APSHELL_DATA`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network` | string | `testnet` | Default network (mainnet, testnet, betanet) |
| `networks_allowed` | []string | `[]` | Restrict allowed networks (empty = all) |
| `signer_port` | int | `11270` | Local REST port for apsignerd |
| `ai_model` | string | `(none)` | AI model override (provider default if empty) |
| `ssh` | object | (none) | SSH tunnel settings (omit for direct localhost connection) |
| `ssh.host` | string | `(none)` | Remote host to SSH to (required) |
| `ssh.port` | int | `1127` | SSH port |
| `ssh.identity_file` | string | `.ssh/id_ed25519` | SSH private key path (relative to data dir) |
| `ssh.known_hosts_path` | string | `.ssh/known_hosts` | Known hosts file path (relative to data dir) |
| `mainnet_algod_server` | string | `(none)` | Mainnet algod server URL |
| `mainnet_algod_port` | int | `(none)` | Mainnet algod port (if separate from URL) |
| `mainnet_algod_token` | string | `(none)` | Mainnet algod API token |
| `testnet_algod_server` | string | `(none)` | Testnet algod server URL |
| `testnet_algod_port` | int | `(none)` | Testnet algod port (if separate from URL) |
| `testnet_algod_token` | string | `(none)` | Testnet algod API token |
| `betanet_algod_server` | string | `(none)` | Betanet algod server URL |
| `betanet_algod_port` | int | `(none)` | Betanet algod port (if separate from URL) |
| `betanet_algod_token` | string | `(none)` | Betanet algod API token |

## apsignerd Configuration

File: `config.yaml` in apsignerd data directory (`-d` or `APSIGNER_DATA`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `signer_port` | int | `11270` | REST API port |
| `ssh` | object | (none) | SSH tunnel settings (omit to disable SSH) |
| `ssh.port` | int | `1127` | SSH port to listen on |
| `ssh.host_key_path` | string | `.ssh/ssh_host_key` | Server's private host key path |
| `ssh.authorized_keys_path` | string | `.ssh/authorized_keys` | Allowed client public keys file |
| `ssh.auto_register` | *bool | `false` | Auto-register new SSH keys (TOFU) |
| `passphrase_timeout` | string | `15m` | Inactivity timeout before auto-lock (0=never) |
| `store` | string | `(none)` | Store directory (required) |
| `ipc_path` | string | `/tmp/aplane.sock` | Unix socket path for admin IPC |
| `lock_on_disconnect` | *bool | `true` | Lock signer when admin disconnects |
| `passphrase_command_argv` | []string | `(none)` | Command to run at startup to obtain the passphrase (argv[0] must be absolute path unless allow_path_lookup is true) |
| `passphrase_command_env` | map | `(none)` | Environment variables to pass to the passphrase command (process env is never inherited) |
| `allow_path_lookup` | bool | `false` | Allow non-absolute argv[0] in passphrase_command_argv, resolved via locked PATH (/usr/sbin:/usr/bin:/sbin:/bin) |
| `teal_compiler_algod_url` | string | `(none)` | Algod URL for TEAL compilation |
| `teal_compiler_algod_token` | string | `(none)` | Algod token for TEAL compilation |
| `require_memory_protection` | bool | `false` | Fail startup if memory protection unavailable |
| `txn_auto_approve` | bool | `false` | Auto-approve ALL single transaction signing requests (use with caution) |
| `group_auto_approve` | bool | `false` | Auto-approve ALL transaction group requests (use with caution) |
| `allow_group_modification` | bool | `false` | Allow /sign to modify pre-grouped transactions (adds dummies, changes group ID) |

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `APSHELL_DATA` | Data directory for apshell (config and plugins) | apshell |
| `APSIGNER_DATA` | Data directory for apsignerd (config, keys, IPC socket) | apsignerd, apadmin, apapprover, apstore |
| `TEST_PASSPHRASE` | Passphrase for automated testing (auto-unlocks apsignerd) | apsignerd, apadmin |
| `TEST_FUNDING_MNEMONIC` | 25-word mnemonic for funding integration test accounts | integration tests |
| `TEST_FUNDING_ACCOUNT` | Testnet address for balance checking in integration tests | integration tests |
| `DISABLE_MEMORY_LOCK` | Set to any value to disable memory locking (for debugging) | apsignerd |
| `ANTHROPIC_API_KEY` | API key for Anthropic Claude (AI code generation) | apshell |
| `OPENAI_API_KEY` | API key for OpenAI GPT (AI code generation) | apshell |
| `APSHELL_DEBUG` | Set to any value to enable debug logging | apshell |
| `XDG_RUNTIME_DIR` | Standard path for runtime files (used for IPC socket default) | apsignerd |

### Data Directory Configuration

Both apshell and apsignerd require a data directory to be specified.

**apshell:**
- `-d <path>` flag, or
- `APSHELL_DATA` environment variable

**apsignerd/apadmin/apapprover/apstore:**
- `-d <path>` flag, or
- `APSIGNER_DATA` environment variable

### Passphrase Precedence

For apsignerd passphrase sources:
1. `TEST_PASSPHRASE` environment variable (highest priority)
2. `passphrase_command_argv` config option (headless mode)
3. Interactive prompt via apadmin IPC (default)
