# Configuration Reference

This document describes the `config.yaml` files used by the aPlane Shell suite.

## Overview

There are two distinct config.yaml formats:

| Tool | Purpose |
|------|---------|
| **apshell** | Client configuration (network, signer connection) |
| **apsignerd, apadmin, apapprover, apstore** | Server/admin configuration (keystore, ports, admin interface) |

Both programs use a **data directory** for configuration and state:

**apshell / Python SDK (clients):**
- Default: `~/.aplane` (like `~/.aws`, `~/.docker`)
- Override: `-d <path>` flag or `APCLIENT_DATA` env var

**apsignerd / apadmin / apstore (server tools):**
- Required: `-d <path>` flag or `APSIGNER_DATA` env var (no default)

Config files are located at `<data_dir>/config.yaml`.

### Client Directory Structure (`~/.aplane`)

```
~/.aplane/
├── aplane.token           # API token (obtained via request-token command)
├── config.yaml            # Connection settings
├── .ssh/
│   ├── id_ed25519         # SSH private key for authentication
│   └── known_hosts        # Trusted server host keys
└── plugins/               # External plugins (optional)
```

### Server Directory Structure (`$APSIGNER_DATA`)

```
$APSIGNER_DATA/
├── config.yaml            # Server configuration (includes policy settings)
├── .ssh/
│   ├── ssh_host_key       # Server's SSH host key
│   └── authorized_keys    # Authorized client public keys
└── store/                 # Encrypted signing keys
    ├── .keystore          # Keystore metadata
    └── users/
        └── default/
            ├── keys/      # Encrypted key files
            │   └── *.key
            └── aplane.token  # Generated API token
```

---

## apshell Configuration

The apshell CLI uses config.yaml to store connection settings.

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `network` | string | `"testnet"` | Algorand network: `mainnet`, `testnet`, or `betanet` |
| `networks_allowed` | []string | `[]` (all) | Restrict allowed networks (empty = all networks allowed) |
| `signer_port` | int | `11270` | Signer REST API port |
| `ai_model` | string | (provider default) | AI model for code generation (e.g., `"claude-sonnet-4-5-20250929"`) |
| `ssh` | object | (none) | SSH tunnel config (omit for direct localhost connection) |
| `ssh.host` | string | (required) | Remote signer host address |
| `ssh.port` | int | `1127` | SSH port for tunnel connections |
| `ssh.identity_file` | string | `".ssh/id_ed25519"` | SSH private key (relative to data dir) |
| `ssh.known_hosts_path` | string | `".ssh/known_hosts"` | known_hosts file (relative to data dir) |
| `mainnet_algod_server` | string | `""` | Mainnet algod server URL |
| `mainnet_algod_port` | int | `0` | Mainnet algod port (0 = use URL default) |
| `mainnet_algod_token` | string | `""` | Mainnet algod API token |
| `testnet_algod_server` | string | `""` | Testnet algod server URL |
| `testnet_algod_port` | int | `0` | Testnet algod port (0 = use URL default) |
| `testnet_algod_token` | string | `""` | Testnet algod API token |
| `betanet_algod_server` | string | `""` | Betanet algod server URL |
| `betanet_algod_port` | int | `0` | Betanet algod port (0 = use URL default) |
| `betanet_algod_token` | string | `""` | Betanet algod API token |

### Example (Direct Connection to Local Signer)

```yaml
network: testnet
signer_port: 11270
```

### Example (SSH Tunnel to Remote Signer)

```yaml
network: testnet
signer_port: 11270
ssh:
  host: signer.example.com
  port: 1127
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
```

Note: SSH paths are relative to the data directory (`~/.aplane` by default). The `.ssh/` subdirectory is created automatically when needed. SSH authentication uses 2FA (API token as username + public key).

### Custom Algod Endpoints

By default, apshell uses [Nodely](https://nodely.io) free API endpoints. To use your own algod node or a different provider, configure the network-specific algod settings:

```yaml
network: mainnet
mainnet_algod_server: http://localhost
mainnet_algod_port: 4001
mainnet_algod_token: your-api-token
```

If port is `0` (default), the URL is used as-is. Otherwise, the port is appended to the server URL.

### Network Restriction

The `networks_allowed` field restricts which networks apshell can connect to. This is useful for:
- Preventing accidental mainnet transactions during development
- Restricting operators to specific networks

```yaml
network: testnet
networks_allowed:
  - testnet
  - betanet
```

With this configuration:
- apshell starts on testnet
- The `network` command can only switch to testnet or betanet
- Attempting to switch to mainnet will fail with an error

If `networks_allowed` is empty or omitted, all networks are allowed.

### AI Model Configuration

The `ai_model` field specifies which AI model to use for the `ai` command (JavaScript code generation). If empty or omitted, the provider's default model is used.

Supported models depend on your API key:
- **Anthropic**: `claude-sonnet-4-5-20250929`, `claude-opus-4-5-20250929`, etc.
- **OpenAI**: `gpt-5.2`, `gpt-4o`, etc.

```yaml
ai_model: claude-sonnet-4-5-20250929
```

### Data Directory Setup

```bash
# apshell uses ~/.aplane by default - just run it
./apshell

# First-time setup: create config and SSH key
mkdir -p ~/.aplane/.ssh
ssh-keygen -t ed25519 -f ~/.aplane/.ssh/id_ed25519 -N ""

# Create config.yaml (or copy from examples/)
cat > ~/.aplane/config.yaml << 'EOF'
network: testnet
signer_port: 11270
ssh:
  host: signer.example.com  # Your signer host
  port: 1127
  identity_file: .ssh/id_ed25519
  known_hosts_path: .ssh/known_hosts
EOF

# Request token from signer (requires operator approval)
./apshell
> request-token

# Or use custom directory
./apshell -d /custom/path
export APCLIENT_DATA=/custom/path
```

### Notes

- For localhost connections, SSH tunneling is skipped
- For remote connections, apshell connects via SSH tunnel to the signer
- The `connect` command reads from config.yaml but never modifies it
- Edit config.yaml manually to change connection settings

### Connect Command Behavior

The `connect` command uses values from config.yaml as defaults:

```bash
# Uses all connection settings from config.yaml
connect

# Uses ssh_port and signer_port from config.yaml, connects to specified host
connect remotehost

# Override ports for this session only (does not modify config.yaml)
connect remotehost --signer-port 9999
```

To permanently change connection settings, edit config.yaml directly.

---

## apsignerd / apadmin / apapprover Configuration

The server and admin tools share the same config format and data directory.

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `signer_port` | int | `11270` | REST API port |
| `ssh` | object | (none) | SSH server config (omit to disable SSH, REST binds to all interfaces) |
| `ssh.port` | int | `1127` | SSH tunnel port |
| `ssh.host_key_path` | string | `".ssh/ssh_host_key"` | SSH host private key (relative to data dir) |
| `ssh.authorized_keys_path` | string | `".ssh/authorized_keys"` | Authorized client public keys (relative to data dir) |
| `ssh.auto_register` | bool | `false` | Auto-register new client SSH keys (TOFU) |
| `store` | string | (required) | Store directory |
| `ipc_path` | string | (see below) | Unix socket path for admin interface |
| `passphrase_timeout` | string | `"15m"` | Inactivity timeout before auto-lock (see below) |
| `lock_on_disconnect` | *bool | `true` | Lock signer when apadmin disconnects |
| `passphrase_command_argv` | []string | (optional) | Command to run at startup to obtain passphrase (see Headless Operation) |
| `passphrase_command_env` | map | (optional) | Environment variables to pass to passphrase command |
| `teal_compiler_algod_url` | string | (required for LogicSigs) | Algod URL for TEAL compilation (LogicSig generation) |
| `teal_compiler_algod_token` | string | (optional) | Algod API token for TEAL compilation |
| `require_memory_protection` | bool | `false` | If true, fail startup when memory protection cannot be enabled (requires root/sudo) |
| `txn_auto_approve` | bool | `false` | Auto-approve ALL single transaction signing requests |
| `group_auto_approve` | bool | `false` | Auto-approve ALL transaction group requests |
| `allow_group_modification` | bool | `false` | Allow /sign to modify pre-grouped transactions (adds dummies, changes group ID) |

### Passphrase Timeout Values

The `passphrase_timeout` setting controls how long the signer stays unlocked after inactivity.
When the timer fires, the signer locks itself (zeroing the master key from memory).
New signing requests will fail with "signer not unlocked" until apadmin re-enters the passphrase.
Each successful `/sign` request resets the timer.

| Value | Behavior |
|-------|----------|
| `"0"` | Signer stays unlocked indefinitely (no auto-lock) |
| `"15m"` | Auto-lock after 15 minutes of inactivity |
| `"1h"` | Auto-lock after 1 hour of inactivity |

### Admin Interface

The admin interface uses Unix sockets (IPC) for secure local communication:
- Socket created at `ipc_path` with 0600 permissions (owner only)
- Cannot be snooped with tcpdump (no network stack)
- apadmin and apapprover connect via this socket

**Default IPC path**: `$APSIGNER_DATA/aplane.sock`
### Data Directory Setup

```bash
# Create data directory
mkdir -p ~/.apsigner

# Generate default config
./apsignerd --print-default-config > ~/.apsigner/config.yaml

# Edit config.yaml to set keystore path and other options
# ...

# Initialize keystore (creates encryption control file)
./apstore -d ~/.apsigner init

# Run apsignerd
./apsignerd -d ~/.apsigner

# Or set environment variable
export APSIGNER_DATA=~/.apsigner
./apsignerd
```

**Note:** The keystore must be initialized with `apstore init` before apsignerd can start. This creates the keystore metadata file (`.keystore`) containing the master salt and passphrase verification check.

### Example (Interactive Mode with SSH)

```yaml
signer_port: 11270
ssh:
  port: 1127
  host_key_path: .ssh/ssh_host_key
  authorized_keys_path: .ssh/authorized_keys
  auto_register: true
store: keys
passphrase_timeout: "15m"
lock_on_disconnect: true
```

### Example (Direct Access - No SSH)

```yaml
signer_port: 11270
store: keys
passphrase_timeout: "15m"
```

Note: SSH paths are relative to the data directory (`$APSIGNER_DATA`). The `.ssh/` subdirectory is created automatically when needed. When `ssh:` block is omitted, REST API binds to all interfaces (0.0.0.0).

### Notes

- `store` is required and must be explicitly set (relative to data directory)
- Relative paths in config are resolved from the data directory
- apadmin and apapprover connect via the IPC socket
- Approval policies are configured inline in `config.yaml` (`txn_auto_approve`, `group_auto_approve`, `allow_group_modification`)
- See [Headless Operation](#headless-operation) for unattended deployment

---

## Approval Policy

Approval policy settings are configured directly in `config.yaml`. By default, all transactions require manual approval via apadmin/apapprover.

**Note**: Validation transactions (0 ALGO self-send) are always auto-approved regardless of policy settings.

### Example (Full Auto-Approve - Testing Only)

```yaml
txn_auto_approve: true
group_auto_approve: true
allow_group_modification: true
```

⚠️ **Warning**: Only use `txn_auto_approve: true` and `group_auto_approve: true` in controlled testing environments.

---

## Authentication

Signer uses a shared token for authenticating API requests from apshell and the Python SDK.

### How It Works

1. **Token generation**: On first run, apsignerd generates a cryptographically secure 256-bit random token
2. **Token storage**: Saved to `<store>/users/default/aplane.token` (alongside the keys it grants access to)
3. **Token provisioning**: Clients request tokens via SSH (requires operator approval in apadmin)
4. **Request authentication**: Clients send the token via `Authorization: aplane <token>` HTTP header
5. **Validation**: apsignerd validates using constant-time comparison (prevents timing attacks)

### Token File

| Property | Value |
|----------|-------|
| Filename | `aplane.token` |
| Format | 64-character hex string (256 bits) |
| Permissions | `0600` (owner read/write only) |

### Token Provisioning (Recommended)

Use the `request-token` command to obtain a token securely via SSH:

```bash
# In apshell - requests token via SSH, operator approves in apadmin
> request-token

# In Python SDK
from aplane import request_token_to_file
request_token_to_file()  # uses ~/.aplane by default
```

The operator sees the client's SSH fingerprint in apadmin and can verify identity before approving.

### Manual Token Setup (Alternative)

For localhost or when SSH is not available:

```bash
# Copy token from signer to client
cp $APSIGNER_DATA/store/users/default/aplane.token ~/.aplane/
```

### Endpoints

| Endpoint | Authentication |
|----------|----------------|
| `POST /sign` | Required |
| `GET /keys` | Required |
| `GET /health` | Not required (public health check) |

### Security Notes

- The token acts as a pre-shared secret between apshell and apsignerd
- For remote connections, the token travels through the SSH tunnel (encrypted)
- Keep `aplane.token` secure with `chmod 600`
- Regenerate by deleting the file and restarting apsignerd

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `APCLIENT_DATA` | Override client data directory (default: `~/.aplane`) |
| `APSIGNER_DATA` | **Data directory for apsignerd** (config, keys, IPC) - required |
| `TEST_PASSPHRASE` | Passphrase for automated testing (auto-unlocks apsignerd) |
| `TEST_FUNDING_MNEMONIC` | 25-word mnemonic for funding integration test accounts |
| `TEST_FUNDING_ACCOUNT` | Testnet address for balance checking in integration tests |
| `DISABLE_MEMORY_LOCK` | Set to `1` to disable mlock (for debugging) |
| `ANTHROPIC_API_KEY` | API key for Anthropic Claude (AI code generation) |
| `OPENAI_API_KEY` | API key for OpenAI GPT (AI code generation) |
| `APSHELL_DEBUG` | Set to any value to enable debug logging |
| `XDG_RUNTIME_DIR` | Standard path for runtime files (used for IPC socket default) |

### Data Directory Configuration

**apshell / Python SDK (clients):**
- Default: `~/.aplane`
- Override: `-d <path>` flag or `APCLIENT_DATA` env var

**apsignerd / apadmin / apapprover / apstore (server tools):**
- Required: `-d <path>` flag or `APSIGNER_DATA` env var (no default for security)

Config files are always located at `<data_dir>/config.yaml`.

---

## Security Recommendations

1. **IPC mode is always used** for admin connections (Unix socket provides file-permission-based access control)
2. **Set restrictive permissions** on config.yaml: `chmod 600 config.yaml`
3. **Use absolute paths** for `store` in production
4. **Avoid `txn_auto_approve: true` and `group_auto_approve: true`** in policy unless in a controlled environment
5. **Use `passphrase_timeout`** for additional security in shared environments

---

## Headless Operation

Headless operation allows Signer to run unattended without interactive prompts, enabling automated signing for use cases like scheduled transactions, CI/CD pipelines, or always-on services.

### What is Headless Mode?

In normal (interactive) operation:
1. Signer starts locked and waits for passphrase via apadmin
2. Each signing request requires manual approval via apapprover
3. When apadmin disconnects, the signer locks

In headless mode:
1. Signer starts unlocked using a passphrase file
2. Signing requests are auto-approved based on policy rules
3. The signer remains unlocked even without an admin connection

### Use Cases

| Scenario | Description |
|----------|-------------|
| **Scheduled transactions** | Cron jobs that send periodic payments |
| **CI/CD pipelines** | Automated testing with real transactions |
| **Always-on services** | Backend services that sign on demand |
| **Systemd services** | Signer as a system service |

### Required Configuration

Three configuration items work together to enable headless operation:

#### 1. `passphrase_command_argv` (config.yaml)

Specifies a helper command that can read and store the passphrase (or master key). The helper receives a **verb** (`read` or `write`) as its first argument, following the `git credential.helper` pattern.

**Protocol:**

| Verb | stdin | stdout | Required |
|------|-------|--------|----------|
| `read` | nothing | passphrase | yes |
| `write` | passphrase | passphrase (read-back) | optional (exit non-zero = unsupported) |

The command is invoked as: `argv[0] <verb> argv[1] argv[2] ...`

For example, `passphrase_command_argv: ["/usr/local/bin/pass-file", "/etc/aplane/passphrase"]` invokes:
- Read: `/usr/local/bin/pass-file read /etc/aplane/passphrase`
- Write: `/usr/local/bin/pass-file write /etc/aplane/passphrase` (with passphrase on stdin)

**Requirements:**
- All paths in `passphrase_command_argv` are resolved relative to the data directory (absolute paths are left unchanged)
- The binary must not be group/world-writable
- `read` must exit 0 and produce non-empty stdout
- Exactly one trailing newline is stripped from output
- Output may use `base64:` or `hex:` prefix for binary data
- `write` is optional — helpers that only support `read` should exit non-zero on `write`

**Built-in helper — pass-file (INSECURE / DEV ONLY):**

`pass-file` is a simple file-based helper included with aPlane. It reads/writes the passphrase from a plaintext file. Useful for development and testing, but not for production.

```yaml
# INSECURE / DEV ONLY: Passphrase stored in plaintext file
# Relative path (./pass-file) resolved relative to data directory
passphrase_command_argv: ["./pass-file", "passphrase"]
```

**Writing a custom helper:**

Your helper must accept a verb (`read` or `write`) as its first argument. A minimal shell wrapper around an existing tool:

```bash
#!/bin/sh
# /usr/local/bin/aplane-keychain-helper
# Wraps macOS Keychain for the passphrase command protocol
case "$1" in
  read)  security find-generic-password -s aplane-signer -w ;;
  write) read -r pass; security add-generic-password -U -s aplane-signer -w "$pass"
         security find-generic-password -s aplane-signer -w ;;
  *)     exit 2 ;;
esac
```

```yaml
# macOS Keychain via custom helper
passphrase_command_argv: ["/usr/local/bin/aplane-keychain-helper"]
```

**More examples:**

```yaml
# systemd credential via custom helper
passphrase_command_argv: ["/usr/local/bin/aplane-systemd-helper"]

# HashiCorp Vault via custom helper
passphrase_command_argv: ["/usr/local/bin/aplane-vault-helper"]
passphrase_command_env:
  VAULT_ADDR: "http://127.0.0.1:8200"
  VAULT_TOKEN: "s.xxxx"
```

**Controlled environment:** By default, the passphrase command runs with no environment variables. Use `passphrase_command_env` to declare specific variables:

```yaml
passphrase_command_env:
  AWS_REGION: "us-west-2"
  HOME: "/var/lib/aplane"
```

#### 2. `lock_on_disconnect` (config.yaml)

Keeps signer unlocked when no admin is connected.

```yaml
lock_on_disconnect: false
```

- Default is `true` (signer locks when apadmin disconnects)
- Set to `false` for headless operation
- Without this, the signer would lock immediately after startup

#### 3. Auto-Approve Policy (config.yaml)

Defines which transactions are signed without manual approval.

```yaml
# Auto-approve all transactions (use with caution)
txn_auto_approve: true
group_auto_approve: true
```

**Note**: Validation transactions (0 ALGO self-send) are always auto-approved.

### Complete Example

**config.yaml:**
```yaml
signer_port: 11270
store: /var/lib/aplane/keys
passphrase_command_argv: ["/usr/local/bin/aplane-keychain-helper"]
lock_on_disconnect: false
txn_auto_approve: true
```

### Security Considerations

| Risk | Mitigation |
|------|------------|
| Passphrase command compromise | Use absolute paths, verify binary is not writable by group/other |
| Unauthorized signing | Restrictive policy (avoid `txn_auto_approve`/`group_auto_approve` in production) |
| Physical access | Run on secured/isolated hardware |

**Recommendations:**

1. **Validation transactions** (0 ALGO self-send) are always auto-approved for connectivity testing.

2. **Audit logging**: All auto-approved signatures are logged for audit trails.

3. **Network isolation**: Run headless Signer on a private network segment.

### Interactive vs Headless Comparison

| Aspect | Interactive | Headless |
|--------|-------------|----------|
| Startup | Waits for passphrase | Reads from file |
| Admin connection | Required (apadmin) | Optional |
| Signing approval | Manual (apapprover) | Policy-based |
| Disconnect behavior | Signer locks | Signer stays unlocked |
| Use case | High-value, manual ops | Automated, scheduled ops |
