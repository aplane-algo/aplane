# Configuration Reference

This document describes the `config.yaml` files used by the APlane Shell suite.

## Overview

There are two distinct config.yaml formats:

| Tool | Purpose |
|------|---------|
| **apshell** | Client configuration (network defaults); endpoint routing lives in `endpoints.yaml` |
| **apsigner, apadmin, apapprover, apstore** | Server/admin configuration (keystore, ports, admin interface) |

Both programs use a **data directory** for configuration and state:

**apshell / Python SDK (clients):**
- Required: `-d <path>` flag or `APCLIENT_DATA` env var (no default)
- Installer convention: `~/aplane/apclient`

**apsigner / apadmin / apstore (server tools):**
- Required: `-d <path>` flag or `APSIGNER_DATA` env var (no default)
- Installer convention: `~/aplane/apsigner`

Config files are located at `<data_dir>/config.yaml`.
Unknown YAML fields are rejected at startup. This is intentional: misspelled
settings should fail visibly instead of being silently ignored.
Both client and signer `config.yaml` files support optional `schema_version: 1`;
omitting it is treated as v1 for existing configs.

See [USER_INSTALL.md](USER_INSTALL.md) for the installation directory layout and what each install mode creates.

---

## apshell Configuration

The apshell CLI uses `config.yaml` for network and UI defaults. Signer endpoint
routing lives in `$APCLIENT_DATA/endpoints.yaml`. See
[USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md) for field-level reference.

### Example config.yaml

```yaml
schema_version: 1
network: testnet
signer_status_poll_interval: "10s"
```

### Example endpoints.yaml

```yaml
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
```

Note: endpoint SSH paths are relative to the data directory (installer default:
`~/aplane/apclient`). The `.ssh/` subdirectory is created automatically when
needed. SSH authentication uses an enrolled public key plus a programmatic,
host-key-bound proof of the API token; the token is not sent as the SSH username.
APlane does not read or write the operating-system user's personal SSH
directory; client keys and host trust are isolated under `$APCLIENT_DATA/.ssh/`.

`signer_status_poll_interval` controls interactive apshell's background
authenticated `/status` checks. The default is `"10s"`. Use a larger duration
to reduce background traffic, or `"0"` to disable automatic keyset refresh
polling; when disabled, apshell will not automatically notice signer key
additions/deletions made elsewhere.

### Algod Endpoints

Installer-written client and signer configs include `testnet`, `mainnet`, and
`localnet` under `networks` by default. `testnet` and `mainnet` use public
Nodely endpoints. `localnet` uses the
standard AlgoKit LocalNet algod endpoint and token. Installer-written client
configs restrict `networks_allowed` to `mainnet` and `testnet` by
default. The default active network remains `testnet`. For AlgoKit LocalNet,
run `aplocalnet` to set `network: localnet`, refresh the signer genesis mapping,
enable the bundled LocalNet plugin, and add `localnet` to a non-empty
`networks_allowed` list. If you edit config manually, add `localnet` to
`networks_allowed` before switching apshell to that network.

Network names are context tokens: 1-64 lowercase letters, digits, `_`, or `-`,
starting with a letter or digit. Built-in Algorand tokens are `mainnet`,
`testnet`, and `betanet`; custom tokens such as `localnet` and `voi_mainnet`
are also valid.

```yaml
schema_version: 1
network: testnet
networks_allowed:
  - mainnet
  - testnet
networks:
  testnet:
    algod:
      server: https://testnet-api.4160.nodely.dev
      token: ""
  mainnet:
    algod:
      server: https://mainnet-api.4160.nodely.dev
      token: ""
  localnet:
    algod:
      server: http://localhost:4001
      token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  voi_mainnet:
    algod:
      server: http://localhost:4002
      token: your-api-token
```

### Network Restriction

The `networks_allowed` field restricts which networks apshell can connect to. This is useful for:
- Preventing accidental mainnet transactions during development
- Restricting operators to specific networks

```yaml
network: testnet
networks_allowed:
  - mainnet
  - testnet
```

With this configuration:
- apshell starts on testnet
- The `network` command can only switch to mainnet or testnet
- Attempting to switch to localnet will fail unless `localnet` is added

If `networks_allowed` is empty or omitted, all networks are allowed.

### Data Directory Setup

```bash
# Export APCLIENT_DATA (or pass -d every invocation)
export APCLIENT_DATA=~/aplane/apclient

# First-time setup: create config and SSH key
mkdir -p "$APCLIENT_DATA/.ssh"
ssh-keygen -t ed25519 -f "$APCLIENT_DATA/.ssh/id_ed25519" -N ""

# Create config.yaml (or start from examples/config/apclient/config.yaml)
cat > "$APCLIENT_DATA/config.yaml" << 'EOF'
schema_version: 1
network: testnet
signer_status_poll_interval: "10s"
EOF

# Create endpoints.yaml (or start from examples/config/apclient/endpoints.yaml)
cat > "$APCLIENT_DATA/endpoints.yaml" << 'EOF'
schema_version: 2
default: primary
endpoints:
  primary:
    role: signer
    url: ssh://signer.example.com:1127
    identity_file: .ssh/id_ed25519
    known_hosts_path: .ssh/known_hosts
    token_file: aplane.token
EOF

# Request token from signer (requires operator approval)
./apshell
> request-token
# After approval, apshell saves the token and immediately tries to connect.

# Or use custom directory
./apshell -d /custom/path
export APCLIENT_DATA=/custom/path
```

### Notes
- Ready-to-copy example configs live under [`examples/config/`](../examples/config/), including [`examples/config/apclient/`](../examples/config/apclient/) and [`examples/config/apsigner/`](../examples/config/apsigner/).

- All connections use SSH tunneling for uniform per-client identity
- Clients store signer routing in `endpoints.yaml`
- Top-level `ssh:` and `signer_port:` settings in client `config.yaml` are not
  supported; create a fresh apclient data directory or write signer routing in
  `endpoints.yaml`.
- Edit `endpoints.yaml` or use `endpoints import` to change signer
  endpoint routing

### Connect Command Behavior

The `connect` command with no arguments connects to the default signer. In the
normal endpoint-registry setup, it reads the default signer from
`endpoints.yaml` and that endpoint's configured token file:

```bash
connect
```

Client signer routing must be present in `endpoints.yaml`. Startup does not
rewrite client config or synthesize endpoint records from `config.yaml`.

For endpoint aliases, the preferred handoff is for the signer operator to
export a public endpoint envelope and for the client to import it:

`apadmin endpoint export` connects to the running daemon through authenticated
admin transport. It reads the configured endpoint defaults without requiring direct
access to the private signer store and writes `--out` as the invoking operator.

```bash
# signer side
apadmin -d "$APSIGNER_DATA" endpoint export \
  --host signer.example.com \
  --out signer.endpoint.json

# client side, inside apshell
endpoints import --alias main --role signer signer.endpoint.json
endpoints show main
request-token --endpoint main
connect main
```

For a cosigner endpoint, the client can also create the endpoint profile manually
when the operator already knows the client-reachable URL:

```bash
endpoints create --alias local-cosigner \
  --endpoint ssh://cosigner.example.com:1127
request-token --endpoint local-cosigner
endpoints discover-cosigners
```

Discovery is a read-only connectivity diagnostic. To make the cosigner key
available when generating guarded accounts, export it on the cosigner node with
`apadmin cosigner export` and explicitly import it on the signer node with
`apadmin cosigner import`. Signing operations resolve the matching endpoint from
live authenticated `/keys` responses.

If the signer operator sets a client-reachable advertised URL in
`$APSIGNER_DATA/config.yaml`, `apadmin endpoint export` can omit `--host`, and
the cosigner key export screen shows it as the address clients add with
`endpoints add`. Cosigner installs prompt for this address when they write a
new config:

```yaml
endpoint:
  advertise_url: ssh://signer.example.com:1127
```

Without `--host`, `--url`, or `endpoint.advertise_url`, endpoint export fails
instead of guessing from local network interfaces.

The SSH bind host and advertised handoff URL are deployment settings managed in
`$APSIGNER_DATA/config.yaml`. `endpoint.ssh.listen_address` defaults to
`127.0.0.1`; change it in config and restart apsigner when the SSH listener
should bind somewhere else. If `endpoint.advertise_url` is empty, the admin
header derives a local URL from `endpoint.ssh.listen_address` and
`endpoint.ssh.port`; a wildcard bind such as `0.0.0.0` displays the signer
host's detected primary outbound IPv4 address when available, with `127.0.0.1`
as the fallback.

Importing an endpoint creates routing/configuration only. It does not copy API
tokens, SSH host trust, private keys, or passphrases. Tokens are still obtained
with `request-token --endpoint <alias>`. Re-import with the same alias replaces
that alias's endpoint data.

The imported local registry is stored in `$APCLIENT_DATA/endpoints.yaml`:

```yaml
schema_version: 2
default: main
endpoints:
  main:
    role: signer
    url: ssh://signer.example.com:1127
    token_file: aplane.token
```

Then:

```bash
connect                 # default endpoint
connect main
request-token --endpoint main
```

Useful local commands:

```bash
endpoints list
endpoints show main
endpoints import --alias main --role signer --dry-run signer.endpoint.json
endpoints create --alias local-cosigner --endpoint ssh://127.0.0.1:2223
endpoints default main
endpoints delete old-signer
```

Token enrollment is endpoint-only. Import or configure a signer endpoint
before running `request-token`; create or import a cosigner endpoint before
running `request-token --endpoint <alias>`.

---

## apsigner / apadmin / apapprover Configuration

The server and admin tools share the same config format and data directory.

### Live vs Offline Configuration

There are two configuration paths for the signer, and they cover different
moments:

- `apsigner` + `apadmin`: use these while the signer daemon is running.
- `appass`: use this while the signer daemon is stopped, to change how the
  passphrase is handled at startup.

Day-to-day:

- Use `apadmin` to unlock the signer, approve transactions, change runtime
  admin settings, and check and apply the node-role policy with
  `apadmin policy` while `apsigner` is running.
- Use `apadmin policy rescue` for offline or scriptable policy inspection,
  validation, and application of the node-role policy documents: `policy.json`
  on signer nodes, or one `policies/<WitnessKeyID>.json` per cosigner key on
  cosigner nodes.
- Use `appass` only to switch passphrase auto-handling mode (`prompt`,
  `passfile`, `systemd-creds`).
- `appass` refuses to run while `apsigner` is active for the same data
  directory.
- Stop `apsigner` before changing `unlock.yaml` or the process-global
  `passphrase_command_argv` compatibility setting.

Keeping live admin and offline unlock setup in separate tools prevents the
running daemon's in-memory state from drifting out of sync with the signer
config files on disk.

### Fields

See [USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md) for field-level reference.

The top-level `config.yaml` provides defaults for `user_auto_approve`,
`lock_on_disconnect`, `passphrase_timeout`, and `approval_wait`. When you
change `user_auto_approve`, `lock_on_disconnect`, or `passphrase_timeout`
through admin IPC, the signer writes it as a product-local override at
`identities/default/config.yaml`. `approval_wait` is process/YAML-only; it is
not part of the admin settings payload and cannot be changed through admin IPC.

Node role is stored separately in the signer data root `node.yaml`. Standard
installations initialize as signer nodes; product config does not carry a role
or mode field.

In `apadmin`, the operator-default shortcut is shown as `User Auto-Approve`:
`ON` means `user_auto_approve: true`; `OFF` means `user_auto_approve: false`.

`passphrase_command_argv` and `passphrase_command_env` are accepted in the
top-level `config.yaml`. `appass` writes its configuration to
`identities/default/unlock.yaml`, which takes precedence.

### Genesis Hash Network Mapping

Signer policy derives transaction network identity from `GenesisHash`, not from `GenesisID`. The built-in Algorand mappings are compiled into the source:

| Network token | Genesis hash |
|---------------|--------------|
| `mainnet` | `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=` |
| `testnet` | `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=` |
| `betanet` | `mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=` |

Custom networks are configured with `networks.<network>.genesis_hash`:

```yaml
teal_compile_network: voi_mainnet
networks:
  voi_mainnet:
    algod:
      server: http://localhost:4002
      token: your-api-token
    genesis_hash: "base64-or-hex-32-byte-genesis-hash"
```

`mainnet`, `testnet`, and `betanet` are reserved. Custom mappings cannot reuse
those tokens or override their built-in genesis hashes. Use the grouped
`networks` form; top-level `algod` and `genesis_hash_networks` are not part of
the config schema.

Each custom network token has one configured genesis hash. If you recreate an
AlgoKit LocalNet or switch to another private network with a different genesis
hash, update `networks.<network>.genesis_hash` or use a different network token.

### Passphrase Timeout Values

The `passphrase_timeout` setting controls how long `apadmin` stays connected
without local keyboard activity. When the timer fires, `apadmin` disconnects
from `apsigner`. The signer does not maintain a separate activity timer based
on admin input.

> **Naming note:** despite the name, `passphrase_timeout` is not a time-to-live
> on passphrase entry. It is the admin idle-session timeout — the runtime concept
> is `SessionTimeout` (admin idle disconnect). The configuration field remains
> `passphrase_timeout`.

In the default `prompt` passphrase mode, the signer effectively stays unlocked
only while an admin client remains connected when `lock_on_disconnect: true`.
With a nonzero `passphrase_timeout`, `apadmin` disconnects after local keyboard
inactivity. If `lock_on_disconnect` is `true`, that disconnect locks the signer.
If `lock_on_disconnect` is `false`, the signer remains unlocked until manual
lock, process stop, restart, or another explicit lock path. The time-based
disconnect can be disabled by setting `passphrase_timeout: "0"`.

When `apadmin` is connected, keyboard input in the TUI counts as user activity
for the admin session. Background screen refreshes, admin-panel polling, IPC
responses, window resize events, and mouse events do not keep the admin session
alive. If the TUI sees no local keyboard input for the effective
`passphrase_timeout`, it disconnects the admin session. A lock caused by that
disconnect is controlled by `lock_on_disconnect`.

When product-local `unlock.yaml` is configured by `appass`, the signer starts
the product runtime in headless mode and the effective runtime behavior is:

- passphrase timeout is disabled (`0`)
- lock-on-disconnect is disabled

For process-global `passphrase_command_argv`, `config.yaml` must set
`passphrase_timeout: "0"` and must not set `lock_on_disconnect: true`.

#### Lock / Unlock Behavior Matrix

| Passphrase mode | `passphrase_timeout` | `lock_on_disconnect` | While Admin app is connected | When Admin app closes/disconnects |
|-----------------|----------------------|-----------------------|------------------------------|-----------------------------------|
| `prompt` | nonzero, e.g. `"15m"` | `true` | Admin app disconnects after local inactivity; signer locks through disconnect policy | Signer locks immediately |
| `prompt` | nonzero, e.g. `"15m"` | `false` | Admin app disconnects after local inactivity; signer remains unlocked | Signer stays unlocked |
| `prompt` | `"0"` | `true` | Admin app stays connected until closed | Signer locks immediately |
| `prompt` | `"0"` | `false` | Admin app stays connected until closed | Signer stays unlocked |
| `passfile` / `systemd-creds` | `"0"` | effectively `false` | Signer starts unlocked and stays unlocked until stopped | Signer stays unlocked |
| `passfile` / `systemd-creds` | nonzero | any | Invalid headless configuration; startup validation rejects it | Invalid headless configuration |

In this table, "Admin app" means `apadmin` or the embedded signer-admin panel
inside `apconsole`. "Admin activity" means local keyboard interaction in the
TUI; background refreshes do not keep the admin session connected.

| Value | Behavior |
|-------|----------|
| `"0"` | Admin idle disconnect is disabled |
| `"15m"` | Admin app disconnects after 15 minutes of local keyboard inactivity |
| `"1h"` | Admin app disconnects after 1 hour of local keyboard inactivity |

### Admin Interface

apadmin uses local Unix socket IPC at `ipc_path`:
- systemd installs use `/run/apsigner/aplane.sock`: runtime directory `0750`,
  socket `0660`, and no operator-group access to persistent signer state
- same-UID local mode defaults to `$APSIGNER_DATA/aplane.sock`
- `APSIGNER_IPC_PATH` or an explicit `-ipc-path` client option can override
  discovery for custom deployments
- an explicit `-d` takes precedence over inherited `APSIGNER_IPC_PATH`; use
  `-ipc-path` as well when intentionally overriding the socket for that
  explicitly selected store
- `apconsole` only manages daemon startup when the client path matches the
  selected store's configured daemon path. Use `--no-start-daemon` for an
  intentional attach-only IPC override.
- cannot be snooped with tcpdump (no network stack)
- local apadmin and apapprover connect via this socket

`apadmin` does not read `APCLIENT_DATA`, endpoint registries, or client tokens.
For remote administration, SSH into the signer machine and run it there:

```bash
ssh -t user@signer 'apadmin -d /path/to/signer-data'
```

**Default IPC path**: `/run/apsigner/aplane.sock` for systemd;
`$APSIGNER_DATA/aplane.sock` for same-UID local mode.
### Data Directory Setup

```bash
# Create data directory (installer convention: ~/aplane/apsigner)
export APSIGNER_DATA=~/aplane/apsigner
mkdir -p "$APSIGNER_DATA"

# Start from the example config
cp examples/config/apsigner/config.yaml.example "$APSIGNER_DATA/config.yaml"

# Edit $APSIGNER_DATA/config.yaml to set ports, algod endpoints, and other options

# Initialize the local keystore before starting apsigner
./apstore initialize
# Or, for a dedicated cosigner node:
./apstore initialize --role cosigner
./apsigner
```

`apsigner` supports `-version`, `-print-manifest`, and `-d <data-dir>`.

**Note:** Run `apstore initialize` locally to create the store's atomic cryptographic root (`store-root.enc`), initial generation, and format marker (`.keystore`). `apsigner` can start without them — it enters a forced-locked state until the keystore is initialized — but no signing operations work until they exist.

### Example (Interactive Mode with SSH)

```yaml
endpoint:
  signer_port: 11270
  ssh:
    listen_address: 127.0.0.1
    port: 1127
    host_key_path: .ssh/ssh_host_key
    authorized_keys_path: .ssh/authorized_keys
  advertise_url: ssh://signer.example.com:1127
passphrase_timeout: "15m"
lock_on_disconnect: true
```

### Managing Passphrase Auto-Handling with `appass`

`appass` is the dedicated tool for switching between these startup modes:

- `Prompt` — normal manual unlock via `apadmin`
- `Passfile` — development-only plaintext file helper
- `Systemd` — Systemd helper using `systemd-creds`

Important:

- `appass` is an offline configuration tool
- `apsigner` must be stopped before running `appass`
- if `apsigner` is running, `appass` exits with a warning instead of editing auto-unlock configuration

Typical workflow:

```bash
# Stop the signer first
sudo systemctl stop apsigner

# Or for a local/manual process: stop the running apsigner instance

# Then run appass against the systemd signer data directory
sudo appass -d /var/lib/apsigner
```

Inside the `appass` TUI, choose the desired passphrase handling mode and follow the prompts.

Use `appass` when you want to change startup unlock behavior. Use `apadmin` when the daemon is already running and you want to manage the live signer session.

If `appass` reports a warning after a successful mode change, the new mode is already active and stored in product-local `unlock.yaml`. The warning means cleanup of the previous mode's leftover files or service settings needs manual follow-up.

Note: SSH paths are relative to the data directory (`$APSIGNER_DATA`). The `.ssh/` subdirectory is created automatically when needed. `apsigner` always enables SSH using these defaults unless you override them, and keeps its REST API bound to loopback.

### Notes

- Relative paths in config are resolved from the data directory
- apadmin and apapprover connect via the IPC socket
- `user_auto_approve` is the `User Auto-Approve` runtime admin setting persisted with product config
- signer safety guards live in the product-local v1 JSON policy documents
- See [Headless Operation](#headless-operation) for unattended deployment

---

## Policy

For the full current policy model and phase ordering, see
[ARCH_POLICY.md](ARCH_POLICY.md). The v1 JSON document format is specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md).

Signer safety policy is product-local and stored in the selected store
generation. A signer node has one document; a cosigner node has one document
per cosigner key:

```text
$APSIGNER_DATA/identities/default/generations/<selected-generation>/policy.json
$APSIGNER_DATA/identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json
```

Each document has a sibling `.hmac` sidecar that authenticates its exact bytes.
`apstore initialize` creates a signer node with a signed starting document
that allows self-transfers only: one route lets any account send any asset
to itself, and every other transfer is rejected until a route allows it. A
new cosigner node has no policy documents, so every cosigner key rejects
every request until its policy is applied. The signer verifies every policy document on unlock/reload before it
loads keys. A missing or mismatched sidecar, or a document that does not
decode, makes the node refuse to load instead of falling back to default
policy.

The policy controls hard-reject, forced-review, and explicit auto-approval
rules for signing. It is separate from:

- process/product runtime settings like `signer_port`, `user_auto_approve`, and SSH
- approval UI state such as which pending request an operator is viewing

For the operator-facing policy guide, including commands, transfer routing,
and key override examples, see [USER_POLICY.md](USER_POLICY.md). This section
is a configuration reference for the policy fields.

Write or edit the policy file outside the node, run `apadmin policy check FILE`,
then `apadmin policy apply FILE` while `apsigner` is running; the signer
validates the file for its node role, commits the exact bytes plus a fresh
sidecar as a new store generation, and activates the result immediately. On a
cosigner node each file names its key in its `"key"` field, and
`apadmin policy remove ID` deletes one key's document. Use
`apadmin policy rescue status|export|check|apply|remove` while the daemon is
stopped; rescue applies use the same rules and also commit a new generation.
For documents placed or edited by hand in the selected generation, run
`apstore policy check`, review the change, then run `apstore policy sign`;
`apstore policy verify` confirms the signed policy documents with the store
passphrase. `apstore policy sign` and `apadmin policy rescue apply` are offline
store mutations, so run them while `apsigner` is stopped. Hand edits are
active only after the next successful signer start, reload, or unlock.

Policy verdicts override the operator default. Among policy verdicts, the most
restrictive matching verdict wins:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

### Supported Fields

Signer document fields (`"format": "aplane.signer-policy.v1"`). Amounts are
decimal strings in base units.

| Field | Type | Meaning |
|-------|------|---------|
| `format` | string | Required document type |
| `description` | string | Notes for reviewers |
| `reject_foreign_rekey` | bool | Reject txns with non-zero `RekeyTo` only when the rekey target is not held by the current signer |
| `reject_close_remainder` | bool | Reject payment txns with non-zero `CloseRemainderTo` |
| `reject_asset_close` | bool | Reject ASA transfer txns with non-zero `AssetCloseTo` |
| `reject_clawback` | bool | Reject ASA clawback txns using `AssetSender` |
| `always_review_warnings` | bool | Require operator review for txns with warning-level findings, even when `user_auto_approve:true` |
| `auto_approve_self_noop_transfer` | bool | Auto-approve a single 0 ALGO payment to self or 0-unit ASA transfer to self with no caller-provided group, no passthrough/foreign slots, no rekey, no close remainder, no asset close, no clawback sender, no note, no lease, and normalized fee at most 1000 microAlgos. Signer-generated LogicSig-budget dummies are allowed when they exactly match APlane's dummy transaction shape. |
| `max_fee_microalgos` | amount | Reject txns whose fee exceeds this raw microAlgo ceiling (omitted = no limit) |
| `limits` | map | Per-network, per-asset (`algo` or `asa:<id>`) `review_above` / `reject_above` thresholds in base units |
| `address_sets` | map | Named address sets for routes |
| `asset_sets` | map | Named per-network asset sets for routes |
| `transfer_policy` | map | Direct transfer route table for source/asset/destination policy; see [Transfer routing](#transfer-routing) |
| `key_overrides` | map | Per-key override blocks; see [Key overrides](#key-overrides) below |

Cosigner documents (`"format": "aplane.cosigner-policy.v1"`) carry a required
`key` (the Witness Key ID, matching the file name), `reject_close_remainder`,
`reject_asset_close`, `reject_clawback`, `reject_rekey` (coarse deny-all switch
for non-zero `RekeyTo`), `max_fee_microalgos`, `limits` with `reject_above`
only, document-local `address_sets` and `asset_sets`, a required
`transfer_policy` with `blocked_destinations` and `routes`, and `rekey_policy`
(allow-list for pure 0 ALGO self-payment rekeys by sender and rekey target).

`auto_approve_self_noop_transfer` treats the transaction shape as low risk; a
0-unit ASA self-transfer can still opt the account into an asset if the account
does not already hold it. For Falcon and other large LogicSig keys, APlane may
add dummy transactions to provide LogicSig budget; this rule only approves those
dummies when they are generated by the signer and the real transaction's fee
increase exactly matches the required dummy fees.

### Defaults

Omitted fields default to:

- `reject_foreign_rekey: true` (foreign rekey changes account control to an address outside this signer, so it is rejected by default)
- cosigner `reject_rekey: false`, but non-zero `RekeyTo` still fails closed unless `rekey_policy.allowed` authorizes the sender-to-target edge
- `reject_close_remainder: false`
- `reject_asset_close: false`
- `reject_clawback: false`
- `always_review_warnings: false`
- `auto_approve_self_noop_transfer: false`
- other guards unset / disabled

`rekey_policy` applies to dedicated `cosigner1` guarded accounts. Corridor v1's
cosigner is spend-only; its pure rekey uses the separate offline contract-admin
witness and does not evaluate cosigner policy.

### Example

```json
{
  "format": "aplane.signer-policy.v1",
  "reject_foreign_rekey": true,
  "reject_close_remainder": true,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "1000000",
  "limits": {
    "mainnet": {
      "algo": { "review_above": "1000000", "reject_above": "5000000" },
      "asa:31566704": { "reject_above": "1000000" }
    },
    "testnet": {
      "algo": { "review_above": "5000000", "reject_above": "10000000" },
      "asa:10458941": { "review_above": "500000000" },
      "asa:123456": { "reject_above": "500" }
    },
    "voi_mainnet": {
      "asa:987654": { "reject_above": "250" }
    }
  }
}
```

This reviews mainnet ALGO payments over 1 ALGO and rejects them over 5 ALGO
(amounts are raw microAlgos), and sets per-asset thresholds in raw ASA units;
`"500000000"` for testnet ASA `10458941` is 500 USDC, assuming 6 decimals.

### Transfer Routing

`transfer_policy` is the route table for direct `pay` and `axfer`
transactions. Edit routes in the policy file outside the node, then run
`apadmin policy check FILE` and `apadmin policy apply FILE` while the signer is
running, or the `apadmin -d "$APSIGNER_DATA" policy rescue` forms while it is
stopped.

For the broader operator policy guide, see [USER_POLICY.md](USER_POLICY.md).
For the transfer routing deep dive with worked examples, validation rules, and
troubleshooting, see [USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

Routes constrain signer-controlled transfer movements by network, source,
asset, and destination. A matching route means the movement may continue
through the normal policy pipeline; it is not an auto-approval. Routing can
produce Always Deny or Always Review verdicts, never Always Approve.

Minimal signer shape:

```json
{
  "format": "aplane.signer-policy.v1",
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "blocked_destinations": [],
    "routes": []
  }
}
```

`close_on_no_route` and `clawback_on_no_route` are optional keys that control
close-out and clawback movements matching no route; both default to `reject`
when omitted and accept the same values as `on_no_route`.

The `on_no_route` value controls in-scope transfer movements that match no
route:

| Value | Meaning |
|-------|---------|
| `reject` | route misses are Always Deny |
| `review` | route misses are Always Review |
| `operator_default` | route misses produce no routing verdict |

Whenever a signer `transfer_policy` is present, set `enabled` explicitly to
`true` or `false`. When `enabled` is `true`, set `on_no_route` explicitly. A
cosigner document's `transfer_policy` has no `enabled` or `on_no_route`: its
route misses are always rejected.

Route fields:

| Field | Meaning |
|-------|---------|
| `id` | Stable lowercase identifier used in audit/policy rule IDs |
| `description` | Optional operator-facing note |
| `networks` | `["*"]` for all resolved networks, or concrete tokens such as `["mainnet"]` |
| `sources` | Sender addresses, `@address_set` references, or `*` |
| `assets` | `algo`, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | Receiver addresses, `@address_set` references, `self`, or `*` |
| `limits` | Optional per-network, per-asset raw amount thresholds |
| `allow_close` | Optional; permits matching close-out movements when `true` |
| `allow_clawback` | Optional; permits matching clawback movements when `true` |
| `asset_sources` | Clawback-only ASA source terms; requires `"allow_clawback": true` |

`transfer_policy.blocked_destinations` is a flat concrete-address deny list
checked before route matching. It is useful for recipients that must always be
denied even when a broad wildcard route would otherwise match.

`self` is valid only in `destinations` and means "the same address as the
transaction sender." `"networks": ["*"]` means all networks whose genesis
hashes the signer can resolve; it is not limited to localnet.

#### Address And Asset Sets

Address sets and asset sets are top-level document fields. A flat address list
applies on every network; a map applies only on named network context tokens.
Asset sets are always network maps because ASA IDs are network-local.

```json
{
  "format": "aplane.signer-policy.v1",
  "address_sets": {
    "treasury": {
      "mainnet": ["TREASURYMAINNET..."],
      "testnet": ["TREASURYTESTNET..."]
    },
    "payroll": ["PAYROLL1...", "PAYROLL2..."]
  },
  "asset_sets": {
    "stablecoins": {
      "mainnet": ["asa:31566704"],
      "testnet": ["asa:10458941"]
    }
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": [
      {
        "id": "treasury_algo_payroll",
        "networks": ["mainnet", "testnet"],
        "sources": ["@treasury"],
        "assets": ["algo"],
        "destinations": ["@payroll"]
      },
      {
        "id": "treasury_stablecoins_payroll",
        "networks": ["mainnet", "testnet"],
        "sources": ["@treasury"],
        "assets": ["@stablecoins"],
        "destinations": ["@payroll"]
      }
    ]
  }
}
```

#### Amount Thresholds

Amount thresholds use raw on-chain units: microAlgos for ALGO and raw ASA units
for assets. Threshold comparison is strict greater-than. For example,
`"review_above": "250000000"` reviews ALGO payments above 250 ALGO, not exactly
250 ALGO. Route `limits` are keyed by network, then by asset, and may name only
networks and assets the route covers:

```json
"limits": {
  "mainnet": {
    "algo": { "review_above": "250000000", "reject_above": "1000000000" }
  }
}
```

`reject_above` must be greater than or equal to `review_above` when both are
set. Deny is evaluated before review, so equal thresholds reject matching
amounts above that value.

#### Close-Out And Clawback

Close-out and clawback are denied by routing unless a matching route explicitly
sets `"allow_close": true` or `"allow_clawback": true`. The
`reject_close_remainder`, `reject_asset_close`, and `reject_clawback` guards
still apply independently and can reject even when a route permits the
movement; `apadmin policy check` warns about that overlap. See
[USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md#close-out-and-clawback) for
route examples.

#### Route-Miss Defaults

Use `"on_no_route": "review"` when route misses should reach an operator prompt
instead of hard rejection. Use `"on_no_route": "operator_default"` only when
route misses should behave as if routing did not exist; matching route
thresholds and close/clawback checks still apply.

For normative implementation details, see
[ARCH_POLICY.md#transfer-routing](ARCH_POLICY.md#transfer-routing).

### Key Overrides

`key_overrides` lets a signer document relax or tighten specific guards for
one concrete signing key without changing the document-wide settings. Map keys
are Algorand auth addresses. Scalar fields left unset in an override inherit
from the document, and override `limits` merge per network, asset, and
threshold (`null` removes one inherited threshold). Overrides do not nest, and
they cannot carry `transfer_policy` or sets; express per-account routing with
route `sources` instead. Cosigner documents have no overrides.

When a transaction is linted, the signer picks the override block for the auth
address that will actually sign it and applies that block on top of the
document settings; other keys use the document settings.

```json
{
  "format": "aplane.signer-policy.v1",
  "reject_foreign_rekey": true,
  "reject_asset_close": false,
  "key_overrides": {
    "SIGNINGAUTHADDRESS...": {
      "description": "Generic key with no LogicSig enforcement: tighten further.",
      "reject_asset_close": true
    },
    "OTHERAUTHADDRESS...": {
      "description": "Needs more fee headroom.",
      "max_fee_microalgos": "5000"
    }
  }
}
```

### Approval vs Policy

Policy and approval are separate:

- safety policy rejects matching requests before approval
- transfer review guards force operator review for matching requests that were not rejected
- `always_review_warnings:true` forces operator review for warning-level findings before auto-approval or operator default can sign
- warnings still appear for dangerous fields even when not configured to force review
- `User Auto-Approve` ON (`user_auto_approve: true`) skips human approval only for requests that are not rejected, not forced to review, and not explicitly auto-approved

In short:

```text
Policy first, operator default last.
```

### Example (User Auto-Approve On - Testing Only)

```yaml
user_auto_approve: true
```

⚠️ **Warning**: Only use this in controlled testing environments.

---

## Authentication

Signer uses one product token for authenticating API requests from apshell and the Python SDK.

### How It Works

1. **Token generation**: `apstore initialize` creates a cryptographically secure 256-bit random token for the product
2. **Token storage**: Saved to `identities/default/aplane.token`, alongside the keys it grants access to
3. **Token provisioning**: Clients request tokens via SSH (requires operator approval in apadmin)
4. **Request authentication**: Clients send the token via `Authorization: aplane <token>` HTTP header
5. **Validation**: apsigner validates using constant-time comparison (prevents timing attacks)

apadmin authenticates over local IPC independently of client API tokens.

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

# For a named endpoint in endpoints.yaml
> request-token --endpoint main

# In Python SDK
from aplanesdk import request_token_to_file
request_token_to_file()  # reads APCLIENT_DATA from environment
```

The operator sees the client's SSH fingerprint in apadmin and can verify identity before approving.

### Manual Token Setup (Alternative)

If the client's SSH key is already in `authorized_keys` (e.g. added manually by the operator), you can copy the token directly:

```bash
# 1. Add the APlane client's public key to authorized_keys
mkdir -p $APSIGNER_DATA/identities/default/.ssh
cat $APCLIENT_DATA/.ssh/id_ed25519.pub >> $APSIGNER_DATA/identities/default/.ssh/authorized_keys

# 2. Copy token from signer to client
cp $APSIGNER_DATA/identities/default/aplane.token $APCLIENT_DATA/
```

Copy the token **after** the client endpoint exists (`endpoints import` or
`endpoints create`). Creating an endpoint, or changing its destination, removes
any token file already at that endpoint's token path, because such a file was
issued for an earlier endpoint. Copy it to the endpoint's `token_file`, shown
by `endpoints show <alias>`.

> **Note:** The `request-token` flow is preferred — it handles both key enrollment and token delivery in a single operator-approved step.
After approval, interactive `apshell` writes the token to the selected endpoint's
configured token file and immediately attempts to establish the signer SSH tunnel
when that endpoint is the default signer.

### Token Revocation

The operator can revoke the current token from the apadmin Admin panel by
pressing `t`. This:

1. Generates a new random token and writes it to disk
2. Disconnects all connected clients immediately
3. Requires clients to run `request-token` again to obtain the new token (operator approval required)

Use this when a token may be compromised or to rotate credentials.

### Endpoints

| Endpoint | Authentication |
|----------|----------------|
| `POST /sign` | Required |
| `POST /sign/component` | Required |
| `POST /sign/assemble` | Required |
| `POST /sign/cancel` | Required |
| `POST /plan` | Required |
| `GET /status` | Required |
| `GET /keys` | Required |
| `GET /keytypes` | Required |
| `POST /admin/generate` | Required |
| `DELETE /admin/keys` | Required |
| `GET /health` | Not required (public health check) |

### Security Notes

- The token acts as a pre-shared secret between apshell and apsigner
- For remote connections, the token travels through the SSH tunnel (encrypted)
- Keep `aplane.token` secure with `chmod 600`
- Revoke and regenerate via the `t` shortcut on the apadmin Admin panel (preferred), or by deleting the file and restarting apsigner

---

## Environment Variables

See [USER_CONFIG_REFERENCE.md](USER_CONFIG_REFERENCE.md) for the full list of environment variables and data directory configuration.

---

## Security Recommendations

1. **Prefer local IPC when you are on the signer host** (Unix socket provides file-permission-based access control)
2. **Set restrictive permissions** on config.yaml: `chmod 600 config.yaml`
3. **Avoid `user_auto_approve: true`** unless in a controlled environment
4. **Use restrictive policy safety guards** for rekey, close-out, and transfer ceilings
5. **Use `passphrase_timeout` with `lock_on_disconnect:true`** for additional security in shared environments

---

## Headless Operation

Headless operation allows Signer to run unattended without interactive prompts, enabling automated signing for use cases like scheduled transactions, CI/CD pipelines, or always-on services.

### What is Headless Mode?

In normal (interactive) operation:
1. Signer starts locked and waits for passphrase via apadmin
2. By default, signing and token-provisioning requests require manual approval via apadmin or apapprover
3. In default prompt mode, apadmin can disconnect after local keyboard inactivity
4. When apadmin disconnects, the signer locks

In headless mode:
1. Signer starts unlocked using a configured passphrase helper
2. Signing requests can skip manual review when `User Auto-Approve` is ON (`user_auto_approve: true`)
3. The signer remains unlocked even without an admin connection

Headless mode is intentionally long-lived: `passphrase_timeout` must be `0`, `lock_on_disconnect:true` is invalid, and the signer stays unlocked in memory until you stop it or lock it manually.

### Use Cases

| Scenario | Description |
|----------|-------------|
| **Scheduled transactions** | Cron jobs that send periodic payments |
| **CI/CD pipelines** | Automated testing with real transactions |
| **Always-on services** | Backend services that sign on demand |
| **Systemd services** | Signer as a system service |

### Required Configuration

Use `appass` to configure headless unlock for the product store. It writes
`identities/default/unlock.yaml` and removes process-global passphrase helper
compatibility settings so they do not conflict.

Three effective settings work together to enable headless operation:

#### 1. `passphrase_command_argv` (`unlock.yaml`, or process-global `config.yaml`)

Specifies a helper command that can read and store the passphrase (or master
key). The helper receives a **verb** (`read` or `write`) as its first argument,
following the `git credential.helper` pattern.

**Protocol:**

| Verb | stdin | stdout | Required |
|------|-------|--------|----------|
| `read` | nothing | passphrase | yes |
| `write` | passphrase | passphrase (read-back) | optional (exit non-zero = unsupported) |

The command is invoked as: `argv[0] <verb> argv[1] argv[2] ...`

For example, `passphrase_command_argv: ["/usr/local/bin/appass-file", "/etc/aplane/passphrase"]` invokes:
- Read: `/usr/local/bin/appass-file read /etc/aplane/passphrase`
- Write: `/usr/local/bin/appass-file write /etc/aplane/passphrase` (with passphrase on stdin)

**Requirements:**
- All paths in `passphrase_command_argv` are resolved relative to the data directory (absolute paths are left unchanged)
- The binary must not be group/world-writable
- `read` must exit 0 and produce non-empty stdout
- Exactly one trailing newline is stripped from output
- Output may use `base64:` or `hex:` prefix for binary data
- `write` is optional — helpers that only support `read` should exit non-zero on `write`

**Built-in helper — appass-file (INSECURE / DEV ONLY):**

`appass-file` is a simple file-based helper included with APlane. It reads/writes the passphrase from a plaintext file. Useful for development and testing, but not for production.

```yaml
# INSECURE / DEV ONLY: Passphrase stored in plaintext file
# Relative path (./appass-file) resolved relative to data directory
passphrase_command_argv: ["./appass-file", "passphrase"]
```

Use `appass`, not manual line editing, if you want to switch between prompt mode and passfile mode on an existing signer data directory.

**Built-in helper — appass-systemd-creds (systemd / Linux):**

`appass-systemd-creds` encrypts the passphrase via `systemd-creds`, binding it to the machine's TPM2 chip and/or host key. Recommended for Systemd deployments. Requires systemd 250+ (Ubuntu 24.04+, Debian 12+, RHEL/Rocky 9+). Stop `apsigner`, then run `sudo appass -d <data-dir>` and select `Systemd` to set it up.

See [ARCH_SECURITY.md — Usage Guide: appass-systemd-creds](ARCH_SECURITY.md#usage-guide-appass-systemd-creds) for full setup instructions.

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

**Controlled environment:** By default, the passphrase command runs with no inherited process environment. Use `passphrase_command_env` to declare specific variables. The only automatic passthrough is `CREDENTIALS_DIRECTORY`, which systemd sets for decrypted credentials:

```yaml
passphrase_command_env:
  AWS_REGION: "us-west-2"
  HOME: "/var/lib/apsigner"
```

#### 2. Lock-on-disconnect

Headless mode keeps the signer unlocked when no admin is connected.

```yaml
lock_on_disconnect: false
```

- Default is `true` (signer locks when apadmin disconnects)
- Product-store `unlock.yaml` forces the effective value to `false`
- Process-global helper configuration must set this to `false`
- Without this, the signer would lock immediately after startup

#### 3. User Auto-Approve

This is the same setting shown in `apadmin` as `User Auto-Approve`. Set it to
`true` to sign non-rejected default-fallback requests without an operator
approval prompt.

```yaml
# User Auto-Approve: ON (use with caution)
user_auto_approve: true
```

This can be a process-global default in `config.yaml` or a product-local
override in `identities/default/config.yaml`.

### Complete Example

**identities/default/unlock.yaml:**
```yaml
passphrase_command_argv: ["/usr/local/bin/aplane-keychain-helper"]
```

**identities/default/config.yaml:**
```yaml
lock_on_disconnect: false
user_auto_approve: true
```

### Changing Modes Safely

If you want to move between interactive and headless operation:

1. Stop `apsigner`
2. Run `appass -d <data-dir>`
3. Select the desired mode in the TUI
4. Start `apsigner` again

Do not edit passphrase auto-handling settings with `appass` while the daemon is running. For live administration of an already-running signer, use `apadmin` instead.

If `appass` shows a warning after switching modes, treat it as a completed switch with cleanup still required.

### Security Considerations

| Risk | Mitigation |
|------|------------|
| Passphrase command compromise | Use absolute paths, verify binary is not writable by group/other |
| Unauthorized signing | Restrictive policy (avoid `user_auto_approve:true` in production) |
| Physical access | Run on secured/isolated hardware |

**Recommendations:**

1. **Audit logging**: All auto-approved signatures are logged for audit trails.
2. **Network isolation**: Run headless Signer on a private network segment.

### Interactive vs Headless Comparison

| Aspect | Interactive | Headless |
|--------|-------------|----------|
| Startup | Waits for passphrase | Reads from configured helper |
| Admin connection | Required (apadmin) | Optional |
| Unlock lifetime | Connected and active admin session by default | Long-lived until stopped |
| Signing approval | Manual (`apadmin` or `apapprover`) | `User Auto-Approve` ON (`user_auto_approve:true`) or manual admin client |
| Disconnect behavior | Signer locks | Signer stays unlocked |
| Use case | High-value, manual ops | Automated, scheduled ops |
