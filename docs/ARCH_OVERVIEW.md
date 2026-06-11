# System Architecture

This document provides a high-level overview of the APlane system architecture.
For a system-wide durable/runtime/wire data model, see
[ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md).

## System Layering

```
┌─────────────────────────────────────────────────────────────┐
│                      UI Layer                               │
│  REPL, TUI (apadmin/appass), CLI modes, MCP surface         │
│  Command parsing, user interaction, display formatting      │
│                                                             │
│  See: ARCH_REPL.md, ARCH_MCP.md, ARCH_TUI.md                │
├─────────────────────────────────────────────────────────────┤
│               Application / Workflow Layer                  │
│  Shell workflows, structured results, signer runtime flows  │
│  Boundaries: internal/apshellapp, internal/signerapp        │
├─────────────────────────────────────────────────────────────┤
│                    Engine Layer                             │
│  Reusable client mechanics, transaction preparation, state  │
│  management, signer connection lifecycle                    │
│                                                             │
│  See: ARCH_ENGINE.md                                        │
├─────────────────────────────────────────────────────────────┤
│                   Provider Layer                            │
│  Signing providers, LSig providers, salting, metadata,      │
│  mnemonic, key generation, key type catalog/activation      │
│                                                             │
│  See: ARCH_CRYPTO.md                                        │
├─────────────────────────────────────────────────────────────┤
│              Algorand SDK / Network                         │
│  Transaction encoding, node communication, crypto primitives│
└─────────────────────────────────────────────────────────────┘
```

## Signing Authority

**Signing authority lives in the key file, not in the template.** Every
LogicSig key file stores its compiled bytecode, off-curve salt counter, and
signing metadata at creation time. Sign-time code uses that stored metadata;
DSA-backed keys use the appropriate base signing provider to produce and
pack signatures. Templates are used for generation, discovery, lifecycle, and
provenance, not to reconstruct missing signing metadata. Template provenance
conflicts or absence may warn in inventory but do not by themselves invalidate
a key.

## Applications

| Application | Purpose | Key Layers Used |
|-------------|---------|-----------------|
| **apshell** | Interactive shell, scripting runtime, plugin host, and MCP surface | UI + Shell App + Engine + Providers |
| **apadmin** | Signer admin TUI over IPC or SSH admin transport | UI (TUI) + admin protocol + Providers |
| **apconsole** | Secure-machine console wrapper for shell/admin/daemon panes; local sentry nodes show admin plus daemon/status only | UI (TUI wrapper) + Shell App + admin protocol + signer lifecycle |
| **apsigner** | Signing server daemon, approval coordinator, REST API, IPC admin surface, and SSH tunnel/admin server | Signer App + HTTP + admin protocol + Providers |
| **apapprover** | Lightweight interactive approval CLI over IPC | UI (CLI) + IPC |
| **apstore** | Keystore management client for local initialize, policy integrity, endpoint export, public sentry references, backup import admission, verification, and rebuild rescue flows; live backup, restore, template, key type, and passphrase operations use the admin protocol | Providers (KeyGen) + Crypto + Store Mutation + admin protocol |
| **appolicy** | Offline policy checker/editor for the node-role policy document (`policy.yaml` for signer nodes, sentry-domain `policy.yaml` for sentry nodes), plus signing-to-sentry conversion | UI (TUI) + Policy + Store Mutation |
| **appass** | Passphrase auto-unlock configuration TUI | UI (TUI) + Crypto |
| **aplocalnet** | LocalNet setup TUI/CLI for apclient default-network config, signer genesis config, plugin activation, and KMD plugin-env persistence | UI (TUI/CLI) + config + plugin catalog |
| **approbe** | Installer-facing liveness probe for signer IPC reachability before replacing local binaries | Installer helper + admin protocol probe |

## Identity Model

APlane is a **single-operator, single-exposed-identity product**: one operator
domain owns the signer, keys, token, approvals, and client devices that connect
to it. The supported product identity is `default`. Client SSH identities
distinguish **which enrolled client/device/agent is acting on behalf of that
same operator domain and identity**; they do not represent separate tenants
with independent authorization domains. The detailed principal/group/grant
model is documented in [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).

The codebase uses an internally identity-scoped runtime model: each identity
has its own `identity.Runtime` owning keystore, session, lock state, approval
coordinator, token authority, SSH enrollment, config, and watcher. At startup,
`apsigner` discovers all identity directories under `identities/`, filters out
decommissioned identities, and builds a runtime for each. The operator surface
is one effective identity (`"default"`) and one active admin session at a time,
regardless of whether that session arrives over local IPC or the SSH
`aplane-admin` subsystem.

The signer architecture is multitenant-shaped infrastructure inside that
single-operator product:

- runtime state is identity-scoped,
- authorization separates principals from signing identities,
- admin sessions carry principal and target-identity attribution,
- HTTP and admin operations pass through stable action/resource authorization checks,
- audit records carry target identity and principal attribution.

This plumbing should be read as infrastructure, not as a claim that the
deployment model is multi-user.

Signer transaction policy is identity-scoped and uses the current verdict model
documented in [ARCH_POLICY.md](ARCH_POLICY.md): Always Deny, Always Review,
Always Approve, then Operator Default.

## Security Boundary

The system enforces a strict security boundary between APlane Shell (client) and Signer (server):

```
┌──────────────────────┐          ┌──────────────────────┐
│      Client          │          │      Signer          │
│  (shell, sdk, etc)   │          │                      │
│                      │          │                      │
│  • Builds txns       │  ──────► │  • Manages keys per  │
│  • No keys           │  SignReq │    identity runtime  │
│  • Submits txns      │  ◄────── │  • Signs messages    │
│    to Algorand       │          │                      │
│                      │          │                      │
└──────────────────────┘          └──────────────────────┘
     Internet-connected              Network-isolated
```

Remote shell clients connect through an SSH tunnel to the signer HTTP API.
Local clients may use loopback REST directly or through local console
composition. In all cases, signer operations use the signer's HTTP/JSON API or
authenticated admin protocol.

**Key principle**: Signer-managed private keys never leave the signing device.

## Layer Responsibilities

### Shell: UI Layer
- Parse user commands
- Resolve aliases and addresses
- Format output with colors
- Handle interactive prompts
- Delegate shell workflows to `internal/apshellapp`

### Shell: Application Layer
- Own shell command workflows and shell-facing use cases
- Convert typed requests into reusable engine operations
- Produce typed shell results shared by text rendering and MCP projection
- Keep `cmd/apshell` adapter-only where possible

### Shell: Engine Layer
- Prepare transactions (fee calculation, balance checks)
- Manage caches (aliases, signers, auth addresses, sets, ASAs)
- Coordinate signing via signer
- Submit signed transactions to network
- Provide UI-agnostic API

### Signer: Provider Layer
- Abstract signature algorithms (Ed25519, Falcon, dual Falcon/Ed25519, ECDSA secp256k1)
- Handle key loading, signing, zeroing
- Construct LogicSig transactions
- Generate and recover keys from mnemonics
- Register explicitly from binary entrypoints
- Track default-enabled and library-visible key types through the key type catalog
- Apply identity-scoped key type activation before generation surfaces expose library-visible providers

## Directory Structure

This is an orientation map, not a complete file listing. For source-of-truth
files and ownership boundaries, prefer [ARCH_SPEC.md](ARCH_SPEC.md).

```
aplane/
├── cmd/                           # Application entry points
│   ├── apshell/                   # Thin shell binary entrypoint
│   ├── apsigner/                 # Signing server, HTTP/IPC/SSH adapters
│   ├── apadmin/                   # Admin TUI over IPC or SSH admin transport
│   ├── apconsole/                 # Secure-machine console wrapper
│   ├── apapprover/                # Approval-only IPC client
│   ├── apstore/                   # Keystore management, local flows, IPC-admin flows
│   ├── appolicy/                  # Offline policy checker/editor
│   ├── appass/                    # Passphrase auto-unlock configuration TUI
│   ├── aplocalnet/                # LocalNet setup TUI/CLI
│   ├── compile_teal/              # Dev/build helper for TEAL bytecode generation
│   ├── configdoc/                 # Configuration documentation generator
│   ├── appass-file/               # Dev passphrase helper
│   ├── appass-systemd-creds/      # systemd-creds passphrase helper
│   ├── approbe/                   # Installer liveness probe for signer IPC
│   └── applugin-checksum/         # Plugin checksum generator
│
├── internal/                      # Shared packages
│   ├── apshellcli/                # Shell adapter, REPL/runtime wiring, rendering, MCP
│   ├── apshellapp/                # Shell command workflows and shell-facing APIs
│   ├── appresult/                 # Shared shell/MCP structured results
│   ├── shellrepl/                 # Human shell syntax, parsing, and completion
│   ├── cmdspec/, command/         # Shared command specs and registry helpers
│   ├── signertui/                 # Shared signer administration TUI package
│   ├── engine/                    # Reusable client mechanics and transaction operations
│   ├── engine/connect/            # Remote signer connection and signer-facing HTTP
│   ├── clientstate/               # Client-side alias/set/cache mutation ownership
│   ├── cache/                     # Disk-backed client caches
│   ├── addressbook/, refname/      # Address resolution and persisted alias/set name rules
│   ├── signerapp/                 # Signer runtime packages
│   │   ├── startup/               # Startup validation and identity runtime assembly
│   │   ├── identity/              # Identity runtime, registry, config, lifecycle
│   │   ├── runtime/               # Lock state
│   │   ├── approval/              # Approval queues
│   │   ├── signing/               # Plan/approve/execute orchestration
│   │   ├── keyadmin/              # Key generation/import/delete workflows
│   │   ├── storeadmin/            # Store initialization and passphrase rotation
│   │   ├── backupadmin/           # Signer-managed backup/restore admin workflows
│   │   ├── rest/                  # Signer REST service layer
│   │   ├── sshprovision/          # SSH token provisioning
│   │   └── templates/             # Template reload and state reporting
│   ├── adminproto/                # Transport-neutral admin protocol
│   ├── protocol/                  # IPC/admin wire message definitions
│   ├── transport/                 # IPC/SSH admin client transports
│   ├── sshtunnel/                 # SSH server and client tunnel support
│   ├── signerclient/              # Signer REST client
│   ├── signerapi/                 # Internal aliases for pkg/signerapi DTOs
│   ├── keytypecatalog/            # Compiled key type visibility catalog
│   ├── keytypestate/              # Identity-scoped key type state records
│   ├── templatelibrary/           # Plaintext KeyType Library parsing/install
│   ├── templatestore/             # Encrypted identity template storage
│   ├── storepaths/                # Signer data path construction
│   ├── storemut/                  # Signer-owned persistent mutation service
│   ├── keystore/, keys/, crypto/  # Keystore storage, key scanning, encryption
│   ├── signing/, signingargs/, keygen/  # Native signing, signing-arg metadata, and keygen registries
│   ├── lsigprovider/              # Unified LogicSig provider registry
│   ├── logicsigdsa/               # LogicSig DSA interface and registry
│   ├── lsigsalt/                  # Shared off-curve LogicSig salting
│   ├── mnemonic/                  # Mnemonic handlers
│   ├── jsapi/, scripting/         # JavaScript bindings and Goja runtime
│   ├── plugin/                    # Plugin discovery, manifest, RPC, integrity, sandbox
│   ├── config/                    # Client and server config loading
│   ├── policy/, approvalpolicy/   # Signer policy config and approval warnings
│   ├── appinput/, appspec/        # App command parsing and ABI spec handling
│   └── fsutil/, theme/, tokenfile/, cmdlog/, ...   # Focused support packages
│
├── lsig/                          # LogicSig provider implementations
│   ├── all.go                     # Built-in LogicSig registration aggregator
│   ├── falcon1024/                # Falcon-1024 DSA provider
│   │   ├── derivation/, family/, keygen/, keys/, signing/
│   │   └── v1/                    # v1 standard provider, ops, composer, templates
│   ├── falcon1024_ed25519/        # Dual Falcon-1024 / Ed25519 DSA provider
│   ├── ecdsak1/                   # ECDSA secp256k1 LogicSig DSA provider
│   ├── composeddsa/               # Generic ComposedDSA composer
│   └── generictemplate/           # YAML-backed generic template provider
│
├── library/templates/             # Optional plaintext KeyType Library YAML sources
├── pkg/signerapi/                 # Public signer HTTP DTO source of truth used by external SDKs
└── examples/
    ├── js/                        # JavaScript examples
    └── external_plugins/          # External plugin examples
```

### Package Location Principles

| Package Type | Location | Rationale |
|--------------|----------|-----------|
| **Binary-local UI** | `cmd/<app>/internal/` when present | Only used by that application |
| **Shared UI/adapters** | `internal/apshellcli`, `internal/shellrepl`, `internal/signertui` | Shared or separately testable shell/TUI surfaces |
| **Shell workflows** | `internal/apshellapp` | Shell-facing behavior shared by text, script, and MCP adapters |
| **Shared library** | `internal/` | Used by multiple apps or plugins |
| **Algorithm impl** | `lsig/` | DSA provider implementations |
| **Wire DTOs** | `pkg/signerapi` | Public signer HTTP payload types shared with SDKs |

The `internal/` packages include shared infrastructure and shared UI/adapter
packages used by product binaries. Binary-local UI code may live under
`cmd/<app>/internal/` when it is private to that binary. Shell command workflow
behavior should live in `internal/apshellapp`, not in `cmd/apshell`.

## Configuration

Applications read from `config.yaml` in their data directory:
- apshell: `$APCLIENT_DATA/config.yaml` or `-d <path>`
- apsigner: `$APSIGNER_DATA/config.yaml` or `-d <path>`

apshell uses `config.yaml` for network, theme, and polling defaults. Signer and
sentry endpoint routing lives in `$APCLIENT_DATA/endpoints.yaml`; top-level
client `ssh:` signer routing is not supported by managed startup in this
new-install-only release.

apsigner also reads per-identity configuration overlays:
- `identities/<identity>/config.yaml` — identity-scoped settings (`user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `mode`, `decommissioned`) that override process-global defaults
- `identities/<identity>/unlock.yaml` — identity-scoped passphrase helper configuration
- `identities/<identity>/policy.yaml` — identity-scoped node-role policy
- `identities/<identity>/keytypes/<key_type>.json` — identity-scoped state records for optional key types
- `identities/<identity>/keytypes/<key_type>.template` — encrypted installed YAML templates

The signer data root may also contain `library/templates/*.yaml`, a plaintext
KeyType Library source copied from release or installer artifacts. Files there
are reference material until an authenticated admin installs a YAML template or
enables a library-visible compiled provider for an identity.

See [USER_CONFIG.md](USER_CONFIG.md) for full reference.

## Transaction Signing Flow (Summary)

Clients send `TxnBytesHex` to the signer and the server derives what to sign based on key type:
- **Ed25519**: sign full transaction bytes (`TX` + msgpack)
- **LogicSig DSA**: sign 32-byte transaction ID hash
- **Generic LogicSig**: no signature

The signer returns finalized group-shaped payloads rather than per-key-type component fields:

- `POST /sign` returns `signed`, a list of hex-encoded signed transaction msgpack blobs
- `POST /plan` returns `transactions`, a list of `TX`-prefixed hex-encoded unsigned canonical transactions
- `POST /simulate` signs internally, calls algod simulate, and returns txids, diagnostics, and final unsigned transaction bytes without exposing reusable signed bytes

Clients may submit the returned signed bytes directly, or use `/plan` plus local signing / passthrough flows when they need explicit control over a multi-party workflow.

**Endpoints:**
- `POST /sign` — Sign transactions (supports sign, passthrough, and foreign-context modes)
- `POST /sign/cancel` — Cancel a pending manual approval prompt by `/sign` request ID
- `POST /plan` — Preview group building (dummies, fees, group ID) without signing
- `POST /simulate` — Perform signer-managed signed preflight simulation without returning signed transaction bytes

**Multi-party signing:** Transactions can be marked as **foreign** (`txn_bytes_hex` without `auth_address`) to include them in group building without signing. This works on both `/plan` and `/sign`: `/plan` returns canonical unsigned transactions, while `/sign` returns `""` in foreign positions and signed bytes only for signer-owned or passthrough positions. An optional `lsig_size` hint enables correct dummy calculation for the other party's key type. See [`ARCH_TXNFLOW.md`](ARCH_TXNFLOW.md) for details.

## apsigner Startup Modes

apsigner supports four startup modes that share a unified initialization path:

| Mode | Passphrase Source | Starts | Use Case |
|------|-------------------|--------|----------|
| **Headless** | `passphrase_command_argv` config | Unlocked | Automation, CI/CD, systemd services |
| **Locked** | apadmin IPC connection | Locked | Interactive operation, manual approval |
| **Test** | `TEST_PASSPHRASE` env | Unlocked | Test harness / integration environments |
| **Forced locked** | No `.keystore` present | Locked | Uninitialized signer state |

Before these modes are selected, a signer data directory containing `.prod` is
treated as systemd-managed. Manual `apsigner` startup is refused unless the
process is systemd-managed through `APLANE_SYSTEMD_MANAGED=1` or parent PID 1.

**Startup flow:**

1. Discover all identity directories under `identities/` via `identity.DiscoverIdentities`
2. Filter out identities whose stored config marks them `decommissioned:true`
3. Ensure the current product identity is always present
4. For each discovered identity, `startup.BuildIdentityRuntime` loads the per-identity config overlay, API token, keystore, and wires the approval coordinator and reload function
5. In headless mode, the product identity is unlocked immediately; in locked mode, unlock happens later via apadmin IPC

Both modes use the same `reloadKeysLocked` path after unlock. That path
registers enabled installed runtime templates before key scanning and populates
per-identity key indexes. Identity key type activation and disabled records are
consulted by inventory and admin key operations when deciding whether an
optional key type can be discovered, generated, or imported.

**Identity-scoped runtime state:**

Each identity owns an `identity.Runtime` containing:
- key maps (`keys`, `keyTypes`, `keyLsigSizes`) protected by `keysLock`
- key session and master key access protected by `passphraseLock`
- approval coordinator (atomic pointer)
- effective policy config
- lock state
- file watcher lifecycle
- identity-scoped config (`user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `mode`)

The on-disk layout is identity-scoped: keys under
`identities/<identityID>/keys/`, encrypted templates and state records under
`identities/<identityID>/keytypes/`, deleted key/template
archives under `identities/<identityID>/deleted/`, node-role policy at
`identities/<identityID>/policy.yaml`, and config at
`identities/<identityID>/config.yaml`. HTTP handlers extract the authenticated
identity from request context; admin sessions over IPC or the SSH
`aplane-admin` subsystem bind to one identity at auth time.

**Admin protocol architecture:**

The admin protocol is split into transport and protocol layers:
- `internal/adminproto` owns the transport-neutral protocol: session state machine, auth handshake, message dispatch, and business operation handlers
- `internal/adminproto` owns active-session tracking, displacement negotiation, and line-stream adapters; `internal/signerapp/daemon/ipc.go` owns the Unix socket transport
- `internal/sshtunnel` carries the same admin protocol over the SSH `aplane-admin` subsystem

Non-transport code reaches the admin channel through the `AdminHub` interface on `Signer`, not by depending on the Unix IPC implementation directly. Protocol handlers access business logic through the `Services` interface, implemented by the Signer-backed `signerAdminServices`.

See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for headless configuration details.

## Adding New Features

| To Add | Layer | Documentation |
|--------|-------|---------------|
| New command | UI | ARCH_REPL.md (REPL/CLI) and ARCH_MCP.md (MCP) |
| New shell workflow | Shell App | ARCH_SPEC.md and ARCH_ENGINE.md |
| Reusable transaction/client mechanic | Engine | ARCH_ENGINE.md |
| New key type or algorithm | Provider | DEV_KEYTYPES.md and ARCH_CRYPTO.md |
| New KeyType Library template | Provider / Template Library | DEV_KEYTYPES.md |
| New config option | Config | USER_CONFIG.md |

## Related Documentation

- [ARCH_SPEC.md](ARCH_SPEC.md) - current ownership map and source-of-truth files
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) - compatibility-bearing contracts
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md) - network context tokens and genesis-hash mapping
- [ARCH_REPL.md](ARCH_REPL.md) - apshell REPL architecture
- [ARCH_MCP.md](ARCH_MCP.md) - apshell MCP server and tool surface
- [ARCH_TUI.md](ARCH_TUI.md) - signer admin TUI (apadmin)
- [ARCH_ENGINE.md](ARCH_ENGINE.md) - Engine layer details
- [ARCH_SENTRY.md](ARCH_SENTRY.md) - Guarded signing and sentry node architecture
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow details
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Provider layer details (DSA algorithms)
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) - key type and LogicSig template development guide
- [USER_KEYTYPES.md](USER_KEYTYPES.md) - key type and template management guide
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
- [README.md](../README.md) - User-facing documentation
