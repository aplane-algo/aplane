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
LogicSig key file stores its compiled bytecode, derivation record, and signing
metadata at creation time. Current TEAL v13-generated keys record
`lsig_derivation: algod_v13_auto_salt` and do not carry a mutable salt counter;
legacy manual-salting formats retain their compatibility counter. Sign-time code uses that stored metadata;
DSA-backed keys use the appropriate base signing provider to produce and
pack signatures. Templates are used for generation, discovery, lifecycle, and
provenance, not to reconstruct missing signing metadata. Template provenance
conflicts or absence may warn in inventory but do not by themselves invalidate
a key.

## Applications

| Application | Purpose | Key Layers Used |
|-------------|---------|-----------------|
| **apshell** | Interactive shell, scripting runtime, plugin host, and MCP surface | UI + Shell App + Engine + Providers |
| **aprekey** | External witness custody and bounded contract-admin rekey/unrekey orchestration, including separated ceremonies | Client orchestration + Bounded Admin + Witness Artifact |
| **apadmin** | Signer admin TUI and batch client over IPC or SSH, owning all general live administration | UI (TUI/CLI) + admin protocol + Providers |
| **apconsole** | Secure-machine console wrapper for shell/admin/daemon panes; local sentry nodes show admin plus daemon/status only | UI (TUI wrapper) + Shell App + admin protocol + signer lifecycle |
| **apsigner** | Signing server daemon, approval coordinator, REST API, IPC admin surface, and SSH tunnel/admin server | Signer App + HTTP + admin protocol + Providers |
| **apapprover** | Lightweight interactive approval CLI over IPC | UI (CLI) + IPC |
| **apstore** | Stopped-daemon keystore bootstrap, policy integrity, external backup verification, rebuild rescue, permission migration, and generation pruning | Providers (KeyGen) + Crypto + Store Mutation |
| **appass** | Passphrase auto-unlock configuration TUI | UI (TUI) + Crypto |
| **aplocalnet** | LocalNet setup TUI/CLI for client (`apshell`) default-network config, signer genesis config, plugin activation, and KMD plugin-env persistence | UI (TUI/CLI) + config + plugin catalog |
| **approbe** | Installer-facing liveness probe for signer IPC reachability before replacing local binaries | Installer helper + admin protocol probe |

## Fixed Product Store and Runtime

APlane is a **single-operator, single-signing-identity product**. Every
`apsigner` process owns exactly one signing-state aggregate. The aggregate owns
the keystore, lock state, approval coordinator, token authority, SSH enrollment,
configuration, and watcher; it has no runtime ID, registry, or selector. IPC
and SSH admin clients compete for one process-wide admin session.

The durable namespace is `identities/default/`, with managed archives under
`backups/default/`. `default` is the fixed on-disk directory name, not a runtime
ID or authorization principal. `internal/storepaths.Paths` constructs these
paths without accepting a selector. The same fixed layout applies to signer-role
and sentry-role data roots.

At startup, a no-follow layout-integrity check rejects any direct entry under
`identities/` other than a real directory named `default`; it fails closed
before tokens, keys, policy, or watchers are loaded. HTTP token authentication binds the reserved
principal `system:product-admin` to the one product runtime. Normal SSH accepts
only `aplane`; enrollment accepts only `request-token`; product request
and admin inputs expose no runtime selector.

Signer transaction policy is product-scoped under `identities/default/` and uses the current verdict model
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
│  • No keys           │  SignReq │    product runtime   │
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
- Provide native Ed25519, Falcon-1024, and Ed25519 LogicSig signing implementations
- Handle key loading, signing, zeroing
- Construct LogicSig transactions
- Generate and recover keys from mnemonics
- Register explicitly from binary entrypoints
- Track default-enabled and library-visible key types through the key type catalog
- Apply the product key type activation set before generation surfaces expose library-visible providers

## Directory Structure

This is an orientation map, not a complete file listing. For source-of-truth
files and ownership boundaries, prefer [ARCH_SPEC.md](ARCH_SPEC.md).

```
aplane/
├── cmd/                           # Application entry points
│   ├── apshell/                   # Thin shell binary entrypoint
│   ├── aprekey/                   # External witness and bounded admin ceremonies
│   ├── apsigner/                 # Thin signer entrypoint: flags, providers, handoff
│   ├── apadmin/                   # Admin TUI over IPC or SSH admin transport
│   ├── apconsole/                 # Secure-machine console wrapper
│   ├── apapprover/                # Approval-only IPC client
│   ├── apstore/                   # Stopped-daemon bootstrap and rescue flows
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
│   ├── signerapp/signertui/       # Shared signer administration TUI package
│   ├── engine/                    # Reusable client mechanics and transaction operations
│   ├── engine/connect/            # Remote signer connection and signer-facing HTTP
│   ├── engine/guarded/            # Guarded and bounded client orchestration
│   ├── clientstate/               # Client-side alias/set/cache mutation ownership
│   ├── cache/                     # Disk-backed client caches
│   ├── addressbook/, refname/      # Address resolution and persisted alias/set name rules
│   ├── signerapp/                 # Signer runtime packages
│   │   ├── daemon/                # Process composition and HTTP/IPC/SSH runtime
│   │   ├── adminserver/           # Admin sessions, dispatch, handlers, displacement
│   │   ├── startup/               # Startup validation and product runtime assembly
│   │   ├── productruntime/        # Product runtime/config/lifecycle
│   │   ├── runtime/               # Lock state
│   │   ├── approval/              # Approval queues
│   │   ├── approvalpolicy/        # Signer approval policy integration
│   │   ├── signing/               # Plan/approve/execute orchestration
│   │   ├── keyadmin/              # Key generation/import/delete workflows
│   │   ├── storeadmin/            # Store initialization and passphrase rotation
│   │   ├── storemut/              # Signer-owned persistent mutation service
│   │   ├── backupadmin/           # Signer-managed backup/restore admin workflows
│   │   ├── rest/                  # Signer REST service layer
│   │   ├── sshprovision/          # SSH token provisioning
│   │   └── templates/             # Template reload and state reporting
│   ├── adminproto/                # Admin service vocabulary and framed server connection
│   ├── protocol/                  # IPC/admin wire message definitions
│   ├── transport/                 # IPC/SSH admin client transports
│   ├── sshtunnel/                 # SSH server and client tunnel support
│   ├── signerclient/              # Signer REST client
│   ├── signerapi/                 # Internal aliases for pkg/signerapi DTOs
│   ├── keytypecatalog/            # Compiled key type visibility catalog
│   ├── keytypestate/              # Product-store key type state records
│   ├── templatelibrary/           # Plaintext KeyType Library parsing/install
│   ├── templatestore/             # Encrypted product-store template storage
│   ├── storepaths/                # Signer data path construction
│   ├── keystore/, keys/, crypto/  # Keystore storage, key scanning, encryption
│   ├── signing/, signingargs/, keygen/  # Native signing, signing-arg metadata, and keygen registries
│   ├── lsigprovider/              # Unified LogicSig provider registry
│   ├── logicsigdsa/               # LogicSig DSA interface and registry
│   ├── lsigsalt/                  # Shared off-curve LogicSig salting
│   ├── sentry/                    # Sentry/guarded component protocol (keytypes, messages, canonical hashing, verification)
│   ├── mnemonic/                  # Mnemonic handlers
│   ├── jsapi/, scripting/         # JavaScript bindings and Goja runtime
│   ├── plugin/                    # Plugin discovery, manifest, RPC, integrity, sandbox
│   ├── config/                    # Client and server config loading
│   ├── serverconfig/              # apsigner server configuration loading and validation
│   ├── noderole/, keyclass/       # Durable signer node role and key-type classification gates
│   ├── policy/                    # Signer and sentry policy configuration
│   ├── appinput/, appspec/        # App command parsing and ABI spec handling
│   └── fsutil/, theme/, tokenfile/, cmdlog/, ...   # Focused support packages
│
├── lsig/                          # LogicSig provider implementations
│   ├── all.go                     # Built-in LogicSig registration aggregator
│   ├── falcon1024/                # Falcon-1024 DSA provider
│   │   ├── derivation/, family/, keygen/, keys/, signing/
│   │   └── v1/                    # v1 standard provider, ops, composer, templates
│   ├── falcon1024_guarded/        # Guarded Falcon-1024 (user + sentry) LogicSig provider
│   ├── ed25519lsig/               # Ed25519 LogicSig DSA base for composed templates
│   ├── composeddsa/               # Generic ComposedDSA composer
│   ├── dsafamily/                 # Client-safe DSA family registration descriptors
│   ├── signerreg/                 # Built-in signer-side LogicSig provider registration
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
| **Shared UI/adapters** | `internal/apshellcli`, `internal/shellrepl`, `internal/signerapp/signertui` | Shared or separately testable shell/TUI surfaces |
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
endpoint-routed client model.

apsigner also reads product-store configuration:
- `identities/default/config.yaml` — product runtime settings (`user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `approval_wait`) that override process-global defaults; unknown fields are rejected and node role is configured only in root `node.yaml`
- `identities/default/unlock.yaml` — product passphrase helper configuration
- `identities/default/policy.yaml` — product node-role policy
- `identities/default/keytypes/<key_type>.json` — product state records for optional key types
- `identities/default/keytypes/<key_type>.template` — encrypted installed YAML templates

The signer data root may also contain `library/templates/*.yaml`, a plaintext
KeyType Library source copied from release or installer artifacts. Files there
are reference material until an authenticated admin installs a YAML template or
enables a library-visible compiled provider for the product runtime.

See [USER_CONFIG.md](USER_CONFIG.md) for full reference.

## Transaction Signing Flow (Summary)

Clients send `TxnBytesHex` to the signer and the server derives what to sign based on key type:
- **Ed25519**: sign full transaction bytes (`TX` + msgpack)
- **LogicSig DSA**: sign 32-byte transaction ID hash
- **Generic LogicSig**: no signature

The signer returns finalized group-shaped payloads rather than per-key-type component fields:

- `POST /sign` returns `signed`, a list of hex-encoded signed transaction msgpack blobs
- `POST /plan` returns `transactions`, a list of `TX`-prefixed hex-encoded unsigned canonical transactions

Clients may submit the returned signed bytes directly, send the exact executable
group to their configured algod simulation endpoint, or use `/plan` plus local
signing / passthrough flows when they need explicit control over a multi-party
workflow. Apsigner does not distinguish simulation from submission; both use
ordinary signing policy, approval, and audit behavior.

**Signing endpoints (summary):**
- Ordinary: `POST /sign` signs transactions in sign, passthrough, and
  foreign-context modes; `POST /sign/cancel` cancels a pending manual approval
  prompt by `/sign` request ID; `POST /plan` previews group building without
  signing.
- Component flow: `POST /plan` freezes groups, `POST /sign/component` produces
  guarded or bounded components, and `POST /sign/assemble` assembles guarded or
  bounded-sentry signed groups.
- Bounded administration: `POST /sign/bounded-admin` prepares external
  contract-admin partials outside the ordinary send path.

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the full REST inventory and wire
contracts, [ARCH_SENTRY.md](ARCH_SENTRY.md) for guarded choreography, and
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) for bounded choreography.

**Multi-party signing:** Transactions can be marked as **foreign**
(`txn_bytes_hex` without `auth_address`) to include them in group building
without signing. This works on both `/plan` and `/sign`: `/plan` returns
canonical unsigned transactions, while `/sign` returns `""` in foreign
positions and signed bytes only for signer-owned or passthrough positions. An
optional structured `lsig_resources` hint enables consensus-aware dummy and
fee calculation for the other party's selected LogicSig path. See
[`ARCH_TXNFLOW.md`](ARCH_TXNFLOW.md) for details.

## apsigner Startup Modes

apsigner supports four startup modes that share a unified initialization path:

| Mode | Passphrase Source | Starts | Use Case |
|------|-------------------|--------|----------|
| **Headless** | `passphrase_command_argv` config | Unlocked | Automation, CI/CD, systemd services |
| **Locked** | apadmin IPC connection | Locked | Interactive operation, manual approval |
| **Test** | `TEST_PASSPHRASE` env | Unlocked | Test harness / integration environments |
| **Forced locked** | No `keyring.enc` present | Locked | Uninitialized signer state |

Before these modes are selected, a signer data directory containing `.prod` is
treated as systemd-managed. Manual `apsigner` startup is refused unless the
process is systemd-managed through `APLANE_SYSTEMD_MANAGED=1` or parent PID 1.

**Startup flow:**

1. Validate that `identities/` is blank or contains only a real `default/`
   directory, with no extra files, directories, or symlinks.
2. `startup.BuildProductRuntime` constructs the one product runtime from the
   default config overlay, API token, and keystore.
3. In headless mode, the product store is unlocked immediately; in locked
   mode, unlock happens later via admin IPC.

Both modes use the runtime reload path after unlock:
`productruntime.Runtime.Reload` or `ReloadWithPassphrase` delegates through
`reloadLocked` to `templates.ReloadService.Reload`, wired by
`startup.WireReloadFunc`. The reload verifies the node role and authenticated
policy before registering enabled installed templates, scanning keys,
validating key classes against the node role, and publishing the product
identity's key indexes. Key type activation and disabled records are consulted by
inventory and admin key operations when deciding whether an optional key type
can be discovered, generated, or imported.

**Product runtime state:**

The process owns one `productruntime.Runtime` signing-state aggregate containing:
- key maps (`keys`, `keyTypes`, `keyMetadata`) protected by `keysLock`
- key session and keyring access protected by `passphraseLock`
- approval coordinator (atomic pointer)
- effective policy config
- lock state
- file watcher lifecycle
- product runtime config (`user_auto_approve`, `lock_on_disconnect`, `passphrase_timeout`, `approval_wait`)

The on-disk namespace is rooted at `identities/default/`: keys live
under `keys/`, encrypted templates and state records under `keytypes/`, deleted
key/template archives under `deleted/`, node-role policy at `policy.yaml`, and
runtime configuration at `config.yaml`. HTTP authentication authorizes access
to that one aggregate; admin sessions over IPC or the SSH `aplane-admin`
subsystem bind to the same aggregate at authentication time. The aggregate has
no runtime selector or registry.

**Admin protocol architecture:**

The admin protocol is split into wire, server, and transport layers:

- `internal/protocol` owns the IPC/SSH admin message catalog and envelope
  definitions;
- `internal/adminproto` owns transport-neutral admin request/result types and
  the framed `AdminConn` abstraction;
- `internal/signerapp/adminserver` owns authentication, session lifecycle,
  active-session tracking, displacement, dispatch, handlers, and service
  interfaces;
- `internal/signerapp/daemon` adapts and wires the process transports; and
- `internal/sshtunnel` carries the same admin protocol over the SSH
  `aplane-admin` subsystem.

Non-transport code reaches the admin channel through
`internal/signerapp/adminserver.AdminHub`, implemented by the daemon
composition, rather than depending on the Unix IPC implementation directly.
Adminserver handlers access business logic through service interfaces wired to
the signer-backed services in `internal/signerapp/daemon/admin_services.go`.

See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for headless configuration details.

## Adding New Features

| To Add | Layer | Documentation |
|--------|-------|---------------|
| New command | UI | ARCH_REPL.md (REPL/CLI) and ARCH_MCP.md (MCP) |
| New shell workflow | Shell App | ARCH_SPEC.md and ARCH_ENGINE.md |
| Reusable transaction/client mechanic | Engine | ARCH_ENGINE.md |
| New key type or algorithm | Provider | DEV_KEYTYPES.md, ARCH_KEYTYPE_AXES.md, and ARCH_CRYPTO.md |
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
- [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) - Bounded DSA contracts, effect model, and external contract-admin ceremonies
- [ARCH_CORRIDOR.md](ARCH_CORRIDOR.md) - Corridor v1 bounded-sentry composition and lifecycle
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) - Transaction signing flow details
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Provider layer details (DSA algorithms)
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) - key type and LogicSig template development guide
- [USER_KEYTYPES.md](USER_KEYTYPES.md) - key type and template management guide
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
- [README.md](../README.md) - User-facing documentation
