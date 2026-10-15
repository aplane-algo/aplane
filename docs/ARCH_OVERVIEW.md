# System Architecture

> Orientation map for engineers working on the APlane repository: what the
> system is, its components, which package owns what, the runtime model, the
> architectural seams, and the source-of-truth files. Each subject has its own
> `ARCH_*` document; [How To Use These Docs](#how-to-use-these-docs) says when
> to read each. For a system-wide durable/runtime/wire data model, see
> [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md).

## Contents

- [Purpose](#purpose)
- [How To Use These Docs](#how-to-use-these-docs)
- [System](#system)
- [Binaries](#binaries)
- [Directory Structure](#directory-structure)
- [Architecture Layers](#architecture-layers)
- [Deployment Model](#deployment-model)
- [Runtime Configuration Model](#runtime-configuration-model)
- [On-Disk Data Model](#on-disk-data-model)
- [Security Model](#security-model)
- [Server Ownership Model](#server-ownership-model)
- [Client Ownership Model](#client-ownership-model)
- [Transaction Processing](#transaction-processing)
- [Bounded Authorization Contracts](#bounded-authorization-contracts)
- [Guarded Signing And Cosigner Nodes](#guarded-signing-and-cosigner-nodes)
- [Provider and Algorithm Model](#provider-and-algorithm-model)
- [Keystore and Key Lifecycle](#keystore-and-key-lifecycle)
- [Plugin System](#plugin-system)
- [JavaScript and MCP](#javascript-and-mcp)
- [Caching and Local State](#caching-and-local-state)
- [Approval Model](#approval-model)
- [SSH, Watching, Templates, and Audit](#ssh-watching-templates-and-audit)
- [Backup and Restore Ownership](#backup-and-restore-ownership)
- [Architectural Invariants](#architectural-invariants)
- [Architectural Seams](#architectural-seams)
- [Key Entry Points](#key-entry-points)
- [Testing and Verification Model](#testing-and-verification-model)
- [Adding New Features](#adding-new-features)
- [Related Documentation](#related-documentation)

## Purpose

This document is the implementation-derived orientation and architecture specification for the APlane codebase. It describes:

- what the system is,
- which binaries and packages exist,
- how runtime state, data, and control flow through the system,
- which boundaries are clean,
- which parts of the codebase are tightly coupled or compatibility-sensitive,
- where to look first when changing a subsystem.

This document is derived from the codebase and documentation. Where documentation and code differ, the code is authoritative.

## How To Use These Docs

Read this file as the system map:

- product shape,
- package ownership,
- runtime state,
- subsystem boundaries,
- operator surfaces,
- key source files.

Read [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) as the binding compatibility companion:

- HTTP and IPC schemas,
- on-disk formats,
- config contracts,
- SDK, plugin, MCP, SSH, swap, and reload behaviors that should not drift silently.

Read [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md) as the system-wide data map:

- durable authorities,
- runtime projections,
- wire projections,
- caches and display/provenance data,
- entity ownership and compatibility invariants.

Read [ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types) before changing key file
schemas, key type state, template install/enable/disable/remove behavior,
LogicSig signing metadata, or backup/restore rules for keys and key types.

Read [ARCH_STORE.md](ARCH_STORE.md#ownership-and-access) before changing signer
data permissions, IPC placement, direct local-client store access, durable
writes, or offline maintenance execution modes.

Read [ARCH_SECURITY.md](ARCH_SECURITY.md) before changing
authorization-sensitive behavior:

- the reserved product-admin principal, the explicit allowed-action list, and stable actions,
- product bootstrap authorization,
- target identity/resource conventions,
- admin and HTTP enforcement points.

Read [ARCH_POLICY.md](ARCH_POLICY.md) before changing signer policy,
approval phase ordering, hard-reject rules, forced-review rules, or
auto-approval rules.

Read [ARCH_NETWORKS.md](ARCH_NETWORKS.md) before changing network handling:

- network context token syntax,
- built-in and custom genesis-hash mappings,
- client cache and algod context,
- signer policy network resolution,
- ASA transfer guard editing by network.

Read [ARCH_SHELL.md](ARCH_SHELL.md) before changing app
read/call/deploy behavior, ABI handling, `PreparedGroup`, or signer approval
metadata for app calls.

Read [ARCH_GUARDED.md](ARCH_GUARDED.md) before changing cosigner node behavior,
guarded account generation, cosigner keys, guarded transaction
orchestration, endpoint-discovered cosigners, `/sign/component` /
`/sign/assemble` behavior, or the canonical Corridor v1 bounded-cosigner
profile.

Read [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) before changing composer-owned transaction
authorization, Falcon contract-admin custody, bounded schema v2, effect
classification, or the `bounded1` signing flow.

Read [FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md) and the applicable
`FORMAL_*_MODEL.md` document before changing behavior that has formalized
state, transition, or invariant semantics.

Together, these documents are the cross-cutting engineering map for
implementation, authorization, network handling, app interaction, and
compatibility work.

## System

APlane is a safety-first Algorand operations toolkit split across a client shell and a signing service.

### System Layering

```
┌─────────────────────────────────────────────────────────────┐
│                      UI Layer                               │
│  REPL, TUI (apadmin/appass), CLI modes, MCP surface         │
│  Command parsing, user interaction, display formatting      │
│                                                             │
│  See: ARCH_SHELL.md, ARCH_ADMIN.md                          │
├─────────────────────────────────────────────────────────────┤
│               Application / Workflow Layer                  │
│  Shell workflows, structured results, signer runtime flows  │
│  Boundaries: internal/apshellapp, internal/signerapp        │
├─────────────────────────────────────────────────────────────┤
│                    Engine Layer                             │
│  Reusable client mechanics, transaction preparation, state  │
│  management, signer connection lifecycle                    │
│                                                             │
│  See: ARCH_SHELL.md                                         │
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

### Security Boundary

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
Local API clients also use an enrolled SSH connection; direct loopback REST
serves only `/health`. Local console administration uses IPC. In all cases,
signer operations use the signer's HTTP/JSON API or authenticated admin protocol.

**Key principle**: ordinary signing does not return private keys. Explicit
authenticated backup/export workflows can release encrypted credential artifacts.

### Layer Responsibilities

#### Shell: UI Layer
- Parse user commands
- Resolve aliases and addresses
- Format output with colors
- Handle interactive prompts
- Delegate shell workflows to `internal/apshellapp`

#### Shell: Application Layer
- Own shell command workflows and shell-facing use cases
- Convert typed requests into reusable engine operations
- Produce typed shell results shared by text rendering and MCP projection
- Keep `cmd/apshell` adapter-only where possible

#### Shell: Engine Layer
- Prepare transactions (fee calculation, balance checks)
- Manage caches (aliases, signers, auth addresses, sets, ASAs)
- Coordinate signing via signer
- Submit signed transactions to network
- Provide UI-agnostic API

#### Signer: Provider Layer
- Provide native Ed25519, Falcon-1024, and Ed25519 LogicSig signing implementations
- Handle key loading, signing, zeroing
- Construct LogicSig transactions
- Generate and recover keys from mnemonics
- Register explicitly from binary entrypoints
- Track default-enabled and library-visible key types through the key type catalog
- Apply the product key type activation set before generation surfaces expose library-visible providers

## Binaries

All under `cmd/`:

| Binary | Role | Key Layers Used |
|--------|------|-----------------|
| `apshell` | Client shell: REPL, script runner, JS runtime (Goja), MCP server, plugin host | UI + Shell App + Engine + Providers |
| `aprekey` | Dedicated client for generating, inspecting, verifying, and using external Falcon bounded contract-admin credentials; `rekey`/`unrekey` own online orchestration and `prepare-*`/`sign`/`complete` own separated ceremonies | Client orchestration + Bounded Admin + Witness Artifact |
| `apsigner` | Signing daemon: HTTP API, admin protocol over local IPC, key management, approval coordination, SSH tunnel server, audit logging | Signer App + HTTP + admin protocol + Providers |
| `apadmin` | TUI and batch admin client over local IPC; owns all general live administration, including policy, backup/restore, passphrase rotation, templates, key types, cosigner references, endpoint export, and generation inventory, plus explicit offline policy rescue | UI (TUI/CLI) + admin protocol + Providers |
| `apconsole` | Secure-machine console wrapper that hosts operator panes while preserving apshell/apadmin/apsigner interfaces | UI (TUI wrapper) + Shell App + admin protocol + signer lifecycle |
| `apapprover` | Minimal approval-only CLI over IPC | UI (CLI) + IPC |
| `apstore` | Stopped-daemon store tool: local `initialize`, policy integrity check/verify/sign, external-file-only `verify`, `rebuild`, offline generation pruning, private-store permission audit/migration, and offline key inventory; it has no live admin transport | Providers (KeyGen) + Crypto + Store Mutation |
| `appass` | Passphrase auto-unlock setup TUI | UI (TUI) + Crypto |
| `aplocalnet` | LocalNet setup TUI/CLI for algod reachability, client (`apshell`) default-network config, signer genesis config, bundled plugin activation, and KMD plugin-env persistence | UI (TUI/CLI) + config + plugin catalog |
| `compile_teal` | Dev/build helper that compiles TEAL source to generated Go bytecode via algod |  |
| `configdoc` | Config documentation generator |  |
| `appass-file` | Dev passphrase helper |  |
| `appass-systemd-creds` | Production passphrase helper |  |
| `approbe` | Installer/helper liveness probe and canonical signer IPC-path resolver | Installer helper + admin protocol probe |
| `applugin-checksum` | Plugin integrity helper |  |

Documentation notes:

- `appass` owns passphrase setup and `apapprover` is the separate approval-only CLI.
- the repository uses `docs/`; `doc/` does not exist.

## Directory Structure

This is an orientation map, not a complete file listing. For source-of-truth
files, see [Key Entry Points](#key-entry-points); for ownership boundaries, see
[Architecture Layers](#architecture-layers).

```
aplane/
├── cmd/                           # Application entry points
│   ├── apshell/                   # Thin shell binary entrypoint
│   ├── aprekey/                   # External witness and bounded admin ceremonies
│   ├── apsigner/                 # Thin signer entrypoint: flags, providers, handoff
│   ├── apadmin/                   # Admin TUI over IPC
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
│   │   ├── clientregistry/        # Enrolled client key registry (authorized_keys)
│   │   ├── enrollment/            # Client enrollment requests, approval, and audit
│   │   ├── enrollqueue/           # Persisted pending-enrollment queue (pending_enrollments.json)
│   │   └── templates/             # Template reload and state reporting
│   ├── adminproto/                # Admin service vocabulary and framed server connection
│   ├── protocol/                  # IPC/admin wire message definitions
│   ├── transport/                 # IPC admin client transport
│   ├── sshtunnel/                 # SSH server and client tunnel support
│   ├── signerclient/              # Signer REST client
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
│   ├── cosigner/                    # Cosigner/guarded component protocol (keytypes, messages, canonical hashing, verification)
│   ├── mnemonic/                  # Mnemonic handlers
│   ├── jsapi/, scripting/         # JavaScript bindings and Goja runtime
│   ├── plugin/                    # Plugin discovery, manifest, RPC, integrity, sandbox
│   ├── config/                    # Client and server config loading
│   ├── serverconfig/              # apsigner server configuration loading and validation
│   ├── noderole/, keyclass/       # Durable signer node role and key-type classification gates
│   ├── policy/                    # Signer and cosigner policy documents, compilation, and evaluation
│   ├── appinput/, appspec/        # App command parsing and ABI spec handling
│   └── fsutil/, theme/, cmdlog/, ...   # Focused support packages
│
├── lsig/                          # LogicSig provider implementations
│   ├── all.go                     # Built-in LogicSig registration aggregator
│   ├── falcon1024/                # Falcon-1024 DSA provider
│   │   ├── derivation/, family/, keygen/, keys/, signerops/, signerreg/
│   │   └── v1/                    # v1 standard provider, ops, composer, reference vectors
│   ├── falcon1024_guarded/        # Guarded Falcon-1024 (user + cosigner) LogicSig provider
│   ├── ed25519lsig/               # Ed25519 LogicSig DSA base for composed templates
│   ├── composeddsa/               # Generic ComposedDSA composer
│   ├── dsafamily/                 # Client-safe DSA family registration descriptors
│   ├── signerreg/                 # Built-in signer-side LogicSig provider registration
│   ├── rotatinghybrid/            # Rotating Falcon-1024 + Ed25519 hybrid stage (signerops/, signerreg/, stage/)
│   ├── rotatingwots/              # Rotating WOTS hybrid stage (signerops/, signerreg/, stage/)
│   ├── rotatingtriple/            # Rotating Falcon + WOTS + Ed25519 triple hybrid stage (signerops/, signerreg/, stage/)
│   └── generictemplate/           # YAML-backed generic template provider
│
├── library/templates/             # Optional plaintext KeyType Library YAML sources
├── pkg/signerapi/                 # Public signer HTTP DTO source of truth used by external SDKs
├── pkg/policyschema/              # Public v1 policy JSON schema
└── examples/
    ├── js/                        # JavaScript examples
    └── external_plugins/          # External plugin examples
```

### Package Location Principles

| Package Type | Location | Rationale |
|--------------|----------|-----------|
| **Binary-local UI** | the `cmd/<app>` package itself | Only used by that application |
| **Shared UI/adapters** | `internal/apshellcli`, `internal/shellrepl`, `internal/signerapp/signertui` | Shared or separately testable shell/TUI surfaces |
| **Shell workflows** | `internal/apshellapp` | Shell-facing behavior shared by text, script, and MCP adapters |
| **Shared library** | `internal/` | Used by multiple apps or plugins |
| **Algorithm impl** | `lsig/` | DSA provider implementations |
| **Wire DTOs** | `pkg/signerapi` | Public signer HTTP payload types shared with SDKs |

The `internal/` packages include shared infrastructure and shared UI/adapter
packages used by product binaries. Binary-local UI code lives in the
`cmd/<app>` package itself when it is private to that binary. Shell command workflow
behavior should live in `internal/apshellapp`, not in `cmd/apshell`.

## Architecture Layers

| Layer | Packages |
|-------|----------|
| UI | `cmd/apshell`, `cmd/apconsole`, `internal/apshellcli`, `internal/shellrepl`, `internal/signerapp/signertui`, `cmd/apadmin`, `cmd/appass`, `cmd/aplocalnet`, `internal/aplocalnet`, `cmd/apapprover`, `internal/command`, `internal/cmdspec`, `internal/cmdlog`, `internal/theme`, `internal/addressdisplay`, `internal/keytypeux` |
| Engine | `internal/apshellapp`, `internal/apadminapp`, `internal/apboundedadminapp`, `internal/engine`, `internal/clientstate`, `internal/cache`, `internal/config`, `internal/engine/connect`, `internal/engine/guarded`, `internal/clientsign`, `internal/appresult`, `internal/appinput`, `internal/appspec`, `internal/asa`, `internal/addressbook`, `internal/refname`, `internal/keymgmt`, `internal/partkeyparse`, `internal/txnutil`, `internal/algo` |
| Signer App | `internal/bootstrap/signer`, `internal/signerapp/daemon`, `internal/signerapp/startup`, `internal/signerapp/runtime`, `internal/signerapp/productruntime`, `internal/signerapp/unlockconfig`, `internal/signerapp/signing`, `internal/signerapp/chainread`, `internal/signerapp/approval`, `internal/signerapp/templates`, `internal/signerapp/templateadmin`, `internal/signerapp/keyadmin`, `internal/signerapp/storeadmin`, `internal/signerapp/backupadmin`, `internal/signerapp/rest`, `internal/signerapp/admin`, `internal/signerapp/adminserver`, `internal/signerapp/svcerr`, `internal/signerapp/enrollment`, `internal/signerapp/enrollqueue`, `internal/signerapp/clientregistry`, `internal/signerapp/asametadata`, `internal/signerapp/audit`, `internal/signerapp/filewatcher`, `internal/signerapp/ipcbind`, `internal/signerapp/txdesc`, `internal/signerapp/policycmd`, `internal/signerapp/policyreview`, `internal/signerapp/policyapply`, `internal/signerapp/policyruntime`, `internal/noderole`, `internal/policy`, `internal/integritysidecar`, `internal/signerapp/approvalpolicy`, `internal/signerapp/storevalidate` |
| Provider | `internal/signing`, `internal/signing/falcon1024`, `internal/falconparams`, `internal/lsigresource`, `lsig/`, `lsig/rotatinghybrid`, `lsig/rotatingwots`, `lsig/rotatingtriple`, `internal/cosigner`, `internal/boundedadmin`, `internal/boundedmeta`, `internal/txeffects`, `internal/keyclass`, `internal/lsigprovider`, `internal/signingargs`, `internal/logicsigdsa`, `internal/genericlsig`, `internal/lsigsalt`, `internal/tealtemplate`, `internal/addressderive`, `internal/keytypecatalog`, `internal/keytypestate`, `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Storage/Crypto | `internal/crypto`, `internal/witness`, `internal/witness/artifact`, `internal/merkleallowlist`, `internal/keys`, `internal/keystore`, `internal/storepaths`, `internal/stagetable`, `internal/rotatingkey`, `internal/crypto/wots`, `internal/crypto/rotatinghybrid`, `internal/genstore`, `internal/storelock`, `internal/signerapp/storemut`, `internal/storeinit`, `internal/storepass`, `internal/serverconfig`, `internal/defaultkeytypes`, `internal/clientdata`, `internal/templatestore`, `internal/templatelibrary`, `internal/templatepolicy`, `internal/backup`, `internal/security`, `internal/fsutil` |
| Integration | `internal/bootstrap/shell`, `internal/auth`, `internal/authz`, `internal/protocol`, `internal/adminproto`, `internal/transport`, `internal/sshtunnel`, `internal/clientenroll`, `internal/endpointrefs`, `internal/plugin`, `internal/scripting`, `internal/jsapi`, `pkg/signerapi`, `internal/signerclient`, `internal/checksum`, `internal/manifest`, `internal/productmode` |
| Tooling | `analysis/`, `test/arch`, `test/contracts`, `test/fixtures`, `test/integration`, `test/storeintegration`, `test/registry`, `test/soak`, `internal/testcheckpoint`, `internal/docassets`, `internal/xregistry`, `internal/signerprobe`, `internal/version` |

This table is an orientation map rather than an ownership API. Small support
packages are listed under the closest layer that depends on them.

### UI Layer

The UI layer is split between thin binary adapters and reusable shell/admin UI packages:

- `cmd/apshell`: thin binary adapter and composition entry point for flags, provider registration, bootstrap, and mode selection
- `internal/apshellcli`: REPL/session mechanics, command registry, scripting mode adapters, MCP surface, plugin argument normalization, and shell rendering
- `cmd/apadmin`: TUI/batch adapter and composition entry point;
  `internal/apadminapp` owns authenticated noninteractive catalog, client
  enrollment, and store workflows over admin transport
- `cmd/apconsole`: secure-machine Bubble Tea wrapper for shell/admin/daemon panes, with local cosigner nodes using admin plus daemon panes only
- `internal/signerapp/signertui`: Bubble Tea signer admin UI
- `cmd/appass`: Bubble Tea passphrase setup UI
- `cmd/aplocalnet`: Bubble Tea/CLI LocalNet setup adapter; `internal/aplocalnet` owns reachability checks and config/plugin/env mutations
- `cmd/apapprover`: approval-only CLI

`internal/signerapp/signertui` keeps invalid-passphrase failures inline on the
passphrase screen. Serious post-auth unlock/load failures, such as a verified
passphrase followed by policy integrity or key reload failure, surface through
the blocking `ViewError` popup and remain visible until the operator dismisses
them.

UI responsibilities:

- parse human or machine input,
- resolve aliases, sets, assets, and formatting concerns,
- render text or JSON views,
- translate interaction into engine calls or IPC/HTTP requests.

`apshell` parsing is intentionally layered rather than ad hoc:

- human-facing shell syntax, command-specific parsing, tokenization, and interactive
  completion live in `internal/shellrepl`,
- reusable semantic argument parsing, including typed addresses, assets, amounts,
  byte decoding, and bracket-aware `key=value` fields, lives in `internal/cmdspec`,
- address/address-list resolution and ASA metadata/amount resolution are shared
  helpers rather than command-local parsers,
- the parser is incrementally moving from raw strings toward semantic values where that pays off (`AssetRef`, `AmountText`),
- execution relies on resolved domain values such as `asa.Amount` rather than a new parallel asset model.

### Engine Layer

The main shared application layer is `internal/engine`, which is the business-logic core for `apshell`.

It owns:

- transaction preparation,
- network access through algod,
- signer connectivity,
- client caches,
- script execution entrypoints,
- application call argument parsing and ABI method resolution,
- state transitions that should not depend on a particular UI.

Internally, `internal/engine` is split into a shared infrastructure type and the
domain command operations built on it. `engine.Core` (`internal/engine/core.go`)
owns the cross-cutting infrastructure — client-scoped caches and network state,
the remote signer connection lifecycle, the signer key cache, address and
signability resolution, and the client-data lock. `engine.Engine` embeds `*Core`
and adds the domain command methods (payments, assets, apps, key management,
guarded signing). This keeps the shared infrastructure in one place rather than
interleaved with domain logic on a single flat facade.

The live consensus boundary is client-owned in `internal/engine/consensus.go`.
Transaction construction validates algod SuggestedParams, and first-party
planning and executable workflows refresh the v42 check before asking
apsigner to plan, releasing signatures, invoking plugin signers, or submitting
or simulating immutable signed groups. The guarded flow enters through the same
checked submit boundary. `NewInitializedEngine` may leave `AlgodClient` nil when
algod is not configured or client creation fails; consensus-gated operations
then fail with `ErrNoAlgodClient` before contacting a signer, plugin, or network.
Apsigner remains network-independent and applies its compiled v42 contract.

Engine code must not depend on UI parsing or formatting packages; this is
enforced by `test/arch/client_layering_test.go` (see Architectural Invariants).

`apsigner` does not use `internal/engine`; it has its own server-side orchestration.

### Provider Layer

The provider layer supports multiple signing and LogicSig families:

- native Ed25519 in `internal/signing/ed25519`
- protocol-native Falcon in `internal/signing/falcon1024`, with signer-only
  registration and operations under `signerreg` and `signerops`
- client-safe shared Falcon size constants in `internal/falconparams`
- LogicSig DSA providers in `lsig/`
- compiled consensus resource profiles and the pure LogicSig group solver in
  `internal/lsigresource`
- provider metadata in `internal/algorithm`
- key generation in `internal/keygen`
- mnemonic support in `internal/mnemonic`
- unified LogicSig provider registry in `internal/lsigprovider`
- shared off-curve LogicSig validation and derivation helpers, including legacy
  manual-counter support, in `internal/lsigsalt`

Registration is explicit and happens from binary entrypoints via `RegisterProviders()`, not via package-global magic hidden from `main`.

`internal/signing` is the shared signing leaf: provider interfaces and
registries, key material types, and group-shaping/simulation helpers used by
both the client and the signer daemon. The client-side submit pathway
(`SignAndSubmitViaGroup`, `SubmitOptions`, transaction summary formatting)
lives in `internal/clientsign`, which imports the signer HTTP client and
client caches; `internal/signing` must not import `internal/signerclient`,
`internal/cache`, or `internal/addressbook`, so the daemon never links its
own HTTP client. New shell-facing command behavior should prefer
`internal/apshellapp` and `internal/engine`, and new signer HTTP transport
behavior should prefer `internal/signerclient` or `internal/engine/connect`.

### Storage/Crypto Layer

Persistent sensitive state is stored on disk and unlocked into memory only via the keyring flow:

- encryption and secure memory: `internal/crypto`
- key file IO and scanning: `internal/keys`
- keystore abstraction and file-backed implementation: `internal/keystore`
- signer-store path ownership, mutation coordination, and cooperative locking: `internal/storepaths`, `internal/signerapp/storemut`, `internal/storelock`
- primitive encrypted template persistence: `internal/templatestore`
- primitive key-type activation-record persistence: `internal/keytypestate`
- plaintext template parsing and all feature-level template/key-type mutation: `internal/templatelibrary`
- live template mutation locking/reload: `internal/signerapp/templateadmin`
- staged default-template bootstrap: `internal/defaultkeytypes`
- template reload/registration outcome reporting: `internal/templatepolicy`
- backup archives/validation: `internal/backup`
- generation mint/seal/store-root commit/reconcile/quarantine: `internal/genstore`

### Storage, Key, And Template Package Clusters

Several package families have similar prefixes because they split compatibility-sensitive
state by responsibility rather than by a single "keystore" package. This is intentional;
do not consolidate these packages just to reduce the directory count. Use this map when
deciding where a change belongs:

| Cluster | Package | Role |
|---------|---------|------|
| `store*` | `internal/storepaths` | Canonical signer/client path construction for data directories, identities, keys, templates, config, and library locations. |
| `store*` | `internal/genstore` | Atomic store-root selection, generation mint/seal, reconciliation/quarantine, sealed-prior validation, deleted-archive bounds/prune, garbage collection, and complete generation inventory (see [ARCH_STORE.md](ARCH_STORE.md#generations)). |
| `store*` | `internal/storelock` | Cooperative filesystem lock acquisition for signer-store mutation safety. |
| `store*` | `internal/signerapp/storemut` | Higher-level store mutation coordination around operations that rewrite identity/store files. |
| `store*` | `internal/storeinit` | Store initialization and bootstrap creation logic. |
| `store*` | `internal/storepass` | Passphrase-helper and passphrase-change support around store state. |
| `key*` | `internal/keys` | Encrypted key file payload/envelope IO, scanning, metadata, and key-file compatibility behavior. |
| `key*` | `internal/keystore` | File-backed keystore abstraction, keyring/session handling, and encrypted key persistence. |
| `key*` | `internal/keygen` | Signer-side key generation registry and generation result model. |
| `key*` | `internal/keymgmt` | Client/shell-facing key management request/result helpers. |
| `key*` | `internal/signingargs` | Shared internal model for signing-time LogicSig argument metadata projected into key files, signer cache records, and wire DTOs. |
| `key*` | `internal/keytypestate` | Product-store key type state record format and primitive read/write/delete operations for installed/disabled/activated template or provider definitions. |
| `key*` | `internal/keytypecatalog` | Key type catalog metadata assembled from registered providers and template records. |
| `key*` | `internal/keytypefmt` | Presentation-only key type formatting and publisher extraction. |
| `template*` | `internal/templatelibrary` | Plaintext signer-data template parsing and sole feature-level coordinator for template files and key-type state mutation. |
| `template*` | `internal/templatestore` | Encrypted product-store `.template` format and primitive save, load, scan, remove, and archive operations. |
| `template*` | `internal/templatepolicy` | Template registration outcome vocabulary and reload/report policy helpers. |
| `signerapp/templates` | `internal/signerapp/templates` | Read-only runtime reload coordinator that walks installed product-store templates and registers provider implementations. |
| `signerapp/templateadmin` | `internal/signerapp/templateadmin` | Live admin/use-case owner for signing-authority locking, library mutation, runtime reload/acceptance, results, and logging. |
| `defaultkeytypes` | `internal/defaultkeytypes` | Bootstrap use-case owner that installs defaults through `templatelibrary` into an unpublished staged generation. |

Rule of thumb:

- path/layout questions belong in `storepaths`, not in individual feature packages,
- generation commit, authenticated selection, reconciliation, and quarantine belong in `internal/genstore`; feature packages receive bound active-path capabilities rather than choosing a generation themselves,
- lock/mutation ordering belongs in `storelock` or `storemut`,
- key file bytes and encrypted key payload compatibility belong in `internal/keys` and `internal/keystore`,
- key generation/provider registration belongs in `internal/keygen` and provider packages,
- primitive installed-template persistence belongs in `templatestore`, and
  primitive key-type record persistence belongs in `keytypestate`,
- every production feature-level mutation of either persistence format routes
  through `templatelibrary`; feature packages do not call leaf writers,
- plaintext library parsing/import behavior belongs in `templatelibrary`,
- runtime template reload behavior belongs in the read-only
  `internal/signerapp/templates` package,
- live user/admin workflows and identity locking belong in
  `internal/signerapp/templateadmin`, while first-generation bootstrap belongs
  in `internal/defaultkeytypes` and publishes through `genstore` rather than a
  live reload.

### Integration/Protocol Layer

This layer includes:

- HTTP auth and authorization vocabulary/interfaces: `internal/auth`
- grant-backed authorization decisions: `internal/authz`
- IPC admin wire protocol and envelope definitions: `internal/protocol`
- transport-neutral admin request/result types and framed `AdminConn`:
  `internal/adminproto`
- server-side admin session lifecycle, dispatch, and handlers:
  `internal/signerapp/adminserver`
- admin client transport, dispatcher, and stream wrappers: `internal/transport`
- SSH tunnel server/client: `internal/sshtunnel`
- plugin discovery, manifest, integrity, sandbox, JSON-RPC: `internal/plugin`
- JavaScript runtime and bindings: `internal/scripting` and `internal/jsapi`

Admin transport model:

- the admin protocol is line-delimited JSON over local IPC only; SSH does not carry it (`aplane` connections accept only direct-tcpip forwards, and `request-enrollment` session channels accept only the `enroll` exec),
- every admin message carries an explicit envelope `kind` (`request`, `response`, `notification`),
- `internal/transport` owns one dispatcher-backed reader per post-auth connection,
- request/response correlation is by request `id`,
- transport lifecycle is separate from application semantics such as displacement,
- displacement handling remains in client layers like the `apadmin` TUI.

**Admin protocol architecture:**

The admin protocol is split into wire, server, and transport layers:

- `internal/protocol` owns the IPC admin message catalog and envelope
  definitions;
- `internal/adminproto` owns transport-neutral admin request/result types and
  the framed `AdminConn` abstraction;
- `internal/signerapp/adminserver` owns authentication, session lifecycle,
  active-session tracking, displacement, dispatch, handlers, and service
  interfaces;
- `internal/signerapp/daemon` adapts and wires the IPC transport. SSH
  (`internal/sshtunnel`) does not carry the admin protocol.

Non-transport code reaches the admin channel through
`internal/signerapp/adminserver.AdminHub`, implemented by the daemon
composition, rather than depending on the Unix IPC implementation directly.
Adminserver handlers access business logic through service interfaces wired to
the signer-backed services in `internal/signerapp/daemon/admin_services.go`.

### Tooling And External SDK Layer

The repo includes:

- analysis tools under `analysis/`
- architecture guards under `test/arch/`
- compatibility fixtures under `test/contracts/` and test support under
  `test/fixtures/`
- integration, registry, and soak coverage under `test/integration/`,
  `test/registry/`, and `test/soak/`
- network-independent blank-store lifecycle and deterministic crash coverage
  under `test/storeintegration/`, with build-tagged semantic fault injection
  owned by `internal/testcheckpoint/`

The Go, TypeScript, and Python SDKs live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. This repo owns the signer HTTP API DTOs in
`pkg/signerapi` and the golden fixtures in `test/contracts/signerapi/` that the
SDK repo consumes for compatibility testing. In-repo callers import
`pkg/signerapi` directly; there is no internal alias layer.
`pkg/signerapi/error_codes.go` remains the sole error-code source.
The SDK client shape, the SDK-native prep layer, the AlgoKit Utils adapters,
and the guarded prepared-signing sequence are specified in
[ARCH_SIGNING.md](ARCH_SIGNING.md).
SDK-facing HTTP behavior includes not only JSON payload shape, but also
contractual client expectations such as `/status` discovery and
approval-wait-aware `/sign` deadlines and explicit `/sign/cancel` request
cancellation. When this repo changes an SDK-exposed
endpoint, fixture, or timeout/deadline contract, the external SDK repo should
be audited and updated in the same release window.

Repository release/distribution workflow includes:

- GitHub release archives for full binary bundles on Linux and macOS,
- GitHub release archives for client-only bundles (`apshell`) on Linux, macOS,
  and Windows (`windows-amd64` zip with `apshell.exe`).

Release/distribution source-of-truth files are `Makefile` (`release-local` and
bundled plugin targets), `.github/workflows/release.yml`,
`docs/RELEASE_NOTES.md`,
`scripts/package-bootstrap-release.sh`,
`scripts/build-algokit-localnet-plugin-target.sh`,
`scripts/stage-bundled-plugins.sh`,
`scripts/install-example-plugins.sh`,
`scripts/docker-systemd-smoke.sh`,
`scripts/docker-local-four-node-smoke.sh`,
`plugins/algokit-localnet/`, `bootstrap-install.sh`, `install.sh`,
`uninstall.sh`, `installer/`, and `library/templates/`. Full release archives
include installer helpers, template libraries, and staged plugin runtime
payloads at `plugins.available/algokit-localnet`;
client-only archives include `apshell`/`apshell.exe`, client config templates,
README/setup metadata, and MCP setup helpers where supported by the platform.
Checksums are generated for release archives, and CI release checksums are
minisign-signed.

## Deployment Model

- One `apsigner` on the signer host
- Zero or one `apadmin`/`apapprover` admin workflow for the product runtime, connected over local IPC. For remote administration, log in to the signer host and run `apadmin` there.
- One or more `apshell` clients, local or via SSH tunnel. Interactive `apshell` is both the normal client shell and the enrollment/recovery surface: it may start before client enrollment is complete. Startup requires client config/bootstrap inputs, but not an enrolled key or a trusted signer host. SSH host trust is enforced when interactive `apshell` attempts a signer connection or enrollment flow, not before process startup; whether the key is enrolled is learned from the node at connect time. After successful enrollment at the default signer, `apshell` immediately connects with the enrolled key; cosigner enrollment does not replace the primary connection.
- `apshell --mcp` is a separate operational surface, not an enrollment or inspection surface. MCP startup is non-interactive and refuses to start unless a default signer endpoint is configured with a trusted endpoint `known_hosts` entry and the startup signer connection succeeds. First-time enrollment and trust bootstrap happen through interactive `apshell`, not MCP.
- Optional `apconsole` wrapper on the secure signer machine, preserving the same apshell/apadmin/apsigner transport interfaces while composing operator panes. `apconsole` can load `apconsole.yaml` from the install root to determine the client/signer data paths for local IPC administration. Startup resolution is deterministic per field: flags win over environment variables, environment variables win over an explicitly selected profile, and an explicitly selected profile wins over auto-discovery. If explicit sources disagree, `apconsole` exits instead of guessing. In local signer mode, `apconsole` may start before client enrollment is complete because it owns or attaches the local signer/admin surfaces needed for first-time `request-enrollment` approval; when the client SSH host is loopback, it probes the live loopback SSH endpoint before pinning the local signer's configured SSH host key into the client `known_hosts` file, and a mismatch aborts startup. Enrollment is learned from the node when the embedded shell attempts `request-enrollment`, `connect`, or startup auto-connect. The embedded admin pane uses local IPC and does not receive the shell's client data or enrollment client. In local cosigner mode, `apconsole` does not create an embedded shell pane; it renders the signer admin pane above the daemon/status pane. Remote console mode is rejected; SSH into the signer host and run apconsole there. In local mode it attaches to an existing IPC socket or starts `apsigner -d <signer-data>` as a child it owns; the daemon pane reports disabled/attached/starting/ready/failed/exited status and streams owned-daemon logs. When present, the shell pane uses `internal/apshellcli.Session`, preserving apshell command behavior; Ctrl+C cancels a running shell command when the shell pane is focused, and shell `quit`/`exit` closes only that embedded shell pane. Operator controls are root-level function-key pane focus, F4 zoom, Shift+arrow (and Shift+Tab) pane navigation, and `?`/F5 help overlay.
- Optional plugin child processes spawned by `apshell`

Trust boundaries:

- apshell↔apsigner
- apadmin over local admin IPC ↔ apsigner
- apshell↔plugins
- encrypted disk↔unlocked memory
- operator Unix group↔private signer store (runtime socket connectivity only)

Plaintext signer-managed credential authority is never returned across the
HTTP or admin transports. Store-owning local processes may decrypt credentials
transiently for signing, backup creation, verification, restore, or rebuild;
exported backup archives carry only passphrase-encrypted credential records.

### Fixed Product Store and Runtime

APlane is a **single-operator, single-signing-identity product**. Every
`apsigner` process owns exactly one signing-state aggregate. The aggregate owns
the keystore, lock state, approval coordinator, enrolled-client registry,
configuration, and watcher; it has no runtime ID, registry, or selector. IPC
admin clients compete for one process-wide admin session.

The durable namespace is `identities/default/`, with managed archives under
`backups/default/`. `default` is the fixed on-disk directory name, not a runtime
ID or authorization principal. The same fixed layout applies to signer-role
and cosigner-role data roots.

Signer transaction policy is product-scoped under `identities/default/` and uses the current verdict model
documented in [ARCH_POLICY.md](ARCH_POLICY.md): Always Deny, Always Review,
Always Approve, then Operator Default.

#### Fixed Store Namespace

`internal/storepaths.Paths` binds the
`identities/default/` and `backups/default/` directories from the signer data
root; storage, runtime, request, authentication, SSH, admin, and audit APIs
accept no runtime locator.

Startup performs a no-follow check that rejects any direct `identities/`
entry other than a real `default` directory before loading secrets or starting
watchers. HTTP authentication maps the enrolled client key of the request's SSH connection to
`client:<fingerprint>`. SSH accepts only `aplane` and `request-enrollment`;
an `aplane` connection must present an enrolled key, and every API channel it
opens carries that key's identity.

#### Product Runtime Invariants

The runtime enforces these single-product invariants:

- `adminserver.SessionManager` owns one pre-auth pending slot, one authenticated
  displacement slot, and one active product session;
- template/provider registration is process-global and
  `internal/lsigprovider.registerMu` has no per-owner reference counts;
- one product runtime owns the watcher, approval coordinator, enrolled-client
  registry, pending enrollment queue, runtime settings, and lock state;
- SSH uses the fixed usernames `aplane` and `request-enrollment` and carries no
  store or runtime identifier;
- audit records attribute actors through principal and session fields and carry
  no store or runtime identifier;
- `node.yaml.hmac` and policy sidecars bind authenticated state to the one
  product store root;
- startup layout validation rejects additional direct entries under
  `identities/` before secret loading.

## Runtime Configuration Model

### Client Configuration

`apshell` loads `internal/config.Config` from `config.yaml` in the first of:

- `-d <path>`
- `APCLIENT_DATA`

If neither is set, `apshell` errors out; there is no implicit default.

Current client config includes:

- default network context token,
- allowed network context tokens,
- per-network-context algod configuration,
- theme settings.
- signer status polling interval.

Signer and cosigner routing is not stored as active top-level `config.yaml`
state. Normal client routing lives in `endpoints.yaml` through
`internal/config.ClientEndpointRegistry`: at most one `signer` endpoint and up
to 12 `cosigner` endpoints. Endpoint records carry URL, identity file, and
`known_hosts`; no credential, because the enrolled identity key is the
credential; and no port beyond the one in the URL, because the
node's SSH server forwards every channel to its own REST listener and the
signer-role forward binds a free local port at connect time. Live cosigner-key discovery is operation-scoped
and is not stored in the registry. `internal/endpointrefs` owns the public `aplane.endpoint.v1` JSON
handoff envelope used by `apadmin endpoint export` and
`apshell endpoints import`.

`internal/config.Config` contains no signer-routing fields. Client signer and
cosigner routing is loaded exclusively from `endpoints.yaml`; top-level
`config.yaml` `ssh:` and `signer_port:` fields fail closed.

### Server Configuration

`apsigner`, `apadmin`, `apstore`, and `appass` load `internal/serverconfig.ServerConfig`
(client config remains `internal/config.Config`) from:

- `-d <path>`
- `APSIGNER_DATA`

Server config includes process-global settings such as:

- the `endpoint` block (loopback `signer_port`, required `ssh` server
  settings, optional `advertise_url`),
- IPC socket path,
- optional passphrase command,
- optional passphrase command environment,
- algod config for compilation/policy use,
- TEAL compile network context token,
- optional custom transaction genesis-hash to network-token mappings,
- memory protection requirement,
- rotating stage-table lookahead (`rotating.stage_horizon`),
- theme.

Product runtime settings are owned separately by `internal/signerapp/productruntime.RuntimeConfig`:

- `user_auto_approve`,
- `lock_on_disconnect`,
- `passphrase_timeout` (admin idle disconnect timeout),
- `approval_wait` (maximum manual signing approval wait).

Those values are persisted at `identities/default/config.yaml` via
`internal/signerapp/productruntime.StoredConfig`. Unknown fields, including
`decommissioned`, fail strict parsing. On startup, stored
runtime values overlay process-global defaults (nil/empty means inherit).
Runtime reads resolve through the product runtime rather than directly from
`ServerConfig`.

apsigner also reads product-store configuration:
- selected generation `keytypes/<key_type>.json` — product state records for optional key types
- selected generation `keytypes/<key_type>.template` — encrypted installed YAML templates

The signer data root may also contain `library/templates/*.yaml`, a plaintext
KeyType Library source copied from release or installer artifacts. Files there
are reference material until an authenticated admin installs a YAML template or
enables a library-visible compiled provider for the product runtime.

Key-class role is process/data-root scoped, not identity scoped. An initialized
signer data directory has a root `node.yaml` with exactly one role:
`signer` or `cosigner`. New installs default to `signer` unless explicitly
initialized as cosigner nodes. The role is immutable in supported tools, is
integrity-bound to the product store with an HMAC sidecar over the exact root
`node.yaml`, and gates key generation, key import/restore, key scan, and HTTP
service dispatch. Product runtime config does not own node role; a `mode` field
there is unsupported and must be rejected.

Passphrase helper configuration is product-store scoped via
`internal/signerapp/unlockconfig.UnlockConfig`, stored at
`identities/default/unlock.yaml`:

- `passphrase_command_argv`
- `passphrase_command_env`

Passphrase files are stored at `identities/default/passphrase` or `passphrase.cred` for `systemd-creds`.

Signer policy participates in the ordered approval engine. The current policy
verdict model is documented in [ARCH_POLICY.md](ARCH_POLICY.md). The active
node-role policy is product-store scoped and stored in the selected generation
as v1 JSON policy documents, each with a sibling HMAC sidecar: one node
default, `default.json`, and zero or one per-key document,
`policies/<selector>.json`. Document format, policy selection, and the
`apadmin policy`, `apadmin policy rescue`, and `apstore policy` workflows are
owned by [ARCH_POLICY.md](ARCH_POLICY.md); in code,
`internal/signerapp/policycmd` owns both `apadmin` workflows,
`internal/signerapp/policyapply` owns the shared check and commit rules, and
`internal/signerapp/policyreview` owns what the operator reviews before an
apply.

ASA amount-threshold editing in display units uses signer-wide ASA metadata under `cache/<network>_asa_cache.json` in the signer data directory. Signer code reaches this cache through `internal/signerapp/asametadata.Store`, not by treating it as APCLIENT_DATA cache state. This metadata is process-wide because ASA metadata is public chain state, not signing authority. Built-in ASA metadata is starter data for the same effective cache model; successful live algod lookups for numeric ASA IDs are persisted to the signed cache. Enforcement remains raw-unit and numeric-ASA-ID based, so the metadata cache is not authoritative for requiring review, accepting, or rejecting transactions.

LocalNet setup is owned by `aplocalnet` (`cmd/aplocalnet` plus
`internal/aplocalnet`). It is an operator-run setup utility, not a long-running
runtime service. It probes the running AlgoKit LocalNet algod, writes the
client `localnet` default and signer `localnet` genesis mapping, activates the
bundled `algokit-localnet` plugin, and can persist a KMD endpoint override into
the install `apenv.sh` so later `apconsole`/`apshell` plugin processes inherit
it. Installers use the same `aplocalnet --check`/`--apply` surface to offer
LocalNet setup when a reachable AlgoKit LocalNet is detected, defaulting the
prompt to no and applying only to the client and/or signer data roots being
installed. The compatibility details are documented in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

`apsigner` startup resolves the product store's `unlock.yaml` before the
process-global `config.yaml` passphrase command. `appass` has no runtime
selector and always manages `identities/default/unlock.yaml`.

Configuration behavior and validation rules are compatibility-bearing and are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). The network context model and genesis-hash mapping rules are explained in [ARCH_NETWORKS.md](ARCH_NETWORKS.md).

See [USER_CONFIG.md](USER_CONFIG.md) for full reference.

## On-Disk Data Model

The concrete on-disk layouts, key-file compatibility, keystore metadata versioning, template files, and backup format are documented in [ARCH_STORE.md](ARCH_STORE.md). The audit log format and events are documented in [ARCH_SECURITY.md](ARCH_SECURITY.md).

Operationally:

- client-local state lives under the client data directory, including plugins (`plugins.available/`, `plugins.yaml`), scripts (`scripts/`), the SSH identity (`.ssh/`), caches (`cache/`), swap state (`swap/<network>/`), and the cooperative `.apclient.lock`,
- signer-local state lives under the signer data directory, with the plaintext key type library at `library/templates/`, signer-wide ASA metadata at `cache/<network>_asa_cache.json`, managed backup archives at `backups/default/`, and all sensitive runtime assets rooted under `identities/default/`,
- systemd signer state is service-user-only (`0700` directories and `0600`
  ordinary files); the operator Unix group has no traversal rights and reaches
  signer operations only through authenticated transports. See
  [ARCH_STORE.md](ARCH_STORE.md#ownership-and-access),
- active credentials and key-type state live under `identities/default/generations/<gen-id>/`, selected by authenticated `store-root.enc`; see [ARCH_STORE.md](ARCH_STORE.md#generations) and [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md),
- store initialization stages the first generation with its node-role sidecar,
  the role's policy baseline (a signed `default.json` seeded from the embedded
  default for the role, on both roles; no per-key documents), and default key
  types before publishing `store-root.enc`; installers do not create or sign
  policy files outside the generation,
- systemd-managed admin IPC defaults to `/run/apsigner/aplane.sock`; explicit custom paths and same-UID local installs remain supported,
- the effective product layout is fixed; `default` is a literal namespace and
  compatibility value, not a caller-supplied locator.

The on-disk namespace is rooted at `identities/default/`. Runtime
configuration lives at `config.yaml` there. Everything that changes through a
generation commit lives under the selected `generations/<gen-id>/`: keys under
`keys/`, encrypted templates and state records under `keytypes/`, deleted
key/template/policy archives under `deleted/`, the node default policy at
`default.json`, and per-key policy at `policies/<selector>.json`, on both node
roles. `store-root.enc` selects the generation. HTTP authentication authorizes access
to that one aggregate; admin sessions over IPC bind to the same aggregate at
authentication time. The aggregate has
no runtime selector or registry.

## Security Model

### Authentication and Authorization

The system has two main auth channels:

- enrolled SSH key auth for shell/API callers: the HTTP API is reachable only
  through the node's SSH server, and each request is attributed to the key
  that authenticated its connection
- passphrase auth for admin sessions over local IPC

Authorization is a separate concern through `auth.Authorizer`. Runtime code uses
the explicit product action allowlist documented in
[ARCH_SECURITY.md](ARCH_SECURITY.md). In product mode,
credentials map to the reserved `system:product-admin` principal
and the fixed `default` resource boundary; authentication does not bypass
authorization.

### Secret Handling

Important secret-handling contracts:

- passphrases unwrap the store's keyring and should be zeroed promptly,
- the file keystore caches the keyring only while unlocked,
- normal signing decrypts individual keys on demand rather than retaining a
  fully decrypted key inventory,
- backup validation, direct restore, and offline rebuild may transiently
  decrypt the complete selected credential set so it can be validated before
  mutation; those plaintext buffers are explicitly zeroed after use,
- key/session destruction zeros or invalidates in-memory sensitive state,
- memory locking and core-dump disabling are best-effort unless configured as required.

### Session Semantics

`apsigner` has three relevant session concepts:

- unlock state of the signer,
- active admin client connection state,
- apadmin's configured local idle disconnect timeout.

Admin protocol sessions carry `adminserver.SessionContext`: session ID,
admin principal, auth method, transport, remote address, and requester/approver
attribution fields. This context is internal to the admin transport and audit
plumbing; it is not a new public product surface.
Admin authorization denials are audited with the session context, action,
resource, and denial reason before returning `authorization_denied` to the
admin client.

`adminserver.SessionManager` owns one pre-auth pending slot, one authenticated
pending slot during displacement, and one active slot for the process. Local
IPC admin sessions contend for those slots. Displacement, pending
cleanup, lock-on-disconnect, approval delivery, and notification delivery all
address the active product session.

Locking zeroes every term key and deactivates the key session. Local
admin idle timeout is enforced by `apadmin` as a disconnect; the signer applies
`lock_on_disconnect` when that disconnect is observed.

### Authentication

- HTTP: connection auth. The enrolled client key that authenticated the SSH
  connection becomes the request's `client:<fingerprint>` principal; requests
  carry no credential, and handlers use the one product runtime.
- IPC: passphrase auth. The admin protocol has no runtime selector and
  binds to the product runtime after passphrase verification.
- SSH: enrolled public key for tunnel connections. The fixed non-secret
  username is `aplane`; the key must be in the node's registry, which is
  re-checked after the handshake. Enrollment is a key-only bootstrap using the
  `request-enrollment` username: the request is queued for the operator,
  who approves it later, and the client connects once it is approved.

## Server Ownership Model

`Signer` (`internal/signerapp/daemon/server.go`) is the composition root. The
one product signing-state aggregate lives in `productruntime.Runtime`
(`internal/signerapp/productruntime/runtime.go`). It has no runtime selector or
registry.

| Concern | Owner |
|---------|-------|
| Lock/unlock state | `internal/signerapp/runtime` |
| Sign request lifecycle, approval queue, cancellation | `internal/signerapp/approval` |
| Planning, approval flow, execution, signing orchestration | `internal/signerapp/signing` |
| Template registration, reload coordination | `internal/signerapp/templates` |
| Admin protocol wire types, envelopes, and framing primitives | `internal/protocol` |
| Admin service request/result vocabulary and framed server connections | `internal/adminproto` |
| Admin session state, message dispatch, and handlers | `internal/signerapp/adminserver` |
| Product runtime aggregate, config, enrolled-client registry and pending queue, lifecycle | `internal/signerapp/productruntime` |
| HTTP contract types (request/response DTOs) | `pkg/signerapi` |
| Startup composition, path threading | `internal/bootstrap/signer`, `internal/bootstrap/shell` |
| Keystore paths | `internal/storepaths.Paths` value types (no process-global setters) |
| Cache paths | `cache.Store` value types |

`cmd/apsigner` is a thin binary adapter: it parses flags, registers the
providers shipped in the binary, and hands off to `internal/signerapp/daemon`.
The daemon package owns HTTP mux registration and handlers, IPC/SSH runtime
wiring, and final transport adaptation. Signer-side application failures use
typed `ServiceError` values mapped to HTTP status at that transport edge.
Signer request lifecycle state is owned below the HTTP layer:
`pkg/signerapi` defines the request/cancel DTOs,
`internal/signerapp/daemon` routes `/sign` and `/sign/cancel`,
`internal/signerapp/rest` binds live `/sign` request IDs to the product runtime,
`internal/signerapp/approval` owns pending/canceled lifecycle state, and
`internal/signerclient` is the repo-owned client that creates request IDs and
sends explicit cancellation.

### Server Responsibilities

`apsigner` is the system’s control plane for:

- HTTP signing and planning,
- key inventory exposure,
- key generation, mnemonic import, delete, and export rejection
  admin operations,
- approval orchestration,
- admin protocol interactions over local IPC,
- SSH tunnel hosting,
- audit logging,
- signer lock/unlock lifecycle,
- key file watching and reload.

### Server Startup

apsigner supports four startup modes that share a unified initialization path:

| Mode | Passphrase Source | Starts | Use Case |
|------|-------------------|--------|----------|
| **Headless** | `passphrase_command_argv` config | Unlocked | Automation, CI/CD, systemd services |
| **Locked** | apadmin IPC connection | Locked | Interactive operation, manual approval |
| **Test** | `TEST_PASSPHRASE` env | Unlocked | Test harness / integration environments |
| **Forced locked** | No `store-root.enc` present | Locked | Uninitialized signer state |

Before normal startup option loading, `apsigner` rejects manual startup from a
signer data directory containing `.prod` unless the process is systemd-managed.
Systemd-managed means `APLANE_SYSTEMD_MANAGED=1` or parent PID 1. This guard is
checked before locked/headless/test startup mode selection.

**Startup flow:**

1. Validate that `identities/` is blank or contains only a real `default/`
   directory, with no extra files, directories, or symlinks.
2. `startup.BuildProductRuntime` constructs the one product runtime from the
   default config overlay, enrolled-client registry, and keystore.
3. In headless mode, the product store is unlocked immediately; in locked
   mode, unlock happens later via admin IPC.

See [USER_CONFIG.md](USER_CONFIG.md#headless-operation) for headless configuration details.

Both locked and headless paths converge through
`productruntime.Runtime.reloadLocked`, entered through `Runtime.Reload` or
`ReloadWithPassphrase`. Production wiring from
`startup.WireReloadFunc` delegates the work to
`templates.ReloadService.Reload`, which:

1. opens or reuses the keyring,
2. verifies the identity's node role and loads its authenticated policy,
3. registers templates,
4. scans keys,
5. validates the scanned key classes against the node role,
6. replaces runtime indexes,
7. activates the key session,
8. emits audit and IPC notifications.

Key type activation and disabled records are consulted by inventory and admin
key operations when deciding whether an optional key type can be discovered,
generated, or imported.

Template scan precedes key scan so generation/discovery state is current.
LogicSig key files carry their own bytecode and signing arg contract, so
signing an existing key does not depend on the installed template definition.
The complete key file and key type state machines are documented in
[ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).
LogicSig key files whose stored bytecode derives an on-curve address are
rejected during key scan. Legacy empty/`manual_counter` derivations require
`salt_counter`; `algod_v13_auto_salt` derivations forbid it and require final
TEAL v13+ bytecode plus a valid `lsig_opcode_profile`. LogicSig key files without
`signing_metadata_version` are rejected when signing or restore would need
durable signing metadata. Key files with `signing_metadata_version >= 1` are
**versioned signing-metadata keys**; non-bounded keys use version 1 and bounded
keys require version 2 plus durable `bounded_authorization`. DSA LogicSig
files persist `base_key_type` even when it equals `key_type`. The stored
bytecode must derive an off-curve LogicSig address.

### Server Primary In-Memory State

The main server struct is `Signer`, which owns:

- the one product runtime and node-level fail-closed state,
- authn/authz components,
- signer-side planning/approval/execution service adapters,
- IPC server,
- optional SSH server,
- config and data-dir references.

Sensitive product state lives under `internal/signerapp/productruntime.Runtime`, including:

- `keySession`,
- product `keys`, `keyTypes`, and `keyMetadata` resource profiles,
- signer runtime owner,
- approval coordinator,
- watcher lifecycle,
- effective policy (`policyruntime.NodePolicy`: the default plus per-key documents, resolved by `PolicyFor(selector)`),
- product runtime config,
- enrolled-client registry state.

The key indexes are authoritative runtime indexes of what the server believes is signable.

### Lock Hierarchy

| Lock | Protects |
|------|----------|
| `Signer.configMu` | Live `ServerConfig` snapshots and mutable process settings such as theme; SSH listener and advertise values are deployment-owned reads, not writable admin settings |
| `Signer.configMutationMu` | Process-owned `config.yaml` write serialization |
| `Signer.storeMutationLock` | Product key/template/config/policy mutation serialization |
| `Signer.restoreAttemptMu` | Lazy initialization of the per-archive restore backoff limiter |
| `Signer.sshRuntimeMu` | SSH runtime and server swaps |
| `Signer.rotatingLocks` | Per-account serialization of rotating signing |
| `productruntime.Runtime.keysLock` | `keys`, `keyTypes`, `keyMetadata` |
| `productruntime.Runtime.passphraseLock` | `keySession`, `reloadFn`, unlock-sensitive ops |
| `productruntime.Runtime.watcherMu` | Watcher lifecycle, dirty state |
| `productruntime.Runtime.policyMu` | Effective node policy (`nodePolicy`) |
| `productruntime.Runtime.keyUseMu` | Key-user context and WaitGroup for background key holders (stage-table worker), drained on lock |
| `productruntime.Runtime.rotatingStatusMu` | Rotating alerts and notes published to `/status` and apadmin |
| `productruntime.Runtime.approval` | `atomic.Pointer` — approval coordinator |
| `Runtime.stateMu` | Signer locked/unlocked state |
| `Coordinator.pendingRequestsLock` | Pending sign approvals |
| `productruntime.Runtime.clientsMu` | Enrolled-client registry and pending enrollment queue together, so an approval is one step |
| `adminproto.StreamAdminConn.writeMu` | Serializes outbound framed messages for each admin connection |
| `adminserver.SessionManager.mu` | Process-wide admin session registration/displacement |
| `AuditLogger.mu` | Audit file writes |
| SSH server locks | Product hooks, client connections by fingerprint, enrollment claims, listener |

Goroutines:

- HTTP server plus per-request handler goroutines,
- IPC accept loop plus per-client goroutines,
- file watcher goroutine,
- SSH server accept loop plus per-connection goroutines.

### Lock/Unlock Lifecycle

Unlocking must:

- open and authenticate `store-root.enc` with the passphrase,
- hold the unsealed term keys,
- initialize the key store,
- scan templates before key scanning where needed,
- scan keys and populate indexes,
- mark the key session active,
- update signer runtime state,
- optionally start key watching.

Locking must:

- zero every term key,
- destroy the key session state,
- clear or invalidate key caches as appropriate,
- notify interested IPC clients.

Store maintenance adds a product-store state fence in `Runtime.stateMu`.
Beginning maintenance clears and locks the published key session before any
root transition. Unlock and recovery attempts that start during the fence are
rejected without loading authority; attempts already in flight lose on the
generation check and clear anything they loaded. Only the matching successful
maintenance token may republish after verified reload. Failure, a stale token,
or a racing explicit lock leaves the runtime locked.

The watcher is owned by the product runtime but is not tied to every lock
transition:

- when the runtime is unlocked, the watcher reloads immediately on qualifying filesystem changes,
- when the runtime is locked, the watcher remains active and marks the runtime dirty,
- the next unlock reconciles dirty state by reloading,
- watchers are stopped on runtime shutdown, not on every ordinary lock.

Watcher-triggered reloads acquire the same process-wide mutation lock used by
admin template/key/config mutations. Admin mutation paths that already hold the
lock call `Reload` directly; watcher paths use the watcher reload entrypoint so
they do not re-enter the same lock.

Installed-template provider reconciliation follows `Signer.storeMutationLock`
to `internal/lsigprovider.registerMu`. The one product activation set directly
registers or unregisters its process-global provider; there are no identity
owner counts.

The signer owns one product `*productruntime.Runtime` directly. There is no live
identity-decommission state or operation lease. Graceful shutdown stops and
drains request servers before destroying runtime key state; key-session locks
continue to protect signing authority access. Lock, disconnect,
displacement, and shutdown continue to fail pending approvals through the
reason-independent coordinator fail-all contract.
If a request server fails to stop, lifecycle records
`SERVER_STOP_INCOMPLETE` with `outcome:"failed"` and the service error. A
deadline error means a handler may still be running, so lifecycle leaves the
audit logger and runtime key state intact for process exit. A non-deadline stop
error occurs only after handlers have drained; lifecycle closes the audit log
and destroys runtime state normally. SSH stop uses the same lifecycle deadline
and reports a deadline error until its accept loop and all connection handlers
have exited.

### Server-Side Application Boundary

The server-side plan/sign boundary is split as follows:

- startup option resolution, validation, product-runtime assembly, and lifecycle entrypoint in `internal/signerapp/startup`,
- transport adapters/builders for HTTP, IPC, and SSH in `internal/signerapp/daemon`,
- transport-neutral admin request/result types and framed connections in `internal/adminproto`,
- server-side admin protocol/session state machine in `internal/signerapp/adminserver`,
- process-root admin facade for server-originated admin traffic and process-wide
  session presence checks in `internal/signerapp/adminserver.AdminHub` and
  `internal/signerapp/daemon/admin_hub.go`,
- signer-backed admin protocol services in `internal/signerapp/daemon/admin_services.go`,
- admin settings and policy service composition in `internal/signerapp/admin`,
- admin key-mutation HTTP/IPC transport mapping in `internal/signerapp/daemon/http_handlers_admin.go` and `internal/signerapp/daemon/admin_services.go`, with reusable key operations in `internal/signerapp/keyadmin`,
- IPC bind-path validation in `internal/signerapp/ipcbind`,
- filesystem key/template reload watching in `internal/signerapp/filewatcher`,
- REST service composition for signing, planning, key administration, and generic LogicSig generation in `internal/signerapp/rest`,
- signer runtime state and lifecycle management in `internal/signerapp/runtime`,
- sign request lifecycle, cancellation, and approval queue ownership in `internal/signerapp/approval`,
- planning, approval flow, execution, and top-level sign orchestration in `internal/signerapp/signing`,
- signer transaction description formatting in `internal/signerapp/txdesc`,
- template registration and reload lifecycle in `internal/signerapp/templates`,
- template library, install, show, import, remove, activate, and deactivate workflows in `internal/signerapp/templateadmin`,
- client enrollment requests (queued at once, answered by the operator later) and their audit in `internal/signerapp/enrollment`, with the persisted queue file in `internal/signerapp/enrollqueue`,
- the enrolled-client registry (strict parser, validate-then-publish) in `internal/signerapp/clientregistry`,
- append-only audit logging in `internal/signerapp/audit`, with HTTP/request
  attribution and operational side effects wired from
  `internal/signerapp/daemon`.

Transport adapters should not own:

- lock/unlock state transitions,
- key index mutation,
- approval queue ownership,
- admin request dispatch and message-specific handler logic,
- request canonicalization,
- policy enforcement,
- client enrollment and revocation side effects.

Storage primitives should not own:

- HTTP status mapping,
- IPC message shaping,
- approval prompting,
- admin idle-timeout policy,
- audit formatting.

### Simulate Signing Boundary

Client simulate mode is a post-signing routing choice. Apsigner has no
simulation endpoint or simulation-only signing mode.
`internal/clientsign.SignAndSubmitViaGroup` sends the normal request to `/sign`,
including ordinary policy, review, approval, signing, and audit behavior. Once
the executable signed group is returned, the client either submits it or sends
the exact same bytes to its configured algod simulation endpoint. Apsigner
cannot know which route the client chooses.

For both simulate and submit paths, `SignAndSubmitViaGroup` returns the
post-planning submitted transaction objects so callers and `txnjson` output
describe the exact transaction slots sent to algod rather than the caller's
pre-signing drafts.

This boundary matters because the returned msgpack is reusable and normally
submittable until the validity window expires. Simulation therefore requires
the same authorization as submission and must not be presented as a
non-executable approval. Audit events record authorization and release of
signatures, not whether the client later simulated, submitted, or committed the
group.

Mixed plugin/server-managed groups retain their ordinary canonicalization and
signing path, then branch to client algod only after the final executable group
exists. Guarded groups likewise complete the normal user and cosigner component
signing plus `/sign/assemble` path before the client routes the assembled group
to submit or simulate. The client consequently holds executable guarded bytes
in both modes. See [ARCH_GUARDED.md](ARCH_GUARDED.md).

## Client Ownership Model

| Concern | Owner |
|---------|-------|
| Shell application use-cases and command semantics | `internal/apshellapp` |
| Business operations, transaction orchestration | `internal/engine` |
| Cache-backed client state and alias/set mutation | `internal/clientstate` |
| Persisted alias/set name validation and normalization | `internal/refname` |
| Address/key-type terminal display formatting | `internal/addressdisplay` |
| Signer connection, tunnel lifecycle, signer-facing HTTP | `internal/engine/connect` |
| Signer HTTP client (plan, sign, keys) | `internal/signerclient` |
| Semantic result vocabulary | `internal/appresult`, `internal/apshellapp` |
| Shared ASA metadata, reference, and amount handling | `internal/asa` |
| Command registry, parsing adapters, rendering, plugin arg normalization, command-specific safe machine projections | `internal/apshellcli` |

Engine inputs are resolved application values, not raw CLI tokens. Engine outputs are structured data, not terminal text.

### Client Responsibilities

`apshell` is both an operator shell and an automation host. It provides:

- interactive REPL,
- one-shot command execution,
- script execution,
- JavaScript execution through Goja,
- MCP server mode,
- external plugin orchestration,
- remote signer communication over SSH + HTTP.

### Client State Model

Most client business state is split across four cooperating layers:

- `internal/apshellapp.App` for shell-facing use-cases and command semantics,
- `internal/engine.Engine` for business operations and transaction orchestration,
- `internal/clientstate` for APCLIENT_DATA-scoped caches and client mutation state,
- `internal/engine/connect` for signer connection state, tunnel lifecycle, and signer-facing requests.

ASA-specific ref/amount semantics are centralized separately:

- `internal/asa` owns network-aware ASA reference resolution,
- `internal/asa` owns raw/display conversion helpers,
- `internal/asa` owns caller-facing ASA display formatting,
- `internal/cache` remains the persistence/fetch layer for cached ASA metadata.

The combined client runtime owns:

- selected network,
- algod client,
- ASA, alias, signer, auth, and set caches,
- write/verbose/simulate toggles,
- SSH tunnel connection state.

UI-specific session state lives mostly in `internal/apshellcli` around that runtime split. Shell-owned concerns include:

- command parsing,
- terminal output and prompts,
- plugin argument token normalization,
- transaction write-mode status notices,
- explicit automation policy and safe machine-result projection.

Rule of thumb:

- `cmd/apshell` should stay a thin binary adapter for flags, provider registration, bootstrap, and mode selection,
- `internal/apshellcli` should parse input, call `internal/apshellapp`, and render output,
- `cmd/apshell` should not call behavior-owning `internal/engine` methods directly,
- direct `internal/engine` usage in `cmd/apshell` should be runtime/composition glue only, not command workflow ownership.

### Engine Boundary

The practical client-side split is:

- `internal/apshellapp` owns shell-facing command semantics and application orchestration,
- `internal/apshellcli` owns command syntax, interactive UX, MCP mode, plugin argument normalization, final shell rendering, and command-specific safe machine projections,
- `cmd/apshell` owns binary-level composition and startup delegation,
- `internal/engine` owns business operations and stateful client runtime behavior,
- `internal/clientstate` owns cache-backed client mutation state,
- `internal/addressdisplay` owns alias/rekey-aware address and key-type terminal display formatting,
- `internal/engine/connect` owns signer connectivity and signer-facing request flow,
- `internal/asa` owns shared ASA metadata/reference/raw-display handling,
- `internal/appresult` owns shared structured result vocabulary and reusable
  machine-projection types/helpers; `internal/apshellcli` owns the one
  human/machine command-result boundary and its command-specific allowlists.

The engine boundary is partial rather than absolute:

- shell-facing command orchestration routes through `internal/apshellapp`,
- transaction preparation and signing-facing operations are largely UI-independent,
- command-line syntax parsing stays in `internal/apshellcli` and `internal/shellrepl`,
- core transaction and network operations live in `internal/engine`,
- alias/set/cache mutation and disk-backed refresh behavior live in `internal/clientstate`,
- signer connection state and signer-facing HTTP request flow live in `internal/engine/connect`,
- ASA metadata fetch/cache composition and amount formatting live in `internal/asa`,
- some account/result shaping concerns leak across the boundary.

### Connection Model

`apshell` can connect to a signer through:

- local or remote SSH tunnel transport,
- then HTTP requests tunneled to signer REST endpoints, attributed to the
  enrolled key that authenticated the tunnel.

The client treats transport connectivity and signer key availability as separate concerns. `EnsureSignerCache()` exists specifically because a connected signer may transition from locked to unlocked later.

### Rendering Model

The shell has one result-bearing execution contract with two presentations:

- human-oriented text rendering,
- machine-oriented JSON rendering for MCP and automation.

This is implemented through `command.Result`, explicit projections in
`internal/apshellcli`, and semantic result types from `internal/apshellapp`,
not by parsing terminal output.

- business operations return structured results first,
- text rendering and machine marshaling are presentation-only,
- REPL and MCP invoke the same handler once,
- MCP has no terminal-output capture fallback.

### Command Surface

The `apshell` command surface is itself a compatibility-sensitive operator surface.

First-class built-in command families include:

- transaction commands: `send`, `sweep`, `sign`, `optin`, `optout`, `keyreg`, `close`, `validate`, `rotate`
- information commands: `balance`/`bal`, `holders`, `participation`, `asa`, `help`/`h`, `status`, `accounts`, `info`, `plugins`
- app commands: `app`
- alias/set commands: `alias`, `sets`
- rekey commands: `rekey`, `unrekey`
- signer/key-management commands: `keys`, `keytypes`, `generate`, `delete`
- config/toggle/connectivity/session commands: `network`, `write`, `verbose`, `simulate`, `config`, `connect`, `disconnect`, `request-enrollment`, `endpoints`, `cosigner`, `clear`/`cls`, `quit`/`exit`/`q`
- scripting/plugin commands: `script`, `js`, `jssave`, `jslist`

Command handling constraints:

- command names, aliases, and top-level usage grammar are operator-visible compatibility surfaces,
- moving handler code does not by itself change behavior; silently changing accepted syntax does.

### Standalone Swap Client

The standalone atomic-swap client is outside this repository. This repository does not own standalone
swap source under `cmd/` or `internal/`.
This section describes the cross-repository compatibility contract for the
client-state layout and on-chain note protocol that APlane clients coordinate
around.

Proposer and acceptor communicate via on-chain zero-ALGO payment notes:

- `swap_propose`
- `swap_accept`
- `swap_submit`

Proposal notes include:

- `proposal_id`
- `terms_hash`
- `app_id`
- proposer and acceptor legs
- proposer selected-path LogicSig resource profile
- expiry round
- creation timestamp

Acceptance binds to proposal by `proposal_id` and `terms_hash`.

Session state persists under `swap/<network>/`.

Statuses:

- `waiting_acceptance`
- `acceptance_seen`
- `handoff_ready`
- `submitted`
- `cleanup_pending`
- `complete`
- `expired`
- `abandoned`
- `cleanup_failed`

Reconciliation behavior:

- terminal sessions are skipped
- submitted sessions with pending cleanup always reconcile
- pre-submit sessions expired more than 100 blocks ago are skipped
- diagnostics track observed round, protocol compatibility, payload size, planned transaction count, dummy count, and cleanup metadata
- terminal sessions and tombstones are garbage-collected after 30 days

Indexer URL resolution:

- `APSWAP_INDEXER_URL`
- `APSHELL_INDEXER_URL`
- `APLANE_INDEXER_URL`
- built-in Algonode default

## Transaction Processing

The system separates:

- group shaping and canonicalization,
- cryptographic authorization,
- submission.

The signer server canonicalizes group shape, fee pooling, dummy requirements,
and group IDs; then it signs or assembles each entry according to key type. In
component choreography, canonicalization occurs only in the preceding `/plan`
call. `/sign/component` and `/sign/assemble` consume and validate the frozen
group without adding or repairing transactions.

Four authorization classes:

- native Ed25519: signs `TX || msgpack(txn)`
- native Falcon-1024 (`native_pq`): signs `TX || msgpack(txn)` and carries the
  signature in top-level `SignedTxn.PQsig`
- DSA-backed LogicSig: signs a derived message, typically the transaction ID
- generic LogicSig: assembles bytecode plus runtime args, no cryptographic signature

Three request modes per transaction entry:

- sign
- passthrough
- foreign

These modes can mix within a single group request.

The server is responsible for:

- decoding transaction bytes,
- validating request shape,
- determining key type requirements,
- adding dummies,
- pooling fees,
- computing group IDs,
- assembling signed transactions.

The client is responsible for:

- constructing the intended transaction set,
- supplying auth address and runtime args,
- optionally merging foreign or passthrough outputs,
- submitting the final signed bytes to algod.

Group canonicalization and the HTTP request/response contracts are described in [ARCH_SIGNING.md](ARCH_SIGNING.md); the component-flow canonicalization and byte-binding rules live in [ARCH_GUARDED.md](ARCH_GUARDED.md).

### Transaction Signing Flow (Summary)

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
  bounded-cosigner signed groups.
- Bounded administration: `POST /sign/bounded-admin` prepares external
  contract-admin partials outside the ordinary send path.
- Rotating (`rotating1` flow): `POST /sign/rotating/prepare` builds the exact
  stage-rotation group and `POST /sign/rotating/sign` signs only that prepared
  group; ordinary signing endpoints refuse rotating accounts with
  `rotating_signing_required`.

See [ARCH_SIGNING.md](ARCH_SIGNING.md) for the full REST inventory and wire
contracts, [ARCH_GUARDED.md](ARCH_GUARDED.md) for guarded choreography, and
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) for bounded choreography.

**Multi-party signing:** Transactions can be marked as **foreign**
(`txn_bytes_hex` without `auth_address`) to include them in group building
without signing. This works on both `/plan` and `/sign`: `/plan` returns
canonical unsigned transactions, while `/sign` returns `""` in foreign
positions and signed bytes only for signer-owned or passthrough positions. An
optional structured `lsig_resources` hint enables consensus-aware dummy and
fee calculation for the other party's selected LogicSig path. See
[`ARCH_SIGNING.md`](ARCH_SIGNING.md) for details.

### Signing Authority And Template Authority

See [ARCH_STORE.md](ARCH_STORE.md#signing-authority) for the signing authority contract.

## Bounded Authorization Contracts

The `bounded1` authorization envelope, its fee ceiling and Layer 3 gate, Falcon
contract-admin custody, admin-key rekey routing through `POST /sign/bounded-admin`,
and the single finalized-transaction classification boundary are specified in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

`aplane.falcon1024-allowlist-alock.v1` is the framework-owned fixed-list
profile. `aplane.corridor.v1` composes the framework Merkle policy with a
cosigner spend gate and external-admin rekey. External key generation and ceremonies are owned by
`aprekey`; apshell and apconsole do not handle private contract-admin
artifacts. The normative field inventory, canonical encodings, vectors,
schema, normal forms, and custody contract are in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

Package ownership: `internal/boundedmeta` owns the durable non-secret bounded
metadata vocabulary and canonical encodings; `lsig/composeddsa` owns profile
compilation, TEAL rendering, and the program-instance binding;
`internal/txeffects` owns the frozen effect-classification manifest and the
single finalized-transaction `Classify`/`Inspect` boundary. Signer-side
planning/execution live in `internal/signerapp/signing`, and online rekey
submission in `internal/engine/bounded_admin.go`. The external contract-admin
ceremony is owned by the `aprekey`-only packages:
`internal/boundedadmin/{authorization,program,protocol,message,helpersign}`
(request validation, frozen-bytecode structural validation, ceremony wire
format, admin transcript, and Falcon signing ops), with encrypted standalone
witness custody in `internal/witness/artifact` and
`internal/apboundedadminapp` composing the client application.

## Guarded Signing And Cosigner Nodes

This section is the system-map summary. The detailed subsystem architecture,
trust boundaries, guarded authorizer semantics, endpoint routing model, and
implementation map live in [ARCH_GUARDED.md](ARCH_GUARDED.md).

Guarded signing is APlane's two-party LogicSig authorization path for
accounts whose LogicSig bytecode requires both:

- a user component signature produced by the user signer that owns the
  guarded-account key file, and
- a cosigner component signature produced by a separate cosigner signer that
  owns a cosigner key and evaluates the cosigner policy that governs that key
  (its own document, or the node default).

The client never holds private key material. It orchestrates component signing
and assembly through authenticated signer endpoints, then submits or simulates
the final signed group with algod.

### Node Roles

Each initialized signer data root has one immutable root `node.yaml` role:
`signer` or `cosigner`.

The root role gates key generation, mnemonic import, restore, key scan, and
HTTP signing dispatch. A role-conflicting key in the inventory fails closed for
the node rather than being silently skipped. `internal/noderole` owns
`node.yaml` parsing and runtime-bound integrity sidecars, sharing the sidecar
format and HMAC checks with policy through `internal/integritysidecar`; `internal/keyclass`
owns role-versus-key-type classification. The exact node-role contract and
on-disk integrity checks live in [ARCH_STORE.md](ARCH_STORE.md#node-role-gate).

### Key Types

Witness key types are raw auxiliary signing keys, not spending
accounts and not LogicSig providers:

- `aplane.witness-falcon1024.v1`

They are selected by 52-character uppercase, no-padding base32 Witness Key IDs
derived as:

```text
base32_no_padding(SHA512_256(
  field("APLANE_WITNESS_KEY_ID_V1") || field(key_type) ||
  field(canonical_public_key_bytes)
))
```

The Witness Key ID intentionally has the visual shape of an Algorand transaction
ID, but it is not a valid Algorand address because addresses are 58 characters.
Signer-custodied cosigner witnesses use
`<active-generation>/keys/<WitnessKeyID>.cos`; account authority uses the same
active namespace with `<AlgorandAddress>.key`. Physically, the active namespace
is `identities/default/generations/<gen-id>/keys/`, selected by the store root.
There is no root-level credential namespace or compatibility fallback. External contract-admin
witnesses remain standalone `.wit` artifacts and are never scanned by the signer.
The full cosigner public key remains the verifier key embedded in guarded
account LogicSig bytecode. The same witness key form can serve a bounded
contract-admin enrollment under standalone custody, but one keypair should
never serve both roles. `internal/witness` owns identity and custodian/domain
capabilities; `internal/cosigner/keytypes` owns guarded-account role mapping.

### Runtime Flow

#### Unified Component-Flow Migration Contract

`/plan` is the sole canonicalizing endpoint; component and assembly endpoints
consume frozen canonical group bytes. The old bounded-specific component and
assembly routes are retired and return 404. The invariants that survive that
migration are owned by [ARCH_GUARDED.md](ARCH_GUARDED.md).

The current guarded choreography is named `cosigner1`. Signer `/keys` and
`/keytypes` inventory label guarded keys with `signing_flow: cosigner1` and
`cosigner_component_key_type`; clients route on the flow label, treat key-type
and component-key-type strings as opaque, and fail fast on flow labels they do
not implement. The `cosigner1` label is frozen: any choreography change mints a
new label, and unrelated future mechanisms get their own label family.
For cache compatibility, a client may treat a cached built-in guarded key type
that lacks `signing_flow` or cosigner metadata as stale and refresh `/keys`
before route selection; the refreshed `signing_flow` remains the routing
authority.

### Endpoint Routing

Runtime guarded and bounded-cosigner routing performs live `/keys` discovery at
the start of each signing operation and keeps an operation-scoped route
snapshot. It probes the deterministic configured endpoint order with bounded
parallelism and stops only after every required embedded public key has one
unambiguous route. Same-host deployments use an explicit loopback or SSH
endpoint for the separate cosigner process; the primary signer connection is
never reused as a cosigner route.

The signer reference catalog is a generation trust-input inventory, while
live endpoint discovery is routing only. Neither proves endpoint ownership;
the embedded public key and verified component signature remain authoritative.

### Implementation Ownership

Primary implementation ownership:

- `pkg/signerapi`: component-signing and assembly DTOs plus fixtures.
- `internal/cosigner/message`: role-separated component message construction.
- `internal/cosigner/canonical`: canonical group decoding and group hashing.
- `internal/cosigner/verify`: component signature verification primitives
  (signer-side only; client binaries must not link them).
- `internal/cosigner/keytypes`: the guarded-account key type and its mapping
  to the cosigner witness component key type; Witness Key ID derivation and
  validation live in `internal/witness`.
- `internal/signerapp/signing`: signer-side component signing, cosigner policy
  evaluation, and assembly.
- `internal/signerapp/rest`: REST service methods for component signing and
  assembly (`Service.SignComponents`, `Service.Assemble`);
  `internal/signerapp/daemon` owns the HTTP routes and handlers.
- `internal/engine/guarded`: client guarded-send orchestration, cosigner
  component-signature collection, and cosigner endpoint resolution/discovery,
  isolated from the engine facade (it depends on the engine only through a
  narrow `SignerCacheView` and injected connection/caches; `internal/engine`
  wires it and re-exports the discovery types). Its exported surface is only
  the sanctioned entry points (`New`/`Deps`/`Signer`/`SignerCacheView`,
  `HasGuardedEffectiveSigner`, `SignAndSubmitGroup`,
  `DiscoverCosignerComponentKeys`, `DiscoveredCosignerComponentKey`,
  read-only `InspectRoutes` with `RouteStatus`, `ConnectionObservation`, and
  `AccountRouteObservation` (closed probe connections, no signing) and the
  `ConnectionState*` / `AccountRoute*` names of the states it reports,
  read-only `InspectCosignerEndpoint` with `EndpointInspection` and
  `NodeRoleCosigner` (one endpoint's node role and key inventory for guided
  setup, on its own connection), `CanAuthorizeOtherAccounts` (whether an
  account's `signing_flow` can authorize another account, the routing table's
  fail-closed answer for rekey targets), and the
  `ErrCosignerDiscovery*` sentinels); the choreography internals are unexported
  and tested in-package. Import isolation is pinned by
  `test/arch/client_layering_test.go`.
- `internal/config` and `internal/endpointrefs`: endpoint registry and public
  endpoint envelope handling.
- `internal/witness`: the canonical public witness reference, which is the
  whole of the cosigner key file a cosigner exports and a signer imports.
- `internal/apadminapp`: operator-side cosigner key export/import,
  explicit-endpoint ID discovery, and bounded read-only unique-route
  verification. Discovery and verification persist neither fetched inventory
  nor a reference-to-endpoint binding.
- `internal/clientenroll`: shared client-owned enrollment request (answered at
  once as pending or already enrolled) and remote preflight used by shell and
  MCP surfaces.
- `internal/cosigner/cosignerrefs`: public cosigner reference catalog used by
  generation UIs.
- `internal/policy`: shared signer/cosigner policy grammar, validation, and
  evaluation domains.

Compatibility-bearing wire, file, endpoint, policy, backup/restore, and SDK
contracts live in their subject documents; [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md)
indexes them.

### Rotating Account Ownership

Rotating accounts are not guarded accounts; they use their own `rotating1`
signing flow. Ownership:

- `lsig/rotatinghybrid`: the Falcon-1024 + Ed25519 hybrid rotating stage
  (program, signer-side key operations, registration) over
  `internal/crypto/rotatinghybrid`, which derives the per-stage key seeds.
- `lsig/rotatingwots`: the WOTS hybrid rotating stage (program template,
  stage ops, codec and generator) over `internal/crypto/wots`.
- `internal/rotatingkey`: rotating key-type identifiers, frozen sizes and
  timing bounds; `internal/stagetable`: the stage address cache;
  `internal/signerapp/chainread`: the signer's own authorizer read for the
  `rotating1` flow.
- `internal/signerapp/rest/rotating.go`: REST service methods
  `Service.PrepareRotating` and `Service.SignRotating`;
  `internal/signerapp/daemon` owns the `/sign/rotating/*` routes.
- `internal/apshellapp/rotate.go`: the shell `rotate` workflow (rotate-only
  spend and rotating account status).

## Provider and Algorithm Model

See [ARCH_CRYPTO.md](ARCH_CRYPTO.md) for the provider and algorithm model.

Key type identifiers use the canonical form `publisher.family.vN` for APlane-defined LogicSig, template, and compiled-provider key types, and the single-segment built-ins `ed25519` and `falcon1024` for native signing keys. Native Falcon uses the `native_pq` authorization kind and top-level `SignedTxn.PQsig`; it is not part of the `aplane.falcon1024.*` LogicSig family. The full contract lives in [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md).

## Keystore and Key Lifecycle

`internal/keystore.FileKeyStore` is the concrete keystore implementation in active use.

It owns:

- product-store key directory resolution,
- keyring opening and caching,
- decrypted scan metadata cache,
- on-demand decryption for specific addresses.

The keystore compatibility model is split between:

- `.key` account-authority and `.cos` cosigner-credential envelope/payload compatibility for individual entries,
- `store-root.enc` compatibility for passphrase verification, KDF parameters, and generation selection,
  and the `.keystore` marker for the store format gate.

A scan:

- requires an open keyring,
- decrypts keys sufficiently to discover address, type, category, the
  structured LogicSig program/argument/opcode resource profile, and stored
  signing metadata,
- populates a cache of `address -> KeyScanInfo`,
- is the foundation for the signer’s runtime key indexes.

`internal/keystore.KeySession` is a thin runtime guard around a keystore. It tracks whether signing operations are permitted and delegates actual key retrieval to the keystore.

This split means:

- lifetime policy lives above raw storage,
- decryption remains on-demand,
- signer lock state is modeled as keyring availability plus session activity.

Offline mutation rules are compatibility-sensitive and are documented in [ARCH_STORE.md](ARCH_STORE.md#ownership-and-access).

## Plugin System

External plugins are separate processes discovered at runtime. `apshell` spawns them lazily and talks JSON-RPC over stdin/stdout.

Key characteristics:

- plugin processes are isolated from signer key material,
- network access is allowed because plugins often need algod, KMD, or indexer access,
- plugin manifests are mandatory,
- plugin integrity checks are mandatory.

Plugin payloads live under `$APCLIENT_DATA/plugins.available`, and
`$APCLIENT_DATA/plugins.yaml` is the activation source of truth. Manifest
schema 2.0 is command-only: commands are the sole executable and discoverable
plugin surface, while the JSON-RPC protocol remains `aplane-plugin/2`.

The plugin manager owns:

- discovery cache,
- running plugin instances,
- initialization,
- reuse between commands,
- shutdown.

Process protocol details, discovery order, method names, and manifest contract are documented in [ARCH_PLUGINS.md](ARCH_PLUGINS.md).

## JavaScript and MCP

`apshell` embeds Goja for scripting. JS bindings are defined in `internal/jsapi` and runtime orchestration in `internal/scripting`.

The scripting subsystem gives programmatic access to:

- accounts,
- assets,
- app interactions,
- transactions,
- plugin commands,
- shell-level workflow helpers.

MCP mode exposes `apshell` over stdio for LLM tooling. It is an alternate UI surface over the same business logic, not a separate backend.

Important MCP transport and structured-output contracts are documented in [ARCH_SHELL.md](ARCH_SHELL.md).

## Caching and Local State

Client-side cached storage is implemented in `internal/cache`, while caller-facing ASA metadata/ref/amount handling routes through `internal/asa`. The signer also persists signer-wide ASA metadata with `internal/cache`, but signer callers go through `internal/signerapp/asametadata.Store` because that cache is rooted under the signer data directory and is not APCLIENT_DATA state.

Caches include:

- ASA cache
- alias cache
- signer cache
- auth-address cache (`<network>_auth_cache.json`)
- set cache
- address resolver helpers
- external standalone swap-client session JSON files and tombstones under the
  shared client-data layout; their implementation is outside this repository

These caches are not interchangeable:

- signer-side ASA metadata cache depends on signer-configured algod endpoints,
  is process-wide rather than product-runtime state, and has no long-lived
  process-global in-memory map,
- signer cache depends on remote signer state; interactive and embedded
  apshell sessions poll authenticated `/status` on the configured
  `signer_status_poll_interval` (default `10s`) and refresh `/keys` when
  `keyset_revision` changes. MCP mode does not run this background
  poller; it relies on startup connection and serialized command execution
  instead. The signer cache carries the signer-advertised key type, structured
  LogicSig program/argument/opcode resource profiles, signing argument schema,
  guarded `signing_flow`, cosigner component key type, and embedded cosigner
  public key. Guarded key-type checks
  in the cache layer are compatibility freshness heuristics only; client
  signing route selection remains driven by `signing_flow`,
- auth cache depends on network state and signer/alias information,
- alias and set caches are local operator state,
- ASA cache persistence lives in `internal/cache`, but most callers should not bypass `internal/asa` for display or conversion logic.

Write-ownership model:

- disk-backed cache persistence is owned by `internal/cache`
- shared APCLIENT_DATA cache writes are serialized through the cooperative `.apclient.lock` owned by `internal/clientdata`
- apshell starts a passive best-effort cache watcher for shared APCLIENT_DATA; filesystem events only mark cache files dirty, and in-memory reloads are applied at shell/MCP command boundaries
- signer-side ASA cache reads and writes are serialized in-process by `internal/signerapp/asametadata.Store`
- `internal/clientstate` remains the higher-level mutation owner for alias/set and related client-state workflows
- `internal/refname` owns canonical validation and lowercasing for persisted alias and set names

The external standalone swap client adds a distinct form of local state to
the shared client-data layout; APlane does not implement this subsystem:

- it is per-network and per-local-actor rather than process-global,
- it is authoritative for local history display when reconciliation is unavailable,
- it is reconciled against on-chain note traffic and external swap handoff state instead of being a purely ephemeral UI cache.

Cache invalidation policy is explicit and type-specific.

## Approval Model

See [ARCH_POLICY.md](ARCH_POLICY.md) for the approval contract.

## SSH, Watching, Templates, and Audit

The SSH tunnel is implemented in `internal/sshtunnel`. It provides:

- an SSH server embedded in `apsigner` that forwards TCP connections to the local REST API,
- SSH clients in `apshell` and the external Go, Python, and
  TypeScript SDKs that establish the tunnel.

Watcher, template reload, and backup/restore contracts are documented in [ARCH_STORE.md](ARCH_STORE.md). Audit logging, client enrollment, and key revocation contracts are documented in [ARCH_SECURITY.md](ARCH_SECURITY.md).

Architecturally:

- one watcher is owned by the product runtime,
- template registration precedes key scan for generation/discovery,
- signer-data library templates are authoritative install sources when present,
  and same-`key_type` template mutation is rejected rather than applied on
  reload/unlock,
- audit logging is a signer-side operational subsystem, not a UI concern,
- client enrollment is an approval-mediated path, not just SSH auth,
- enrollment requests are persisted even without an active admin session;
  an authenticated admin approves or rejects them later, and pending requests
  are announced again when the admin authenticates,
- revoking a key closes every SSH connection that key authenticated,
- every change to the enrollment queue, the enrolled-key registry, or an
  enrolled key's connection state is announced to the connected admin session
  (`enrollment_changed`), so an admin screen showing those lists re-fetches
  them rather than polling; the SSH server reports each session's key to the
  daemon after the connection is tracked and after it is untracked.

## Backup and Restore Ownership

For backup/restore specifically, `internal/backup` owns export packaging,
archive inspection, complete credential validation, the sealed credential-only
archive manifest, canonical-plaintext collision classification, and the staged
credential apply primitive. `internal/genstore` owns the generation commit protocol: mint,
staged validation, sealing of the outgoing generation, the durable store-root
replacement, reconciliation/quarantine of ambiguous attempts, reconstruction
from authenticated history, and garbage collection of sealed priors. `internal/signerapp/backupadmin`
owns live direct restore, explicit restore rollback, and recovery-mode
reconciliation. A restore validates every selected credential before writing,
then commits them by minting one generation behind a single durable store-root
replacement. Incomplete staging is discarded; complete ambiguous publications
are quarantined by reconciliation at unlock, never resumed or adopted.
A commit with unconfirmed durability, or a rollback that fails after mutation
began, transitions the runtime into recovery mode immediately and blocks
signing until the store reconciles cleanly.
Managed archives contain complete credential authority, each key's verified
own policy document when it has one (`policies/<selector>.apb`, on both node
roles), archive integrity metadata, and source node role. They exclude the node
default policy, approval defaults, genesis-hash mappings, templates, endpoints,
and operator settings. Restore installs an archived key policy with its key; a
differing destination document for the key is a conflict requiring
`replace_existing`, and a destination document is kept when the archive carries
none. A restored key with no document follows the destination's default. The
destination's `default.json` and operational configuration remain authoritative.

`apadmin` is the sole general-purpose CLI owner of this daemon-owned lifecycle
over local IPC. Remote operators use an ordinary SSH login to run `apadmin`
on the signer host. `cmd/apstore` retains local
`initialize`, external-backup validation, `verify`, policy integrity
check/sign/verify, private-store permission migration, offline generation
pruning and key inventory, and `rebuild` replacement-keystore rescue. Managed
backup import publication and export bytes are streamed through authenticated
admin transport. Imports are capped
at 1 GiB, only one incomplete import exists for the product store, and startup removes
unpublished transfer residue. Archive chunk reads require unlocked or recovery
state but do not take the store mutation lock.
Offline rebuild is deliberately distinct: it requires an absent product store,
creates a new keyring and node-role integrity state, and commits the restored
credentials as the first generation through `genstore.Mint`; it bypasses the
live daemon, admin authorization, and durable audit path. The wire and on-disk
compatibility rules remain in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md); the key/keytype lifecycle state model
is in [ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).

## Architectural Invariants

1. Plaintext signer-managed credential authority is never returned through
   HTTP or admin transports. Store-owning local processes may decrypt it
   transiently; exported backups contain only passphrase-encrypted credential
   records.
2. Unlock state = keyring availability + active session state.
3. Engine code is independent of UI parsing/formatting. Pinned transitively by `test/arch/client_layering_test.go`: nothing in the module-internal dependency closure of `internal/engine` (and subpackages) may import UI parsing/formatting packages (`cmdspec`, `shellrepl`, `apshellcli`, `apshellapp`, `keytypefmt`, `theme`, `addressdisplay`), with no exceptions. Shared semantic grammars live in engine-layer leaves (e.g. byte-value parsing in `internal/appinput`, key-type canonicalization in `internal/keytypecatalog`) and UI packages depend downward on them.
4. Provider registration is explicit at startup via `RegisterProviders()` / `lsig.RegisterClient()` / `lsig/signerreg.RegisterSigner()`.
5. Versioned key types are stable identifiers across storage, UI, and protocol.
6. IPC messages are line-delimited JSON with typed message contracts.
7. `/sign` and `/plan` share canonical group-shaping rules.
8. Plugins are process-isolated with no direct keystore access.
9. Offline keystore mutations (`apstore`) are guarded by the store lock, not transport-specific liveness probes.
10. Durable signer state is rooted at `identities/default/`; request and
    runtime models do not expose a runtime selector.
11. Product UI/docs are single-operator and single-signing-identity.
12. Exactly one product runtime is constructed, and an extra direct entry under
    `identities/` fails startup before product-store secrets are consumed.
13. File mutations and watcher reloads share the product store mutation lock.
14. Pure shell binaries register only client-safe providers; binaries that own
    admin, store mutation, or local signer composition (`apsigner`, `apconsole`,
    `apadmin`, `apstore`) additionally register signer-side keygen, sign, and
    mnemonic capabilities through `lsig/signerreg.RegisterSigner()`,
    `internal/signing/ed25519/signerreg.RegisterSigner()`, and
    `internal/signing/falcon1024/signerreg.RegisterSigner()`.
    `cmd/apshell/deps_test.go` pins the client/signer registration boundary,
    including native Falcon signer registration and operations.
15. LogicSig key files are the signing authority: every signable LogicSig key file has versioned signing metadata (version 1 for non-bounded, version 2 for bounded). Signing and restore reject files without `signing_metadata_version` or with a metadata version/shape mismatch; templates and live providers are not consulted to reconstruct missing signing metadata.
16. Every persisted LogicSig key file has an off-curve address. Stored bytecode
    that derives an on-curve LogicSig address is rejected on load. Legacy
    empty/`manual_counter` derivations require `salt_counter`;
    `algod_v13_auto_salt` derivations must omit it and carry final TEAL v13+
    bytecode plus a valid `lsig_opcode_profile`.

## Architectural Seams

Strong existing seams:

- `internal/engine` as the client business boundary
- `internal/apshellapp` as the shell application boundary between `cmd/apshell` and `internal/engine`
- `internal/apadminapp` as the noninteractive admin application boundary
  between `cmd/apadmin` and admin transport
- `internal/clientstate` for client-side cache state and mutation ownership
- `internal/engine/connect` for remote signer connection state, lifecycle, and signer-facing request flow
- `internal/appresult` for shared structured result vocabulary and reusable
  machine projections, with command-specific safe allowlists and the final
  result boundary in `internal/apshellcli`
- `internal/config` for configuration normalization
- `internal/keystore` for storage/session separation
- `internal/protocol` for the compatibility-bearing IPC wire contract,
  envelopes, and framing primitives
- `internal/adminproto` for transport-neutral admin service requests/results
  and framed server connections; these are not the external JSON message types
- `internal/signerapp/adminserver` for server-side admin session state,
  dispatch, and handler ownership
- `internal/lsigprovider` and provider registries for algorithm extensibility
- `internal/plugin` for plugin lifecycle isolation

Weaker or more coupled areas:

- `internal/signerapp/daemon` owns the remaining operational glue, final
  transport adaptation, and startup/operator logging; `cmd/apsigner` retains
  only flag parsing, provider registration, manifest/version early exits, and
  process handoff,
- `internal/engine` separates shared infrastructure (`engine.Core`) from the
  domain command methods on `Engine`, is transitively free of UI
  parsing/formatting imports, and the guarded-signing flow lives in the
  import-isolated `internal/engine/guarded` package — all enforced by
  `test/arch`. Remaining follow-up: the client-data lock helper plus the last
  signer-cache `*Locked` split still live on the engine side rather than being
  fully owned by `internal/clientstate`,
- shell commands execute once and return one result with human and machine presentations,
- the runtime core is product-store-owned and the operator/control-plane surface
  is single-operator; the product admin workflow arrives over local IPC.

Product-level boundaries:

- one fixed product store, runtime session, approval coordinator, and
  enrolled-client registry exist, with a single-operator deployment model,
- plugin manifests expose one command-first executable contract,
- template files are product-store scoped and encrypted; `key_type` is an immutability boundary rather than an override hook,
- shell command automation is explicit per primary command, with aliases inheriting policy and no text-capture fallback.

## Key Entry Points

| Area | Files |
|------|-------|
| Server | `cmd/apsigner/main.go`, `internal/signerapp/daemon/server.go`, `internal/signerapp/startup/*.go` |
| Client | `cmd/apshell/main.go`, `internal/apshellcli/registry.go`, `internal/apshellcli/mcp.go`, `internal/apshellcli/status_poll.go`, `internal/shellrepl/*.go` |
| Client Enrollment / Remote Preflight | `internal/clientenroll/preflight.go`, `internal/clientenroll/enrollment_request.go` |
| Shell App | `internal/apshellapp/app.go`, `internal/apshellapp/runtime.go`, `internal/apshellapp/connect.go` |
| Admin Client App | `cmd/apadmin/main.go`, `cmd/apadmin/admin_batch.go`, `internal/apadminapp/catalog.go`, `internal/apadminapp/session.go`, `internal/apadminapp/clients.go`, `internal/apadminapp/store.go` |
| Server Client Enrollment | `internal/signerapp/enrollment/service.go`, `internal/signerapp/enrollqueue/queue.go`, `internal/signerapp/enrollqueue/store.go`, `internal/signerapp/clientregistry/registry.go`, `internal/signerapp/clientregistry/store.go`, `internal/signerapp/daemon/enrollment_service.go`, `internal/signerapp/productruntime/runtime.go` |
| Engine | `internal/engine/engine.go`, `internal/engine/core.go`, `internal/engine/consensus.go`, `internal/engine/status_sync.go`, `internal/engine/connect/state.go`, `internal/engine/guarded/submit.go` |
| Signing | `internal/signerapp/signing/service.go`, `internal/signerapp/signing/planner.go`, `internal/signerapp/signing/planner_runtime.go`, `internal/signerapp/signing/execution.go`, `internal/signerapp/signing/approval.go` |
| Native Signature Providers | `internal/signing/ed25519`, `internal/signing/falcon1024/address.go`, `internal/signing/falcon1024/register.go`, `internal/signing/falcon1024/signerreg/*.go`, `internal/signing/falcon1024/signerops/*.go`, `internal/falconparams/params.go` |
| Key Admin | `internal/signerapp/keyadmin/service.go`, `internal/signerapp/keyadmin/admin_ops.go`, `internal/signerapp/keyadmin/generic_lsig.go` |
| KeyType Library | `internal/signerapp/templateadmin/service.go`, `internal/templatelibrary/library.go`, `internal/templatestore/store.go`, `internal/keytypestate/state.go`, `internal/storepaths/paths.go`, `internal/signerapp/daemon/admin_services.go` |
| Store/Backup Admin | `internal/signerapp/storeadmin/service.go`, `internal/signerapp/backupadmin/*.go`, `internal/backup/*.go` |
| Store Ownership / Permissions | `internal/storeperm/*.go`, `internal/fsutil/perms.go`, `internal/fsutil/durable.go`, `internal/adminipc/path.go`, `cmd/apstore/permissions.go`, `docs/ARCH_STORE.md` |
| Store Integration Harness | `test/storeintegration/*.go`, `internal/storepass/capacity_test.go`, `internal/testcheckpoint/*.go`, `Makefile` (`store-lifecycle-test`, `store-capacity-test`, `store-crash-test`, `store-release-drill`) |
| LSig Providers / Resource Planning | `lsig/all.go`, `lsig/signerreg/register.go`, `internal/lsigresource/consensus.go`, `internal/lsigresource/solver.go`, `internal/signerapp/signing/planner_runtime.go`, `internal/signerapp/signing/native_pq_fee.go`, `internal/signing/dummy_transactions.go`, `internal/lsigprovider/provider.go`, `internal/signingargs/types.go`, `internal/lsigsalt/salt.go`, `lsig/falcon1024/v1/standard.go`, `lsig/falcon1024_guarded/provider.go`, `lsig/falcon1024_guarded/register.go`, `lsig/ed25519lsig/register.go`, `lsig/ed25519lsig/signerreg/register.go`, `lsig/falcon1024/signerops/ops.go`, `lsig/dsafamily/register.go`, `lsig/generictemplate/provider.go`, `lsig/composeddsa/composer.go`, `lsig/composeddsa/layer3.go`, `library/templates/aplane.corridor.v1.yaml`, `internal/boundedadmin/message/message.go`, `internal/boundedmeta/metadata.go`, `internal/merkleallowlist/allowlist.go`, `internal/tealtemplate/legacy_list.go`, `internal/tealtemplate/template.go` |
| Protocol | `internal/protocol/messages.go`, `internal/signerapp/svcerr/svcerr.go`, `internal/signerapp/adminserver/dispatch.go`, `internal/signerapp/adminserver/displacement.go`, `internal/adminproto/stream_conn.go` |
| Config | `internal/config/config.go`, `internal/serverconfig/serverconfig.go`, `internal/config/networkid.go`, `internal/config/genesishash.go` |
| LocalNet Setup | `cmd/aplocalnet/main.go`, `internal/aplocalnet/setup.go`, `plugins/algokit-localnet/algokit-localnet.go`, `plugins/algokit-localnet/manifest.json` |
| Policy | `internal/policy/doc_v1.go`, `internal/policy/doc_v1_compile.go`, `internal/policy/jsontree.go`, `internal/policy/store_v1.go`, `internal/policy/integrity.go`, `pkg/policyschema/policy.v1.schema.json`, `internal/signerapp/policyapply/apply.go`, `internal/integritysidecar/sidecar.go`, `internal/crypto/policy_integrity.go`, `internal/signerapp/policyruntime/policy.go`, `internal/policy/lint.go`, `internal/policy/review.go`, `internal/signerapp/signing/always_review.go`, `internal/signerapp/signing/service.go`, `internal/signerapp/admin/service.go`, `internal/signerapp/admin/policy.go`, `internal/signerapp/signing/cosigner_policy.go`, `cmd/apstore/policy.go`, `internal/templatepolicy/outcome.go` |
| Keys (payload codec) | `internal/keys/payload_codec.go`, `internal/keys/save.go`, `internal/keys/keys.go`, `internal/keys/file_types.go` |
| Keystore | `internal/keystore/file.go`, `internal/keystore/session.go` |
| Node Role / Key Class | `internal/noderole/role.go`, `internal/noderole/integrity.go`, `internal/integritysidecar/sidecar.go`, `internal/keyclass/keyclass.go`, `internal/cosigner/keytypes/keytypes.go` |
| Store Init/Passphrase | `internal/storeinit/initialize.go`, `internal/defaultkeytypes/defaults.go`, `internal/storepass/rotate.go`, `internal/signerapp/unlockconfig/unlock.go`, `cmd/apstore/main.go`, `internal/signerapp/daemon/admin_services.go` |
| Generation Storage | `internal/genstore/*.go`, `internal/storepaths/generations.go`, `internal/storepaths/active.go`, `cmd/apstore/generations.go`, `docs/ARCH_STORE.md` |
| Client Data | `internal/clientdata/lock.go`, `internal/clientstate/state.go`, `internal/refname/refname.go` |
| Product Runtime | `internal/signerapp/productruntime/runtime.go`, `internal/signerapp/productruntime/config.go` |
| Release/Distribution | `Makefile`, `.github/workflows/release.yml`, `docs/RELEASE_NOTES.md`, `scripts/package-bootstrap-release.sh`, `scripts/build-algokit-localnet-plugin-target.sh`, `scripts/stage-bundled-plugins.sh`, `scripts/docker-systemd-smoke.sh`, `scripts/docker-local-four-node-smoke.sh`, `plugins/algokit-localnet/`, `bootstrap-install.sh`, `install.sh`, `uninstall.sh`, `installer/`, `library/templates/` |

## Testing and Verification Model

The repo uses:

- package-level unit tests beside source,
- integration tests in `test/integration`,
- architecture guard tests in `test/arch`: `layering_test.go` pins shared/signer
  dependency direction and family-agnostic core-package imports;
  `client_layering_test.go` keeps the client engine core free of UI
  parsing/formatting imports and isolates the guarded package;
  `guarded_surface_test.go` pins the guarded package's sanctioned exported API;
  `signingflow_test.go` pins guarded client routing on runtime `signing_flow`
  metadata; `bounded_vocabulary_test.go` pins bounded naming boundaries;
  `keytype_inventory_test.go` pins the bundled key-type inventory;
  `managed_credential_files_test.go` pins managed credential extension
  ownership; `witness_boundary_test.go` pins witness custody and signing
  boundaries; `generation_storage_test.go` pins the no-hardlink rule,
  store-owning package inventory, removal of retired root store paths and commit
  artifacts, confinement of direct generation writers, and the prohibition on
  installer-owned root-level policy setup from ARCH_STORE;
  `store_permissions_test.go` pins the audited shared-mode allowlist and keeps
  legacy group-bearing modes out of signer-store writers;
  `kdf_confinement_test.go` pins key-derivation, raw-term-key, test-fixture,
  and historical-term boundaries; `product_mode_boundary_test.go` pins the
  one-runtime ownership graph and absence of selectors;
  `admin_binary_boundary_test.go` and
  `policy_command_subtraction_test.go` keep live administration and policy
  ownership in `apadmin` rather than regrowing retired command surfaces;
  `admin_protocol_boundary_test.go` pins wire/domain/transport
  dependency direction; `cosigner_catalog_test.go` separates signer-owned
  generation references from client routing discovery;
  `template_mutation_boundary_test.go` makes `templatelibrary` the sole
  feature-level template/key-type mutation owner;
  `shell_result_boundary_test.go` pins command-only plugin metadata, the shared
  human/machine result path, and process-local output;
  `admin_client_state_boundary_test.go` keeps admin clients independent of
  transaction-client state and transport;
  `product_store_locator_test.go` prevents store selectors and runtime IDs
  from returning to the fixed product-store APIs;
  `candidate_validation_test.go` confines generation validation opt-outs to
  test code; `shell_endpoint_state_test.go` keeps shell configuration and
  endpoint resolution in `internal/apshellapp`; and
  `formal_traceability_test.go` pins live cosigner-routing traceability anchors,
- the opt-in store harnesses, invoked through `make store-lifecycle-test`,
  `make store-crash-test`, and `make store-capacity-test`, create genuine
  blank signer roots without algod or the shared integration fixture;
  `internal/testcheckpoint` provides `storetest`-only semantic checkpoints and
  compiles to no-op behavior in production builds, while the capacity gate
  exercises the exact deleted-archive warning threshold and records its copy,
  re-encryption, seal, and retained-disk costs,
- analysis tools for security properties,
- signer API and SDK contract tests backed by JSON fixtures in `test/contracts/signerapi/`.
  These fixtures pin SDK-exposed HTTP DTOs. SDK package tests are owned by the external
  `aplane-algo/aplanesdk` repository; that repository also owns cross-language
  prepared-request parity fixtures for the SDK prep layer. `/status` is
  SDK-facing because clients use `keyset_revision` for refresh decisions and
  `approval_wait_seconds` for sizing `/sign` deadlines.
- `make contract-sync-check APLANESDK_DIR=/path/to/aplanesdk` compares the
  committed `test/contracts/signerapi/` fixture tree with the external SDK
  repository. Run it when changing shared signer HTTP fixtures; ordinary CI
  runs `make contract-test` but does not check out the SDK repository for this
  comparison.
- machine-checkable TLA+ models under `docs/formal/`, run locally with
  `make formal-test` and in CI by the Formal Models job. The authoritative
  `(spec, cfg)` run list and expected outcomes/metrics live in
  `docs/formal/metrics.json`. It covers `sign_boundary`,
  `policy_precedence`, `composition`, `approval_coordinator`,
  `approval_composition`, `session_ownership`,
  `guarded_assembly`, `bounded_cosigner`, `plugin_signing`,
  `store_root_commit`, `enrollment_queue`, and `recovery_binding`, plus
  liveness configurations for `approval_coordinator` and expected-failure
  negative controls (outgoing-seal pinning for `store_root_commit`, durable
  acknowledgement for `enrollment_queue`, pre-fix recovery binding for
  `recovery_binding`).
  `make formal-test-deep` uses `docs/formal/metrics_deep.json` for larger
  pre-release or scheduled bounds. Both targets run
  `formal-copy-sync-check` first and require `tla2tools.jar` through
  `TLA2TOOLS_JAR` or one of the Makefile's default jar search paths.

`make integrity-check` is the broad verification target. It chains formatting,
vet, module-tidy, lint/dead-code/security checks, race tests, blank-store
lifecycle and deterministic crash tests, cross-builds, smoke tests, contract
tests, integration tests, and a clean-tree check.
Formal model checking remains a separate `make formal-test`/CI job and is not
part of `integrity-check`.

`make store-release-drill` runs the same release-critical initialize,
generate, sign, backup, fresh restore, rotation, restart, and re-sign workflow
against explicitly staged production `apsigner`, `apstore`, and `apadmin`
binaries. The release workflow runs it against the staged amd64 artifacts;
unlike the crash harness, it does not use `storetest` checkpoints.

Docker-backed install and topology smoke targets are separate release workflow
guards:

- `make docker-systemd-test` runs `scripts/docker-systemd-smoke.sh` against a
  fresh Ubuntu systemd container and verifies systemd install/uninstall state.
- `make docker-local-test` runs `scripts/docker-local-four-node-smoke.sh`
  against signer, cosigner, client/admin, and LocalNet algod containers on one
  Docker network. It verifies local install layout, shared LocalNet
  reachability, SSH client enrollment, local IPC `apadmin` cosigner
  public-reference export and authorized import, client signer
  reachability, guarded signing, and corridor allowlist enforcement across the
  Docker network.
- `make docker-local-release-test` runs the same topology and assertions using
  published GitHub APlane release assets plus the PyPI and npm SDK packages.

Additional opt-in verification targets include `make soak-test-localnet` for
long-running LocalNet transaction coverage and
`make apshell-command-coverage-localnet` for broad shell-command coverage.

The integration harness behavior is part of the effective repository contract:

- `make integration-test` requires an explicit TestNet or LocalNet
  profile and fails closed when the profile is absent or invalid;
  `make integration-test-testnet` and `make integration-test-localnet` are the
  convenience targets,
- `TEST_FUNDING_MNEMONIC` has one authorization meaning on every integration
  network: it is a protocol-native Falcon-1024 recovery mnemonic; the harness
  adds the native-PQ fee contribution before group IDs and emits structured
  `PQsig` envelopes for direct fixture transactions,
- LocalNet setup uses a KMD Ed25519 account only as a bootstrap source for a
  disposable funded native Falcon account; TestNet uses an operator-supplied
  funded native Falcon account and therefore requires a v42-capable network,
- `make integration-test` regenerates the shared test fixture and `.env.test` before running the suite,
- the shared fixture lives under `/tmp/aplane-test-env`,
- the generated signer fixture uses a private runtime directory with `ipc_path: run/aplane.sock`,
- `TEST_PASSPHRASE` for integration tests is taken from the generated fixture passphrase rather than trusting an inherited shell value,
- when `APLANE_SDKS_REPO` points at a local `aplanesdk` checkout, `make integration-test` and
  `make integration-test-reuse` run the external SDK live signer integration suites through
  `test/run-sdk-integration.sh`; when unset, the SDK bridge is skipped, and when set to
  a non-directory path, the make target fails before running SDK tests.

The codebase is verified with tests around:

- transaction planning/signing parity,
- keystore unlock and key scanning,
- key import and encrypted backup/restore behavior,
- key derivation regression stability, including known-answer address fixtures
  in `test/integration/key_derivation_regression_test.go`,
- IPC protocol behavior,
- plugin manifest and protocol handling,
- cache resolution,
- provider registration,
- engine transaction operations.

Verification expectations remain:

- unit tests for touched core packages pass,
- `test/arch` remains current when changing package layering, provider
  registration boundaries, or guarded signing route-selection metadata,
- contract fixtures and per-SDK contract tests pass when signer API shapes change,
- `make formal-test` passes when formalized behavior or `docs/formal/` modules change,
- external SDK fixtures and timeout behavior are reviewed when `/status`,
  `/sign`, or approval-wait contracts change,
- integration tests covering signer, app, passthrough, Falcon, and SSH client enrollment pass,
- external SDK tests pass when the touched surface includes SDK-facing behavior,
- signing outputs for unchanged inputs remain stable,
- IPC notifications and request/response message shapes remain compatible with `apadmin` and `apapprover`,
- client enrollment and revocation remain compatible with the SSH client flow,
- plugin discovery precedence and manifest validation remain unchanged unless explicitly versioned,
- on-disk compatibility is checked for `store-root.enc`, `.keystore`, `.key`, `.cos`, `.template`, `config.yaml`, `audit.log`, the enrolled-client registry, and the pending enrollment queue.
- client endpoint compatibility is checked for `endpoints.yaml`,
  endpoint handoff envelopes, and public cosigner
  reference records when those surfaces change.

## Adding New Features

| To Add | Layer | Documentation |
|--------|-------|---------------|
| New command | UI | ARCH_SHELL.md (REPL/CLI and MCP) |
| New shell workflow | Shell App | This document and ARCH_SHELL.md |
| Reusable transaction/client mechanic | Engine | ARCH_SHELL.md |
| New key type or algorithm | Provider | DEV_KEYTYPES.md, ARCH_KEYTYPES.md, and ARCH_CRYPTO.md |
| New KeyType Library template | Provider / Template Library | DEV_KEYTYPES.md |
| New config option | Config | USER_CONFIG.md |

## Related Documentation

- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) - compatibility-bearing contracts
- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md) - durable, runtime, and wire data model
- [ARCH_STORE.md](ARCH_STORE.md) - signer store layout, generations, keys and key types, backup and restore
- [ARCH_SECURITY.md](ARCH_SECURITY.md) - authentication, authorization, enrollment, and audit
- [ARCH_POLICY.md](ARCH_POLICY.md) - signer and cosigner policy model and document format
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md) - network context tokens and genesis-hash mapping
- [ARCH_SHELL.md](ARCH_SHELL.md) - apshell engine, REPL, app interaction, and MCP surface
- [ARCH_ADMIN.md](ARCH_ADMIN.md) - admin protocol and signer admin TUI (apadmin)
- [ARCH_SIGNING.md](ARCH_SIGNING.md) - transaction signing flow and HTTP API
- [ARCH_GUARDED.md](ARCH_GUARDED.md) - guarded signing, cosigner nodes, and Corridor v1
- [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) - Bounded DSA contracts, effect model, and external contract-admin ceremonies
- [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md) - key type axes and LogicSig providers
- [ARCH_CRYPTO.md](ARCH_CRYPTO.md) - Provider layer details (DSA algorithms)
- [ARCH_PLUGINS.md](ARCH_PLUGINS.md) - plugin system
- [DEV_KEYTYPES.md](DEV_KEYTYPES.md) - key type and LogicSig template development guide
- [USER_KEYTYPES.md](USER_KEYTYPES.md) - key type and template management guide
- [USER_CONFIG.md](USER_CONFIG.md) - Configuration reference
- [README.md](../README.md) - User-facing documentation
