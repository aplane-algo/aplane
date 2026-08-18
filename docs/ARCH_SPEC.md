# Engineering Specification

> Orientation map for engineers working on the APlane repository.
> For compatibility contracts (wire formats, on-disk formats, error mappings, and behavioral guarantees), see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the system-wide durable/runtime/wire data model, see [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md).
> For key and key type state machines, see [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
> For the product authorization model — the reserved admin principal and the explicit allowed-action list — see [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).
> For the current signer policy verdict model, see [ARCH_POLICY.md](ARCH_POLICY.md).
> For network context tokens and transaction genesis-hash mapping, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
> For guarded signing and sentry node architecture, see [ARCH_SENTRY.md](ARCH_SENTRY.md).
> For bounded authorization contracts and external contract-admin custody, see [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).
> For the canonical Corridor v1 bounded-sentry profile, see [ARCH_CORRIDOR.md](ARCH_CORRIDOR.md).
> For signer-store process ownership, filesystem permissions, and the
> single-writer migration, see [ARCH_STORE_OWNERSHIP.md](ARCH_STORE_OWNERSHIP.md).

## Table of Contents

- [Purpose](#purpose)
- [How To Use These Docs](#how-to-use-these-docs)
- [System](#system)
- [Binaries](#binaries)
- [Architecture Layers](#architecture-layers)
- [Deployment Model](#deployment-model)
- [Runtime Configuration Model](#runtime-configuration-model)
- [On-Disk Data Model](#on-disk-data-model)
- [Security Model](#security-model)
- [Server Ownership Model](#server-ownership-model)
- [Client Ownership Model](#client-ownership-model)
- [Transaction Processing](#transaction-processing)
- [Bounded Authorization Contracts](#bounded-authorization-contracts)
- [Guarded Signing And Sentry Nodes](#guarded-signing-and-sentry-nodes)
- [Provider and Algorithm Model](#provider-and-algorithm-model)
- [Keystore and Key Lifecycle](#keystore-and-key-lifecycle)
- [Plugin System](#plugin-system)
- [JavaScript and MCP](#javascript-and-mcp)
- [Caching and Local State](#caching-and-local-state)
- [Testing and Verification Model](#testing-and-verification-model)
- [Authentication](#authentication)
- [Approval Model](#approval-model)
- [SSH, Watching, Templates, and Audit](#ssh-watching-templates-and-audit)
- [Architectural Invariants](#architectural-invariants)
- [Architectural Seams](#architectural-seams)
- [Key Entry Points](#key-entry-points)
- [Backup and Restore Ownership](#backup-and-restore-ownership)

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

Read [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md) before changing key file
schemas, key type state, template install/enable/disable/remove behavior,
LogicSig signing metadata, or backup/restore rules for keys and key types.

Read [ARCH_STORE_OWNERSHIP.md](ARCH_STORE_OWNERSHIP.md) before changing signer
data permissions, IPC placement, direct local-client store access, durable
writes, or offline maintenance execution modes.

Read [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) before changing
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

Read [ARCH_APP_INTERACTION.md](ARCH_APP_INTERACTION.md) before changing app
read/call/deploy behavior, ABI handling, `PreparedGroup`, or signer approval
metadata for app calls.

Read [ARCH_SENTRY.md](ARCH_SENTRY.md) before changing sentry node behavior,
guarded account generation, sentry keys, guarded transaction
orchestration, endpoint-discovered sentries, or `/sign/component` /
`/sign/assemble` behavior.

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

Identity model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model).

## Binaries

All under `cmd/`:

| Binary | Role |
|--------|------|
| `apshell` | Client shell: REPL, script runner, JS runtime (Goja), MCP server, plugin host |
| `aprekey` | Dedicated client for generating, inspecting, verifying, and using external Falcon bounded contract-admin credentials; `rekey`/`unrekey` own online orchestration and `prepare-*`/`sign`/`complete` own separated ceremonies |
| `apsigner` | Signing daemon: HTTP API, admin protocol over IPC and SSH subsystem, key management, approval coordination, SSH tunnel server, audit logging |
| `apadmin` | TUI and batch admin client over IPC or SSH; owns all general live administration, including policy, backup/restore, passphrase rotation, templates, key types, sentry references, endpoint export, and generation inventory, plus explicit offline policy rescue |
| `apconsole` | Secure-machine console wrapper that hosts operator panes while preserving apshell/apadmin/apsigner interfaces |
| `apapprover` | Minimal approval-only CLI over IPC |
| `apstore` | Stopped-daemon store tool: local `initialize`, policy integrity check/verify/sign, external-file-only `verify`, `rebuild`, offline generation pruning, private-store permission audit/migration, and offline key inventory; it has no live admin transport |
| `appass` | Passphrase auto-unlock setup TUI |
| `aplocalnet` | LocalNet setup TUI/CLI for algod reachability, client (`apshell`) default-network config, signer genesis config, bundled plugin activation, and KMD plugin-env persistence |
| `compile_teal` | Dev/build helper that compiles TEAL source to generated Go bytecode via algod |
| `configdoc` | Config documentation generator |
| `appass-file` | Dev passphrase helper |
| `appass-systemd-creds` | Production passphrase helper |
| `approbe` | Installer/helper liveness probe and canonical signer IPC-path resolver |
| `applugin-checksum` | Plugin integrity helper |

Documentation notes:

- `appass` owns passphrase setup and `apapprover` is the separate approval-only CLI.
- the repository uses `docs/`; `doc/` does not exist.

## Architecture Layers

| Layer | Packages |
|-------|----------|
| UI | `cmd/apshell`, `cmd/apconsole`, `internal/apshellcli`, `internal/shellrepl`, `internal/signerapp/signertui`, `cmd/apadmin`, `cmd/appass`, `internal/signerapp/policytui`, `internal/policyview`, `cmd/aplocalnet`, `internal/aplocalnet`, `cmd/apapprover`, `internal/command`, `internal/cmdspec`, `internal/cmdlog`, `internal/theme`, `internal/addressdisplay`, `internal/keytypeux` |
| Engine | `internal/apshellapp`, `internal/apboundedadminapp`, `internal/engine`, `internal/clientstate`, `internal/cache`, `internal/config`, `internal/engine/connect`, `internal/engine/guarded`, `internal/clientsign`, `internal/appresult`, `internal/appinput`, `internal/appspec`, `internal/asa`, `internal/addressbook`, `internal/refname`, `internal/keymgmt`, `internal/partkeyparse`, `internal/txnutil`, `internal/algo` |
| Signer App | `internal/bootstrap/signer`, `internal/signerapp/daemon`, `internal/signerapp/startup`, `internal/signerapp/runtime`, `internal/signerapp/identity`, `internal/signerapp/unlockconfig`, `internal/signerapp/signing`, `internal/signerapp/approval`, `internal/signerapp/templates`, `internal/signerapp/templateadmin`, `internal/signerapp/keyadmin`, `internal/signerapp/storeadmin`, `internal/signerapp/backupadmin`, `internal/signerapp/rest`, `internal/signerapp/admin`, `internal/signerapp/adminserver`, `internal/signerapp/svcerr`, `internal/signerapp/sshprovision`, `internal/signerapp/asametadata`, `internal/signerapp/audit`, `internal/signerapp/filewatcher`, `internal/signerapp/ipcbind`, `internal/signerapp/txdesc`, `internal/signerapp/policycmd`, `internal/signerapp/policyeditor`, `internal/signerapp/policyruntime`, `internal/noderole`, `internal/policy`, `internal/signerapp/approvalpolicy` |
| Provider | `internal/signing`, `internal/signing/falcon1024`, `internal/falconparams`, `internal/lsigresource`, `lsig/`, `internal/sentry`, `internal/boundedadmin`, `internal/boundedmeta`, `internal/txeffects`, `internal/keyclass`, `internal/lsigprovider`, `internal/signingargs`, `internal/logicsigdsa`, `internal/genericlsig`, `internal/lsigsalt`, `internal/tealtemplate`, `internal/addressderive`, `internal/keytypecatalog`, `internal/keytypestate`, `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Storage/Crypto | `internal/crypto`, `internal/witness`, `internal/witness/artifact`, `internal/merkleallowlist`, `internal/keys`, `internal/keystore`, `internal/storepaths`, `internal/genstore`, `internal/rotationinventory`, `internal/storelock`, `internal/signerapp/storemut`, `internal/storeinit`, `internal/storepass`, `internal/serverconfig`, `internal/defaultkeytypes`, `internal/clientdata`, `internal/templatestore`, `internal/templatelibrary`, `internal/templatepolicy`, `internal/backup`, `internal/security`, `internal/fsutil` |
| Integration | `internal/bootstrap/shell`, `internal/auth`, `internal/authz`, `internal/protocol`, `internal/adminproto`, `internal/transport`, `internal/sshtunnel`, `internal/clientenroll`, `internal/endpointrefs`, `internal/plugin`, `internal/scripting`, `internal/jsapi`, `pkg/signerapi`, `internal/signerapi`, `internal/signerclient`, `internal/tokenfile`, `internal/checksum`, `internal/manifest` |
| Tooling | `analysis/`, `test/arch`, `test/contracts`, `test/fixtures`, `test/integration`, `test/storeintegration`, `test/registry`, `test/soak`, `internal/testcheckpoint`, `internal/docassets`, `internal/xregistry`, `internal/signerprobe`, `internal/version` |

This table is an orientation map rather than an ownership API. Small support
packages are listed under the closest layer that depends on them.

### UI Layer

The UI layer is split between thin binary adapters and reusable shell/admin UI packages:

- `cmd/apshell`: thin binary adapter and composition entry point for flags, provider registration, bootstrap, and mode selection
- `internal/apshellcli`: REPL/session mechanics, command registry, scripting mode adapters, MCP surface, plugin argument normalization, and shell rendering
- `cmd/apconsole`: secure-machine Bubble Tea wrapper for shell/admin/daemon panes, with local sentry nodes using admin plus daemon panes only
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
planning and executable workflows refresh the v42/`fnet5` check before asking
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
- generation mint/seal/`CURRENT` commit/reconcile: `internal/genstore`

### Storage, Key, And Template Package Clusters

Several package families have similar prefixes because they split compatibility-sensitive
state by responsibility rather than by a single "keystore" package. This is intentional;
do not consolidate these packages just to reduce the directory count. Use this map when
deciding where a change belongs:

| Cluster | Package | Role |
|---------|---------|------|
| `store*` | `internal/storepaths` | Canonical signer/client path construction for data directories, identities, keys, templates, config, and library locations. |
| `store*` | `internal/genstore` | Generation mint/seal/`CURRENT` flip, reconciliation of uncommitted attempts, sealed-prior validation, garbage collection, and inventory hashing for the active `keys/` + `keytypes/` namespaces (see [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md)). |
| `store*` | `internal/storelock` | Cooperative filesystem lock acquisition for signer-store mutation safety. |
| `store*` | `internal/signerapp/storemut` | Higher-level store mutation coordination around operations that rewrite identity/store files. |
| `store*` | `internal/storeinit` | Store initialization and bootstrap creation logic. |
| `store*` | `internal/storepass` | Passphrase-helper and passphrase-change support around store state. |
| `key*` | `internal/keys` | Encrypted key file payload/envelope IO, scanning, metadata, and key-file compatibility behavior. |
| `key*` | `internal/keystore` | File-backed keystore abstraction, keyring/session handling, and encrypted key persistence. |
| `key*` | `internal/keygen` | Signer-side key generation registry and generation result model. |
| `key*` | `internal/keymgmt` | Client/shell-facing key management request/result helpers. |
| `key*` | `internal/signingargs` | Shared internal model for signing-time LogicSig argument metadata projected into key files, signer cache records, and wire DTOs. |
| `key*` | `internal/keytypestate` | Identity-local key type state record format and primitive read/write/delete operations for installed/disabled/activated template or provider definitions. |
| `key*` | `internal/keytypecatalog` | Key type catalog metadata assembled from registered providers and template records. |
| `key*` | `internal/keytypefmt` | Presentation-only key type formatting and publisher extraction. |
| `template*` | `internal/templatelibrary` | Plaintext signer-data template parsing and sole feature-level coordinator for template files and key-type state mutation. |
| `template*` | `internal/templatestore` | Encrypted identity-local `.template` format and primitive save, load, scan, remove, and archive operations. |
| `template*` | `internal/templatepolicy` | Template registration outcome vocabulary and reload/report policy helpers. |
| `signerapp/templates` | `internal/signerapp/templates` | Read-only runtime reload coordinator that walks installed identity templates and registers provider implementations. |
| `signerapp/templateadmin` | `internal/signerapp/templateadmin` | Live admin/use-case owner for identity locking, library mutation, runtime reload/acceptance, results, and logging. |
| `defaultkeytypes` | `internal/defaultkeytypes` | Bootstrap use-case owner that installs defaults through `templatelibrary` into an unpublished staged generation. |

Rule of thumb:

- path/layout questions belong in `storepaths`, not in individual feature packages,
- generation commit, reconciliation, and `CURRENT` resolution belong in `internal/genstore`; feature packages resolve the active namespaces through it rather than composing generation paths themselves,
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
- IPC/SSH admin wire protocol and envelope definitions: `internal/protocol`
- transport-neutral admin request/result types and framed `AdminConn`:
  `internal/adminproto`
- server-side admin session lifecycle, dispatch, and handlers:
  `internal/signerapp/adminserver`
- admin client transport, dispatcher, and stream wrappers: `internal/transport`
- SSH tunnel server/client: `internal/sshtunnel`
- plugin discovery, manifest, integrity, sandbox, JSON-RPC: `internal/plugin`
- JavaScript runtime and bindings: `internal/scripting` and `internal/jsapi`

Admin transport model:

- the IPC and SSH admin channels share the same line-delimited JSON admin protocol,
- every admin message carries an explicit envelope `kind` (`request`, `response`, `notification`),
- `internal/transport` owns one dispatcher-backed reader per post-auth connection,
- request/response correlation is by request `id`,
- transport lifecycle is separate from application semantics such as displacement,
- displacement handling remains in client layers like the `apadmin` TUI.

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
SDK repo consumes for compatibility testing. `internal/signerapi` is an
in-repo alias layer over the public DTO types in `pkg/signerapi` (not error
codes); `pkg/signerapi/error_codes.go` remains the sole error-code source.
The SDK shape is native-client first: `SignerClient` wrappers expose APlane's
HTTP signing, planning, inventory, status, and cancellation APIs
directly, and the SDK-native prep layer mirrors apshell's core client-side
transaction preparation once a caller has a normalized typed intent. That prep
layer builds unsigned transaction candidates, resolves effective signer
metadata, attaches LogicSig runtime args and app-call display metadata, and
preserves apshell-equivalent group ordering without copying apshell's UI
grammar.
Language-specific integrations such as the TypeScript and Python AlgoKit Utils
adapters compose that native client rather than becoming separate signer
transports. Those adapters are intentionally thin transaction-signer projections:
they sign already-shaped AlgoKit transaction indexes through raw `/sign` and do
not perform APlane typed prep themselves.
For ordinary APlane-managed signing, final group IDs, fee pooling, dummy
insertion, policy, approval, and signing remain apsigner authority. Guarded
prepared signing is the deliberate exception at the client-prep boundary:
because component signatures require frozen canonical bytes, SDKs follow the
same guarded client flow as apshell by classifying guarded targets, preparing
guarded dummy/passthrough context locally when required, then using
`/sign/component` and `/sign/assemble` for signer-owned component signing and
final assembly.
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
- Zero or one product-mode `apadmin`/`apapprover` admin workflow for the exposed product identity, connected over local IPC or the SSH admin subsystem. Remote `apadmin` requires a pre-enrolled default signer endpoint, its token, and trusted `known_hosts`; enrollment and first-use host trust happen through standalone `apshell`.
- One or more `apshell` clients, local or via SSH tunnel. Interactive `apshell` is both the normal client shell and the enrollment/recovery surface: it may start before client enrollment is complete. Startup requires client config/bootstrap inputs, but not a pre-existing `aplane.token` or trusted signer host. Token presence and SSH host trust are enforced when interactive `apshell` attempts a signer connection or token provisioning flow, not before process startup. After successful enrollment of the default signer, `apshell` immediately attempts to connect using the newly issued token; sentry enrollment does not replace the primary connection. Token files are bearer credentials and are rejected if group/world accessible.
- `apshell --mcp` is a separate operational surface, not an enrollment or inspection surface. MCP startup is non-interactive and refuses to start unless the client is already enrolled (default signer endpoint, endpoint token, trusted endpoint `known_hosts`) and the startup signer connection succeeds. First-time enrollment and trust bootstrap happen through interactive `apshell`, not MCP.
- Optional `apconsole` wrapper on the secure signer machine, preserving the same apshell/apadmin/apsigner transport interfaces while composing operator panes. `apconsole` can load `apconsole.yaml` from the install root to determine local versus remote console mode and the client/signer data paths. Startup resolution is deterministic per field: flags win over environment variables, environment variables win over an explicitly selected profile, and an explicitly selected profile wins over auto-discovery. If explicit sources disagree, `apconsole` exits instead of guessing. In local signer mode, `apconsole` may start before client enrollment is complete because it owns or attaches the local signer/admin surfaces needed for first-time `request-token` approval; when the client SSH host is loopback, it probes the live loopback SSH endpoint before pinning the local signer's configured SSH host key into the client `known_hosts` file, and a mismatch aborts startup. Token presence is enforced when the embedded shell attempts `request-token`, `connect`, or startup auto-connect. In local sentry mode, `apconsole` does not create an embedded shell pane; it renders the signer admin pane above the daemon/status pane. In remote mode, `apconsole` preflights the client data directory and requires a default signer endpoint, its token, and a trusted signer host in the endpoint's `known_hosts` before the UI starts. In local mode it attaches to an existing IPC socket or starts `apsigner -d <signer-data>` as a child it owns; the daemon pane reports disabled/attached/starting/ready/failed/exited status and streams owned-daemon logs. When present, the shell pane uses `internal/apshellcli.Session`, preserving apshell command behavior; Ctrl+C cancels a running shell command when the shell pane is focused, and shell `quit`/`exit` closes only that embedded shell pane. Operator controls are root-level function-key pane focus, F4 zoom, Shift+Left/Right pane navigation, and `?`/F5 help overlay.
- Optional plugin child processes spawned by `apshell`

Trust boundaries:

- apshell↔apsigner
- admin protocol over IPC or SSH admin subsystem ↔ apsigner
- apshell↔plugins
- encrypted disk↔unlocked memory
- operator Unix group↔private signer store (runtime socket connectivity only)

Plaintext signer-managed credential authority is never returned across the
HTTP or admin transports. Store-owning local processes may decrypt credentials
transiently for signing, backup creation, verification, restore, or rebuild;
exported backup archives carry only passphrase-encrypted credential records.

### Identity Model

Identity model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model).

Identity plumbing rules specific to this spec:

- every signer process owns exactly one runtime, fixed to
  `auth.CurrentProductIdentityID()` (`default`),
- preserving `identities/default/` preserves the storage namespace, not a
  multi-identity runtime model,
- reusable storage code may retain an identity locator parameter; product
  request, authentication, SSH, admin-session, and runtime code has no identity
  selector,
- startup validates the direct `identities/` entries without following
  symlinks and rejects every entry other than a real `default` directory before
  loading identity secrets or starting watchers,
- HTTP authentication verifies one product token and produces the reserved
  `system:product-admin` principal; runtime binding is independently fixed to
  the product runtime,
- SSH accepts only `default` and `request-token:default`; the token proof keeps
  `default` as its fixed domain-separated transcript value,
- output and audit identity fields may retain `default` attribution even where
  corresponding input selectors are removed.

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

Signer and sentry routing is not stored as active top-level `config.yaml`
state. Normal client routing lives in `endpoints.yaml` through
`internal/config.ClientEndpointRegistry`: at most one `signer` endpoint and zero
or more `sentry` endpoints. Endpoint records carry URL, SSH tunnel ports,
identity file, `known_hosts`, and token file. Live sentry-key discovery is
operation-scoped and is not stored in the registry. `internal/endpointrefs`
owns the public `aplane.endpoint.v1` JSON
handoff envelope used by `apadmin endpoint export` and
`apshell endpoints import`.

`internal/config.Config` contains no signer-routing fields. Client signer and
sentry routing is loaded exclusively from `endpoints.yaml`; top-level
`config.yaml` `ssh:` and `signer_port:` fields fail closed.

### Server Configuration

`apsigner`, `apadmin`, `apstore`, and `appass` load `internal/serverconfig.ServerConfig`
(client config remains `internal/config.Config`) from:

- `-d <path>`
- `APSIGNER_DATA`

Server config includes process-global settings such as:

- REST port,
- optional SSH server block,
- IPC socket path,
- optional passphrase command,
- optional passphrase command environment,
- algod config for compilation/policy use,
- TEAL compile network context token,
- optional custom transaction genesis-hash to network-token mappings,
- memory protection requirement,
- theme.

Identity-sensitive runtime settings are owned separately by `internal/signerapp/identity.IdentityConfig`:

- `user_auto_approve`,
- `lock_on_disconnect`,
- `passphrase_timeout` (admin idle disconnect timeout).

Those values are persisted per identity at
`identities/<identity>/config.yaml` via
`internal/signerapp/identity.StoredConfig`. Unknown fields, including the
removed `decommissioned` setting, fail strict parsing. On startup, stored
runtime values overlay process-global defaults (nil/empty means inherit).
Runtime reads resolve through the bound
identity runtime rather than directly from `ServerConfig`.

Key-class role is process/data-root scoped, not identity scoped. An initialized
signer data directory has a root `node.yaml` with exactly one role:
`signer` or `sentry`. New installs default to `signer` unless explicitly
initialized as sentry nodes. The role is immutable in supported tools, is
integrity-bound per identity with an HMAC sidecar over the exact root
`node.yaml`, and gates key generation, key import/restore, key scan, and HTTP
service dispatch. Identity config does not own node role; a `mode` field there
is unsupported and must be rejected.

Passphrase helper configuration is identity-scoped via
`internal/signerapp/unlockconfig.UnlockConfig`, stored at
`identities/<identity>/unlock.yaml`. `internal/signerapp/identity` re-exports
that type and its path/load/save helpers for existing callsites:

- `passphrase_command_argv`
- `passphrase_command_env`

Passphrase files are stored at `identities/<identity>/passphrase` or `passphrase.cred` for `systemd-creds`.

Signer policy participates in the ordered approval engine. The current policy
verdict model is documented in [ARCH_POLICY.md](ARCH_POLICY.md). The active
node-role policy is identity-scoped and stored at
`identities/<identity>/policy.yaml` with a sibling HMAC sidecar. On signer
nodes the document is client-signing policy; on sentry nodes the same
filename is direct sentry component policy. The default approval fallback is
`user_auto_approve`, persisted in
`identities/<identity>/config.yaml` and shown in `apadmin` as
`User Auto-Approve`. Policy is verified with a key derived from the identity
term key and loaded into the bound identity runtime on unlock/reload before
the key scan. Guided policy editing is implemented once in
`internal/signerapp/policytui`. `apadmin policy` edits the active document
through authenticated admin IPC or SSH while `apsigner` is running;
`apadmin policy rescue` edits the selected domain directly while holding the
store mutation lock. `internal/signerapp/policycmd` owns both workflows.
Both modes select the policy domain from the node role; store-backed
role-incompatible targets fail closed. Direct edits to `policy.yaml` are checked
and signed with `apstore policy`. Admin IPC policy messages are
target-aware (`signer|sentry`), validate replacements before writing, use
`expected_current_sha256` for optimistic concurrency, write the YAML plus a
fresh sidecar, and update the bound runtime immediately on success. The policy
admin surface reads, validates, and replaces only complete YAML documents
through `get_policy_snapshot`, `validate_policy`, and `replace_policy`,
including YAML-only fields such as `key_overrides`. There is no scalar
policy-settings IPC. Separate admin-settings IPC reports identity/process
configuration and status and mutates only its documented writable settings; it
does not project policy fields.

The policy document may contain YAML-only `key_overrides`; during normal
signing, the effective policy is selected by signing auth address, not by
transaction sender, so rekeyed accounts use the policy override for the auth
address. On sentry nodes, component signing selects overrides by the
txid-shaped Witness Key ID from the sentry-domain `policy.yaml`.
Network-scoped policy derives transaction network identity from
`GenesisHash` through built-in and configured mappings; `GenesisID` is
display/diagnostic data, not the policy key.

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

`apsigner` startup resolves the product identity's `unlock.yaml` before the
process-global `config.yaml` passphrase command. `appass` has no identity
selector and always manages `identities/default/unlock.yaml`.

Configuration behavior and validation rules are compatibility-bearing and are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). The network context model and genesis-hash mapping rules are explained in [ARCH_NETWORKS.md](ARCH_NETWORKS.md).

## On-Disk Data Model

The concrete on-disk layouts, key-file compatibility, keystore metadata versioning, template files, audit log, and backup format are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

Operationally:

- client-local state lives under the client data directory, including plugins (`plugins.available/`, `plugins.yaml`), scripts (`scripts/`), token (`aplane.token`), caches (`cache/`), swap state (`swap/<network>/`), and the cooperative `.apclient.lock`,
- signer-local state lives under the signer data directory, with the plaintext key type library at `library/templates/`, signer-wide ASA metadata at `cache/<network>_asa_cache.json`, managed backup archives at `backups/<identity>/`, and all sensitive runtime assets rooted under `identities/<identity>/`,
- systemd signer state is service-user-only (`0700` directories and `0600`
  ordinary files); the operator Unix group has no traversal rights and reaches
  signer operations only through authenticated transports. See
  [ARCH_STORE_OWNERSHIP.md](ARCH_STORE_OWNERSHIP.md),
- active credentials and key-type state live under `identities/<identity>/generations/<gen-id>/`, selected by the `CURRENT` pointer file; see [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md) and the on-disk layout in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md),
- systemd-managed admin IPC defaults to `/run/apsigner/aplane.sock`; explicit custom paths and same-UID local installs remain supported,
- the effective layout is identity-scoped even though the default deployment uses only `"default"`.

## Security Model

### Authentication and Authorization

The system has two main auth channels:

- HTTP token auth for shell/API callers
- passphrase auth for admin sessions over IPC or the SSH `aplane-admin` subsystem

Optional SSH provides transport-level authentication for remote shell access, but HTTP requests require the API token.

Authorization is a separate concern through `auth.Authorizer`. Runtime code uses
the explicit product action allowlist documented in
[ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md). In product mode,
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
- active admin client connection state across IPC and SSH admin transport,
- apadmin's configured local idle disconnect timeout.

Admin protocol sessions carry `adminserver.SessionContext`: session ID,
admin principal, target identity, auth method, transport, remote address, and
requester/approver attribution fields. This context is internal to the admin
transport and audit plumbing; it is not a new public product surface.
Admin authorization denials are audited with the session context, action,
resource, and denial reason before returning `authorization_denied` to the
admin client.

`adminserver.SessionManager` owns one pre-auth pending slot, one authenticated
pending slot during displacement, and one active slot for the process. Local
IPC and SSH admin sessions contend for those same slots. Displacement, pending
cleanup, lock-on-disconnect, approval delivery, and notification delivery all
address the active product session.

Locking zeroes every term key and deactivates the key session. Local
admin idle timeout is enforced by `apadmin` as a disconnect; the signer applies
`lock_on_disconnect` when that disconnect is observed.

## Server Ownership Model

`Signer` (`internal/signerapp/daemon/server.go`) is the composition root. Per-identity mutable state lives in `identity.Runtime` (`internal/signerapp/identity/runtime.go`).

| Concern | Owner |
|---------|-------|
| Lock/unlock state | `internal/signerapp/runtime` |
| Sign request lifecycle, approval queues, cancellation (sign + token) | `internal/signerapp/approval` |
| Planning, approval flow, execution, signing orchestration | `internal/signerapp/signing` |
| Template registration, reload coordination | `internal/signerapp/templates` |
| Admin protocol wire types, envelopes, and framing primitives | `internal/protocol` |
| Admin service request/result vocabulary and framed server connections | `internal/adminproto` |
| Admin session state, message dispatch, and handlers | `internal/signerapp/adminserver` |
| Identity runtime, config, token, SSH enrollment, lifecycle | `internal/signerapp/identity` |
| HTTP contract types (request/response DTOs) | `pkg/signerapi` with `internal/signerapi` aliases |
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
`internal/signerapp/rest` binds live `/sign` request IDs to identity runtimes,
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
- admin protocol interactions over IPC and SSH,
- SSH tunnel hosting,
- audit logging,
- signer lock/unlock lifecycle,
- key file watching and reload.

### Server Startup

`apsigner` validates that `identities/` is absent/empty or contains only a real
`default/` directory, then constructs the one product `identity.Runtime`.

Before normal startup option loading, `apsigner` rejects manual startup from a
signer data directory containing `.prod` unless the process is systemd-managed.
Systemd-managed means `APLANE_SYSTEMD_MANAGED=1` or parent PID 1. This guard is
checked before locked/headless/test startup mode selection.

Implemented startup modes:

- locked startup with later unlock through an authenticated admin session,
- headless unlocked startup via passphrase command,
- test unlocked startup via `TEST_PASSPHRASE`,
- forced locked startup when the keyring root does not exist.

Both locked and headless paths converge through
`identity.Runtime.reloadLocked`. Production wiring from
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

Template scan precedes key scan so generation/discovery state is current.
LogicSig key files carry their own bytecode and signing arg contract, so
signing an existing key does not depend on the installed template definition.
The complete key file and key type state machines are documented in
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
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

- the one product identity runtime and node-level fail-closed state,
- authn/authz components,
- signer-side planning/approval/execution service adapters,
- IPC server,
- optional SSH server,
- config and data-dir references.

Sensitive per-identity state lives under `internal/signerapp/identity.Runtime`, including:

- `keySession`,
- identity-scoped `keys`, `keyTypes`, and `keyMetadata` resource profiles,
- signer runtime owner,
- approval coordinator,
- watcher lifecycle,
- identity-scoped config,
- token authority and SSH enrollment state.

The key indexes are authoritative runtime indexes of what the server believes is signable.

### Lock Hierarchy

| Lock | Protects |
|------|----------|
| `Signer.configMu` | Mutable process-global `ServerConfig` fields exposed through admin settings, including theme, SSH listen address, and endpoint advertise URL |
| `Signer.configMutationMu` | Process-owned `config.yaml` write serialization |
| `Signer.storeMutationLock` | Product key/template/config/policy mutation serialization |
| `Signer.restoreAttemptMu` | Lazy initialization of the per-archive restore backoff limiter |
| `identity.Runtime.keysLock` | `keys`, `keyTypes`, `keyMetadata` |
| `identity.Runtime.passphraseLock` | `keySession`, `reloadFn`, unlock-sensitive ops |
| `identity.Runtime.watcherMu` | Watcher lifecycle, dirty state |
| `identity.Runtime.approval` | `atomic.Pointer` — approval coordinator |
| `Runtime.stateMu` | Signer locked/unlocked state |
| `Coordinator.pendingRequestsLock` | Pending sign approvals |
| `Coordinator.pendingTokenRequestsLock` | Pending token provisioning approvals |
| `IPCServer.writeMu` | Serializes outbound IPC JSON writes |
| `adminserver.SessionManager.mu` | Process-wide admin session registration/displacement |
| `AuditLogger.mu` | Audit file writes |
| SSH server locks | Authorized keys, product-token callbacks, product connections, listener |

Goroutines:

- HTTP server plus per-request handler goroutines,
- IPC accept loop plus per-client goroutines,
- file watcher goroutine,
- SSH server accept loop plus per-connection goroutines.

### Lock/Unlock Lifecycle

Unlocking must:

- open `keyring.enc` with the passphrase,
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

Store maintenance adds an identity-local state fence in `Runtime.stateMu`.
Beginning maintenance clears and locks the published key session before any
root transition. Unlock and recovery attempts that start during the fence are
rejected without loading authority; attempts already in flight lose on the
generation check and clear anything they loaded. Only the matching successful
maintenance token may republish after verified reload. Failure, a stale token,
or a racing explicit lock leaves the runtime locked.

The watcher model is identity-owned but not tied to every lock transition:

- when an identity is unlocked, the watcher reloads immediately on qualifying filesystem changes,
- when an identity is locked, the watcher remains active and marks the identity dirty,
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

The runtime has no live decommission transition or operation lease. Server
shutdown stops accepting and drains HTTP work before destroying runtime key
state; key-session locks continue to protect signing authority access. If a
service cannot drain before its shutdown deadline, lifecycle teardown retains
the audit logger and runtime state until process exit rather than destroying
them underneath a live handler.

### Server-Side Application Boundary

The server-side plan/sign boundary is split as follows:

- startup option resolution, validation, identity assembly, and lifecycle entrypoint in `internal/signerapp/startup`,
- transport adapters/builders for HTTP, IPC, and SSH in `internal/signerapp/daemon`,
- transport-neutral admin request/result types and framed connections in `internal/adminproto`,
- server-side admin protocol/session state machine in `internal/signerapp/adminserver`,
- process-root identity-targeted admin facade for server-originated admin traffic in `internal/signerapp/adminserver.AdminHub` and `internal/signerapp/daemon/admin_hub.go`,
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
- SSH token provisioning approval and audit service in `internal/signerapp/sshprovision`,
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
- token issuance and revocation side effects.

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
exists. Guarded groups likewise complete the normal user and sentry component
signing plus `/sign/assemble` path before the client routes the assembled group
to submit or simulate. The client consequently holds executable guarded bytes
in both modes. See [ARCH_SENTRY.md](ARCH_SENTRY.md).

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
| Command registry, parsing adapters, rendering, plugin arg normalization | `internal/apshellcli` |

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
- `internal/apshellcli` owns command syntax, interactive UX, MCP mode, plugin argument normalization, and final shell rendering,
- `cmd/apshell` owns binary-level composition and startup delegation,
- `internal/engine` owns business operations and stateful client runtime behavior,
- `internal/clientstate` owns cache-backed client mutation state,
- `internal/addressdisplay` owns alias/rekey-aware address and key-type terminal display formatting,
- `internal/engine/connect` owns signer connectivity and signer-facing request flow,
- `internal/asa` owns shared ASA metadata/reference/raw-display handling,
- `internal/appresult` owns shared structured result and MCP projection.

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
- then HTTP requests tunneled to signer REST endpoints,
- plus a locally stored token for per-request auth.

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

- transaction commands: `send`, `sweep`, `sign`, `optin`, `optout`, `keyreg`, `close`, `validate`
- information commands: `balance`/`bal`, `holders`, `participation`, `asa`, `help`/`h`, `status`, `accounts`, `info`, `plugins`
- app commands: `app`
- alias/set commands: `alias`, `sets`
- rekey commands: `rekey`, `unrekey`
- signer/key-management commands: `keys`, `keytypes`, `generate`, `delete`
- config/toggle/connectivity/session commands: `network`, `write`, `verbose`, `simulate`, `config`, `connect`, `disconnect`, `request-token`, `endpoints`, `clear`/`cls`, `quit`/`exit`/`q`
- scripting/plugin commands: `script`, `js`, `jssave`, `jslist`

Command handling constraints:

- command names, aliases, and top-level usage grammar are operator-visible compatibility surfaces,
- moving handler code does not by itself change behavior; silently changing accepted syntax does.

### Standalone Swap Client

The standalone atomic-swap client is outside this repository. This repository does not own standalone
swap source under `cmd/` or `internal/`.

## Transaction Processing

The system separates:

- group shaping and canonicalization,
- cryptographic authorization,
- submission.

The signer server canonicalizes group shape, fee pooling, dummy requirements, and group IDs; then it signs or assembles each entry according to key type.

Three authorization classes:

- native Ed25519: signs `TX || msgpack(txn)`
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

Canonicalization rules live in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). HTTP request/response contracts live in [ARCH_HTTP_API.md](ARCH_HTTP_API.md).

### Signing Authority And Template Authority

See [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Key Files / Signing Authority) for the signing authority contract.

## Bounded Authorization Contracts

`bounded1` moves the pure-spend/admin-operation envelope into
`lsig/composeddsa`, admits only `pay`/`axfer` pure spends plus configured pure
rekey, and compiles a 10,000 microAlgo fee ceiling. Layer 3 is reachable only
for an admitted spend or for a spending-key rekey whose profile explicitly
declares `policy_gate: layer3`; it can narrow but never broaden the envelope.

The one bounded1 contract admin primitive is the Falcon-1024 witness key. The
signer retains the spending key and public contract-admin metadata; the private
admin witness remains in standalone `.wit` custody. Admin-key rekey uses
`POST /sign/bounded-admin`, never ordinary caller runtime args or sentry
assembly. Sentry-enabled spend profiles advertise
`signing_flow: bounded-sentry1` and use bounded component assembly; their admin
rekey still bypasses the sentry. Spending-key rekey remains possible only when
the profile explicitly selects it and always receives forced operator review.
Planning owns the single finalized-transaction classification boundary after
fee pooling. The executor checks the selected path and loaded durable metadata
against the immutable plan without maintaining a second classifier. Pure
spends and spending-key rekeys assemble the path-specific durable base,
derived, and runtime argument slots; undeclared caller arguments and hybrid
effects fail closed.

`aplane.falcon1024-allowlist-alock.v1` is the framework-owned fixed-list
profile. `aplane.corridor.v1` composes the framework Merkle policy with a
sentry spend gate and external-admin rekey. External key generation and ceremonies are owned by
`aprekey`; apshell and apconsole do not handle private contract-admin
artifacts. The normative field inventory, canonical encodings, vectors,
schema, normal forms, and custody contract are in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

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

## Guarded Signing And Sentry Nodes

This section is the system-map summary. The detailed subsystem architecture,
trust boundaries, guarded authorizer semantics, endpoint routing model, and
implementation map live in [ARCH_SENTRY.md](ARCH_SENTRY.md).

Guarded signing is APlane's two-party LogicSig authorization path for
accounts whose LogicSig bytecode requires both:

- a user component signature produced by the user signer that owns the
  guarded-account key file, and
- a sentry component signature produced by a separate sentry signer that
  owns a sentry key and evaluates sentry-domain `policy.yaml`.

The client never holds private key material. It orchestrates component signing
and assembly through authenticated signer endpoints, then submits or simulates
the final signed group with algod.

### Node Roles

Each initialized signer data root has one immutable root `node.yaml` role:
`signer` or `sentry`.

| Node role | May hold | Must not hold |
|---|---|---|
| `signer` | ordinary account-signing keys and guarded account keys | sentry private keys |
| `sentry` | sentry private keys and sentry policy | ordinary account-signing keys or guarded account keys |

There is no `dual` role and no supported same-process mixed-role hosting.
Same-host development or production co-location uses separate signer and
sentry data roots and separate `apsigner` processes. Independence is a
deployment-domain property: a signer node and sentry node operated by the
same party are still one trust domain, even when their key classes are
structurally separated.

The root role gates key generation, mnemonic import, restore, key scan, and
HTTP signing dispatch. A role-conflicting key in the inventory fails closed for
the node rather than being silently skipped. `internal/noderole` owns
`node.yaml` parsing and identity-bound integrity sidecars; `internal/keyclass`
owns role-versus-key-type classification. The exact node-role contract and
on-disk integrity checks live in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

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
Signer-custodied sentry witnesses use
`<active-generation>/keys/<WitnessKeyID>.sen`; account authority uses the same
active namespace with `<AlgorandAddress>.key`. Physically, the active namespace
is `identities/<identity>/generations/<gen-id>/keys/`, selected by `CURRENT`.
The direct `identities/<identity>/keys/` path is pre-generation legacy state,
not an active credential source. External contract-admin
witnesses remain standalone `.wit` artifacts and are never scanned by the signer.
The full sentry public key remains the verifier key embedded in guarded
account LogicSig bytecode. The same witness key form can serve a bounded
contract-admin enrollment under standalone custody, but one keypair should
never serve both roles. `internal/witness` owns identity and custodian/domain
capabilities; `internal/sentry/keytypes` owns guarded-account role mapping.

Guarded account key types name both the account DSA and the sentry DSA:

- `aplane.falcon1024-sentry1024.v1`

A guarded account key file stores the resolved `sentry_public_key` and the
LogicSig bytecode embeds that same public key. `/sign` rejects guarded-account
key types and witness key types. Guarded accounts are signed only
through the component-signing and assembly flow below.

### Component Message Contract

Component signatures are role-separated. Message construction is owned by
`internal/sentry/message`, and signature verification is owned by
`internal/sentry/verify` (signer-side only; clients treat component
signatures as opaque). Callers must use those shared primitives rather
than reconstructing the component message locally.

The message commits to:

- the APlane sentry domain string and version,
- the component role (`user` or `sentry`), and
- the target transaction ID derived from the canonical group entry.

User-role and sentry-role signatures are not interchangeable. The LogicSig
program and the user signer's assembly step verify the sentry signature
against the sentry public key embedded in the local guarded-account key.

### Runtime Flow

### Unified Component-Flow Migration Contract

The component-flow unification keeps `/plan` as the sole canonicalizing
endpoint. Component and assembly endpoints consume frozen canonical group
bytes; they do not append dummies, pool fees, regroup transactions, or repair
invalid input. The signer does not assert that those bytes originated at its
own `/plan` endpoint. Independently constructed canonical bytes may succeed
when they satisfy the same signer-owned authorization and policy checks.

This changed the bounded-sentry component boundary deliberately. The retired
bounded-specific route planned and approved in one call. The unified component
route instead reconstructs the
bounded authorization envelope from frozen bytes, typed position context, and
the signer's durable key metadata, then applies policy and operator approval to
those exact bytes. Every released signature or receipt is derived from the
same decoded group that policy evaluated and the operator saw. Assembly keeps
the authorization models distinct: guarded targets require user and sentry
component signatures, while bounded-sentry targets require the bounded
assembly receipt as well as their base and sentry signatures.

The old bounded-specific component and assembly routes are retired and return
404. This section owns the invariants that survive that migration.

The current guarded choreography is named `sentry1`. Signer `/keys` and
`/keytypes` inventory label guarded keys with `signing_flow: sentry1` and
`sentry_component_key_type`; clients route on the flow label, treat key-type
and component-key-type strings as opaque, and fail fast on flow labels they do
not implement. The `sentry1` label is frozen: any choreography change mints a
new label, and unrelated future mechanisms get their own label family.
For cache compatibility, a client may treat a cached built-in guarded key type
that lacks `signing_flow` or sentry metadata as stale and refresh `/keys`
before route selection; the refreshed `signing_flow` remains the routing
authority.

`apshell send` resolves each original sender through the auth-address cache and
detects guarded targets by effective signer. If any effective signer declares
a signing flow, the client uses guarded orchestration for the whole
atomic group. The group may mix direct guarded senders, senders rekeyed to a
guarded authorizer, and ordinary signer-managed senders.

The client submits one unsigned intended group to `/plan`. The signer returns
the canonical group after sizing resource dummies across every LogicSig
position from structured profiles: final compiled program bytes,
selected-path maximum argument bytes, and the reviewed maximum opcode cost.
Bounded profiles derive their path-specific argument budgets from the durable
argument layout, including the admin-key slot only for an admin-key rekey. No
combined LogicSig-size scalar participates in planning. Fees and group ID are
fixed before any downstream component or non-guarded signature is produced.

For guarded targets, the client obtains component signatures:

1. user signer `/sign/component` with `kind:"user"`,
2. sentry signer `/sign/component` with `kind:"sentry"`.

The user-role component request proves the user signer controls the
guarded effective signer and runs the signer-domain approval gates (hard
policy rejection, always-review rules, blocking operator approval) before any
key operation, with the guarded account as the per-target policy key. The
sentry-role component request evaluates decoded target transaction facts
against sentry-domain `policy.yaml` and returns sentry component signatures
when allowed.

If the original group also has non-guarded positions, the client then calls the
primary signer `/sign` over the full canonical group: non-guarded originals are
sign-mode entries, guarded targets are `foreign` entries with accurate
selected-path `lsig_resources`, and client-signed dummies are `foreign` context
entries. This keeps the complete group in approval context and lets the signer
reject client mis-sizing before algod evaluation.

Finally, the client calls the user signer `/sign/assemble`. The assembly
request verifies both component signatures against the local guarded account
key's stored metadata, packs LogicSig arguments, verifies the resulting LogicSig
address equals the guarded account, verifies any passthrough signed bytes
against the canonical transaction IDs, and returns signed group bytes. If the
target sender differs from the guarded account, assembly verifies the decoded
signed transaction carries `AuthAddr == guarded_account` before returning it.
Signed non-guarded originals and signed dummies are supplied to assembly as
passthrough entries.

Guarded component signing supports a guarded account either as `txn.Sender` or
as the effective signer/AuthAddr for another sender. Component messages still
commit only to role and target transaction ID; sentry policy is based on
decoded transaction facts and does not receive a separate authorizer field.
Per-authorizer delegation controls would require a versioned component message
and LogicSig change and are not part of this flow. Sentry-role component signing
is transfer policy based: target transactions must produce direct transfer
movements covered by `transfer_policy`. App calls, key registration, asset
configuration, and other unsupported target shapes are rejected for sentry
role because routing cannot authorize them.

### Trust Model

The trust decision is made at guarded-account generation, when the operator
selects the sentry public key that is baked into the LogicSig bytecode and
stored in the key file. Later endpoint routing is mechanical:

- endpoint import is not an ownership proof,
- `/keys` is self-reported inventory and is not an ownership proof,
- a wrong endpoint can only produce a signature that fails assembly or
  on-chain LogicSig verification unless it holds the real sentry key.

The enforcement layers are:

1. required `/sign/assemble` verification against the sentry public key
   embedded in the local user signer's guarded-account key, and
2. final on-chain LogicSig verification.

Clients do not verify component signatures; they validate response shape and
forward signatures to assembly as opaque material.

### Endpoint Routing

Client routing lives in `$APCLIENT_DATA/endpoints.yaml`. The registry contains
at most one `signer` endpoint and zero or more `sentry` endpoints. Endpoint
records contain connection profile data, endpoint role, token-file path,
known-hosts path, and SSH identity path. They do not persist sentry-key
inventory.

Operator handoff and manual endpoint setup use two paths:

- `apadmin endpoint export` emits `aplane.endpoint.v1` with portable endpoint
  URL and port data only. The endpoint URL is either explicit CLI input
  (`--url` or `--host`) or the operator-declared signer
  `config.yaml` value `endpoint.advertise_url`; it is not inferred from the
  SSH listener bind address.
- `apshell endpoints import --alias <name> --role signer|sentry`
  writes client-local endpoint routing.
- `apshell endpoints create --alias <name> --endpoint <url> --sentryport
  <port>` writes a manual sentry endpoint profile when no exported endpoint
  envelope is used.
- bearer tokens are obtained separately with `request-token --endpoint`.
- SSH host trust remains owned by the existing known-hosts flow.

`apshell endpoints discover-sentries` is a read-only diagnostic. It queries
authenticated `/keys` on configured sentry endpoints, validates Witness Key ID
metadata, and prints the live results without changing client or signer state.

Runtime guarded and bounded-sentry routing performs the same live discovery at
the start of each signing operation and keeps an operation-scoped route
snapshot. It probes the deterministic configured endpoint order with bounded
parallelism and stops only after every required embedded public key has one
unambiguous route. `url: self` is an explicit co-location profile; there is no
implicit fallback to the primary signer.

The signer reference catalog is a generation trust-input inventory, while
live endpoint discovery is routing only. Neither proves endpoint ownership;
the embedded public key and verified component signature remain authoritative.

### Policy And Audit

Signer nodes use `policy.yaml` for account signing. Sentry nodes also use
`policy.yaml`, parsed in the sentry policy domain, for sentry component
signing. Both domains use the shared policy grammar and HMAC sidecar model, but
sentry policy has no manual-review or operator-default verdict. It is
deterministic authorization: all selected target movements must be positively
authorized by the effective sentry policy, and deny guards fail closed.

Sentry policy overrides are keyed by Witness Key ID.
Client-signing policy overrides are keyed by signing auth address.

Sentry component approvals and rejections are recorded through existing sign
audit events. Current records put the Witness Key ID in `txn_auth`, the
decoded target sender in `txn_sender`, and the matching deterministic policy
rule in `policy_rule_id` when one applies.

### Implementation Ownership

Primary implementation ownership:

- `pkg/signerapi`: component-signing and assembly DTOs plus fixtures.
- `internal/sentry/message`: role-separated component message construction.
- `internal/sentry/canonical`: canonical group decoding and group hashing.
- `internal/sentry/verify`: component signature verification primitives
  (signer-side only; client binaries must not link them).
- `internal/sentry/keytypes`: sentry and guarded key-type identifiers,
  Witness Key ID validation, and DSA mapping.
- `internal/signerapp/signing`: signer-side component signing, sentry policy
  evaluation, and assembly.
- `internal/signerapp/rest`: HTTP handlers for `/sign/component` and
  `/sign/assemble`.
- `internal/engine/guarded`: client guarded-send orchestration, sentry
  component-signature collection, and sentry endpoint resolution/discovery,
  isolated from the engine facade (it depends on the engine only through a
  narrow `SignerCacheView` and injected connection/caches; `internal/engine`
  wires it and re-exports the discovery types). Its exported surface is only
  the sanctioned entry points (`New`/`Deps`/`Signer`/`SignerCacheView`,
  `HasGuardedEffectiveSigner`, `SignAndSubmitGroup`,
  `DiscoverSentryComponentKeys`, `DiscoveredSentryComponentKey`, and the
  `ErrSentryDiscovery*` sentinels); the choreography internals are unexported
  and tested in-package. Import isolation is pinned by
  `test/arch/client_layering_test.go`.
- `internal/config` and `internal/endpointrefs`: endpoint registry and public
  endpoint envelope handling.
- `internal/sentry/sentryrefs`: public sentry reference catalog used by
  generation UIs.
- `internal/policy`: shared signer/sentry policy grammar, validation, and
  evaluation domains.

Compatibility-bearing wire, file, endpoint, policy, backup/restore, and SDK
contracts remain in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) and
[ARCH_HTTP_API.md](ARCH_HTTP_API.md).

## Provider and Algorithm Model

See [ARCH_CRYPTO.md](ARCH_CRYPTO.md) for the provider and algorithm model.

Key type identifiers use the canonical form `publisher.family.vN` for APlane-defined LogicSig, template, and compiled-provider key types, and the single-segment built-ins `ed25519` and `falcon1024` for native signing keys. Native Falcon uses the `native_pq` authorization kind and top-level `SignedTxn.PQsig`; it is not part of the `aplane.falcon1024.*` LogicSig family. The full contract lives in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Key Type Identifier Contract).

## Keystore and Key Lifecycle

`internal/keystore.FileKeyStore` is the concrete keystore implementation in active use.

It owns:

- identity-scoped key directory resolution,
- keyring opening and caching,
- decrypted scan metadata cache,
- on-demand decryption for specific addresses.

The keystore compatibility model is split between:

- `.key` account-authority and `.sen` sentry-credential envelope/payload compatibility for individual entries,
- `keyring.enc` compatibility for passphrase verification and KDF parameters,
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

Offline mutation rules are compatibility-sensitive and are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

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

Process protocol details, discovery order, method names, and manifest contract are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

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

Important MCP transport and structured-output contracts are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Caching and Local State

Client-side cached storage is implemented in `internal/cache`, while caller-facing ASA metadata/ref/amount handling routes through `internal/asa`. The signer also persists signer-wide ASA metadata with `internal/cache`, but signer callers go through `internal/signerapp/asametadata.Store` because that cache is rooted under the signer data directory and is not APCLIENT_DATA state.

Caches include:

- ASA cache
- alias cache
- signer cache
- auth-address cache (`<network>_auth_cache.json`)
- set cache
- address resolver helpers
- swap session JSON files and tombstones under the client swap state root

These caches are not interchangeable:

- signer-side ASA metadata cache depends on signer-configured algod endpoints, is shared across signer identities, and has no long-lived process-global in-memory map,
- signer cache depends on remote signer state; interactive and embedded
  apshell sessions poll authenticated `/status` on the configured
  `signer_status_poll_interval` (default `10s`) and refresh `/keys` when
  `keyset_revision` changes. MCP mode does not run this background
  poller; it relies on startup connection and serialized command execution
  instead. The signer cache carries the signer-advertised key type, LogicSig
  size budget, signing argument schema, guarded `signing_flow`, sentry
  component key type, and embedded sentry public key. Guarded key-type checks
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

The swap subsystem adds a distinct form of local client state:

- it is per-network and per-local-actor rather than process-global,
- it is authoritative for local history display when reconciliation is unavailable,
- it is reconciled against on-chain note traffic and external swap handoff state instead of being a purely ephemeral UI cache.

Cache invalidation policy is explicit and type-specific.

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
  boundaries; `generation_storage_test.go` pins the no-hardlink rule and
  store-owning package inventory from ARCH_GENERATIONS;
  `store_permissions_test.go` pins the audited shared-mode allowlist and keeps
  legacy group-bearing modes out of signer-store writers;
  `kdf_confinement_test.go` pins key-derivation, raw-term-key, test-fixture,
  and historical-term boundaries,
- the opt-in `test/storeintegration` process harness, invoked through
  `make store-lifecycle-test` and `make store-crash-test`, creates genuine
  blank signer roots without algod or the shared integration fixture;
  `internal/testcheckpoint` provides `storetest`-only semantic checkpoints and
  compiles to no-op behavior in production builds,
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
  `guarded_assembly`, `bounded_sentry`, `plugin_signing`, and
  `generation_commit`, and `rotation_transition`, plus liveness
  configurations for `approval_coordinator` and an expected-failure R5 negative control for
  `rotation_transition`.
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
  against signer, sentry, client/admin, and LocalNet algod containers on one
  Docker network. It verifies local install layout, shared LocalNet
  reachability, SSH token provisioning, client signer reachability, guarded
  signing, and corridor allowlist enforcement across the Docker network.
- `make docker-fnet-test` runs the same installed signer, sentry, and
  client/admin topology against the public FNet algod. Funding transactions
  are authorized on the host by the protocol-native Falcon account in
  `TEST_FUNDING_MNEMONIC`; the mnemonic is not copied into a container or
  persisted in generated node configuration.
- `make docker-local-release-test` runs the same topology and assertions using
  published GitHub APlane release assets plus the PyPI and npm SDK packages.

Additional opt-in verification targets include `make soak-test-localnet` for
long-running LocalNet transaction coverage and
`make apshell-command-coverage-localnet` for broad shell-command coverage.

The integration harness behavior is part of the effective repository contract:

- `make integration-test` requires an explicit TestNet, LocalNet, or FNet
  profile and fails closed when the profile is absent or invalid;
  `make integration-test-testnet`, `make integration-test-localnet`, and
  `make integration-test-fnet` are the convenience targets,
- `TEST_FUNDING_MNEMONIC` has one authorization meaning on every integration
  network: it is a protocol-native Falcon-1024 recovery mnemonic; the harness
  adds the native-PQ fee contribution before group IDs and emits structured
  `PQsig` envelopes for direct fixture transactions,
- LocalNet setup uses a KMD Ed25519 account only as a bootstrap source for a
  disposable funded native Falcon account; TestNet/FNet use an operator-supplied
  funded native Falcon account and therefore require a v42-capable network,
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
- integration tests covering signer, app, passthrough, Falcon, and SSH token provisioning pass,
- external SDK tests pass when the touched surface includes SDK-facing behavior,
- signing outputs for unchanged inputs remain stable,
- IPC notifications and request/response message shapes remain compatible with `apadmin` and `apapprover`,
- token provisioning and revocation remain compatible with the SSH client flow,
- plugin discovery precedence and manifest validation remain unchanged unless explicitly versioned,
- on-disk compatibility is checked for `keyring.enc`, `.keystore`, `.key`, `.sen`, `.template`, `config.yaml`, `audit.log`, and token files.
- client endpoint compatibility is checked for `endpoints.yaml`,
  endpoint token files, endpoint handoff envelopes, and public sentry
  reference records when those surfaces change.

## Authentication

- HTTP: token auth (`Authorization: aplane <token>`). The one product token
  authenticates `system:product-admin`; handlers use the one product runtime.
- IPC: passphrase auth. The admin protocol has no target-identity selector and
  binds to the product runtime after passphrase verification.
- SSH: dual-factor for tunnel/admin connections. The non-secret identity ID is
  fixed SSH username `default`. An enrolled public key is verified first, followed by a
  programmatic mutual HMAC proof of the identity token bound to the accepted
  SSH host key and fresh client/server nonces. Token provisioning remains a
  key-only, operator-approved exception using `request-token:default`.

## Approval Model

See [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Approval and Policy Contracts) for the approval contract.

## SSH, Watching, Templates, and Audit

The SSH tunnel is implemented in `internal/sshtunnel`. It provides:

- an SSH server embedded in `apsigner` that forwards TCP connections to the local REST API,
- SSH clients in `apshell`, remote `apadmin`, and the external Go, Python, and
  TypeScript SDKs that establish the tunnel.

Watcher, template reload, audit logging, token provisioning, token revocation, and backup/restore contracts are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

Architecturally:

- one watcher is owned by the product runtime,
- template registration precedes key scan for generation/discovery,
- signer-data library templates are authoritative install sources when present,
  and same-`key_type` template mutation is rejected rather than applied on
  reload/unlock,
- audit logging is a signer-side operational subsystem, not a UI concern,
- token provisioning is an approval-mediated enrollment path, not just SSH auth,
- token provisioning requires the active product admin session, and product
  token rotation closes every SSH connection authenticated with an older token
  generation.

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
10. Durable signer state remains rooted at `identities/default/`; request and
    runtime models do not expose an identity selector.
11. Product UI/docs are single-operator and single-signing-identity.
12. Exactly one product runtime is constructed, and an extra direct entry under
    `identities/` fails startup before identity secrets are consumed.
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
- `internal/clientstate` for client-side cache state and mutation ownership
- `internal/engine/connect` for remote signer connection state, lifecycle, and signer-facing request flow
- `internal/appresult` for shared shell/MCP structured result and projection ownership
- `internal/config` for configuration normalization
- `internal/keystore` for storage/session separation
- `internal/protocol` for the compatibility-bearing IPC/SSH wire contract,
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
- the runtime core is identity-owned, but the operator/control-plane surface is single-identity/single-operator in product mode, even though that product admin workflow may arrive over IPC or the SSH `aplane-admin` subsystem.

Product-level boundaries:

- identity-scoped storage, sessions, approval routing, and token plumbing exist,
  with a single-operator deployment model,
- plugin manifests expose one command-first executable contract,
- template files are identity-scoped and encrypted; `key_type` is an immutability boundary rather than an override hook,
- shell command automation is explicit per primary command, with aliases inheriting policy and no text-capture fallback.

## Key Entry Points

| Area | Files |
|------|-------|
| Server | `cmd/apsigner/main.go`, `internal/signerapp/daemon/server.go`, `internal/signerapp/startup/*.go` |
| Client | `cmd/apshell/main.go`, `internal/apshellcli/registry.go`, `internal/apshellcli/mcp.go`, `internal/apshellcli/status_poll.go`, `internal/shellrepl/*.go` |
| Client Enrollment / Remote Preflight | `internal/clientenroll/preflight.go`, `cmd/apconsole/preflight.go`, `cmd/apadmin/remote.go` |
| Shell App | `internal/apshellapp/app.go`, `internal/apshellapp/runtime.go`, `internal/apshellapp/connect.go` |
| Engine | `internal/engine/engine.go`, `internal/engine/core.go`, `internal/engine/consensus.go`, `internal/engine/status_sync.go`, `internal/engine/connect/state.go`, `internal/engine/guarded/submit.go` |
| Signing | `internal/signerapp/signing/service.go`, `internal/signerapp/signing/planner.go`, `internal/signerapp/signing/planner_runtime.go`, `internal/signerapp/signing/execution.go`, `internal/signerapp/signing/approval.go` |
| Native Signature Providers | `internal/signing/ed25519`, `internal/signing/falcon1024/address.go`, `internal/signing/falcon1024/register.go`, `internal/signing/falcon1024/signerreg/*.go`, `internal/signing/falcon1024/signerops/*.go`, `internal/falconparams/params.go` |
| Key Admin | `internal/signerapp/keyadmin/service.go`, `internal/signerapp/keyadmin/admin_ops.go`, `internal/signerapp/keyadmin/generic_lsig.go` |
| KeyType Library | `internal/signerapp/templateadmin/service.go`, `internal/templatelibrary/library.go`, `internal/templatestore/store.go`, `internal/keytypestate/state.go`, `internal/storepaths/paths.go`, `internal/signerapp/daemon/admin_services.go` |
| Store/Backup Admin | `internal/signerapp/storeadmin/service.go`, `internal/signerapp/backupadmin/*.go`, `internal/backup/*.go` |
| Store Ownership / Permissions | `internal/storeperm/*.go`, `internal/fsutil/perms.go`, `internal/fsutil/durable.go`, `internal/adminipc/path.go`, `cmd/apstore/permissions.go`, `docs/ARCH_STORE_OWNERSHIP.md` |
| Store Integration Harness | `test/storeintegration/*.go`, `internal/testcheckpoint/*.go`, `Makefile` (`store-lifecycle-test`, `store-crash-test`, `store-release-drill`) |
| LSig Providers / Resource Planning | `lsig/all.go`, `lsig/signerreg/register.go`, `internal/lsigresource/consensus.go`, `internal/lsigresource/solver.go`, `internal/signerapp/signing/planner_runtime.go`, `internal/signerapp/signing/native_pq_fee.go`, `internal/signing/dummy_transactions.go`, `internal/lsigprovider/provider.go`, `internal/signingargs/types.go`, `internal/lsigsalt/salt.go`, `lsig/falcon1024/v1/standard.go`, `lsig/falcon1024_guarded/provider.go`, `lsig/falcon1024_guarded/register.go`, `lsig/ed25519lsig/register.go`, `lsig/ed25519lsig/signerreg/register.go`, `lsig/falcon1024/signerops/ops.go`, `lsig/dsafamily/register.go`, `lsig/generictemplate/provider.go`, `lsig/composeddsa/composer.go`, `lsig/composeddsa/layer3.go`, `library/templates/aplane.corridor.v1.yaml`, `lsig/sentryaccount/sentryaccount.go`, `internal/boundedadmin/message/message.go`, `internal/boundedmeta/metadata.go`, `internal/merkleallowlist/allowlist.go`, `internal/tealtemplate/legacy_list.go`, `internal/tealtemplate/template.go` |
| Protocol | `internal/protocol/messages.go`, `internal/signerapp/svcerr/svcerr.go`, `internal/signerapp/adminserver/dispatch.go`, `internal/signerapp/adminserver/displacement.go`, `internal/adminproto/stream_conn.go` |
| Config | `internal/config/config.go`, `internal/serverconfig/serverconfig.go`, `internal/config/networkid.go`, `internal/config/genesishash.go` |
| LocalNet Setup | `cmd/aplocalnet/main.go`, `internal/aplocalnet/setup.go`, `plugins/algokit-localnet/algokit-localnet.go`, `plugins/algokit-localnet/manifest.json` |
| Policy | `internal/policy/config.go`, `internal/policy/store.go`, `internal/policy/integrity.go`, `internal/crypto/policy_integrity.go`, `internal/signerapp/policyruntime/policy.go`, `internal/policy/lint.go`, `internal/policy/review.go`, `internal/signerapp/signing/always_review.go`, `internal/signerapp/signing/service.go`, `internal/signerapp/admin/service.go`, `cmd/apstore/policy.go`, `internal/templatepolicy/outcome.go` |
| Keys (payload codec) | `internal/keys/payload_codec.go`, `internal/keys/save.go`, `internal/keys/keys.go`, `internal/keys/file_types.go` |
| Keystore | `internal/keystore/file.go`, `internal/keystore/session.go` |
| Node Role / Key Class | `internal/noderole/role.go`, `internal/noderole/integrity.go`, `internal/keyclass/keyclass.go`, `internal/sentry/keytypes/keytypes.go` |
| Store Init/Passphrase | `internal/storeinit/initialize.go`, `internal/defaultkeytypes/defaults.go`, `internal/storepass/rotate.go`, `internal/signerapp/unlockconfig/unlock.go`, `cmd/apstore/main.go`, `internal/signerapp/daemon/admin_services.go` |
| Generation Storage | `internal/genstore/*.go`, `internal/storepaths/generations.go`, `internal/storepaths/active.go`, `cmd/apstore/generations.go`, `docs/ARCH_GENERATIONS.md` |
| Rotation Inventory | `internal/rotationinventory/*.go`, `internal/crypto/term_envelope.go`, `internal/genstore/records.go`, `internal/genstore/validate.go`, `docs/PHASE3_ONBOARDING.md` |
| Client Data | `internal/clientdata/lock.go`, `internal/clientstate/state.go`, `internal/refname/refname.go` |
| Identity | `internal/signerapp/identity/runtime.go`, `internal/signerapp/identity/config.go` |
| Release/Distribution | `Makefile`, `.github/workflows/release.yml`, `docs/RELEASE_NOTES.md`, `scripts/package-bootstrap-release.sh`, `scripts/build-algokit-localnet-plugin-target.sh`, `scripts/stage-bundled-plugins.sh`, `scripts/docker-systemd-smoke.sh`, `scripts/docker-local-four-node-smoke.sh`, `plugins/algokit-localnet/`, `bootstrap-install.sh`, `install.sh`, `uninstall.sh`, `installer/`, `library/templates/` |

## Backup and Restore Ownership

For backup/restore specifically, `internal/backup` owns export packaging,
archive inspection, complete credential validation, the sealed credential-only
archive manifest, canonical-plaintext collision classification, and the staged
credential apply primitive. `internal/genstore` owns the generation commit protocol: mint,
staged validation, sealing of the outgoing generation, the durable `CURRENT`
flip, reconciliation of uncommitted attempts, rollback to the sealed parent,
and garbage collection of sealed priors. `internal/signerapp/backupadmin`
owns live direct restore, explicit restore rollback, and recovery-mode
reconciliation. A restore validates every selected credential before writing,
then commits them by minting one generation behind a single durable `CURRENT`
flip. Uncommitted attempts and staging
residue are discarded by generation reconciliation at unlock, never resumed.
A commit with unconfirmed durability, or a rollback that fails after mutation
began, transitions the runtime into recovery mode immediately and blocks
signing until the store reconciles cleanly.
Managed archives contain complete credential authority plus archive integrity
metadata and source node role. They exclude policy, approval defaults,
genesis-hash mappings, templates, endpoints, and operator settings. Destination
policy and configuration are always authoritative.

`apadmin` is the sole general-purpose CLI owner of this daemon-owned lifecycle
over local IPC or strict-known-host SSH. `cmd/apstore` retains local
`initialize`, external-backup validation, `verify`, policy integrity
check/sign/verify, private-store permission migration, offline generation
pruning and key inventory, and `rebuild` replacement-keystore rescue. Managed
backup import publication and export bytes are streamed through authenticated
admin transport. Imports are capped
at 1 GiB, only one incomplete import exists per identity, and startup removes
unpublished transfer residue. Archive chunk reads require unlocked or recovery
state but do not take the identity mutation lock.
Offline rebuild is deliberately distinct: it requires an absent identity,
creates a new keyring and node-role integrity state, and commits the restored
credentials as the first generation through `genstore.Mint`; it bypasses the
live daemon, admin authorization, and durable audit path. The wire and on-disk
compatibility rules remain in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md); the key/keytype lifecycle state model
is in [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
