# Engineering Specification

> Orientation map for engineers working on the APlane repository.
> For compatibility contracts (wire formats, on-disk formats, error mappings, and behavioral guarantees), see [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
> For the system-wide durable/runtime/wire data model, see [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md).
> For key and key type state machines, see [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
> For the principal/group/grant authorization model, see [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md).
> For the current signer policy verdict model, see [ARCH_POLICY.md](ARCH_POLICY.md).
> For network context tokens and transaction genesis-hash mapping, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
> For guarded signing and sentry node architecture, see [ARCH_SENTRY.md](ARCH_SENTRY.md).

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

Read [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) before changing
authorization-sensitive behavior:

- principals, groups, grants, and stable actions,
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
| `apsigner` | Signing daemon: HTTP API, admin protocol over IPC and SSH subsystem, key management, approval coordination, SSH tunnel server, audit logging |
| `apadmin` | TUI admin client over IPC or SSH admin transport |
| `apconsole` | Secure-machine console wrapper that hosts operator panes while preserving apshell/apadmin/apsigner interfaces |
| `apapprover` | Minimal approval-only CLI over IPC |
| `apstore` | Local keystore management client: local `initialize`, policy integrity check/verify/sign, public endpoint export, public sentry reference import/export/list, local `verify`, and local `rebuild` rescue flows; daemon-owned backup, restore, template, key type, and changepass operations use the admin protocol |
| `appolicy` | Offline policy checker/editor TUI that auto-targets the `policy.yaml` domain from the node role, plus scriptable save/check/export and signing-to-sentry-policy conversion while holding the store mutation lock |
| `appass` | Passphrase auto-unlock setup TUI |
| `aplocalnet` | LocalNet setup TUI/CLI for algod reachability, client (`apshell`) default-network config, signer genesis config, bundled plugin activation, and KMD plugin-env persistence |
| `compile_teal` | Dev/build helper that compiles TEAL source to generated Go bytecode via algod |
| `configdoc` | Config documentation generator |
| `appass-file` | Dev passphrase helper |
| `appass-systemd-creds` | Production passphrase helper |
| `approbe` | Installer/helper liveness probe for signer IPC reachability |
| `applugin-checksum` | Plugin integrity helper |

Documentation notes:

- `appass` owns passphrase setup and `apapprover` is the separate approval-only CLI.
- the repository uses `docs/`; `doc/` does not exist.

## Architecture Layers

| Layer | Packages |
|-------|----------|
| UI | `cmd/apshell`, `cmd/apconsole`, `internal/apshellcli`, `internal/shellrepl`, `internal/signerapp/signertui`, `cmd/appass`, `cmd/appolicy`, `internal/signerapp/policytui`, `internal/policyview`, `cmd/aplocalnet`, `internal/aplocalnet`, `cmd/apapprover`, `internal/command`, `internal/cmdspec`, `internal/cmdlog`, `internal/theme`, `internal/addressdisplay`, `internal/keytypeux` |
| Engine | `internal/apshellapp`, `internal/engine`, `internal/clientstate`, `internal/cache`, `internal/config`, `internal/engine/connect`, `internal/clientsign`, `internal/appresult`, `internal/appinput`, `internal/appspec`, `internal/asa`, `internal/addressbook`, `internal/refname`, `internal/keymgmt`, `internal/partkeyparse`, `internal/txnutil`, `internal/algo` |
| Signer App | `internal/bootstrap/signer`, `internal/signerapp/daemon`, `internal/signerapp/startup`, `internal/signerapp/runtime`, `internal/signerapp/identity`, `internal/signerapp/unlockconfig`, `internal/signerapp/signing`, `internal/signerapp/approval`, `internal/signerapp/templates`, `internal/signerapp/templateadmin`, `internal/signerapp/keyadmin`, `internal/signerapp/storeadmin`, `internal/signerapp/backupadmin`, `internal/signerapp/rest`, `internal/signerapp/admin`, `internal/signerapp/adminserver`, `internal/signerapp/svcerr`, `internal/signerapp/sshprovision`, `internal/signerapp/asametadata`, `internal/signerapp/audit`, `internal/signerapp/filewatcher`, `internal/signerapp/ipcbind`, `internal/signerapp/txdesc`, `internal/signerapp/policyruntime`, `internal/noderole`, `internal/policy`, `internal/signerapp/approvalpolicy` |
| Provider | `internal/signing`, `lsig/`, `internal/sentry`, `internal/keyclass`, `internal/lsig`, `internal/lsigprovider`, `internal/signingargs`, `internal/logicsigdsa`, `internal/genericlsig`, `internal/lsigsalt`, `internal/tealtemplate`, `internal/addressderive`, `internal/keytypecatalog`, `internal/keytypestate`, `internal/algorithm`, `internal/keygen`, `internal/mnemonic` |
| Storage/Crypto | `internal/crypto`, `internal/merklewhitelist`, `internal/keys`, `internal/keystore`, `internal/storepaths`, `internal/storelock`, `internal/signerapp/storemut`, `internal/storeinit`, `internal/storepass`, `internal/serverconfig`, `internal/defaultkeytypes`, `internal/clientdata`, `internal/signerapp/policyeditor`, `internal/templatestore`, `internal/templatelibrary`, `internal/templatepolicy`, `internal/backup`, `internal/security`, `internal/fsutil` |
| Integration | `internal/bootstrap/shell`, `internal/auth`, `internal/authz`, `internal/protocol`, `internal/adminproto`, `internal/transport`, `internal/sshtunnel`, `internal/clientenroll`, `internal/endpointrefs`, `internal/plugin`, `internal/scripting`, `internal/jsapi`, `pkg/signerapi`, `internal/signerapi`, `internal/signerclient`, `internal/tokenfile`, `internal/checksum`, `internal/manifest` |
| Tooling | `analysis/`, `test/arch`, `test/integration`, `internal/docassets`, `internal/xregistry`, `internal/signerprobe`, `internal/version` |

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

`apsigner` does not use `internal/engine`; it has its own server-side orchestration.

### Provider Layer

The provider layer supports multiple signing and LogicSig families:

- native Ed25519 in `internal/signing/ed25519`
- LogicSig DSA providers in `lsig/`
- provider metadata in `internal/algorithm`
- key generation in `internal/keygen`
- mnemonic support in `internal/mnemonic`
- unified LogicSig provider registry in `internal/lsigprovider`
- shared off-curve LogicSig salting in `internal/lsigsalt`

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

Persistent sensitive state is stored on disk and unlocked into memory only via a master key flow:

- encryption and secure memory: `internal/crypto`
- key file IO and scanning: `internal/keys`
- keystore abstraction and file-backed implementation: `internal/keystore`
- signer-store path ownership, mutation coordination, and cooperative locking: `internal/storepaths`, `internal/signerapp/storemut`, `internal/storelock`
- template storage: `internal/templatestore`
- plaintext template library parsing and install preparation: `internal/templatelibrary`
- template reload/registration outcome reporting: `internal/templatepolicy`
- backup/restore: `internal/backup`

### Storage, Key, And Template Package Clusters

Several package families have similar prefixes because they split compatibility-sensitive
state by responsibility rather than by a single "keystore" package. This is intentional;
do not consolidate these packages just to reduce the directory count. Use this map when
deciding where a change belongs:

| Cluster | Package | Role |
|---------|---------|------|
| `store*` | `internal/storepaths` | Canonical signer/client path construction for data directories, identities, keys, templates, config, and library locations. |
| `store*` | `internal/storelock` | Cooperative filesystem lock acquisition for signer-store mutation safety. |
| `store*` | `internal/signerapp/storemut` | Higher-level store mutation coordination around operations that rewrite identity/store files. |
| `store*` | `internal/storeinit` | Store initialization and bootstrap creation logic. |
| `store*` | `internal/storepass` | Passphrase-helper and passphrase-change support around store state. |
| `key*` | `internal/keys` | Encrypted key file payload/envelope IO, scanning, metadata, and key-file compatibility behavior. |
| `key*` | `internal/keystore` | File-backed keystore abstraction, master-key/session handling, and encrypted key persistence. |
| `key*` | `internal/keygen` | Signer-side key generation registry and generation result model. |
| `key*` | `internal/keymgmt` | Client/shell-facing key management request/result helpers. |
| `key*` | `internal/signingargs` | Shared internal model for signing-time LogicSig argument metadata projected into key files, signer cache records, and wire DTOs. |
| `key*` | `internal/keytypestate` | Identity-local key type state records for installed/disabled/activated template or provider definitions. |
| `key*` | `internal/keytypecatalog` | Key type catalog metadata assembled from registered providers and template records. |
| `key*` | `internal/keytypefmt` | Presentation-only key type formatting and publisher extraction. |
| `template*` | `internal/templatelibrary` | Plaintext signer-data template library parsing and install preparation. |
| `template*` | `internal/templatestore` | Encrypted identity-local `.template` storage, load, remove, and archive behavior. |
| `template*` | `internal/templatepolicy` | Template registration outcome vocabulary and reload/report policy helpers. |
| `signerapp/templates` | `internal/signerapp/templates` | Runtime reload coordinator that walks installed identity templates and registers provider implementations. |
| `signerapp/templateadmin` | `internal/signerapp/templateadmin` | Admin/use-case service for template library and installed-template operations. |

Rule of thumb:

- path/layout questions belong in `storepaths`, not in individual feature packages,
- lock/mutation ordering belongs in `storelock` or `storemut`,
- key file bytes and encrypted key payload compatibility belong in `internal/keys` and `internal/keystore`,
- key generation/provider registration belongs in `internal/keygen` and provider packages,
- installed-template file persistence belongs in `templatestore`; key type
  state writes belong in `templatelibrary` or `signerapp/templateadmin`,
- plaintext library import/refresh behavior belongs in `templatelibrary`,
- runtime template reload behavior belongs in `internal/signerapp/templates`,
- user/admin template workflows belong in `internal/signerapp/templateadmin`.

### Integration/Protocol Layer

This layer includes:

- HTTP auth and authorization vocabulary/interfaces: `internal/auth`
- grant-backed authorization decisions: `internal/authz`
- IPC/SSH admin wire protocol and envelope definitions: `internal/protocol`
- server-side admin protocol/session implementation: `internal/adminproto`
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
- integration harness under `test/integration`

The Go, TypeScript, and Python SDKs live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. This repo owns the signer HTTP API DTOs in
`pkg/signerapi` and the golden fixtures in `test/contracts/signerapi/` that the
SDK repo consumes for compatibility testing. `internal/signerapi` is an
in-repo alias layer over the public DTO types in `pkg/signerapi` (not error
codes); `pkg/signerapi/error_codes.go` remains the sole error-code source.
The SDK shape is native-client first: `SignerClient` wrappers expose APlane's
HTTP signing, planning, simulation, inventory, status, and cancellation APIs
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
- Zero or one product-mode `apadmin`/`apapprover` admin workflow for the exposed product identity, connected over local IPC or the SSH admin subsystem. Remote `apadmin` requires pre-enrolled client SSH config, `aplane.token`, and trusted `known_hosts`; enrollment and first-use host trust happen through standalone `apshell`.
- One or more `apshell` clients, local or via SSH tunnel. Interactive `apshell` is both the normal client shell and the enrollment/recovery surface: it may start before client enrollment is complete. Startup requires client config/bootstrap inputs, but not a pre-existing `aplane.token` or trusted signer host. Token presence and SSH host trust are enforced when interactive `apshell` attempts a signer connection or token provisioning flow, not before process startup. After successful interactive token provisioning, `apshell` immediately attempts to connect using the newly issued token. Token files are bearer credentials and are rejected if group/world accessible.
- `apshell --mcp` is a separate operational surface, not an enrollment or inspection surface. MCP startup is non-interactive and refuses to start unless the client is already enrolled (default signer endpoint, endpoint token, trusted endpoint `known_hosts`) and the startup signer connection succeeds. First-time enrollment and trust bootstrap happen through interactive `apshell`, not MCP.
- Optional `apconsole` wrapper on the secure signer machine, preserving the same apshell/apadmin/apsigner transport interfaces while composing operator panes. `apconsole` can load `apconsole.yaml` from the install root to determine local versus remote console mode and the client/signer data paths. Startup resolution is deterministic per field: flags win over environment variables, environment variables win over an explicitly selected profile, and an explicitly selected profile wins over auto-discovery. If explicit sources disagree, `apconsole` exits instead of guessing. In local signer mode, `apconsole` may start before client enrollment is complete because it owns or attaches the local signer/admin surfaces needed for first-time `request-token` approval; when the client SSH host is loopback, it probes the live loopback SSH endpoint before pinning the local signer's configured SSH host key into the client `known_hosts` file, and a mismatch aborts startup. Token presence is enforced when the embedded shell attempts `request-token`, `connect`, or startup auto-connect. In local sentry mode, `apconsole` does not create an embedded shell pane; it renders the signer admin pane above the daemon/status pane. In remote mode, `apconsole` preflights the client data directory and requires SSH config, an enrolled `aplane.token`, and a trusted signer host in the configured `known_hosts` before the UI starts. In local mode it attaches to an existing IPC socket or starts `apsigner -d <signer-data>` as a child it owns; the daemon pane reports disabled/attached/starting/ready/failed/exited status and streams owned-daemon logs. When present, the shell pane uses `internal/apshellcli.Session`, preserving apshell command behavior; Ctrl+C cancels a running shell command when the shell pane is focused, and shell `quit`/`exit` closes only that embedded shell pane. Operator controls are root-level function-key pane focus, F4 zoom, Shift+Left/Right pane navigation, and `?`/F5 help overlay.
- Optional plugin child processes spawned by `apshell`

Trust boundaries:

- apshell↔apsigner
- admin protocol over IPC or SSH admin subsystem ↔ apsigner
- apshell↔plugins
- encrypted disk↔unlocked memory

Private key material never leaves the signer device.

### Identity Model

Identity model: see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md) (Identity Model).

Identity plumbing rules specific to this spec:

- identity is a real cross-cutting dimension in the type model,
- code does not collapse identity scoping away, and the system does not claim strong tenant isolation beyond what is implemented,
- product-facing code routes single-operator assumptions through the product-identity helpers rather than scattering raw `"default"` assumptions,
- local IPC admin auth is product-identity scoped unless the transport has a pre-authenticated identity,
- SSH admin sessions can bind a non-product identity only when the SSH layer already authenticated that identity,
- HTTP request routing uses the token-authenticated identity and rejects missing or decommissioned runtimes,
- `auth.CurrentProductIdentityID()` is used at process boundaries only, not as a shortcut inside runtime-owned behavior.

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
identity file, `known_hosts`, token file, and endpoint-published sentry
inventory. `internal/endpointrefs` owns the public `aplane.endpoint.v1` JSON
handoff envelope used by `apstore endpoint export` and
`apshell endpoints import`.

`internal/config.Config` still has compatibility fields named
`LegacySignerPort` and `LegacySSH` with YAML tags `signer_port` and `ssh`, but
managed `apshell` startup calls `CheckSupportedClientEndpointConfig` and
rejects top-level `ssh:` signer routing in endpoint-routed client installs.
Those fields are retained for old command forms and narrow internal
materialization, not as the current routing contract.

### Server Configuration

`apsigner`, `apadmin`, `apstore`, and `appass` load `internal/config.ServerConfig` from:

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
`internal/signerapp/identity.StoredConfig`. The same file also carries
lifecycle state such as `decommissioned:true` for disabled identities. On
startup, stored runtime values overlay process-global defaults (nil/empty means
inherit), while `decommissioned:true` is treated as an explicit disable marker
rather than an inherited setting. Runtime reads resolve through the bound
identity runtime rather than directly from `ServerConfig`.

Key-class role is process/data-root scoped, not identity scoped. An initialized
signer data directory has a root `node.yaml` with exactly one role:
`signer` or `sentry`. New installs default to `signer` unless explicitly
initialized as sentry nodes. The role is immutable in supported tools, is
integrity-bound per identity with an HMAC sidecar over the exact root
`node.yaml`, and gates key generation, key import/restore, key scan, and HTTP
service dispatch. Identity config `mode` is an unsupported pre-release shape
and must be rejected rather than interpreted.

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
master key and loaded into the bound identity runtime on unlock/reload before
the key scan. Guided policy editing is implemented once in
`internal/signerapp/policytui` and used through two stores: `appolicy` edits the selected
domain offline while holding the store mutation lock, and `apadmin` edits the
active document online through the admin protocol while `apsigner` is running.
Both surfaces select the policy domain from the node role; store-backed
role-incompatible targets fail closed. Direct edits to `policy.yaml` are checked
and signed with `apstore policy`. Admin IPC policy messages are
target-aware (`signer|sentry`), validate replacements before writing, use
`expected_current_sha256` for optimistic concurrency, write the YAML plus a
fresh sidecar, and update the bound runtime immediately on success. The limited
admin policy settings payload remains a legacy scalar projection; YAML-only
fields such as `key_overrides` are edited through the shared full-document
editor and are visible in canonical YAML snapshots.

The policy document may contain YAML-only `key_overrides`; during normal
signing, the effective policy is selected by signing auth address, not by
transaction sender, so rekeyed accounts use the policy override for the auth
address. On sentry nodes, component signing selects overrides by the
txid-shaped Sentry Key ID from the sentry-domain `policy.yaml`.
Network-scoped policy derives transaction network identity from
`GenesisHash` through built-in and configured mappings; `GenesisID` is
display/diagnostic data, not the policy key.

Legacy signer ASA transfer guard editing uses signer-wide ASA metadata under `cache/<network>_asa_cache.json` in the signer data directory. Signer code reaches this cache through `internal/signerapp/asametadata.Store`, not by treating it as APCLIENT_DATA cache state. This metadata is shared by all identities because ASA metadata is public chain state, not identity-private state. Built-in ASA metadata is starter data for the same effective cache model; successful live algod lookups for numeric ASA IDs are persisted to the signed cache. Enforcement remains raw-unit and numeric-ASA-ID based, so the metadata cache is not authoritative for requiring review, accepting, or rejecting transactions.

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

`apsigner` startup resolves unlock config per identity: identity-scoped `unlock.yaml` takes precedence over the process-global `config.yaml` passphrase command. `appass` accepts `-identity <id>` to target a specific identity and defaults to `"default"`.

Configuration behavior and validation rules are compatibility-bearing and are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). The network context model and genesis-hash mapping rules are explained in [ARCH_NETWORKS.md](ARCH_NETWORKS.md).

## On-Disk Data Model

The concrete on-disk layouts, key-file compatibility, keystore metadata versioning, template files, audit log, and backup format are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

Operationally:

- client-local state lives under the client data directory, including plugins (`plugins.available/`, `plugins.yaml`), scripts (`scripts/`), token (`aplane.token`), caches (`cache/`), swap state (`swap/<network>/`), and the cooperative `.apclient.lock`,
- signer-local state lives under the signer data directory, with the plaintext key type library at `library/templates/`, signer-wide ASA metadata at `cache/<network>_asa_cache.json`, managed backup archives at `backups/<identity>/`, and all sensitive runtime assets rooted under `identities/<identity>/`,
- admin IPC binds the resolved `ipc_path` (default `<data_dir>/aplane.sock`),
- the effective layout is identity-scoped even though the default deployment uses only `"default"`.

## Security Model

### Authentication and Authorization

The system has two main auth channels:

- HTTP token auth for shell/API callers
- passphrase auth for admin sessions over IPC or the SSH `aplane-admin` subsystem

Optional SSH provides transport-level authentication for remote shell access, but HTTP requests require the API token.

Identity disable state is enforced at the transport boundary:

- decommissioned identities are skipped during HTTP token resolution,
- HTTP request routing rejects decommissioned runtimes before business logic executes,
- SSH token validation, authorized-key checks, and key enrollment all reject decommissioned identities.

Authorization is a separate concern through `auth.Authorizer`. Runtime code uses
the grant-backed authorization path documented in
[ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md). In product mode,
credentials map to the reserved `system:product-admin` principal
and bootstrap grants; authentication does not bypass authorization.

### Secret Handling

Important secret-handling contracts:

- passphrases are used to derive a master key and should be zeroed promptly,
- the file keystore caches the master key only while unlocked,
- individual keys are decrypted on demand, not fully preloaded,
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

`adminserver.SessionManager` stores active and pending sessions per identity.
Local IPC sessions start in a pre-auth pending slot and move to the product
identity after auth. SSH admin sessions may be pre-bound to the SSH-authenticated
identity before the admin protocol passphrase exchange. Displacement, pending
cleanup, lock-on-disconnect, approval delivery, and notification delivery are
identity-scoped internally. Product-mode clients operate against the
single exposed product identity.

Locking clears the active master key and deactivates the key session. Local
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
| Admin protocol, session state, message dispatch | `internal/adminproto` |
| Identity runtime, config, token, SSH enrollment, lifecycle | `internal/signerapp/identity` |
| HTTP contract types (request/response DTOs) | `pkg/signerapi` with `internal/signerapi` aliases |
| Startup composition, path threading | `internal/bootstrap/signer`, `internal/bootstrap/shell` |
| Keystore paths | `internal/storepaths.Paths` value types (no process-global setters) |
| Cache paths | `cache.Store` value types |

`cmd/apsigner` is the HTTP/IPC adapter layer and wires subsystems together. Signer-side application failures use typed `ServiceError` values mapped to HTTP status at the adapter edge. Signer request lifecycle state is owned below the HTTP layer: `pkg/signerapi` defines the request/cancel DTOs, `cmd/apsigner` routes `/sign` and `/sign/cancel`, `internal/signerapp/rest` binds live `/sign` request IDs to identity runtimes, `internal/signerapp/approval` owns pending/canceled lifecycle state, and `internal/signerclient` is the repo-owned client that creates request IDs and sends explicit cancellation.

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

`apsigner` discovers identity directories under `identities/`, filters out `decommissioned:true`, constructs an `identity.Runtime` per surviving identity.

Before normal startup option loading, `apsigner` rejects manual startup from a
signer data directory containing `.prod` unless the process is systemd-managed.
Systemd-managed means `APLANE_SYSTEMD_MANAGED=1` or parent PID 1. This guard is
checked before locked/headless/test startup mode selection.

Implemented startup modes:

- locked startup with later unlock through an authenticated admin session,
- headless unlocked startup via passphrase command,
- test unlocked startup via `TEST_PASSPHRASE`,
- forced locked startup when keystore metadata does not exist.

Both locked and headless paths converge through `reloadKeysLocked`, which:

1. initializes or reuses the master key,
2. registers templates,
3. scans keys,
4. replaces runtime indexes,
5. activates the key session,
6. emits audit and IPC notifications.

Template scan precedes key scan so generation/discovery state is current.
LogicSig key files carry their own bytecode and signing arg contract, so
signing an existing key does not depend on the installed template definition.
The complete key file and key type state machines are documented in
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
LogicSig key files without `salt_counter`, or whose stored bytecode derives an
on-curve address, are rejected during key scan. LogicSig key files without
`signing_metadata_version` are rejected when signing or restore would need
durable signing metadata. Key files with `signing_metadata_version >= 1` are
**v1 signing-metadata keys**; DSA LogicSig files in that form persist
`base_key_type` even when it equals `key_type`. The stored bytecode must derive
an off-curve LogicSig address.

### Server Primary In-Memory State

The main server struct is `Signer`, which owns:

- identity registry / process root composition,
- authn/authz components,
- signer-side planning/approval/execution service adapters,
- IPC server,
- optional SSH server,
- config and data-dir references.

Sensitive per-identity state lives under `internal/signerapp/identity.Runtime`, including:

- `keySession`,
- identity-scoped `keys`, `keyTypes`, `keyLsigSizes`,
- signer runtime owner,
- approval coordinator,
- watcher lifecycle,
- identity-scoped config,
- token authority and SSH enrollment state,
- lifecycle/decommission state.

The key indexes are authoritative runtime indexes of what the server believes is signable.

### Lock Hierarchy

| Lock | Protects |
|------|----------|
| `Signer.configMu` | Mutable process-global `ServerConfig` fields exposed through admin settings, including theme, SSH listen address, and endpoint advertise URL |
| `Signer.configMutationMu` | Process-owned `config.yaml` write serialization |
| `Signer.storeMutationMu` | Map of per-identity mutation locks |
| `Signer.storeMutationLocks[identityID]` | Identity-owned key/template/config/policy mutation serialization |
| `Signer.restoreAttemptMu` | Lazy initialization of the per-identity/archive restore backoff limiter |
| `identity.Runtime.keysLock` | `keys`, `keyTypes`, `keyLsigSizes` |
| `identity.Runtime.passphraseLock` | `keySession`, `reloadFn`, unlock-sensitive ops |
| `identity.Runtime.watcherMu` | Watcher lifecycle, dirty state |
| `identity.Runtime.lifecycleMu` | Decommission vs in-flight operation leases |
| `identity.Runtime.decommissioned` | `atomic.Bool` — lifecycle disable |
| `identity.Runtime.approval` | `atomic.Pointer` — approval coordinator |
| `Runtime.stateMu` | Signer locked/unlocked state |
| `Coordinator.pendingRequestsLock` | Pending sign approvals |
| `Coordinator.pendingTokenRequestsLock` | Pending token provisioning approvals |
| `IPCServer.writeMu` | Serializes outbound IPC JSON writes |
| `adminserver.SessionManager.mu` | Per-identity admin session registration/displacement |
| `AuditLogger.mu` | Audit file writes |
| SSH server locks | Authorized keys, token callbacks, identity-scoped connections, listener |

Goroutines:

- HTTP server plus per-request handler goroutines,
- IPC accept loop plus per-client goroutines,
- file watcher goroutine,
- SSH server accept loop plus per-connection goroutines.

### Lock/Unlock Lifecycle

Unlocking must:

- verify passphrase against `.keystore`,
- derive the master key,
- initialize the key store,
- scan templates before key scanning where needed,
- scan keys and populate indexes,
- mark the key session active,
- update signer runtime state,
- optionally start key watching.

Locking must:

- clear master key material,
- destroy the key session state,
- clear or invalidate key caches as appropriate,
- notify interested IPC clients.

The watcher model is identity-owned but not tied to every lock transition:

- when an identity is unlocked, the watcher reloads immediately on qualifying filesystem changes,
- when an identity is locked, the watcher remains active and marks the identity dirty,
- the next unlock reconciles dirty state by reloading,
- watchers are stopped on runtime shutdown and decommission, not on every ordinary lock.

Watcher-triggered reloads acquire the same per-identity mutation lock used by
admin template/key/config mutations. Admin mutation paths that already hold the
lock call `Reload` directly; watcher paths use the watcher reload entrypoint so
they do not re-enter the same lock.

Runtime decommission is logical disablement, not data deletion. `Registry.Remove`
prevents future lookup only; an in-flight request may still hold a runtime
pointer. The runtime's `BeginOperation`/`Decommission` lease is the final
signing stop signal: if final execution has not acquired the lease,
decommission wins and signing fails; if execution already holds the lease,
decommission waits for release before completing.

### Server-Side Application Boundary

The server-side plan/sign boundary is split as follows:

- startup option resolution, validation, identity assembly, and lifecycle entrypoint in `internal/signerapp/startup`,
- transport adapters/builders for HTTP, IPC, and SSH in `cmd/apsigner`,
- server-side admin protocol/session state machine in `internal/adminproto`,
- process-root identity-targeted admin facade for server-originated admin traffic in `internal/adminproto.AdminHub` and `internal/signerapp/daemon/admin_hub.go`,
- signer-backed admin protocol services in `internal/signerapp/daemon/admin_services.go`,
- admin settings and policy service composition in `internal/signerapp/admin`,
- admin key-mutation HTTP/IPC transport mapping in `internal/signerapp/daemon/http_handlers_admin.go` and `internal/signerapp/daemon/admin_services.go`, with reusable key operations in `internal/signerapp/keyadmin`,
- IPC bind-path validation in `internal/signerapp/ipcbind`,
- filesystem key/template reload watching in `internal/signerapp/filewatcher`,
- REST service composition for signing, planning, simulation, key administration, and generic LogicSig generation in `internal/signerapp/rest`,
- signer runtime state and lifecycle management in `internal/signerapp/runtime`,
- sign request lifecycle, cancellation, and approval queue ownership in `internal/signerapp/approval`,
- planning, approval flow, execution, simulation, and top-level sign orchestration in `internal/signerapp/signing`,
- signer transaction description formatting in `internal/signerapp/txdesc`,
- template registration and reload lifecycle in `internal/signerapp/templates`,
- template library, install, show, import, remove, activate, and deactivate workflows in `internal/signerapp/templateadmin`,
- SSH token provisioning approval and audit service in `internal/signerapp/sshprovision`,
- append-only audit logging in `internal/signerapp/audit`, with HTTP/request attribution and operational side effects wired from `cmd/apsigner`.

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

Client simulate mode is a signed preflight for signer-managed transactions.
`internal/clientsign.SignAndSubmitViaGroup` builds the normal server-shaped
requests and sends them to signer `/simulate`, so the signer performs the same
group-shaping work used by real submission: dummy transaction insertion, fee
pooling, group-ID assignment, network/genesis validation, hard-policy validation, and
simulation-only signing. apsigner then calls algod simulate using the algod
configuration for the transaction group's genesis/network and does not enable
empty-signature bypasses. This makes LogicSig policy checks, including template
runtime args, match real execution.

For both simulate and submit paths, `SignAndSubmitViaGroup` returns the
post-planning submitted transaction objects so callers and `txnjson` output
describe the exact transaction slots sent to algod rather than the caller's
pre-signing drafts.

This boundary matters because reusable signed transaction msgpack can be
submitted normally until the validity window expires. `/simulate` keeps those
bytes inside apsigner and returns only txids, final unsigned transaction bytes,
mutation metadata, and simulation diagnostics. Mixed plugin/server-managed
groups still use `/plan` first so plugin-owned slots can be signed locally from
canonical bytes, then use `/simulate` with passthrough plugin signatures for
the full real-signed preflight. All-plugin groups assign group IDs and sign
locally before local algod simulation without contacting the signer.

## Client Ownership Model

| Concern | Owner |
|---------|-------|
| Shell application use-cases and command semantics | `internal/apshellapp` |
| Business operations, transaction orchestration | `internal/engine` |
| Cache-backed client state and alias/set mutation | `internal/clientstate` |
| Persisted alias/set name validation and normalization | `internal/refname` |
| Address/key-type terminal display formatting | `internal/addressdisplay` |
| Signer connection, tunnel lifecycle, signer-facing HTTP | `internal/engine/connect` |
| Signer HTTP client (plan, sign, simulate, keys) | `internal/signerclient` |
| Structured result + MCP projection | `internal/appresult` |
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
- MCP output capture/fallback behavior.

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

The shell has a dual-rendering model:

- human-oriented text rendering,
- machine-oriented JSON rendering for MCP and automation.

This is implemented through `CommandResult` types in `internal/apshellcli` and
semantic result types from `internal/apshellapp`, not by parsing terminal
output.

- business operations return structured results first,
- text rendering is a presentation layer,
- MCP mode uses stdout capture only as a compatibility fallback.

### Command Surface

The `apshell` command surface is itself a compatibility-sensitive operator surface.

First-class built-in command families include:

- transaction commands: `send`, `sweep`, `sign`, `optin`, `optout`, `keyreg`, `close`, `validate`
- information commands: `balance`/`bal`, `holders`, `participation`, `asa`, `help`/`h`, `status`, `accounts`, `info`, `plugins`
- app commands: `app`
- alias/set commands: `alias`, `sets`
- rekey commands: `rekey`, `unrekey`
- signer/key-management commands: `keys`, `keytypes`, `generate`, `delete`
- config/toggle/connectivity/session commands: `network`, `write`, `verbose`, `simulate`, `config`, `connect`, `request-token`, `clear`/`cls`, `quit`/`exit`/`q`
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

Sentry key types are raw component-signing keys, not spending
accounts and not LogicSig providers:

- `aplane.sentry-ed25519.v1`
- `aplane.sentry-falcon1024.v1`

They are selected by 52-character uppercase, no-padding base32 Sentry Key IDs
derived as:

```text
base32_no_padding(SHA512_256(
  "APLANE_COMPONENT_KEY_V1" || 0x00 || key_type || 0x00 ||
  canonical_public_key_bytes
))
```

The Sentry Key ID intentionally has the visual shape of an Algorand transaction ID,
but it is not a valid Algorand address because addresses are 58 characters.
The full sentry public key remains the verifier key embedded in guarded
account LogicSig bytecode.

Guarded account key types name both the account DSA and the sentry DSA:

- `aplane.falcon1024-sentry-ed25519.v1`
- `aplane.falcon1024-sentry-falcon1024.v1`

A guarded account key file stores the resolved `sentry_public_key` and the
LogicSig bytecode embeds that same public key. `/sign` rejects guarded-account
key types and sentry key types. Guarded accounts are signed only
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

The client first builds one canonical group. It sizes LogicSig-budget dummies
across every LogicSig position from signer-advertised `lsig_size`, including
non-guarded positions budgeted by effective signer/AuthAddr, then fixes fees
and group ID. `lsig_size` is the expected post-signing LogicSig program plus
args budget: bytecode plus cryptographic signature args and any runtime or
signer-generated args such as proof material. All downstream component and
non-guarded signatures are over those frozen bytes.

For guarded targets, the client obtains component signatures:

1. user signer `/sign/component` with role `user`,
2. sentry signer `/sign/component` with role `sentry`.

The user-role component request proves the user signer controls the
guarded effective signer. The sentry-role component request evaluates
decoded target transaction facts against sentry-domain `policy.yaml` and returns
sentry component signatures when allowed.

If the original group also has non-guarded positions, the client then calls the
primary signer `/sign` over the full canonical group: non-guarded originals are
sign-mode entries, guarded targets are `foreign` entries with accurate
authorizer `lsig_size` hints, and client-signed dummies are `foreign` context entries. This
keeps the complete group in approval context and lets the signer's existing
budget check reject client mis-sizing before algod evaluation.

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
known-hosts path, SSH identity path, and endpoint-local
`published_sentries`.

Operator handoff and manual endpoint setup use two paths:

- `apstore endpoint export` emits `aplane.endpoint.v1` with portable endpoint
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

Sentry inventory is discovered explicitly with
`apshell endpoints sync-sentries`. It queries authenticated `/keys` on
configured sentry endpoints, validates Sentry Key ID metadata, and rebuilds
reachable endpoints' `published_sentries` inventory. Temporarily unavailable
or locked endpoints preserve their prior local inventory; authentication
failures, malformed responses, duplicate public keys across endpoints, and
Sentry Key ID validation errors are hard failures that leave files unchanged.
After discovery, the command prints Sentry Key IDs and asks before syncing the
public inventory into the connected signer identity's sentry reference
library for generation-time selection.

Runtime guarded-send routing maps the embedded sentry public key to the
endpoint whose `published_sentries` contains that key. If no explicit mapping
exists, local self-discovery may resolve to the currently connected signer only
when that endpoint advertises the matching Sentry Key ID; this is
development ergonomics, not a production independence claim.

### Policy And Audit

Signer nodes use `policy.yaml` for account signing. Sentry nodes also use
`policy.yaml`, parsed in the sentry policy domain, for sentry component
signing. Both domains use the shared policy grammar and HMAC sidecar model, but
sentry policy has no manual-review or operator-default verdict. It is
deterministic authorization: all selected target movements must be positively
authorized by the effective sentry policy, and deny guards fail closed.

Sentry policy overrides are keyed by Sentry Key ID.
Client-signing policy overrides are keyed by signing auth address.

Sentry component approvals and rejections are recorded through existing sign
audit events. Current records put the Sentry Key ID in `txn_auth`, the
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
  Sentry Key ID validation, and DSA mapping.
- `internal/signerapp/signing`: signer-side component signing, sentry policy
  evaluation, and assembly.
- `internal/signerapp/rest`: HTTP handlers for `/sign/component` and
  `/sign/assemble`.
- `internal/engine`: client guarded-send orchestration and endpoint
  resolution.
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

Key type identifiers use the canonical form `publisher.family.vN` for APlane-defined LogicSig, template, and compiled-provider key types, and the single-segment built-in `ed25519` for native signing keys. The full contract lives in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Key Type Identifier Contract).

## Keystore and Key Lifecycle

`internal/keystore.FileKeyStore` is the concrete keystore implementation in active use.

It owns:

- identity-scoped key directory resolution,
- master key derivation and caching,
- decrypted scan metadata cache,
- on-demand decryption for specific addresses.

The keystore compatibility model is split between:

- `.key` file envelope/payload compatibility for individual entries,
- `.keystore` metadata compatibility for master-key verification and KDF parameters.

A scan:

- requires an initialized master key,
- decrypts keys sufficiently to discover address, type, category, the
  post-signing LogicSig program+args size budget, and stored signing metadata,
- populates a cache of `address -> KeyScanInfo`,
- is the foundation for the signer’s runtime key indexes.

`internal/keystore.KeySession` is a thin runtime guard around a keystore. It tracks whether signing operations are permitted and delegates actual key retrieval to the keystore.

This split means:

- lifetime policy lives above raw storage,
- decryption remains on-demand,
- signer lock state is modeled as master-key availability plus session activity.

Offline mutation rules are compatibility-sensitive and are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Plugin System

External plugins are separate processes discovered at runtime. `apshell` spawns them lazily and talks JSON-RPC over stdin/stdout.

Key characteristics:

- plugin processes are isolated from signer key material,
- network access is allowed because plugins often need algod, KMD, or indexer access,
- plugin manifests are mandatory,
- plugin integrity checks are mandatory.

Plugin payloads live under `$APCLIENT_DATA/plugins.available`, and
`$APCLIENT_DATA/plugins.yaml` is the activation source of truth. The supported
plugin runtime model is command-first even though manifests may also carry typed
JS function metadata.

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
- plugin commands/functions,
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
- architecture guard tests in `test/arch` that pin signer/client layering,
  family-agnostic core-package imports, and guarded signing route selection on
  runtime `signing_flow` metadata,
- dedicated test harness packages,
- analysis tools for security properties,
- signer API and SDK contract tests backed by JSON fixtures in `test/contracts/signerapi/`.
  These fixtures pin SDK-exposed HTTP DTOs, including signer-managed
  `/simulate` response shape. SDK package tests are owned by the external
  `aplane-algo/aplanesdk` repository; that repository also owns cross-language
  prepared-request parity fixtures for the SDK prep layer. `/status` is
  SDK-facing because clients use `keyset_revision` for refresh decisions and
  `approval_wait_seconds` for sizing `/sign` deadlines.
- machine-checkable TLA+ models under `docs/formal/`, run locally with
  `make formal-test` and in CI by the Formal Models job. The target checks the
  `sign_boundary`, `policy_precedence`, `composition`, and `lifecycle` TLC
  modules and requires `tla2tools.jar` through `TLA2TOOLS_JAR` or one of the
  Makefile's default jar search paths.

`make integrity-check` is the broad verification target. It chains formatting,
vet, module-tidy, lint/dead-code/security checks, race tests, cross-builds,
smoke tests, contract tests, integration tests, and a clean-tree check.

Docker-backed install and topology smoke targets are separate release workflow
guards:

- `make docker-systemd-test` runs `scripts/docker-systemd-smoke.sh` against a
  fresh Ubuntu systemd container and verifies systemd install/uninstall state.
- `make docker-local-test` runs `scripts/docker-local-four-node-smoke.sh`
  against signer, sentry, client/admin, and LocalNet algod containers on one
  Docker network. It verifies local install layout, shared LocalNet
  reachability, SSH token provisioning, client signer reachability, guarded
  signing, and corridor whitelist enforcement across the Docker network.

The integration harness behavior is part of the effective repository contract:

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
- on-disk compatibility is checked for `.keystore`, `.key`, `.template`, `config.yaml`, `audit.log`, and token files.
- client endpoint compatibility is checked for `endpoints.yaml`,
  endpoint token files, endpoint handoff envelopes, and public sentry
  reference records when those surfaces change.

## Authentication

- HTTP: token auth (`Authorization: aplane <token>`). The token resolves the
  authenticated identity and HTTP handlers route to that identity's runtime.
- IPC: passphrase auth. Product-mode local IPC binds to the product identity;
  explicit non-product identity selection is rejected unless the transport was
  pre-bound to that identity.
- SSH: dual-factor for tunnel/admin connections — API token as SSH username plus
  a public key enrolled for the token identity under
  `identities/<identity>/.ssh/authorized_keys`. Token provisioning flow exists
  for new client enrollment via admin approval.

Decommissioned identities are rejected at all transport boundaries.

## Approval Model

See [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) (Approval and Policy Contracts) for the approval contract.

## SSH, Watching, Templates, and Audit

The SSH tunnel is implemented in `internal/sshtunnel`. It provides:

- an SSH server embedded in `apsigner` that forwards TCP connections to the local REST API,
- SSH clients in `apshell` and the external Go SDK that establish the tunnel.

Watcher, template reload, audit logging, token provisioning, token revocation, and backup/restore contracts are documented in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

Architecturally:

- watcher ownership is per identity runtime,
- template registration precedes key scan for generation/discovery,
- signer-data library templates are authoritative install sources when present,
  and same-`key_type` template mutation is rejected rather than applied on
  reload/unlock,
- audit logging is a signer-side operational subsystem, not a UI concern,
- token provisioning is an approval-mediated enrollment path, not just SSH auth,
- token provisioning and SSH token revocation are identity-scoped internally:
  provisioning requires an admin session for the requested identity, and token
  rotation closes only SSH connections authenticated for that identity.

## Architectural Invariants

1. Signer-managed private keys never leave `apsigner`.
2. Unlock state = master-key availability + active session state.
3. Engine code is independent of UI parsing/formatting.
4. Provider registration is explicit at startup via `RegisterProviders()` / `lsig.RegisterClient()` / `lsig/signerreg.RegisterSigner()`.
5. Versioned key types are stable identifiers across storage, UI, and protocol.
6. IPC messages are line-delimited JSON with typed message contracts.
7. `/sign` and `/plan` share canonical group-shaping rules.
8. Plugins are process-isolated with no direct keystore access.
9. Offline keystore mutations (`apstore`) are guarded by the store lock, not transport-specific liveness probes.
10. Identity scoping is present in storage and request models.
11. Product UI/docs are single-operator.
12. Registry lookup does not own runtime lifecycle; runtime decommission is the stop signal for in-flight work.
13. File mutations and watcher reloads for one identity share the same per-identity mutation lock.
14. Pure shell binaries register only client-safe providers; binaries that own admin, store mutation, or local signer composition (`apsigner`, `apconsole`, `apadmin`, `apstore`) additionally register the signer-side keygen, sign, and mnemonic registries through `lsig/signerreg.RegisterSigner()` and `internal/signing/ed25519.RegisterSigner()`.
15. LogicSig key files are the signing authority: every signable LogicSig key file is a v1 signing-metadata key. Signing and restore reject files without `signing_metadata_version`; templates and live providers are not consulted to reconstruct missing signing metadata.
16. Every persisted LogicSig key file has an off-curve address. LogicSig key files without `salt_counter`, or whose stored bytecode derives an on-curve LogicSig address, are rejected on load.

## Architectural Seams

Strong existing seams:

- `internal/engine` as the client business boundary
- `internal/apshellapp` as the shell application boundary between `cmd/apshell` and `internal/engine`
- `internal/clientstate` for client-side cache state and mutation ownership
- `internal/engine/connect` for remote signer connection state, lifecycle, and signer-facing request flow
- `internal/appresult` for shared shell/MCP structured result and projection ownership
- `internal/config` for configuration normalization
- `internal/keystore` for storage/session separation
- `internal/protocol` for IPC contract centralization
- `internal/adminproto` for server-side admin session state, dispatch, and handler ownership
- `internal/lsigprovider` and provider registries for algorithm extensibility
- `internal/plugin` for plugin lifecycle isolation

Weaker or more coupled areas:

- `cmd/apsigner` owns some operational glue, final transport adaptation, and startup/operator logging,
- `internal/engine` contains some direct cache/result shaping concerns,
- plugin manifests carry dual-surface complexity because typed function metadata exists alongside a command-first runtime contract,
- shell command handling mixes structured results and stdout capture fallback,
- the runtime core is identity-owned, but the operator/control-plane surface is single-identity/single-operator in product mode, even though that product admin workflow may arrive over IPC or the SSH `aplane-admin` subsystem.

Product-level boundaries:

- identity-scoped storage, sessions, approval routing, and token plumbing exist,
  with a single-operator deployment model,
- plugin manifests expose typed JS metadata, with a command-first executable contract,
- template files are identity-scoped and encrypted; `key_type` is an immutability boundary rather than an override hook,
- shell command execution supports both structured results and text capture fallback.

## Key Entry Points

| Area | Files |
|------|-------|
| Server | `cmd/apsigner/main.go`, `internal/signerapp/daemon/server.go`, `internal/signerapp/startup/*.go` |
| Client | `cmd/apshell/main.go`, `internal/apshellcli/registry.go`, `internal/apshellcli/mcp.go`, `internal/apshellcli/status_poll.go`, `internal/shellrepl/*.go` |
| Client Enrollment / Remote Preflight | `internal/clientenroll/preflight.go`, `cmd/apconsole/preflight.go`, `cmd/apadmin/remote.go` |
| Shell App | `internal/apshellapp/app.go`, `internal/apshellapp/runtime.go`, `internal/apshellapp/connect.go` |
| Engine | `internal/engine/engine.go`, `internal/engine/status_sync.go`, `internal/engine/connect/state.go` |
| Signing | `internal/signerapp/signing/service.go`, `internal/signerapp/signing/planner.go`, `internal/signerapp/signing/planner_runtime.go`, `internal/signerapp/signing/execution.go`, `internal/signerapp/signing/approval.go`, `internal/signerapp/signing/simulation.go` |
| Key Admin | `internal/signerapp/keyadmin/service.go`, `internal/signerapp/keyadmin/admin_ops.go`, `internal/signerapp/keyadmin/generic_lsig.go` |
| KeyType Library | `internal/signerapp/templateadmin/service.go`, `internal/templatelibrary/library.go`, `internal/templatestore/store.go`, `internal/keytypestate/state.go`, `internal/storepaths/paths.go`, `internal/signerapp/daemon/admin_services.go` |
| Store/Backup Admin | `internal/signerapp/storeadmin/service.go`, `internal/signerapp/backupadmin/service.go`, `internal/signerapp/backupadmin/limiter.go`, `internal/backup/*.go` |
| LSig Providers | `lsig/all.go`, `lsig/signerreg/register.go`, `internal/lsig/wrapper.go`, `internal/lsigprovider/provider.go`, `internal/signingargs/types.go`, `internal/lsigsalt/salt.go`, `lsig/falcon1024/v1/standard.go`, `lsig/falcon1024_ed25519/provider.go`, `lsig/falcon1024_ed25519/register.go`, `lsig/falcon1024_ed25519/signerops/ops.go`, `lsig/falcon1024_guarded/provider.go`, `lsig/falcon1024_guarded/register.go`, `lsig/ed25519lsig/register.go`, `lsig/ed25519lsig/signerreg/register.go`, `lsig/ecdsak1/register.go`, `lsig/ecdsak1/signerops/ops.go`, `lsig/ecdsak1/v1/standard.go`, `lsig/falcon1024/signerops/ops.go`, `lsig/dsafamily/register.go`, `lsig/generictemplate/provider.go`, `lsig/composeddsa/composer.go`, `lsig/corridor/provider.go`, `lsig/corridor/register.go`, `lsig/corridor/signerreg/register.go`, `lsig/sentryaccount/sentryaccount.go`, `internal/merklewhitelist/whitelist.go`, `internal/tealtemplate/legacy_list.go`, `internal/tealtemplate/template.go` |
| Protocol | `internal/protocol/messages.go`, `internal/signerapp/svcerr/svcerr.go`, `internal/signerapp/adminserver/dispatch.go`, `internal/signerapp/adminserver/displacement.go`, `internal/adminproto/stream_conn.go` |
| Config | `internal/config/config.go`, `internal/serverconfig/serverconfig.go`, `internal/config/networkid.go`, `internal/config/genesishash.go` |
| LocalNet Setup | `cmd/aplocalnet/main.go`, `internal/aplocalnet/setup.go`, `plugins/algokit-localnet/algokit-localnet.go`, `plugins/algokit-localnet/manifest.json` |
| Policy | `internal/policy/config.go`, `internal/policy/store.go`, `internal/policy/integrity.go`, `internal/crypto/policy_integrity.go`, `internal/signerapp/policyruntime/policy.go`, `internal/policy/lint.go`, `internal/policy/review.go`, `internal/signerapp/signing/always_review.go`, `internal/signerapp/signing/service.go`, `internal/signerapp/admin/service.go`, `cmd/apstore/policy.go`, `internal/templatepolicy/outcome.go` |
| Keystore | `internal/keystore/file.go`, `internal/keystore/session.go` |
| Node Role / Key Class | `internal/noderole/role.go`, `internal/noderole/integrity.go`, `internal/keyclass/keyclass.go`, `internal/sentry/keytypes/keytypes.go` |
| Store Init/Passphrase | `internal/storeinit/initialize.go`, `internal/defaultkeytypes/defaults.go`, `internal/storepass/rotate.go`, `internal/signerapp/unlockconfig/unlock.go`, `cmd/apstore/main.go`, `internal/signerapp/daemon/admin_services.go` |
| Client Data | `internal/clientdata/lock.go`, `internal/clientstate/state.go`, `internal/refname/refname.go` |
| Identity | `internal/signerapp/identity/runtime.go`, `internal/signerapp/identity/config.go` |
| Release/Distribution | `Makefile`, `.github/workflows/release.yml`, `scripts/package-bootstrap-release.sh`, `scripts/build-algokit-localnet-plugin-target.sh`, `scripts/stage-bundled-plugins.sh`, `scripts/docker-systemd-smoke.sh`, `scripts/docker-local-four-node-smoke.sh`, `plugins/algokit-localnet/`, `bootstrap-install.sh`, `install.sh`, `uninstall.sh`, `installer/`, `library/templates/` |

## Backup and Restore Ownership

For backup/restore specifically, `internal/backup` owns export packaging and
restore-time resolution/mutation policy: authoritative local template
precedence for explicit template restore and bundled-template conflict checks,
import-time bundled template/key bytecode reproduction validation, LogicSig
signing-metadata validation, compiled-provider activation, and per-key rollback
if the final key-file write fails. Managed backup archives also carry a verified
policy snapshot under `policy/`, but restore paths do not install that snapshot
as active policy. `cmd/apsigner` owns the live daemon restore path for both
`apadmin` and local-IPC `apstore` restore commands. `cmd/apstore` retains the
local `initialize` path, local `backup import` admission check, `verify`
inspection command, policy integrity check/sign/verify commands, and `rebuild`
replacement-keystore rescue path. The wire and on-disk compatibility rules remain in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md); the key/keytype lifecycle state model
is in [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
