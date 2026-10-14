# Engineering Contracts

> Index of APlane's compatibility-bearing contracts. Each contract lives in the
> document that owns its subject; this index says where. The compatibility scope
> and the configuration contracts, which have no other owner, are kept here.
> For system orientation, ownership, and architecture, see [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md).

## Contents

- [Where Each Contract Lives](#where-each-contract-lives)
- [Current Release Compatibility Scope](#current-release-compatibility-scope)
- [Configuration Contracts](#configuration-contracts)

## Where Each Contract Lives

| Contract | Owner |
|---|---|
| HTTP API wire shapes, status codes, `/sign/cancel` | [ARCH_SIGNING.md](ARCH_SIGNING.md#http-api-contract) |
| Error model | [ARCH_SIGNING.md](ARCH_SIGNING.md#error-model) |
| SDK contracts | [ARCH_SIGNING.md](ARCH_SIGNING.md#sdk-contracts) |
| Admin protocol, admin error codes, admin client capabilities | [ARCH_ADMIN.md](ARCH_ADMIN.md#admin-protocol-contract) |
| apshell parsing | [ARCH_SHELL.md](ARCH_SHELL.md#parsing-contracts) |
| Signer data directory layout and store formats (store root, term envelopes, managed credential files, key type records, template files, stage address tables) | [ARCH_STORE.md](ARCH_STORE.md) |
| Generations, reload, key watching, backup and restore | [ARCH_STORE.md](ARCH_STORE.md) |
| Client data directory layout, endpoint registry, client caches | [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md#client-data-model) |
| Policy document format and storage | [ARCH_POLICY.md](ARCH_POLICY.md#the-boundary) |
| Approval and policy verdicts | [ARCH_POLICY.md](ARCH_POLICY.md#verdict-model) |
| Approval waits and cancellation | [ARCH_SIGNING.md](ARCH_SIGNING.md#approval-waits-and-cancellation) |
| Native Falcon authorization and consensus resources | [ARCH_SIGNING.md](ARCH_SIGNING.md) |
| Authentication, SSH, client enrollment, revocation | [ARCH_SECURITY.md](ARCH_SECURITY.md#ssh-tunnel-transport-layer) |
| Audit log | [ARCH_SECURITY.md](ARCH_SECURITY.md#audit-logger) |
| Cosigner component message and canonicalization, cosigner key file, public key reference library | [ARCH_GUARDED.md](ARCH_GUARDED.md) |
| `bounded1` authorization, external contract-admin artifact, ceremony, and inventory | [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) |
| Key type identifiers | [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#key-type-identifier-contract) |
| Network context tokens and genesis hashes | [ARCH_NETWORKS.md](ARCH_NETWORKS.md) |
| Plugin contract | [ARCH_PLUGINS.md](ARCH_PLUGINS.md) |
| MCP tool contract | [ARCH_SHELL.md](ARCH_SHELL.md#tool-surface) |
| Runtime ownership and shutdown | [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md#lockunlock-lifecycle) |
| Standalone swap client | [ARCH_OVERVIEW.md](ARCH_OVERVIEW.md#standalone-swap-client) |

## Current Release Compatibility Scope

### Fixed Product Store Boundary

An `apsigner` process owns exactly one signing-state aggregate and one product
store. The aggregate has no runtime ID, registry, or selector. The durable
roots are `identities/default/` and `backups/default/`; `default` is the fixed
directory name, not an authorization principal or request value.

Startup performs a no-follow check of direct `identities/` entries before it
loads the client registry, keys, policy, or watchers. A directory, ordinary file, hidden
entry, or symlink with any name other than `default` is rejected. An existing
`default` entry must be a real directory and not a symlink. A missing
`identities/` tree or missing `default` uses the explicit blank-store
initialization behavior.

HTTP authentication resolves the enrolled client key that authenticated the
request's SSH connection and produces `client:<fingerprint>`; it cannot choose
a runtime. Normal SSH usernames must be exactly `aplane`, and client enrollment
must be exactly `request-enrollment`.
Product HTTP, admin, CLI, SDK, and audit surfaces expose no runtime selector.

Internal storage APIs also expose no product-store selector:
`internal/storepaths.Paths` binds `identities/default/` and
`backups/default/` when constructed from the signer data root, generation and
backup operations accept that bound `Paths` value, and the runtime aggregate
has no ID field or accessor. One process-wide store mutation lock serializes
live mutation and watcher reload. Template activation, authentication,
administration, and signing always bind to that store.

Until APlane reaches a stable `v1.0` compatibility contract, in-place
installer upgrades are intentionally narrow:

- existing install directories are supported in place only when their
  `install/release.json` reports at least the installer's minimum supported
  upgrade version,
- installers require source release metadata before modifying an installation;
  Git checkout installs without `release.json` derive it from the built binaries'
  embedded version, commit, and build timestamp (matching signer/client version
  and commit, or client alone in client-only mode). Successful installs persist
  this metadata for future upgrade checks; unknown build stamps are rejected,
- install directories below that floor or without release metadata require a
  fresh install root unless the operator explicitly passes the installer
  `-f`/`--force` upgrade-check override,
- no config, key, cache, or endpoint migration utility is shipped,
- signer stores unlock only with keystore marker version 6 and the
  `store-root/v1` layout tag; stores in any other format are rejected at
  unlock, rotation, rebuild, and policy-sign. Keys move between installs via
  backup archives restored into a freshly initialized store,
- usable apclient signer routing is endpoint-based and lives in
  `endpoints.yaml`; top-level client `config.yaml` `ssh:` and `signer_port:`
  routing is rejected in this release,
- config files, product-runtime settings, admin IPC names, SDK DTO field names, caches,
  and generated docs examples may be reset or reshaped by a release before
  `v1.0`.

This section deliberately does not weaken the security-sensitive key contracts
below: encrypted key files, keystore metadata, and signing provider lookup still
define whether an existing key can be unlocked, validated, and signed by a
future release.

## Configuration Contracts

### Client Config

Source of truth: `internal/config/config.go`. External SDK config loaders in
`aplane-algo/aplanesdk` are related client-side loaders with similar defaults
and path resolution, but they are not strict validation mirrors.

The low-level loader returns defaults for an empty data directory or a missing
`config.yaml`; callers that need stricter startup behavior must enforce it
separately. The client data directory is resolved from the first of:

- `-d <path>`
- `APCLIENT_DATA`

Client config is loaded from `config.yaml` under the resolved data directory.
It supports optional `schema_version: 1`; absent means v1 for existing configs,
and unsupported versions fail during load.
Installer-written client configs include `networks` entries for `testnet`,
`mainnet`, and `localnet`, and restrict `networks_allowed` to `mainnet` and
`testnet` by default; existing configs are left unchanged if the
installer is pointed at a supported in-place upgrade target.
Unknown YAML fields are rejected by the Go loader with guidance that the file
may have been written by a newer version or may contain a typo.

The Go `Config` type contains no signer-routing fields. Current signer and
cosigner routing is loaded from `endpoints.yaml` into `ClientEndpointRegistry`.
Top-level client `config.yaml` `ssh:` and `signer_port:` fields are rejected;
they are not compatibility aliases.

`apshell` process startup goes through `internal/bootstrap/shell.Load`: it
requires a resolved client data directory, requires `<data_dir>/config.yaml` to
exist, validates the selected network against `networks_allowed`, requires a
`networks.<network>.algod` entry for the selected network, and requires that
entry's `server`.

Validation:

- `network`, `networks_allowed`, and `networks` keys are network context tokens
- network context tokens must be 1-64 characters, start with a lowercase ASCII letter or digit, and contain only lowercase ASCII letters, digits, `_`, or `-`
- if `networks_allowed` is set, `network` must be in it
- top-level client `ssh:` and `signer_port:` routing is not supported; signer
  routing lives in `endpoints.yaml`
- relative SSH paths in endpoint records resolve against the client data dir
- `theme` is a local client UI preference for apshell/apadmin/apconsole before
  any signer-admin setting is received; it does not mutate signer config
- `signer_status_poll_interval` parses as a Go duration string; empty defaults
  to `10s`, `"0"` disables background `/status` polling, and nonzero values
  below `1s` are rejected
- `networks.<token>.algod` is normalized into the runtime algod map
- SDK config loaders are intentionally similar but not strict mirrors of the
  Go client loader. The companion Go, TypeScript, and Python SDKs reject
  top-level `endpoint`, `ssh`, and `signer_port` routing in `config.yaml` and
  resolve SSH-only connection profiles from `endpoints.yaml`. First-use trust
  is an explicit connection/enrollment option, not a config.yaml routing field.

### Server Config

Source: `internal/serverconfig/serverconfig.go`

Loaded from `-d <path>` or `APSIGNER_DATA`.
It supports optional `schema_version: 1`; absent means v1 for existing configs,
and unsupported versions fail during load.
Installer-written signer configs include `networks` entries for `testnet`,
`mainnet`, and `localnet`; existing configs are left unchanged if the installer
is pointed at a supported in-place upgrade target.
Unknown YAML fields are rejected by the Go loader with guidance that the file
may have been written by a newer version or may contain a typo.

Process-global settings live in `config.yaml`. Product runtime settings live in
`identities/default/config.yaml`; nil means inherit from process defaults.
Unknown fields, including `decommissioned`, fail parsing.

Signer policy participates in the ordered approval engine.
The active node-role policy is product-store scoped and stored in the selected
generation as v1 JSON documents in one format, `aplane.policy.v1`
([ARCH_POLICY.md](ARCH_POLICY.md#the-boundary)), with the same layout on both
node roles: `default.json`, the node default that governs every key without a
document of its own, and one `policies/<selector>.json` per key that has one
(selector: the account address on a signer node, the Witness Key ID on a
cosigner node). A key's own document replaces the default wholesale; nothing
is inherited. Each document has a sibling `.hmac` sidecar that authenticates
its exact bytes with a key derived from the product store key. The default
approval fallback is `user_auto_approve`, lives in
`identities/default/config.yaml`, and is not a policy document field. Policy
documents are verified and loaded on unlock/reload before the key scan; any
document failing HMAC verification or decode, or a generation without
`default.json`, makes the node refuse to load policy instead of falling back
to defaults. A document carries a `role` that must match the node role and a
`key` that must match its file name; either mismatch is rejected.
Every policy change is an authenticated whole-document `apply_policy` (online)
or `apadmin policy rescue apply|remove` (stopped daemon), and each committed
change mints a new generation (see [ARCH_POLICY.md](ARCH_POLICY.md#storage-and-acceptance)).
There is no scalar policy-settings IPC.

Validation:

- `teal_compile_network` and server `networks` keys must be valid network context tokens
- `networks.<token>.algod` is normalized into the runtime algod map
- `networks.<token>.genesis_hash` maps one base64 or hex encoded 32-byte genesis hash to that custom network context token
- `mainnet`, `testnet`, and `betanet` are reserved built-in Algorand network tokens; custom genesis-hash mappings cannot use those tokens or remap their built-in genesis hashes
- duplicate genesis-hash mappings and duplicate custom token mappings are rejected at config load
- relative SSH server paths resolve against the signer data dir
- every `passphrase_command_argv` element resolves relative to the signer data dir before execution
- `theme` is the signer-admin UI preference persisted by the admin setting
  update path; it is process-global signer config, not client config
- `endpoint.signer_port` is the loopback REST API port behind the signer
  endpoint. It defaults to `11270`.
- `endpoint.ssh.listen_address` is the SSH listener bind host/address. It
  defaults to `127.0.0.1` and is deployment-owned `config.yaml` state, not a
  writable admin setting.
- `endpoint.ssh.port` is the SSH listener port. It defaults to `1127`.
- `endpoint.advertise_url` is optional operator-declared endpoint handoff
  routing metadata. It is deployment-owned `config.yaml` state, not a writable
  admin setting, and is not inferred from the SSH bind address.
- Admin IPC `endpoint_display_url` is display-only metadata derived by
  apsigner. It equals `endpoint.advertise_url` when configured; otherwise it is
  derived from the SSH listener. For a wildcard IPv4 bind (`0.0.0.0`), apsigner
  may use the kernel-selected primary outbound IPv4 address; if no usable
  address is detected, it falls back to `127.0.0.1`.
- at startup validation, headless mode rejects `lock_on_disconnect:true`
- at startup validation, headless mode requires `passphrase_timeout:"0"`
- `approval_wait` must parse as a positive Go duration between 30 seconds and
  30 minutes. The default is `60s`. The product runtime configuration may
  override the process default.
- initialized signer data roots must contain root `node.yaml` with role
  `signer` or `cosigner`. New initialization defaults to `signer` unless an
  cosigner node is explicitly requested. Product runtime config `mode` is an
  unsupported field and is rejected.
- node role gates key generation, mnemonic import, restore, signer key reload,
  and signing service dispatch. Hand-placed key files or restored keys from the
  forbidden role are not usable; role-conflicting active inventory fails closed
  for the node.
- node role parsing and `node.yaml` integrity sidecars are owned by
  `internal/noderole`; role-versus-key-type allowance decisions are owned by
  `internal/keyclass`.
- the selected generation's `node.yaml.hmac` is strict sidecar version 2 with
  algorithm
  `hmac-sha256`, key ID `keystore-master-hkdf-node-role-v1`, an explicit
  positive `integrity_term`, and a canonical lowercase HMAC-SHA256 over the
  exact root `node.yaml` bytes. Only the current term is authorized while the
  keyring remains settled and single-term.
- `require_memory_protection:true` requires disabled core dumps and successful memory locking

Built-in Algorand genesis-hash mappings are source-defined:

- `mainnet`: `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=`
- `testnet`: `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=`
- `betanet`: `mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=`

Signer policy network identity is derived from transaction `GenesisHash`, not `GenesisID`. `GenesisID` may appear in transaction descriptions and diagnostics, but it is not the authoritative key for policy lookup.

Operational rules:

- missing `store-root.enc` is not a startup error; it forces locked-start behavior
- a signer data dir containing `.prod` is systemd-managed; `apsigner`
  refuses manual startup unless `APLANE_SYSTEMD_MANAGED=1` or parent PID is 1
- missing the effective `networks.<teal_compile_network>.algod.server` is a warning because TEAL-dependent generation will fail later
- headless mode with `user_auto_approve:false` is only a warning because
  transactions require an admin approver
- process-owned `config.yaml` mutations are serialized by the signer process config mutation lock
- admin setting writes fail if the loaded process config is stale relative to
  mutable on-disk process settings such as `endpoint.signer_port`,
  `endpoint.ssh.port`, `passphrase_command_argv`, `passphrase_command_env`,
  `networks`, `approval_wait`, and `theme`
- runtime reads that need configuration should use snapshots or narrow accessors rather than holding mutable `ServerConfig` pointers
- product-runtime settings and policy writes are serialized by the store mutation lock
- node role is immutable in supported tools; create a separate signer data root
  for the other role

### LocalNet Setup Utility

Source: `cmd/aplocalnet/main.go` and `internal/aplocalnet/setup.go`.

`aplocalnet` is an operator-run setup utility for an already running AlgoKit
LocalNet. It has a Bubble Tea TUI by default, `--check` for reachability-only
inspection, and `--apply` for non-interactive mutation. It is not a long-running
runtime service and does not add HTTP or admin-protocol endpoints. The TUI's
primary action is labeled `apply`.

Data directory resolution:

- client data: `--client-data`, then `APCLIENT_DATA`, then `~/aplane/apclient`
- signer data: `--signer-data` or `-d`, then `APSIGNER_DATA`, then
  `~/aplane/apsigner`

Endpoint and token resolution:

- algod URL: `--algod-url`, then `APLANE_LOCALNET_ALGOD_URL`, then
  `http://localhost:4001`
- algod token: `--algod-token`, then `APLANE_LOCALNET_TOKEN`, then the
  well-known AlgoKit LocalNet default token
  `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- KMD URL: `--kmd-url`, then `APLANE_LOCALNET_KMD_URL`; if omitted, no
  persistent KMD override is written and the bundled LocalNet plugin uses its
  own default of `http://localhost:4002`

Endpoint URL inputs are trimmed and trailing slashes are removed.

`--check` constructs an algod client, reads status and versions, canonicalizes
the returned genesis hash, prints LocalNet metadata, and writes nothing.

`--apply` and the TUI apply path perform the same reachability check. The TUI
uses the resolved client and signer paths it displays. Non-interactive
`--apply` targets the explicitly supplied data roots: `--client-data` or
`APCLIENT_DATA` enables client mutation, and `--signer-data`/`-d` or
`APSIGNER_DATA` enables signer mutation. If no explicit target source is
present, client data defaults to `~/aplane/apclient` and signer data defaults
to `~/aplane/apsigner`. At least one target is required after resolution. For
each selected target it then:

- write signer `config.yaml` with `networks.localnet.algod.server`,
  `networks.localnet.algod.token`, and `networks.localnet.genesis_hash`
- write client `config.yaml` with `network: localnet`,
  `networks.localnet.algod.server`, and `networks.localnet.algod.token`
- append `localnet` to a non-empty `networks_allowed` list when needed so the
  new default network remains valid; missing or empty `networks_allowed` remains
  unconstrained
- ensure `$APCLIENT_DATA/plugins.yaml` has an `enabled_plugins` sequence and
  contains `algokit-localnet`
- warn, but complete, if `algokit-localnet` is enabled but missing under
  `$APCLIENT_DATA/plugins.available/algokit-localnet`
- if a KMD URL override is supplied, add or replace
  `export APLANE_LOCALNET_KMD_URL='...'` in `apenv.sh` discovered at either
  `dirname(APCLIENT_DATA)/apenv.sh` or `$APCLIENT_DATA/apenv.sh`; if no
  `apenv.sh` is found, emit a warning telling the operator to export the value
  before starting `apconsole`

All file writes use a temporary file, file sync, atomic rename, and directory
sync. Existing ownership is preserved where possible; existing modes are
clamped to the mutator's ceiling. Newly created files use `0600` for signer
config and `0644` for client config/plugin/env files. Symlink and non-regular
targets are rejected.

### Passphrase Helper Contract

Sources: `internal/signerapp/unlockconfig/unlock.go` owns product-store
`unlock.yaml` persistence; `internal/serverconfig/passphrasecmd.go` owns helper
execution, output decoding, environment filtering, and validation.

- each `passphrase_command_argv` element resolves relative to signer data dir
- `argv[0]` must resolve to absolute path
- helper timeout is 5 seconds
- stdout is capped at 8 KiB
- stderr is discarded
- one trailing newline is stripped
- payload may be raw bytes, `base64:<payload>`, or `hex:<payload>`
- NUL bytes and empty output are rejected
- environment is built from `passphrase_command_env` plus `CREDENTIALS_DIRECTORY` allowlist, not inherited wholesale
- write flow sends passphrase on stdin and requires constant-time round-trip match on stdout

### Server Listen Contract

- SSH is always enabled at startup using configured or default SSH settings
- REST binds `127.0.0.1:<endpoint.signer_port>`
- SSH binds `<endpoint.ssh.listen_address>:<endpoint.ssh.port>` and hands API
  channels to the REST listener with the authenticated connection identity.
  Direct loopback REST requests have no identity, so only `/health` succeeds.
  The default `endpoint.ssh.listen_address` is `127.0.0.1`.
- `endpoint.signer_port`, `endpoint.ssh.*`, and `endpoint.advertise_url` are
  configured in signer `config.yaml`. Admin settings may report those values,
  but do not mutate listener bind or handoff URL state. Changing
  `endpoint.signer_port` or `endpoint.ssh.*` requires restarting apsigner.
- Admin settings may also report `endpoint_display_url` for UI chrome. This is
  not exported endpoint handoff metadata and must not be persisted by admin
  clients as `endpoint.advertise_url`.
