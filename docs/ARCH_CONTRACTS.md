# Engineering Contracts

> Compatibility-bearing wire formats, on-disk formats, and behavioral contracts.
> For system orientation, ownership, and architecture, see [ARCH_SPEC.md](ARCH_SPEC.md).
> For the explanatory network context model, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
> For the current signer policy verdict model, see [ARCH_POLICY.md](ARCH_POLICY.md).
> Load this document when working on a specific subsystem, not as general pre-reading.

## Contents

- [Current Release Compatibility Scope](#current-release-compatibility-scope)
- [Key Type Identifier Contract](#key-type-identifier-contract)
- [HTTP API Contract](#http-api-contract)
- [Admin Protocol](#admin-protocol)
- [apshell Parsing Contracts](#apshell-parsing-contracts)
- [Configuration Contracts](#configuration-contracts)
- [On-Disk Formats](#on-disk-formats)
- [Authentication, SSH, and Token Provisioning](#authentication-ssh-and-token-provisioning)
- [Approval and Policy Contracts](#approval-and-policy-contracts)
- [Runtime Lifecycle and Decommission](#runtime-lifecycle-and-decommission)
- [Key Watching and Reload](#key-watching-and-reload)
- [Template Reload Contract](#template-reload-contract)
- [Plugin Contract](#plugin-contract)
- [MCP Contract](#mcp-contract)
- [Backup and Restore Contract](#backup-and-restore-contract)
- [Error Model](#error-model)
- [SDK Contracts](#sdk-contracts)
- [Swap Contract](#swap-contract)

## Current Release Compatibility Scope

Until APlane reaches a stable `v1.0` compatibility contract, this release is
new-install-only:

- existing install directories are not a supported in-place upgrade target,
- no config, key, cache, or endpoint migration utility is shipped,
- apclient signer routing must be present in `endpoints.yaml`,
- config files, identity settings, admin IPC names, SDK DTO field names, caches,
  and generated docs examples may be reset or reshaped by a release before
  `v1.0`.

This section deliberately does not weaken the security-sensitive key contracts
below: encrypted key files, keystore metadata, and signing provider lookup still
define whether an existing key can be unlocked, validated, and signed by a
future release.

## Key Type Identifier Contract

Every protocol, config, key file, template, and key type state field named
`key_type` carries the canonical identifier, not a presentation label.

Canonical forms:

- native Ed25519 is the single-segment built-in `ed25519`
- APlane-defined LogicSig, template, and compiled-provider key types use
  `publisher.family.vN`, where `vN` is a literal `v` followed by a positive
  decimal version, for example `aplane.falcon1024.v1`,
  `aplane.htlc.v1`, and `aplane.falcon1024-whitelist.v1`

YAML templates declare `publisher`, `family`, and integer `version`; the
computed key type is `publisher.family.v<version>`. Clients and tools must send
and persist the full canonical identifier in `key_type` fields. Human-facing
CLI/TUI input may additionally accept the default-publisher shorthand
`family.vN`, which resolves to `aplane.family.vN`; this shorthand is never
persisted or emitted in wire/storage fields. Compact human display may elide the
default `aplane` publisher, but third-party publishers stay explicit.

Terminology:

- `family` is the middle segment of `publisher.family.vN`. It groups versions
  of one key type or template policy, for example `aplane.whitelist.v1` and
  `aplane.whitelist.v2`.
- `base_key_type` is the field composed DSA templates use to point at their
  signing provider. For example, `base_key_type: aplane.falcon1024.v1` means
  the template signs with Falcon-1024, while its own identity is named by its
  `family` segment (e.g. `family: falcon1024-whitelist`).
- `Family` / `FamilyName` on Go provider types are display metadata. The
  authoritative identifier for storage, routing, and migration is the full
  canonical `key_type`.

## HTTP API Contract

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the HTTP request/response wire shapes, status codes, identity routing, and cancellation semantics.

## Admin Protocol

See [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md) for the apsigner admin RPC message catalog, payload shapes, and writable-settings rules.

The pre-auth `auth` request verifies the passphrase and may also unlock and
reload the bound identity. Therefore `auth_result{success:false}` does not
always mean a bad passphrase. If passphrase verification succeeds but unlock or
reload fails, the signer returns `auth_result` with `code:"unlock_failed"` and
an `error` prefixed with `auth ok but unlock failed:`. Clients should surface
that case as a serious post-auth load/integrity failure, not as ordinary
credential rejection. A direct authenticated `unlock` request reports failed
unlock/reload after passphrase verification through
`unlock_result{success:false, code:"unlock_failed"}`.

## apshell Parsing Contracts

The `apshell` command surface remains compatibility-sensitive even when internal parsing is refactored.

Parsing contracts:

- bracketed address lists such as `[ A1 A2 ]` and `[A1 A2]` are accepted where a command already accepts address-list input,
- `generate` parameter parsing is bracket-aware for `key=value` arguments,
- LogicSig `arg:name=value` parsing keeps the `arg:name=` split local to `internal/cmdspec/lsigarg.go` and uses the shared byte parser for the value side,
- byte-oriented shell inputs support `hex:`, `b64:`, `text:`, and `0x...`; bare text is accepted only where command behavior allows it,
- ASA-facing commands may parse shell input into semantic values (`AssetRef`, `AmountText`) before command execution, but this does not change user syntax,
- `send` and `sweep` parse their required `from`/`to`/`leaving` structure first and only treat later tokens as trailing options, so positional address/account inputs may legitimately equal keywords such as `atomic`, `nowait`, or `leaving` without being reinterpreted as flags.

Failure messages carry optional `code` alongside `error`. Central protocol
error-message codes:

- `invalid_message_format`
- `expected_auth_message`
- `invalid_auth_message`
- `authentication_failed`
- `invalid_passphrase`
- `unlock_failed`
- `signer_locked`
- `no_identity_bound`
- `authorization_denied`
- `invalid_request`
- `unknown_message_type`
- `key_not_found`
- `internal_error`

Consumers should branch on message `type` and `code` first, and use `error` for display or fallback handling.

Specific admin result messages may define additional stable result-local codes,
including `key_type_in_use` for template disable/removal or compiled-provider deactivation and
`restore_rate_limited` for managed restore preview/restore throttling. See the
corresponding payload sections and contract tests before treating the central
protocol list as exhaustive.

IPC failure semantics:

- protocol-level failures are reported through `error` messages or result messages with `success:false`,
- `code` is additive and optional on the wire,
- the transport does not provide a complete typed error taxonomy end-to-end.

### Admin Client Capabilities

| Capability | `apadmin` TUI | `apadmin` test mode | `apapprover` | `appass` |
|-----------|----------------|------------------|--------------|----------|
| Auth handshake | yes | yes | yes | no |
| Displacement negotiation | yes | no | no | no |
| Unlock | yes | yes | no | no |
| Key management | yes | partial | no | no |
| Managed backup/restore | yes | no | no | no |
| Signing approval | yes | no | yes | no |
| Token provisioning approval | yes | no | yes | no |
| Admin settings | yes | no | no | no |
| Policy viewer | yes | no | no | no |
| Policy settings editor | limited | no | no | no |
| Async notifications | yes | limited | limited | no |

`appass` edits config offline; it is outside the live IPC surface.

`apadmin`'s policy settings editor is intentionally limited. It can mutate the
admin-projected policy settings exposed by `get_policy_settings`,
`update_policy_setting`, and `update_policy_asa_amounts`, including scalar
policy toggles, max fee, and network-scoped transfer guard thresholds. It is not
a full guided `policy.yaml` editor and does not expose YAML-only fields such as
`key_overrides`.

These client capabilities describe the product surface for the product
identity. Backend admin routing is identity-scoped internally; `apadmin`,
`apapprover`, and `appass` do not expose a tenant-management UI.

`apadmin` test mode details:

- test mode is only present in builds compiled with `-tags testmode`,
- default builds keep the `-test` flag surface but reject it with a stub error instead of exposing the non-interactive path,
- remote test mode uses the same build-tag gate and also rejects unknown SSH hosts instead of offering interactive trust-on-first-use.

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
Installer-written client configs include `networks` entries for `testnet`,
`mainnet`, and `localnet`, but restrict `networks_allowed` to `mainnet` and
`testnet` by default; existing configs are left unchanged if the installer is
pointed at an existing path, but this release is not an in-place upgrade target.
Unknown YAML fields are rejected by the Go loader.

`apshell` process startup goes through `internal/bootstrap/shell.Load`: it
requires a resolved client data directory, requires `<data_dir>/config.yaml` to
exist, validates the selected network against `networks_allowed`, requires a
`networks.<network>.algod` entry for the selected network, and requires that
entry's `server`.

Validation:

- `network`, `networks_allowed`, and `networks` keys are network context tokens
- network context tokens must be 1-64 characters, start with a lowercase ASCII letter or digit, and contain only lowercase ASCII letters, digits, `_`, or `-`
- if `networks_allowed` is set, `network` must be in it
- top-level client `ssh:` signer routing is not supported by `apshell` startup
  in this release; signer routing lives in `endpoints.yaml`
- relative SSH paths in endpoint records resolve against the client data dir
- `theme` is a local client UI preference for apshell/apadmin/apconsole before
  any signer-admin setting is received; it does not mutate signer config
- `signer_status_poll_interval` parses as a Go duration string; empty defaults
  to `10s`, `"0"` disables background `/status` polling, and nonzero values
  below `1s` are rejected
- `networks.<token>.algod` is normalized into the runtime algod map
- SDK config loaders are intentionally similar but not strict mirrors of the Go
  client loader: Go, TypeScript, and Python expose SDK-only
  `ssh.trust_on_first_use`; Go rejects an empty `ssh.host` when an `ssh:` block
  is present; TypeScript only enables SSH when `ssh.host` is truthy and falls
  back to defaults on config read/parse errors; Python rejects an SSH block
  without `host`

### Server Config

Source: `internal/config/serverconfig.go`

Loaded from `-d <path>` or `APSIGNER_DATA`.
Installer-written signer configs include `networks` entries for `testnet`,
`mainnet`, and `localnet`; existing configs are left unchanged if the installer
is pointed at an existing path, but this release is not an in-place upgrade
target.
Unknown YAML fields are rejected by the Go loader.

For compatibility with pre-`user_auto_approve` signer configs, the Go loader
accepts top-level `manual_approval` as a deprecated inverse alias:
`manual_approval:true` maps to `user_auto_approve:false`, and
`manual_approval:false` maps to `user_auto_approve:true`. If both fields are
present, they must agree under that inverse mapping. New configs should write
only `user_auto_approve`.

Process-global settings live in `config.yaml`. Identity-scoped settings live in `identities/<identity>/config.yaml` and nil means inherit from process defaults. `decommissioned:true` disables the identity.

Signer policy participates in the ordered approval engine.
Client-signing policy is identity-scoped and stored in
`identities/<identity>/policy.yaml`; attestor component policy is stored in
`identities/<identity>/attestation.yaml`. Each document has a sibling `.hmac`
sidecar that authenticates the exact YAML bytes with a key derived from the
identity master key. The default approval fallback is `user_auto_approve`,
lives in `identities/<identity>/config.yaml`, and is not a policy document
field. Both policy documents are verified and loaded on unlock/reload before
the key scan; a missing policy file or missing/mismatched sidecar fails closed
instead of falling back to defaults. Authenticated admin IPC policy replacement
currently writes `policy.yaml`; direct `attestation.yaml` edits are checked,
signed, and verified through `apstore policy`.
Both documents support YAML-only `key_overrides` blocks for per-key effective
policy. Client-signing overrides in `policy.yaml` are keyed by Algorand auth
address; attestor overrides in `attestation.yaml` are keyed by `a_...`
component selector. These overrides apply to policy phases, are not exposed
through admin IPC, and direct YAML edits require offline `apstore policy sign`
before the signer will trust them.

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
- at startup validation, headless mode rejects `lock_on_disconnect:true`
- at startup validation, headless mode requires `passphrase_timeout:"0"`
- `approval_wait` must parse as a positive Go duration between 30 seconds and
  30 minutes. The default is `60s`. Identity config may override the process
  default for that identity.
- identity `mode`, when present, must be one of `signing`, `attestation`, or
  `dual`. Omitted mode defaults to `signing`. Key generation, import, and
  key reload reject key classes disallowed by the effective identity mode.
- `require_memory_protection:true` requires disabled core dumps and successful memory locking

Built-in Algorand genesis-hash mappings are source-defined:

- `mainnet`: `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=`
- `testnet`: `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=`
- `betanet`: `mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0=`

Signer policy network identity is derived from transaction `GenesisHash`, not `GenesisID`. `GenesisID` may appear in transaction descriptions and diagnostics, but it is not the authoritative key for policy lookup.

Operational rules:

- missing `.keystore` is not a startup error; it forces locked-start behavior
- a signer data dir containing `.prod` is systemd-managed; `apsigner`
  refuses manual startup unless `APLANE_SYSTEMD_MANAGED=1` or parent PID is 1
- missing the effective `networks.<teal_compile_network>.algod.server` is a warning because TEAL-dependent generation will fail later
- headless mode with `user_auto_approve:false` is only a warning because
  transactions require an admin approver
- process-owned `config.yaml` mutations are serialized by the signer process config mutation lock
- admin setting writes fail if the loaded process config is stale relative to
  mutable on-disk process settings such as `signer_port`, `ssh.port`,
  `passphrase_command_argv`, `passphrase_command_env`, `networks`,
  `approval_wait`, and `theme`
- runtime reads that need configuration should use snapshots or narrow accessors rather than holding mutable `ServerConfig` pointers
- identity-owned settings and policy writes are serialized by the target identity's mutation lock
- managed identity mode tightening is refused while the active key inventory
  contains key classes disallowed by the requested target mode

### LocalNet Setup Utility

Source: `cmd/aplocalnet/main.go` and `internal/aplocalnet/setup.go`.

`aplocalnet` is an operator-run setup utility for an already running AlgoKit
LocalNet. It has a Bubble Tea TUI by default, `--check` for reachability-only
inspection, and `--apply` for non-interactive mutation. It is not a long-running
runtime service and does not add HTTP or admin-protocol endpoints.

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

`--apply` and the TUI apply path perform the same reachability check, then:

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

All file writes use a temporary file followed by atomic rename. Existing target
mode and ownership are preserved where possible; newly created files use the
mode supplied by the mutator (`0640` for signer config, `0644` for client
config/plugin/env files).

### Passphrase Helper Contract

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
- REST binds `127.0.0.1:<signer_port>`
- SSH binds `0.0.0.0:<ssh.port>` and forwards to loopback REST

## On-Disk Formats

### Signer Data Directory Layout

```text
<data_dir>/
  config.yaml
  audit.log
  .apstore.lock
  cache/
    .cache_key
    <network>_asa_cache.json
  library/
    templates/*.yaml        # plaintext optional KeyType Library YAML source
  backups/<identity>/
    *.tar.gz                # restorable managed/imported backup archives
  .ssh/ssh_host_key
  identities/<identity>/
    keys/*.key
    .keystore
    aplane.token
    config.yaml
    policy.yaml
    policy.yaml.hmac
    attestation.yaml
    attestation.yaml.hmac
    unlock.yaml
    .ssh/authorized_keys
    passphrase              # plaintext appass-file helper artifact, mode 0600
    passphrase.cred         # systemd-creds helper artifact, mode 0600
    keytypes/<key_type>.json
    keytypes/<key_type>.template
    attestors/<name>.json
    deleted/keys/*.key
    deleted/keytypes/<key_type>.template
```

Additional signer-state notes:

- admin IPC listens on resolved `ipc_path`; default is `<data_dir>/aplane.sock`, but an absolute `ipc_path` may place the socket outside the signer data dir
- `.apstore.lock` is the cooperative signer-store lock used by live signer startup and the local `apstore rebuild` rescue path
- signer-managed backup archives are written under
  `<data_dir>/backups/<identity>/`; the archive contains `README.md` and
  `apb/*.apb` encrypted backup payloads plus a policy snapshot under
  `policy/`
- imported backup archives are validated and published under
  `<data_dir>/backups/<identity>/`, making the backup locker the source for
  restorable archives
- signer `cache/<network>_asa_cache.json` is signer-wide public ASA metadata for policy editing/rendering; it is not identity-scoped and is not authoritative for policy enforcement
- signer cache files use the same signed JSON/HMAC envelope as client cache files, with `cache/.cache_key` scoped to the signer cache root
- signer ASA cache access is serialized inside `apsigner` by `internal/signerapp/asametadata.Store`; external/manual cache edits are unsupported and tampering is rejected by HMAC validation
- signer ASA metadata is loaded per operation from disk with `internal/asa/registry` built-in metadata as seed data; there is no separate long-lived in-memory signer ASA metadata cache to reconcile
- built-in ASA metadata and convenience aliases live in `internal/asa/registry`; cache-backed current-network metadata is preferred for symbolic resolution, and registry aliases are the fallback used by shell and JavaScript helpers
- `ssh.authorized_keys_path` remains a validated/resolved server setting for the underlying SSH server wiring, but product-mode identity auth and token enrollment use `identities/<identity>/.ssh/authorized_keys`
- `passphrase` and `passphrase.cred` are sensitive identity-scoped helper files referenced by `unlock.yaml`

### Client Data Directory Layout

```text
<data_dir>/
  config.yaml
  endpoints.yaml
  .mcp.json
  aplane.token
  tokens/
    <endpoint-alias>.token
  .apclient.lock
  .ssh/id_ed25519
  .ssh/known_hosts
  cache/
    .cache_key
    alias_cache.json
    set_cache.json
    signer_cache.json
    <network>_asa_cache.json
    <network>_auth_cache.json
  plugins.yaml
  plugins.available/
  scripts/*.js
  swap/<network>/<proposal_id>.<address>.json
  swap/<network>/<proposal_id>.<address>.tombstone.json
```

Additional client-state notes:

- installers write `.mcp.json` for the installed `apshell --mcp` command and data directory; existing `.mcp.json` files are preserved and a `.mcp.json.aplane-installer.new` template is written instead
- installers create the client `plugins.available/` catalog directory,
  `plugins.yaml` activation file, and `scripts/` directory; `apshell` loads only
  catalog plugin directories named in `plugins.yaml`
- `scripts/`, `plugins.yaml`, and non-bundled plugin catalog directories are
  user-managed client state, while bundled plugin directories are
  installer-managed reserved paths.
  `plugins.available/algokit-localnet` is refreshed atomically from the release
  or repo payload on install or installer re-run. Existing `plugins.yaml`
  activation choices are preserved.
- local-mode installers write generated launcher `start.sh` and `apconsole.yaml` alongside `apenv.sh` in the local install root; systemd writes the same operator-side `apenv.sh`/`apconsole.yaml` shape under the selected operator root (default `~<installing-user>/aplane/`) while keeping signer data in `/var/lib/apsigner`; these are installer-managed convenience entrypoints/config for `apconsole`, not client data under `APCLIENT_DATA`; generated `apenv.sh` files export `APLANE_INSTALL_ROOT`, and systemd operator env files also export `APLANE_BINDIR`
- installer path precedence is explicit CLI argument, then `APLANE_INSTALL_ROOT`, then prompts/defaults; systemd binary directory precedence is `--bindir`, then `APLANE_BINDIR`, then `/usr/local/bin`
- systemd records the selected operator root in `/var/lib/apsigner/install/operator-root`; systemd uninstall removes the operator-side client workspace only when an operator root is explicitly provided or recorded by the installer, and does not guess `$SUDO_USER_HOME/aplane` for deletion
- existing local-mode installs are probed with the bundled `approbe` helper before binaries are replaced; reachable signer IPC aborts the install, missing/stale/refused IPC is treated as stopped, and unknown probe errors fail closed
- systemd installs refuse to proceed while `apsigner.service` is `active`, `activating`, `reloading`, or `deactivating`; operators must stop the service before running the installer against that data directory
- local-mode uninstall removes generated binaries, launcher/env files, and installer-generated MCP config, but preserves `APCLIENT_DATA` and local signer data by default; destructive removal of keys, tokens, plugins, scripts, caches, and swap state is an explicit manual step
- `apconsole.yaml` supports `mode: local|remote`, `client_data`, and local-mode `signer_data`; relative paths resolve against the profile file
- `endpoints.yaml` is the normal client-local endpoint registry for new installs, with `schema_version: 1`, a derived `default` signer endpoint alias, and user-defined endpoint aliases under `endpoints:`. Endpoint aliases are local references only; they are unique within one `APCLIENT_DATA` and use only ASCII letters, digits, `.`, `_`, and `-`.
- if client `config.yaml` contains top-level `ssh:` signer settings, `apshell` startup and the apconsole shell pane fail closed with an operator-facing message that says this release is new-install-only. Startup never materializes or rewrites endpoint routing.
- endpoint records carry connection profile fields together: required `role` (`signer` or `attestor`), `url` (`ssh://host[:port]`, loopback `http://...`, `https://...`, or `self` where supported), `signer_port`, `local_port`, `identity_file`, `known_hosts_path`, `token_file`, and endpoint-published `published_attestors`. Relative file paths resolve against `APCLIENT_DATA`. A registry may contain at most one `signer` endpoint; if present, that endpoint is the effective default. `published_attestors` is valid only on `attestor` endpoints.
- endpoint token files are bearer credentials. The default signer endpoint commonly uses `APCLIENT_DATA/aplane.token` unless overridden. Non-primary endpoints default to `APCLIENT_DATA/tokens/<endpoint-alias>.token`. Reads reject group/world-accessible token files and token writes create owner-only files.
- `published_attestors` is keyed by canonical embedded attestor public-key hex. Each record carries `component_key`, `key_type`, and `last_seen_at`; runtime attested-send routing derives the endpoint for an embedded attestor public key from this endpoint-local inventory.
- `apstore endpoint export` emits a public `aplane.endpoint.v1` JSON envelope for operator handoff. The common form takes `--host <client-reachable-host>` and derives `ssh://<host>:<configured-ssh-port>` plus the configured signer REST port; `--url <url>` overrides that URL for explicit HTTPS, loopback HTTP, forwarded SSH ports, or unusual deployments. Like other portable JSON handoff envelopes, it uses a single `schema: "aplane.endpoint.v1"` discriminator. The envelope is strict JSON with portable endpoint URL and signer/local ports only. It must not contain client-local aliases, endpoint-role metadata, attestor public-key metadata, bearer tokens, private keys, mnemonics, encrypted key payloads, passphrases, or `known_hosts` trust entries; exported envelopes reject `url: self` because `self` is client-local state.
- `apshell endpoints import-public --alias <alias> --role signer|attestor [--dry-run] <endpoint-json>` validates that envelope and writes client-local endpoint routing only: `$APCLIENT_DATA/endpoints.yaml`. Import replaces existing endpoint data when the alias matches. If the imported URL already belongs to a different alias with the same role, import fails without writing; the same URL may be represented by one `signer` alias and one `attestor` alias for dev co-location. Import is not an ownership or trust proof and does not discover attestor keys. Tokens are still obtained separately with `request-token --endpoint <alias>`, and SSH host trust is still established by the existing known-hosts flow.
- `apshell endpoints sync-attestors [--dry-run] [--yes]` scans configured `attestor` endpoints with authenticated `/keys`, extracts attestor component-key `public_key_hex` values, validates each `component_key`, and atomically rebuilds endpoint-local `published_attestors` inventory in `endpoints.yaml`. Reachable endpoints are refreshed; temporarily unavailable endpoints, including locked signer identities, preserve their existing `published_attestors` entries. Authentication failures, endpoint configuration errors, malformed responses, duplicate public keys advertised by multiple endpoint aliases, and component-key validation failures are hard errors and leave files unchanged. After discovery, the command prints component IDs and requires interactive confirmation, unless `--yes` is provided, before copying the current inventory into the connected signer identity's public attestor reference catalog as source-marked `client_discovery` records. Sync carries only public metadata (`endpoint_alias`, `component_key`, `key_type`, `public_key_hex`, `last_seen_at`) and replaces only prior `client_discovery` records; manually imported records are preserved. This makes endpoint-discovered attestors selectable from signer-side key generation clients such as `apadmin`.
- `apshell endpoints attestors` lists the local endpoint-discovered attestor inventory by endpoint alias, component ID, and key type without calling remote endpoints.
- `apshell endpoints list`, `endpoints show <alias>`, `endpoints default <alias>`, and `endpoints delete <alias>` operate on local client configuration. `show` is local-only, does not call `/keys`, and includes `last_seen_at` for that endpoint's published attestors; `delete` refuses to remove the signer endpoint or an endpoint with published attestors still referenced by derived runtime routing.
- interactive `apshell` startup does not require a pre-enrolled client: it validates client bootstrap/config inputs, but it may start without endpoint token files or a trusted signer host so the operator can run enrollment, recovery, and troubleshooting commands
- for interactive `apshell`, token presence and SSH host trust are enforced when the shell attempts `connect`, startup auto-connect, or `request-token` flows; they are not preflight requirements for process startup
- after a successful interactive `request-token` for the default endpoint, `apshell` immediately attempts to establish the signer SSH tunnel with the newly issued token; `request-token --endpoint <alias>` saves that endpoint's token and only auto-connects when `<alias>` is the default endpoint.
- `apshell --mcp` has a stricter startup contract than interactive `apshell`: MCP startup is non-interactive and refuses to start unless the client is already enrolled (default signer endpoint, endpoint token, trusted `known_hosts`)
- `apshell --mcp` also requires the startup signer connection to succeed; it does not start in a disconnected or partially enrolled state, and it cannot perform first-use trust or token enrollment itself
- `apconsole` resolves startup inputs per field in this order: flags, environment variables, explicitly selected profile (`-config` or `APCONSOLE_CONFIG`), auto-discovered profile, then defaults
- conflicting explicit inputs do not auto-resolve: if flags, environment variables, or an explicitly selected profile disagree, `apconsole` exits and requires the operator to remove the conflict or make the values match
- auto-discovered profile values are convenience defaults only; if they differ from explicit flags or environment variables, `apconsole` keeps the explicit values and emits a warning naming the ignored profile value
- local-mode `apconsole` may start before client enrollment is complete; it requires valid local client/signer data paths, but it allows the embedded shell to perform first-time `request-token` while the local signer/admin panes are available for approval
- for local-mode `apconsole`, when the client SSH host is loopback, the local signer's configured SSH host key is probed against the live loopback SSH endpoint before being pinned into the client `known_hosts` file; a mismatch aborts the trust write and shell startup, and token presence is enforced when the embedded shell attempts startup auto-connect, `connect`, or `request-token`
- remote-mode `apconsole` requires the configured client data directory to be enrolled before the UI starts: `endpoints.yaml` must define a default signer endpoint, that endpoint's token file must exist, and the configured signer host must already be present in the endpoint `known_hosts_path`
- remote `apadmin` has the same client enrollment prerequisite as `apconsole`: it requires a default signer endpoint, the endpoint token, and a trusted signer host in the endpoint `known_hosts_path`; it does not prompt for first-use host trust
- shared non-interactive client-enrollment preflight lives in `internal/clientenroll/preflight.go` and is used by `apshell --mcp` and remote-mode `apconsole`; remote `apadmin` has a separate implementation in `cmd/apadmin/remote.go`
- tombstones suppress locally deleted proposals for that local actor
- cache files are signed JSON with a per-client `.cache_key` and are local, rebuildable client state; the signed envelope has `version: 1`, and versioned cache payloads carry `schema_version: 1` with missing payload versions treated as legacy v1
- persisted alias and set names are canonicalized to lowercase by
  `internal/refname`; both allow only ASCII letters, digits, `-`, and `_`;
  aliases reserve `list`, `delete`, and `remove`; sets reserve `list`, `add`,
  `remove`, `delete`, and dynamic runtime set names `all` and `signers`
- `.apclient.lock` is the cooperative local mutation lock for shared `APCLIENT_DATA`
- apshell passively watches the shared `cache/` directory when possible and reloads changed in-memory cache snapshots at command boundaries; this is best-effort freshness, not an authority or synchronization contract

Identity key type records under `keytypes/` are plaintext metadata. One
`<key_type>.json` record stores `source`, `state`, optional compatibility
`fingerprint`, and activation time for an identity opt-in key type. A
`source:"compiled", state:"enabled"` record makes a compiled library-visible
provider available to that identity for discovery and generation. YAML template
records use `source:"yaml_generic"` or `source:"yaml_composed"` and pair with an
encrypted adjacent `<key_type>.template` file. A disabled YAML record keeps the
encrypted template installed but hides that key type from discovery, reload, and
generation. These records do not gate signing for keys that already exist.

Identity-local deletion archives live under `deleted/`. Key deletion moves the
encrypted key file from `keys/` to `deleted/keys/`. Template removal deletes the
state record and moves the encrypted `.template` file from `keytypes/` to
`deleted/keytypes/`. Archived files are outside active scans.

#### Key Type Records

Key type state records are written by `internal/keytypestate` through the
identity-scoped mutation lock. Admin handlers acquire that lock before writing;
watcher-triggered reloads acquire the same lock before scanning. Record writes
use the shared atomic write helper (temporary file plus rename). They do not
fsync the parent directory, so the durability contract is the same as other
small signer metadata files in this store.

Records are intentionally plaintext because they contain no key material. The
fingerprint is a semantic compatibility digest of the provider/template
definition, useful for conflict detection and backup provenance checks; it is
not a signing secret and is not an authorization token.

### KeyType Library And Template Files

There are two plaintext library locations with the same relative layout:

- repository and release artifacts carry optional template YAML under top-level `library/templates/`,
- signer installations may carry a copy under `<APSIGNER_DATA>/library/templates/`.

The signer-data path is defined by `internal/storepaths.Paths.TemplateLibraryDir()`. Release installers,
installer re-runs, and test setup flows may refresh this directory from the repository or packaged copy. Files in this
directory are reference material and are not active key types by themselves.

`apadmin` presents this mixed source as the KeyType Library. It lists the signer-data library over the
admin protocol and also includes installed identity templates that no longer have a matching plaintext
library YAML entry. The list result includes parsed metadata (`key_type`, `template_type`, display text,
creation parameters, and runtime arguments) when library source is available, plus install and enabled state.
Invalid files are reported as invalid entries; duplicate or ambiguous library candidates are not activation
events. Compiled providers that are `library` visible in `internal/keytypecatalog` also appear in this list
with `template_type:"compiled_provider"`; their enabled state comes from identity key type state
records. `compiled_provider` is an admin/library wire projection of
`keytypestate.SourceCompiled`, not a `templatestore.TemplateType`; the encrypted
template store accepts only YAML-backed `generic` and `composed` template types.
YAML template entries use `installed` for encrypted template-file presence and `enabled` for whether
the installed template is exposed to generation. Installed-only entries are derived from
encrypted `.template` filenames and therefore may not include parameter metadata until matching library YAML is
available.

Installing a library template takes `key_type` and `template_type`, re-resolves the candidate from the
signer-data library, parses the YAML, writes it through the encrypted identity-scoped template store under
`identities/<identity>/keytypes/<key_type>.template`, writes an enabled state record, then
reloads that identity. Installed `.template` files, not the plaintext library files, are the active persisted
runtime source for key generation and key-type discovery; the installed template is not consulted to sign
already-created keys. Template enabled state changes discovery and generation only; it is not a
signing authorization gate for existing key files. The low-level template store
persists encrypted template bytes only; install/admin code owns the paired key
type state mutation. Activating a
`compiled_provider` library entry uses `activate_key_type` and writes only the
identity state record because the executable provider is already registered in
the binary. Calling `activate_key_type` for an installed YAML template sets its
state record to `enabled` and reloads the identity. Calling `deactivate_key_type`
for an installed YAML template verifies that no key of that `key_type` exists
for the identity, then sets the record to `disabled`. Calling
`deactivate_key_type` for a compiled provider uses the same unused-key guard,
then deletes the state record.

Install is idempotent for an already-installed matching key type/template type. Activation is verified from
the identity-local reload report before success is returned; activation failure rolls back a newly written
encrypted template file when possible. Editing or copying files into `<APSIGNER_DATA>/library/templates/`
does not change available key types until an authenticated admin installs one.

Removal helpers distinguish disabling from removal. Disabling a compiled provider removes only the identity
state record and does not unregister process-global provider code. Disabling a YAML template leaves the
encrypted `.template` installed and sets the identity state record to disabled. Removing an encrypted YAML template
moves the `.template` source to the identity-local deleted key type archive and deletes the state record; this
removal is exposed through authenticated local IPC as `apstore template remove`.
Disabling or removing an installed YAML template requires that no stored identity
key depends on that `key_type`; compiled-provider deactivation has the same
unused-key guard because it removes the identity's compiled-provider opt-in. The
unused check requires the identity master key, scans existing keys, and returns
`key_type_in_use` on the live admin protocol when the guard blocks installed
template disable/removal or compiled-provider deactivation. Live activation,
deactivation, template install, non-generic key generation, key import, and key
delete operations are serialized per identity so key creation cannot race a
lifecycle decision made from a stale state snapshot.

### Keystore Metadata (`.keystore`)

Defined in `internal/crypto/encryption.go` as `crypto.KeystoreMetadata`.

- version 1: salt, encrypted check value, creation time; Argon2id params implicit (`time=1`, `memory=64 MiB`, `threads=4`)
- version 2: same fields plus explicit `kdf_time`, `kdf_memory`, `kdf_threads`

Behavior:

- new keystores are version 2
- version 2 unlock uses stored KDF params
- version 2 metadata with missing or zero KDF params is rejected
- version 1 unlock falls back to the older Argon2id time parameter

### Policy Files (`policy.yaml`, `attestation.yaml`)

The identity-scoped signer safety policy is stored at
`identities/<identity>/policy.yaml`. The identity-scoped attestor component
policy is stored at `identities/<identity>/attestation.yaml`. Each has a JSON
sidecar at `<document>.hmac` that authenticates the exact YAML bytes.

The policy integrity key is derived from the identity master key with HKDF-SHA256
using info string `aplane policy integrity v1`. The derived key is 32 bytes and
is not persisted.

Sidecar JSON fields:

- `version`: integer sidecar version; currently `1`
- `algorithm`: currently `hmac-sha256`
- `key_id`: currently `keystore-master-hkdf-v1`
- `hmac`: hex HMAC-SHA256 over the exact policy document bytes
- `policy_sha256`: optional diagnostic SHA-256 of the policy document
- `signed_at_unix`: optional diagnostic signing timestamp
- `policy_mtime_ns`: optional diagnostic policy-file mtime

Only `version`, `algorithm`, `key_id`, and `hmac` are security fields.
`policy_sha256`, `signed_at_unix`, and `policy_mtime_ns` are diagnostic
metadata; tampering with those fields does not affect the policy integrity
decision.

Policy load behavior:

- unlock/reload verifies both `policy.yaml.hmac` and
  `attestation.yaml.hmac` before parsing and applying policy
- missing `policy.yaml`, missing `attestation.yaml`, or a missing/mismatched
  sidecar fails closed
- during initial locked startup, a policy integrity failure prevents the
  admin-auth unlock from completing and is reported as `auth_result` with
  `code:"unlock_failed"`
- reload failure keeps the previous in-memory policy active
- admin policy writes require an unlocked identity and replace `policy.yaml`
- direct YAML edits to either document require offline `apstore policy sign`
  before the signer trusts them
- `appolicy --yaml` emits the exact verified `policy.yaml` bytes;
  `appolicy --save-policy` reads replacement policy bytes from stdin,
  validates them, and writes those exact bytes plus a fresh sidecar under the
  store mutation lock; `appolicy --save-attestation` does the same for direct
  `attestation.yaml`
- `apstore policy check|verify|sign` checks, verifies, or signs both policy
  documents

### Key Files (`.key`)

Encrypted files with:

- envelope versioning,
- payload format versioning,
- enough metadata to recover address and key type after decryption,
- for LogicSig keys, enough signing metadata to assemble LogicSig args without
  trusting the registered template definition.

Categories:

- native signing keys,
- DSA-backed LogicSig keys,
- generic LogicSig template instances.

Generic LogicSig entries contain salted bytecode, `salt_counter`, and
parameters rather than a private signing key.

Key payload readers normalize legacy/cosmetic field aliases in one parser
boundary (`internal/keys.ParseKeyPayloadMetadata`). `parameters` and `params`
are treated as the same creation-parameter map, and `lsig_bytecode` and
`bytecode_hex` are treated as the same stored bytecode field. A payload that
contains both aliases with different values is rejected as an incompatible key
format instead of choosing one by precedence.

This document uses **v1 signing-metadata keys** for key files that carry
`signing_metadata_version >= 1`. LogicSig key payloads in that form include:

- `signing_metadata_version` — required; key files lacking it are rejected for
  signing and restore
- `salt_counter` — required; the single-byte counter used to select the stored
  off-curve LogicSig bytecode/address
- `signing_args` — optional; the signing-time arg schema in TEAL argument
  order, represented internally by `internal/signingargs.Info`; absent and
  empty are equivalent and mean the key takes no runtime args
- `base_key_type` — required for composed DSA keys, pointing to the signer-side
  base algorithm used for private-key signing and signature arg packing; v1
  signing-metadata DSA keys also persist it when it equals `key_type`
- `template_fingerprint` — optional; the semantic compatibility fingerprint of
  the template/provider definition that created or was bundled with the key,
  when known

Stored LogicSig bytecode and stored signing metadata are authoritative for
signing:

- generic LogicSig signing reads bytecode and orders caller-supplied runtime
  args using stored `signing_args`
- DSA-backed LogicSig signing reads bytecode and stored `signing_args`, signs
  with the stored key material, and uses `base_key_type` to find the signer-side
  base provider that packs the cryptographic signature args
- the generic/composed template registered under `key_type` is not consulted
  to assemble args at sign time

Key address identity is derived from key material, not from signing metadata:

- native signing keys derive their address from stored public/private key
  material, with `key_type` selecting the address derivation implementation
- DSA-backed LogicSig keys derive their account address from stored LogicSig
  bytecode
- generic LogicSig keys persist an `address` field for inventory and lookup,
  but the cryptographic LogicSig address is still the address of the stored
  bytecode; key state repair may fill a missing generic LogicSig `address`
  from bytecode and rejects stored/derived mismatches

Fields such as `signing_args`, `signing_metadata_version`, `base_key_type`,
and `template_fingerprint` are signing/provenance metadata, not address
derivation inputs. `salt_counter` records the byte already embedded in stored
LogicSig bytecode; changing the metadata field alone does not rederive or
change the key address.

Signer key scanning also binds accepted key authority to the canonical address
filename. After decrypting a `.key` file, the scanner derives the payload
address and accepts the file as signing authority only when its basename is
`<derived-address>.key`. Misnamed `.key` artifacts are skipped and reported as
key-file rejection diagnostics; they do not shadow the canonical file for that
address. Key creation/import paths, and restore paths that elect to write a key,
write the canonical address filename. Live restore still skips an existing
canonical key file unless `overwrite:true` is supplied.

Every persisted LogicSig key file must derive an off-curve LogicSig address.
Signer load, key scanning, backup verify, and restore reject LogicSig key
payloads that omit `salt_counter` or whose stored bytecode derives an on-curve
address.

LogicSig salting is a generation-time contract:

- Salt anchor style is a versioned provider/template derivation contract, not a
  wire field. Template-backed programs with omitted `derivation_version` do not
  reserve a generated salt slot; the signer compiles the template as written
  and accepts it only if the unmodified bytecode already derives an off-curve
  LogicSig address. Template-backed programs with `derivation_version: 1` use a
  stack-neutral generated marker preamble
  (`byte 0x41504c414e455f4c5349475f53414c545f56315f005f454e44; pop`) so
  algod can own constant-block layout. Template-backed programs with
  `derivation_version: 2` use a trailing dead-code `bytecblock 0x00` salt
  anchor. Provider-owned bare DSA versions may explicitly choose a reference
  layout such as a fixed `bytecblock 0x00` preamble.
- Salt-style assignments: generic and composed templates with omitted
  `derivation_version` are unsalted, generic and composed templates with
  `derivation_version: 1` use the generated marker, generic and composed
  templates with `derivation_version: 2` use the trailing dead-code
  `bytecblock`, `aplane.falcon1024.v1` uses the Algorand Foundation
  reference-compatible fixed `bytecblock` preamble, and `aplane.ecdsak1.v1`
  uses a fixed `bytecblock` preamble.
- After algod compilation, salted providers patch the selected byte through
  counter values `0..255` and persist the first compiled bytecode whose LogicSig
  address is off-curve. Unsalted template providers perform no patching and
  fail generation if the unmodified address is on-curve.
- Bytecblock-style providers must verify the expected preamble immediately
  after the TEAL version varint; they must not scan arbitrary bytecode for a
  matching byte sequence. Template-backed marker style must locate exactly one
  generated marker and must not match generic `pushbytes 0x00`.
- `salt_counter` records the selected byte for salted providers. It remains
  required on disk for LogicSig key files; unsalted template-derived keys store
  `0` as compatibility metadata. The field is not exposed through signer HTTP
  DTOs or SDK DTOs.
- The stored bytecode, not a live template or regenerated TEAL, is the
  signing authority.

Templates are the source for generation, discovery, and new key creation;
they are not consulted at sign time. `template_fingerprint` is provenance only.
Key inventory surfaces may compare it with the registered local
definition and report a template conflict or unavailable template, but those
notices do not invalidate a key.

#### Signing Authority

The key file is the signing authority. Templates and live providers are not
consulted to reconstruct missing signing metadata.

- A v1 signing-metadata LogicSig key file persists the TEAL bytecode and the
  signing-time argument contract captured at generation.
- Generic LogicSig keys store bytecode, the `salt_counter` that selected the
  off-curve address, and runtime argument schema.
- DSA-backed LogicSig keys additionally store `base_key_type`; the base
  cryptographic provider must be available because the signer must produce and
  pack the DSA signature. The composed template/provider for that `key_type` is
  not required to sign an already-created key.
- A LogicSig key file that contains bytecode but is not a v1 signing-metadata
  key is rejected for restore and signing.

Templates are used for key creation and LogicSig bytecode derivation, creation
parameter and runtime argument metadata in generation surfaces, key-type
catalog/library/install/enable/disable flows, optional backup bundling and
explicit template restore, backup import provenance validation (a bundled
template is recompiled with the bundled key's stored creation parameters and
must reproduce the key's stored LogicSig bytecode), and live provenance
comparison through `template_fingerprint`. `template_fingerprint` is
informational provenance only: inventory surfaces may report a template
conflict or unavailable template, but that status does not invalidate the key
or alter signing behavior.

#### Offline Identity Key Inventory

`apstore keys list` is a local, passphrase-gated inventory surface for the
current product identity's encrypted key files. It decrypts key metadata using
the identity store passphrase and lists successfully scanned key addresses or
component selectors with their key type, durable category, creation timestamp,
and key-file name.

The default human output must not emit private key material, mnemonic material,
or raw public-key hex. Component keys are identified by their `a_` selector,
not by the raw attestor public key. Recoverable key-scan warnings may be
reported while still listing keys that scanned successfully.

#### Attestor Public Key Export Envelope

`apstore attestor export-public <component-key> [output-json]` emits a public-only
JSON envelope for an attestor component key. The command reads the
`keys/<component-key>.public.json` sidecar, verifies that `<component-key>`
equals the canonical selector derived from the public key, and never reads or
decrypts private key material. If the sidecar is missing or malformed, export
fails closed; the operator must regenerate the attestor component key or run an
explicit metadata backfill before exporting.

The envelope schema is:

```json
{
  "schema": "aplane.attestor-public-key.v1",
  "component_key": "a_<sha256-public-key>",
  "key_type": "aplane.attestor-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "<full public key hex>",
  "public_key_size": 1793,
  "public_key_sha256": "<sha256-public-key>"
}
```

`component_key` is always the `a_` selector used to select a local attestor
component key. `public_key_hex` is the raw component public key encoded in hex;
it is the value embedded into attested-account LogicSig bytecode and supplied
as `attestor_public_key` during attested account generation. The envelope makes
no endpoint, policy, ownership, freshness, or trust claim.

#### Attestor Public Key Reference Library

`apstore attestor import-public <export-json> <name>` imports an
`aplane.attestor-public-key.v1` envelope into the target identity's public
attestor reference library:

```text
identities/<identity>/attestors/<name>.json
```

Reference names are normalized to lowercase and may contain lowercase letters,
digits, `.`, `-`, and `_`. The persisted record schema is:

```json
{
  "schema": "aplane.attestor-public-key-ref.v1",
  "name": "lab-att",
  "component_key": "a_<sha256-public-key>",
  "key_type": "aplane.attestor-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "<full public key hex>",
  "public_key_size": 1793,
  "public_key_sha256": "<sha256-public-key>",
  "source": "manual",
  "imported_at": "2026-06-04T00:00:00Z"
}
```

Endpoint discovery may also populate this catalog through
`apshell endpoints sync-attestors`. Synced records use the same schema with
`source: "client_discovery"`, a deterministic generated name
`endpoint-<alias>-<component_key>`, `endpoint_alias`, `last_seen_at`, and
`synced_at`. They are public candidates derived from the client's
`endpoints.yaml`; they are not an attestor ownership proof.

The library is a generation convenience and trust-input inventory for the user
signer. When generating an attested account, callers may provide
`attestor=<name>` instead of `attestor_public_key=<hex>`. The signer resolves
the name to `public_key_hex`, verifies that the reference key type matches the
attested-account key type's required attestor component key type, rejects
requests that provide both forms, and persists only the resolved
`attestor_public_key` in the key file.

Identity-scoped `/keytypes` metadata may expose imported references as a
creation parameter named `attestor` with `type:"select"` and `options[]`
containing reference names whose component key type matches the attested
account key type. This is UI metadata for generation clients such as `apadmin`;
the durable key file still stores the resolved `attestor_public_key`.

### Template Files (`.template`)

Encrypted YAML using master-key encryption. `BaseTemplateSpec` contains:

- `schema_version`
- `derivation_version` (optional; omitted means no generated salting)
- `template_type` (`generic` or `composed`)
- `base_key_type` (required for `composed`, rejected for `generic`)
- `template_mode` (`strict` or `generated`)
- `publisher`
- `family`
- `version`
- `display_name`
- `description`
- `display_color`

Template capability notes:

- importable template YAML uses `schema_version: 1`
- omitted `derivation_version` compiles the template without a generated salt
  anchor and therefore succeeds only when the unmodified bytecode already
  derives an off-curve LogicSig address
- `derivation_version: 1` uses the legacy generated `pushbytes; pop` marker,
  and `derivation_version: 2` uses the trailing dead-code `bytecblock` salt
  anchor; new template-derived key types that need reliable generation should
  use `derivation_version: 2`
- `template_mode` is required for imported, installed, bundled, and library
  templates; templates without `template_mode` are rejected rather than
  interpreted
- `creation_params` may include scalar params, `select` params with `options[]`,
  plus unordered `address[]` and `uint64[]` list params; public key type
  surfaces preserve optional `input_modes` UI metadata for alternate parameter
  entry forms such as hash/preimage toggles
- strict generic-template YAML and Falcon composed-template YAML use declared `template_variables`
  and symbolic `$name` references that render through generated `intcblock` and `bytecblock`
  constants
- user-authored template TEAL must be relocatable: raw `bytecblock` or
  `intcblock` declarations, numeric `bytec N` or `intc N` references, and
  short forms such as `bytec_0` or `intc_0` are rejected during template
  validation
- generated-mode YAML supports restricted creation-time list expansion
- supported generated-mode list expansion form is `{{range @name}} ... {{.}} ... {{end}}`
- list expansion is creation-time only; it is not a runtime-arg feature
- Falcon/composed suffixes are predicate fragments, not standalone TEAL programs
- Falcon/composed suffixes must not contain `return`; verifier-first composition owns the final `int 1 / return`

### Audit Log

JSONL at `audit.log`, `0600` permissions, fsynced per write, UTC timestamps. Identity-scoped events carry `identity_id`; process-level events omit it.

Audit entries may include:

- `identity_id`: owning identity field,
- `target_identity_id`: signing/admin identity targeted by the action,
- `principal`: principal field,
- `requester_principal`: principal that requested the action,
- `approver_principal`: principal that approved or rejected the action,
- `admin_session_id`: admin protocol session ID when the event came from an admin session,
- `transport`: `ipc`, `ssh`, `http`, or omitted for process events,
- `remote_addr`: remote address when available,
- `reason`: rejection, failure, or denial reason when available,
- `outcome`: requested, approved, rejected, failed, connected, disconnected, or similar action outcome.

Product-mode audit values collapse to the product identity. Target identity,
requester, and approver remain distinct fields in the log shape.

Rotation:

- size-based at 10 MB
- rotate to `audit.log.1`
- previous `audit.log.1` rotates to `audit.log.2`
- two rotated generations retained

Events:

- `SERVER_START`
- `SERVER_STOP`
- `SIGN_REQUEST`
- `SIGN_APPROVED`
- `SIGN_REJECTED`
- `SIGN_FAILED`
- `AUTH_FAILED`
- `AUTHORIZATION_DENIED`
- `KEY_RELOAD`
- `KEY_GENERATED`
- `KEY_DELETED`
- `KEY_IMPORTED`
- `KEY_REJECTED`
- `BACKUP_CREATED`
- `BACKUP_FAILED`
- `BACKUP_RESTORE_PREVIEWED`
- `BACKUP_RESTORE_PREVIEW_FAILED`
- `BACKUP_RESTORE_STARTED`
- `BACKUP_RESTORE_COMPLETED`
- `BACKUP_RESTORE_PARTIAL`
- `BACKUP_RESTORE_FAILED`
- `STORE_INITIALIZED`
- `STORE_INITIALIZE_FAILED`
- `PASSPHRASE_CHANGED`
- `PASSPHRASE_CHANGE_FAILED`
- `SESSION_CONNECTED`
- `SESSION_DISCONNECTED`
- `IDENTITY_LOCKED`
- `TOKEN_PROVISIONED`

Signing-audit semantics:

- `SIGN_APPROVED` is emitted only for transactions the signer actually signs
- foreign and passthrough entries may appear in `SIGN_REQUEST`/planning context, but are not recorded as `SIGN_APPROVED`
- signing audit over HTTP records `transport:"http"` and the token-authenticated identity as requester
- approval audit enriches approved/rejected records with the admin session approver principal when an admin response supplies it
- approved/rejected signing records include `policy_rule_id` when a policy rule forced manual review before the operator decision
- admin authorization-denial audit records event `AUTHORIZATION_DENIED`, outcome `denied`, admin session ID, transport, target identity, principal attribution, action/resource details in `reason`, and remote address when available
- session connected/disconnected audit records the admin session ID, transport, target identity, and remote address
- key-management audit events are emitted for both REST and authenticated IPC admin operations
- `KEY_REJECTED` is emitted when signer key scanning skips a key file that
  violates a load-time key-file invariant; for LogicSig salt failures,
  `reason` includes the key filename and rejection reason

Backup-audit semantics:

- `BACKUP_CREATED` is emitted when an authenticated admin backup operation
  writes a managed archive; `reason` contains the archive path
- `BACKUP_FAILED` is emitted when that operation fails; `reason` contains the failure reason
- `BACKUP_RESTORE_PREVIEWED` is emitted when an authenticated preview operation successfully decrypts and inspects a managed archive; `reason` contains the resolved archive path and `key_count` contains previewed keys
- `BACKUP_RESTORE_STARTED` is emitted when an authenticated admin restore operation begins; `reason` contains the requested archive path
- `BACKUP_RESTORE_COMPLETED` is emitted when a restore operation completes without per-key errors; `reason` contains the resolved archive path and `key_count` contains restored keys
- `BACKUP_RESTORE_PARTIAL` is emitted when a restore operation restores at least one key and fails at least one key; `reason` contains the resolved archive path and counts
- `BACKUP_RESTORE_FAILED` is emitted when a restore operation fails before restoring any key; `reason` contains the failure reason
- `BACKUP_RESTORE_PREVIEW_FAILED` is emitted when an authenticated preview request fails; `reason` contains the failure reason

Store-management audit semantics:

- `STORE_INITIALIZED` is emitted when authenticated local IPC store initialization succeeds
- `STORE_INITIALIZE_FAILED` is emitted when authenticated local IPC store initialization fails
- `PASSPHRASE_CHANGED` is emitted when authenticated local IPC passphrase rotation succeeds; re-encrypted key/template counts are recorded on the event
- `PASSPHRASE_CHANGE_FAILED` is emitted when authenticated local IPC passphrase rotation fails

## Authentication, SSH, and Token Provisioning

HTTP auth uses `Authorization: aplane <token>`.

Client and signer token files are bearer credentials. Token reads reject
group/world-accessible `aplane.token` files and report a `chmod 600`
remediation; token writes create owner-only files.

SSH server uses Ed25519 host keys, auto-generated at `.ssh/ssh_host_key`.

Authentication requires both factors in one handshake:

- public key enrolled for the bound identity in `identities/<identity>/.ssh/authorized_keys`
- API token as SSH username

The API token is identity-scoped. In identity-aware mode the SSH server scans
registered, non-decommissioned identity authenticators and accepts the token only
when exactly one identity matches. The authenticated token identity is then used
for the authorized-key check, connection tracking, and optional admin subsystem
pre-binding.

`ssh.authorized_keys_path` is part of the server config surface; in product mode identity-scoped SSH authorization and enrollment are sourced from `identities/<identity>/.ssh/authorized_keys`.

Invalid tokens incur a 5-second delay.

Token provisioning flow:

1. client connects as `request-token:<identity>`
2. server rejects unknown or decommissioned identities before SSH auth succeeds
3. key-only SSH auth succeeds for supported identities
4. the `provision` exec request re-checks that the identity is supported
5. server verifies an admin client is connected for the requested identity
6. admin approves via TUI
7. server enrolls the public key for that identity
8. server generates or loads token
9. token is sent over SSH exec channel
10. audit log is written after confirmed delivery

The callbacks are separated as approval, key enrollment, issuance, then audit.

Product-facing clients request tokens for the product identity. The identity
parameter exists in the wire shape because the backend provisioning path is
identity-scoped.

Token revocation behavior in identity-aware mode:

- rotate the target identity's token file and in-memory authenticator,
- record the new token generation,
- send `token-revoked@aplane` to active SSH connections authenticated for that identity with older generations,
- close those target-identity SSH connections,
- leave other identities' SSH connections open.

`sshtunnel.Server.UpdateToken()` is the global updater. Signer
identity-aware revocation uses `CloseIdentityConnections(identityID,
minTokenGeneration, reason)` instead. If SSH authentication races token
rotation, authentication may complete against the old token, but connection
tracking closes the stale target-identity connection after the authenticator is
updated.

SSH server callbacks are startup-only. Token validation, key checking,
key enrollment, token provisioning, operator checks, provisioning identity
checks, session notifications, and admin channel callbacks must be configured
before `Start`; setters fail fast after the server has started.

## Approval and Policy Contracts

For the current policy tier model, storage ownership, and rule inventory, see
[ARCH_POLICY.md](ARCH_POLICY.md). This section records compatibility-bearing
behavior.

Transaction handling is an ordered, short-circuiting policy and approval engine:

1. **Auto-Rejection**: `EvaluateAutoRejectionRules` runs hard safety rules first.
   Any violation rejects the request and no later phase can approve it.
2. **Always Review**: `EvaluateAlwaysReviewRules` runs after auto-rejection.
   Matching rules require operator review even when `user_auto_approve:true`.
3. **Auto-Approval**: `EvaluateAutoApprovalRules` runs only after
   auto-rejection passes and no Always Review rule matched. Matching rules
   approve explicit low-risk request shapes without operator review.
4. **User Auto-Approve fallback**: requests not rejected, not forced to review,
   and not explicitly auto-approved use `user_auto_approve`.
   `user_auto_approve:false` requires operator approval;
   `user_auto_approve:true` signs without operator review.

Auto-rejection policy includes:

- `reject_foreign_rekey` (rejects foreign rekey targets; rekeying to an address held by the current signer is allowed)
- `reject_close_remainder`
- `reject_asset_close`
- `reject_clawback`
- `max_fee_microalgos`
- network-scoped `max_algo_payments`
- network-scoped `max_asa_amounts`
- `transfer_policy` blocked destinations, route misses,
  close/clawback denials, and `reject_above` thresholds for direct `pay` and
  `axfer` movements
- YAML-only `key_overrides` keyed by signing auth address or attestor component selector

Policy enforcement stores and compares `review_algo_payments` and
`max_algo_payments` in raw microAlgos; admin-facing input, display, and
review/rejection text use ALGO display units.

Always-review policy includes:

- `always_review_warnings`: require operator review for requests that carry
  warning-level approval findings, such as rekey, close-out, clawback, asset
  close, or unusually high fees.
- network-scoped `review_algo_payments`
- network-scoped `review_asa_amounts`
- `transfer_policy` `on_no_route: review` route misses and
  `review_above` thresholds for direct `pay` and `axfer` movements

Auto-approval policy includes:

- `auto_approve_self_noop_transfer`: approve a single signer-controlled request without operator review only when the real transaction is either a 0 ALGO payment to self or a 0-unit ASA transfer to self, has no caller-provided group, no passthrough/foreign slots, no rekey, no close remainder, no asset close, no clawback sender, no note, no lease, and its fee after subtracting signer-added dummy fees is at most 1000 microAlgos. Server-generated LogicSig-budget dummy transactions are allowed only when they use APlane's embedded dummy LogicSig address, match the real transaction's network and validity window, carry no fee, and the real transaction fee increase exactly covers those dummies. The ASA form may opt into an asset if the account does not already hold it.

`user_auto_approve` is not an auto-approval policy rule. It is the per-identity
fallback switch stored in identity config and shown in `apadmin` as
`User Auto-Approve`. It controls only the operator-default fallback after
auto-rejection, forced review, and explicit auto-approval have all had a chance
to run.

Client-signing `transfer_policy` is persisted in `policy.yaml`; attestor
component `transfer_policy` is persisted in `attestation.yaml`. Both are
validated by the normal policy load path and by `apstore policy
check/sign/verify`. `appolicy --save-policy` and apadmin whole-file replacement
target `policy.yaml`; `appolicy --save-attestation` targets
`attestation.yaml`. Transfer policy is not projected through mutable admin IPC
policy settings and has no guided `apadmin` editor surface; `apadmin` can
request an active signing-policy snapshot for inspection and can ask the signer
to hot-replace the whole signing-policy YAML file. The `appolicy --yaml` /
`--save-policy` / `--save-attestation` CLI path is the scriptable offline
editor for byte-preserving route-table edits.
Route matches are allow-to-continue, not approvals.

Transaction-level hard policy skips passthrough and foreign slots because those
positions are not signed by this signer. Those slots participate in group
consistency checks, group-level policy context, approval rendering, warning
analysis, and audit visibility.

Operator-visible warning analysis includes:

- `RekeyTo`
- `CloseRemainderTo`
- `AssetCloseTo`
- clawback via `AssetSender`
- excessive fees above 1 ALGO

Warnings are displayed but do not block approval. They are relevant to the
manual review fallback path; when `always_review_warnings:true`, warnings force
operator review before auto-approval or the `user_auto_approve` fallback can
sign the request. Groups get group-level approval; single transactions get
transaction-level approval. Signing approval timeout is the identity-effective
`approval_wait` value, defaulting to 60 seconds.

For HTTP `/sign`, request context cancellation cancels queued or pending manual
approval waits when the cancellation reaches apsigner. Clients that need
reliable prompt dismissal across tunnels or other transports should also send
`POST /sign/cancel` with the same `request_id` from a fresh request context.
Canceled approval requests are removed from the coordinator and must not be
delivered later as stale prompts. If the request was already sent to an admin
client, apsigner sends a best-effort `sign_request_canceled` notification with
reason `client_canceled` so the client can dismiss the prompt. Approval timeout
also removes the request and sends `sign_request_canceled` with reason
`timeout`. Both are distinct from operator rejection; the current HTTP mapping
is service unavailable. `POST /sign/cancel` returns `state:"canceled"` for a
matched live request and `state:"not_found"` when the ID is no longer live or
was never known to the authenticated identity.

Broader group-level or structural policy constraints are not part of this compatibility surface.

## Runtime Lifecycle and Decommission

Identity lifecycle is logical, not destructive.

- `identities/<identity>/config.yaml` with `decommissioned:true` disables the identity at startup.
- live decommission persists `decommissioned:true`, then marks the runtime decommissioned.
- if persistence fails, the runtime remains active and pending approvals are not failed.
- decommission fails pending signing and token-provisioning approvals with an identity-decommissioned reason.
- decommission locks the runtime if it is unlocked and stops the identity watcher.
- decommissioned identities reject unlock, reload, token provisioning, HTTP routing, SSH token auth, SSH key checks, and SSH key enrollment.

Registry removal and runtime decommission are separate contracts:

- `Registry.Remove(identityID)` prevents new registry lookup only.
- in-flight requests may retain a `*identity.Runtime` after registry removal.
- final signing uses the runtime lifecycle lease, not a registry lookup, to decide whether it may execute.
- if decommission wins before final execution obtains the lease, signing fails cleanly; if execution already holds the lease, decommission waits for release.

## Key Watching and Reload

Key/template watching is implemented via `fsnotify` and owned per identity runtime.

Watched paths:

- `identities/<identity>/keys/`
- `identities/<identity>/keytypes/`
- the identity directory for late directory creation

Mechanism:

- reacts to Create, Write, Remove, and Rename on `.key`, `.template`, and key type state `.json` files
- missing key and key type directories are tracked and added later when created
- when unlocked, qualifying changes trigger immediate reload
- when locked, the watcher remains running and marks the identity dirty
- watcher-triggered reload obtains the identity mutation lock before scanning keys/templates
- admin mutation paths that already hold the identity mutation lock call direct reload paths and must not call watcher-only reload entrypoints

Debounce:

- 500 ms debounce
- each qualifying event resets the timer

Lifecycle:

- starts when the identity runtime is unlocked or initialized
- remains running across lock/unlock transitions
- stops on runtime shutdown or decommission

## Template Reload Contract

`reloadKeysLocked()` order:

1. master key
2. template registration
3. key scan
4. index replacement
5. session activation
6. notifications

Template installation and identity key-type state are resolved from key type
state records before key scan so generation/discovery state is current. The key scan
classifies generic LogicSig keys and exposes signing args directly from the
v1 signing-metadata key payload. LogicSig key files missing `salt_counter` or
whose bytecode derives an on-curve address are rejected during scan. LogicSig
key files missing `signing_metadata_version` are rejected when signing or
restoring would otherwise depend on missing durable signing metadata.

New enabled template `key_type` values activate on reload/unlock. Disabled
installed templates remain stored but are skipped. Reload may change what key
types can be generated or displayed as available; it must not change signing
behavior for an existing key file.

Key type immutability:

- a `key_type` is a compatibility boundary and must not be redefined in-place,
- provider registries are process-global within one `apsigner` process,
- identity-private provider namespaces are not part of the current contract,
- custom template/provider authors must use globally unique `key_type` values in one signer process,
- signer-data library templates are authoritative install sources when present,
- keystore templates may add new non-built-in `key_type` values but must not override built-ins,
- reload/unlock may activate new key types or ignore idempotent re-loads of the same definition, but must not replace an existing conflicting definition.

Identity filtering:

- a process-global provider can exist without being visible to every identity,
- `/keytypes`, admin `list_key_types`, and key generation filter by the target identity's default-enabled key types plus enabled identity state records,
- a globally registered generic/composed template that is not installed or enabled for an identity is not generatable by that identity,
- existing keys remain isolated by identity keystore ownership; provider lookup only supplies compatible signing/derivation code for keys already owned by that identity.

`internal/signerapp/templates` reports this through a `ReloadReport` with:

- `KeyCount`
- `TemplateNotices`
- `TemplateWarnings`
- `GenericActivatedKeyTypes`
- `ComposedActivatedKeyTypes`
- `GenericIdempotentKeyTypes`
- `ComposedIdempotentKeyTypes`
- `GenericDisabledKeyTypes`
- `ComposedDisabledKeyTypes`
- `GenericConflictingKeyTypes`
- `ComposedConflictingKeyTypes`
- `GenericInvalidKeyTypes`
- `ComposedInvalidKeyTypes`
- `InvalidStateRecordKeyTypes`
- `CompiledInvalidKeyTypes`
- `GenericExternalEditKeyTypes`
- `ComposedExternalEditKeyTypes`
- `GenericOrphanedKeyTypes`
- `ComposedOrphanedKeyTypes`
- `CompiledIdempotentKeyTypes`
- `CompiledConflictingKeyTypes`

Admin library template install verifies activation from the identity-local
`ReloadReport`: the installed key type must appear in the activated or
idempotent bucket for the requested template family. A process-global provider
registry hit alone is not sufficient proof that the bound identity accepted the
template during reload.

## Plugin Contract

Process-isolated, JSON-RPC over stdin/stdout.

Discovery order:

1. Read enabled plugin names from `$APCLIENT_DATA/plugins.yaml`.
2. Load each enabled plugin from `$APCLIENT_DATA/plugins.available/<name>`.

Missing or integrity-failing enabled plugin directories are skipped with a
warning. Invalid `plugins.yaml` syntax or unsafe plugin names fail discovery.
If `plugins.yaml` is missing, no plugins are loaded.

Activation file format:

```yaml
enabled_plugins: []
```

On first install, installers create an empty activation list. `algokit-localnet`
is staged under `plugins.available/` but never enabled by default; `aplocalnet`
is the supported utility that explicitly activates it for LocalNet setups.
Existing `plugins.yaml` activation choices are preserved when the installer is
run again against the same client data directory.

The in-tree reference plugin at `examples/external_plugins/echo-plugin/` is not
bundled into release archives; it is the canonical example for plugin authors
and loads only when explicitly copied into a client `plugins.available/`
directory and listed in `plugins.yaml`.

The bundled `algokit-localnet` plugin is scoped to the `localnet` execution
network and implements `localnet status`, `localnet genesis`, `localnet
accounts`, and `localnet fund`. It uses algod and the Algorand Key Management
Daemon (KMD), not indexer. During initialization it accepts the generic
`network`, `algodUrl`, and `algodToken` fields, but the following environment
variables take precedence for LocalNet operation:

- `APLANE_LOCALNET_ALGOD_URL` (default `http://localhost:4001`)
- `APLANE_LOCALNET_KMD_URL` (default `http://localhost:4002`)
- `APLANE_LOCALNET_TOKEN` (default AlgoKit LocalNet token)
- `APLANE_LOCALNET_WALLET` (default `unencrypted-default-wallet`)
- `APLANE_LOCALNET_WALLET_PASSWORD` (default empty)

JSON-RPC methods:

- `initialize`
- `execute`
- `getInfo`
- `shutdown`

Callbacks into apshell:

- `getAccount`
- `listAccounts`
- `getBalance`
- `getAssetInfo`
- `getAppInfo`
- `signTransaction`
- `log`

`initialize` carries network/algo context including:

- `network`
- `algodUrl`
- `algodToken`
- optional `indexerUrl`
- plugin runtime/protocol version (`version`, `"1.0"`, not the
  apshell build version)

`execute` carries:

- selected plugin command
- argv-style args
- execution context including known accounts, alias/address maps, structured asset metadata, network metadata, suggested params, and continuation state

Plugins return:

- optional `message`
- `transactions` using raw unsigned msgpack transaction intents only
- optional top-level `localSigners` for plugin-controlled ephemeral keys
- optional `data`
- optional `presentation`
- optional `requiresApproval`
- optional `continuation`

`data` is the canonical machine-readable payload.
`presentation` is optional human-oriented display metadata for apshell text rendering.
Raw `data` is not part of the default human CLI rendering contract.

Manifest contract:

- plugin directories must contain `manifest.json`
- required manifest fields: `name`, `version`, `description`, and `executable`
- `manifest_format` defaults to `1.0`; only `1.0` is accepted
- `timeout` is seconds and defaults to 30
- at least one executable command is required
- each command requires `name` and `description`
- function-only plugins are rejected
- `functions` metadata is consumed for AI prompts and JS docs but does not
  create an executable surface independent of commands
- symlinked plugin directories are ignored

Integrity and sandboxing:

- every plugin must include `checksums.sha256`
- checksum entries use `<64-hex-sha256><one-or-two-spaces><relative-file>`
- the plugin executable must be listed in `checksums.sha256`; if `executable`
  names a system command, the first manifest arg is verified instead
- checksum paths must stay within the plugin directory
- external plugins require OS sandboxing; Linux uses bubblewrap, macOS uses
  `sandbox-exec`, and unsupported platforms reject plugin execution rather than
  running plugins unsandboxed

## MCP Contract

Six MCP tools:

| Tool | Parameters | Purpose |
|------|-----------|---------|
| `execute` | `command` (string) | Execute shell commands |
| `mcp_reference` | none | Return the shell command reference |
| `js` | `code` (string) | Execute JavaScript with structured results |
| `js_reference` | none | Return the JavaScript API reference |
| `jssave` | `path` (string), `filename` (string, optional alias), `code` (string, optional), `last` (bool, optional), `overwrite` (bool, optional) | Save JavaScript for later execution |
| `jslist` | none | List saved JavaScript scripts in the data directory's `scripts/` folder |

Shared behavior:

- stdout is reserved for MCP JSON-RPC
- command output is redirected to stderr
- execution is serialized with an in-process mutex
- auto-confirm is enabled

### `execute` tool

The `execute` tool description is built from a static reference plus plugin `mcp.md` files.

Structured JSON commands:

- `keys`
- `status`
- `accounts`
- `balance`
- `holders`
- `participation`
- `keytypes`
- `info`
- `app read`
- `alias` with no args
- `sets` with no args
- `asa list`
- `verbose`
- `write`
- plugin commands returning `PluginResult`

Fallback behavior:

- all other commands fall back to captured text
- silent success normalizes to `OK`
- error results append `Error: ...` after any captured output

JSON results are returned as text containing JSON bytes via `mcp.NewToolResultText(string(data))`, not as typed JSON content objects.

Blocked commands in `execute`:

- `js` (use the `js` MCP tool instead)
- `jssave` (use the `jssave` MCP tool instead)
- `jslist` (use the `jslist` MCP tool instead)
- `request-token`
- `quit`
- `exit`
- `keyreg` paste mode

Blocked commands are matched by literal command name before shell alias
resolution. Blocked exit spellings are `quit` and `exit`; the `q` alias
is not blocked unless `internal/apshellcli/mcp.go` is updated.

### `mcp_reference` tool

Returns the shell command reference including plugin commands. No parameters. Runs the `help` command internally to produce a live listing.

### `js` tool

Executes JavaScript in the Goja runtime.

Response shape:

```json
{"value": <return-value>, "output": "<print-output>"}
```

- `value`: the JSON-serialized return value of the last expression (omitted if `undefined`/`null`)
- `output`: captured `print()` output (omitted if empty)

Errors are returned as MCP error results. If `print()` output was produced before the error, it is prepended to the error message.

The `code` argument is required.

### `js_reference` tool

Returns the embedded `USER_JSAPI.md` content. No parameters. Stateless.

### `jssave` tool

Saves JavaScript code to a file for later execution via `js <file.js>`.

- `path` is required (`filename` is an alias)
- `code` is required unless `last=true`
- if `path` contains no `/`, it is saved under the data directory's `scripts/` folder
- otherwise, `path` must be absolute, so `/` must be the first character
- `.js` is appended if missing
- existing files are rejected unless `overwrite=true`

Returns `{"path": "<absolute path>"}` on success.

### `jslist` tool

Returns saved JavaScript scripts in the data directory's `scripts/` folder.

No parameters. Response shape:

```json
[{"name": "<filename>", "size": <bytes>, "mtime": <unix seconds>}, ...]
```

Entries are sorted by name. Returns an empty array if the directory does not exist or contains no `.js` files.

### Shell parity

The REPL `js`, `jssave`, and `jslist` commands and the MCP `js`/`jssave`/`jslist` tools share the same underlying helpers (`captureJSExecution`, `saveJSScript`, `listJSScripts`); the REPL commands produce human-friendly output while the MCP handlers produce structured JSON directly, without re-entering the shell parser. The REPL `js` command additionally accepts `-help` to print the JavaScript API reference text; MCP clients fetch the same reference by calling `js_reference`.

## Backup and Restore Contract

Backup and restore are implemented in `internal/backup`.

Export:

1. decrypt key using store master key
2. if a key is template-backed, bundle key JSON and template YAML into a
   `BackupBundle` using installed identity-local template YAML when available;
   generated bundles set `backup_bundle: 1` plus `payload_version: 1`
3. re-encrypt with standalone passphrase using envelope version 2
4. write `.apb` and return SHA256 checksum

`ExportAllKeys()` writes all exports into an `apb/` subdirectory.

Managed archive packaging:

- `apstore backup create` asks the signer daemon to write a managed `.tar.gz` archive
- managed archives are stored under `backups/<identity>/aplane-backup-YYYYMMDD-HHMMSS.tar.gz`
- `apstore backup export` resolves a selected managed archive by filename,
  managed path, or checksum, copies it into a caller-selected destination
  directory using the managed archive filename, creates the destination directory
  when needed, and verifies the copy
- the archive contains `README.md`, `apb/*.apb`, and policy snapshots at
  `policy/policy.yaml`, `policy/policy.yaml.hmac`,
  `policy/attestation.yaml`, and `policy/attestation.yaml.hmac`
- the tarball is packaging only; `.apb` remains the cryptographic backup unit
- the archived policy sidecar is source-store provenance material only; restore
  does not install it as the destination sidecar

Live signer-managed backup:

- `apadmin` can trigger a signer-managed backup for the bound, unlocked identity
- the operator supplies an export passphrase over the authenticated admin session
- the signer uses the unlocked runtime master key; it does not re-prompt for the store passphrase
- output path is signer-managed, not operator-chosen
- archives are written under `backups/<identity>/aplane-backup-YYYYMMDD-HHMMSS.tar.gz` beneath the signer data root
- archive layout matches managed backups: `README.md`, `apb/*.apb`, and
  `policy/`
- signer-managed backup covers active key files for the bound identity plus a
  verified policy snapshot; it does not export deleted archives, other
  identities, or live runtime state
- `apstore backup import` validates an external `.tar.gz`/`.tgz` archive,
  prompts for the export passphrase, decrypts each `.apb` payload, and publishes
  it under `backups/<identity>/` only after deep payload validation succeeds
- when an imported `.apb` contains bundled generic or composed template YAML,
  import recompiles the bundled template with the key's stored creation
  parameters and verifies that the result exactly matches the key's stored
  LogicSig bytecode; mismatches reject the import
- this bundled-template bytecode check requires a TEAL compile algod endpoint;
  if compilation is unavailable, the import is rejected rather than admitted
  without the provenance check
- restore preview/apply perform passphrase-backed inspection and mutation
  through the signer daemon

Live signer-managed restore:

- `apadmin` exposes this as the interactive restore path for signer-managed
  backup/imported archives; `apstore restore preview/apply` exposes the
  scripted daemon-owned restore path
- `apadmin` restore uses restorable archives under `backups/<identity>/`
- preview and apply resolve bare names or absolute managed paths from
  `backups/<identity>/`
- restore rejects paths outside the identity backup directory, unsupported
  archive extensions, symlinks, non-regular files, missing archives, and
  archives with no `apb/*.apb` files
- preview requires the export passphrase before showing key addresses or key types; wrong-passphrase or pre-decrypt payload errors do not echo filename-derived addresses
- preview decrypts and inspects backup payload metadata, reports whether each key already exists, and does not write key, template, or key type state
- failed preview/restore decrypt or payload parse attempts are rate limited with per-identity/archive exponential backoff; rate-limited responses use `code:"restore_rate_limited"`
- restore decrypts selected `addresses`; if `addresses` is omitted, all `.apb` payloads in the archive are attempted
- restore skips existing key files unless `overwrite:true` is supplied
- restore reloads the bound identity runtime after one or more keys are restored
- restore does not install archived policy documents or sidecars; restoring
  policy is an explicit manual recovery operation, and the destination store
  must sign fresh sidecars before the signer trusts restored policy
- restore is per-key: failed keys are reported in `errors[]`, skipped existing keys are reported in `skipped[]`, successfully written keys are reported in `restored[]`, and non-fatal restore notices such as skipped bundled templates are reported in `warnings[]`

Restore:

- `ParseBackup()` detects plain `KeyPair` JSON or bundled `BackupBundle`;
  `backup_bundle` is a sentinel, while `payload_version` is the bundle payload
  schema version. Missing `payload_version` is treated as legacy v1; unknown
  sentinels or payload versions are rejected.
- restore `warnings[]` entries have optional `address`, optional `key_type`, and `warning`; warnings are informational and do
  not change restore success/failure
- bundled templates are checked against the authoritative definition for their
  `key_type`; this check protects template installation and provenance, not
  signing authority — the key file is the signing authority
- authoritative order is:
  1. signer-data library template for that `key_type`, if present
  2. existing identity-local keystore template, whether enabled or disabled
  3. incoming bundled template, if no authoritative local source exists
- identical signer-data library definitions are treated as authoritative and may be installed into the identity store rather than
  trusting the bundled copy
- conflicting same-`key_type` template definitions are rejected for explicit template restore; for key restore, the key is
  written and the conflicting bundled template is skipped rather than overwriting or activating the local template; the skip is
  surfaced in restore `warnings[]`
- library-visible compiled providers are activated for the identity when a key of that type is restored; this writes the normal
  `identities/<identity>/keytypes/<key_type>.json` state record and is idempotent
- a LogicSig key restore is rejected when the key payload has bytecode but is not a v1 signing-metadata key; templates are not
  consulted to reconstruct missing signing metadata
- a generic LogicSig key restores from its key payload alone; a DSA LogicSig key restores when its stored `base_key_type` is
  supported by the binary
- if a bundled template fingerprint can be computed and the key lacks
  `template_fingerprint`, restore annotates the restored key with that
  provenance before encrypting it into the destination keystore
- if an installed identity-local template exists but is disabled, explicit template restore can re-enable it; key restore does
  not require enabling a template for signing
- single-key restore is transactional at the key level: restore-required template installs and compiled-provider activations are rolled
  back if the later key-file write fails
- restore apply is per-key, not all-or-nothing; one key may fail while others succeed

Local rescue surface:

- normal `apstore` mutations are local IPC operations owned by the daemon
- `apstore verify` is a read-only local archive inspection command
- `apstore rebuild` is the only local mutating rescue command; it refuses to run when the destination identity directory already exists and uses the store lock to avoid concurrent signer access

## Error Model

Internal sentinel errors include, for example, in `internal/keystore`:

- `ErrKeyNotFound`
- `ErrKeyExists`
- `ErrNotExportable`
- `ErrInvalidPassphrase`
- `ErrStoreLocked`

Errors are wrapped with contextual `%w`.

SDK-facing typed errors in Go include:

- `ErrAuthentication`
- `ErrSigningRejected`
- `ErrSignerUnavailable`
- `ErrKeyNotFound`
- `ErrSignerLocked`
- `ErrKeyDeletion`
- `ErrLogicSigRejected`
- `ErrInsufficientFunds`
- `ErrInvalidTransaction`
- `ErrTransactionRejected`

`TransactionError` wraps rejection details with optional TxID.

## SDK Contracts

All SDKs communicate via the same HTTP REST API as `apshell`. Auth header is `Authorization: aplane <token>`.

Cross-SDK compatibility-bearing behavior:

- concatenated-group and list-per-slot signing APIs are distinct supported shapes
- passthrough semantics are first-class for final signing
- high-level signing helpers return base64 payloads converted from server hex
- `FromEnv` and connection helper path resolution are part of the product contract
- SDKs expose the authenticated `/status` DTO, including
  `keyset_revision` and `approval_wait_seconds`, and include the matching
  signer API fixture in their contract suites.
- SDKs decode non-2xx HTTP bodies as `signerapi.ErrorResponse` with top-level
  `error`. Endpoint-specific success DTOs are not the error envelope.
- SDK/client `/sign` deadlines must be long enough for the identity-effective
  signer approval wait. The repo-owned signer client discovers
  `/status.approval_wait_seconds` and uses that value plus slack; external SDKs
  should avoid defaults shorter than the configured approval wait. When
  `/status` discovery fails or older signers omit `approval_wait_seconds`,
  clients use the documented compatibility fallback deadline rather than the
  short inventory/health timeout.
- SDK `/sign` calls should include an opaque `request_id` when the client may
  need cancellation. SDKs should expose `/sign/cancel` and use it for
  best-effort cleanup when a local timeout, caller cancellation, or transport
  disconnect ends a live synchronous signing request. Go supports
  caller-initiated cancellation through `context.Context`; Python high-level
  signing accepts a caller-owned `request_id` so applications can cancel from
  another thread; TypeScript high-level signing accepts a caller-owned
  `requestId` and `AbortSignal`.

Go SDK specifics:

- `ConnectSSH(host, token, sshKeyPath, opts)` establishes SSH tunnel then HTTP
- `FromEnv(opts)` resolves config/token from client data dir and requires signer endpoint routing
- `NewSignerClientWithToken(baseURL, token)` supports caller-owned transport and direct client construction
- `SetHTTPClient(client)` overrides the HTTP transport for advanced callers.
  If caller-owned transport sets a global timeout shorter than the effective
  signing approval wait, the SDK cannot extend that deadline.
- `GetKeysResponseWithContext(ctx)` returns the raw `/keys` DTO. In-tree client
  code carries locked-signer state in an internal wrapper, not in the HTTP DTO.
- `GetStatusWithContext(ctx)` returns the raw `/status` DTO for keyset
  revision and approval-wait discovery
- `PlanRequestsWithContext(ctx, requests)` and `SignRequestsWithContext(ctx, requests)` expose server-shaped `/plan` and `/sign` request flows directly
- raw request methods operate on SDK DTOs (`SignRequest`, `KeysResponse`,
  `PlanGroupResponse`, `GroupSignResponse`) rather than the base64-returning
  convenience layer. `SignResponse` is a legacy source-compatibility type; the
  live `/sign` response is `GroupSignResponse`.
- `Config.NewAlgodClient(network)` is part of the supported Go SDK config surface
- `GroupPlanResponse`, `RuntimeArgInfo`, and `SigningArgInfo` are compatibility aliases for `PlanGroupResponse`, `RuntimeArg`, and `SigningArg`
- input uses `go-algorand-sdk` `types.Transaction`

TypeScript and Python SDKs preserve the same broad behaviors:

- normal signing returns base64 payloads
- list-returning APIs preserve per-slot outputs
- foreign `/sign` requests are rejected client-side
- signer status helpers expose `/status` and are used to size signing
  request deadlines when callers do not provide an earlier explicit timeout
- raw `signRequests` / `sign_requests` APIs accept one or more `/sign` request
  entries and expose the native `/sign` response for adapters that already own
  transaction encoding
- AlgoKit Utils adapters are optional client-side projections over the native
  SDK client. They provide the AlgoKit `addr` plus transaction-signer shape and
  call raw `/sign` for the indexes AlgoKit asks them to sign. They do not
  mutate or re-plan groups; Falcon and LogicSig flows that require dummy
  insertion, fee pooling, or runtime-argument management remain native APlane
  planning/signing concerns.

Primary SDK sources live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. When `APLANE_SDKS_REPO` points at a local
SDK checkout, this repo's `make integration-test` and `make integration-test-reuse`
targets also run the SDK live signer integration suites through
`test/run-sdk-integration.sh`; when unset, that bridge is skipped, and when set
to a non-directory path, the make target fails before running SDK tests.

Committed JSON golden fixtures for signer API contract tests live under
`test/contracts/signerapi/`. These fixtures are compatibility source material
for this repository and the external SDK repository: update them intentionally
with any wire-contract change, not as generated test runtime state.

Known-answer key derivation fixtures live in
`test/integration/key_derivation_regression_test.go`. They pin deterministic
addresses for supported DSA and template-backed LogicSig derivation paths.
Update those expected addresses intentionally, in the same change as the
behavior change, when a versioned derivation path, salt style, TEAL template
body, seed derivation, or generator changes.

## Swap Contract

The standalone atomic-swap client implementation lives outside this
repository; this repository does not own swap source under `cmd/` or
`internal/`. This section describes the cross-repository compatibility
contract for the client-state layout and on-chain note protocol that APlane
clients coordinate around.

Proposer and acceptor communicate via on-chain zero-ALGO payment notes:

- `swap_propose`
- `swap_accept`
- `swap_submit`

Proposal notes include:

- `proposal_id`
- `terms_hash`
- `app_id`
- proposer and acceptor legs
- proposer LogicSig size
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
