# System Data Model

> Implementation-derived model of APlane's durable data, runtime state,
> wire projections, caches, and ownership boundaries.
>
> This is not a database schema. APlane is file-backed, runtime-oriented, and
> protocol-driven, so the useful data model is a map of authorities and
> projections rather than tables and foreign keys.

## Contents

- [Purpose](#purpose)
- [Modeling Conventions](#modeling-conventions)
- [System Boundaries](#system-boundaries)
- [Core Entity Map](#core-entity-map)
- [Relationship Map](#relationship-map)
- [Signer Data Model](#signer-data-model)
- [Client Data Model](#client-data-model)
- [Network Data Model](#network-data-model)
- [Transaction Data Model](#transaction-data-model)
- [Wire Projection Model](#wire-projection-model)
- [Lifecycle Models](#lifecycle-models)
- [Security-Sensitive Data](#security-sensitive-data)
- [Compatibility Invariants](#compatibility-invariants)
- [Changing the Data Model](#changing-the-data-model)
- [Source Of Truth Index](#source-of-truth-index)

## Purpose

This document answers these questions:

- what are the primary entities in APlane,
- where is each entity durably stored,
- which package owns each entity's mutation and runtime projection,
- which wire surfaces expose the entity,
- which fields or relationships are compatibility-sensitive,
- which data is authoritative versus cache, display metadata, or provenance.

For low-level wire and file-format contracts, see
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). For implementation ownership and
runtime layering, see [ARCH_SPEC.md](ARCH_SPEC.md). For key/keytype state
machines and transition rules, see [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
For the complete inventory of durable files, caches, DTOs, runtime managers,
request models, and public handoff envelopes, see
[ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md).

## Modeling Conventions

APlane data appears in four forms:

| Form | Meaning |
|------|---------|
| Durable authority | The file, config, key payload, or protocol contract that is authoritative for behavior. |
| Runtime projection | In-memory state derived from durable data and current process state. |
| Wire projection | HTTP, admin IPC, plugin, MCP, or SDK DTO shape exposed to another process. |
| Cache/display data | Rebuildable or informational state used for UX, lookup, or rendering. |

This document and [ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md) intentionally
exclude ordinary local variables and helper structs whose lifetime is contained
inside one function. The catalog covers model elements with identity beyond one
function call: durable files, wire DTOs, public envelopes, caches, long-lived
runtime managers, request models that cross process or goroutine boundaries,
and UI/admin projections backed by those objects.

Important vocabulary:

- **identity** means a signer-owned security domain. Product mode exposes the
  `default` signing identity.
- **principal** means an authorization actor. In product mode compatibility
  credentials map to `system:product-admin`.
- **network context token** means a local namespace such as `testnet`,
  `mainnet`, or `localnet`. It is not cryptographic chain identity.
- **genesis hash** is the cryptographic transaction chain identity used by
  signer policy and group validation.
- **key type** is the canonical identifier stored and sent on the wire, such as
  `ed25519` or `aplane.falcon1024.v1`.
- **Witness Key ID** means the 52-character uppercase base32 SHA-512/256 digest
  over canonical length-prefixed domain, key type, and public-key fields. It
  identifies the same role-neutral public key form in hot sentry custody or
  standalone contract-admin custody; it is not an Algorand account address.
  Sentry-role wire/storage fields may call this value `component_key`.

## System Boundaries

### Signer Boundary

`apsigner` owns signer data under `APSIGNER_DATA`:

- identity keystores and key files,
- identity config, node-role policy in `policy.yaml`, tokens, SSH enrollments,
  and key type state,
- encrypted installed templates,
- public sentry references and witness public metadata sidecars,
- signer-wide ASA metadata cache,
- audit log,
- managed backup archives,
- SSH host key and IPC socket.

Private key material never crosses this boundary. Clients send transaction
intent and receive finalized signed transaction bytes, not key material.

### Client Boundary

`apshell`, SDKs, MCP mode, scripts, and plugins own client/operator data under
`APCLIENT_DATA`:

- client config and endpoint registry,
- endpoint-scoped bearer token files copied from signer enrollment,
- SSH client keys and known-hosts trust,
- aliases, sets, signer inventory cache, auth cache, ASA cache,
- endpoint-published sentry inventory,
- plugins and plugin activation,
- saved JavaScript scripts,
- local swap proposal state.

Client data is operational state. It can reference signer-owned accounts, but
it is not signing authority.

### Protocol Boundary

The public signer HTTP API is defined in `pkg/signerapi`. The live admin
protocol is defined in `internal/protocol`. External SDKs consume the same HTTP
DTOs and contract fixtures.

## Core Entity Map

| Entity | Scope | Durable authority | Runtime projection | Wire projection | Owner |
|--------|-------|-------------------|--------------------|-----------------|-------|
| Client config | Client data dir | `APCLIENT_DATA/config.yaml` | `internal/config.Config` network/theme/polling state | SDK config loaders, shell runtime | `internal/config`, `internal/bootstrap/shell` |
| Release metadata | Release archive and install root | `release.json`, copied to install metadata directory when present | installer/version provenance for diagnostics and future upgrade checks; archive filenames are packaging labels only | installer output, support tooling | release workflow, `make release-local`, `scripts/package-bootstrap-release.sh`, `install.sh` |
| Endpoint registry | Client data dir | `APCLIENT_DATA/endpoints.yaml` | `config.ClientEndpointRegistry`, derived signer and sentry connection profiles | shell endpoint commands, connection runtime | `internal/config`, `internal/apshellapp`, `internal/engine/connect` |
| Endpoint-published sentries | Client data dir | `endpoints.yaml` `published_sentries` | derived `Config.SentryEndpoints` map keyed by embedded public key hex | guarded send orchestration | `internal/config`, `internal/apshellapp`, `internal/engine` |
| Server config | Signer data dir | `APSIGNER_DATA/config.yaml` | `internal/serverconfig.ServerConfig` snapshot | Admin settings subset | `internal/serverconfig`, `internal/bootstrap/signer` |
| Node role | Signer data dir | `APSIGNER_DATA/node.yaml` plus `identities/<identity>/node.yaml.hmac` | single-purpose signer/sentry role gate | `/status`, service dispatch, key generation/restore gating | `internal/noderole`, `internal/keyclass`, signer startup, identity load, keyadmin, restore, signing dispatch |
| Signing identity | Signer identity | `identities/<identity>/` | `identity.Runtime` | HTTP identity routing, admin session target | `internal/signerapp/identity` |
| Identity config | Signer identity | `identities/<identity>/config.yaml` (parsed as `identity.StoredConfig`) | `identity.EffectiveConfig` (resolved, excluding key-class role) | admin settings | `internal/signerapp/identity`, `internal/signerapp/admin` |
| Unlock config | Signer identity | `identities/<identity>/unlock.yaml` | startup/headless unlock config | none | `internal/signerapp/unlockconfig` (identity re-exports helpers), `cmd/appass` |
| Keystore metadata | Signer identity | `identities/<identity>/.keystore` | derived master key after unlock | none | `internal/crypto`, `internal/keystore` |
| Master key/session | Signer identity runtime | passphrase-derived, not persisted | `keystore.FileKeyStore`, `keystore.KeySession` | lock/status booleans only | `internal/keystore`, `internal/signerapp/runtime` |
| Account authority | Signer identity | `identities/<identity>/keys/<address>.key` | address -> key file/type/LogicSig size indexes | `/keys`, admin key lists/details | `internal/keys`, `internal/keystore`, `internal/signerapp/identity` |
| Sentry witness authority | Sentry identity | `identities/<identity>/keys/<witness_key_id>.sen` | Witness Key ID -> witness credential index | `/keys`, sentry component signing | `internal/keys`, `internal/keystore`, `internal/signerapp/identity` |
| Sentry public sidecar | Signer identity | `identities/<identity>/keys/<witness_key_id>.wit.json` | public sentry-key export metadata | `apstore sentry export` | `internal/keys`, `internal/sentry/sentryrefs` |
| Public sentry reference | Signer identity | `identities/<identity>/sentries/<name>.json` | key-generation select option | `/keytypes`, admin/apadmin generation UX | `internal/sentry/sentryrefs`, `internal/signerapp/rest`, `cmd/apstore` |
| Key type | Process plus identity | compiled provider registry plus enabled identity records/templates | key type catalog and provider registries | `/keytypes`, admin `key_types` | `internal/keytypecatalog`, `internal/lsigprovider`, `internal/keygen` |
| Key type state | Signer identity | `keytypes/<key_type>.json` | enabled/disabled generation state | admin library/install state | `internal/keytypestate` |
| Library template source | Signer data dir or repo | `library/templates/*.yaml` | parsed install candidate | admin KeyType Library | `internal/templatelibrary`, `internal/signerapp/templateadmin` |
| Installed template | Signer identity | encrypted `keytypes/<key_type>.template` | registered generation provider after reload | admin installed template surface | `internal/templatestore`, `internal/signerapp/templates` |
| Node-role policy | Signer identity | `policy.yaml` plus `policy.yaml.hmac` | client-signing or sentry component `policy.Config`, selected by node role | admin/appolicy policy editor flows | `internal/policy`, `internal/signerapp/policyruntime`, `internal/signerapp/admin`, `cmd/appolicy` |
| Authorization principal/group/grant | Product bootstrap model | source-defined bootstrap records | `auth.Authorizer` decisions | denial audit/error codes | `internal/auth`, `internal/authz` |
| API token | Signer identity and client | signer `identities/<identity>/aplane.token`, client `aplane.token` | token authenticator | HTTP auth, SSH mutual proof | `internal/tokenfile`, `internal/auth`, `internal/sshtunnel` |
| SSH enrollment | Signer identity | `identities/<identity>/.ssh/authorized_keys` | identity SSH key set | SSH auth and token provisioning | `internal/sshtunnel`, `internal/signerapp/sshprovision` |
| Admin session | Signer identity | none | `adminserver.SessionContext`, session manager | admin IPC/SSH JSON envelope | `internal/signerapp/adminserver`, `internal/adminproto`, `internal/protocol` |
| Sign request | Live signer runtime | none durable | approval coordinator pending request | `/sign`, `/sign/cancel`, admin `sign_request` | `internal/signerapp/approval`, `internal/signerapp/signing` |
| Transaction plan/group | Request-scoped | caller transaction bytes | canonical planned group and mutation report | `/plan`, `/sign` | `internal/signerapp/signing`, `pkg/signerapi` |
| Component signing request | Request-scoped | canonical group bytes and target indices | per-target user or sentry component signatures | `/sign/component` | `internal/signerapp/signing`, `pkg/signerapi` |
| Guarded assembly request | Request-scoped | user and sentry component signatures plus group bytes | assembled signed group bytes | `/sign/assemble` | `internal/signerapp/signing`, `pkg/signerapi` |
| App call metadata | Request-scoped | caller/engine prepared request | approval description context | `app_call_info` | `internal/engine`, `internal/signerapp/txdesc` |
| ASA metadata | Network-scoped cache | `cache/<network>_asa_cache.json` | operation-local metadata lookup | admin ASA search/resolve, client display | client: `internal/cache`, `internal/asa`; signer: `internal/signerapp/asametadata.Store` |
| Client alias/set/auth/signer caches | Client data dir | `APCLIENT_DATA/cache/*.json` | client state snapshots | shell/MCP structured output | `internal/clientstate`, `internal/cache`, `internal/refname` for alias/set names |
| Plugin | Client data dir | `plugins.available/<name>`, `plugins.yaml`, checksums | plugin manager process state | plugin JSON-RPC result | `internal/plugin`, `internal/apshellcli` |
| JavaScript script | Client data dir | `scripts/*.js` | Goja execution context | shell/MCP `js`, `jssave`, `jslist` | `internal/scripting`, `internal/jsapi` |
| Backup archive | Signer identity | `backups/<identity>/*.tar.gz` containing `.apb` files, `manifest.json`, and policy snapshots | restore preview/recovery input | admin backup/restore messages | `internal/backup`, `internal/signerapp/backupadmin` |
| Backup manifest | Backup archive | `manifest.json` schema `aplane.backup.manifest.v1` | source node role default and diagnostics for rebuild | none | `internal/backup` |
| Recovered batch | Signer identity | destination-encrypted `recovered/<restore-id>/batch.enc`, `entries/*.recovered`, and optional `activation/` reconciliation state | none before explicit activation; recovery-only runtime when activation is incomplete | recovered lifecycle admin messages | `internal/backup/recovered`, `internal/signerapp/backupadmin` |
| Audit record | Signer process | `audit.log` JSONL | append-only logger state | not a request API | `internal/signerapp/audit` |

## Relationship Map

```text
Client data dir
  -> client config
  -> active network context token
  -> algod endpoint and client caches
  -> endpoints.yaml
      -> default signer endpoint
      -> zero or more sentry endpoints
      -> endpoint-published sentries -> derived runtime sentry routing
  -> endpoint tokens + SSH trust
  -> signer HTTP/admin connection

Signer data dir
  -> process config
  -> identity registry
      -> identity runtime
          -> keystore metadata -> derived master key -> key session
          -> key files -> runtime key indexes -> /keys and signing
          -> sentries public references -> /keytypes generation options
          -> key type state + installed templates -> /keytypes and generation
          -> policy.yaml + HMAC -> signer approval verdicts or sentry component-sign authorization by node role
          -> API token + SSH keys -> authn
          -> approval coordinator -> sign/token prompts
          -> admin sessions -> admin mutations and approvals
```

The strongest authority chain is:

```text
identity master key
  -> decrypts key files and installed templates
  -> derives policy integrity key used to verify policy.yaml sidecar
  -> enables runtime signing session
```

The strongest signing authority is:

```text
encrypted canonical managed credential (`.key` or `.sen`)
  -> stored key type, bytecode, signing args, salt counter, base key type
  -> signer-side base provider where cryptographic signing is required
```

Templates are generation and provenance authority, not sign-time authority for
existing keys.
The full key file and key type lifecycle is documented in
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).

## Signer Data Model

### Signer Data Root

The signer data root contains process-scoped state:

```text
config.yaml
node.yaml
audit.log
.apstore.lock
cache/
library/templates/
backups/<identity>/
.ssh/ssh_host_key
identities/<identity>/
```

Process-scoped data is owned by `apsigner` or installer/setup tools. Mutations
that affect live signer behavior should flow through signer-owned services or
the cooperative store lock.

### Identity

An identity is the root of sensitive signer state:

```text
identities/<identity>/
  keys/*.key
  keys/*.sen
  keys/*.wit.json          # public sentry metadata sidecar (not private authority)
  .keystore
  node.yaml.hmac
  aplane.token
  config.yaml
  policy.yaml
  policy.yaml.hmac
  unlock.yaml
  .ssh/authorized_keys
  sentries/*.json
  keytypes/<key_type>.json
  keytypes/<key_type>.template
  recovered/<restore-id>/
    batch.enc
    entries/<selector-hash>.recovered
    activation/
      journal.enc
      rollback.enc
  deleted/
  passphrase | passphrase.cred   # optional helper artifacts
```

Recovered batches are inactive, identity-scoped recovery state. Their metadata
and entries are authenticated encryption under the destination identity master
key, but they are not managed `.key` or `.sen` files and have no signing-runtime
projection. The batch commits to each exact entry plaintext, and each entry
also carries its restore ID. Store passphrase rotation validates and
re-encrypts every published recovered file. Before rotation, the recovered
store removes exact `.new`/`.old` siblings after the canonical file validates,
or restores a missing/invalid canonical file only from an exact sibling that
validates under the current master key. Unknown state fails closed. Directories
prefixed `.recovering-` are unpublished staging state and must be ignored by
inventory operations. Before the first active activation write, an encrypted
activation journal and exact rollback snapshot are published under
`activation/`. Their presence is authoritative incomplete-activation state:
startup retains the master-key session only for recovery administration,
blocks signing, and requires exact resume or rollback. Purge cannot erase this
state.

`identity.Runtime` is the runtime projection. It owns:

- lock/unlock state,
- key session,
- key indexes,
- approval coordinator,
- token authority,
- SSH enrollment,
- effective identity config,
- effective node-role policy: client-signing policy on signer nodes or sentry
  component policy on sentry nodes,
- watcher and decommission lifecycle.

Product mode exposes only `default`, but the runtime model is internally
identity-scoped.

### Key Files

Key files are encrypted JSON payloads using master-key encryption. The current
payload families are:

| Category | Meaning |
|----------|---------|
| `ed25519` | Native Algorand signing key. |
| `dsa_lsig` | DSA-backed LogicSig key with private signing key plus stored LogicSig metadata. |
| `generic_lsig` | TEAL-only LogicSig instance with bytecode and signing args. |
| `witness` | Signer-custodied witness key (`.sen`) used only through sentry-role `/sign/component`. |

Category selects the managed credential class and filename extension: account
categories use `.key`; `witness` uses `.sen`. There is no durable payload
category named `component`; “component signing” is the wire/runtime flow, not
the on-disk category.

Durable signing metadata includes:

- `format_version`,
- `category`,
- `key_type`,
- public/private key material where applicable,
- stored LogicSig bytecode where applicable,
- `salt_counter` for LogicSig keys,
- `signing_metadata_version` (version 1 non-bounded; version 2 bounded),
- `base_key_type` for composed DSA keys,
- stored signing-argument schema in JSON field `signing_args`,
- optional `bounded_authorization` for bounded1 DSA keys (metadata version 2),
- optional `template_fingerprint`,
- creation parameters and timestamps.

Dedicated guarded account keys are DSA LogicSig keys whose stored bytecode
embeds a sentry public key (currently `aplane.falcon1024-sentry1024.v1`). They
are not accepted by `/sign`; the client must use the
guarded flow: user `/sign/component`, sentry `/sign/component`, user
`/sign/assemble`, then algod submit. Inventory advertises
`signing_flow: sentry1` for those keys. Sentry witness keys are selected by an uppercase,
52-character txid-shaped Witness Key ID and are not Algorand spending accounts.

Bounded keys with durable `bounded_authorization.sentry` use the distinct
`bounded-sentry1` flow. Corridor v1 is the first such template. Their spend
path uses `/sign/bounded-component`, sentry-role `/sign/component`, and
`/sign/bounded-assemble`; their admin path remains `/sign/bounded-admin`.

Decrypted key payloads are parsed through `internal/keys.ParsePayload` and
written through `internal/keys.MarshalPayload`. The v1 payload vocabulary is
canonical: creation parameters use `parameters`, LogicSig bytecode uses
`lsig_bytecode`, and duplicate JSON object members or unknown fields are
rejected. Noncanonical aliases such as `params` and `bytecode_hex` are not
accepted in fresh-system stores.

The key file is the source of truth for signing existing keys. A live template
or library source may explain provenance or enable new key creation, but it must
not be used to reconstruct missing signing metadata.

Address identity comes from key material rather than signing metadata: native
keys derive from stored public/private key material, and LogicSig keys derive
from stored bytecode. Payloads do not persist an address field; inventory and
key state repair recover the selector from key material or bytecode.
`signing_args`, `signing_metadata_version`, `base_key_type`,
`template_fingerprint`, and `salt_counter` are not independent address
derivation inputs.

The full durable payload is `keys.Payload` (codec in
`internal/keys/payload_codec.go`). The signing-argument *schema slice* is
modeled by `internal/signingargs.Info`; key-file storage aliases that type as
`keys.StoredSigningArg`, signer cache aliases it as `cache.SigningArgInfo`, and
`/keys` projects it to the SDK-facing `signerapi.SigningArgInfo` DTO. Template
and `/keytypes` generation metadata uses `runtime_args`.

### Bounded Authorization And External Contract Admin

Bounded1 is an authorization contract used by both `bounded1` and
`bounded-sentry1` signing choreographies. Normative field inventory, encodings, and custody
rules live in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) and
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md). From a data-model perspective:

- Durable non-secret capability is stored on the account key as
  `bounded_authorization` (signing metadata version 2), owned by
  `internal/boundedmeta` and assembled by `lsig/composeddsa` at generation.
- Inventory advertises `signing_flow: bounded1` without a sentry or
  `bounded-sentry1` with a sentry. Admin-key rekeys always route to
  `POST /sign/bounded-admin` rather than ordinary runtime args or sentry assembly.
- The spending key remains signer-managed (`.key`). The Falcon contract-admin
  private material is **not** a signer-managed credential: it lives in a
  standalone encrypted `.wit` bundle (`aplane.witness-key-bundle.v1`) owned by
  `aprekey` / `internal/witness/artifact`, optionally with a public
  `.wit.json` sidecar.
- Separated ceremonies use short-lived non-secret files
  `.apbounded-admin-request` / `.apbounded-admin-signature` (schemas
  `aplane.bounded-admin-request.v2` / `aplane.bounded-admin-signature.v1`)
  owned by `internal/boundedadmin/protocol` and
  `internal/apboundedadminapp`.
- Signer and `apstore` must not import, decrypt, back up, or restore private
  `.wit` artifacts as managed keys.

### Key Types And Templates

Key type discovery draws from three source classes:

1. default-enabled compiled providers,
2. library-visible compiled providers enabled by identity state records,
3. installed YAML templates that are enabled for the identity.

These classes are not assembled by a single function. Compiled and
composed-template providers surface through the key generation / DSA registries
(`internal/keymgmt`), while generic YAML templates are added by the REST
inventory layer (`internal/signerapp/rest`). `internal/keytypecatalog` holds
visibility metadata, not the assembled list.

Default-enabled compiled providers include signer account providers
(`ed25519`, `aplane.falcon1024.v1`) and witness providers
(`aplane.witness-falcon1024.v1`). Node role gates
determine which default-enabled key classes may be generated or served by a
store. Optional compiled providers and YAML templates become available only
after identity-local enablement or installation.

Identity key type records are plaintext because they are not key material:

```json
{
  "key_type": "aplane.htlc.v1",
  "source": "yaml_generic",
  "state": "enabled",
  "fingerprint": "...",
  "activated_at": "..."
}
```

Installed templates are encrypted adjacent `.template` files under the same
`keytypes/` directory. Library templates under `library/templates/` are
plaintext install sources only; they are not active key types by presence
alone. New signer identities initialize with `aplane.falcon1024-allowlist.v1`
installed and enabled from the bundled library source; otherwise YAML templates
become active only after identity-local installation and enablement.

### Policy

Policy is identity-scoped durable state selected by node role:

```text
policy.yaml
policy.yaml.hmac
```

The HMAC authenticates exact YAML bytes with a key derived from the identity
master key. Policy load verifies the sidecar before applying policy; a missing
or mismatched sidecar fails closed according to the policy contract.

`policy.yaml` is parsed according to node role. On signer nodes, it is the
client-signing policy. Runtime client-signing policy is an effective
`policy.Config` layered from defaults and stored YAML. It controls:

- Always Deny rules,
- Always Review rules,
- Always Approve rules,
- network-scoped ALGO and ASA transfer thresholds,
- YAML-only `key_overrides`.

On sentry nodes, the same `policy.yaml` file is parsed as the sentry component
policy. It uses the same transfer routing model as deterministic authorization for
`/sign/component`; it has no operator default and no review verdict. Sentry
`key_overrides` are keyed by Witness Key ID, while client-signing overrides
are keyed by Algorand auth address.

`user_auto_approve` is not policy. It is the user/operator-default fallback in
identity config.

### Tokens, SSH, And Admin Sessions

API tokens are bearer credentials:

- signer authority: `identities/<identity>/aplane.token`,
- client copy: endpoint-scoped files such as `APCLIENT_DATA/aplane.token` or
  `APCLIENT_DATA/tokens/<alias>.token`.

SSH enrollment is identity-scoped:

```text
identities/<identity>/.ssh/authorized_keys
```

Remote clients authenticate with SSH public key plus token. Admin protocol
sessions then authenticate with passphrase and bind to a target identity.

Admin sessions are runtime-only. They are represented by session context,
transport, principal, and target identity attribution, not by durable session
records.

### Audit

The audit log is append-only JSONL at `audit.log`. It records process events,
identity-scoped events, signing outcomes, authorization denials, session
connect/disconnect, key management, backup/restore, token provisioning, and
policy-related signing decisions.

Audit is observability and accountability data. It is not consulted as authority
for signing, authorization, or recovery.

## Client Data Model

### Client Data Root

The client data root contains operator-side state:

```text
config.yaml
endpoints.yaml
.mcp.json
.codex/config.toml
aplane.token
tokens/<alias>.token
.apclient.lock
.ssh/id_ed25519
.ssh/known_hosts
cache/
plugins.yaml
plugins.available/
scripts/*.js
swap/<network>/
```

### Client Config And Network Context

Client config selects:

- startup network context token,
- allowed network tokens,
- per-network algod endpoints under `networks.<token>.algod`,
- signer status polling interval,
- theme.

The selected network token scopes algod lookup and cache state. It is a local
namespace and must not be treated as chain identity.

Signer and sentry endpoint routing lives in `endpoints.yaml`, not in
`config.yaml`. The endpoint registry contains a `schema_version`, one default
signer endpoint alias, and endpoint records with `role: signer` or
`role: sentry`. Endpoint records own connection details such as URL,
signer/local ports, token file, SSH identity file, and known-hosts path.

Sentry endpoint records may also contain `published_sentries`, keyed by the
embedded sentry `public_key_hex`. That inventory is routing metadata derived
from authenticated `/keys` discovery. It is not proof that the endpoint owns the
key; assembly and on-chain LogicSig verification remain the trust checks.

### Client Caches

Client caches are signed JSON files with a per-client cache key. They are
local, rebuildable state:

- alias cache,
- set cache,
- signer inventory cache,
- network ASA cache,
- network auth-address cache,
- swap session files and tombstones.

JSON cache files use an HMAC envelope version plus a payload-level
`schema_version`. A missing payload `schema_version` is interpreted as v1;
future unsupported payload versions are rejected and the cache is rebuilt from
empty or seed data. Cache files remain non-authoritative.

The cache owner is `internal/clientstate` plus `internal/cache`, with
`internal/refname` owning persisted alias and set name validation and
normalization. Callers should use `internal/asa` for ASA reference and amount
semantics rather than reading cache files directly. Static ASA metadata and
convenience aliases are centralized in `internal/asa/registry`; JavaScript
helpers, engine resolution, and cache seeding all project from that registry
instead of carrying separate built-in asset maps. Current-network cache entries
have precedence over convenience aliases, while ambiguous symbolic references
are rejected.

### Plugins

Plugin activation is durable client state:

```yaml
enabled_plugins:
  - my-plugin
```

Release-archive installs create an empty activation list on first install
(when `plugins.yaml` does not already exist). The bundled `algokit-localnet`
plugin is staged under `plugins.available/` but not enabled by default.
Existing `plugins.yaml` activation choices are preserved when the installer is
run again against the same client data directory.

A plugin is executable only when it appears in `plugins.yaml`, exists under
`plugins.available/<name>`, has a valid manifest, passes checksum validation,
and can run in the platform sandbox.

Plugin process state is runtime-only and owned by the plugin manager.

### JavaScript And MCP

Saved scripts live under `scripts/*.js`. The Goja runtime and MCP server are
runtime surfaces over the same shell application and engine model. MCP does not
define separate durable state beyond client MCP configuration (`.mcp.json` and
`.codex/config.toml`) and saved scripts.

## Network Data Model

Network context tokens are config and cache keys. They:

- select algod endpoints,
- partition client caches,
- select signer TEAL compile endpoints,
- scope signer ASA transfer guard policy,
- flow into plugin execution context.

Transaction chain identity is `GenesisHash`, not `GenesisID`. Signer policy and
planning resolve:

```text
transaction GenesisHash -> resolver -> network context token -> policy bucket
```

Unknown genesis hashes fail closed for planning and network-scoped policy.

Built-in resolver entries are compiled for Algorand `mainnet`, `testnet`, and
`betanet`. Custom genesis-hash mappings live in canonical signer config at
`networks.<token>.genesis_hash`. Top-level `algod` and
`genesis_hash_networks` are not current schema.

## Transaction Data Model

### Prepared Client Transactions

The client prepares transactions and groups from user input, scripts, plugins,
and app interaction helpers. For app interaction, `PreparedGroup` is the engine
boundary:

```text
PreparedGroup
  -> ordered entries
  -> transaction
  -> signing context
  -> per-entry LogicSig args
  -> optional app-call approval metadata
```

Prepared groups are not authorization proofs. They are structured transaction
intent plus metadata required for the signer path.

### Signer Request Entries

Signer HTTP request entries have three modes:

| Mode | Required fields | Meaning |
|------|-----------------|---------|
| sign | `auth_address`, `txn_bytes_hex` | signer owns and signs this slot |
| passthrough | `signed_txn_hex` | already signed, included unchanged |
| foreign | `txn_bytes_hex` without `auth_address` | another signer owns this slot; context only |

The signer canonicalizes the group:

- validates genesis hash consistency,
- adds required LogicSig dummies,
- pools fees,
- computes group ID,
- applies policy to signer-controlled slots,
- requests approval if required,
- signs or assembles finalized transactions.

### Mutation Report

The mutation report is a wire projection of canonicalization:

- dummies added,
- group ID changes,
- fee modifications,
- original/final count,
- passthrough/foreign counts,
- reason.

It is request observability, not a durable state record.

## Wire Projection Model

### HTTP

HTTP DTOs live in `pkg/signerapi` and are the SDK-facing contract.

Primary projections:

- `GroupSignRequest`,
- `SignRequest`,
- `BoundedAdminRequest`, `BoundedAdminPartialResponse`, `BoundedAdminMetadata`,
- `ComponentSignRequest`,
- `ComponentSignResponse`,
- `GuardedAssemblyRequest`,
- `GuardedAssemblyResponse`,
- `GroupPlanResponse`,
- `GroupSignResponse`,
- `MutationReport`,
- `KeysResponse` / `KeyInfo` (including `signing_flow`,
  `sentry_component_key_type`, optional `bounded_authorization`),
- `KeyTypesResponse`,
- `StatusResponse`,
- `HealthResponse`,
- `CancelSignRequest`, `CancelSignResponse`,
- admin generate/delete DTOs,
- admin sentry reference sync DTOs,
- `ErrorResponse`.

HTTP token authentication resolves exactly one identity, and handlers route to
that identity runtime. Clients route signing on inventory `signing_flow`
labels (`sentry1`, `bounded1`, or empty for plain `/sign`) and must fail closed
on unknown labels.

### Admin Protocol

Admin protocol messages live in `internal/protocol` and use line-delimited JSON
with:

- `kind`,
- `type`,
- `id`.

The admin protocol projects:

- identity/session state,
- lock/unlock results,
- keys and key details,
- template library and installed-template state,
- key type metadata,
- sign approval prompts and responses,
- token provisioning prompts,
- backup/restore results,
- admin and policy settings,
- signer-local ASA metadata search/resolve.

Admin IPC exposes live administration. It is not the same contract as the HTTP
SDK surface.

Key inventory projections may include `template_provenance_status` and
`template_provenance_note`. These are informational comparisons between a key
file's stored template fingerprint and the currently registered local
definition. The fingerprint is behavior-only, versioned (`<n>:` prefix), and
identifier-independent, and the comparison is version-aware: only a same-version,
different-hash pair is a conflict, while a different-version or malformed stored
fingerprint is "not comparable" and benign. They do not change signing behavior.

### Plugin Protocol

Plugins use JSON-RPC over stdin/stdout. Durable plugin authority is the manifest
and checksums in the client plugin directory. Runtime plugin calls receive
execution context, known accounts, aliases, assets, network metadata, and
suggested params.

Plugin `data` is the canonical machine-readable return payload; `presentation`
is optional human display metadata.

### MCP

MCP is a machine UI over the shell runtime. Its structured outputs are
projections of shell application results, not a separate backend model.

## Lifecycle Models

### Signer Startup

1. Load server config.
2. Load root node role from `node.yaml`.
3. Discover identity directories.
4. Skip decommissioned identities.
5. Build an `identity.Runtime` per live identity.
6. Start locked, unlock headlessly, or unlock through admin depending on
   passphrase startup configuration.

### Unlock And Reload

1. Verify passphrase against `.keystore`.
2. Derive master key.
3. Verify root `node.yaml` against the identity's role HMAC sidecar.
4. Verify and load the node-role policy domain from `policy.yaml`.
5. Apply node role gates.
6. Register installed templates.
7. Scan key files.
8. Replace key indexes.
9. Activate key session.
10. Publish status/keyset notifications.

Template registration precedes key scan so generation/discovery state is
current. Existing key signing still depends on key files.

### Key Type And Template Lifecycle

| Operation | Durable change | Runtime effect |
|-----------|----------------|----------------|
| Enable compiled provider | write enabled key type state record | provider appears in key generation/discovery |
| Disable compiled provider | delete state record after unused-key guard | provider hidden for that identity |
| Install YAML template | encrypt `.template`, write enabled record | template provider registered on reload |
| Disable YAML template | set state disabled after unused-key guard | hidden from discovery/generation |
| Remove YAML template | archive `.template`, delete record after unused-key guard | inactive and outside active scans |

Unused-key guards require the identity master key because they scan encrypted
keys.

### Signing Lifecycle

1. Client prepares transaction bytes and metadata.
2. Client classifies effective signers from inventory (`signing_flow` and key
   type). Guarded targets use the guarded lifecycle below; bounded admin-key
   rekeys use `/sign/bounded-admin`; ordinary targets use `/plan` or `/sign`.
3. Signer validates request shape and transaction network. Plain `/sign`
   rejects guarded-account and witness key types and admin-key bounded
   operations that require the bounded-admin path.
4. Signer canonicalizes group and computes mutations (bounded planning
   classifies effects after fee pooling).
5. Signer evaluates policy for signer-controlled slots.
6. Signer either rejects, auto-approves, or requests operator approval.
7. Signer signs/assembles finalized slots (bounded admin path returns a
   partial plus authorization metadata, not a fully submittable group alone).
8. Client routes returned signed bytes to algod submission or simulation,
   completing a bounded ceremony when required.

Live `/sign` cancellation is request-scoped runtime state only. There is no
durable sign request table.

### Guarded Signing Lifecycle

1. Client detects a guarded account key from `/keys` metadata and local signer
   inventory.
2. Client prepares the canonical group, classifies guarded target indices and
   non-guarded original indices, budgets every LogicSig by effective signer,
   and signs required dummy transactions locally.
3. Client calls the user signer `/sign/component` for user-role signatures.
4. Client routes by embedded sentry public key to a sentry endpoint from
   `endpoints.yaml` and calls sentry `/sign/component`.
5. If non-guarded originals exist, client calls the primary signer `/sign` over
   the full canonical group: non-guarded originals are sign-mode entries,
   guarded targets are `foreign` entries with accurate `lsig_size` hints, and
   dummies are `foreign` context entries.
6. Client calls user signer `/sign/assemble` with guarded targets plus
   passthrough signed bytes for non-guarded originals and dummies.
7. User signer verifies sentry signatures against the sentry public key
   embedded in the local guarded account key, packs LogicSig args, and returns
   signed group bytes.
8. Client submits the signed bytes to algod.

Endpoint routing and `/keys` discovery are not trust proofs. A wrong endpoint
can only return a signature that assembly or the on-chain LogicSig rejects.

### Token Provisioning Lifecycle

1. Client connects over SSH as `request-token:<identity>`.
2. Server verifies supported identity and SSH key-only bootstrap path.
3. Server asks connected admin for approval.
4. Admin approves.
5. Server enrolls SSH public key for the identity.
6. Server creates or loads identity API token.
7. Token is delivered over the SSH channel.
8. Audit records confirmed delivery.

### Backup And Restore Lifecycle

Managed backup archives live under `backups/<identity>/`. Each archive contains
encrypted `.apb` payloads, `manifest.json` with source node role metadata, and a
policy snapshot. The manifest role is a rebuild default/diagnostic; explicit
`apstore rebuild --role` is the replacement store authority when supplied.
`.apb` is the cryptographic backup unit; the tarball is packaging.

Live restore is batch-oriented:

- preview decrypts and reports without mutation,
- recovery atomically publishes selected entries outside active scans,
- review binds the batch to current destination policy, approval mode, and
  active conflicts,
- activation requires explicit acknowledgements, publishes rollback state,
  writes active state, and reloads,
- hard interruption blocks signing until resume or rollback,
- policy files are never installed automatically and must be reviewed and
  replaced explicitly.

`apstore rebuild` is the separate absent-store rescue path and may write active
credentials directly because no live signer identity is being mutated.

## Security-Sensitive Data

| Data | Sensitivity | Handling rule |
|------|-------------|---------------|
| Passphrase | secret | parsed into mutable buffers where possible; zero promptly |
| Master key | secret | derived at unlock; cached only while unlocked; zero on lock |
| `.key` account private material | secret | encrypted at rest; decrypted on demand |
| `.sen` sentry witness material | secret | encrypted at rest; usable only in the sentry component-signing domain |
| External `.wit` contract-admin private material | secret | standalone `aplane.witness-key-bundle.v1`; never signer-managed; not backed up by `apstore` |
| Bounded ceremony request/signature files | short-lived signing authority | non-secret but bind network/partial; mode `0600`, no overwrite |
| Installed `.template` files | sensitive policy material | encrypted in identity store |
| `policy.yaml` | safety-critical | authenticated by HMAC sidecar; parsed as signer or sentry policy according to node role |
| `release.json` | provenance metadata | public installer/release stamp; not signing, policy, or trust authority |
| API token | bearer secret | mode `0600`; endpoint-scoped client copies are used for HTTP and SSH token identity |
| SSH private key | client secret | client-side file, used for tunnel auth |
| Backup export passphrase | secret | protects `.apb` payloads |
| Audit log | sensitive operational record | mode `0600`; append/rotate |
| Public sentry reference | public metadata | generation input only; not endpoint trust or ownership proof |
| Endpoint-published sentries | public routing metadata | routing input only; not endpoint trust or ownership proof |

Signer-wide ASA metadata and identity key type state records are not secrets.
They still must be mutated through supported paths because they affect UX,
generation availability, provenance, and policy editing behavior.

## Compatibility Invariants

- In-place installer upgrades require `install/release.json` at or above the
  installer's minimum supported upgrade version. Key files are signing
  authority; the exact compatibility scope for other persisted and wire shapes
  is defined in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
- Installer upgrade checks read `install/release.json`; tarball filenames and
  local archive labels are not compatibility authorities.
- Canonical `key_type` strings are stored and transmitted exactly; display
  labels are not identifiers.
- Key files are signing authority for existing keys.
- Templates are generation/provenance authority, not sign-time authority.
- `GenesisHash` is signer policy chain identity; `GenesisID` is display data.
- Server config can seed the default `user_auto_approve`; identity config owns
  the effective live setting; policy owns rule verdicts.
- Policy HMAC authenticates exact YAML bytes and fails closed on mismatch.
- `policy.yaml` is client-signing policy on signer nodes and sentry component
  policy on sentry nodes. Neither domain may wrap the other.
- Client signer and sentry routing authority is `endpoints.yaml`, not
  `config.yaml`.
- Witness Key IDs are uppercase 52-character base32-no-padding
  SHA-512/256 digests over the domain-separated key-type/public-key tuple;
  embedded sentry verifier keys are full public-key hex values.
- Endpoint import and `/keys` discovery are routing/configuration inputs, not
  trust proofs.
- `/keys` per-key `signing_args` are the key file's durable signing-argument
  schema and sign-time authority for that key; `/keytypes` `runtime_args` are
  generation metadata for future keys.
- Key type state records affect discovery and generation only; existing keys
  remain signable when their key file and required base provider are valid.
- Client caches are rebuildable and not authoritative for signing or policy.
- Sign request cancellation is live runtime state, not durable workflow state.
- Admin protocol and HTTP protocol are separate compatibility surfaces.
- Product mode exposes one signing identity (`default`) even though runtime
  internals are identity-scoped.

## Changing the Data Model

Data-model changes must preserve these ownership rules:

- Each durable or cross-boundary value has one authoritative representation.
- HTTP, IPC, plugin, SDK, cache, and UI adapters project that authority into
  boundary-specific DTOs.
- `pkg/signerapi` owns the public HTTP contract. Signer domain packages use
  internal types unless they implement the HTTP boundary.
- Persistent identifiers such as key types, policy rule IDs, transfer route
  IDs, schema versions, and signing-flow labels are compatibility-bearing.
- Stored signing metadata describes an existing key's signing authority.
  Key-type creation metadata describes future key generation. The two are not
  interchangeable.
- Security-sensitive mutable bytes are zeroed at the boundary that consumes
  them.
- Unknown schema variants, template types, key classes, signing flows, and
  security-relevant enum values fail closed.

When a change adds or modifies a durable file, cache payload, request DTO,
admin message, long-lived runtime object, or cross-package request model:

1. Update [ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md) in the same change.
2. Update the owning architecture document and
   [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) when the behavior is
   compatibility-bearing.
3. Regenerate configuration documentation when documented config structs
   change.
4. Update `test/contracts/signerapi/*.json` and all SDK projections when the
   public HTTP shape changes.
5. Preserve explicit adapters between domain and boundary types.
6. Add positive, malformed-input, and unknown-version tests at the authority
   boundary.
7. Document user-visible behavior and failure modes in the relevant user
   guide.

Current implementation constraints:

- Signing-domain requests use selected `pkg/signerapi` group and sign DTOs
  internally. Separating those types requires explicit REST-boundary
  translation that preserves the HTTP JSON contract.
- Add a schema-version field only with a concrete compatibility or migration
  policy.
- Retain persistent decode paths only when they are part of the active
  compatibility contract in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Source Of Truth Index

| Model area | Source |
|------------|--------|
| Architecture ownership | [ARCH_SPEC.md](ARCH_SPEC.md) |
| Wire/file contracts | [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) |
| Complete data catalog | [ARCH_DATA_CATALOG.md](ARCH_DATA_CATALOG.md) |
| HTTP DTOs | `pkg/signerapi/types.go` |
| Admin protocol DTOs | `internal/protocol/messages.go`, [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md) |
| Authorization actions/resources | `internal/auth`, `internal/authz`, [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) |
| Policy config and verdicts | `internal/policy`, [ARCH_POLICY.md](ARCH_POLICY.md) |
| Network tokens and genesis hashes | `internal/config/networkid.go`, `internal/config/genesishash.go`, [ARCH_NETWORKS.md](ARCH_NETWORKS.md) |
| Client/server config | `internal/config/config.go`, `internal/serverconfig/serverconfig.go` |
| Client endpoint registry | `internal/config/client_endpoints.go`, `internal/config/client_endpoint_writes.go` |
| Identity runtime/config | `internal/signerapp/identity` |
| Keystore and key files | `internal/crypto`, `internal/keystore`, `internal/keys` |
| Signing-arg schema model | `internal/signingargs` |
| Node role / key class gates | `internal/noderole`, `internal/keyclass` |
| Sentry key types/messages/references | `internal/sentry`, `pkg/signerapi/sentry.go`, [ARCH_SENTRY.md](ARCH_SENTRY.md) |
| Bounded authorization / external admin | `internal/boundedmeta`, `lsig/composeddsa`, `internal/witness/artifact`, `internal/boundedadmin`, `internal/apboundedadminapp`, [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md) |
| Key type state/catalog | `internal/keytypestate`, `internal/keytypecatalog` |
| Template library/store | `internal/templatelibrary`, `internal/templatestore`, `internal/signerapp/templates` |
| Signing flow | `internal/signerapp/signing`, [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md) |
| Unlock config | `internal/signerapp/unlockconfig` |
| Client mutation lock | `internal/clientdata` |
| App interaction model | `internal/engine`, `internal/appspec`, [ARCH_APP_INTERACTION.md](ARCH_APP_INTERACTION.md) |
| Client state/cache | `internal/clientstate`, `internal/cache`, `internal/asa`, `internal/refname` |
| Plugins | `internal/plugin`, [ARCH_PLUGINS.md](ARCH_PLUGINS.md) |
| JavaScript/MCP | `internal/scripting`, `internal/jsapi`, [ARCH_MCP.md](ARCH_MCP.md) |
| Backup/restore | `internal/backup` |
| Audit | `internal/signerapp/audit` |
