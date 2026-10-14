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
- [Catalog](#catalog)
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
machines and transition rules, see [ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).
The [Catalog](#catalog) at the end inventories every durable file, cache, DTO,
runtime manager, request model, and public handoff envelope.

## Modeling Conventions

APlane data appears in four forms:

| Form | Meaning |
|------|---------|
| Durable authority | The file, config, key payload, or protocol contract that is authoritative for behavior. |
| Runtime projection | In-memory state derived from durable data and current process state. |
| Wire projection | HTTP, admin IPC, plugin, MCP, or SDK DTO shape exposed to another process. |
| Cache/display data | Rebuildable or informational state used for UX, lookup, or rendering. |


This document intentionally excludes ordinary local variables and helper structs
whose lifetime is contained inside one function. It includes objects that have
identity beyond one function call:

- files and directories under `APSIGNER_DATA` or `APCLIENT_DATA`,
- key payloads, config files, policy files, caches, the client registry, and envelopes,
- long-lived runtime managers, registries, sessions, snapshots, and indexes,
- request-scoped objects that cross package, process, approval, or goroutine
  boundaries,
- HTTP, admin IPC, SSH, plugin, MCP, and SDK DTOs,
- audit and backup records.

If a future change introduces a new durable file, cache payload, request DTO,
admin message, long-lived runtime object, or cross-boundary request model, add
it to the [Catalog](#catalog) in the same change as the behavior.

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
  identifies the same role-neutral public key form in hot cosigner custody or
  standalone contract-admin custody; it is not an Algorand account address.
  Cosigner-role wire/storage fields may call this value `component_key`.

## System Boundaries

### Signer Boundary

`apsigner` owns signer data under `APSIGNER_DATA`:

- identity keystores and key files,
- product runtime config, policy documents (`default.json` and
  `policies/<selector>.json`), the enrolled-client registry,
  and key type state,
- encrypted installed templates,
- public cosigner references and witness public metadata sidecars,
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
- SSH client keys (the client's credential) and known-hosts trust,
- aliases, sets, signer inventory cache, auth cache, ASA cache,
- operation-scoped live cosigner routing,
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
| Endpoint registry | Client data dir | `APCLIENT_DATA/endpoints.yaml` | `config.ClientEndpointRegistry`, derived signer and cosigner connection profiles | shell endpoint commands, connection runtime | `internal/config`, `internal/apshellapp`, `internal/engine/connect` |
| Live cosigner discovery | Signing operation | authenticated `/keys` responses from configured cosigner endpoints | operation-scoped map keyed by embedded public key hex | guarded and bounded-cosigner orchestration | `internal/engine/guarded` |
| Server config | Signer data dir | `APSIGNER_DATA/config.yaml` | `internal/serverconfig.ServerConfig` snapshot | Admin settings subset | `internal/serverconfig`, `internal/bootstrap/signer` |
| Node role | Signer data dir plus selected generation | `APSIGNER_DATA/node.yaml` plus selected generation `node.yaml.hmac` | single-purpose signer/cosigner role gate | `/status`, service dispatch, key generation/restore gating | `internal/noderole`, `internal/keyclass`, signer startup, runtime load, keyadmin, restore, signing dispatch |
| Signing authority | Product signer | `identities/default/` | one `productruntime.Runtime` | lock, readiness, key, and principal-attributed audit state without a runtime ID | `internal/signerapp/productruntime` |
| Product runtime config | Product signer | `identities/default/config.yaml` (parsed as `productruntime.StoredConfig`) | `productruntime.EffectiveConfig` (resolved, excluding key-class role) | admin settings | `internal/signerapp/productruntime`, `internal/signerapp/admin` |
| Unlock config | Product signer | `identities/default/unlock.yaml` | startup/headless unlock config | none | `internal/signerapp/unlockconfig`, `cmd/appass` |
| Atomic store root | Product signer | `identities/default/store-root.enc` (`aplane.store-root.v1`) | authenticated generation selection and term-key session | none | `internal/crypto`, `internal/genstore`, `internal/keystore` |
| Keystore marker | Product signer | `identities/default/.keystore` | version 6 / `store-root/v1` format gate only | none | `internal/crypto` |
| Term keys/session | Product runtime | unsealed from `store-root.enc`, resident only while unlocked | `keystore.FileKeyStore`, `keystore.KeySession` | lock/status booleans only | `internal/keystore`, `internal/signerapp/runtime` |
| Account authority | Selected generation | `generations/<gen-id>/keys/<address>.key` | address -> key file/type/LogicSig resource-profile indexes | `/keys`, admin key lists/details | `internal/keys`, `internal/keystore`, `internal/signerapp/productruntime` |
| Cosigner witness authority | Selected generation | `generations/<gen-id>/keys/<witness_key_id>.cos` | Witness Key ID -> witness credential index | `/keys`, cosigner component signing | `internal/keys`, `internal/keystore`, `internal/signerapp/productruntime` |
| Cosigner public sidecar | Selected generation | `generations/<gen-id>/keys/<witness_key_id>.wit.json` | public cosigner-key export metadata | `apadmin cosigner export` | `internal/keys`, `internal/cosigner/cosignerrefs` |
| Public cosigner reference | Signer identity | `identities/default/cosigners/<name>.json` | key-generation select option | `/keytypes`, admin/apadmin generation UX | `internal/cosigner/cosignerrefs`, `internal/signerapp/rest`, `internal/apadminapp` |
| Key type | Process plus identity | compiled provider registry plus enabled identity records/templates | key type catalog and provider registries | `/keytypes`, admin `key_types` | `internal/keytypecatalog`, `internal/lsigprovider`, `internal/keygen` |
| Key type state | Signer identity | `keytypes/<key_type>.json` | enabled/disabled generation state | admin library/install state | `internal/keytypestate` |
| Library template source | Signer data dir or repo | `library/templates/*.yaml` | parsed install candidate | admin KeyType Library | `internal/templatelibrary`, `internal/signerapp/templateadmin` |
| Installed template | Signer identity | encrypted `keytypes/<key_type>.template` | registered generation provider after reload | admin installed template surface | `internal/templatestore`, `internal/signerapp/templates` |
| Policy | Signer identity | `default.json` plus `default.json.hmac`, and `policies/<selector>.json` plus `.json.hmac` per key with a policy of its own, on both node roles | `policyruntime.NodePolicy` (`Default` plus `Keys`), resolved per signing key by `PolicyFor(selector)` | live admin and offline rescue policy flows | `internal/policy`, `internal/signerapp/policyruntime`, `internal/signerapp/policyapply`, `internal/signerapp/admin`, `internal/signerapp/policycmd`, `cmd/apadmin` |
| Product authorization | Product single-operator model | reserved `system:product-admin` principal plus the source-defined known-action vocabulary and closed product allowlist | `auth.Authorizer` decisions | denial audit/error codes | `internal/auth`, `internal/authz` |
| Enrolled client registry | Product signer | `identities/default/.ssh/authorized_keys` | `clientregistry.Registry` published into the product runtime | SSH auth, HTTP principal resolution, enrollment, revocation | `internal/signerapp/clientregistry`, `internal/signerapp/productruntime`, `internal/sshtunnel`, `internal/signerapp/enrollment` |
| Admin session | Signer process | none | scalar `adminserver.SessionContext` ownership | admin IPC JSON envelope | `internal/signerapp/adminserver`, `internal/adminproto`, `internal/protocol` |
| Sign request | Live signer runtime | none durable | approval coordinator pending request | `/sign`, `/sign/cancel`, admin `sign_request` | `internal/signerapp/approval`, `internal/signerapp/signing` |
| Transaction plan/group | Request-scoped | caller transaction bytes | canonical planned group and mutation report | `/plan`, `/sign` | `internal/signerapp/signing`, `pkg/signerapi` |
| Component signing request | Request-scoped | canonical group bytes and target indices | per-target user or cosigner component signatures | `/sign/component` | `internal/signerapp/signing`, `pkg/signerapi` |
| Guarded assembly request | Request-scoped | user and cosigner component signatures plus group bytes | assembled signed group bytes | `/sign/assemble` | `internal/signerapp/signing`, `pkg/signerapi` |
| App call metadata | Request-scoped | caller/engine prepared request | approval description context | `app_call_info` | `internal/engine`, `internal/signerapp/txdesc` |
| ASA metadata | Network-scoped cache | `cache/<network>_asa_cache.json` | operation-local metadata lookup | admin ASA search/resolve, client display | client: `internal/cache`, `internal/asa`; signer: `internal/signerapp/asametadata.Store` |
| Client alias/set/auth/signer caches | Client data dir | `APCLIENT_DATA/cache/*.json` | client state snapshots | shell/MCP structured output | `internal/clientstate`, `internal/cache`, `internal/refname` for alias/set names |
| Plugin | Client data dir | `plugins.available/<name>`, `plugins.yaml`, checksums | plugin manager process state | plugin JSON-RPC result | `internal/plugin`, `internal/apshellcli` |
| JavaScript script | Client data dir | `scripts/*.js` | Goja execution context | shell/MCP `js`, `jssave`, `jslist` | `internal/scripting`, `internal/jsapi` |
| Backup archive | Signer identity | `backups/default/*.tar.gz` containing canonical credential `.apb` files and `manifest.sealed` | restore preview/direct restore input | admin backup/restore messages | `internal/backup`, `internal/signerapp/backupadmin` |
| Backup manifest | Backup archive | `manifest.sealed` schema `aplane.credential-backup.manifest.v1`, sealed under the export passphrase | exact member inventory plus source node role default for rebuild | none | `internal/backup` |
| Credential backup manifest | Backup archive | `manifest.sealed` (schema `aplane.credential-backup.manifest.v1`) | exact member inventory and source node role | preview/direct restore | `internal/backup` |
| Audit record | Signer process | `audit.log` JSONL | append-only logger state | not a request API | `internal/signerapp/audit` |

## Relationship Map

```text
Client data dir
  -> client config
  -> active network context token
  -> algod endpoint and client caches
  -> endpoints.yaml
      -> default signer endpoint
      -> zero or more cosigner endpoints
      -> live /keys discovery -> operation-scoped cosigner routing
  -> client SSH identity + SSH trust
  -> signer HTTP connection over the tunnel

Signer data dir
  -> process config
  -> product runtime
      -> store-root.enc -> selected generation + unsealed term keys
      -> selected generation key files -> runtime key indexes -> /keys and signing
      -> cosigners public references -> /keytypes generation options
      -> key type state + installed templates -> /keytypes and generation
      -> policy documents + HMAC -> per-key policy resolution -> signer approval verdicts or cosigner component-sign authorization by node role
      -> enrolled client registry -> SSH authn and client principals
      -> approval coordinator -> sign/enrollment prompts
      -> process-wide admin session -> admin mutations and approvals
```

The strongest authority chain is:

```text
identity term key
  -> decrypts key files and installed templates
  -> derives policy integrity key used to verify policy document sidecars
  -> enables runtime signing session
```

The strongest signing authority is:

```text
encrypted canonical managed credential (`.key` or `.cos`)
  -> stored key type, bytecode, derivation record, signing args, base key type
  -> signer-side base provider where cryptographic signing is required
```

Templates are generation and provenance authority, not sign-time authority for
existing keys.
The full key file and key type lifecycle is documented in
[ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).

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
backups/default/
.ssh/ssh_host_key
identities/default/
```

Process-scoped data is owned by `apsigner` or installer/setup tools. Mutations
that affect live signer behavior should flow through signer-owned services or
the cooperative store lock.

### Identity

An identity is the root of sensitive signer state:

```text
identities/default/
  store-root.enc           # one authenticated generation + key-authority root
  .keystore                # static version 6 / store-root-v1 format gate
  generations/<gen-id>/
    manifest.json          # immutable at-mint operation record
    seal.json              # final content record, written before flip-away
    keys/*.key
    keys/*.cos
    keys/*.wit.json        # public cosigner metadata sidecar (not private authority)
    keytypes/*.json        # key-type state records
    keytypes/*.template    # encrypted template documents
    default.json           # node default policy, both roles
    default.json.hmac
    policies/<selector>.json           # per-key policy, both roles: address on signer nodes, Witness Key ID on cosigner nodes
    policies/<selector>.json.hmac
    node.yaml.hmac
    cosigners/*.json
    deleted/{keys,keytypes,policies}/
  quarantine/generations/<gen-id>/
  config.yaml
  unlock.yaml
  .ssh/authorized_keys
  cosigners/*.json
  passphrase | passphrase.cred   # optional helper artifacts
```

Credential restore state is request-scoped and never published beside the
generation store. After the complete archive has been authenticated and every
credential validated, restore applies the in-memory set to one staged
generation and commits it with one durable `store-root.enc` replacement.

`productruntime.Runtime` is the runtime projection. It owns:

- lock/unlock state,
- key session,
- key indexes,
- approval coordinator,
- enrolled client registry,
- effective product runtime config,
- effective node policy: the default plus every per-key document for the node
  role, resolved per signing key,
- watcher and shutdown lifecycle.

The process owns one product runtime over the fixed `identities/default/`
store. Runtime and storage APIs carry no selectable identity locator.

Active policy, role integrity, deleted archive, `keys/`, and `keytypes/`
namespaces exist only inside the generation authenticated by
`store-root.enc`. Normal consumers receive a bound active-generation capability
from `genstore.ResolveStoreRoot`; there is no public pointer or legacy active
layout.

### Key Files

Key files are encrypted JSON payloads in the term envelope, bound to the
account address or Witness Key ID they belong to. The current
payload families are:

| Category | Meaning |
|----------|---------|
| `ed25519` | Native Algorand signing key. |
| `dsa_lsig` | DSA-backed LogicSig key with private signing key plus stored LogicSig metadata. |
| `generic_lsig` | TEAL-only LogicSig instance with bytecode and signing args. |
| `witness` | Signer-custodied witness key (`.cos`) used only through cosigner-role `/sign/component`. |

Category selects the managed credential class and filename extension: account
categories use `.key`; `witness` uses `.cos`. There is no durable payload
category named `component`; “component signing” is the wire/runtime flow, not
the on-disk category.

Durable signing metadata includes:

- `format_version`,
- `category`,
- `key_type`,
- public/private key material where applicable,
- stored LogicSig bytecode where applicable,
- `lsig_derivation` for current compiler-auto-salted LogicSig keys, with
  compatibility-only `salt_counter` on manual-counter records,
- `signing_metadata_version` (version 1 non-bounded; version 2 bounded),
- `base_key_type` for composed DSA keys,
- stored signing-argument schema in JSON field `signing_args`,
- optional `bounded_authorization` for bounded1 DSA keys (metadata version 2),
- optional `template_fingerprint`,
- creation parameters and timestamps.

Dedicated guarded account keys are DSA LogicSig keys whose stored bytecode
embeds a cosigner public key (currently `aplane.falcon1024-cosigner1024.v1`). They
are not accepted by `/sign`; the client must use the
guarded flow: user `/sign/component`, cosigner `/sign/component`, user
`/sign/assemble`, then algod submit. Inventory advertises
`signing_flow: cosigner1` for those keys. Cosigner witness keys are selected by an uppercase,
52-character txid-shaped Witness Key ID and are not Algorand spending accounts.

Bounded keys with durable `bounded_authorization.cosigner` use the distinct
`bounded-cosigner1` flow. Corridor v1 is the first such template. Their spend
path uses `/plan`, kind-tagged `/sign/component`, and `/sign/assemble`; their
admin path remains `/sign/bounded-admin`.

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
`template_fingerprint`, `lsig_derivation`, and any compatibility
`salt_counter` are not independent address-derivation inputs.

The full durable payload is `keys.Payload` (codec in
`internal/keys/payload_codec.go`). The signing-argument *schema slice* is
modeled by `internal/signingargs.Info`; key-file storage aliases that type as
`keys.StoredSigningArg`, signer cache aliases it as `cache.SigningArgInfo`, and
`/keys` projects it to the SDK-facing `signerapi.SigningArgInfo` DTO. Template
and `/keytypes` generation metadata uses `runtime_args`.

### Bounded Authorization And External Contract Admin

Bounded1 is an authorization contract used by both `bounded1` and
`bounded-cosigner1` signing choreographies. Normative field inventory, encodings, and custody
rules live in [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md). From a data-model perspective:

- Durable non-secret capability is stored on the account key as
  `bounded_authorization` (signing metadata version 2), owned by
  `internal/boundedmeta` and assembled by `lsig/composeddsa` at generation.
- Inventory advertises `signing_flow: bounded1` without a cosigner or
  `bounded-cosigner1` with a cosigner. Admin-key rekeys always route to
  `POST /sign/bounded-admin` rather than ordinary runtime args or cosigner assembly.
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
2. library-visible compiled providers enabled by product-store state records,
3. installed YAML templates enabled in the product store.

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
after product-store enablement or installation.

Product-store key type records are plaintext because they are not key material:

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
alone. New signer-role stores initialize with
`aplane.falcon1024-allowlist.v1` installed and enabled from the bundled library
source; otherwise YAML templates become active only after product-store
installation and enablement.

### Policy

Policy is product-store durable state stored as `aplane.policy.v1` JSON
documents ([ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md)) in the selected
generation, with the same layout on both node roles:

```text
default.json                         # node default, governs every key without its own file
default.json.hmac
policies/<selector>.json             # one key's own policy; selector is the signing
policies/<selector>.json.hmac        # address (signer) or Witness Key ID (cosigner)
```

Each HMAC authenticates exact document bytes with a key derived from the
identity's current term key. Policy load verifies every sidecar before applying
policy; a missing or mismatched sidecar, a missing `default.json`, or a
document that fails to decode or whose `role` or `key` does not match, fails
the node closed. Every policy change mints a new generation.

Every document carries `role` (`signer` or `cosigner`, matching the node) and
`key` (`default` or the selector the file governs). A key's own file replaces
the default wholesale: there is no inheritance and no override layer. A key
without a file follows the default. The runtime compiles one
`policyruntime.NodePolicy` snapshot (`Default` plus `Keys`) per generation and
resolves `PolicyFor(selector)` from the snapshot captured when a request's
signing service is built, so a reload never changes a request in flight.

`default.json` is seeded at initialize and rebuild from the embedded defaults
(`internal/policy/defaults/signer.json`, `internal/policy/defaults/cosigner.json`).
The signer default rejects a foreign rekey, reviews warning-level fields, and
leaves everything else to the operator default. The cosigner default is
deny-all: a cosigner key with no file signs nothing until it is given one.
Cosigner documents never produce a review verdict. A compiled `policy.Config`
controls:

- the `transaction_types` gate, evaluated first,
- Always Deny rules,
- Always Review rules (signer nodes only),
- Always Approve rules,
- network-scoped, per-asset transfer routing and thresholds.

Deleting a key archives its policy pair under `deleted/policies/` on both
roles. Key backups carry a key's own file as `policies/<selector>.apb`;
`default.json` is node configuration and never travels in a backup.

`user_auto_approve` is not policy. It is the user/operator-default fallback in
product runtime config.

### Client Keys, SSH, And Admin Sessions

The client's enrolled SSH key is its only credential; no token exists on
either side. Enrollment is product-scoped:

```text
identities/default/.ssh/authorized_keys
```

The daemon is the registry's only writer: it validates a complete candidate,
writes it atomically, and installs it under one lock. Clients authenticate the
SSH tunnel with the enrolled public key, and every HTTP request is attributed
to the key of its connection as `client:<fingerprint>`. Admin protocol
sessions authenticate with the product passphrase over local IPC.

The one admin session is runtime-only. It is represented by session context,
transport, and principal, not by a durable session record.

### Audit

The audit log is append-only JSONL at `audit.log`. It records process events,
product-runtime events, signing outcomes, authorization denials, session
connect/disconnect, key management, backup/restore, client enrollment and
revocation, and policy-related signing decisions.

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
swap/<network>/<proposal_id>.<address>.json           # external standalone swap client
swap/<network>/<proposal_id>.<address>.tombstone.json # external standalone swap client
```

- `.apclient.lock` is the cooperative local mutation lock for shared `APCLIENT_DATA`
- tombstones suppress locally deleted proposals for that local actor

### Client Config And Network Context

Client config selects:

- startup network context token,
- allowed network tokens,
- per-network algod endpoints under `networks.<token>.algod`,
- signer status polling interval,
- theme.

The selected network token scopes algod lookup and cache state. It is a local
namespace and must not be treated as chain identity.

Signer and cosigner endpoint routing lives in `endpoints.yaml`, not in
`config.yaml`. The endpoint registry contains a `schema_version`, one default
signer endpoint alias, and endpoint records with `role: signer` or
`role: cosigner`. Endpoint records own connection details: the `ssh://` URL,
SSH identity file, and known-hosts path.

Cosigner endpoint records do not contain key inventory. Guarded and
bounded-cosigner operations query authenticated `/keys` and retain routing only
for the lifetime of that operation. The signer reference catalog is a
generation trust-input inventory, while live endpoint discovery is routing
only. Neither proves endpoint ownership; the embedded public key and verified
component signature remain authoritative.

### Endpoint Registry

- `endpoints.yaml` is the client-local endpoint registry. It requires `schema_version: 2`; any other or missing version is rejected. It has a derived `default` signer endpoint alias, and user-defined endpoint aliases under `endpoints:`. Endpoint aliases are local references only; they are unique within one `APCLIENT_DATA` and use only ASCII letters, digits, `.`, `_`, and `-`.
- if client `config.yaml` contains top-level `ssh:` or `signer_port:` routing, client startup fails closed with an operator-facing message directing the operator to configure `endpoints.yaml`. Startup never materializes or rewrites endpoint routing.
- endpoint records carry connection profile fields together: required `role` (`signer` or `cosigner`), `url` (`ssh://host[:port]` only; `http://`, `https://`, and `self` are rejected, because a node is reachable only through its SSH server), `identity_file`, and `known_hosts_path`. There is no remote REST port field: the node's SSH server accepts only loopback channel destinations and forwards every channel to its own REST listener, so the client never chooses that port. There is no local tunnel port field either; the signer-role forward binds a free loopback port at connect time. There is no credential field: the client's enrolled SSH key at `identity_file` is its only credential. The retired `signer_port`, `local_port`, and `token_file` keys are dropped on load and gone after the next write. Relative file paths resolve against `APCLIENT_DATA`. A registry may contain at most one `signer` endpoint; if present, that endpoint is the effective default. A registry may contain at most 12 cosigner endpoints.
- SSH cosigner endpoints carry HTTP over restricted direct channels on their authenticated SSH connection and never allocate a transient local port. Discovery has a 30-second total deadline, a 10-second per-endpoint deadline, and at most four workers. It completes the bounded sweep before selecting routes because uniqueness cannot be established from an alias prefix: every required witness must be advertised by exactly one live endpoint, and duplicate live advertisers fail closed. Failed endpoints that do not otherwise invalidate the sweep are reported as warnings.
- signer `config.yaml` may set `endpoint.advertise_url` to the client-reachable endpoint URL used by `apadmin endpoint export` when the operator omits both `--host` and `--url`. This is operator-declared routing metadata, not a value inferred from the SSH bind address. It follows the same portable URL rules as endpoint envelopes and rejects `self`. The daemon projects it and the configured endpoint ports through authenticated admin settings; the client does not traverse the private store.
- `apadmin endpoint export` emits a public `aplane.endpoint.v1` JSON envelope for operator handoff after reading endpoint defaults through authenticated admin transport. URL precedence is `--url <url>`, then `--host <client-reachable-host>` deriving `ssh://<host>:<endpoint.ssh.port>`, then the daemon-reported `endpoint.advertise_url`; if none is present, export fails with guidance to pass `--host`/`--url` or configure `endpoint.advertise_url`. `--url <url>` is for explicit HTTPS, loopback HTTP, forwarded SSH ports, or unusual deployments. Like other portable JSON handoff envelopes, it uses a single `schema: "aplane.endpoint.v1"` discriminator. The envelope is strict JSON with the schema and the portable endpoint URL only; the retired `signer_port` and `local_port` members are rejected as unknown fields. It must not contain client-local aliases, endpoint-role metadata, cosigner public-key metadata, credentials, private keys, mnemonics, encrypted key payloads, passphrases, or `known_hosts` trust entries; exported envelopes reject the unsupported URL `self`. File output is published by the operator process with owner-private permissions and refuses symlink destinations.
- `apshell endpoints import --alias <alias> --role signer|cosigner [--dry-run] <endpoint-json>` validates that envelope and writes client-local endpoint routing only: `$APCLIENT_DATA/endpoints.yaml`. Import replaces existing endpoint data when the alias matches. If the imported URL already belongs to a different alias with the same role, import fails without writing; the same URL may be represented by one `signer` alias and one `cosigner` alias for dev co-location. Import is not an ownership or trust proof and does not discover cosigner keys. Enrollment of this client's key at that node is still requested separately with `request-enrollment --endpoint <alias>` (or by guided setup), and SSH host trust is still established by the existing known-hosts flow.
- `apshell endpoints create --alias <alias> --endpoint <url> [--dry-run]` manually creates or replaces a `role: cosigner` endpoint profile in `$APCLIENT_DATA/endpoints.yaml` without an endpoint envelope. `--endpoint` is the client-reachable URL, commonly `ssh://host[:ssh-port]`. Manual creation has the same replacement and duplicate same-role URL rules as import. It does not discover cosigner keys, enroll the client, or establish SSH host trust.
- `apshell endpoints discover-cosigners` is a read-only diagnostic. It scans configured `cosigner` endpoints with authenticated `/keys`, validates each advertised Witness Key ID, and prints the live results without mutating `endpoints.yaml` or the signer reference catalog. Temporarily unavailable or locked endpoints are reported and skipped; authentication failures, endpoint configuration errors, malformed responses, duplicate public keys, and SSH host-key mismatches fail closed.
- `apshell cosigner status` is a read-only route diagnostic with structured `connections`, `accounts`, `account_inventory`, optional `inventory_error`, `discovery_error`, and `duplicate_routes` fields. It uses the runtime discovery cap, concurrency, deadlines, host-key mismatch handling, and witness uniqueness rules. Per-endpoint failures retain partial observations; unavailable signer inventory is distinct from an empty inventory. It never approves host trust, requests enrollment, updates caches, or changes the primary connection. Its positive result means only point-in-time route availability; it does not authorize a transaction. The `cosigner` command remains blocked through MCP.
- `apshell endpoints add [<cosigner-url>] [--alias <alias>] [--replace] [--dry-run]` is the guided cosigner connection setup; `apshell cosigner add` forwards to it with a one-line notice. It takes the cosigner's URL (`--endpoint <url>` is an accepted spelling) and no document: a file argument is refused with guidance that the cosigner's key file is imported on the signer. Interactively, a missing URL is prompted for; script use requires it. `--alias` is optional interactively: a `role: cosigner` profile already configured for the resolved URL is reused without a name prompt or confirmation, and otherwise a name derived from the endpoint host is suggested; script use requires `--alias` for a new profile. Naming an already configured cosigner URL differently is refused with the existing alias. It plans and revalidates a `role: cosigner` endpoint under the shared client-data mutation lock, and performs SSH trust and enrollment only after releasing that lock. It first tries the connection with the client's key; if the node refuses the key as unenrolled (`sshtunnel.ErrKeyNotEnrolled`, surfaced as `engine.ErrCosignerDiscoveryAuth`), it submits an enrollment request there. A request the node queues for its operator stops setup with the connection configured and the error `ErrCosignerSetupEnrollmentPending` ("enrollment request is waiting for the cosigner's operator"); setup is rerun once the operator approves. Only when the node answers that the key is already enrolled is the connection tried once more. On its own connection it then reads `node_role` from authenticated `/status` and continues only for `cosigner` (a `signer`, an absent or unrecognized role, or a failed read stops setup), and it reports the number of keys the node advertises and the resolver's route sweep. The client never handles a cosigner key; key trust is decided on the signer. Its structured result carries `connected`, `node_role`, `advertised_keys`, `enrolled`, `enrollment_pending`, and `routes`. It fails only for the connection being added: no access, a non-cosigner node, or a witness that this endpoint and another both advertise. Unavailable signer inventory, accounts needing other cosigners, failures on other endpoints, and a sweep that stopped early are reported without failing it. The setup connection and enrollment request are isolated from the primary signer tunnel. Dry-run performs no writes, trust changes, enrollment requests, or network probes. Conflicting replacements require interactive review. The `add` subcommand is blocked through MCP at the subcommand boundary; the other `endpoints` subcommands remain available.
- an endpoint record carries no per-destination credential, so creating, re-pointing, or deleting an alias retires nothing on the client. The enrollment a node recorded for this client's key outlives the client's route to it; revoking it is the node operator's action.
- endpoint create, import, delete, default selection, and `endpoints add` serialize their `endpoints.yaml` read-modify-write sections with `$APCLIENT_DATA/.apclient.lock`. Network waits occur outside endpoint-write critical sections.
- `apshell endpoints list`, `endpoints show <alias>`, `endpoints default <alias>`, and `endpoints delete <alias>` operate on local client routing configuration. `show` is local-only and does not call `/keys`; deletion has no cosigner-inventory dependency.

### Client Startup And Enrollment

- interactive `apshell` startup does not require a pre-enrolled client: it validates client bootstrap/config inputs, but it may start with a key the signer has not enrolled or without a trusted signer host so the operator can run enrollment, recovery, and troubleshooting commands. Whether a key is enrolled is known only to the node; an unenrolled key is discovered as an authentication failure at connect time, with guidance to run `request-enrollment`
- for interactive `apshell`, SSH host trust is enforced when the shell attempts `connect`, startup auto-connect, or `request-enrollment` flows; it is not a preflight requirement for process startup
- `request-enrollment [--endpoint <alias>] [--label <text>]` asks configured endpoints only to enroll this client's key: without `--endpoint` it uses the default signer endpoint; `--endpoint <alias>` uses that signer or cosigner endpoint. A positional host is not accepted. The optional label is display text the node stores beside the key. The command returns as soon as the node has answered: `pending` (the request waits for the node's operator; apshell says to run `connect` once it is approved) or `enrolled` (the key was already enrolled). Nothing is written on the client. `apshell` connects at once only when the default signer answered `enrolled`
- `apshell --mcp` has a stricter startup contract than interactive `apshell`: MCP startup is non-interactive and refuses to start unless a default signer endpoint is configured and its host is trusted in `known_hosts`
- `apshell --mcp` also requires the startup signer connection to succeed; it does not start in a disconnected state or with a key the signer refuses, and it cannot perform first-use trust or enrollment itself
- shared non-interactive client-enrollment preflight lives in `internal/clientenroll/preflight.go` and is used by `apshell --mcp`
- `apadmin` uses local IPC only and has no client enrollment prerequisite. For remote administration, SSH into the signer host and run apadmin there.

### apconsole Startup

- `apconsole.yaml` supports `mode: local`, `client_data`, and `signer_data`; relative paths resolve against the profile file
- `apconsole` resolves startup inputs per field in this order: flags, environment variables, explicitly selected profile (`-config` or `APCONSOLE_CONFIG`), auto-discovered profile, then defaults
- an explicit `-d` or explicitly selected profile `signer_data` is also an
  explicit signer-store selection for IPC discovery and cannot be retargeted
  by an inherited `APSIGNER_IPC_PATH`. A signer root selected through
  `APSIGNER_DATA` may pair with `APSIGNER_IPC_PATH`; auto-discovered profile
  values remain lower precedence than environment values
- local `apconsole` lifecycle management requires its client IPC path to equal
  the path the selected store's daemon will bind. An intentional client-only
  override must use `--no-start-daemon`; otherwise `apconsole` refuses before
  attaching to the override or starting a daemon whose readiness it cannot
  observe. Attach-only mode uses the selected client socket without deriving or
  validating the store's daemon bind path because it will not manage that
  daemon's lifecycle
- conflicting explicit inputs do not auto-resolve: if flags, environment variables, or an explicitly selected profile disagree, `apconsole` exits and requires the operator to remove the conflict or make the values match
- auto-discovered profile values are convenience defaults only; if they differ from explicit flags or environment variables, `apconsole` keeps the explicit values and emits a warning naming the ignored profile value
- local-mode signer `apconsole` may start before client enrollment is complete; it requires valid local client/signer data paths, but it allows the embedded shell to perform first-time `request-enrollment` while the local signer/admin panes are available for approval
- local-mode cosigner `apconsole` suppresses the embedded shell and renders only the admin pane plus daemon/status pane; cosigner policy changes use the `apadmin policy` verbs
- the embedded `apadmin` pane uses local IPC independently of the shell pane's client data, enrollment, and endpoint configuration
- for local-mode signer `apconsole`, when the client SSH host is loopback, the local signer's configured SSH host key is probed against the live loopback SSH endpoint before being pinned into the client `known_hosts` file; a mismatch aborts the trust write and shell startup; enrollment is discovered at connect time, when the embedded shell attempts startup auto-connect, `connect`, or `request-enrollment`
- remote-mode `apconsole` is rejected; run apconsole on the signer machine, using an ordinary SSH login when needed

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
`schema_version`, which every write records. The signed envelope has
`version: 1`; alias, set, ASA, and auth-address payloads carry
`schema_version: 1`, while `signer_cache.json` carries `schema_version: 2` for
structured LogicSig resources. A missing or unsupported payload
version is rejected and the cache is rebuilt from empty or seed data; the
signer cache then rebuilds from authenticated signer inventory without
invalidating unrelated client caches. Cache
files remain non-authoritative. Caches persist only under a client data
directory; without one they live in memory and nothing is written to the
working directory.

The cache owner is `internal/clientstate` plus `internal/cache`, with
`internal/refname` owning persisted alias and set name validation and
normalization. Callers should use `internal/asa` for ASA reference and amount
semantics rather than reading cache files directly. Static ASA metadata and
convenience aliases are centralized in `internal/asa/registry`; JavaScript
helpers, engine resolution, and cache seeding all project from that registry
instead of carrying separate built-in asset maps. Current-network cache entries
have precedence over convenience aliases, while ambiguous symbolic references
are rejected.

- `signer_cache.json` is a local projection of authenticated signer `/keys`
  inventory. It may persist address key types, generic-LogicSig flags,
  structured `logic_sig_resources`, key-file signing argument schemas,
  `signing_flows`, `cosigner_component_key_types`, and `cosigner_public_keys`.
  Each LogicSig resource profile keeps final compiled program bytes separate
  from path-specific maximum argument bytes and reviewed opcode-cost ceilings.
  Bounded profiles expose spend, spending-rekey, and admin-rekey paths from the
  durable argument layout; no combined program-plus-arguments scalar is stored.
  Covered APlane-owned declarations are exercised by the integration
  opcode-ceiling gate: production-generated final bytecode and maximum-input
  accepted paths are simulated by the same algod selected by the signer fixture's
  `teal_compile_network`, and its nonzero `logic-sig-budget-consumed` result
  must not exceed the persisted declaration. This validates the selected path
  ceiling, not the feasibility of every assembled group.
  For guarded signing, clients route on `signing_flows`; a cached
  built-in guarded key type with missing flow or cosigner metadata is only a
  stale-cache signal that triggers `/keys` refresh before route selection.
- persisted alias and set names are canonicalized to lowercase by
  `internal/refname`; both allow only ASCII letters, digits, `-`, and `_`;
  aliases reserve `list`, `delete`, and `remove`; sets reserve `list`, `add`,
  `remove`, `delete`, and dynamic runtime set names `all` and `signers`
- apshell passively watches the shared `cache/` directory when possible and reloads changed in-memory cache snapshots at command boundaries; this is best-effort freshness, not an authority or synchronization contract

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

### Installer And Launcher State

- installers write `.mcp.json` and `.codex/config.toml` for the installed
  `apshell --mcp` command and data directory; existing files are preserved and
  `.mcp.json.aplane-installer.new` or
  `.codex/config.toml.aplane-installer.new` templates are written instead
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
- interactive installers probe the default or environment-overridden AlgoKit LocalNet endpoint with `aplocalnet --check` after target data roots and `apenv.sh` exist; when reachable, they ask whether to apply LocalNet setup to the data roots being installed, defaulting to `No`. `APLANE_SKIP_LOCALNET_SETUP=1` suppresses this prompt. Client-only installs apply only the client target, local installs apply client and signer targets, and systemd installs apply the signer target plus the operator client target when one exists.
- local-mode uninstall removes generated binaries, launcher/env files, and installer-generated MCP config, but preserves `APCLIENT_DATA` and local signer data by default; destructive removal of keys, tokens, plugins, scripts, caches, and swap state is an explicit manual step

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
- `ComponentRequest`,
- `ComponentResponse`,
- `AssemblyRequest`,
- `AssemblyResponse`,
- `GroupPlanResponse`,
- `GroupSignResponse`,
- `MutationReport`,
- `KeysResponse` / `KeyInfo` (including `signing_flow`,
  `cosigner_component_key_type`, optional `bounded_authorization`),
- `KeyTypesResponse`,
- `StatusResponse`,
- `HealthResponse`,
- `CancelSignRequest`, `CancelSignResponse`,
- admin generate/delete DTOs,
- `ErrorResponse`.

HTTP authentication resolves the connection's enrolled client key to a
`client:<fingerprint>` principal, and handlers use the process-owned product
runtime. Clients route signing on inventory `signing_flow`
labels (`cosigner1`, `bounded1`, `bounded-cosigner1`, or empty for plain `/sign`)
and must fail closed on unknown labels.

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
- client enrollment prompts, the enrolled-key list, and key revocation,
- backup/restore results,
- cosigner-reference and generation inventory,
- admin and policy settings.

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
3. Validate that `identities/` has no entry other than a real `default/` directory.
4. Build the one product `productruntime.Runtime` for `default`.
5. Start locked, unlock headlessly, or unlock through admin depending on
   passphrase startup configuration.

### Unlock And Reload

1. Open `store-root.enc` with the passphrase; the unwrap and selection MAC are
   the checks.
2. Bind the authenticated selected generation and hold its unsealed term keys
   for the unlocked session.
3. Verify root `node.yaml` against the selected generation's role HMAC sidecar.
4. Verify and load the policy documents (`default.json` and every
   `policies/*.json`) for the node role; any sidecar or decode failure stops
   the load.
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

Unused-key guards require the unlocked keyring because they scan encrypted
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
4. Client routes by embedded cosigner public key to a cosigner endpoint from
   `endpoints.yaml` and calls cosigner `/sign/component`.
5. If non-guarded originals exist, client calls the primary signer `/sign` over
   the full canonical group: non-guarded originals are sign-mode entries,
   guarded targets are `foreign` entries with accurate `lsig_resources` hints, and
   dummies are `foreign` context entries.
6. Client calls user signer `/sign/assemble` with guarded targets plus
   passthrough signed bytes for non-guarded originals and dummies.
7. User signer verifies cosigner signatures against the cosigner public key
   embedded in the local guarded account key, packs LogicSig args, and returns
   signed group bytes.
8. Client submits the signed bytes to algod.

Endpoint routing and `/keys` discovery are not trust proofs. A wrong endpoint
can only return a signature that assembly or the on-chain LogicSig rejects.

### Client Enrollment Lifecycle

1. Client connects over SSH as `request-enrollment` and runs `enroll [<label>]`.
2. Server verifies the fixed enrollment username and key-only bootstrap path.
3. Server records the request in `identities/default/.ssh/pending_enrollments.json`
   (one entry per key, bounded), audits `CLIENT_ENROLLMENT_REQUESTED`, and
   announces it to a connected admin session.
4. Server replies `pending <fingerprint>` over the SSH channel (or
   `enrolled <fingerprint>` for a key already in the registry); the client
   disconnects.
5. Later, an admin session approves (`approve_enrollment`) or rejects
   (`reject_enrollment`) the request, or imports the public key directly
   (`import_client_key`). Waiting requests are announced again at admin login
   and survive a restart.
6. On approval the server adds the SSH public key and label to the registry,
   removes the request, and audits `CLIENT_ENROLLED`; on rejection it removes
   the request and audits `CLIENT_ENROLLMENT_REJECTED`.
7. The client connects as `aplane`; an enrolled key is accepted.

Revocation removes the key from the registry, closes its live SSH connections,
and audits `CLIENT_KEY_REVOKED`; the client must enroll again.

### Backup And Restore Lifecycle

Managed backup archives live under `backups/default/`. Each archive contains
encrypted canonical credential `.apb` payloads and `manifest.sealed` — the
archive's authenticated description, carrying the member inventory and source
node role. Opening an archive
verifies every member against that inventory. The manifest role is a rebuild
default; explicit `apstore rebuild --role` is the replacement store authority
when supplied.
`.apb` is the cryptographic backup unit; the tarball is packaging.

Live restore is generation-transaction oriented:

- preview decrypts and reports without mutation,
- direct restore validates the complete selected set and classifies
  canonical-plaintext destination conflicts before any write,
- one generation mint commits credential changes behind a single durable
  `store-root.enc` replacement, then reloads,
- an uncommitted attempt leaves the prior generation active; a commit with
  unconfirmed durability blocks signing in recovery mode until
  reconciliation,
- policy, templates, network mappings, approval defaults, and other
  configuration are absent from the backup and remain destination-owned.

`apstore rebuild` is the separate absent-store rescue path and may write active
credentials directly because no live signer store is being mutated.

## Security-Sensitive Data

| Data | Sensitivity | Handling rule |
|------|-------------|---------------|
| Passphrase | secret | parsed into mutable buffers where possible; zero promptly |
| Term keys | secret | unsealed from `store-root.enc` at unlock; cached only while unlocked; zeroed on lock |
| `.key` account private material | secret | encrypted at rest; decrypted on demand |
| `.cos` cosigner witness material | secret | encrypted at rest; usable only in the cosigner component-signing domain |
| External `.wit` contract-admin private material | secret | standalone `aplane.witness-key-bundle.v1`; never signer-managed; not backed up by `apstore` |
| Bounded ceremony request/signature files | short-lived signing authority | non-secret but bind network/partial; mode `0600`, no overwrite |
| Installed `.template` files | sensitive policy material | encrypted in the product store |
| `default.json`, `policies/*.json` | safety-critical | authenticated by HMAC sidecars; `aplane.policy.v1` documents whose `role` must match the node |
| `release.json` | provenance metadata | public installer/release stamp; not signing, policy, or trust authority |
| Enrolled client registry | authoritative access list | `identities/default/.ssh/authorized_keys`, daemon-written; a key listed here authenticates as `client:<fingerprint>` |
| SSH private key | client secret | client-side file or agent key; the client's only credential |
| Backup export passphrase | secret | protects `.apb` payloads |
| Audit log | sensitive operational record | mode `0600`; append/rotate |
| Public cosigner reference | public metadata | generation input only; not endpoint trust or ownership proof |
| Endpoint-published cosigners | public routing metadata | routing input only; not endpoint trust or ownership proof |

Signer-wide ASA metadata and product-store key type state records are not secrets.
They still must be mutated through supported paths because they affect UX,
generation availability, provenance, and policy amount rendering.

## Compatibility Invariants

- The exact compatibility scope for persisted and wire shapes is defined in
  [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).
- Canonical `key_type` strings are stored and transmitted exactly; display
  labels are not identifiers.
- Key files are signing authority for existing keys.
- Templates are generation/provenance authority, not sign-time authority.
- `GenesisHash` is signer policy chain identity; `GenesisID` is display data.
- Server config can seed the default `user_auto_approve`; product runtime config owns
  the effective live setting; policy owns rule verdicts.
- Policy HMAC authenticates exact document bytes and fails closed on mismatch.
- `default.json` governs every key without a file of its own; `policies/<selector>.json`
  governs exactly one key and replaces the default for it. A document's `role`
  must match the node; neither role's documents may be loaded on the other.
- Witness Key IDs are uppercase 52-character base32-no-padding
  SHA-512/256 digests over the domain-separated key-type/public-key tuple;
  embedded cosigner verifier keys are full public-key hex values.
- `/keys` per-key `signing_args` are the key file's durable signing-argument
  schema and sign-time authority for that key; `/keytypes` `runtime_args` are
  generation metadata for future keys.
- Key type state records affect discovery and generation only; existing keys
  remain signable when their key file and required base provider are valid.
- Client caches are rebuildable and not authoritative for signing or policy.
- Sign request cancellation is live runtime state, not durable workflow state.
- Admin protocol and HTTP protocol are separate compatibility surfaces.
- The product owns one fixed store (`identities/default/`) and one runtime;
  `default` is only the on-disk store directory name.

### Design Decisions

These decisions are part of the current data model and contract surface:

| Decision | Rationale |
|---|---|
| `store-root.enc` is the store's sole commit record. | KDF parameters, sealed term set, epoch, and authenticated generation selection live in one file, so generation and key-authority transitions require one durable rename and no second record can disagree. `.keystore` is a non-authoritative format gate. |
| Every encrypted object names itself in its envelope. | The AEAD's authenticated data binds the term and the object's class and canonical selector, so one store key no longer makes every file interchangeable with every other. The identity is logical, never a path, because generations copy ciphertext between namespaces without re-encrypting it. |
| In-place upgrades have a minimum supported release. | The installer upgrades only installs with `install/release.json` at or above the current floor; installs below the floor require a fresh install root. |
| `release.json` is release provenance metadata. | It helps identify the installed distribution and apply installer compatibility gates, but does not authenticate code or authorize upgrades by itself. |
| Release archive labels are not upgrade authority. | Local packaging and smoke tests may use simple archive labels while embedding a semver-comparable `release.json.version`; installers compare the metadata file, not the tarball filename. |
| `endpoints.yaml` is the client routing authority. | Client `config.yaml` owns network/theme/polling, not signer or cosigner endpoint routes. |
| The store-root selection is the only active-generation authority. | Normal readers and writers receive one authenticated, bound `storepaths.GenPaths` capability. Generation directories, including quarantine, cannot select themselves. |
| Endpoint import and `/keys` discovery are routing metadata. | The trust anchor is the cosigner public key embedded in the guarded account key, then `/sign/assemble` verification and on-chain LogicSig verification. |
| Cosigner routing is operation-scoped runtime state. | Clients query authenticated `/keys` for each guarded or bounded-cosigner operation; no cosigner-key inventory is persisted in `endpoints.yaml`. |
| `cosigners/<name>.json` records are public generation references. | They help the TUI select a cosigner public key but do not prove endpoint ownership or signer custody. |
| Guarded account key files store the resolved embedded public key. | Endpoint alias, reference name, and route selection are client/runtime concerns, not sign-time authority for the key. |
| External `.wit` bundles are not signer-managed credentials. | Contract-admin private material stays in standalone custody (`aprekey`); signer and `apstore` never treat `.wit` as `.key`/`.cos`. |
| Inventory `signing_flow` labels are frozen routing tokens. | Clients implement empty, `cosigner1`, `bounded1`, and `bounded-cosigner1` and fail closed on unknown labels. |
| `signerapi.SignResponse` is not the live `/sign` wire shape. | Live `/sign` uses `GroupSignResponse`; `SignResponse` is not a separate wire authority. |
| Admin mnemonic export messages do not release recovery material. | Servers deny `export_key`, `GenerateResultMessage.Mnemonic` is omitted, and recovery material is handled through encrypted backups instead of admin result payloads. |
| `internal/signerapp/signing` uses SDK DTOs at the service boundary. | It is not a duplicate durable authority; request DTO changes belong in `pkg/signerapi` with fixtures. |
| Plugin manifest schema 2.0 is command-only. | `functions` and `protocol_version` are rejected before execution; plugin JSON-RPC protocol and manifest schema are separate models. |
| Template `ReloadReport` is a reload projection. | It verifies product-store activation results but does not persist template authority; encrypted template files and key type state records remain the durable sources. |

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

1. Update the [Catalog](#catalog) in the same change.
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

## Catalog

The catalog inventories model elements with identity beyond one function call,
in compact rows. Key file and key type state transitions are in
[ARCH_STORE.md](ARCH_STORE.md#keys-and-key-types).

### Reading the catalog

The catalog uses compact rows instead of one subsection per object. Read the
columns as follows:

- **Element** is the model element name and category.
- **Kind** records whether the row is authority, cache, display metadata,
  provenance, derived state, secret state, or runtime-only state.
- **Authority** records the durable path, wire contract, source-defined record,
  schema name, and version field when one exists.
- **Projection** records runtime, wire, UI, or SDK projections.
- **Owner** records writer packages first and reader/projection packages where
  they differ.
- **Checks** records mutation locks or atomic-write paths, security sensitivity,
  validation/normalization rules, failure behavior, and representative tests or
  fixtures when they are compatibility-bearing. Rows without a named lock are
  runtime-only, source-defined, or mutated through the owning subsystem's
  existing file writer/store lock.

The entries are compact by design. Compatibility-bearing details remain in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md), [ARCH_HTTP_API.md](ARCH_HTTP_API.md),
and [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md).

### Signer Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Signer data root | authoritative root | `APSIGNER_DATA` | `storepaths.Paths` and startup path resolution | `internal/serverconfig`, `internal/bootstrap/signer`, `internal/storepaths`, installers | Required for signer startup; systemd-managed roots reject manual startup unless explicitly allowed. |
| Process config | authoritative config | `APSIGNER_DATA/config.yaml` | `serverconfig.ServerConfig` snapshot | `internal/serverconfig`, `internal/bootstrap/signer`, `internal/signerapp/admin` | Unknown fields reject; mutable writes use process config lock; tests in `internal/serverconfig` and admin settings tests. |
| Network config | authoritative config section | `config.yaml` `networks.<token>` and `teal_compile_network` | algod map and genesis resolver | `internal/serverconfig`, `internal/signerapp/daemon` | Token syntax and genesis hash collisions fail closed; see `docs/ARCH_NETWORKS.md`. |
| SSH host key | secret server credential | `.ssh/ssh_host_key` | `sshtunnel.Server` host key | `internal/sshtunnel`, startup/install | Generated locally; clients pin through known-hosts flow. |
| IPC socket path | runtime endpoint | systemd default `/run/apsigner/aplane.sock`; same-UID local default `<data_dir>/aplane.sock`; explicit override supported | local admin transport listener | `internal/signerapp/daemon`, `internal/signerapp/ipcbind`, `internal/adminproto`, `internal/transport` | Production runtime parent is service-owned `0750`, socket is `0660`, and local admin protocol still requires passphrase auth. |
| Store mutation lock | runtime/durable coordination | `.apstore.lock` | cooperative store lock | `internal/storelock`, `internal/signerapp/storemut` | Serializes live signer and local `apstore` mutations. |
| Audit log | authoritative audit trail | `audit.log` JSONL | append-only audit logger | `internal/signerapp/audit`, `internal/signerapp/daemon` | Mode `0600`, rotated by size; not authority for signing or recovery. |
| Signer ASA cache key | cache secret | `cache/.cache_key` | HMAC verifier for signer ASA cache | `internal/cache`, `internal/signerapp/asametadata` | Tampered cache files reject and rebuild from seed where applicable. |
| Signer ASA cache | cache/display | `cache/<network>_asa_cache.json` | per-operation ASA metadata lookup | `internal/signerapp/asametadata`, `internal/asa` | Signed cache; built-in registry seeds; not authority for policy enforcement. |
| Managed backup locker | authoritative backup inventory | `backups/default/*.tar.gz` | backup list/restore preview/direct restore input | `internal/backup`, `internal/signerapp/backupadmin` | Imported archives are validated before publication; archive payloads are encrypted `.apb`. |
| Backup import residue | ephemeral validation state | `backups/default/.import-*.part`, `.import-claimed-*.part`, `.import-validation-*/` | unpublished upload, immutable validation claim, and same-filesystem deep-validation workspace | `internal/signerapp/backupadmin` | Owner-private, excluded from managed inventory, removed on normal completion or daemon startup. |
| Sealed archive manifest | authenticated archive description | `manifest.sealed` inside managed archives | member inventory and source node role | `internal/backup` | Schema `aplane.credential-backup.manifest.v1` sealed under the export passphrase; every open path verifies exact membership. |
| Deleted archive root | inactive generation storage | selected `generations/<gen-id>/deleted/` | outside active key/template scans | `internal/genstore`, `internal/keys`, `internal/templatestore` | Hard-limited to 4,096 entries and 256 MiB encoded; mutations reserve capacity before publishing; explicit live prune requires confirmation and durable audit intent. |

### Signer Identity Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Node role | authoritative root config | `<APSIGNER_DATA>/node.yaml` plus selected generation `node.yaml.hmac` | key-class and service-dispatch gates | `internal/noderole`, `internal/keyclass`, signer startup, identity load, keyadmin, restore, signing dispatch | Values: `signer`, `cosigner`; no `dual`; no supported role changes; active role conflicts fail the whole node closed. |
| Signing identity directory | authoritative root | `identities/default/` | the one `productruntime.Runtime` | `internal/signerapp/productruntime` | Any other direct `identities/` entry fails startup. |
| Product runtime config | authoritative config | `identities/default/config.yaml` (parsed as `productruntime.StoredConfig`) | `productruntime.EffectiveConfig` (resolved) | `internal/signerapp/productruntime`, `internal/signerapp/admin` | Unknown or invalid settings fail closed. Node role belongs only in root `node.yaml`. |
| Unlock config | authoritative config | `identities/default/unlock.yaml` | passphrase helper command config | `internal/signerapp/unlockconfig`, `cmd/appass` | Helper artifacts are product-scoped and independent of node role. |
| Passphrase helper files | secret helper state | `passphrase`, `passphrase.cred` | startup/headless passphrase source | `cmd/appass`, `cmd/appass-file`, `cmd/appass-systemd-creds` | Mode `0600`; systemd/local ownership rules enforced by appass. |
| Atomic store root | authoritative cryptographic and selection root | `identities/default/store-root.enc` | passphrase verification, selected generation, epoch, and term keys | `internal/crypto`, `internal/genstore`, `internal/keystore` | Schema `aplane.store-root.v1` containing an `aplane.keyring.v3` envelope and selection MAC; a passphrase change or generation commit replaces this one file atomically. |
| Keystore marker | store format gate | `identities/default/.keystore` | none | `internal/crypto` | Static `{version: 6, layout: "store-root/v1", created}`; carries no authority; any other version fails closed. |
| Term key session | runtime-only secret | unsealed from `store-root.enc`, resident only while unlocked | `keystore.KeySession`, `FileKeyStore` | `internal/keystore`, `internal/signerapp/runtime` | Zeroed on lock; not exposed on wire. |
| Enrolled client registry | authoritative enrollment | `identities/default/.ssh/authorized_keys` | `clientregistry.Registry` installed in the product runtime | `internal/signerapp/clientregistry`, `internal/signerapp/productruntime`, `internal/sshtunnel`, `internal/signerapp/enrollment` | Daemon-written only; strict option-free parser, duplicates rejected; validated, atomically written, and installed under one lock. Enrollment writes after admin approval; revocation closes the key's SSH connections. |
| Node default policy | authoritative safety policy | selected generation `default.json` plus `default.json.hmac`, on both node roles | `policyruntime.NodePolicy.Default` runtime snapshot | `internal/policy`, `internal/signerapp/policyruntime` | `aplane.policy.v1` document with `role` matching the node and `key` equal to `default`; seeded from the embedded default at initialize and rebuild; HMAC over exact bytes; missing document, mismatched sidecar, or decode failure fails the node closed. |
| Per-key policy | authoritative safety policy | selected generation `policies/<selector>.json` plus `.json.hmac`, at most one pair per key, on both node roles | `policyruntime.NodePolicy.Keys[selector]`, resolved by `PolicyFor(selector)` | `internal/policy`, `internal/signerapp/policyruntime`, `internal/signerapp/signing` | `aplane.policy.v1` document whose signed `key` matches the file name (signing address on signer nodes, Witness Key ID on cosigner nodes); replaces the default wholesale for that key; cosigner documents carry no review or operator-default outcomes; any mismatched sidecar or decode failure fails the node closed. |
| Policy sidecar | authoritative integrity metadata | selected generation `default.json.hmac`, `policies/<selector>.json.hmac`, and archived `deleted/policies/*.json.hmac` JSON | HMAC verification result | `internal/policy`, `internal/integritysidecar`, `internal/signerapp/policyapply`, `cmd/apstore` | Security fields are `version`, `algorithm`, `key_id`, `hmac`; diagnostics such as `signed_at` are not trust inputs; passphrase rotation re-signs every policy sidecar. |
| Key type state record | authoritative generation state | selected generation `keytypes/<key_type>.json` | enabled/disabled product-store key type state | `internal/keytypestate`, `internal/signerapp/templateadmin` | Plaintext, not key material; affects discovery/generation, not existing-key signing. |
| Installed template | authoritative generation source | selected generation `keytypes/<key_type>.template` | registered template provider after unlock/reload | `internal/templatestore`, `internal/signerapp/templates` | Sealed under the identity's current term key and bound to its key type; disabled state skips registration. |
| Public cosigner reference | public product catalog | `identities/default/cosigners/<name>.json` | `/keytypes` `cosigner` select options | `internal/cosigner/cosignerrefs`, `internal/signerapp/rest`, `internal/apadminapp` | Non-generational, explicitly imported public metadata only; not endpoint ownership proof. |

### Key Material And Key Metadata

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Managed credential envelope | authoritative secret storage | selected generation `keys/*.key` or `keys/*.cos` encrypted JSON | decrypted canonical payload | `internal/keys`, `internal/keystore` | Category selects the sole filename class; envelope and payload versions checked before use; the term envelope's AAD binds the account address or Witness Key ID, so a credential filed under another name does not decrypt. |
| Native Ed25519 key | signing authority | `.key` category `ed25519` | address to private key material | `internal/signing`, `internal/keygen`, `internal/keys` | Address derives from key material; private key never leaves signer boundary. |
| DSA LogicSig key | signing authority | `.key` category `dsa_lsig` | address, bytecode, private signing key, signing args | `internal/keys`, `internal/signerapp/signing`, `lsig/*` | Stored bytecode and `signing_args` are sign-time authority. |
| Generic LogicSig key | signing authority | `.key` category `generic_lsig` | address, bytecode, runtime arg schema | `internal/keys`, `lsig/generictemplate` | TEAL-only key stores no private signing key; address derives from bytecode. |
| Guarded account key | signing/assembly authority | `.key` category `dsa_lsig`, key type `aplane.falcon1024-cosigner1024.v1` | local user-role key plus embedded cosigner public key | `lsig/falcon1024_guarded`, `internal/signerapp/signing` | `/sign` rejects; inventory uses `signing_flow: cosigner1`; user-role `/sign/component` and `/sign/assemble` use stored bytecode/params. |
| Bounded-cosigner account key | signing/assembly authority | `.key` category `dsa_lsig`, bounded metadata with `cosigner` (for example `aplane.corridor.v1`) | local base key, bytecode, bounded metadata, embedded cosigner public key | `lsig/composeddsa`, `internal/boundedmeta`, `internal/signerapp/signing` | `/sign` rejects cosigner-gated spend; inventory uses `signing_flow: bounded-cosigner1`; bounded component and assembly endpoints consume stored metadata. |
| Bounded account key metadata | signing authority metadata | key payload `bounded_authorization` at `signing_metadata_version: 2` | inventory `bounded_authorization` / path sizing | `internal/boundedmeta`, `lsig/composeddsa`, `internal/keys`, `internal/signerapp/signing` | Required for bounded1 DSA keys; ordinary `/sign` rejects admin-key operations that need `/sign/bounded-admin`. |
| Cosigner witness key | component-sign authority | `.cos` category `witness`, key type `aplane.witness-*` | raw cosigner-role witness key | `internal/keygen`, `internal/signing`, `internal/signerapp/signing` | Selected by Witness Key ID; `/sign` rejects; cosigner-role `/sign/component` only; not a spending account. |
| External contract-admin witness bundle | secret standalone custody | `<WITNESS_KEY_ID>.wit` schema `aplane.witness-key-bundle.v1` | `aprekey` generate/inspect/verify/sign | `internal/witness/artifact`, `cmd/aprekey` | Never a signer-managed `.key`/`.cos`; signer/`apstore` must not import, decrypt, back up, or restore private material. |
| Witness Key ID | public selector | 52-character uppercase base32 SHA-512/256 of canonical length-prefixed domain, key type, and public key bytes | cosigner key row `address`, public reference `witness_key_id`, and role-specific `component_key` fields | `internal/witness` | Txid-shaped but not a valid Algorand address; rejected where an Algorand address is required. |
| Cosigner public metadata sidecar | public metadata | `keys/<witness_key_id>.wit.json` | `apadmin cosigner export` source | `internal/keys`, `internal/cosigner/cosignerrefs` | Witness Key ID/key type/public key consistency verified; no private material. |
| Key creation parameters | provenance/generation input | key payload `parameters` | `/keys` `parameters`, key details | `internal/keys`, `internal/keymgmt` | Canonical payload parser rejects duplicate object members, unknown fields, and noncanonical aliases. |
| LogicSig bytecode | signing authority | key payload `lsig_bytecode` | LogicSig address and signing assembly | `internal/keys`, `internal/signerapp/signing` | Bytecode must derive an off-curve address. |
| Signing args | signing authority | key payload `signing_args` | `internal/signingargs.Info`, `/keys` `signing_args` | `internal/signingargs`, `internal/keys` | Per-key snapshot; distinct from `/keytypes` runtime args. |
| Signing flow label | wire/runtime routing projection | inventory `signing_flow` on `/keys` and `/keytypes` | client route selection (`cosigner1`, `bounded1`, `bounded-cosigner1`, or empty) | `pkg/signerapi`, `internal/signerapp/rest`, clients | Frozen labels; unknown flows fail closed; empty means ordinary `/sign`. |
| LogicSig derivation record | signing authority metadata | key payload `lsig_derivation` and compatibility-only `salt_counter` | stored final-bytecode derivation contract | `internal/lsigsalt`, `internal/keys` | Current `algod_v13_auto_salt` keys require final TEAL v13+ bytecode and forbid `salt_counter`; compatible manual-counter keys require it. Unknown or internally inconsistent derivation records reject scan/restore/signing. |
| Base key type | signing authority metadata | key payload `base_key_type` | base provider lookup for DSA keys | `internal/keys`, `internal/signerapp/signing` | Required for composed/DSA signing that needs base provider ops. |
| Template fingerprint | provenance | key payload `template_fingerprint` | inventory provenance status/note | `internal/lsigprovider`, `internal/keys` | Behavior-only and versioned (`<n>:` prefix); identifier-independent (base key types projected to stable `base_primitive` tokens); provenance only, conflicts do not block signing; cross-version or malformed comparisons are "not comparable" (benign, not a conflict). |
| Offline key inventory | local decrypted projection | encrypted key files plus passphrase | `apstore keys list` output | `cmd/apstore`, `internal/keys` | Does not print private key, mnemonic, or raw cosigner public key by default. |

### Key Type And Template Catalog

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Compiled provider registry | process authority | Go registrations in `lsig/all.go` and provider packages | provider lookup by `key_type` | `internal/lsigprovider`, `internal/keygen`, `internal/signing` | Canonical `key_type` strings are identifiers; display labels are not. |
| Key type visibility catalog | process metadata | `internal/keytypecatalog` registrations | default-enabled/library-visible/disabled state | `internal/keytypecatalog` | Library-visible providers require a product-store state record before generation. |
| Plaintext template library | install source | repo or signer-data `library/templates/*.yaml` | KeyType Library candidates | `internal/templatelibrary` | Not active by presence alone; new signer-role stores install the bundled Falcon allowlist v1 default; other entries require product-store import/enablement, and invalid entries are reported but not enabled. |
| YAML template spec | generation contract | template YAML `schema_version`, `template_mode`, `template_type` | parsed `BaseTemplateSpec` | `internal/tealtemplate`, `internal/templatelibrary` | Unknown/missing required fields reject import/install. |
| Template install result | wire/runtime projection | admin request response | install/rollback report | `internal/signerapp/templateadmin`, `internal/protocol` | Low-level template store owns encrypted bytes; admin path owns state record. |
| `/keytypes` metadata | wire projection | enabled providers/templates plus references | `signerapi.KeyTypesResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Creation params are future-generation metadata; contract fixtures cover shape. |
| Admin KeyType Library row | UI/wire projection | library source plus product-store state | `protocol.LibraryTemplateInfo` | `internal/adminproto`, `internal/signerapp/signertui` | `compiled_provider` is a wire/display projection, not a template store type. |

### Client Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client data root | authoritative root | `APCLIENT_DATA` | shell/bootstrap path context | `internal/clientdata`, `internal/bootstrap/shell` | Required for apshell; mutation lock protects shared local state. |
| Client config | authoritative config | `APCLIENT_DATA/config.yaml` | `config.Config` network/theme/polling state | `internal/config`, `internal/bootstrap/shell` | Does not own signer routing; top-level `ssh:` and `signer_port:` routing is rejected. |
| Endpoint registry | authoritative routing config | `APCLIENT_DATA/endpoints.yaml` | `config.ClientEndpointRegistry` | `internal/config`, `internal/apshellapp` | `schema_version:2`; role is `signer` or `cosigner`; at most one signer endpoint and at most 12 cosigner endpoints. |
| Endpoint alias | local identifier | map key under `endpoints` | endpoint lookup by alias | `internal/config`, `internal/apshellapp` | ASCII letters, digits, `.`, `_`, `-`; aliases are local, not exported. |
| Endpoint record | authoritative routing record | `endpoints.<alias>` | endpoint connection profile | `internal/config`, `internal/engine/connect` | `ssh://` URL; identity file and known hosts resolve relative to `APCLIENT_DATA`; retired `signer_port`, `local_port`, and `token_file` keys are dropped on load. |
| Live cosigner inventory | routing metadata | authenticated `/keys` responses | operation-scoped route snapshot | `internal/engine/guarded` | Keyed by embedded public key hex; never persisted and not ownership proof. |
| Client SSH identity | client secret | `.ssh/id_ed25519` (endpoint `identity_file`) or an agent key | SSH tunnel private key | `internal/sshtunnel`, `internal/engine/connect` | The client's only credential; enrolled per node through `request-enrollment` (operator approval later) or operator import. |
| Known hosts | trust store | `.ssh/known_hosts` or endpoint override | SSH host-key verification | `internal/sshtunnel`, `internal/clientenroll`, `cmd/apconsole` | Host trust is not imported through endpoint envelope. |
| Client mutation lock | local coordination | `.apclient.lock` | cache/config mutation serialization | `internal/clientdata` (lock ownership), used by `internal/clientstate` and `internal/config` | Prevents concurrent local writers from corrupting client state. |
| MCP config | client config | `.mcp.json`, `.codex/config.toml` | installed MCP command registration | installer, `cmd/apshell` | Installer preserves existing files and writes `.aplane-installer.new` templates when needed. |
| Plugin activation | authoritative client config | `plugins.yaml` | enabled plugin names | `internal/plugin`, installer | Empty activation list on fresh install; non-bundled choices preserved. |
| Plugin catalog entry | client executable catalog | `plugins.available/<name>` plus manifest/checksums | plugin manager candidate | `internal/plugin`, installer | Symlinked directories ignored; checksum/manifest validation gates execution. |
| JavaScript script | user-managed client artifact | `scripts/*.js` | Goja runtime input | `internal/scripting`, `internal/jsapi` | Script files are not signer authority. |
| Swap proposal | client-local workflow state | `swap/<network>/<proposal_id>.<address>.json` | swap workflow display/action state | `internal/clientstate`, shell swap code | Tombstones suppress locally deleted proposals. |

### Client Caches

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client cache key | cache secret | `cache/.cache_key` | HMAC key for cache envelopes | `internal/cache`, `internal/clientstate` | Local only; regenerated cache means rebuildable state. |
| Alias cache | cache/display | `cache/alias_cache.json` | alias to address/set references | `internal/cache`, `internal/clientstate`, `internal/refname` | Names canonicalized; cache is not signing authority. |
| Set cache | cache/display | `cache/set_cache.json` | named address sets | `internal/cache`, `internal/clientstate`, `internal/refname` | Reserved names rejected near persistence. |
| Signer inventory cache | cache/display | `cache/signer_cache.json` | local view of signer keys, key types, and structured LogicSig resources | `internal/cache`, `internal/engine` | Rebuilt from `/keys`/`/keytypes`; `Locked` is non-persisted runtime state. |
| ASA cache | cache/display | `cache/<network>_asa_cache.json` | ASA metadata lookup by network | `internal/cache`, `internal/asa`, `internal/engine` | Signed JSON; symbolic ambiguity rejects instead of guessing. |
| Auth-address cache | cache/display | `cache/<network>_auth_cache.json` | account auth-address lookups | `internal/cache`, `internal/clientstate` | Network-scoped; rebuilt from algod. |

### Network And Chain Identity

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Network context token | authoritative local namespace | config map key/string | selected client context and signer policy bucket | `internal/config`, `docs/ARCH_NETWORKS.md` | Filesystem-safe syntax; not cryptographic chain identity. |
| Built-in genesis mapping | source-defined authority | `internal/config/genesishash.go` | genesis hash resolver | `internal/config` | Built-in Algorand mappings cannot be remapped. |
| Custom genesis mapping | authoritative signer config | `server config networks.<token>.genesis_hash` | resolver entries | `internal/config`, `internal/serverconfig` | Duplicate or malformed hashes reject startup/config load. |
| Algod endpoint config | authoritative endpoint config | client/signer `networks.<token>.algod` | algod client construction | `internal/config`, `internal/serverconfig`, `internal/engine`, `internal/signerapp/daemon` | Missing client algod server rejects shell startup for active network. |
| ASA built-in registry | source-defined metadata | `internal/asa/registry` | seed data and symbolic fallback | `internal/asa` | Cache-backed current-network entries take precedence; ambiguity rejects. |

### Policy Model

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Policy document | authoritative policy domain | `default.json` or `policies/<selector>.json`, format `aplane.policy.v1` with `role` and `key` | one compiled `policy.Config` | `internal/policy`, `internal/signerapp/policyruntime` | Every verdict-bearing field is required; unknown fields and fields the role does not support are rejected; the schema at `pkg/policyschema/policy.v1.schema.json` is a `oneOf` by `role`. |
| Policy selection | runtime resolution | `policyruntime.NodePolicy` (`Default` plus `Keys`) | effective policy for one signing key | `internal/signerapp/policyruntime`, `internal/signerapp/signing` | `PolicyFor(selector)` returns the key's own document or the default; no inheritance or merge; one snapshot per request. |
| Signer policy semantics | authoritative policy domain | `role: signer` documents | signer approval verdicts | `internal/policy`, `internal/signerapp/signing` | Four-tier verdict model with operator default fallback; shipped default rejects a foreign rekey, reviews warnings, and otherwise falls through to the operator default. |
| Cosigner policy semantics | authoritative policy domain | `role: cosigner` documents | cosigner component-sign authorization | `internal/policy`, `internal/signerapp/signing` | Deterministic reject/sign only; no review or operator default; `allow` permitted only for `pay` and `axfer`; shipped default is deny-all. |
| Transaction type gate | authoritative policy section | `transaction_types` map (`*` required) | per-type `allow`, `review`, or `reject` | `internal/policy` | Evaluated first; `reject` is Always Deny and `review` is Always Review with rule ID `transaction_type:<type>`. |
| Transfer policy | authoritative policy section | `transfer_policy` object | route table and movement authorization | `internal/policy` | Schema-checked by the v1 format; route IDs are audit identifiers. |
| Transfer route | authoritative policy row | `transfer_policy.routes[]` | route match and rule ID source | `internal/policy` | Dynamic rule IDs use `transfer_policy:<route_id>:<outcome>`. |
| Policy verdict | runtime decision | effective policy plus decoded txn facts | approve/review/reject outcome | `internal/policy`, `internal/signerapp/signing` | Cosigner documents cannot express a review verdict; the decoder rejects one. |

### Authorization And Authentication

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Authorization action | source-defined authority | `internal/auth/authorizer.go` constants | authorizer known-action vocabulary | `internal/auth`, `internal/authz` | Unknown actions fail closed before grant matching. |
| Authorization resource | request-scoped model | `auth.Resource` | target type/id/identity | `internal/auth`, HTTP/admin adapters | Empty identity is resolved at boundary or rejected. |
| Product action allowlist | source-defined authority | `internal/authz` explicit product action set | in-memory authorization decision | `internal/authz` | Known actions are not granted automatically; non-default resource identities fail closed. |
| Authenticated HTTP principal | runtime-only | connection identity (`auth.ConnIdentity`) resolved against the enrolled registry | `auth.Identity` | `internal/auth`, `internal/signerapp/daemon/product_authenticator.go`, `internal/signerapp/daemon/http_auth.go` | The connection's enrolled key authenticates `client:<fingerprint>` with role `client`; runtime binding is independently fixed to `default`. |
| Admin session context | runtime-only | admin transport auth result | `adminserver.SessionContext` | `internal/signerapp/adminserver`, `internal/adminproto`, `internal/protocol` | Bound to target identity; approvals carry approver principal. |
| Client enrollment request | persisted queue entry | SSH key-only request | `identities/default/.ssh/pending_enrollments.json` (`internal/signerapp/enrollqueue`), announced as admin `client_enrollment_request` | `internal/sshtunnel`, `internal/signerapp/enrollment`, `internal/signerapp/enrollqueue` | Daemon-written, one entry per key, capped at 16, lapses after 7 days; the SSH acknowledgement is `pending <fingerprint>` and the registry is written only on admin approval. |

### HTTP Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| HTTP error response | wire contract | `signerapi.ErrorResponse` | non-2xx JSON error | `pkg/signerapi`, `internal/signerapp/daemon`, `internal/signerapp/svcerr` | Contracted in `ARCH_HTTP_API.md`. |
| Health response | wire projection | process liveness | `signerapi.HealthResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Unauthenticated `GET /health`; not product-store state. |
| Status response | wire projection | authenticated product runtime state | `signerapi.StatusResponse` | `internal/signerapp/daemon`, `internal/signerapp/rest`, `pkg/signerapi` | `keyset_revision` is process-local, not durable. |
| Keys response | wire projection | loaded key snapshot | `signerapi.KeysResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Cosigner-key rows use Witness Key ID as `address`; guarded rows expose non-secret params. |
| Key info row | wire projection | loaded key metadata | `signerapi.KeyInfo` | `internal/signerapp/rest` | `is_witness_key`/`is_spending_account` disambiguate selectors from accounts; may carry `signing_flow`, `cosigner_component_key_type`, and `bounded_authorization`. |
| Key types response | wire projection | enabled providers/templates and cosigner refs | `signerapi.KeyTypesResponse` | `internal/signerapp/rest` | Runtime args are generation metadata, not existing-key signing args; may carry `signing_flow`. |
| Group sign request | wire request | client transaction bytes | `signerapi.GroupSignRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Shared by `/sign` and `/plan`; all-foreign invalid. |
| Bounded admin request/partial | wire request/projection | planned admin-key rekey group plus durable metadata | `signerapi.BoundedAdminRequest`, `BoundedAdminPartialResponse` | `pkg/signerapi`, `internal/signerapp/signing` | `POST /sign/bounded-admin`; not interchangeable with `GroupSignResponse`; external admin completion is out of band. |
| Sign request entry | wire request row | caller-supplied txn/signed bytes | sign/passthrough/foreign entry | `pkg/signerapi`, signer planner | `txn_sender` is advisory display data only. |
| Group plan response | wire projection | canonical planned group | `signerapi.GroupPlanResponse` | `internal/signerapp/signing` | No key access; returns unsigned TX-prefixed transaction bytes. |
| Group sign response | wire projection | finalized signed group | `signerapi.GroupSignResponse` | `internal/signerapp/signing` | Signed array aligns to finalized group positions. |
| Mutation report | wire projection | canonicalization effects | `signerapi.MutationReport` | `internal/signerapp/signing` | Observability only, not durable authority. |
| Cancel sign request/response | wire request/projection | live request registry lookup | `signerapi.CancelSign*` | `internal/signerapp/approval` | `/sign` and approval-bearing user/bounded-base component request IDs are live cancel handles; cosigner-component and assembly IDs are correlation only. |
| Admin generate DTOs | wire request/projection | enabled key type plus parameters | `signerapi.AdminGenerate*` | `internal/signerapp/keyadmin` | No mnemonic in REST response. |
| Admin delete DTO | wire request/projection | address query parameter | delete response or error | `internal/signerapp/daemon`, `internal/signerapp/keyadmin`, `pkg/signerapi` | Missing address 400; missing key 404. |
| Component request | wire request | canonical group bytes and discriminated target records | `signerapi.ComponentRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Target kind is `user`, `cosigner`, or `bounded-base`; every original group position is a target or contextual position, and omitted request IDs are generated. |
| Component response | wire projection | kind-tagged per-target authorization material | `signerapi.ComponentResponse` | `internal/signerapp/signing` | Guarded components carry one signature; bounded-base components carry base signatures, validated runtime args, and an assembly receipt. |
| Assembly request | wire request | group bytes plus discriminated guarded or bounded-cosigner targets | `signerapi.AssemblyRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Guarded targets carry user/cosigner signatures; bounded targets also carry base authorization and a receipt. Mixed guarded/bounded groups remain rejected. |
| Assembly response | wire projection | assembled signed group bytes | `signerapi.AssemblyResponse` | `internal/signerapp/signing` | Assembly revalidates each target against signer-owned metadata and does not trust endpoint-advertised public keys. |

### Admin IPC Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Admin envelope | wire contract | line-delimited JSON `kind`, `type`, `id` | request/response/notification routing | `internal/protocol`, `internal/transport`, `internal/signerapp/adminserver` | Missing/unsupported messages yield protocol error. |
| Passphrase messages | secret wire fields | JSON string decoded as `protocol.SensitiveBytes` | auth/unlock/changepass/store messages | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Handlers clone/zero mutable buffers where possible. |
| Admin key list entry | wire projection | admin service key metadata | `protocol.AdminKeyInfo` projected from `adminproto.KeyInfo` | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Deliberately distinct from the richer HTTP `signerapi.KeyInfo`; extend both admin types together for TUI-visible fields. |
| Key management messages | wire contract | `generate_key`, `delete_key`, `import_key`, details/list | admin key operations | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Import mnemonic is accepted only over local IPC; generate responses omit mnemonic; export message types decode to an explicit denial. |
| Template management messages | wire contract | library/install/show/import/remove/activate/deactivate messages | template/key type lifecycle | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/signertui` | Authenticated IPC admin sessions can show/import/remove installed template source; user-facing CLI/TUI verbs are enable/disable. |
| Sign approval prompt | runtime wire model | signer approval coordinator request | admin `sign_request` | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/approval` | Approval prompts carry descriptions; response attaches approver principal. |
| Client enrollment prompt | runtime wire model | queued SSH enrollment request | admin `client_enrollment_request` notification, pending list, approve/reject/import messages, enrolled-key list, and revocation messages | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/enrollment` | Admin approval (or import) enrolls the key whenever the operator acts; revocation closes the key's connections. |
| Backup/restore messages | wire contract | backup create/list/delete, bounded import/export, preview, direct restore, rollback, and reconcile DTOs | backup admin service calls | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/backupadmin` | Import authenticates the sealed manifest and validates every credential before publication; restore validates the complete set before publishing one generation; export passphrases are parsed as `SensitiveBytes`. |
| Admin settings messages | wire contract | settings get/update messages | process/product runtime config mutation | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/admin` | Update paths authorize and apply config-staleness guards. |
| Policy get/check/apply messages | wire/runtime projection | active policy documents (default plus per-key) or candidate documents and removals | `apadmin policy` online store | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/admin`, `internal/signerapp/policyapply` | Exact document bytes; each document names its key (`default` or a selector); `get_policy_document` takes a key; key status is `own`, `default`, or `key_not_held`; `remove` refuses `default`; `apply_policy` requires `expected_policy_set_sha256` and mints one generation per change. |

### Transaction And Signing Runtime Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Prepared client group | request-scoped model | shell/script/plugin/app input | `engine.PreparedGroup` and related request plans | `internal/engine`, `internal/apshellapp` | Not authorization proof; submitted to signer for canonicalization. |
| App call metadata | request-scoped display metadata | caller/appspec input | `app_call_info` | `internal/engine`, `internal/signerapp/txdesc` | Approval rendering only; not signing authority. |
| Canonical signer group | request-scoped authority for signing | decoded request transaction bytes | planned group, dummies, fees, group ID | `internal/signerapp/signing` | Genesis hash consistency, group size, dummy budget, policy validation. |
| Sign request live entry | runtime-only | active synchronous request | approval registry entry by request ID | `internal/signerapp/approval` | Not durable; cancelable only while live. |
| Approval description | display projection | decoded transaction/group facts | admin prompt text and audit context | `internal/signerapp/txdesc` | Presentation-only; must not introduce signing inputs. |
| Cosigner component message | request-scoped signing input | role byte plus target TxID | 32-byte message digest | `internal/cosigner/message` | Shared by signer assembly and TEAL vectors; clients treat component signatures as opaque. |
| Component signature set | request-scoped wire data | `/sign/component` response | per-target signatures by target index | `internal/signerapp/signing`, `pkg/signerapi` | Each signature is bound to one target TxID and role. |
| Guarded assembly target | request-scoped wire data | `/sign/assemble` request targets | LogicSig args packing plan | `internal/signerapp/signing` | User and cosigner signatures are verified before packed bytes are returned. |
| Guarded send orchestration | long-lived client workflow | signer inventory plus endpoint registry plus requests | user component call (signer-domain gated), cosigner call, optional non-guarded `/sign`, assembly, then client algod submit or simulate | `internal/engine`, `internal/apshellapp` | Client holds no key material but does hold the final executable group; endpoint routing is not trust; guarded targets are classified by effective signer and may be direct senders or AuthAddr authorizers; mixed groups sign non-guarded originals over the same canonical bytes. |
| Bounded admin ceremony orchestration | long-lived offline/online workflow | `/sign/bounded-admin` partial plus external `.wit` custody | request/signature files and final submit | `cmd/aprekey`, `internal/apboundedadminapp`, `internal/boundedadmin`, `internal/engine` | Online rekey/unrekey or prepare/sign/complete; signer never holds contract-admin private material. |

### Plugin, JavaScript, And MCP Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Plugin manifest | authoritative plugin metadata | `plugins.available/<name>/manifest.json` | plugin registry entry | `internal/plugin` | Manifest format is separate from JSON-RPC protocol version. |
| Plugin checksum | integrity metadata | `checksums.sha256` and package files | validation result | `internal/plugin`, `cmd/applugin-checksum` | Invalid checksum prevents plugin execution. |
| Plugin execution context | wire/runtime projection | shell/engine state | JSON-RPC context payload | `internal/plugin`, `internal/apshellcli` | Structured `assets` list is canonical; no lossy `assetMap`. |
| JavaScript runtime state | runtime-only | loaded script plus engine state | Goja runner | `internal/scripting`, `internal/jsapi` | Per-run runtime state; saved scripts are durable user state. |
| MCP structured result | wire projection | shell app result objects | MCP tool result payload | `internal/apshellcli`, `internal/appresult` | Projection of shell runtime, not a separate backend model. |

### Backup And Restore Payloads

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Backup archive | authoritative packaged backup | `backups/default/*.tar.gz` | archive metadata and restore source | `internal/backup` | Tarball is packaging; `.apb` is cryptographic unit. |
| `.apb` file | encrypted backup payload | standalone encryption envelope | complete canonical managed credential | `internal/backup` | Envelope and payload versions checked; internal bundle wrappers and unsupported versions reject. |
| Restore preview | request-scoped runtime model | archive plus export passphrase | credential identities, destination presence, and errors | `internal/backup`, `internal/signerapp/backupadmin` | No mutation during preview. |
| Direct restore set | request-scoped secret model | authenticated archive credentials in memory | one staged generation transaction | `internal/backup`, `internal/signerapp/backupadmin` | Complete validation precedes any write; secrets are zeroed after use. |

### Envelopes And Public Handoff Files

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Endpoint export envelope | public handoff | JSON `schema:"aplane.endpoint.v1"` | `apshell endpoints import` input | `internal/apadminapp`, `internal/config`, `internal/apshellapp` | No alias, role, credential, known hosts, private key, or cosigner inventory; URL comes from `--url`, `--host`, or signer `endpoint.advertise_url`. |
| Witness public reference | public handoff | JSON `schema:"aplane.witness-key-public.v1"` | cosigner key export; signer cosigner reference import or contract-admin enrollment | `internal/witness`, `internal/apadminapp`, `internal/signerapp/signertui`, `internal/cosigner/cosignerrefs` | Contains `key_type`, `witness_key_id`, and full `public_key_hex`; no custody, role, endpoint, or trust claim. The cosigner's address is handed to clients separately for `endpoints add`. |
| Public cosigner reference record | public signer catalog | JSON `schema:"aplane.cosigner-public-key-ref.v2"` | generation select option | `internal/cosigner/cosignerrefs` | Stored under `cosigners/`; populated by explicit operator import. A v1 read adapter preserves closed migration provenance. |
| Bounded admin ceremony request | short-lived handoff | `*.apbounded-admin-request` schema `aplane.bounded-admin-request.v2` | offline `aprekey sign` input | `internal/boundedadmin/protocol`, `internal/apboundedadminapp`, `cmd/aprekey` | Strict JSON; size-bounded; request-hash binds partial, optional cosigner authorization, and network context; mode `0600`, no overwrite. |
| Bounded admin ceremony signature | short-lived handoff | `*.apbounded-admin-signature` schema `aplane.bounded-admin-signature.v1` | networked `aprekey complete` input | `internal/boundedadmin/protocol`, `internal/apboundedadminapp`, `cmd/aprekey` | Binds `request_hash_hex`, contract admin key ID, and signature; mode `0600`, no overwrite. |

### Installer And Release Metadata

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Release metadata | public provenance | release archive `release.json`, copied to `<install-root>/install/release.json` or systemd `<APSIGNER_DATA>/install/release.json` when present | version, commit, and build timestamp for diagnostics and future upgrade checks | `.github/workflows/release.yml`, `Makefile release-local`, `scripts/package-bootstrap-release.sh`, `install.sh` | Schema `schema_version:1`; public metadata only, not signing, policy, endpoint trust, or upgrade authority by itself. |
| Signer service principal metadata | root-controlled install state | systemd `<APSIGNER_DATA>/install/service-principal.json` | numeric service uid/gid used by permission audit, migration, and post-root-mutation normalization | `installer/scripts/systemd-setup.sh`, `internal/storeperm` | Schema `schema_version:1`; refreshed before migration and required fail-closed so a damaged store root cannot nominate its own repair owner. |

### Audit And Observability

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Audit event | authoritative audit record | JSONL line in `audit.log` | operational/accountability history | `internal/signerapp/audit` | Event fields are not signing inputs. |
| Cosigner component audit projection | audit projection | component-signing outcome | `SIGN_APPROVED`/`SIGN_REJECTED` rows | `internal/signerapp/signing`, `internal/signerapp/audit` | Uses sign events; Witness Key ID is `txn_auth`, decoded sender is `txn_sender`. |
| Policy rule ID | stable identifier | policy constants and dynamic route grammar | audit/prompt/error context | `internal/policy` | Typos should be caught by tests; route IDs are persistent audit identifiers. |
| Request ID | runtime correlation ID | optional request field or generated server ID | audit/cancel/prompt correlation | `pkg/signerapi`, `internal/signerapp/approval` | Syntax-limited; only live `/sign` IDs are cancelable in MVP. |
| Keyset revision | runtime freshness marker | in-memory identity key snapshot counter | `/status` and client refresh logic | `internal/signerapp/productruntime`, `internal/engine` | Process-local; must not be compared across restarts. |

### Representative Test And Fixture Index

Use this index when a catalog entry points at an owning subsystem but does not
name a test inline:

- HTTP DTO and contract fixtures: `pkg/signerapi/types_contract_test.go`,
  `pkg/signerapi/cosigner_test.go`, `test/contracts/signerapi/*.json`.
- HTTP method/shape enforcement: `internal/signerapp/daemon/method_compat_test.go`,
  `internal/signerapp/daemon/rest_shape_test.go`, `internal/signerclient/client_test.go`.
- Endpoint registry and endpoint writes:
  `internal/config/client_endpoints.go`,
  `internal/config/client_endpoint_writes_test.go`,
  `internal/apshellapp/endpoints_test.go`.
- Guarded send orchestration: `internal/engine/guarded/submit_test.go`,
  `internal/engine/connect/client_test.go`.
- Cosigner component signing and assembly:
  `internal/signerapp/signing/component_test.go`,
  `internal/signerapp/rest/service_test.go`.
- Cosigner references and public metadata:
  `internal/cosigner/cosignerrefs`, `internal/apadminapp/catalog.go`,
  related package tests.
- Node role and key-class gates: signer startup, `internal/signerapp/productruntime`,
  `internal/signerapp/rest/service_test.go`,
  `internal/signerapp/signing/cosigner_gate.go`.
- Policy domains and integrity: `internal/policy/*_test.go`,
  `internal/signerapp/policycmd/policycmd_test.go`, `cmd/apadmin/policy_test.go`,
  `internal/signerapp/admin/policy_test.go`, `test/contracts/policy/v1/`
  (`valid` top-level fixtures, `invalid/`, `semantic_invalid/`),
  `test/integration/policy_per_key_test.go`.
- Key payload parsing, scan, backup, and restore: `internal/keys`,
  `internal/backup/service_test.go`, `cmd/apstore/policy_test.go`.
- Bounded metadata, ceremony, and external witness artifacts:
  `internal/boundedmeta`, `internal/boundedadmin`, `internal/witness/artifact`,
  `internal/apboundedadminapp`, `test/contracts/signerapi/bounded_*`.
- Authorization vocabulary and bootstrap grants:
  `internal/auth/authorizer.go`, `internal/authz/authorizer_test.go`.
- Integration coverage for signer/client flows: `test/integration`.

## Source Of Truth Index

| Model area | Source |
|------------|--------|
| Architecture ownership | [ARCH_SPEC.md](ARCH_SPEC.md) |
| Wire/file contracts | [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md) |
| HTTP DTOs | `pkg/signerapi/types.go`, [ARCH_HTTP_API.md](ARCH_HTTP_API.md) |
| Admin protocol DTOs | `internal/protocol/messages.go`, [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md) |
| Authorization actions/resources | `internal/auth`, `internal/authz`, [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md) |
| Policy config and verdicts | `internal/policy`, [ARCH_POLICY.md](ARCH_POLICY.md) |
| Network tokens and genesis hashes | `internal/config/networkid.go`, `internal/config/genesishash.go`, [ARCH_NETWORKS.md](ARCH_NETWORKS.md) |
| Client/server config | `internal/config/config.go`, `internal/serverconfig/serverconfig.go` |
| Client endpoint registry | `internal/config/client_endpoints.go`, `internal/config/client_endpoint_writes.go` |
| Product runtime/config | `internal/signerapp/productruntime` |
| Keystore and key files | `internal/crypto`, `internal/keystore`, `internal/keys`, [ARCH_STORE.md](ARCH_STORE.md) |
| Signing-arg schema model | `internal/signingargs` |
| Node role / key class gates | `internal/noderole`, `internal/keyclass` |
| Cosigner key types/messages/references | `internal/cosigner`, `pkg/signerapi/cosigner.go`, [ARCH_COSIGNER.md](ARCH_COSIGNER.md) |
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
