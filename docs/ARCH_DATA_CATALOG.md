# Data Model Catalog

> Complete catalog of APlane data model elements that have durable authority,
> wire compatibility, cache/display identity, or long-lived runtime identity.

This catalog complements [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md). The data
model document explains the conceptual model; this catalog inventories the
actual elements that cross package, process, request, goroutine, or persistence
boundaries. Key file and key type state transitions are documented in
[ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).

## Scope

This catalog intentionally excludes ordinary local variables and helper structs
whose lifetime is contained inside one function. It includes objects that have
identity beyond one function call:

- files and directories under `APSIGNER_DATA` or `APCLIENT_DATA`,
- key payloads, config files, policy files, caches, tokens, and envelopes,
- long-lived runtime managers, registries, sessions, snapshots, and indexes,
- request-scoped objects that cross package, process, approval, or goroutine
  boundaries,
- HTTP, admin IPC, SSH, plugin, MCP, and SDK DTOs,
- audit and backup records.

If a future change introduces a new durable file, cache payload, request DTO,
admin message, long-lived runtime object, or cross-boundary request model, add
it here in the same slice as the behavior change.

## Reading Rules

Columns used below:

- **Kind:** authoritative, derived, cache, display/provenance, or runtime-only.
- **Authority:** the durable file, wire DTO, or source-defined record that
  controls behavior.
- **Projection:** runtime or wire shape derived from the authority.
- **Owner:** package or subsystem that owns mutation and validation.
- **Checks:** validation, failure behavior, and representative tests or
  fixtures.

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

## Signer Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Signer data root | authoritative root | `APSIGNER_DATA` | `storepaths.Paths` and startup path resolution | `internal/serverconfig`, `internal/bootstrap/signer`, `internal/storepaths`, installers | Required for signer startup; systemd-managed roots reject manual startup unless explicitly allowed. |
| Process config | authoritative config | `APSIGNER_DATA/config.yaml` | `serverconfig.ServerConfig` snapshot | `internal/serverconfig`, `internal/bootstrap/signer`, `internal/signerapp/admin` | Unknown fields reject; mutable writes use process config lock; tests in `internal/serverconfig` and admin settings tests. |
| Network config | authoritative config section | `config.yaml` `networks.<token>` and `teal_compile_network` | algod map and genesis resolver | `internal/serverconfig`, `internal/signerapp/daemon` | Token syntax and genesis hash collisions fail closed; see `docs/ARCH_NETWORKS.md`. |
| SSH host key | secret server credential | `.ssh/ssh_host_key` | `sshtunnel.Server` host key | `internal/sshtunnel`, startup/install | Generated locally; clients pin through known-hosts flow. |
| IPC socket path | runtime endpoint | default `<data_dir>/aplane.sock` or absolute `ipc_path` | local admin transport listener | `internal/signerapp/daemon`, `internal/signerapp/ipcbind`, `internal/adminproto`, `internal/transport` | IPC path can live outside data root; local admin protocol requires passphrase auth. |
| Store mutation lock | runtime/durable coordination | `.apstore.lock` | cooperative store lock | `internal/storelock`, `internal/signerapp/storemut` | Serializes live signer and local `apstore` mutations. |
| Audit log | authoritative audit trail | `audit.log` JSONL | append-only audit logger | `internal/signerapp/audit`, `internal/signerapp/daemon` | Mode `0600`, rotated by size; not authority for signing or recovery. |
| Signer ASA cache key | cache secret | `cache/.cache_key` | HMAC verifier for signer ASA cache | `internal/cache`, `internal/signerapp/asametadata` | Tampered cache files reject and rebuild from seed where applicable. |
| Signer ASA cache | cache/display | `cache/<network>_asa_cache.json` | per-operation ASA metadata lookup | `internal/signerapp/asametadata`, `internal/asa` | Signed cache; built-in registry seeds; not authority for policy enforcement. |
| Managed backup locker | authoritative backup inventory | `backups/<identity>/*.tar.gz` | backup list/restore preview/recovery input | `internal/backup`, `internal/signerapp/backupadmin` | Imported archives are validated before publication; archive payloads are encrypted `.apb`. |
| Sealed archive manifest | authenticated archive description | `manifest.sealed` inside managed archives | member inventory, source node role, and source context | `internal/backup` | Schema `aplane.backup.manifest.v2` sealed under the export passphrase with the standalone envelope; every open path verifies each member against the inventory; a missing, added, or altered member rejects the archive. |
| Deleted archive root | inactive durable storage | `identities/<identity>/deleted/` | outside active key/template scans | `internal/keys`, `internal/templatestore` | Deleted keys/templates are not active authority. |
| Recovered batch root | inactive encrypted recovery state | `identities/<identity>/recovered/<restore-id>/` | no signing-runtime projection before activation | `internal/backup/recovered`, `internal/signerapp/backupadmin`, `internal/storepass` | Batch and entries are authenticated encryption under the destination term key, bound to the `recovered-batch` and `recovered-entry` object classes so an entry cannot be moved between batches; activation consumes the batch by minting a new generation; passphrase rotation mints a fresh term key and re-encrypts published state; `.recovering-*` directories are unpublished staging state. |

## Signer Identity Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Node role | authoritative root config | `<APSIGNER_DATA>/node.yaml` plus `identities/<identity>/node.yaml.hmac` | key-class and service-dispatch gates | `internal/noderole`, `internal/keyclass`, signer startup, identity load, keyadmin, restore, signing dispatch | Values: `signer`, `sentry`; no `dual`; no supported role changes; active role conflicts fail the whole node closed. |
| Signing identity directory | authoritative root | `identities/<identity>/` | `identity.Runtime` | `internal/signerapp/identity` | Product mode exposes `default`; internals are identity-scoped. |
| Identity config | authoritative config | `identities/<identity>/config.yaml` (parsed as `identity.StoredConfig`) | `identity.EffectiveConfig` (resolved) | `internal/signerapp/identity`, `internal/signerapp/admin` | Unknown or invalid settings fail closed. Node role belongs only in root `node.yaml`. |
| Unlock config | authoritative config | `identities/<identity>/unlock.yaml` | passphrase helper command config | `internal/signerapp/unlockconfig` (identity re-exports helpers), `cmd/appass` | Helper artifacts are identity-scoped and independent of node role. |
| Passphrase helper files | secret helper state | `passphrase`, `passphrase.cred` | startup/headless passphrase source | `cmd/appass`, `cmd/appass-file`, `cmd/appass-systemd-creds` | Mode `0600`; systemd/local ownership rules enforced by appass. |
| Keyring root | authoritative cryptographic root | `identities/<identity>/keyring.enc` | passphrase verification and the identity's term keys | `internal/crypto`, `internal/keystore` | Schema `aplane.keyring.v1`; plaintext Argon2id parameters and salt over an AEAD-sealed term set; the unwrap is the passphrase check; a passphrase change replaces it in one atomic write. |
| Keystore marker | store format gate | `identities/<identity>/.keystore` | none | `internal/crypto` | Static `{version: 4, layout: "keyring/v1", created}`; carries no salt, verifier, or KDF parameters, so it cannot disagree with the keyring; any other version fails closed. |
| Term key session | runtime-only secret | unsealed from `keyring.enc`, resident only while unlocked | `keystore.KeySession`, `FileKeyStore` | `internal/keystore`, `internal/signerapp/runtime` | Zeroed on lock; not exposed on wire. |
| API token | bearer secret | `identities/<identity>/aplane.token` | HTTP authenticator and SSH mutual-proof key | `internal/tokenfile`, `internal/auth`, `internal/sshtunnel` | Mode `0600`; never sent as SSH metadata; token revocation rotates identity credential and closes stale SSH sessions. |
| SSH authorized keys | authoritative enrollment | `identities/<identity>/.ssh/authorized_keys` | SSH identity key set | `internal/sshtunnel`, `internal/signerapp/sshprovision` | Token plus SSH key required; token provisioning writes after admin approval. |
| Client-signing policy domain | authoritative safety policy | role-selected `policy.yaml` plus `policy.yaml.hmac` on signer nodes | client-signing `policy.Config` runtime snapshot | `internal/policy`, `internal/signerapp/policyruntime` | HMAC over exact YAML; missing/mismatched sidecar fails closed. |
| Sentry component policy domain | authoritative co-sign policy | role-selected `policy.yaml` plus `policy.yaml.hmac` on sentry nodes | sentry policy runtime snapshot | `internal/policy`, `internal/signerapp/policyruntime`, `internal/signerapp/signing` | Same durable file contract as signer policy; no review/operator-default outcomes; missing/mismatched sidecar fails closed. |
| Policy sidecar | authoritative integrity metadata | `policy.yaml.hmac` JSON | HMAC verification result | `internal/policy`, `cmd/appolicy`, `cmd/apstore` | Security fields are `version`, `algorithm`, `key_id`, `hmac`; diagnostics are not trust inputs. |
| Key type state record | authoritative generation state | `keytypes/<key_type>.json` | enabled/disabled identity key type state | `internal/keytypestate`, `internal/signerapp/templateadmin` | Plaintext, not key material; affects discovery/generation, not existing-key signing. |
| Installed template | authoritative generation source | encrypted `keytypes/<key_type>.template` | registered template provider after unlock/reload | `internal/templatestore`, `internal/signerapp/templates` | Sealed under the identity's current term key and bound to its key type; disabled state skips registration. |
| Recovered credential batch | inactive recovery authority | encrypted `recovered/<restore-id>/batch.enc` and `entries/*.recovered` | none until a later explicit activation operation | `internal/backup/recovered` | Restore ID is random 128-bit lowercase hex; selector/category/key type derive from canonical payload; entry digest and embedded restore ID bind each entry to its batch; published plaintext is immutable so rotation preserves additive/unknown fields; runtime scans ignore this directory. |
| Public sentry reference | public generation catalog | `sentries/<name>.json` | `/keytypes` `sentry` select options | `internal/sentry/sentryrefs`, `internal/signerapp/rest`, `cmd/apstore` | Public metadata only; source is `manual` or `client_discovery`; not endpoint ownership proof. |

## Key Material And Key Metadata

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Managed credential envelope | authoritative secret storage | `keys/*.key` or `keys/*.sen` encrypted JSON | decrypted canonical payload | `internal/keys`, `internal/keystore` | Category selects the sole filename class; envelope and payload versions checked before use; the term envelope's AAD binds the account address or Witness Key ID, so a credential filed under another name does not decrypt. |
| Native Ed25519 key | signing authority | `.key` category `ed25519` | address to private key material | `internal/signing`, `internal/keygen`, `internal/keys` | Address derives from key material; private key never leaves signer boundary. |
| DSA LogicSig key | signing authority | `.key` category `dsa_lsig` | address, bytecode, private signing key, signing args | `internal/keys`, `internal/signerapp/signing`, `lsig/*` | Stored bytecode and `signing_args` are sign-time authority. |
| Generic LogicSig key | signing authority | `.key` category `generic_lsig` | address, bytecode, runtime arg schema | `internal/keys`, `lsig/generictemplate` | TEAL-only key stores no private signing key; address derives from bytecode. |
| Guarded account key | signing/assembly authority | `.key` category `dsa_lsig`, key type `aplane.falcon1024-sentry1024.v1` | local user-role key plus embedded sentry public key | `lsig/falcon1024_guarded`, `internal/signerapp/signing` | `/sign` rejects; inventory uses `signing_flow: sentry1`; user-role `/sign/component` and `/sign/assemble` use stored bytecode/params. |
| Bounded-sentry account key | signing/assembly authority | `.key` category `dsa_lsig`, bounded metadata with `sentry` (for example `aplane.corridor.v1`) | local base key, bytecode, bounded metadata, embedded sentry public key | `lsig/composeddsa`, `internal/boundedmeta`, `internal/signerapp/signing` | `/sign` rejects sentry-gated spend; inventory uses `signing_flow: bounded-sentry1`; bounded component and assembly endpoints consume stored metadata. |
| Bounded account key metadata | signing authority metadata | key payload `bounded_authorization` at `signing_metadata_version: 2` | inventory `bounded_authorization` / path sizing | `internal/boundedmeta`, `lsig/composeddsa`, `internal/keys`, `internal/signerapp/signing` | Required for bounded1 DSA keys; ordinary `/sign` rejects admin-key operations that need `/sign/bounded-admin`. |
| Sentry witness key | component-sign authority | `.sen` category `witness`, key type `aplane.witness-*` | raw sentry-role witness key | `internal/keygen`, `internal/signing`, `internal/signerapp/signing` | Selected by Witness Key ID; `/sign` rejects; sentry-role `/sign/component` only; not a spending account. |
| External contract-admin witness bundle | secret standalone custody | `<WITNESS_KEY_ID>.wit` schema `aplane.witness-key-bundle.v1` | `aprekey` generate/inspect/verify/sign | `internal/witness/artifact`, `cmd/aprekey` | Never a signer-managed `.key`/`.sen`; signer/`apstore` must not import, decrypt, back up, or restore private material. |
| Witness Key ID | public selector | 52-character uppercase base32 SHA-512/256 of canonical length-prefixed domain, key type, and public key bytes | sentry key row `address`, public reference `witness_key_id`, and role-specific `component_key` fields | `internal/witness` | Txid-shaped but not a valid Algorand address; rejected where an Algorand address is required. |
| Sentry public metadata sidecar | public metadata | `keys/<witness_key_id>.wit.json` | `apstore sentry export` source | `internal/keys`, `internal/sentry/sentryrefs` | Witness Key ID/key type/public key consistency verified; no private material. |
| Key creation parameters | provenance/generation input | key payload `parameters` | `/keys` `parameters`, key details | `internal/keys`, `internal/keymgmt` | Canonical payload parser rejects duplicate object members, unknown fields, and noncanonical aliases. |
| LogicSig bytecode | signing authority | key payload `lsig_bytecode` | LogicSig address and signing assembly | `internal/keys`, `internal/signerapp/signing` | Bytecode must derive an off-curve address. |
| Signing args | signing authority | key payload `signing_args` | `internal/signingargs.Info`, `/keys` `signing_args` | `internal/signingargs`, `internal/keys` | Per-key snapshot; distinct from `/keytypes` runtime args. |
| Signing flow label | wire/runtime routing projection | inventory `signing_flow` on `/keys` and `/keytypes` | client route selection (`sentry1`, `bounded1`, `bounded-sentry1`, or empty) | `pkg/signerapi`, `internal/signerapp/rest`, clients | Frozen labels; unknown flows fail closed; empty means ordinary `/sign`. |
| Salt counter | signing authority metadata | key payload `salt_counter` | stored bytecode derivation record | `internal/lsigsalt`, `internal/keys` | Required for LogicSig keys; missing rejects scan/restore/signing. |
| Base key type | signing authority metadata | key payload `base_key_type` | base provider lookup for DSA keys | `internal/keys`, `internal/signerapp/signing` | Required for composed/DSA signing that needs base provider ops. |
| Template fingerprint | provenance | key payload `template_fingerprint` | inventory provenance status/note | `internal/lsigprovider`, `internal/keys` | Behavior-only and versioned (`<n>:` prefix); identifier-independent (base key types projected to stable `base_primitive` tokens); provenance only, conflicts do not block signing; cross-version or malformed comparisons are "not comparable" (benign, not a conflict). |
| Offline key inventory | local decrypted projection | encrypted key files plus passphrase | `apstore keys list` output | `cmd/apstore`, `internal/keys` | Does not print private key, mnemonic, or raw sentry public key by default. |

## Key Type And Template Catalog

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Compiled provider registry | process authority | Go registrations in `lsig/all.go` and provider packages | provider lookup by `key_type` | `internal/lsigprovider`, `internal/keygen`, `internal/signing` | Canonical `key_type` strings are identifiers; display labels are not. |
| Key type visibility catalog | process metadata | `internal/keytypecatalog` registrations | default-enabled/library-visible/disabled state | `internal/keytypecatalog` | Library-visible providers require identity state record before generation. |
| Plaintext template library | install source | repo or signer-data `library/templates/*.yaml` | KeyType Library candidates | `internal/templatelibrary` | Not active by presence alone; new signer identities install the bundled Falcon allowlist v1 default; other entries require identity-local import/enablement, and invalid entries are reported but not enabled. |
| YAML template spec | generation contract | template YAML `schema_version`, `template_mode`, `template_type` | parsed `BaseTemplateSpec` | `internal/tealtemplate`, `internal/templatelibrary` | Unknown/missing required fields reject import/install. |
| Template install result | wire/runtime projection | admin request response | install/rollback report | `internal/signerapp/templateadmin`, `internal/protocol` | Low-level template store owns encrypted bytes; admin path owns state record. |
| `/keytypes` metadata | wire projection | enabled providers/templates plus references | `signerapi.KeyTypesResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Creation params are future-generation metadata; contract fixtures cover shape. |
| Admin KeyType Library row | UI/wire projection | library source plus identity state | `protocol.LibraryTemplateInfo` | `internal/adminproto`, `internal/signerapp/signertui` | `compiled_provider` is a wire/display projection, not a template store type. |

## Client Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client data root | authoritative root | `APCLIENT_DATA` | shell/bootstrap path context | `internal/clientdata`, `internal/bootstrap/shell` | Required for apshell; mutation lock protects shared local state. |
| Client config | authoritative config | `APCLIENT_DATA/config.yaml` | `config.Config` network/theme/polling state | `internal/config`, `internal/bootstrap/shell` | Does not own signer routing; top-level `ssh:` and `signer_port:` routing is rejected. |
| Endpoint registry | authoritative routing config | `APCLIENT_DATA/endpoints.yaml` | `config.ClientEndpointRegistry` | `internal/config`, `internal/apshellapp` | `schema_version:1`; role is `signer` or `sentry`; at most one signer endpoint. |
| Endpoint alias | local identifier | map key under `endpoints` | endpoint lookup by alias | `internal/config`, `internal/apshellapp` | ASCII letters, digits, `.`, `_`, `-`; aliases are local, not exported. |
| Endpoint record | authoritative routing record | `endpoints.<alias>` | endpoint connection profile | `internal/config`, `internal/engine/connect` | URL, signer/local ports, token file, identity file, known hosts resolve relative to `APCLIENT_DATA`. |
| Published sentry inventory | routing metadata | `endpoints.<alias>.published_sentries` | derived sentry endpoint map | `internal/config`, `internal/apshellapp`, `internal/engine` | Keyed by embedded public key hex; route metadata, not ownership proof. |
| Derived sentry endpoint map | derived runtime | built from `published_sentries` | `Config.SentryEndpoints` | `internal/config`, `internal/engine/guarded/discovery.go` | Not written to `config.yaml`; conflicts/malformed records fail closed. |
| Endpoint token file | bearer secret | default `aplane.token` or `tokens/<alias>.token` | HTTP auth header and SSH mutual-proof key | `internal/tokenfile`, `internal/engine/connect` | Mode `0600`; request-token writes endpoint-scoped token. |
| Client SSH identity | client secret | `.ssh/id_ed25519` | SSH tunnel private key | `internal/sshtunnel`, `internal/engine/connect` | Generated/enrolled separately from tokens. |
| Known hosts | trust store | `.ssh/known_hosts` or endpoint override | SSH host-key verification | `internal/sshtunnel`, `internal/clientenroll`, `cmd/apconsole` | Host trust is not imported through endpoint envelope. |
| Client mutation lock | local coordination | `.apclient.lock` | cache/config mutation serialization | `internal/clientdata` (lock ownership), used by `internal/clientstate` and `internal/config` | Prevents concurrent local writers from corrupting client state. |
| MCP config | client config | `.mcp.json`, `.codex/config.toml` | installed MCP command registration | installer, `cmd/apshell` | Installer preserves existing files and writes `.aplane-installer.new` templates when needed. |
| Plugin activation | authoritative client config | `plugins.yaml` | enabled plugin names | `internal/plugin`, installer | Empty activation list on fresh install; non-bundled choices preserved. |
| Plugin catalog entry | client executable catalog | `plugins.available/<name>` plus manifest/checksums | plugin manager candidate | `internal/plugin`, installer | Symlinked directories ignored; checksum/manifest validation gates execution. |
| JavaScript script | user-managed client artifact | `scripts/*.js` | Goja runtime input | `internal/scripting`, `internal/jsapi` | Script files are not signer authority. |
| Swap proposal | client-local workflow state | `swap/<network>/<proposal_id>.<address>.json` | swap workflow display/action state | `internal/clientstate`, shell swap code | Tombstones suppress locally deleted proposals. |

## Client Caches

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client cache key | cache secret | `cache/.cache_key` | HMAC key for cache envelopes | `internal/cache`, `internal/clientstate` | Local only; regenerated cache means rebuildable state. |
| Alias cache | cache/display | `cache/alias_cache.json` | alias to address/set references | `internal/cache`, `internal/clientstate`, `internal/refname` | Names canonicalized; cache is not signing authority. |
| Set cache | cache/display | `cache/set_cache.json` | named address sets | `internal/cache`, `internal/clientstate`, `internal/refname` | Reserved names rejected near persistence. |
| Signer inventory cache | cache/display | `cache/signer_cache.json` | local view of signer keys, key types, LSig sizes | `internal/cache`, `internal/engine` | Rebuilt from `/keys`/`/keytypes`; `Locked` is non-persisted runtime state. |
| ASA cache | cache/display | `cache/<network>_asa_cache.json` | ASA metadata lookup by network | `internal/cache`, `internal/asa`, `internal/engine` | Signed JSON; symbolic ambiguity rejects instead of guessing. |
| Auth-address cache | cache/display | `cache/<network>_auth_cache.json` | account auth-address lookups | `internal/cache`, `internal/clientstate` | Network-scoped; rebuilt from algod. |

## Network And Chain Identity

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Network context token | authoritative local namespace | config map key/string | selected client context and signer policy bucket | `internal/config`, `docs/ARCH_NETWORKS.md` | Filesystem-safe syntax; not cryptographic chain identity. |
| Built-in genesis mapping | source-defined authority | `internal/config/genesishash.go` | genesis hash resolver | `internal/config` | Built-in Algorand mappings cannot be remapped. |
| Custom genesis mapping | authoritative signer config | `server config networks.<token>.genesis_hash` | resolver entries | `internal/config`, `internal/serverconfig` | Duplicate or malformed hashes reject startup/config load. |
| Algod endpoint config | authoritative endpoint config | client/signer `networks.<token>.algod` | algod client construction | `internal/config`, `internal/serverconfig`, `internal/engine`, `internal/signerapp/daemon` | Missing client algod server rejects shell startup for active network. |
| ASA built-in registry | source-defined metadata | `internal/asa/registry` | seed data and symbolic fallback | `internal/asa` | Cache-backed current-network entries take precedence; ambiguity rejects. |

## Policy Model

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client-signing policy config | authoritative policy domain | `policy.yaml` interpreted on signer nodes | effective client-signing policy | `internal/policy`, `internal/signerapp/policyruntime` | Four-tier verdict model with operator default fallback. |
| Sentry policy config | authoritative policy domain | `policy.yaml` interpreted on sentry nodes | effective sentry component policy | `internal/policy`, `internal/signerapp/signing` | Deterministic reject/sign only; no review or operator default. |
| Transfer policy | authoritative policy section | `transfer_policy` YAML | route table and movement authorization | `internal/policy`, `internal/policyview`, `cmd/appolicy` | `schema_version:1`; route IDs are audit identifiers. |
| Transfer route | authoritative policy row | `transfer_policy.routes[]` | route match and rule ID source | `internal/policy` | Dynamic rule IDs use `transfer_policy:<route_id>:<outcome>`. |
| Policy key override | authoritative sparse override | `key_overrides` map | effective per-key policy | `internal/policy` | Signing overrides keyed by auth address; sentry overrides keyed by Witness Key ID. |
| Policy verdict | runtime decision | effective policy plus decoded txn facts | approve/review/reject outcome | `internal/policy`, `internal/signerapp/signing` | Sentry rejects if a review verdict would be required. |
| Policy editor draft | long-lived UI/runtime state | loaded YAML plus in-memory edits | appolicy TUI draft | `cmd/appolicy`, `internal/signerapp/policyeditor` | Applies only on explicit save/apply; save writes exact bytes and sidecar. |
| Sentry policy conversion output | derived YAML | `appolicy --to-sentry` input policy | deterministic "could allow" sentry-role `policy.yaml` content | `cmd/appolicy`, `internal/policy` | Drops review-only behavior; fails closed for non-deterministic route misses. |

## Authorization And Authentication

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Authorization action | source-defined authority | `internal/auth/authorizer.go` constants | authorizer known-action vocabulary | `internal/auth`, `internal/authz` | Unknown actions fail closed before grant matching. |
| Authorization resource | request-scoped model | `auth.Resource` | target type/id/identity | `internal/auth`, HTTP/admin adapters | Empty identity is resolved at boundary or rejected. |
| Product bootstrap grants | source-defined authority | `internal/authz` bootstrap setup | in-memory authorizer grants | `internal/authz` | No durable grant YAML in product mode. |
| Authenticated HTTP identity | runtime-only | token authenticator match | `auth.Identity` | `internal/auth`, `internal/signerapp/daemon/http_auth.go` | Token authenticates exactly one identity; cross-identity target rejects. |
| Admin session context | runtime-only | admin transport auth result | `adminserver.SessionContext` | `internal/signerapp/adminserver`, `internal/adminproto`, `internal/protocol` | Bound to target identity; approvals carry approver principal. |
| Token provisioning request | runtime wire model | SSH key-only request plus admin approval | admin `token_provisioning_request` | `internal/sshtunnel`, `internal/signerapp/sshprovision` | No token issued until admin approval and SSH key enrollment succeed. |

## HTTP Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| HTTP error response | wire contract | `signerapi.ErrorResponse` | non-2xx JSON error | `pkg/signerapi`, `internal/signerapp/daemon`, `internal/signerapp/svcerr` | Contracted in `ARCH_HTTP_API.md`. |
| Health response | wire projection | process liveness | `signerapi.HealthResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Unauthenticated `GET /health`; not identity-scoped. |
| Status response | wire projection | authenticated identity runtime state | `signerapi.StatusResponse` | `internal/signerapp/daemon`, `internal/signerapp/rest`, `pkg/signerapi` | `keyset_revision` is process-local, not durable. |
| Keys response | wire projection | loaded key snapshot | `signerapi.KeysResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Sentry-key rows use Witness Key ID as `address`; guarded rows expose non-secret params. |
| Key info row | wire projection | loaded key metadata | `signerapi.KeyInfo` | `internal/signerapp/rest` | `is_witness_key`/`is_spending_account` disambiguate selectors from accounts; may carry `signing_flow`, `sentry_component_key_type`, and `bounded_authorization`. |
| Key types response | wire projection | enabled providers/templates and sentry refs | `signerapi.KeyTypesResponse` | `internal/signerapp/rest` | Runtime args are generation metadata, not existing-key signing args; may carry `signing_flow`. |
| Group sign request | wire request | client transaction bytes | `signerapi.GroupSignRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Shared by `/sign` and `/plan`; all-foreign invalid. |
| Bounded admin request/partial | wire request/projection | planned admin-key rekey group plus durable metadata | `signerapi.BoundedAdminRequest`, `BoundedAdminPartialResponse` | `pkg/signerapi`, `internal/signerapp/signing` | `POST /sign/bounded-admin`; not interchangeable with `GroupSignResponse`; external admin completion is out of band. |
| Sign request entry | wire request row | caller-supplied txn/signed bytes | sign/passthrough/foreign entry | `pkg/signerapi`, signer planner | `txn_sender` is advisory display data only. |
| Group plan response | wire projection | canonical planned group | `signerapi.GroupPlanResponse` | `internal/signerapp/signing` | No key access; returns unsigned TX-prefixed transaction bytes. |
| Group sign response | wire projection | finalized signed group | `signerapi.GroupSignResponse` | `internal/signerapp/signing` | Signed array aligns to finalized group positions. |
| Mutation report | wire projection | canonicalization effects | `signerapi.MutationReport` | `internal/signerapp/signing` | Observability only, not durable authority. |
| Cancel sign request/response | wire request/projection | live request registry lookup | `signerapi.CancelSign*` | `internal/signerapp/approval` | Only `/sign` request IDs are live cancel handles; component/assembly IDs are correlation only. |
| Admin generate DTOs | wire request/projection | enabled key type plus parameters | `signerapi.AdminGenerate*` | `internal/signerapp/keyadmin` | No mnemonic in REST response. |
| Admin delete DTO | wire request/projection | address query parameter | delete response or error | `internal/signerapp/daemon`, `internal/signerapp/keyadmin`, `pkg/signerapi` | Missing address 400; missing key 404. |
| Component sign request | wire request | canonical group bytes and target indices | `signerapi.ComponentSignRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Role is `user` or `sentry`; `component_key` means guarded account for `user` and Witness Key ID for `sentry`; omitted request IDs are generated. |
| Component sign response | wire projection | per-target component signatures | `signerapi.ComponentSignResponse` | `internal/signerapp/signing` | Signature scheme is user key type or sentry key type. |
| Guarded assembly request | wire request | group bytes plus user/sentry signatures | `signerapi.GuardedAssemblyRequest` | `internal/signerapp/signing` | Verifies sentry signature against embedded key in local account key. |
| Guarded assembly response | wire projection | assembled signed group bytes | `signerapi.GuardedAssemblyResponse` | `internal/signerapp/signing` | Assembly does not trust endpoint-advertised public keys. |
| Admin sentry sync DTOs | wire request/projection | public candidate list | `signerapi.AdminSyncSentryReferences*` | `internal/signerapp/rest`, `internal/sentry/sentryrefs` | Writes public signer-side reference catalog only; HTTP authorizes as `sentries.sync`; no tokens or private keys. |

## Admin IPC Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Admin envelope | wire contract | line-delimited JSON `kind`, `type`, `id` | request/response/notification routing | `internal/protocol`, `internal/transport`, `internal/signerapp/adminserver` | Missing/unsupported messages yield protocol error. |
| Passphrase messages | secret wire fields | JSON string decoded as `protocol.SensitiveBytes` | auth/unlock/changepass/store messages | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Handlers clone/zero mutable buffers where possible. |
| Admin key list entry | wire projection | admin service key metadata | `protocol.AdminKeyInfo` projected from `adminproto.KeyInfo` | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Deliberately distinct from the richer HTTP `signerapi.KeyInfo`; extend both admin types together for TUI-visible fields. |
| Key management messages | wire contract | `generate_key`, `delete_key`, `import_key`, details/list | admin key operations | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver` | Import mnemonic is accepted only over local IPC; generate responses omit mnemonic; export message types decode to an explicit denial. |
| Template management messages | wire contract | library/install/show/import/remove/activate/deactivate messages | template/key type lifecycle | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/signertui` | Decrypted installed template source is local IPC only; user-facing CLI/TUI verbs are enable/disable. |
| Sign approval prompt | runtime wire model | signer approval coordinator request | admin `sign_request` | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/approval` | Approval prompts carry descriptions; response attaches approver principal. |
| Token provisioning prompt | runtime wire model | SSH enrollment request | admin token provisioning messages | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/sshprovision` | Admin approval required before token delivery. |
| Backup/restore messages | wire contract | admin backup plus preview/recover/list/review/activate/rollback/purge DTOs | backup admin service calls | `internal/protocol`, `internal/signerapp/adminserver`, `internal/signerapp/backupadmin` | Review carries typed source context authenticated by the archive's sealed manifest, plus the destination-derived acknowledgement signal; direct live restore is omitted; export passphrases are parsed as `SensitiveBytes`. |
| Admin settings messages | wire contract | settings get/update messages | process/identity config mutation | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/admin` | Update paths authorize and apply config-staleness guards. |
| Policy snapshot/validation/replacement | wire/runtime projection | active policy snapshot or replacement YAML | shared policy editor online store | `internal/protocol`, `internal/adminproto`, `internal/signerapp/adminserver`, `internal/signerapp/admin`, `internal/signerapp/policyeditor` | Target-aware signer/sentry writes replace whole documents and sidecars; apadmin and appolicy share the editor model. |

## Transaction And Signing Runtime Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Prepared client group | request-scoped model | shell/script/plugin/app input | `engine.PreparedGroup` and related request plans | `internal/engine`, `internal/apshellapp` | Not authorization proof; submitted to signer for canonicalization. |
| App call metadata | request-scoped display metadata | caller/appspec input | `app_call_info` | `internal/engine`, `internal/signerapp/txdesc` | Approval rendering only; not signing authority. |
| Canonical signer group | request-scoped authority for signing | decoded request transaction bytes | planned group, dummies, fees, group ID | `internal/signerapp/signing` | Genesis hash consistency, group size, dummy budget, policy validation. |
| Sign request live entry | runtime-only | active synchronous request | approval registry entry by request ID | `internal/signerapp/approval` | Not durable; cancelable only while live. |
| Approval description | display projection | decoded transaction/group facts | admin prompt text and audit context | `internal/signerapp/txdesc` | Presentation-only; must not introduce signing inputs. |
| Sentry component message | request-scoped signing input | role byte plus target TxID | 32-byte message digest | `internal/sentry/message` | Shared by signer assembly and TEAL vectors; clients treat component signatures as opaque. |
| Component signature set | request-scoped wire data | `/sign/component` response | per-target signatures by target index | `internal/signerapp/signing`, `pkg/signerapi` | Each signature is bound to one target TxID and role. |
| Guarded assembly target | request-scoped wire data | `/sign/assemble` request targets | LogicSig args packing plan | `internal/signerapp/signing` | User and sentry signatures are verified before packed bytes are returned. |
| Guarded send orchestration | long-lived client workflow | signer inventory plus endpoint registry plus requests | user component call (signer-domain gated), sentry call, optional non-guarded `/sign`, assembly, then client algod submit or simulate | `internal/engine`, `internal/apshellapp` | Client holds no key material but does hold the final executable group; endpoint routing is not trust; guarded targets are classified by effective signer and may be direct senders or AuthAddr authorizers; mixed groups sign non-guarded originals over the same canonical bytes. |
| Bounded admin ceremony orchestration | long-lived offline/online workflow | `/sign/bounded-admin` partial plus external `.wit` custody | request/signature files and final submit | `cmd/aprekey`, `internal/apboundedadminapp`, `internal/boundedadmin`, `internal/engine` | Online rekey/unrekey or prepare/sign/complete; signer never holds contract-admin private material. |

## Plugin, JavaScript, And MCP Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Plugin manifest | authoritative plugin metadata | `plugins.available/<name>/manifest.json` | plugin registry entry | `internal/plugin` | Manifest format is separate from JSON-RPC protocol version. |
| Plugin checksum | integrity metadata | `checksums.sha256` and package files | validation result | `internal/plugin`, `cmd/applugin-checksum` | Invalid checksum prevents plugin execution. |
| Plugin execution context | wire/runtime projection | shell/engine state | JSON-RPC context payload | `internal/plugin`, `internal/apshellcli` | Structured `assets` list is canonical; no lossy `assetMap`. |
| JavaScript runtime state | runtime-only | loaded script plus engine state | Goja runner | `internal/scripting`, `internal/jsapi` | Per-run runtime state; saved scripts are durable user state. |
| MCP structured result | wire projection | shell app result objects | MCP tool result payload | `internal/apshellcli`, `internal/appresult` | Projection of shell runtime, not a separate backend model. |

## Backup And Restore Payloads

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Backup archive | authoritative packaged backup | `backups/<identity>/*.tar.gz` | archive metadata and restore source | `internal/backup` | Tarball is packaging; `.apb` is cryptographic unit. |
| Backup source context | authenticated packaged metadata | source fields inside `manifest.sealed` | recovered source approval default and custom mappings | `internal/backup`, `internal/backup/sourcecontext` | 1024-mapping bound; canonical custom mappings only; authenticated by the manifest but never destination authority. |
| `.apb` file | encrypted backup payload | standalone encryption envelope | decrypted key/template bundle | `internal/backup` | Envelope version checked; unsupported versions reject. |
| Backup bundle | versioned payload | JSON `backup_bundle:1`, `payload_version:1` | key plus optional template provenance | `internal/backup` | Unknown sentinel or payload version rejects. |
| Restore preview | request-scoped runtime model | archive plus export passphrase | list of keys/errors/templates | `internal/backup`, `internal/signerapp/backupadmin` | No mutation during preview. |
| Recovered batch | durable inactive model | destination-encrypted batch metadata and entries | list/review projection | `internal/backup/recovered`, `internal/signerapp/backupadmin` | Atomic publish; exact entry digest and restore-ID binding; immutable plaintext preserves additive fields; no active mutation. |
| Activation review | request-scoped runtime model | recovered batch plus current policy/config/active fingerprints | informational policy comparison, destination-derived acknowledgement, and review token | `internal/signerapp/backupadmin` | Token changes with destination policy, approval mode, archive digest, entries, or active conflicts. |

## Envelopes And Public Handoff Files

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Endpoint export envelope | public handoff | JSON `schema:"aplane.endpoint.v1"` | `apshell endpoints import` input | `cmd/apstore`, `internal/config`, `internal/apshellapp` | No alias, role, token, known hosts, private key, or sentry inventory; URL comes from `--url`, `--host`, or signer `endpoint.advertise_url`. |
| Witness public reference | public handoff | JSON `schema:"aplane.witness-key-public.v1"` | manual sentry reference import or contract-admin enrollment | `internal/witness`, `cmd/apstore`, `internal/sentry/sentryrefs` | Contains `key_type`, `witness_key_id`, and full `public_key_hex`; no custody, role, endpoint, or trust claim. |
| Public sentry reference record | public signer catalog | JSON `schema:"aplane.sentry-public-key-ref.v1"` | generation select option | `internal/sentry/sentryrefs` | Stored under `sentries/`; manual and client-discovery sources share schema. |
| Bounded admin ceremony request | short-lived handoff | `*.apbounded-admin-request` schema `aplane.bounded-admin-request.v2` | offline `aprekey sign` input | `internal/boundedadmin/protocol`, `internal/apboundedadminapp`, `cmd/aprekey` | Strict JSON; size-bounded; request-hash binds partial, optional sentry authorization, and network context; mode `0600`, no overwrite. |
| Bounded admin ceremony signature | short-lived handoff | `*.apbounded-admin-signature` schema `aplane.bounded-admin-signature.v1` | networked `aprekey complete` input | `internal/boundedadmin/protocol`, `internal/apboundedadminapp`, `cmd/aprekey` | Binds `request_hash_hex`, contract admin key ID, and signature; mode `0600`, no overwrite. |

## Installer And Release Metadata

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Release metadata | public provenance | release archive `release.json`, copied to `<install-root>/install/release.json` or systemd `<APSIGNER_DATA>/install/release.json` when present | version, commit, and build timestamp for diagnostics and future upgrade checks | `.github/workflows/release.yml`, `Makefile release-local`, `scripts/package-bootstrap-release.sh`, `install.sh` | Schema `schema_version:1`; public metadata only, not signing, policy, endpoint trust, or upgrade authority by itself. |

## Audit And Observability

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Audit event | authoritative audit record | JSONL line in `audit.log` | operational/accountability history | `internal/signerapp/audit` | Event fields are not signing inputs. |
| Sentry component audit projection | audit projection | component-signing outcome | `SIGN_APPROVED`/`SIGN_REJECTED` rows | `internal/signerapp/signing`, `internal/signerapp/audit` | Uses sign events; Witness Key ID is `txn_auth`, decoded sender is `txn_sender`. |
| Policy rule ID | stable identifier | policy constants and dynamic route grammar | audit/prompt/error context | `internal/policy` | Typos should be caught by tests; route IDs are persistent audit identifiers. |
| Request ID | runtime correlation ID | optional request field or generated server ID | audit/cancel/prompt correlation | `pkg/signerapi`, `internal/signerapp/approval` | Syntax-limited; only live `/sign` IDs are cancelable in MVP. |
| Keyset revision | runtime freshness marker | in-memory identity key snapshot counter | `/status` and client refresh logic | `internal/signerapp/identity`, `internal/engine` | Process-local; must not be compared across restarts. |

## Current Design Decisions

These decisions are part of the current data model and contract surface:

| Decision | Rationale |
|---|---|
| `keyring.enc` is the store's only cryptographic root. | KDF parameters, salt, and the sealed term set live in one file, so a passphrase change is one atomic write and no second record can disagree with it. `.keystore` is a non-authoritative static marker whose sole job is the format version gate. |
| Every encrypted object names itself in its envelope. | The AEAD's authenticated data binds the term and the object's class and canonical selector, so one store key no longer makes every file interchangeable with every other. The identity is logical, never a path, because generations copy ciphertext between namespaces without re-encrypting it. |
| In-place upgrades have a minimum supported release. | The installer upgrades only installs with `install/release.json` at or above the current floor; installs below the floor require a fresh install root. |
| `release.json` is release provenance metadata. | It helps identify the installed distribution and apply installer compatibility gates, but does not authenticate code or authorize upgrades by itself. |
| Release archive labels are not upgrade authority. | Local packaging and smoke tests may use simple archive labels while embedding a semver-comparable `release.json.version`; installers compare the metadata file, not the tarball filename. |
| `endpoints.yaml` is the client routing authority. | Client `config.yaml` owns network/theme/polling, not signer or sentry endpoint routes. |
| Endpoint import and `/keys` discovery are routing metadata. | The trust anchor is the sentry public key embedded in the guarded account key, then `/sign/assemble` verification and on-chain LogicSig verification. |
| `Config.SentryEndpoints` is derived runtime state. | Durable sentry endpoint inventory lives under endpoint records in `endpoints.yaml`. |
| `sentries/<name>.json` records are public generation references. | They help the TUI select a sentry public key but do not prove endpoint ownership or signer custody. |
| Guarded account key files store the resolved embedded public key. | Endpoint alias, reference name, and route selection are client/runtime concerns, not sign-time authority for the key. |
| External `.wit` bundles are not signer-managed credentials. | Contract-admin private material stays in standalone custody (`aprekey`); signer and `apstore` never treat `.wit` as `.key`/`.sen`. |
| Inventory `signing_flow` labels are frozen routing tokens. | Clients implement empty, `sentry1`, and `bounded1` and fail closed on unknown labels. |
| `signerapi.SignResponse` is not the live `/sign` wire shape. | Live `/sign` uses `GroupSignResponse`; `SignResponse` is not a separate wire authority. |
| Admin mnemonic export messages do not release recovery material. | Servers deny `export_key`, `GenerateResultMessage.Mnemonic` is omitted, and recovery material is handled through encrypted backups instead of admin result payloads. |
| `internal/signerapp/signing` uses SDK DTOs at the service boundary. | It is not a duplicate durable authority; request DTO changes belong in `pkg/signerapi` with fixtures. |
| Plugin manifest `manifest_format` is the only manifest schema field. | `protocol_version` is rejected before execution; plugin JSON-RPC protocol and manifest schema are separate models. |
| Template `ReloadReport` is a reload projection. | It verifies identity-local activation results but does not persist template authority; encrypted template files and key type state records remain the durable sources. |

## Representative Test And Fixture Index

Use this index when a catalog entry points at an owning subsystem but does not
name a test inline:

- HTTP DTO and contract fixtures: `pkg/signerapi/types_contract_test.go`,
  `pkg/signerapi/sentry_test.go`, `test/contracts/signerapi/*.json`.
- HTTP method/shape enforcement: `internal/signerapp/daemon/method_compat_test.go`,
  `internal/signerapp/daemon/rest_shape_test.go`, `internal/signerclient/client_test.go`.
- Endpoint registry and endpoint writes:
  `internal/config/client_endpoints.go`,
  `internal/config/client_endpoint_writes_test.go`,
  `internal/apshellapp/endpoints_test.go`.
- Guarded send orchestration: `internal/engine/guarded/submit_test.go`,
  `internal/engine/connect/client_test.go`.
- Sentry component signing and assembly:
  `internal/signerapp/signing/component_test.go`,
  `internal/signerapp/rest/service_test.go`.
- Sentry references and public metadata:
  `internal/sentry/sentryrefs`, `cmd/apstore/sentry*.go`,
  related package tests.
- Node role and key-class gates: signer startup, `internal/signerapp/identity`,
  `internal/signerapp/rest/service_test.go`,
  `internal/signerapp/signing/sentry_gate.go`.
- Policy domains, integrity, and conversion: `internal/policy/*_test.go`,
  `cmd/appolicy/main_test.go`, `test/contracts/policy/*.yaml`.
- Key payload parsing, scan, backup, and restore: `internal/keys`,
  `internal/backup/service_test.go`, `cmd/apstore/policy_test.go`.
- Bounded metadata, ceremony, and external witness artifacts:
  `internal/boundedmeta`, `internal/boundedadmin`, `internal/witness/artifact`,
  `internal/apboundedadminapp`, `test/contracts/signerapi/bounded_*`.
- Authorization vocabulary and bootstrap grants:
  `internal/auth/authorizer.go`, `internal/authz/authorizer_test.go`.
- Integration coverage for signer/client flows: `test/integration`.

## Related Source-Of-Truth Docs

- [ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md): conceptual durable/runtime/wire
  model and invariants.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): compatibility-bearing file, config,
  wire, SDK, plugin, and lifecycle contracts.
- [ARCH_HTTP_API.md](ARCH_HTTP_API.md): HTTP DTO and status-code contract.
- [ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md): admin IPC/SSH message
  catalog.
- [ARCH_POLICY.md](ARCH_POLICY.md): policy verdict and routing semantics.
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md): stable action/resource model.
- [ARCH_SENTRY.md](ARCH_SENTRY.md): guarded signing and sentry node
  architecture.
- [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md): bounded1 encodings, custody, and
  ceremony contracts.
- [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md): key and key type state
  machines.
