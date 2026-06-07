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
| Signer data root | authoritative root | `APSIGNER_DATA` | `storepaths.Paths` and startup path resolution | `internal/storepaths`, `cmd/apsigner`, installers | Required for signer startup; systemd-managed roots reject manual startup unless explicitly allowed. |
| Process config | authoritative config | `APSIGNER_DATA/config.yaml` | `config.ServerConfig` snapshot | `internal/config`, `cmd/apsigner`, `internal/signerapp/admin` | Unknown fields reject; mutable writes use process config lock; tests in `internal/config` and admin settings tests. |
| Network config | authoritative config section | `config.yaml` `networks.<token>` and `teal_compile_network` | algod map and genesis resolver | `internal/config`, `cmd/apsigner` | Token syntax and genesis hash collisions fail closed; see `docs/ARCH_NETWORKS.md`. |
| SSH host key | secret server credential | `.ssh/ssh_host_key` | `sshtunnel.Server` host key | `internal/sshtunnel`, startup/install | Generated locally; clients pin through known-hosts flow. |
| IPC socket path | runtime endpoint | default `<data_dir>/aplane.sock` or absolute `ipc_path` | local admin transport listener | `cmd/apsigner`, `internal/adminproto`, `internal/transport` | IPC path can live outside data root; local admin protocol requires passphrase auth. |
| Store mutation lock | runtime/durable coordination | `.apstore.lock` | cooperative store lock | `internal/storelock`, `internal/storemut` | Serializes live signer and local `apstore` mutations. |
| Audit log | authoritative audit trail | `audit.log` JSONL | append-only audit logger | `internal/signerapp/audit`, `cmd/apsigner` | Mode `0600`, rotated by size; not authority for signing or recovery. |
| Signer ASA cache key | cache secret | `cache/.cache_key` | HMAC verifier for signer ASA cache | `internal/cache`, `internal/signerapp/asametadata` | Tampered cache files reject and rebuild from seed where applicable. |
| Signer ASA cache | cache/display | `cache/<network>_asa_cache.json` | per-operation ASA metadata lookup | `internal/signerapp/asametadata`, `internal/asa` | Signed cache; built-in registry seeds; not authority for policy enforcement. |
| Managed backup locker | authoritative backup inventory | `backups/<identity>/*.tar.gz` | backup list/restore preview/apply plans | `internal/backup`, `internal/signerapp/backupadmin` | Imported archives are validated before publication; archive payloads are encrypted `.apb`. |
| Managed backup manifest | backup metadata | `manifest.json` inside managed archives | source node role default and diagnostics | `internal/backup` | Schema `aplane.backup.manifest.v1`; `apstore rebuild --role` is destination authority when provided; missing manifests default to signer. |
| Deleted archive root | inactive durable storage | `identities/<identity>/deleted/` | outside active key/template scans | `internal/keys`, `internal/templatestore` | Deleted keys/templates are not active authority. |

## Signer Identity Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Node role | authoritative root config | `<APSIGNER_DATA>/node.yaml` plus `identities/<identity>/node.yaml.hmac` | key-class and service-dispatch gates | signer startup, identity load, keyadmin, restore, signing dispatch | Values: `signer`, `attestor`; no `dual`; no supported role changes; active role conflicts fail the whole node closed. |
| Signing identity directory | authoritative root | `identities/<identity>/` | `identity.Runtime` | `internal/signerapp/identity` | Product mode exposes `default`; internals are identity-scoped. |
| Identity config | authoritative config | `identities/<identity>/config.yaml` | `identity.EffectiveConfig` | `internal/signerapp/identity`, `internal/signerapp/admin` | Unknown/invalid settings fail; pre-release `mode` fields are rejected. |
| Unlock config | authoritative config | `identities/<identity>/unlock.yaml` | passphrase helper command config | `internal/signerapp/identity`, `cmd/appass` | Helper artifacts are identity-scoped and independent of node role. |
| Passphrase helper files | secret helper state | `passphrase`, `passphrase.cred` | startup/headless passphrase source | `cmd/appass`, `cmd/appass-file`, `cmd/appass-systemd-creds` | Mode `0600`; systemd/local ownership rules enforced by appass. |
| Keystore metadata | authoritative crypto metadata | `.keystore` | passphrase verification and master-key derivation | `internal/crypto`, `internal/keystore` | Version 2 requires explicit KDF params; malformed metadata fails closed. |
| Master key session | runtime-only secret | derived from passphrase, not persisted | `keystore.KeySession`, `FileKeyStore` | `internal/keystore`, `internal/signerapp/runtime` | Zero on lock; not exposed on wire. |
| API token | bearer secret | `identities/<identity>/aplane.token` | HTTP authenticator and SSH username matcher | `internal/tokenfile`, `internal/auth`, `internal/sshtunnel` | Mode `0600`; token revocation rotates identity credential and closes stale SSH sessions. |
| SSH authorized keys | authoritative enrollment | `identities/<identity>/.ssh/authorized_keys` | SSH identity key set | `internal/sshtunnel`, `internal/signerapp/sshprovision` | Token plus SSH key required; token provisioning writes after admin approval. |
| Client-signing policy | authoritative safety policy | `policy.yaml` plus `policy.yaml.hmac` | `policy.Config` runtime snapshot | `internal/policy`, `internal/signerapp/policyruntime` | HMAC over exact YAML; missing/mismatched sidecar fails closed. |
| Attestor component policy | authoritative co-sign policy | `attestation.yaml` plus `attestation.yaml.hmac` | attestor policy runtime snapshot | `internal/policy`, `internal/signerapp/policyruntime`, `internal/signerapp/signing` | No review/operator-default outcomes; missing/mismatched sidecar fails closed. |
| Policy sidecar | authoritative integrity metadata | `<policy>.hmac` JSON | HMAC verification result | `internal/policy`, `cmd/appolicy`, `cmd/apstore` | Security fields are `version`, `algorithm`, `key_id`, `hmac`; diagnostics are not trust inputs. |
| Key type state record | authoritative generation state | `keytypes/<key_type>.json` | enabled/disabled identity key type state | `internal/keytypestate`, `internal/signerapp/templateadmin` | Plaintext, not key material; affects discovery/generation, not existing-key signing. |
| Installed template | authoritative generation source | encrypted `keytypes/<key_type>.template` | registered template provider after unlock/reload | `internal/templatestore`, `internal/signerapp/templates` | Encrypted with identity master key; disabled state skips registration. |
| Public attestor reference | public generation catalog | `attestors/<name>.json` | `/keytypes` `attestor` select options | `internal/attestor/attrefs`, `internal/signerapp/rest`, `cmd/apstore` | Public metadata only; source is `manual` or `client_discovery`; not endpoint ownership proof. |

## Key Material And Key Metadata

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Key file envelope | authoritative secret storage | `keys/*.key` encrypted JSON | decrypted key payload | `internal/keys`, `internal/keystore` | Envelope and payload versions checked before use. |
| Native Ed25519 key | signing authority | `.key` category `ed25519` | address to private key material | `internal/signing`, `internal/keygen`, `internal/keys` | Address derives from key material; private key never leaves signer boundary. |
| DSA LogicSig key | signing authority | `.key` category `dsa_lsig` | address, bytecode, private signing key, signing args | `internal/keys`, `internal/signerapp/signing`, `lsig/*` | Stored bytecode and `signing_args` are sign-time authority. |
| Generic LogicSig key | signing authority | `.key` category `generic_lsig` | address, bytecode, runtime arg schema | `internal/keys`, `lsig/generictemplate` | TEAL-only key stores no private signing key; address derives from bytecode. |
| Attested account key | signing/assembly authority | `.key` category `dsa_lsig`, key type `aplane.falcon1024-att-*` | local user component key plus embedded attestor public key | `lsig/falcon1024_attested`, `internal/signerapp/signing` | `/sign` rejects; user-role `/sign/component` and `/sign/assemble` use stored bytecode/params. |
| Attestor component key | component-sign authority | `.key` category `component`, key type `aplane.attestor-*` | raw component signing key | `internal/keygen`, `internal/signing`, `internal/signerapp/signing` | `/sign` rejects; attestor-role `/sign/component` only; not a spending account. |
| Component selector | public selector | `a_` plus lower hex SHA-256 of public key bytes | component key row `address` and `component_key` fields | `internal/attestor/keytypes` | Uniform for Ed25519/Falcon; rejected as sender/auth/rekey/destination where address is expected. |
| Component public metadata sidecar | public metadata | `keys/<a_selector>.public.json` | `apstore attestor export-public` source | `internal/keys`, `internal/attestor/attrefs` | Selector/key type/public key consistency verified; no private material. |
| Key creation parameters | provenance/generation input | key payload `parameters`/`params` | `/keys` `parameters`, key details | `internal/keys`, `internal/keymgmt` | Aliases normalize at `ParseKeyPayloadMetadata`; conflicting aliases reject. |
| LogicSig bytecode | signing authority | key payload `lsig_bytecode`/`bytecode_hex` | LogicSig address and signing assembly | `internal/keys`, `internal/signerapp/signing` | Aliases normalize; bytecode must derive off-curve address. |
| Signing args | signing authority | key payload `signing_args` | `internal/signingargs.Info`, `/keys` `signing_args` | `internal/signingargs`, `internal/keys` | Per-key snapshot; distinct from `/keytypes` runtime args. |
| Salt counter | signing authority metadata | key payload `salt_counter` | stored bytecode derivation record | `internal/lsigsalt`, `internal/keys` | Required for LogicSig keys; missing rejects scan/restore/signing. |
| Base key type | signing authority metadata | key payload `base_key_type` | base provider lookup for DSA keys | `internal/keys`, `internal/signerapp/signing` | Required for composed/DSA signing that needs base provider ops. |
| Template fingerprint | provenance | key payload `template_fingerprint` | inventory provenance status/note | `internal/lsigprovider`, `internal/keys` | Informational only; conflicts do not block signing. |
| Offline key inventory | local decrypted projection | encrypted key files plus passphrase | `apstore keys list` output | `cmd/apstore`, `internal/keys` | Does not print private key, mnemonic, or raw attestor public key by default. |

## Key Type And Template Catalog

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Compiled provider registry | process authority | Go registrations in `lsig/all.go` and provider packages | provider lookup by `key_type` | `internal/lsigprovider`, `internal/keygen`, `internal/signing` | Canonical `key_type` strings are identifiers; display labels are not. |
| Key type visibility catalog | process metadata | `internal/keytypecatalog` registrations | default-enabled/library-visible/disabled state | `internal/keytypecatalog` | Library-visible providers require identity state record before generation. |
| Plaintext template library | install source | repo or signer-data `library/templates/*.yaml` | KeyType Library candidates | `internal/templatelibrary` | Not active until installed/activated; invalid entries reported, not activated. |
| YAML template spec | generation contract | template YAML `schema_version`, `template_mode`, `template_type` | parsed `BaseTemplateSpec` | `internal/tealtemplate`, `internal/templatelibrary` | Unknown/missing required fields reject import/install. |
| Template install result | wire/runtime projection | admin request response | install/rollback report | `internal/signerapp/templateadmin`, `internal/protocol` | Low-level template store owns encrypted bytes; admin path owns state record. |
| `/keytypes` metadata | wire projection | enabled providers/templates plus references | `signerapi.KeyTypesResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Creation params are future-generation metadata; contract fixtures cover shape. |
| Admin KeyType Library row | UI/wire projection | library source plus identity state | `protocol.LibraryTemplateInfo` | `internal/adminproto`, `internal/signertui` | `compiled_provider` is a wire/display projection, not a template store type. |

## Client Storage

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client data root | authoritative root | `APCLIENT_DATA` | shell/bootstrap path context | `internal/clientdata`, `internal/bootstrap/shell` | Required for apshell; mutation lock protects shared local state. |
| Client config | authoritative config | `APCLIENT_DATA/config.yaml` | `config.Config` network/theme/polling state | `internal/config`, `internal/bootstrap/shell` | Does not own signer routing; top-level `ssh:` signer routing rejects in this release. |
| Endpoint registry | authoritative routing config | `APCLIENT_DATA/endpoints.yaml` | `config.ClientEndpointRegistry` | `internal/config`, `internal/apshellapp` | `schema_version:1`; role is `signer` or `attestor`; at most one signer endpoint. |
| Endpoint alias | local identifier | map key under `endpoints` | endpoint lookup by alias | `internal/config`, `internal/apshellapp` | ASCII letters, digits, `.`, `_`, `-`; aliases are local, not exported. |
| Endpoint record | authoritative routing record | `endpoints.<alias>` | endpoint connection profile | `internal/config`, `internal/engine/connect` | URL, signer/local ports, token file, identity file, known hosts resolve relative to `APCLIENT_DATA`. |
| Published attestor inventory | routing metadata | `endpoints.<alias>.published_attestors` | derived attestor endpoint map | `internal/config`, `internal/apshellapp`, `internal/engine` | Keyed by embedded public key hex; route metadata, not ownership proof. |
| Derived attestor endpoint map | derived runtime | built from `published_attestors` | `Config.AttestorEndpoints` | `internal/config`, `internal/engine/attestor_endpoint.go` | Not written to `config.yaml`; conflicts/malformed records fail closed. |
| Endpoint token file | bearer secret | default `aplane.token` or `tokens/<alias>.token` | HTTP auth header and SSH username | `internal/tokenfile`, `internal/engine/connect` | Mode `0600`; request-token writes endpoint-scoped token. |
| Client SSH identity | client secret | `.ssh/id_ed25519` | SSH tunnel private key | `internal/sshtunnel`, `internal/engine/connect` | Generated/enrolled separately from tokens. |
| Known hosts | trust store | `.ssh/known_hosts` or endpoint override | SSH host-key verification | `internal/sshtunnel`, `internal/clientenroll`, `cmd/apconsole` | Host trust is not imported through endpoint envelope. |
| Client mutation lock | local coordination | `.apclient.lock` | cache/config mutation serialization | `internal/clientstate`, `internal/config` | Prevents concurrent local writers from corrupting client state. |
| MCP config | client config | `.mcp.json` | installed MCP command registration | installer, `cmd/apshell` | Installer preserves existing file and writes `.new` when needed. |
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
| Custom genesis mapping | authoritative signer config | `server config networks.<token>.genesis_hash` | resolver entries | `internal/config`, `cmd/apsigner` | Duplicate or malformed hashes reject startup/config load. |
| Algod endpoint config | authoritative endpoint config | client/signer `networks.<token>.algod` | algod client construction | `internal/config`, `internal/engine`, `cmd/apsigner` | Missing client algod server rejects shell startup for active network. |
| ASA built-in registry | source-defined metadata | `internal/asa/registry` | seed data and symbolic fallback | `internal/asa` | Cache-backed current-network entries take precedence; ambiguity rejects. |

## Policy Model

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Client-signing policy config | authoritative policy | `policy.yaml` | effective client-signing policy | `internal/policy`, `internal/signerapp/policyruntime` | Four-tier verdict model with operator default fallback. |
| Attestation policy config | authoritative policy | `attestation.yaml` | effective attestor component policy | `internal/policy`, `internal/signerapp/signing` | Deterministic reject/sign only; no review or operator default. |
| Transfer policy | authoritative policy section | `transfer_policy` YAML | route table and movement authorization | `internal/policy`, `internal/policyview`, `cmd/appolicy` | `schema_version:1`; route IDs are audit identifiers. |
| Transfer route | authoritative policy row | `transfer_policy.routes[]` | route match and rule ID source | `internal/policy` | Dynamic rule IDs use `transfer_policy:<route_id>:<outcome>`. |
| Policy key override | authoritative sparse override | `key_overrides` map | effective per-key policy | `internal/policy` | Signing overrides keyed by auth address; attestation overrides keyed by component selector. |
| Policy verdict | runtime decision | effective policy plus decoded txn facts | approve/review/reject outcome | `internal/policy`, `internal/signerapp/signing` | Attestation rejects if a review verdict would be required. |
| Policy editor draft | long-lived UI/runtime state | loaded YAML plus in-memory edits | appolicy TUI draft | `cmd/appolicy`, `internal/policyeditor` | Applies only on explicit save/apply; save writes exact bytes and sidecar. |
| Attestation conversion output | derived YAML | `appolicy --to-attestation` input policy | deterministic "could allow" `attestation.yaml` | `cmd/appolicy`, `internal/policy` | Drops review-only behavior; fails closed for non-deterministic route misses. |

## Authorization And Authentication

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Authorization action | source-defined authority | `internal/auth/authorizer.go` constants | authorizer known-action vocabulary | `internal/auth`, `internal/authz` | Unknown actions fail closed before grant matching. |
| Authorization resource | request-scoped model | `auth.Resource` | target type/id/identity | `internal/auth`, HTTP/admin adapters | Empty identity is resolved at boundary or rejected. |
| Product bootstrap grants | source-defined authority | `internal/authz` bootstrap setup | in-memory authorizer grants | `internal/authz` | No durable grant YAML in product mode. |
| Authenticated HTTP identity | runtime-only | token authenticator match | `auth.Identity` | `internal/auth`, `cmd/apsigner/http_auth.go` | Token authenticates exactly one identity; cross-identity target rejects. |
| Admin session context | runtime-only | admin transport auth result | `adminproto.SessionContext` | `internal/adminproto`, `internal/protocol` | Bound to target identity; approvals carry approver principal. |
| Token provisioning request | runtime wire model | SSH key-only request plus admin approval | admin `token_provisioning_request` | `internal/sshtunnel`, `internal/signerapp/sshprovision` | No token issued until admin approval and SSH key enrollment succeed. |

## HTTP Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| HTTP error response | wire contract | `signerapi.ErrorResponse` | non-2xx JSON error | `pkg/signerapi`, `cmd/apsigner` | Contracted in `ARCH_HTTP_API.md`. |
| Status response | wire projection | authenticated identity runtime state | `signerapi.StatusResponse` | `cmd/apsigner`, `internal/signerapp/rest` | `keyset_revision` is process-local, not durable. |
| Keys response | wire projection | loaded key snapshot | `signerapi.KeysResponse` | `internal/signerapp/rest`, `pkg/signerapi` | Component rows use selector as `address`; attested rows expose non-secret params. |
| Key info row | wire projection | loaded key metadata | `signerapi.KeyInfo` | `internal/signerapp/rest` | `is_component_key`/`is_spending_account` disambiguate selectors from accounts. |
| Key types response | wire projection | enabled providers/templates and attestor refs | `signerapi.KeyTypesResponse` | `internal/signerapp/rest` | Runtime args are generation metadata, not existing-key signing args. |
| Group sign request | wire request | client transaction bytes | `signerapi.GroupSignRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Shared by `/sign`, `/plan`, `/simulate`; all-foreign invalid. |
| Sign request entry | wire request row | caller-supplied txn/signed bytes | sign/passthrough/foreign entry | `pkg/signerapi`, signer planner | `txn_sender` is advisory display data only. |
| Group plan response | wire projection | canonical planned group | `signerapi.GroupPlanResponse` | `internal/signerapp/signing` | No key access; returns unsigned TX-prefixed transaction bytes. |
| Group sign response | wire projection | finalized signed group | `signerapi.GroupSignResponse` | `internal/signerapp/signing` | Signed array aligns to finalized group positions. |
| Group simulate response | wire projection | signer-internal simulation result | `signerapi.GroupSimulateResponse` | `internal/signerapp/rest` | Signed bytes do not leave signer. |
| Mutation report | wire projection | canonicalization effects | `signerapi.MutationReport` | `internal/signerapp/signing` | Observability only, not durable authority. |
| Cancel sign request/response | wire request/projection | live request registry lookup | `signerapi.CancelSign*` | `internal/signerapp/approval` | Only `/sign` request IDs are live cancel handles; component/assembly IDs are correlation only. |
| Admin generate DTOs | wire request/projection | enabled key type plus parameters | `signerapi.AdminGenerate*` | `internal/signerapp/keyadmin` | No mnemonic in REST response. |
| Admin delete DTO | wire request/projection | address query parameter | delete response or error | `cmd/apsigner`, `internal/signerapp/keyadmin` | Missing address 400; missing key 404. |
| Component sign request | wire request | canonical group bytes and target indices | `signerapi.ComponentSignRequest` | `pkg/signerapi`, `internal/signerapp/signing` | Role is `user` or `attestor`; component key meaning is role-specific; omitted request IDs are generated. |
| Component sign response | wire projection | per-target component signatures | `signerapi.ComponentSignResponse` | `internal/signerapp/signing` | Signature scheme is user key type or attestor component key type. |
| Attested assembly request | wire request | group bytes plus user/attestor signatures | `signerapi.AttestedAssemblyRequest` | `internal/signerapp/signing` | Verifies attestor signature against embedded key in local account key. |
| Attested assembly response | wire projection | assembled signed group bytes | `signerapi.AttestedAssemblyResponse` | `internal/signerapp/signing` | Assembly does not trust endpoint-advertised public keys. |
| Admin attestor sync DTOs | wire request/projection | public candidate list | `signerapi.AdminSyncAttestorReferences*` | `internal/signerapp/rest`, `internal/attestor/attrefs` | Writes public signer-side reference catalog only; HTTP authorizes as `attestors.sync`; no tokens or private keys. |

## Admin IPC Wire Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Admin envelope | wire contract | line-delimited JSON `kind`, `type`, `id` | request/response/notification routing | `internal/protocol`, `internal/transport` | Missing/unsupported messages yield protocol error. |
| Passphrase messages | secret wire fields | JSON string decoded as `protocol.SensitiveBytes` | auth/unlock/changepass/store messages | `internal/protocol`, `internal/adminproto` | Handlers clone/zero mutable buffers where possible. |
| Key management messages | wire contract | `generate_key`, `delete_key`, `import_key`, details/list | admin key operations | `internal/protocol`, `internal/adminproto` | Import mnemonic accepted only over local IPC; generate responses omit mnemonic; export messages are retained only to deny/decode legacy requests. |
| Template management messages | wire contract | library/install/show/import/remove/activate/deactivate messages | template/key type lifecycle | `internal/adminproto`, `internal/signertui` | Decrypted installed template source is local IPC only. |
| Sign approval prompt | runtime wire model | signer approval coordinator request | admin `sign_request` | `internal/signerapp/approval`, `internal/adminproto` | Approval prompts carry descriptions; response attaches approver principal. |
| Token provisioning prompt | runtime wire model | SSH enrollment request | admin token provisioning messages | `internal/signerapp/sshprovision`, `internal/adminproto` | Admin approval required before token delivery. |
| Backup/restore messages | wire contract | admin backup/restore DTOs | backup admin service calls | `internal/protocol`, `internal/signerapp/backupadmin` | Export passphrases parsed as `SensitiveBytes`. |
| Admin settings messages | wire contract | settings get/update messages | process/identity config mutation | `internal/adminproto`, `internal/signerapp/admin` | Update paths authorize and apply config-staleness guards. |
| Policy snapshot/validation/replacement | wire/runtime projection | active policy snapshot or replacement YAML | shared policy editor online store | `internal/adminproto`, `internal/signerapp/admin`, `internal/policyeditor` | Target-aware signer/attestation writes replace whole documents and sidecars; apadmin and appolicy share the editor model. |

## Transaction And Signing Runtime Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Prepared client group | request-scoped model | shell/script/plugin/app input | `engine.PreparedGroup` and related request plans | `internal/engine`, `internal/apshellapp` | Not authorization proof; submitted to signer for canonicalization. |
| App call metadata | request-scoped display metadata | caller/appspec input | `app_call_info` | `internal/engine`, `internal/signerapp/txdesc` | Approval rendering only; not signing authority. |
| Canonical signer group | request-scoped authority for signing | decoded request transaction bytes | planned group, dummies, fees, group ID | `internal/signerapp/signing` | Genesis hash consistency, group size, dummy budget, policy validation. |
| Sign request live entry | runtime-only | active synchronous request | approval registry entry by request ID | `internal/signerapp/approval` | Not durable; cancelable only while live. |
| Approval description | display projection | decoded transaction/group facts | admin prompt text and audit context | `internal/signerapp/txdesc` | Presentation-only; must not introduce signing inputs. |
| Attestor component message | request-scoped signing input | role byte plus target TxID | 32-byte message digest | `internal/attestor/message` | Shared by client optional verify, signer assembly, and TEAL vectors. |
| Component signature set | request-scoped wire data | `/sign/component` response | per-target signatures by target index | `internal/signerapp/signing`, `pkg/signerapi` | Each signature is bound to one target TxID and role. |
| Attested assembly target | request-scoped wire data | `/sign/assemble` request targets | LogicSig args packing plan | `internal/signerapp/signing` | User and attestor signatures are verified before packed bytes are returned. |
| Attested send orchestration | long-lived client workflow | signer inventory plus endpoint registry plus requests | user component call, attestor call, assembly, algod submit/simulate | `internal/engine`, `internal/apshellapp` | Client holds no key material; endpoint routing is not trust; MVP requires every original sender to be attested. |

## Plugin, JavaScript, And MCP Models

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Plugin manifest | authoritative plugin metadata | `plugins.available/<name>/plugin.json` | plugin registry entry | `internal/plugin` | Manifest format is separate from JSON-RPC protocol version. |
| Plugin checksum | integrity metadata | `checksums.sha256` and package files | validation result | `internal/plugin`, `cmd/applugin-checksum` | Invalid checksum prevents plugin execution. |
| Plugin execution context | wire/runtime projection | shell/engine state | JSON-RPC context payload | `internal/plugin`, `internal/apshellcli` | Structured `assets` list is canonical; no lossy `assetMap`. |
| Plugin local signer payload | typed wire payload | plugin request | typed signer request data | `internal/plugin`, `internal/engine` | Secret-bearing data is not passed through untyped maps. |
| JavaScript runtime state | runtime-only | loaded script plus engine state | Goja runner | `internal/scripting`, `internal/jsapi` | Per-run runtime state; saved scripts are durable user state. |
| MCP structured result | wire projection | shell app result objects | MCP tool result payload | `internal/apshellcli`, `internal/appresult` | Projection of shell runtime, not a separate backend model. |

## Backup And Restore Payloads

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Backup archive | authoritative packaged backup | `backups/<identity>/*.tar.gz` | archive metadata and restore source | `internal/backup` | Tarball is packaging; `.apb` is cryptographic unit. |
| `.apb` file | encrypted backup payload | standalone encryption envelope | decrypted key/template bundle | `internal/backup` | Envelope version checked; unsupported versions reject. |
| Backup bundle | versioned payload | JSON `backup_bundle:1`, `payload_version:1` | key plus optional template provenance | `internal/backup` | Unknown sentinel or payload version rejects. |
| Restore preview | request-scoped runtime model | archive plus export passphrase | list of keys/errors/templates | `internal/backup`, `internal/signerapp/backupadmin` | No mutation during preview. |
| Restore apply plan | request-scoped runtime model | preview plus selected addresses/overwrite | key/template/state writes | `internal/backup`, `internal/signerapp/backupadmin` | Writes canonical filenames; skips existing keys unless overwrite. |

## Envelopes And Public Handoff Files

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Endpoint export envelope | public handoff | JSON `schema:"aplane.endpoint.v1"` | `apshell endpoints import-public` input | `cmd/apstore`, `internal/config`, `internal/apshellapp` | No alias, role, token, known hosts, private key, or attestor inventory. |
| Attestor public key envelope | public handoff | JSON `schema:"aplane.attestor-public-key.v1"` | manual attestor reference import | `cmd/apstore`, `internal/attestor/attrefs` | Contains `component_key` and full `public_key_hex`; no endpoint/trust claim. |
| Public attestor reference record | public signer catalog | JSON `schema:"aplane.attestor-public-key-ref.v1"` | generation select option | `internal/attestor/attrefs` | Stored under `attestors/`; manual and client-discovery sources share schema. |

## Audit And Observability

| Element | Kind | Authority | Projection | Owner | Checks |
|---|---|---|---|---|---|
| Audit event | authoritative audit record | JSONL line in `audit.log` | operational/accountability history | `internal/signerapp/audit` | Event fields are not signing inputs. |
| Attestor component audit projection | audit projection | component-signing outcome | `SIGN_APPROVED`/`SIGN_REJECTED` rows | `internal/signerapp/signing`, `internal/signerapp/audit` | Current MVP uses existing sign events; component selector is `txn_auth`, decoded sender is `txn_sender`. |
| Policy rule ID | stable identifier | policy constants and dynamic route grammar | audit/prompt/error context | `internal/policy` | Typos should be caught by tests; route IDs are persistent audit identifiers. |
| Request ID | runtime correlation ID | optional request field or generated server ID | audit/cancel/prompt correlation | `pkg/signerapi`, `internal/signerapp/approval` | Syntax-limited; only live `/sign` IDs are cancelable in MVP. |
| Keyset revision | runtime freshness marker | in-memory identity key snapshot counter | `/status` and client refresh logic | `internal/signerapp/identity`, `internal/engine` | Process-local; must not be compared across restarts. |

## Current Design Decisions

These decisions are part of the current data model and contract surface:

| Decision | Rationale |
|---|---|
| This release is new-install-only. | Existing install directories are not supported in-place upgrade targets. |
| `endpoints.yaml` is the client routing authority. | Client `config.yaml` owns network/theme/polling, not signer or attestor endpoint routes. |
| Endpoint import and `/keys` discovery are routing metadata. | The trust anchor is the attestor public key embedded in the attested account key, then `/sign/assemble` verification and on-chain LogicSig verification. |
| `Config.AttestorEndpoints` is derived runtime state. | Durable attestor endpoint inventory lives under endpoint records in `endpoints.yaml`. |
| `attestors/<name>.json` records are public generation references. | They help the TUI select an attestor public key but do not prove endpoint ownership or signer custody. |
| Attested account key files store the resolved embedded public key. | Endpoint alias, reference name, and route selection are client/runtime concerns, not sign-time authority for the key. |
| `signerapi.SignResponse` is not the live `/sign` wire shape. | Live `/sign` uses `GroupSignResponse`; `SignResponse` is not a separate wire authority. |
| Admin mnemonic export messages do not release recovery material. | Servers deny `export_key`, `GenerateResultMessage.Mnemonic` is omitted, and recovery material is handled through encrypted backups instead of admin result payloads. |
| `internal/signerapp/signing` uses SDK DTOs at the service boundary. | It is not a duplicate durable authority; new request DTO changes still belong in `pkg/signerapi` with fixtures. |
| Plugin manifest `manifest_format` is the only manifest schema field. | `protocol_version` is rejected before execution; plugin JSON-RPC protocol and manifest schema are separate models. |
| Template `ReloadReport` is a reload projection. | It verifies identity-local activation results but does not persist template authority; encrypted template files and key type state records remain the durable sources. |

## Representative Test And Fixture Index

Use this index when a catalog entry points at an owning subsystem but does not
name a test inline:

- HTTP DTO and contract fixtures: `pkg/signerapi/types_contract_test.go`,
  `pkg/signerapi/attestor_test.go`, `test/contracts/signerapi/*.json`.
- HTTP method/shape enforcement: `cmd/apsigner/method_compat_test.go`,
  `cmd/apsigner/rest_shape_test.go`, `internal/signerclient/client_test.go`.
- Endpoint registry and endpoint writes:
  `internal/config/client_endpoints.go`,
  `internal/config/client_endpoint_writes_test.go`,
  `internal/apshellapp/endpoints_test.go`.
- Attested send orchestration: `internal/engine/attested_submit_test.go`,
  `internal/engine/connect/client_test.go`.
- Attestor component signing and assembly:
  `internal/signerapp/signing/component_test.go`,
  `internal/signerapp/rest/service_test.go`.
- Attestor references and public metadata:
  `internal/attestor/attrefs`, `cmd/apstore/attestor*.go`,
  related package tests.
- Node role and key-class gates: signer startup, `internal/signerapp/identity`,
  `internal/signerapp/rest/service_test.go`,
  `internal/signerapp/signing/attestor_gate.go`.
- Policy domains, integrity, and conversion: `internal/policy/*_test.go`,
  `cmd/appolicy/main_test.go`, `test/contracts/policy/*.yaml`.
- Key payload parsing, scan, backup, and restore: `internal/keys`,
  `internal/backup/service_test.go`, `cmd/apstore/policy_test.go`.
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
- [ARCH_SPEC.md#attested-signing-and-attestor-nodes](ARCH_SPEC.md#attested-signing-and-attestor-nodes):
  attested signing and attestor node architecture.
