# Engineering Contracts

> Compatibility-bearing wire formats, on-disk formats, and behavioral contracts.
> For system orientation, ownership, and architecture, see [ARCH_SPEC.md](ARCH_SPEC.md).
> For the signer store: layout, formats, generations, key and key type lifecycle, reload,
> and backup and restore, see [ARCH_STORE.md](ARCH_STORE.md).
> For the explanatory network context model, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
> For the current signer policy verdict model, see [ARCH_POLICY.md](ARCH_POLICY.md).
> For guarded signing and cosigner node architecture, see [ARCH_COSIGNER.md](ARCH_COSIGNER.md).
> For bounded authorization and external contract-admin custody, see [ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).
> Load this document when working on a specific subsystem, not as general pre-reading.

## Contents

- [Current Release Compatibility Scope](#current-release-compatibility-scope)
- [Key Type Identifier Contract](#key-type-identifier-contract)
- [HTTP API Contract](#http-api-contract)
- [Admin Protocol](#admin-protocol)
- [apshell Parsing Contracts](#apshell-parsing-contracts)
- [Configuration Contracts](#configuration-contracts)
- [On-Disk Formats](#on-disk-formats)
- [Authentication, SSH, and Client Enrollment](#authentication-ssh-and-client-enrollment)
- [Approval and Policy Contracts](#approval-and-policy-contracts)
- [Runtime Ownership and Shutdown](#runtime-ownership-and-shutdown)
- [Plugin Contract](#plugin-contract)
- [MCP Contract](#mcp-contract)
- [Error Model](#error-model)
- [SDK Contracts](#sdk-contracts)
- [Swap Contract](#swap-contract)

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

## Key Type Identifier Contract

Every protocol, config, key file, template, and key type state field named
`key_type` carries the canonical identifier, not a presentation label.

Canonical forms:

- native Ed25519 is the single-segment built-in `ed25519`
- native Falcon-1024 is the single-segment built-in `falcon1024`. It is a
  protocol-native post-quantum account and is distinct from every
  `aplane.falcon1024.*` LogicSig key type
- APlane-defined LogicSig, template, and compiled-provider key types use
  `publisher.family.vN`, where `vN` is a literal `v` followed by a positive
  decimal version, for example `aplane.falcon1024.v1`,
  `aplane.htlc.v1`, `aplane.falcon1024-allowlist.v1`, and
  `aplane.falcon1024-allowlist-alock.v1`
- witness keys use the same canonical key-type identifier contract,
  currently `aplane.witness-falcon1024.v1`; signer-custodied instances serve
  as cosigner component-signing keys selected by 52-character txid-shaped
  Witness Key IDs, not spending accounts. The
  compatibility wire/storage field name for that selector remains
  `component_key`.
- external bounded contract-admin authorities use the same witness key type
  and Witness Key ID, but private material remains in a structurally distinct
  standalone `.wit` container owned by `aprekey`. It is never a signer-managed
  `.key`/`.cos` credential or spending account.
- `aplane.falcon1024-allowlist-alock.v1` is reserved for the schema-v2
  framework-owned bounded1 allowlist. Its spending key and contract admin key
  are both Falcon-1024. Bounded1 has no Ed25519 contract-admin variant and no
  admin-key algorithm selector.
- the dedicated guarded account key type
  `aplane.falcon1024-cosigner1024.v1` names both its account DSA and cosigner DSA.
  `aplane.corridor.v1` is instead an optional schema-v2 composed template: its
  durable `bounded_authorization` metadata declares `bounded1`, a `cosigner1`
  spend gate, and the framework Merkle allowlist policy. Clients must not infer
  those dimensions from the key-type string.

Witness key records carry no role field. Enrollment assigns the role and
custody assigns signing capability: networked signer custody may produce only
the `APLANE_COSIGNER_V1` component-domain family, while standalone ceremony
custody may produce only `APLANE_BOUNDED_ADMIN_AUTH_V1`. One witness keypair
should serve only one role for its lifetime. Generation rejects collisions
visible in local key metadata and cosigner references, but cannot detect or
prevent out-of-band key copying or enrollment.

YAML templates declare `publisher`, `family`, and integer `version`; the
computed key type is `publisher.family.v<version>`. Clients and tools must send
and persist the full canonical identifier in `key_type` fields. Human-facing
CLI/TUI input and display use the same canonical identifier; publisher
namespaces are not inferred or elided.

Terminology:

- `family` is the middle segment of `publisher.family.vN`. It groups versions
  of one key type or template policy, for example
  `aplane.falcon1024-allowlist.v1` and `aplane.falcon1024-allowlist.v2`.
- `base_key_type` is the field composed DSA templates use to point at their
  private signing primitive. For example,
  `base_key_type: aplane.falcon1024.v1` means the template's DSA signature is
  produced and packed with Falcon-1024, while the account/template identity is
  still named by its own `key_type` and `family` segment (e.g.
  `family: falcon1024-allowlist`).
- `base_key_type` is not a universal owner or routing key. Account semantics,
  creation parameters, TEAL bytecode, metadata, and guarded assembly remain
  owned by the full `key_type` unless a specific contract says otherwise.
  Guarded account key types are the important example: their signing primitive
  is Falcon-1024, but their account semantics and cosigner assembly are guarded
  account semantics.
- `Family` / `FamilyName` on Go provider types are registry/display metadata.
  Current family-keyed registry fallback is an implementation detail, not a
  replacement for canonical `key_type` identity.

## HTTP API Contract

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the HTTP request/response wire shapes, status codes, fixed runtime binding, and cancellation semantics.
The DTO and error-code source of truth is `pkg/signerapi`, which in-repo
callers import directly.

### Cosigner Component Message Contract

Component signatures for guarded signing sign:

```text
SHA512_256("APLANE_COSIGNER_V1" || role_byte || txid)
```

where `role_byte` is `0x01` for the user component role and `0x02` for the
cosigner component role, and `txid` is the canonical 32-byte transaction ID for
the target group entry. Message construction is owned by
`internal/cosigner/message`; clients and signers must use that shared primitive,
or an SDK equivalent with matching vectors, rather than reconstructing the
message independently. The message does not carry a separate sender or
authorizer field; guarded-authorizer binding is derived from the canonical
transaction bytes and verified during assembly by requiring the guarded
LogicSig address, and `AuthAddr` when needed, to equal the requested guarded
account.

### Component Canonicalization And Byte-Binding Contract

`POST /plan` is the sole canonicalizing endpoint in the supported component
choreography. Component-signing and assembly requests carry frozen canonical
group bytes and must never plan, regroup, append dummies, pool fees, or repair
those bytes. They validate or reject the supplied group. The contract does not
assert provenance from `/plan`: an independently constructed group is valid
when it is canonical and satisfies the same policy, resource, fee, and
signer-owned authorization checks.

The position partition is semantic as well as structural. Every declared
dummy must match the canonical signer-added suffix form, and a canonical dummy
suffix cannot be relabeled as caller-supplied original positions to change the
policy or approval input.

For every component call, policy evaluation, operator rendering, and component
message derivation use the same decoded frozen group. In particular, the
bounded-cosigner migration replaces the legacy plan-and-approve-together call
with approval of frozen bytes. The signer reconstructs bounded authorization
from its durable metadata and validates client-supplied runtime arguments; the
client cannot supply or weaken the durable envelope. Guarded assembly remains
authorized by user and cosigner signatures. Bounded-cosigner assembly remains
authorized by its base signature, cosigner signature, and assembly receipt. A
shared transport does not make these authorization materials interchangeable.

### Bounded Authorization Contract V1

`bounded1` is the only bounded-authorization contract. It has no protocol
aliases; bounded admin operations use `POST /sign/bounded-admin` and the
bounded1 DTOs defined below.

This release is the first supported `bounded1` contract. Earlier repository
vectors and developer-generated keys were pre-release and are not
compatibility-bearing; such keys must be recreated. The canonical profile and
goldens below, including the optional-cosigner presence encoding, establish the
v1 baseline.

Bounded1 uses TEAL v13 and admits only pure payments, pure asset transfers,
asset opt-ins, plus an optional pure `pay` rekey. Asset opt-in is a distinct
effect (`AssetAmount == 0` and `AssetReceiver == Sender`), so permission to
transfer assets does not implicitly permit opting into one. Every path requires
the base spending signature and `Fee <= max_fee`; `max_fee` is required and
cannot exceed 10,000 microAlgos.
The four independently inventoried danger fields are `RekeyTo`,
`CloseRemainderTo`, `AssetCloseTo`, and `AssetSender`. A pure spend requires all
four to be zero. A pure rekey requires amount zero, receiver equal to sender,
nonzero `RekeyTo`, and all other danger fields zero. Unknown and unsupported
transaction types reject.

The independent, version-pinned field/type inventory is
[`BOUNDED1_PROTOCOL_INVENTORY.json`](BOUNDED1_PROTOCOL_INVENTORY.json). It must
not be generated from the implementation manifest.

All bounded hashes use SHA-512/256. `u32` and `u64` are unsigned big-endian;
`field(x) = u32(len(x)) || x`; text is exact UTF-8. The canonical profile is:

```text
field("APLANE_BOUNDED_PROFILE_V1") ||
field("bounded1") ||
u32(spend_effect_count) || field(each effect in pay,axfer,asset_opt_in order) ||
u64(max_fee) ||
u32(admin_operation_count) ||
field(kind) || field(authorization) || field(policy_gate) per admin operation in rekey order ||
u32(cosigner_present) ||
if present: field("cosigner1") || field("aplane.witness-falcon1024.v1") ||
u32(1423) || u32(1) || field("spend") ||
field(layer3_policy) ||
u32(base_signature_arg_count) || u32(each base maximum) ||
u32(derived_arg_count) || field/name/kind/parameter/maximum records ||
u32(runtime_arg_count) || field/name/type/required/length/maximum records ||
u32(argument_slot_count) || index/name/source/maximum/path-mask records
```

Canonical behavior parameters are:

```text
field("APLANE_BOUNDED_BEHAVIOR_PARAMETERS_V1") ||
u32(parameter_count) ||
field(name) || field(type) || field(canonical_value) || ...
```

Values use parameter-definition order. Address is 32 raw bytes, bytes is raw,
uint is `u64`, bool is one byte, string is UTF-8, and a list is
`u32(count) || field(each canonical element)`. Only behavior-bearing creation
values participate. A missing or explicitly empty optional parameter uses a
zero-length `canonical_value`, distinct from explicit zero, false, or an empty
list. The separately bound injected
`bounded_admin_public_key`, display/provenance data, paths, and per-request
runtime values do not. A cosigner-enabled profile does include its injected
`cosigner_public_key` behavior parameter. Static runtime/derived declarations and
path masks are part of the canonical profile above.

The sole bounded1 contract admin primitive is Falcon-1024. Its public key is
exactly 1,793 bytes and its deterministic compressed signature is non-empty
and at most 1,423 bytes. The
`contract_admin_key_id` field carries the uppercase unpadded base32 Witness Key
ID of the enrolled admin witness:

```text
SHA512_256(
  field("APLANE_WITNESS_KEY_ID_V1") ||
  field("aplane.witness-falcon1024.v1") ||
  field(falcon_admin_public_key)
)
```

The program-instance binding is:

```text
SHA512_256(
  field("APLANE_BOUNDED_ADMIN_PROGRAM_V1") ||
  field("bounded1") ||
  field(full_key_type) ||
  field(base_primitive) ||
  field(u64(teal_version)) ||
  field(spending_public_key) ||
  field(falcon_admin_public_key) ||
  field(canonical_bounded_profile) ||
  field(canonical_behavior_parameters)
)
```

The rekey authorization message is:

```text
SHA512_256(
  field("APLANE_BOUNDED_ADMIN_AUTH_V1") ||
  field("rekey") ||
  field(bounded_program_binding) ||
  field(transaction_id)
)
```

For `bounded-cosigner1`, the user signer also returns a Falcon-signed assembly
receipt. With `field` as above, `metadata_json` equal to JSON encoding of the
normalized durable `bounded_authorization` structure, and runtime arguments
sorted by name, its message is:

```text
SHA512_256(
  field("APLANE_BOUNDED_COSIGNER_ASSEMBLY_V1") ||
  field(bounded_account) ||
  field(transaction_id) ||
  field(SHA512_256(metadata_json)) ||
  u32(runtime_arg_count) || field(name) || field(value) || ...
)
```

Assembly verifies this receipt with the bounded spending public key before it
accepts the base component or cosigner signature.

For the complete vector inputs in `ARCH_BOUNDED_DSA.md`, the frozen outputs are:

```text
Contract Admin Key ID:
MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ

bounded_program_binding:
bddc0ee16bac8ebad4519c1f138bbfc87e94817fc1d68119f310567fb98e5001

admin_message:
dc6c476953d76d3fcea7ace82ef90624b170fa6aed699988d381ce790a613ce1
```

Argument slots are statically ordered as base signatures, signer-derived Layer
3 values, caller runtime Layer 3 values, the optional cosigner signature, and the
optional admin signature.
Each slot has a frozen index, maximum, source, and path mask. Interior unused
Layer 3 slots are explicit empty values; only trailing unused slots may be
omitted. An admin-key partial omits the admin slot, and external completion pads
to and fills the metadata-declared admin index. Ordinary `/sign` rejects
caller-supplied contract-admin, cosigner, or signer-derived values. The frozen
flow labels are `bounded1` for profiles without a cosigner and
`bounded-cosigner1` for profiles with the cosigner spend gate. The typed admin
partial endpoint remains `POST /sign/bounded-admin`; bounded-cosigner spend uses
`POST /plan`, bounded-base and cosigner targets on `POST /sign/component`, then
`POST /sign/assemble`.

Signer planning classifies for initial path sizing, finalizes grouping, dummy,
and fee mutations, then validates the finalized transaction at the single
classification boundary. Execution verifies plan integrity and loaded metadata
equality without maintaining a second classifier. Assembly accepts only
declared caller runtime slots and generates only declared derived slots; it
rejects wrong-source, oversized, missing, forbidden, hybrid, disabled, and
profile-fee-invalid requests. Every non-spend bounded path carries the unconditional stable rule
`bounded_admin_operation_requires_review` into the approval gate before blanket
or self-no-op autoapproval.

The ordinary client `/sign` submission path independently validates the
returned mutation report before sending bytes to algod. Original positions may
change only through reported fee increases and group-ID assignment; the client
recomputes the final canonical group ID and reconstructs appended resource
dummies, including their embedded LogicSig authorization. Unreported body
changes and inconsistent reports are rejected locally.

Schema-v1 composed YAML rejects `bounded`; schema v2 requires it. Every schema
version rejects unknown and duplicate fields at every level. Bounded reserves
user namespace `bounded_` and composer label namespace `__aplane_bounded1_`.
`bounded.runtime_args` and `bounded.derived_args` declare the only permitted
Layer 3 slots. V1 supports caller runtime values with explicit maximum/exact
length contracts and the signer-derived `merkle_allowlist_proof` primitive.
The optional typed `bounded.layer3` object selects a framework-owned policy. V1 supports
`policy: fixed_allowlist`, with parameter references
`recipients_parameter`, optional `asset_ids_parameter`, optional
`max_payment_amount_parameter`, and optional
`max_asset_amount_parameter`. A framework-owned policy rejects author `teal`.
Its address and asset lists are inline, canonical, and independently capped at
30 entries. A Layer-3-gated spending-key rekey requires `pay` in the fixed
allowlist's `spend_effects`. Omitting `bounded.layer3` selects contained custom
author TEAL.

A profile with `bounded.cosigner` may not declare a
`spending_key`-authorized rekey. The combination would bypass the spend-only
cosigner gate and is not routable through `bounded-cosigner1`; schema-v2 template
and durable metadata validation reject it. Cosigner-enabled profiles use
`admin_key` rekey to escape a failed cosigner or replace the current program.
That path requires both the base spending signature and the external admin
signature; the admin key cannot recover a lost spending key.

V1 also supports `policy: merkle_allowlist`. It accepts only a required
`recipients_parameter` bound to `address[]` with 1-65,536 entries and requires
exactly one 512-byte `merkle_allowlist_proof` derived argument for that same
parameter. The composer computes the fixed-depth root and emits the complete
proof verifier; author TEAL, asset filters, and amount options are forbidden.
Recipients are unique raw address public keys sorted ascending; leaves,
padding, commutative internal-node hashing, and bottom-up proof ordering are
defined normatively in
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md#merkle-allowlist-compatibility-contract).

### External Contract Admin Artifact Contract

`aprekey` owns external contract-admin witness custody. Its encrypted
artifacts use the `.wit` extension and filenames of the form
`<WITNESS_KEY_ID>.wit`. They are not signer-managed `.key` or `.cos` files
or `apstore` `.apb` backup bundles. The helper rejects every other extension
before parsing or passphrase work. The signer and `apstore` must not import,
decrypt, back up, or restore these artifacts.

The top-level JSON contract is:

```json
{
  "schema": "aplane.witness-key-bundle.v1",
  "key_type": "aplane.witness-falcon1024.v1",
  "witness_key_id": "<52-character ID>",
  "public_key_hex": "<canonical lowercase hex>",
  "encryption": {
    "envelope_version": 2,
    "salt": "<base64>",
    "nonce": "<base64>",
    "ciphertext": "<base64>",
    "kdf_time": 2,
    "kdf_memory": 65536,
    "kdf_threads": 4
  }
}
```

The complete file is bounded to 65,536 bytes. The decoder rejects unknown
fields and trailing JSON values. Before prompting or invoking Argon2id, it
requires the exact schema and key type, a matching Witness Key ID, an exact
1,793-byte Falcon-1024 public key, envelope version 2, the exact KDF parameters
above, a 32-byte decoded salt, a 12-byte decoded nonce, and an AES-GCM
ciphertext of at least 16 bytes. Unknown top-level or private-payload schemas
return stable code `unsupported_artifact_schema`. A reader must not honor
attacker-selected alternatives.

The nested envelope is the reviewed standalone encryption contract:
Argon2id derives a 32-byte key using time 2, memory 64 MiB, and parallelism 4;
AES-256-GCM encrypts the private payload with a random 12-byte nonce. The GCM
operation uses no external additional authenticated data. Instead, the
encrypted payload duplicates `key_type`, `witness_key_id`, and
`public_key_hex`; all three must exactly equal the validated public header
after authenticated decryption.

The decrypted payload schema is `aplane.witness-key-private.v1`. It
contains the duplicated public identity, base64 JSON byte field
`private_material`, and an RFC3339Nano UTC `created_at`. Private material is
the canonical 2,305-byte Falcon-1024 private key. The reader derives and
verifies the public key and performs a sign/verify self-test before use.
Private plaintext, private key bytes, passphrases, and temporary signatures
must be cleared on success and failure.

Generation also writes
`<WITNESS_KEY_ID>.wit.json` with schema
`aplane.witness-key-public.v1`, `key_type`, `witness_key_id`, and
`public_key_hex`. This sidecar is public convenience data only. The encrypted
artifact's public header is authoritative and remains sufficient for inspect, verify,
matching, and recovery when the sidecar is missing or stale. Both outputs are
created atomically without overwrite as regular mode `0600` files in an
existing non-symlink directory. Each output is committed atomically; the pair
is not a transactional filesystem unit, and the public sidecar can always be
reconstructed from the committed artifact.

Successful `aprekey generate` output is:

```json
{
  "schema": "aplane.bounded-admin-generate-result.v1",
  "reference": {
    "schema": "aplane.witness-key-public.v1",
    "key_type": "aplane.witness-falcon1024.v1",
    "witness_key_id": "<52-character ID>",
    "public_key_hex": "<canonical lowercase hex>"
  }
}
```

The result does not contain filesystem paths. Callers derive the two generated
filenames from `--out` and `reference.witness_key_id` using the canonical
`.wit` and `.wit.json` suffixes. Moving the generated files does not invalidate
the result or either file.

### Contract Admin Ceremony Contract

`aprekey rekey` and `unrekey` are the interactive online clients for
admin-key-authorized bounded rekeys. They resolve `--client-data` before
`APCLIENT_DATA`, use the configured signer endpoint and selected client
network, obtain `aplane.bounded-admin-partial.v1` from `/sign/bounded-admin`, and
submit through that network's Algod endpoint. Unknown SSH host keys fail
closed. Apshell and apconsole have no contract-admin artifact workflow.

`prepare-rekey` and `prepare-unrekey` perform signer planning, policy, approval,
group finalization, and spending-partial creation, then write a strict
`aplane.bounded-admin-request.v2` to `.apbounded-admin-request`. V2 adds the
optional cosigner authorization record to the request-hash transcript; V1
requests are rejected with `unsupported_request_schema` so version-skewed
offline helpers fail explicitly rather than reporting a generic hash mismatch. Offline `sign`
validates the request and writes `aplane.bounded-admin-signature.v1` to
`.apbounded-admin-signature`. Networked `complete` consumes the pair and submits
without contacting apsigner or replanning.

The request has `schema`, `payload`, and `request_hash_hex`. Its payload carries
the complete bounded-admin partial, selected network, genesis hash, and current
authorization address. The response has `schema`, `request_hash_hex`,
`contract_admin_key_id`, and `signature_hex`. The SHA-512/256 request hash uses
the frozen length-prefixed transcript in `internal/boundedadmin/protocol` and
binds every signer-partial and network-context field.

Offline `sign` validates the network token syntax and the exact genesis hash on
every transaction. For `mainnet`, `testnet`, and `betanet`, it also requires the
token to match APlane's canonical built-in genesis-hash mapping. An air-gapped
helper has no trusted copy of requester-local custom mappings, so a custom token
such as `localnet` is displayed as not independently verified offline; the exact
genesis hash remains transaction-checked and request-hash-bound. Networked
`complete` rechecks custom mappings against the selected client configuration.

Requests are bounded to 512 KiB and responses to 16 KiB. Readers reject unknown
fields, trailing JSON, wrong extensions, non-regular files, oversized input,
unknown schemas, and mismatched request hashes. Writers create regular mode
`0600` files atomically and refuse overwrite. Ceremony files are non-secret but
carry short-lived signing authority. Before submission, `complete` rechecks
network/genesis, current authorization, validity rounds, program binding, and
both signatures. It performs no automatic retry or approval refresh.

## Admin Protocol

The admin protocol contract, including error codes and admin client capabilities, is in
[ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md).

## apshell Parsing Contracts

The apshell parsing contracts are in [ARCH_REPL.md](ARCH_REPL.md#parsing-contracts).

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
([ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md)), with the same layout on both
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
change mints a new generation (see [Policy Documents](#policy-documents)).
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

## On-Disk Formats

The signer data directory layout and the store formats (store root, term
envelopes, managed credential files, key type records, template files, and
stage address tables) are in [ARCH_STORE.md](ARCH_STORE.md).

### Client Data Directory Layout

The client data directory layout and its notes are in
[ARCH_DATA_MODEL.md](ARCH_DATA_MODEL.md#client-data-model).

### Policy Documents

The document format, semantic rules, and storage rules are specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md). Files in
`identities/default/generations/<selected-generation>/`, identical on both
node roles:

| File | Meaning |
|------|---------|
| `default.json`, `default.json.hmac` | The node default: governs every key without a document of its own; required in every generation |
| `policies/<selector>.json`, `policies/<selector>.json.hmac` | One key's own document; `<selector>` is an Algorand address on a signer node, a Witness Key ID on a cosigner node |
| `deleted/policies/<selector>.json[.hmac]` | The pair of a deleted key |

`default.json` and its sidecar are generation authority files, pinned in the
manifest and seal. `policies/` and `deleted/policies/` are generation leaf
namespaces. Deleting a key (`storemut.DeleteKey`) archives its policy pair
under `deleted/policies/` on both roles.

The policy integrity key is derived inside `internal/crypto` from the named
product-store term key with HKDF-SHA256 using info string
`aplane policy integrity v1`. The derived 32-byte key is neither persisted nor
returned to policy callers; they use keyring-confined sign/verify operations.

Sidecar JSON fields:

- `version`: integer sidecar version; currently `2`
- `algorithm`: currently `hmac-sha256`
- `key_id`: currently `keystore-master-hkdf-v1`
- `integrity_term`: positive term whose derived policy-integrity key signs the
  document
- `hmac`: hex HMAC-SHA256 over the exact policy document bytes
- `policy_sha256`: optional diagnostic SHA-256 of the policy document
- `signed_at_unix`: optional diagnostic signing timestamp

Only `version`, `algorithm`, `key_id`, `integrity_term`, and `hmac` are
security fields. Sidecar JSON is strict: unknown fields, trailing documents,
and non-canonical MAC encodings are rejected.
`policy_sha256` and `signed_at_unix` are diagnostic
metadata; tampering with those fields does not affect the policy integrity
decision. The HMAC is not bound to a file name, so every document's signed
`key` field (`default` or the selector) must equal the file it is stored as,
and its signed `role` must equal the node role.

Digests: every document `sha256` covers the exact stored bytes; nothing is
re-serialized. `policy_set_sha256` is the lowercase hex SHA-256 over the
sorted lines `<key> <document sha256>\n`, one per document, where `<key>` is
`default` or the selector. It is the optimistic-concurrency base for apply.

Policy load behavior:

- unlock/reload verifies every policy document against its sidecar and decodes
  it for the node role and its file name; a missing `default.json`, a missing
  or mismatched sidecar, or a decode failure makes the node refuse to load
- a key with no document of its own is governed by the default; on a
  cosigner node the shipped default is deny-all, so such a key rejects every
  component request with `transaction_type:<type>` until it is given a
  document
- during initial locked startup, a policy integrity failure prevents the
  admin-auth unlock from completing and is reported as `auth_result` with
  `code:"unlock_failed"`
- reload failure keeps the previous in-memory policy active
- each signing request resolves policy per signing key (`PolicyFor`) from one
  snapshot captured when its signing service is built; a reload never changes
  a request in flight
- store validation (`storevalidate`) loads and verifies the policy and
  verifies archived policy sidecars
- passphrase rotation re-signs every policy sidecar, archived ones included;
  restore rollback restores `keys/`, `keytypes/`, and per-key `policies/`
  (re-signed under the current term) and keeps the outgoing `default.json`
- a key's own policy travels with it in backups on both roles: restore
  installs the archived document with the key, a different destination
  document is a conflict that `replace_existing` resolves, and a destination
  document is kept when the archive carries none; `default.json` is never in
  a backup

Policy change behavior (shared by the daemon and rescue through
`internal/signerapp/policyapply`):

- every apply or removal verifies the active policy, requires
  `expected_policy_set_sha256` to equal the active `policy_set_sha256`,
  validates the change, and mints one new generation with operation
  `policy-apply`; a change that leaves the set unchanged commits nothing
- each committed apply leaves the outgoing generation retained until explicit
  generation pruning
- a change adds or replaces each listed document (each named by its `key`:
  `default` or a selector), deletes each key in `remove`, and keeps unlisted
  documents; `default` can be replaced but not removed, a removed key must
  have a document of its own, and a key appears at most once across
  documents and removals
- a node holds at most 8,192 per-key documents (`policyapply.MaxPolicies`);
  a change past the cap is rejected with `policy_set_too_large`
- online changes require an unlocked signer store and reload the runtime from
  the committed generation

Operator verbs:

- `apadmin policy [rescue] VERB` requires a verb; with no verb it is a usage
  error. Verbs: `status` (the default's digest, size, and applied time, each
  held key's coverage as `own policy` or `default`, stored documents for
  keys not held as `key not held`, and `policy_set_sha256`),
  `export [--key K]` (exact stored bytes of the default, or of key `K`'s own
  document), `check FILE...|-`, `diff FILE...|-`, `apply [--yes] FILE...|-`,
  `remove [--yes] K...` (`default` is refused), `template [--key K]` (the
  node's current default as the starting document for `K`, or annotated as
  the default itself; fails rather than falling back when the node or store
  is unreachable), and `template --embedded signer|cosigner [--key K]` (the
  shipped default, written locally without a node or passphrase)
- policy files given to `check`, `diff`, and `apply`, and text in the apadmin
  TUI editor, may carry `//` and `/* */` comments outside strings; apadmin
  removes them before sending, so the node receives, checks, digests, and
  stores the stripped document. A file with no comments is sent byte for byte
- each file is one document and names its key in its `"key"` field; several
  files apply in one commit, and documents for unlisted keys stay unchanged
- `diff`, `apply`, and `remove` show the effective change for each key: a
  new per-key document against the default the key followed, a replacement
  against the key's own document, a removal against the default the key
  will follow, and a changed default with the held keys it governs; lines
  are marked tightened, loosened, or changed
- `apply` and `remove` run check first, print warnings, stop on errors,
  print the diff, ask for confirmation on the controlling terminal unless
  `--yes` is given, and then apply against the `policy_set_sha256` read at
  the start; output names the committed generation or reports
  `policy unchanged`
- `check` warns about a document for a key the node does not hold ("policy
  is for a key this node does not hold") and reports document advisories; a
  key on the default is not a coverage gap
- online verbs use admin IPC, authenticate, and may unlock a locked signer
  store
- `apadmin policy rescue` accesses the store directly and rejects
  `--ipc-path`: read verbs hold the shared store lock; `apply` and `remove`
  hold the exclusive store lock and therefore require a stopped daemon. A
  root-run rescue change of a production store restores the owner recorded
  in root-controlled `install/service-principal.json` before returning
- `apstore policy check` validates every stored document (the default and
  each per-key file) without verifying sidecars and warns about missing
  sidecars and documents for keys not held; `apstore policy verify` verifies
  sidecars and compiles the policy; `apstore policy sign` validates and
  re-signs every sidecar in the selected generation for hand-placed
  documents

### Cosigner And Contract-Admin Files

The managed credential file format is in
[ARCH_STORE.md](ARCH_STORE.md#managed-credential-files).

#### Cosigner Public Key Export Envelope

`apadmin cosigner export <witness-key-id> [output-json]` emits a public-only JSON
envelope for a cosigner key. The command reads the
`keys/<witness-key-id>.wit.json` sidecar, verifies that `<witness-key-id>`
equals the canonical Witness Key ID derived from the public key, and never reads
or decrypts private key material. If the sidecar is missing or malformed,
export fails closed; the operator must regenerate the cosigner key or run an
explicit metadata backfill before exporting.

The envelope schema is shown below. The Falcon public key hex is abbreviated in
this prose example; persisted envelopes contain all 3,586 hex characters.

```json
{
  "schema": "aplane.witness-key-public.v1",
  "key_type": "aplane.witness-falcon1024.v1",
  "witness_key_id": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "public_key_hex": "0000...0000"
}
```

`witness_key_id` is the 52-character uppercase base32 selector derived as
`base32_no_padding(SHA512_256(field("APLANE_WITNESS_KEY_ID_V1") ||
field(key_type) || field(canonical_public_key_bytes)))`. It resembles an
Algorand transaction ID and is not a valid Algorand address. Role-specific
wire and cosigner-reference records retain the field name `component_key`.
`public_key_hex` is the raw component
public key encoded in hex; it is the value embedded into guarded-account
LogicSig bytecode and supplied as `cosigner_public_key` during guarded account
generation. The envelope makes no endpoint, policy, ownership, freshness, or
trust claim.

During enrollment, apshell displays the complete SHA256 fingerprint
of the key that signed SSH authentication, including agent-selected keys.
The admin enrollment request already carries that fingerprint; this adds no wire
field. It identifies the requesting client key, not an individual request,
the server host key, or a Witness Key ID.

#### Cosigner Key File

`apadmin cosigner export <witness-key-id> [output-json]` and the apadmin TUI's
**Export Cosigner Key** emit the canonical `aplane.witness-key-public.v1`
document and nothing else:

```json
{
  "schema": "aplane.witness-key-public.v1",
  "key_type": "aplane.witness-falcon1024.v1",
  "witness_key_id": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "public_key_hex": "0000...0000"
}
```

The daemon returns the document over the admin protocol; the operator process
validates it, re-serializes it canonically (`witness.MarshalPublicReference`:
the field order above, two-space indentation, one trailing newline), and
writes it locally with owner-private permissions. The file carries no
endpoint, reference alias, endpoint alias or role, client credential, SSH identity,
`known_hosts` entry, cached live inventory, private witness material, policy,
or proof of endpoint ownership. The cosigner's address is not a file contract
at all: the operator reads it from the export result screen (the configured
`endpoint.advertise_url`, or a placeholder) or from the deployment, and gives
it to each client for `endpoints add <url>`. The earlier
`aplane.cosigner-enrollment.v1` composition envelope, which could carry an
endpoint block, and the `apadmin cosigner enrollment export|import` commands
are gone; the system is unreleased, so no reader for them remains.

#### Cosigner Public Key Reference Library

`apadmin cosigner import <public-json|-> <name>` imports an
`aplane.witness-key-public.v1` document into the product store's public
cosigner reference library. The operator-side adapter validates the document,
refusing any field beyond the public reference, and sends its canonical form
through IPC:

```text
identities/default/cosigners/<name>.json
```

Reference names are normalized to lowercase and may contain lowercase letters,
digits, `.`, `-`, and `_`. The persisted record schema is:

```json
{
  "schema": "aplane.cosigner-public-key-ref.v2",
  "name": "lab-cosigner",
  "component_key": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "key_type": "aplane.witness-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "0000...0000",
  "public_key_size": 1793,
  "public_key_sha256": "d3a3deeec37ef5e50a463a2b1f8c9c6fc934a5c824a0c1cfd027d035a03b923a",
  "imported_at": "2026-06-04T00:00:00Z"
}
```

The catalog is populated only by explicit operator import. Only the version 2
record schema is read; records in any other schema, or carrying fields outside
it, are rejected.
When the source is `-`, stdin is reserved for the bounded public JSON document.
Local operation obtains the store passphrase from `APSIGNER_PASSPHRASE` or a
controlling terminal. Unsupported
headless combinations fail before authentication instead of sharing stdin
between the envelope and passphrase.

Human list output leads with the operator-assigned reference name and a compact
10-leading/10-trailing Witness Key ID. Detailed JSON retains the complete ID
and also exposes a closed
migration marker when present.

The library is a generation convenience and trust-input inventory for the user
signer. When generating a dedicated guarded account or a cosigner-enabled bounded
template, callers may provide
`cosigner=<witness-key-id>` instead of `cosigner_public_key=<hex>`.
`cosigner=<name>` is also accepted as a compatibility input. The signer resolves the
Witness Key ID or name to `public_key_hex`, verifies that the reference key type
matches the definition's required cosigner key type,
rejects requests that provide both forms, and persists the resolved
`cosigner_public_key` plus the template's other creation parameters in the key
file. `aplane.corridor.v1`, for example, persists its public recipient list and
complete bounded metadata; later signing does not require the YAML source to
remain installed.

Product `/keytypes` metadata may expose imported references as a
creation parameter named `cosigner` with `type:"select"` and `options[]`
containing Witness Key IDs whose cosigner key type matches the guarded
account key type. This is UI metadata for generation clients such as `apadmin`;
the durable key file still stores the resolved `cosigner_public_key`; other
provider-specific creation parameters remain exposed normally.

The `apadmin` TUI also receives the optional `cosigner_component_key_type` in
its internal admin key-type projection and joins it with
`list_cosigner_references`. Guarded generation displays aliases but submits the
canonical Witness Key ID. A sole compatible authority may be preselected;
multiple authorities require an explicit picker choice. When none exists, the
TUI opens an in-flow public-envelope enrollment review instead of exposing a
raw `cosigner_public_key` editor. The review locally validates the envelope and
shows the complete grouped Witness Key ID before the authorized import RPC.
The public `/keytypes` DTO and external SDK contract are unchanged by this TUI
projection.

#### External Contract Admin Inventory

Contract-admin private keys never appear in signer inventory. Bounded account
rows expose the immutable derived `admin_key_id`, program binding, Layer-3
policy, and other non-secret bounded-authorization metadata. Apsigner does
not report artifact availability because `.wit` custody is
external and intentionally outside the signer data model.

`/keytypes` exposes the framework-injected scalar
`bounded_admin_public_key` (`type:"bytes"`) parameter for profiles that authorize
an operation with `admin_key`. It accepts exactly a 1,793-byte Falcon-1024
public key and publishes no Contract Admin Key ID input or signer-local key
option. Generation derives the ID from the public key.

### Audit Log

JSONL at `audit.log`, `0600` permissions, fsynced per write, UTC timestamps.

Audit entries may include:

- `principal`: principal field,
- `requester_principal`: principal that requested the action,
- `approver_principal`: principal that approved or rejected the action,
- `admin_session_id`: admin protocol session ID when the event came from an admin session,
- `transport`: `ipc`, `ssh`, `http`, or omitted for process events,
- `remote_addr`: remote address when available,
- `reason`: rejection, failure, or denial reason when available,
- `outcome`: requested, approved, rejected, failed, connected, disconnected, or similar action outcome.

Requester and approver remain distinct principal fields in the log shape.

Rotation:

- size-based at 10 MB
- rotate to `audit.log.1`
- previous `audit.log.1` rotates to `audit.log.2`
- two rotated generations retained

Events:

- `SERVER_START`
- `SERVER_STOP`
- `SERVER_STOP_INCOMPLETE`
- `SIGN_REQUEST`
- `SIGN_APPROVED`
- `SIGN_REJECTED`
- `SIGN_FAILED`
- `AUTH_FAILED`
- `AUTH_FAILURES_SUPPRESSED`
- `COSIGNER_REJECTIONS_SUPPRESSED`
- `AUTHORIZATION_DENIED`
- `KEY_RELOAD`
- `KEY_GENERATED`
- `KEY_DELETED`
- `KEY_IMPORTED`
- `KEY_REJECTED`
- `BACKUP_CREATED`
- `BACKUP_IMPORTED`
- `BACKUP_EXPORT_STARTED`
- `BACKUP_FAILED`
- `BACKUP_RESTORE_PREVIEWED`
- `BACKUP_RESTORE_PREVIEW_FAILED`
- `CREDENTIAL_RESTORE_INTENT`
- `CREDENTIAL_RESTORE_SUCCEEDED`
- `CREDENTIAL_RESTORE_FAILED`
- `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN`
- `CREDENTIAL_RESTORE_ROLLBACK`
- `STORE_INITIALIZED`
- `STORE_INITIALIZE_FAILED`
- `PASSPHRASE_CHANGED`
- `PASSPHRASE_CHANGE_FAILED`
- `SESSION_CONNECTED`
- `SESSION_DISCONNECTED`
- `IDENTITY_LOCKED`
- `CLIENT_ENROLLMENT_REQUESTED`
- `CLIENT_ENROLLED`
- `CLIENT_ENROLLMENT_REJECTED`
- `CLIENT_KEY_REVOKED`

Signing-audit semantics:

- `SIGN_APPROVED` is emitted only for transactions the signer actually signs
- foreign and passthrough entries may appear in `SIGN_REQUEST`/planning context, but are not recorded as `SIGN_APPROVED`
- signing audit over HTTP records `transport:"http"` and the connection's `client:<fingerprint>` principal as requester
- cosigner-role component signing currently records approvals and policy
  rejections through `SIGN_APPROVED`/`SIGN_REJECTED`; `txn_auth` is the
  Witness Key ID, `txn_sender` is the decoded target sender, and
  `policy_rule_id` carries the deterministic cosigner rule when present
- approval audit enriches approved/rejected records with the admin session approver principal when an admin response supplies it
- approved/rejected signing records include `policy_rule_id` when a policy rule forced manual review before the operator decision
- admin authorization-denial audit records event `AUTHORIZATION_DENIED`, outcome `denied`, admin session ID, transport, principal attribution, action/resource details in `reason`, and remote address when available
- session connected/disconnected audit records the admin session ID, transport, principal, and remote address
- key-management audit events are emitted for both REST and authenticated IPC admin operations
- `KEY_REJECTED` is emitted when signer key scanning skips a key file that
  violates a load-time key-file invariant; for LogicSig salt failures,
  `reason` includes the key filename and rejection reason

Backup-audit semantics:

- `BACKUP_CREATED` is emitted when an authenticated admin backup operation
  writes a managed archive; `reason` contains the archive path
- `BACKUP_IMPORTED` is emitted after an uploaded archive passes deep
  verification and is published into the managed backup set
- `BACKUP_EXPORT_STARTED` is emitted on the first successful chunk read for a
  managed archive transfer, including when a client starts at a non-zero
  offset; reaching EOF closes the inferred transfer for subsequent auditing
- `BACKUP_FAILED` is emitted when backup creation, import commit, or export
  streaming fails; `reason` contains the failure reason
- `BACKUP_RESTORE_PREVIEWED` is emitted when an authenticated preview operation successfully decrypts and inspects a managed archive; `reason` contains the resolved archive path and `key_count` contains previewed keys
- `BACKUP_RESTORE_PREVIEW_FAILED` is emitted when an authenticated preview request fails; `reason` contains the failure reason
- `CREDENTIAL_RESTORE_INTENT` is durably audited before restore can make its
  first generation-store write. It records the operation ID and
  `replace_existing`; durable-write failure aborts with no store mutation.
- `CREDENTIAL_RESTORE_SUCCEEDED` and `CREDENTIAL_RESTORE_FAILED` carry the
  available archive SHA-256, operation ID, replacement option, and key count.
- `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN` distinguishes a visible store-root
  replacement whose directory-sync durability could not be confirmed; signing stays
  recovery-blocked until reconciliation confirms the root and reloads the
  visible generation.
- `CREDENTIAL_RESTORE_ROLLBACK` records explicit rollback success or failure.
  Failed attempts use `outcome:"failed"` and `reason`.

Store-management audit semantics:

- `STORE_INITIALIZED` is emitted when authenticated local IPC store initialization succeeds
- `STORE_INITIALIZE_FAILED` is emitted when authenticated local IPC store initialization fails
- `PASSPHRASE_CHANGED` is emitted when authenticated local IPC passphrase rotation succeeds; re-encrypted key/template counts are recorded on the event
- `PASSPHRASE_CHANGE_FAILED` is emitted when authenticated local IPC passphrase rotation fails
- `CLIENT_ENROLLMENT_REQUESTED` is emitted when a new `request-enrollment` request is queued (a repeat that refreshes an existing entry is not audited again); its principal and requester are `client:<fingerprint>`, and it carries the remote address and `client_label`
- `CLIENT_ENROLLED` is emitted when an admin session enrolls a key, by approving its queued request or by importing the public key; it carries the key fingerprint, the `client_label` recorded, the request's remote address (empty for an import), and the admin session attribution
- `CLIENT_ENROLLMENT_REJECTED` is emitted when an admin session rejects a queued request; it carries the fingerprint, `client_label`, and admin session attribution
- `CLIENT_KEY_REVOKED` is emitted when an admin session revokes one enrolled key or every key; it carries the fingerprint, `client_label`, closed-connection count, and admin session attribution

## Authentication, SSH, and Client Enrollment

The client's enrolled SSH key is its only credential. There is no API token,
no `Authorization` header, and no credential file on either side: an HTTP
request is authenticated by the SSH connection it arrived on.

SSH server uses Ed25519 host keys, auto-generated at `.ssh/ssh_host_key`.

Normal clients send the fixed non-secret username `aplane` and authenticate by
public key. The key must be enrolled in `identities/default/.ssh/authorized_keys`
(see the registry contract under the signer data layout). Enrollment is checked
in the public-key callback and again, against the installed registry, after the
handshake completes, so a key revoked while its handshake was in flight is
refused. The server accepts only Ed25519, ECDSA (P-256/384/521), and
hardware-backed `sk-` keys; the public-key algorithm list refuses other key
types before any signature is verified.

An `aplane` connection may open only `direct-tcpip` channels to loopback
destinations; session channels are refused. Each accepted channel is handed off
in-process to the HTTP server as an `sshtunnel.APIConn` carrying the connection's
key fingerprint, which the HTTP server attaches to the connection context as
`auth.ConnIdentity`. The product authenticator maps that fingerprint, if it is
still enrolled, to the principal `client:<fingerprint>` with role `client`.
Nothing in a request can supply or override the connection identity. The
loopback TCP listener on `endpoint.signer_port` attaches no identity: it answers
`/health` and returns `401` with `Authentication required: connect through an
enrolled SSH key` for every other route. Unauthenticated responses carry
`Connection: close` so a client that cannot authenticate cannot hold a
connection slot with keep-alive requests.

The SSH server allows at most 64 concurrent pending handshakes and closes
excess arrivals; one remote address may hold at most 8 of them. Authentication
has a 60-second socket deadline, cleared after successful authentication.
Accepted sockets are tracked before authentication so shutdown also closes
stalled handshakes. The limit applies to pending authentication, not
established sessions.

Client TCP dialing and SSH authentication share one setup timeout (60 seconds
by default). Setup cancellation closes the socket to interrupt blocked I/O.
Successful connections detach from that setup timeout; their established
connection lifecycle remains separately owned.
The setup timeout also covers interactive first-use host-key approval, giving
the operator time to compare the displayed fingerprint.

Client enrollment flow:

1. client connects as `request-enrollment` with any supported key
2. server rejects every other username before SSH auth succeeds
3. the exec request `enroll` or `enroll <label>` is accepted on that
   connection; the label is at most 64 bytes of printable single-line text,
   and any other command is answered `ERROR: unknown command` with exit 1
4. a key the registry already holds is answered `enrolled <fingerprint>`
   with exit 0 and nothing is queued; like every success answer read from
   the registry, it is given only once the registry is durable (a registry
   left by an earlier failed write is re-published first, and the request
   fails with `ERROR: failed to record enrollment request` if that fails)
5. otherwise the server records the request (public key, label, remote
   address, time) in `identities/default/.ssh/pending_enrollments.json`,
   written atomically and durably like the registry, and under the same
   rule for a write that fails after its rename: a request the file then
   holds is a queued request for the operator (audited, announced) and the
   queue is re-published before its next write, but the client is answered
   `ERROR: enrollment request recorded but not yet durable; retry the
   request`, exit 1, so it retries and is answered `pending` only once the
   queue is durable (the retry refreshes the entry and is not audited or
   announced again); a new request is audited as
   `CLIENT_ENROLLMENT_REQUESTED` and announced to a connected admin session
   as `client_enrollment_request`; a repeat for a waiting key refreshes its
   entry. Refusals are `ERROR: enrollment queue is full; ask the operator to
   clear it and try again` and `ERROR: failed to record enrollment request`,
   exit 1
6. server replies `pending <fingerprint>` with exit 0; the client checks the
   fingerprint against the key it authenticated with and disconnects. Nothing
   is stored on the client
7. later, an admin session approves (`approve_enrollment`: the key and label
   are added to the registry under the publication rule, the entry is
   removed, `CLIENT_ENROLLED` is audited) or rejects (`reject_enrollment`:
   the entry is removed, `CLIENT_ENROLLMENT_REJECTED` is audited). The audit
   event follows the change that took effect, not the command's outcome: a
   key that entered the live registry is audited as enrolled even when the
   approval then reports a durability failure or could not clear the entry
   (a repeat approval clears it without a second `CLIENT_ENROLLED`; rejecting
   such a request is refused so the queue and the registry never disagree
   about the key), and a request dropped by a write that is not yet durable
   is audited as rejected. Labels written by the admin protocol follow the
   same rule as client-supplied ones: printable single-line text of at most
   64 bytes. Every
   waiting request is announced again when an admin session authenticates
8. the client learns the outcome by connecting: an enrolled key is accepted,
   anything else is refused at the handshake

The server answers without waiting for the operator, so enrollment never
takes the approval coordinator's delivery turn away from signing. No
credential is issued at any step: the enrolled key is the credential.

The queue is loaded once at startup, like the registry, and a queue file the
daemon cannot read completely refuses to serve. It is bounded because its
writers are unauthenticated: one entry per key, at most 16 waiting keys
(`enrollqueue.MaxPending`), and entries lapse after 7 days
(`enrollqueue.TTL`). Waiting requests survive a daemon restart.
The queue document has `schema_version: 1` and a `requests` array. Each request
stores `public_key` (an OpenSSH line), optional `label` and `remote_addr`, and
`requested_at` (a JSON timestamp). The parser and publication owner is
`internal/signerapp/enrollqueue`; the product runtime serializes queue and
registry mutations under the same lock.

An operator may also pre-enroll a key with `import_client_key` (one OpenSSH
public-key line; its comment is the label unless one is given). Imports reject
authorized_keys options, including reserved `aplane-` options, and trailing key
lines with `invalid_request`; unsupported restrictions are never silently
discarded. The key type check is the same as for `request-enrollment`, the
write follows the publication rule, a waiting request for the same key is cleared, and
`CLIENT_ENROLLED` is audited with an empty remote address.

Product-facing clients request enrollment with the fixed `request-enrollment`
username. Limits: one enrollment request per connection, at most 8 enrollment
connections and 2 session channels per connection, a 30-second deadline to
start the request, and a 10-second deadline for the client to accept the
response.

Revocation behavior (`revoke_enrolled_key`, `revoke_all_enrolled_keys`):

- rewrite the registry without the key under the publication rule,
- send `key-revoked@aplane` to every SSH connection that key authenticated,
  then close those connections and report the count,
- refuse the key's next handshake.

`sshtunnel.Server.CloseConnectionsForFingerprint(fingerprint, reason)` and
`CloseAllClientConnections(reason)` close connections by key. If SSH
authentication races a revocation, the post-handshake re-check against the
installed registry refuses the connection.

SSH server callbacks are startup-only. Key checking, key enrollment,
operator checks, enrollment approval and audit, session notifications, and the
API channel handoff must be configured before `Start`; setters fail fast after
the server has started.

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

- `transaction_types` `reject` (rule `transaction_type:<type>`; evaluated
  first and alone, so nothing else is reported for a rejected type)
- `reject_foreign_rekey` (rejects foreign rekey targets; rekeying to an address held by the current signer is allowed)
- `reject_close_remainder`
- `reject_asset_close`
- `reject_clawback`
- `max_fee_microalgos`
- network- and asset-scoped `limits` `reject_above`
- `transfer_policy` blocked destinations, route misses,
  close/clawback denials, and `reject_above` thresholds for direct `pay` and
  `axfer` movements

Policy documents store amounts as decimal strings in base units (microAlgos
for ALGO); review and rejection text use display units.

Always-review policy includes:

- `transaction_types` `review` (rule `transaction_type:<type>`; evaluated
  first in the tier)
- `always_review_warnings`: require operator review for requests that carry
  warning-level approval findings, such as rekey, close-out, clawback, asset
  close, application delete, clear-state, or update, asset reconfigure or
  destroy, asset freeze, or unusually high fees.
- network- and asset-scoped `limits` `review_above`
- `transfer_policy` `on_no_route: review` route misses and
  `review_above` thresholds for direct `pay` and `axfer` movements

Auto-approval policy includes:

- `auto_approve_self_noop_transfer`: approve a single signer-controlled request without operator review only when the real transaction is either a 0 ALGO payment to self or a 0-unit ASA transfer to self, has no caller-provided group, no passthrough/foreign slots, no rekey, no close remainder, no asset close, no clawback sender, no note, no lease, and its fee after subtracting signer-added dummy fees is at most 1000 microAlgos. Server-generated LogicSig-resource dummy transactions are allowed only when they use APlane's embedded dummy LogicSig address, match the real transaction's network and validity window, carry no fee, and the real transaction fee increase exactly covers those dummies. Priced program bytes and native-PQ fee contributions disable this narrow auto-approval. The ASA form may opt into an asset if the account does not already hold it.

`user_auto_approve` is not an auto-approval policy rule. It is the product-runtime
fallback switch stored in product runtime config and shown in `apadmin` as
`User Auto-Approve`. It controls only the operator-default fallback after
auto-rejection, forced review, and explicit auto-approval have all had a chance
to run.

Every policy setting above, `transfer_policy` included, is persisted only in
policy documents: the node default (`default.json`) or the signing key's own
document (`policies/<selector>.json`), on both node roles. The signing key
selects the document; the node role selects the field set. Documents are
validated by the normal policy load path and by `apstore policy
check|verify|sign`. `apadmin policy` applies whole documents online through
admin IPC, and `apadmin policy rescue` applies them against a stopped
daemon's store; both store the exact submitted bytes. There is no scalar
policy-settings IPC.
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
- application `OnCompletion` `DeleteApplication`, `ClearState`, and
  `UpdateApplication`
- asset reconfigure (`acfg` on an existing asset, naming the resulting
  Manager, Reserve, Freeze, and Clawback addresses) and asset destroy
- asset freeze and unfreeze
- excessive fees above 1 ALGO

Warnings are displayed but do not block approval. They are relevant to the
manual review fallback path; when `always_review_warnings:true`, warnings force
operator review before auto-approval or the `user_auto_approve` fallback can
sign the request. Groups get group-level approval; single transactions get
transaction-level approval. Signing approval timeout is the product-runtime
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

## Runtime Ownership and Shutdown

The signer owns one product `*productruntime.Runtime` directly. There is no live
identity-decommission state or operation lease. Graceful shutdown stops and
drains request servers before destroying runtime key state. Lock, disconnect,
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

Plugin-initiated requests back into apshell are reserved but not installed in
production. The JSON-RPC client keeps typed request plumbing for future
reviewed callbacks such as account/balance/app metadata lookup, but absent a
production handler inbound plugin requests fail closed with `method not found`.
There is intentionally no `signTransaction` callback: plugins cannot ask
apshell to sign arbitrary bytes on their behalf.

`initialize` carries network/algo context including:

- `network`
- `algodUrl`
- `algodToken`
- optional `indexerUrl`

The host does not send its accepted plugin protocol identifier. A plugin must
independently declare the hard-coded identifier `"aplane-plugin/2"` in
`initialize.result.protocol`. A missing or different declaration fails plugin
startup. The identifier is distinct from the JSON-RPC envelope version
(`"2.0"`), from `manifest_format` (`"2.0"`), and from the plugin's semantic
package version.

`execute` carries:

- selected plugin command
- argv-style args
- execution context including known accounts, alias/address maps, structured asset metadata, network metadata, suggested params, and continuation state

Plugins return:

- optional `message`
- `transactions` using raw unsigned msgpack transaction intents only
- optional `data`
- optional `presentation`
- optional `requiresApproval`
- optional `continuation`
- optional `groupMode` with `pregrouped-signed` or `presign-plan` for
  plugin-owned signing material

Top-level `localSigners` is intentionally unsupported. If present, apshell
rejects the plugin result instead of accepting plugin-supplied secret keys.

`data` is the canonical machine-readable payload.
`presentation` is optional human-oriented display metadata for apshell text rendering.
Raw `data` is not part of the default human CLI rendering contract.

Manifest contract:

- plugin directories must contain `manifest.json`
- required manifest fields: `name`, `version`, `description`, and `executable`
- `manifest_format` defaults to `2.0`; only `2.0` is accepted
- `timeout` is seconds and defaults to 30
- at least one executable command is required
- each command requires `name` and `description`
- the retired `functions` metadata field is rejected; commands are the sole
  executable and discoverable manifest surface
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

Eight MCP tools:

| Tool | Parameters | Purpose |
|------|-----------|---------|
| `execute` | `command` (string) | Execute shell commands |
| `mcp_reference` | none | Return the shell command reference |
| `js` | `code` (string) | Execute JavaScript with structured results |
| `js_reference` | none | Return the JavaScript API reference |
| `mcp_manual` | none | Return the condensed apshell MCP operating manual |
| `doc` | `name` (string, optional) | List bundled curated reference docs, or return one doc by name |
| `jssave` | `path` (string), `filename` (string, optional alias), `code` (string, optional), `last` (bool, optional), `overwrite` (bool, optional) | Save JavaScript for later execution |
| `jslist` | none | List saved JavaScript scripts in the data directory's `scripts/` folder |

Shared behavior:

- stdout is reserved for MCP JSON-RPC
- command output is redirected to stderr
- execution is serialized with an in-process mutex
- auto-confirm is enabled
- built-in aliases resolve to their primary command before automation policy is applied

### `execute` tool

The `execute` tool description is built from a static reference plus plugin `mcp.md` files.

Each permitted built-in and plugin command executes through the same handler as
the REPL and returns one semantic result. The REPL renders its human
presentation; MCP marshals its explicit safe machine projection. MCP never
captures terminal output as an `execute` result, and a structured success with
nil, empty, or invalid JSON is rejected.

Machine projections are allowlists. They omit secrets, authorization headers,
credential paths, raw config, signed transaction bytes not deliberately in the
contract, terminal-only render lines, and the plugin-reserved `localSigners`
data field.

JSON results are returned as text containing JSON bytes via `mcp.NewToolResultText(string(data))`, not as typed JSON content objects.

Blocked commands in `execute`:

- `js` (use the `js` MCP tool instead)
- `jssave` (use the `jssave` MCP tool instead)
- `jslist` (use the `jslist` MCP tool instead)
- `help` (use `mcp_reference`)
- `config` (use the safe `status` command)
- `script`
- `request-enrollment`
- `clear`
- `quit`, including aliases `exit` and `q`
- `keyreg` paste mode

Blocked commands reject before handler invocation. `keyreg` with explicit
arguments remains a structured command.

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

### `mcp_manual` tool

Returns the embedded `USER_MCP_MANUAL.md` operating manual text. No
parameters. Stateless.

### `doc` tool

Lists or fetches bundled curated reference docs. With no `name`, it returns the
curated bundled doc index. With `name`, it returns the matching bundled
Markdown doc; names may be supplied with or without `.md`.

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
- `ErrNotEnrolled`
- `ErrEnrollment`
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

The companion SDK source communicates via the same HTTP REST API as `apshell`,
through an SSH tunnel authenticated with the client's enrolled SSH key;
requests carry no auth header. SDK implementation and release publication are
owned by the separate `aplane-algo/aplanesdk` repository.

Cross-SDK compatibility-bearing behavior:

- concatenated-group and list-per-slot signing APIs are distinct supported shapes
- passthrough semantics are first-class for final signing; passthrough
  LogicSigs require selected-path `lsig_resources`, with observable sizes
  checked against the signed envelope
- high-level signing helpers return base64 payloads converted from server hex
- `FromEnv` and connection helper path resolution are part of the product contract
- Enrollment helpers return the authenticating key's SHA256 fingerprint and
  pending/already-enrolled state, validating the reply against the local key.
  Pending means the request was queued for later admin approval; it does not
  authorize API connections. Go exposes `RequestEnrollment`, TypeScript
  `requestEnrollment`, and Python `request_enrollment`, with endpoint-selecting
  from-env variants. Go uses `ErrNotEnrolled` for refused client authentication
  and `ErrEnrollment` for enrollment failures; TypeScript and Python expose
  `AuthenticationError` and `EnrollmentError` for those respective failures.
- SDK-native prepared transaction models carry unsigned transaction bytes plus
  signer metadata such as effective auth address, optional LogicSig args,
  optional selected-path LogicSig resource hints, optional app-call display metadata, and
  SDK-side preflight checks. Prepared groups preserve caller/apshell-equivalent
  transaction ordering before handoff to `/plan`, `/sign`, or the
  guarded component flow.
- For equivalent normalized typed transaction intents, SDK prep should converge
  with apshell's core prep behavior for transaction fields, suggested params,
  flat-fee handling, auth-address semantics, LogicSig runtime args, app-call
  metadata, and group ordering. SDKs do not need to copy shell grammar,
  aliases, prompts, or rendering.
- For ordinary APlane-managed signing, SDK prep must not take ownership of
  final group ID assignment, signer-managed dummy insertion, fee pooling,
  policy, approval, or signing. Those remain apsigner-owned behavior behind
  `/plan` and `/sign`.
- Go, Python, and TypeScript SDKs expose a typed low-level
  `/sign/bounded-admin` request that returns
  `aplane.bounded-admin-partial.v1`. This API handles no external contract-admin
  artifact, does not append the admin argument, and must describe the response
  as incomplete and not submission-ready. Applications that implement
  completion must conform to the frozen bounded protocol and independent
  validation rules; ordinary SDK signing helpers reject admin-key operations.
- Guarded prepared signing requires frozen canonical bytes before component
  signatures are requested. The normative SDK sequence is: classify guarded
  targets; construct intended original transactions; send those originals plus
  signer-advertised structured LogicSig resource hints to `/plan`; validate the
  returned canonical group and mutation report; derive the
  target/context/dummy position partition; locally sign only the canonical
  dummy suffix returned by `/plan`; obtain the required user, cosigner, or
  bounded-base components; call ordinary `/sign` for any non-guarded original
  positions; and call `/sign/assemble` with the frozen group and signed
  passthrough positions. Resource hints are planning inputs, not locally
  inserted transactions. Final guarded assembly remains signer-owned, and
  submission or simulation uses the exact assembled group. User-role
  `/sign/component` requests run the signer-domain approval gates and can block
  on operator approval, so SDK deadlines for them follow the same
  approval-aware rule as `/sign`, not the short cosigner-role component deadline.
- Guarded simulation uses the same component and assembly flow as submission.
  The client obtains ordinary user and cosigner component signatures, signs local
  non-guarded legs through `/sign`, assembles through `/sign/assemble`, verifies
  the frozen canonical bytes, and only then sends the exact executable group to
  its configured algod simulation endpoint.
- SDKs expose the authenticated `/status` DTO, including
  `protocol_version`, `build_version`, `keyset_revision`, and
  `approval_wait_seconds`, plus optional persistent operator-facing `warnings`,
  and include the matching signer API fixture in their contract suites.
- SDKs decode non-2xx HTTP bodies as `signerapi.ErrorResponse` with top-level
  `error` plus a stable machine-readable `code`
  (`pkg/signerapi/error_codes.go`). Clients classify failures by `code`
  (empty when the server does not supply one), never by `error` message text.
  Endpoint-specific success DTOs are not the error envelope.
- SDK/client `/sign` deadlines must be long enough for the product-runtime
  signer approval wait. The repo-owned signer client discovers
  `/status.approval_wait_seconds` and uses that value plus slack; external SDKs
  should avoid defaults shorter than the configured approval wait. When
  `/status` discovery fails or `approval_wait_seconds` is omitted,
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

- `ConnectSSH(host, sshKeyPath, opts)` establishes the SSH tunnel with the client key, then HTTP
- `FromEnv(opts)` resolves the client SSH identity and signer endpoint routing from the client data dir
- `NewSignerClient(baseURL)` supports caller-owned transport and direct client construction
- `SetHTTPClient(client)` overrides the HTTP transport for advanced callers.
  If caller-owned transport sets a global timeout shorter than the effective
  signing approval wait, the SDK cannot extend that deadline.
- `GetKeysResponseWithContext(ctx)` returns the raw `/keys` DTO. In-tree client
  code carries locked-signer state in an internal wrapper, not in the HTTP DTO.
- `GetStatusWithContext(ctx)` returns the raw `/status` DTO for keyset
  revision and approval-wait discovery
- `PlanRequestsWithContext(ctx, requests)` and `SignRequestsWithContext(ctx, requests)` expose server-shaped `/plan` and `/sign` request flows directly
- raw request methods operate on SDK DTOs (`SignRequest`, `KeysResponse`,
  `PlanGroupResponse`, `GroupSignResponse`) rather
  than the base64-returning convenience layer. The `/sign` response is
  `GroupSignResponse`.
- `Config.NewAlgodClient(network)` is part of the supported Go SDK config surface
- `SigningArg` is the `/keys` name for `RuntimeArg`
- input uses `go-algorand-sdk` `types.Transaction`

TypeScript and Python SDKs preserve the same broad behaviors:

- high-level convenience signing APIs return base64 payloads and may reject
  unresolved foreign placeholders when they cannot project empty foreign slots
  into single-payload returns
- list-returning and raw request APIs preserve per-slot outputs, including
  native `/sign` foreign slots returned as empty strings
- signer status helpers expose `/status` and are used to size signing
  request deadlines when callers do not provide an earlier explicit timeout
- raw `signRequests` / `sign_requests` APIs accept one or more `/sign` request
  entries and expose the native `/sign` response for adapters that already own
  transaction encoding
- simulation helpers use ordinary raw signing APIs and then call the SDK's
  client-configured algod simulation endpoint with the returned executable group
- AlgoKit Utils adapters are optional client-side projections over the native
  SDK client. They provide the AlgoKit `addr` plus transaction-signer shape and
  call raw `/sign` for the indexes AlgoKit asks them to sign. They do not
  mutate or re-plan groups or run the SDK-native typed prep layer.

Primary SDK sources live in the separate MIT-licensed
`aplane-algo/aplanesdk` repository. When `APLANE_SDKS_REPO` points at a local
SDK checkout, this repo's `make integration-test` and `make integration-test-reuse`
targets also run the SDK live signer integration suites through
`test/run-sdk-integration.sh`; when unset, that bridge is skipped, and when set
to a non-directory path, the make target fails before running SDK tests.

Committed JSON golden fixtures for signer API contract tests live under
`test/contracts/signerapi/` and round-trip through the public DTO structs in
`pkg/signerapi`. These fixtures are compatibility source material for this
repository and the external SDK repository: update them intentionally with any
wire-contract change, not as generated test runtime state.
With an SDK checkout available,
`make contract-sync-check APLANESDK_DIR=/path/to/aplanesdk` verifies that the
copied fixture trees match. The normal in-repo `contract-test` target does not
perform that cross-repository comparison.
Cross-language SDK prep parity fixtures are owned in the external SDK
repository because they exercise SDK transaction builders rather than signer
HTTP DTOs; update them when SDK prep request-shape behavior intentionally
changes.

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
