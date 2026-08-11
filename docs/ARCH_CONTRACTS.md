# Engineering Contracts

> Compatibility-bearing wire formats, on-disk formats, and behavioral contracts.
> For system orientation, ownership, and architecture, see [ARCH_SPEC.md](ARCH_SPEC.md).
> For key and key type lifecycle state machines, see [ARCH_KEY_LIFECYCLE.md](ARCH_KEY_LIFECYCLE.md).
> For the explanatory network context model, see [ARCH_NETWORKS.md](ARCH_NETWORKS.md).
> For the current signer policy verdict model, see [ARCH_POLICY.md](ARCH_POLICY.md).
> For guarded signing and sentry node architecture, see [ARCH_SENTRY.md](ARCH_SENTRY.md).
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

Until APlane reaches a stable `v1.0` compatibility contract, in-place
installer upgrades are intentionally narrow:

- existing install directories are supported in place only when their
  `install/release.json` reports at least the installer's minimum supported
  upgrade version,
- install directories below that floor or without release metadata require a
  fresh install root unless the operator explicitly passes the installer
  `-f`/`--force` upgrade-check override,
- no config, key, cache, or endpoint migration utility is shipped,
- signer identity stores unlock only with keystore marker version 5 and the
  `keyring/v2` layout tag; stores in any other format are rejected at
  unlock, rotation, rebuild, and policy-sign. Keys move between installs via
  backup archives restored into a freshly initialized store,
- usable apclient signer routing is endpoint-based and lives in
  `endpoints.yaml`; top-level client `config.yaml` `ssh:` and `signer_port:`
  routing is rejected in this release,
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
  `aplane.htlc.v1`, `aplane.falcon1024-allowlist.v1`, and
  `aplane.falcon1024-allowlist-alock.v1`
- witness keys use the same canonical key-type identifier contract,
  currently `aplane.witness-falcon1024.v1`; signer-custodied instances serve
  as sentry component-signing keys selected by 52-character txid-shaped
  Witness Key IDs, not spending accounts. The
  compatibility wire/storage field name for that selector remains
  `component_key`.
- external bounded contract-admin authorities use the same witness key type
  and Witness Key ID, but private material remains in a structurally distinct
  standalone `.wit` container owned by `aprekey`. It is never a signer-managed
  `.key`/`.sen` credential or spending account.
- `aplane.falcon1024-allowlist-alock.v1` is reserved for the schema-v2
  framework-owned bounded1 allowlist. Its spending key and contract admin key
  are both Falcon-1024. Bounded1 has no Ed25519 contract-admin variant and no
  admin-key algorithm selector.
- the dedicated guarded account key type
  `aplane.falcon1024-sentry1024.v1` names both its account DSA and sentry DSA.
  `aplane.corridor.v1` is instead an optional schema-v2 composed template: its
  durable `bounded_authorization` metadata declares `bounded1`, a `sentry1`
  spend gate, and the framework Merkle allowlist policy. Clients must not infer
  those dimensions from the key-type string.

Witness key records carry no role field. Enrollment assigns the role and
custody assigns signing capability: networked signer custody may produce only
the `APLANE_SENTRY_V1` component-domain family, while standalone ceremony
custody may produce only `APLANE_BOUNDED_ADMIN_AUTH_V1`. One witness keypair
should serve only one role for its lifetime. Generation rejects collisions
visible in local key metadata and sentry references, but cannot detect or
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
  is Falcon-1024, but their account semantics and sentry assembly are guarded
  account semantics.
- `Family` / `FamilyName` on Go provider types are registry/display metadata.
  Current family-keyed registry fallback is an implementation detail, not a
  replacement for canonical `key_type` identity.

## HTTP API Contract

See [ARCH_HTTP_API.md](ARCH_HTTP_API.md) for the HTTP request/response wire shapes, status codes, identity routing, and cancellation semantics.
The DTO and error-code source of truth is `pkg/signerapi`; `internal/signerapi`
contains aliases for in-repo callers, not an independent schema.

### Sentry Component Message Contract

Component signatures for guarded signing sign:

```text
SHA512_256("APLANE_SENTRY_V1" || role_byte || txid)
```

where `role_byte` is `0x01` for the user component role and `0x02` for the
sentry component role, and `txid` is the canonical 32-byte transaction ID for
the target group entry. Message construction is owned by
`internal/sentry/message`; clients and signers must use that shared primitive,
or an SDK equivalent with matching vectors, rather than reconstructing the
message independently. The message does not carry a separate sender or
authorizer field; guarded-authorizer binding is derived from the canonical
transaction bytes and verified during assembly by requiring the guarded
LogicSig address, and `AuthAddr` when needed, to equal the requested guarded
account.

### Bounded Authorization Contract V1

`bounded1` is the only bounded-authorization contract. It has no protocol
aliases; bounded admin operations use `POST /sign/bounded-admin` and the
bounded1 DTOs defined below.

This release is the first supported `bounded1` contract. Earlier repository
vectors and developer-generated keys were pre-release and are not
compatibility-bearing; such keys must be recreated. The canonical profile and
goldens below, including the optional-sentry presence encoding, establish the
v1 baseline.

Bounded1 uses TEAL v12 and admits only pure payments, pure asset transfers,
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
u32(sentry_present) ||
if present: field("sentry1") || field("aplane.witness-falcon1024.v1") ||
u32(1280) || u32(1) || field("spend") ||
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
runtime values do not. A sentry-enabled profile does include its injected
`sentry_public_key` behavior parameter. Static runtime/derived declarations and
path masks are part of the canonical profile above.

The sole bounded1 contract admin primitive is Falcon-1024. Its public key is
exactly 1,793 bytes and its signature is non-empty and at most 1,280 bytes. The
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

For `bounded-sentry1`, the user signer also returns a Falcon-signed assembly
receipt. With `field` as above, `metadata_json` equal to JSON encoding of the
normalized durable `bounded_authorization` structure, and runtime arguments
sorted by name, its message is:

```text
SHA512_256(
  field("APLANE_BOUNDED_SENTRY_ASSEMBLY_V1") ||
  field(bounded_account) ||
  field(transaction_id) ||
  field(SHA512_256(metadata_json)) ||
  u32(runtime_arg_count) || field(name) || field(value) || ...
)
```

Assembly verifies this receipt with the bounded spending public key before it
accepts the base component or sentry signature.

For the complete vector inputs in `ARCH_BOUNDED_DSA.md`, the frozen outputs are:

```text
Contract Admin Key ID:
MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ

bounded_program_binding:
23aebf3166f64d6a0e6467d0fde647191094907f733c60fb946129d7cc828509

admin_message:
324dfa8eee495b7f4ddaa67f640c906184beb49abfd304d1336be233e84998b6
```

Argument slots are statically ordered as base signatures, signer-derived Layer
3 values, caller runtime Layer 3 values, the optional sentry signature, and the
optional admin signature.
Each slot has a frozen index, maximum, source, and path mask. Interior unused
Layer 3 slots are explicit empty values; only trailing unused slots may be
omitted. An admin-key partial omits the admin slot, and external completion pads
to and fills the metadata-declared admin index. Ordinary `/sign` rejects
caller-supplied contract-admin, sentry, or signer-derived values. The frozen
flow labels are `bounded1` for profiles without a sentry and
`bounded-sentry1` for profiles with the sentry spend gate. The typed admin
partial endpoint remains `POST /sign/bounded-admin`; bounded-sentry spend uses
`POST /sign/bounded-component`, sentry-role `POST /sign/component`, and
`POST /sign/bounded-assemble` in that order.

Signer planning classifies for initial path sizing, finalizes grouping, dummy,
and fee mutations, then validates the finalized transaction at the single
classification boundary. Execution verifies plan integrity and loaded metadata
equality without maintaining a second classifier. Assembly accepts only
declared caller runtime slots and generates only declared derived slots; it
rejects wrong-source, oversized, missing, forbidden, hybrid, disabled, and
profile-fee-invalid requests. Every non-spend bounded path carries the unconditional stable rule
`bounded_admin_operation_requires_review` into the approval gate before blanket
or self-no-op autoapproval.

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

A profile with `bounded.sentry` may not declare a
`spending_key`-authorized rekey. The combination would bypass the spend-only
sentry gate and is not routable through `bounded-sentry1`; schema-v2 template
and durable metadata validation reject it. Sentry-enabled profiles use
`admin_key` rekey to escape a failed sentry or replace the current program.
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
`<WITNESS_KEY_ID>.wit`. They are not signer-managed `.key` or `.sen` files
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
optional sentry authorization record to the request-hash transcript; V1
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

An unlock can also succeed into recovery mode: when the passphrase verifies
but generation reconciliation or validation of the selected generation fails,
the result reports `success:true` with a zero key count and
`code:"recovery_blocked"`. The identity is then unlocked for administration
only — signing is blocked until the operator resolves the store from recovery
mode. Clients must treat `recovery_blocked` as a store-integrity state
distinct from both `unlock_failed` and credential rejection.

The pre-auth `auth_only` request verifies the same passphrase and binds the
admin session without authorizing or invoking `identity.unlock`. Read-only
clients use a distinct message type so an older server rejects it before
processing instead of silently unlocking. Bound-only sentry-reference,
generation-inventory, and endpoint-settings reads use this mode; operations
whose handlers require unlocked or recovery state continue to use `auth`.

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
including `key_type_in_use` for template disable/removal or compiled-provider disable and
`restore_rate_limited` for managed restore preview/restore throttling. The Go
source of truth for these result-local codes is `internal/protocol`; producers
and CLI consumers must share those constants instead of maintaining parallel
string lists. See the corresponding payload sections and contract tests before
treating the central protocol list as exhaustive. Consumers should dispatch on
`code` when present and treat prose `error` as display text or untyped fallback,
not as an authoritative result-code source.

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
| Policy editor | yes | no | no | no |
| Async notifications | yes | limited | limited | no |

`appass` edits config offline; it is outside the live IPC surface.

`apadmin` uses the shared full-document policy editor. Policy reads,
validation, and mutation use canonical policy YAML through
`get_policy_snapshot`, `validate_policy`, and `replace_policy`; there is no
parallel scalar policy RPC surface.

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
It supports optional `schema_version: 1`; absent means v1 for existing configs,
and unsupported versions fail during load.
Installer-written client configs include `networks` entries for `testnet`,
`mainnet`, and `localnet`, but restrict `networks_allowed` to `mainnet` and
`testnet` by default; existing configs are left unchanged if the installer is
pointed at a supported in-place upgrade target.
Unknown YAML fields are rejected by the Go loader with guidance that the file
may have been written by a newer version or may contain a typo.

The Go `Config` type contains no signer-routing fields. Current signer and
sentry routing is loaded from `endpoints.yaml` into `ClientEndpointRegistry`.
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
- SDK config loaders are intentionally similar but not strict mirrors of the Go
  client loader: Go, TypeScript, and Python expose SDK-only
  `ssh.trust_on_first_use`; Go rejects an empty `ssh.host` when an `ssh:` block
  is present; TypeScript only enables SSH when `ssh.host` is truthy and falls
  back to defaults on config read/parse errors; Python rejects an SSH block
  without `host`

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

Process-global settings live in `config.yaml`. Identity-scoped settings live in `identities/<identity>/config.yaml` and nil means inherit from process defaults. `decommissioned:true` disables the identity.

Signer policy participates in the ordered approval engine.
The active node-role policy is identity-scoped and stored in
`identities/<identity>/policy.yaml`, with a sibling `.hmac` sidecar that
authenticates the exact YAML bytes with a key derived from the identity master
key. Signer nodes parse it as client-signing policy; sentry nodes parse it as
direct sentry component policy. The default approval fallback is
`user_auto_approve`, lives in `identities/<identity>/config.yaml`, and is not a
policy document field. The policy document is verified and loaded on
unlock/reload before the key scan; a missing policy file or missing/mismatched
sidecar fails closed instead of falling back to defaults. Authenticated admin
IPC policy operations are target-aware by policy domain, and role-incompatible
targets fail closed. Direct YAML edits are checked, signed, and verified
through `appolicy` or `apstore policy`.
Policy and sidecar bytes are both staged and synced before either path is
published. HMAC, encoding, or staging failure therefore preserves the prior
pair. Interruption between the two publication renames can still leave a
mixed pair, which verification rejects fail-closed and requires explicit
repair.
Both policy domains support YAML-only `key_overrides` blocks for per-key
effective policy. Client-signing overrides are keyed by Algorand auth address;
sentry overrides are keyed by Witness Key ID. These overrides apply to
policy phases and can be changed through authenticated full-document
`replace_policy`, or by direct/offline YAML editing followed by `appolicy` or
`apstore policy` signing before the signer will trust the edited document.
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
  30 minutes. The default is `60s`. Identity config may override the process
  default for that identity.
- initialized signer data roots must contain root `node.yaml` with role
  `signer` or `sentry`. New initialization defaults to `signer` unless an
  sentry node is explicitly requested. Identity config `mode` is an
  unsupported field and is rejected.
- node role gates key generation, mnemonic import, restore, signer key reload,
  and signing service dispatch. Hand-placed key files or restored keys from the
  forbidden role are not usable; role-conflicting active inventory fails closed
  for the node.
- node role parsing and `node.yaml` integrity sidecars are owned by
  `internal/noderole`; role-versus-key-type allowance decisions are owned by
  `internal/keyclass`.
- each identity's `node.yaml.hmac` is strict sidecar version 2 with algorithm
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

- missing `keyring.enc` is not a startup error; it forces locked-start behavior
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
- identity-owned settings and policy writes are serialized by the target identity's mutation lock
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

Sources: `internal/signerapp/unlockconfig/unlock.go` owns identity-scoped
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
- SSH binds `<endpoint.ssh.listen_address>:<endpoint.ssh.port>` and forwards to
  loopback REST. The default `endpoint.ssh.listen_address` is `127.0.0.1`.
- `endpoint.signer_port`, `endpoint.ssh.*`, and `endpoint.advertise_url` are
  configured in signer `config.yaml`. Admin settings may report those values,
  but do not mutate listener bind or handoff URL state. Changing
  `endpoint.signer_port` or `endpoint.ssh.*` requires restarting apsigner.
- Admin settings may also report `endpoint_display_url` for UI chrome. This is
  not exported endpoint handoff metadata and must not be persisted by admin
  clients as `endpoint.advertise_url`.

## On-Disk Formats

### Signer Data Directory Layout

```text
<data_dir>/
  config.yaml
  node.yaml
  audit.log
  .apstore.lock
  cache/
    .cache_key
    <network>_asa_cache.json
  library/
    templates/*.yaml        # plaintext KeyType Library YAML sources
  backups/<identity>/
    *.tar.gz                # restorable managed/imported backup archives
    .import-*.part          # unpublished bounded upload residue
    .import-claimed-*.part  # immutable archive undergoing deep validation
    .import-validation-*/   # private same-filesystem validation residue
  .ssh/ssh_host_key
  identities/<identity>/
    CURRENT                 # names the active generation (generation layout)
    generations/<gen-id>/
      manifest.json         # immutable at-mint operation record
      seal.json             # final content record, written before flip-away
      keys/*.key            # account authority, selected by Algorand address
      keys/*.sen            # sentry witness authority, selected by Witness Key ID
      keys/*.wit.json       # derived public witness reference; not private authority
      keytypes/<key_type>.json      # key type state record
      keytypes/<key_type>.template  # encrypted key type template
    keyring.enc             # cryptographic root: KDF header over the sealed
                            # term set (aplane.keyring.v2)
    .keystore               # static marker: version 5 + keyring/v2 layout (the
                            # only supported store format; others rejected)
    node.yaml.hmac
    aplane.token
    config.yaml
    policy.yaml
    policy.yaml.hmac
    unlock.yaml
    .ssh/authorized_keys
    passphrase              # plaintext appass-file helper artifact, mode 0600
    passphrase.cred         # systemd-creds helper artifact, mode 0600
    sentries/<name>.json
    deleted/keys/*.{key,sen}
    deleted/keytypes/<key_type>.template
```

Additional signer-state notes:

- production signer directories are service-owned mode `0700` and ordinary
  signer files are service-owned mode `0600`; the recognized root-owned
  exceptions are `identities/<identity>/passphrase.cred` (`root:root`, `0600`)
  and installer metadata under `install/`. Systemd setup writes
  `install/service-principal.json` as root-owned `0640` metadata containing
  schema version 1 and the numeric service `uid`/`gid`; stopped-store repair
  uses that root-controlled record and never infers its target from the store
  root being repaired
- systemd admin IPC defaults to `/run/apsigner/aplane.sock`; the runtime
  directory is service-owned `0750` and the socket is `0660`. Same-UID local
  mode defaults to `<data_dir>/aplane.sock`. An explicit systemd `ipc_path`
  must be outside the signer store in a service-user-owned directory that is
  not writable by group or other users. Trusted root/current-owned directory
  aliases are resolved and both the alias and canonical directory chains are
  validated before the daemon binds the canonical socket path. A reachable
  existing listener is a hard collision; startup removes only a stable socket
  inode that rejects a connection as stale. Bind paths are limited to the
  portable 103-byte Unix-socket pathname maximum.
  An explicit client `--ipc-path` has highest precedence and must be absolute.
  An explicit client `-d` is resolved next and cannot be retargeted by inherited
  `APSIGNER_IPC_PATH`; the absolute environment socket override still takes
  precedence
  when the data root came from `APSIGNER_DATA`, which supports unreadable
  custom managed stores, and it may be used without a data root when the
  socket path alone identifies the signer. Otherwise normal data-root and
  runtime discovery apply. Once a selected root's `config.yaml` is visible, IPC discovery reads
  it strictly: read failures are errors and must never silently select a
  default socket for another store. The systemd installer derives the paired `apenv.sh` value through
  `approbe signer-ipc-path`, which uses this same resolver rather than parsing
  `ipc_path` independently in shell. The read-only environment audit uses the
  same command with `--honor-ipc-env` when its signer root was not explicitly
  selected, preserving the normal `APSIGNER_DATA`/`APSIGNER_IPC_PATH` pairing.
- `.apstore.lock` is the cooperative signer-store lock used by live signer startup and the local `apstore rebuild` rescue path
- signer-managed backup archives are written under
  `<data_dir>/backups/<identity>/`; the archive contains `README.md` and
  `apb/*.apb` encrypted canonical credential payloads plus `manifest.sealed`
- imported backup archives are validated by the operator client, streamed to
  the daemon in bounded admin-protocol chunks, and atomically published under
  `<data_dir>/backups/<identity>/`; exports stream bounded chunks in the other
  direction, so operators never need filesystem access to the private locker
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
  .codex/config.toml
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
- `apconsole.yaml` supports `mode: local|remote`, `client_data`, and local-mode `signer_data`; relative paths resolve against the profile file
- `endpoints.yaml` is the normal client-local endpoint registry for new installs, with `schema_version: 1`, a derived `default` signer endpoint alias, and user-defined endpoint aliases under `endpoints:`. Endpoint aliases are local references only; they are unique within one `APCLIENT_DATA` and use only ASCII letters, digits, `.`, `_`, and `-`.
- if client `config.yaml` contains top-level `ssh:` or `signer_port:` routing, client startup fails closed with an operator-facing message directing the operator to configure `endpoints.yaml`. Startup never materializes or rewrites endpoint routing.
- endpoint records carry connection profile fields together: required `role` (`signer` or `sentry`), `url` (`ssh://host[:port]`, loopback `http://...`, `https://...`, or `self` where supported), `signer_port`, `local_port`, `identity_file`, `known_hosts_path`, `token_file`, and endpoint-published `published_sentries`. Relative file paths resolve against `APCLIENT_DATA`. A registry may contain at most one `signer` endpoint; if present, that endpoint is the effective default. `published_sentries` is valid only on `sentry` endpoints.
- endpoint token files are bearer credentials. The default signer endpoint commonly uses `APCLIENT_DATA/aplane.token` unless overridden. Non-primary endpoints default to `APCLIENT_DATA/tokens/<endpoint-alias>.token`. Reads reject group/world-accessible token files and token writes create owner-only files.
- `published_sentries` is keyed by canonical embedded sentry public-key hex. Each record carries `component_key`, `key_type`, and `last_seen_at`; runtime guarded-send routing derives the endpoint for an embedded sentry public key from this endpoint-local inventory.
- signer `config.yaml` may set `endpoint.advertise_url` to the client-reachable endpoint URL used by `apstore endpoint export` when the operator omits both `--host` and `--url`. This is operator-declared routing metadata, not a value inferred from the SSH bind address. It follows the same portable URL rules as endpoint envelopes and rejects `self`. The daemon projects it and the configured endpoint ports through authenticated admin settings; the client does not traverse the private store.
- `apstore endpoint export` emits a public `aplane.endpoint.v1` JSON envelope for operator handoff after reading endpoint defaults through authenticated admin IPC. URL precedence is `--url <url>`, then `--host <client-reachable-host>` deriving `ssh://<host>:<endpoint.ssh.port>`, then the daemon-reported `endpoint.advertise_url`; if none is present, export fails with guidance to pass `--host`/`--url` or configure `endpoint.advertise_url`. For SSH URLs it includes the daemon-reported `endpoint.signer_port` unless overridden with `--signer-port`. `--url <url>` is for explicit HTTPS, loopback HTTP, forwarded SSH ports, or unusual deployments. Like other portable JSON handoff envelopes, it uses a single `schema: "aplane.endpoint.v1"` discriminator. The envelope is strict JSON with portable endpoint URL and signer/local ports only. It must not contain client-local aliases, endpoint-role metadata, sentry public-key metadata, bearer tokens, private keys, mnemonics, encrypted key payloads, passphrases, or `known_hosts` trust entries; exported envelopes reject `url: self` because `self` is client-local state. File output is published by the operator process with owner-private permissions and refuses symlink destinations.
- `apshell endpoints import --alias <alias> --role signer|sentry [--dry-run] <endpoint-json>` validates that envelope and writes client-local endpoint routing only: `$APCLIENT_DATA/endpoints.yaml`. Import replaces existing endpoint data when the alias matches. If the imported URL already belongs to a different alias with the same role, import fails without writing; the same URL may be represented by one `signer` alias and one `sentry` alias for dev co-location. Import is not an ownership or trust proof and does not discover sentry keys. Tokens are still obtained separately with `request-token --endpoint <alias>`, and SSH host trust is still established by the existing known-hosts flow.
- `apshell endpoints create --alias <alias> --endpoint <url> --sentryport <port> [--dry-run]` manually creates or replaces a `role: sentry` endpoint profile in `$APCLIENT_DATA/endpoints.yaml` without an endpoint envelope. `--endpoint` is the client-reachable URL, commonly `ssh://host[:ssh-port]`; `--sentryport` is stored as the endpoint `signer_port` REST port used behind SSH sentry endpoints. Manual creation has the same replacement and duplicate same-role URL rules as import. It does not discover sentry keys, copy tokens, or establish SSH host trust.
- `apshell endpoints discover-sentries [--dry-run]` scans configured `sentry` endpoints with authenticated `/keys`, extracts sentry-key `public_key_hex` values, validates each `component_key` Witness Key ID, and atomically rebuilds endpoint-local `published_sentries` inventory in `endpoints.yaml`. Reachable endpoints are refreshed; temporarily unavailable endpoints, including locked signer identities, preserve their existing `published_sentries` entries. Authentication failures, endpoint configuration errors, malformed responses, duplicate public keys advertised by multiple endpoint aliases, and Witness Key ID validation failures are hard errors and leave files unchanged. Discovery is local-only and does not require or update a connected primary signer.
- `apshell endpoints sync-sentries [--dry-run] [--yes]` performs the same endpoint discovery, then prints Witness Key IDs, not raw public keys, and requires interactive confirmation, unless `--yes` is provided, before copying the current inventory into the connected signer identity's public sentry reference catalog as source-marked `client_discovery` records. Sync carries only public metadata (`endpoint_alias`, `component_key`, `key_type`, `public_key_hex`, `last_seen_at`) and replaces only prior `client_discovery` records; manually imported records are preserved. This makes endpoint-discovered sentries selectable from signer-side key generation clients such as `apadmin`.
- `apshell endpoints sentries` lists the local endpoint-discovered sentry inventory by endpoint alias, Witness Key ID, and key type without calling remote endpoints.
- `apshell endpoints list`, `endpoints show <alias>`, `endpoints default <alias>`, and `endpoints delete <alias>` operate on local client configuration. Human endpoint output identifies sentries by Witness Key ID and must not print raw sentry public keys. `show` is local-only, does not call `/keys`, and includes `last_seen_at` for that endpoint's published sentries; `delete` refuses to remove the signer endpoint or an endpoint with published sentries still referenced by derived runtime routing.
- interactive `apshell` startup does not require a pre-enrolled client: it validates client bootstrap/config inputs, but it may start without endpoint token files or a trusted signer host so the operator can run enrollment, recovery, and troubleshooting commands
- for interactive `apshell`, token presence and SSH host trust are enforced when the shell attempts `connect`, startup auto-connect, or `request-token` flows; they are not preflight requirements for process startup
- `request-token` enrolls only configured endpoints: without arguments it uses the default signer endpoint; `request-token --endpoint <alias>` uses that signer or sentry endpoint. The removed positional host form is not accepted. After successful enrollment, `apshell` saves the selected endpoint's token and only auto-connects when that endpoint is the default signer.
- `apshell --mcp` has a stricter startup contract than interactive `apshell`: MCP startup is non-interactive and refuses to start unless the client is already enrolled (default signer endpoint, endpoint token, trusted `known_hosts`)
- `apshell --mcp` also requires the startup signer connection to succeed; it does not start in a disconnected or partially enrolled state, and it cannot perform first-use trust or token enrollment itself
- `apconsole` resolves startup inputs per field in this order: flags, environment variables, explicitly selected profile (`-config` or `APCONSOLE_CONFIG`), auto-discovered profile, then defaults
- local `apconsole` lifecycle management requires its client IPC path to equal
  the path the selected store's daemon will bind. An intentional client-only
  override must use `--no-start-daemon`; otherwise `apconsole` refuses before
  attaching to the override or starting a daemon whose readiness it cannot
  observe
- conflicting explicit inputs do not auto-resolve: if flags, environment variables, or an explicitly selected profile disagree, `apconsole` exits and requires the operator to remove the conflict or make the values match
- auto-discovered profile values are convenience defaults only; if they differ from explicit flags or environment variables, `apconsole` keeps the explicit values and emits a warning naming the ignored profile value
- local-mode signer `apconsole` may start before client enrollment is complete; it requires valid local client/signer data paths, but it allows the embedded shell to perform first-time `request-token` while the local signer/admin panes are available for approval
- local-mode sentry `apconsole` suppresses the embedded shell and renders only the admin pane plus daemon/status pane; sentry policy editing happens through apadmin in the admin pane
- for local-mode signer `apconsole`, when the client SSH host is loopback, the local signer's configured SSH host key is probed against the live loopback SSH endpoint before being pinned into the client `known_hosts` file; a mismatch aborts the trust write and shell startup, and token presence is enforced when the embedded shell attempts startup auto-connect, `connect`, or `request-token`
- remote-mode `apconsole` requires the configured client data directory to be enrolled before the UI starts: `endpoints.yaml` must define a default signer endpoint, that endpoint's token file must exist, and the configured signer host must already be present in the endpoint `known_hosts_path`
- remote `apadmin` has the same client enrollment prerequisite as `apconsole`: it requires a default signer endpoint, the endpoint token, and a trusted signer host in the endpoint `known_hosts_path`; it does not prompt for first-use host trust
- shared non-interactive client-enrollment preflight lives in `internal/clientenroll/preflight.go` and is used by `apshell --mcp`, remote-mode `apconsole`, and remote `apadmin`
- tombstones suppress locally deleted proposals for that local actor
- cache files are signed JSON with a per-client `.cache_key` and are local, rebuildable client state; the signed envelope has `version: 1`, and versioned cache payloads carry `schema_version: 1`; a missing payload version is interpreted as v1
- `signer_cache.json` is a local projection of authenticated signer `/keys`
  inventory. It may persist address key types, generic-LogicSig flags,
  `lsig_sizes`, key-file signing argument schemas, `signing_flows`,
  `sentry_component_key_types`, and `sentry_public_keys`. `lsig_sizes` is the
  signer-advertised spend-path post-signing LogicSig program+args budget used
  for dummy planning and foreign `lsig_size` hints: bytecode plus cryptographic
  signature args and any runtime or signer-generated args such as proof
  material. For bounded accounts it excludes the contract-admin signature slot:
  only the `/sign/bounded-admin` choreography attaches that signature, and the
  signer's own planner reserves its bytes when budgeting an admin-key rekey
  (the stored `post_signing_lsig_size` metadata field remains
  admin-inclusive). For guarded signing, clients route on `signing_flows`; a cached
  built-in guarded key type with missing flow or sentry metadata is only a
  stale-cache signal that triggers `/keys` refresh before route selection.
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
fingerprint is a behavior-only compatibility digest of the provider/template
definition: it hashes only behavior-bearing fields and excludes all user-facing
identifiers and display strings, so no identifier rename changes it; base key
types are projected to a stable `base_primitive` token, so a base-identifier
rename is identifier-independent too. It is versioned (`<n>:<sha256hex>`) and
compared version-aware: only a same-version, different-hash pair is a conflict,
while a different-version or malformed fingerprint is "not comparable" (benign,
never a conflict). It is provenance only — useful for conflict detection and
backup provenance checks, never read on the signing path, and not a signing
secret or authorization token.

### KeyType Library And Template Files

There are two plaintext library locations with the same relative layout:

- repository and release artifacts carry template YAML sources under top-level `library/templates/`,
- signer installations may carry a copy under `<APSIGNER_DATA>/library/templates/`.

The signer-data path is defined by `internal/storepaths.Paths.TemplateLibraryDir()`. Release installers,
installer re-runs, and test setup flows may refresh this directory from the repository or packaged copy. Files in this
directory are reference material and are not active key types by themselves.
New signer-store initialization installs and enables
`aplane.falcon1024-allowlist.v1` from the bundled library source into the
identity-local encrypted template store; sentry-role initialization skips this
signer account key type. Other bundled templates remain install sources until
explicitly imported/enabled for an identity.

The bundled templates that ship under `library/templates/` are:

| Template | Purpose |
|----------|---------|
| `aplane.falcon1024-timelock.v1` | Falcon-1024 signature gated by round-based timelock |
| `aplane.falcon1024-allowlist.v1` | Falcon-1024 signature restricted to a fixed set of receiver addresses (default-installed) |
| `aplane.falcon1024-allowlist.v2` | Falcon-1024 allowlist using a fixed-depth Merkle root with signer-generated proofs |
| `aplane.htlc.v1` | Hash time-locked contract |
| `aplane.falcon1024-allowlist-alock.v1` | Falcon-1024 bounded allowlist whose pure rekey additionally requires an external Falcon admin signature |
| `aplane.corridor.v1` | Optional bounded Falcon profile with a Merkle recipient allowlist, sentry-authorized spends, and external-admin pure rekey |

Only `aplane.falcon1024-allowlist.v1` is installed and enabled by default for
new signer stores; the rest are available to install from the library.

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
type state mutation. Store initialization uses the same encrypted template
store and enabled state-record model for default YAML key types, but runs before
the identity has a live reload surface. Activating a
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
key depends on that `key_type`; compiled-provider disable has the same
unused-key guard because it removes the identity's compiled-provider opt-in. The
unused check requires the identity's current term key, scans existing keys, and returns
`key_type_in_use` on the live admin protocol when the guard blocks installed
template disable/removal or compiled-provider disable. Live key type
enable/disable, template install, non-generic key generation, key import, and
key delete operations are serialized per identity so key creation cannot race a
lifecycle decision made from a stale state snapshot. The underlying IPC message
names remain `activate_key_type` and `deactivate_key_type` for compatibility.

### Keyring Root (`keyring.enc`)

Defined in `internal/crypto/keyring.go`. Schema `aplane.keyring.v2`, file
version 2. Fields: `schema`, `envelope_version`, `kdf_time`, `kdf_memory`,
`kdf_threads`, `salt`, `nonce`, `sealed_keyring`.

The KDF parameters and salt are plaintext because they are inputs to the
unwrap. `sealed_keyring` holds the set of numbered term keys, sealed with
AES-256-GCM under the passphrase-derived key-encryption key.

Behavior:

- unlock derives the KEK with the stored KDF parameters and unwraps the term
  set; only this release's own KDF tuple is accepted, checked before
  derivation because the KEK must exist before the AEAD can authenticate
  anything, so an edited root cannot compel work this release did not choose
- changing the KDF tuple requires bumping this file version and the keystore
  marker version with it
- the root is read as a regular file under a size limit, so an oversized or
  non-regular path is refused rather than loaded
- the header travels in the AEAD's authenticated data alongside the sealed
  term set
- the sealed payload has `schema`, `current_term`, sorted `terms`, required
  `historical_anchors`, and optional `rotation`; v2 structural validation
  rejects invalid term order, current-term selection, anchors, and pending
  descriptors before runtime use
- settled and pending multi-term payloads are accepted; ordinary current-state
  envelope and integrity reads authorize exactly `{current_term}` while
  settled and exactly `{current_term, rotation.from_term}` while pending.
  Other resident terms require the separate historical-anchor path
- `StartRotation` refuses an existing descriptor before any snapshot or root
  write, appends exactly `current_term + 1`, and publishes the new current
  term plus former-current descriptor in the same root replacement
- a refused root's decoded term keys are zeroed on every exit path, not only
  the successful one
- the successful unwrap is the passphrase check; there is no separate verifier
- the KEK is zeroed before seal and open return, and is never cached
- a passphrase change replaces this file in one atomic write
- fresh stores begin with term 1; completed roots may retain historical terms,
  and a pending root has one current and one retiring current-state authority

### Keystore Marker (`.keystore`)

Defined in `internal/crypto/keyring_store.go` as `keyringMarker`.

Version 5 is the only readable format. Fields: `version`, `layout`
(`keyring/v2`), and `created`. It carries no salt, no verifier, and no KDF
parameters, so nothing in it can disagree with the keyring.

Behavior:

- new stores are written as version 5 with the `keyring/v2` layout tag
- initialization writes the marker before the root, so a crash between them
  leaves a store that is recognizably uninitialized rather than one whose root
  exists under an unknown version
- a marker with any other version, or version 5 without the `keyring/v2`
  layout tag, is rejected with guidance to restore from a backup archive into
  a freshly initialized store; there is no in-place migration path

### Term Envelope Object Context

Every object encrypted under a keyring term records the term in the clear and
binds both the term and the object's logical identity into the AEAD's
additional authenticated data. The identity is a class plus a canonical
selector:

| Class | Selector |
| --- | --- |
| `account-key` | Algorand address |
| `sentry-credential` | Witness Key ID |
| `keytype-template` | key type |
| `rotation-snapshot` | fixed selector `pending` |
| `rotation-baseline` | fixed selector `current` |

Behavior:

- the identity is logical, never a path: generations copy ciphertext between
  namespaces and into `deleted/` without re-encrypting it, so a path-based
  binding would break on the first commit
- readers recover the identity from the canonical filename, so a file moved
  under another name fails to open
- a wrong key, an edited term header, and a mismatched object identity are
  indistinguishable failures: all three mean the envelope is not what the
  caller asked for
- passphrase rotation re-encrypts under a new term key with the same context,
  so a rotation cannot relabel a file while it rewrites it
- `crypto.EnvelopeTerm` exposes only the positive term header. Any caller
  using that term as inventory authority must open the same byte buffer with
  its expected logical context; inspecting the header alone is insufficient.

### Rotation Artifact Inventory

`internal/rotationinventory` owns the canonical K8 durable-artifact taxonomy,
snapshot scan, guarded transition-start orchestration, and the internal
snapshot-pinned resume and completion passes. `internal/storepass` owns the
operator start/complete workflow, and signer unlock owns automatic resume
before runtime publication.

Each entry contains:

- `path`: UTF-8, slash-separated, signer-data-root-relative canonical path;
- `kind`: one of the explicit credential, template, integrity
  document/sidecar, generation member, or rotation-record kinds;
- positive exact byte `size` and canonical lowercase `sha256`;
- for a term envelope, positive `term`, `object_class`, and
  `object_selector`;
- for an integrity sidecar, positive `term` with no envelope context;
- for plaintext artifacts, no term or envelope context.

Entries are strictly sorted by raw path bytes and paths are unique. Unknown
fields are not inferred from extensions outside their owned namespace:
unclassified files in generation or deleted scope fail the scan.
Independent state (`keyring.enc`, `.keystore`, backups, audit/config/unlock/
token/SSH state, plaintext template library, and caches) is excluded.

The scanner covers:

- every published generation. Current structure is validated live; retained
  generations require an authenticated seal;
- active and retained credentials/templates, key-type state, witness public
  metadata, exact manifest bytes, and retained-generation seal records;
- identity-local deleted credential and template archives;
- exact policy/node-role documents and their explicit-term sidecars;
- optional rotation snapshot and baseline envelopes as classified durable
  records.

`ScanForSnapshot` is the cutover-construction variant. It excludes
`rotation.snapshot.enc` so the body never recursively inventories itself,
while a valid baseline that predates cutover remains a classified input.
A `seal.json` beside `CURRENT` is also excluded: the generation commit
contract defines it as non-authoritative precommit crash residue. Current
generation validation still checks its structural shape, but rotation never
parses, pins, rewrites, or completion-validates its stale content.

Encrypted entries are opened from the exact byte buffer that is hashed under
the logical context derived from their canonical filename. Retained generation
buffers are also compared to their seal entry
before opening. Once ordinary retiring-term authority closes, anchored
generation members use the dedicated historical open operation rather than
regaining ordinary current-state authority. `genstore.ParseManifestBytes`,
`ParseSealBytes`, and `VerifyBytesAgainstSeal` are the buffer-based boundary;
historical consumers must not validate a path and then consume a second read.
The scanner also retains the current manifest and generation inventory
derived from those exact buffers. Rotation-start rollback decisions and
completion baselines consume that retained authority and must not rebuild it
from a second filesystem read.

While a rotation is pending, `WriteFileDurable` names
`<canonical-basename>.tmp-*` are reserved crash residue. Resume removes only
regular matching temps for each root-pinned target, fsyncs the containing
directory, and rejects non-regular matching artifacts before consuming the
canonical file.

#### Sealed Cutover Snapshot

`identities/<identity>/rotation.snapshot.enc` is a term envelope with object
context `rotation-snapshot:pending`. Its strict plaintext schema is
`aplane.rotation-snapshot.v1`:

```json
{
  "schema": "aplane.rotation-snapshot.v1",
  "from_term": 1,
  "to_term": 2,
  "inventory": [],
  "rollback": {
    "generation_id": "gen-1700000000-0123abcd",
    "decision": "clean",
    "authority": {
      "source": "generation-manifest",
      "entry_count": 0,
      "inventory_sha256": "<lowercase hex>"
    }
  }
}
```

`rollback` is omitted when the current generation has no rollback-divergence
decision to preserve. Its decision is exactly `clean` or `diverged`; authority
source is exactly `generation-manifest` or `rotation-baseline`. The inventory
is a required sorted array of the K8 entries above. The snapshot rejects
future-term inputs and any `rotation-snapshot` entry.

The effective generation inventory digest uses
`aplane.generation-inventory-digest.v1` plus a length-prefixed canonical
encoding of entry count and each `(path, decoded SHA-256, size, term)`. It
never depends on JSON formatting.

The pending root carries only `snapshot_sha256` and `snapshot_size` for the
exact encrypted file. `crypto.RotationSnapshotReference` validates and checks
that pair. The encrypted file has an independent 16 MiB limit and is read via
the no-follow bounded regular-file reader. Validation order is exact
size/digest, envelope target term, context-bound open of the same buffer,
strict plaintext parse, then `{from_term,to_term}` equality with the root.

`rotationinventory.StartRotation` reconciles the baseline, scans the cutover
inventory, evaluates the rollback-eligible current generation, and collects
the complete retained-generation anchor set before invoking
`crypto.StartRotation`. `WriteSnapshot` durably publishes the target-term
encrypted body before returning its exact root reference. Only then does
`crypto.StartRotation` atomically replace `keyring.enc` with the appended
current term, former-current descriptor, snapshot reference, and anchor set.
The caller must hold the identity mutation lock.

A failure before root rename leaves the old root and in-memory authority
unchanged; the durable target-term snapshot may be an unreferenced orphan.
On unlock, completion reopens and confirms the old settled root, classifies
an unreferenced `current_term+1` snapshot as pre-root residue, syncs the root
directory, and removes that reserved artifact durably without attempting to
authenticate it under a key the root never adopted. If the root
rename is visible but directory sync fails, the exact candidate is adopted in
memory and the caller receives `ErrRotationCommitDurabilityUnknown`. If root
visibility cannot be classified, `ErrRotationCommitStateUnknown` requires
recovery. Neither result authorizes retrying `StartRotation` as a fresh
append. The descriptor itself is the durable R5 guard.

`OpenKeyring` accepts settled and pending multi-term roots and enforces the
current-state authority set described above. Interactive and headless signer
unlock automatically run completion after generation reconciliation and
before keys, templates, snapshots, or a session can be published. Failure
enters recovery mode with signing blocked. Direct key scanning still rejects
a pending root. `Keyring.RequireSettled` is the common guard for
ordinary runtime keyring access, signing-key loads, and direct keystore
mutation. Offline passphrase change, policy signing/editing, and generation
pruning apply the same guard. `ErrRotationPending` is the stable error
classification; only the explicit resume/completion path may bypass it.

`identities/<identity>/rotation.baseline.enc` is a current-term envelope with
object context `rotation-baseline:current`. Its strict plaintext schema is
`aplane.rotation-baseline.v1` and contains exactly `schema`, canonical
`generation_id`, non-negative `entry_count`, and lowercase
`inventory_sha256`. Plaintext parsing and the exact encrypted file are bounded
to 4 KiB. `WriteBaseline` uses the durable file-replacement protocol;
`ReadBaseline` performs a no-follow bounded read, requires the envelope term
to be current, opens the same buffer under the fixed context, and rejects
unknown fields, omitted/null required fields, and trailing JSON.

`EvaluateRollbackCutover` compares the canonical live generation inventory
against the immutable manifest or a matching authenticated prior baseline and
records `clean` only on exact count/digest equality. A baseline for another
generation is never authority. Preflight reconciliation keeps a valid
matching baseline, durably removes a valid stale one, and preserves malformed
or unauthorized records as blocking evidence. The K8 scanner strictly parses
a baseline and requires it to name `CURRENT`.

Generation seal inventory entries authenticate each member's term, and exact
seal anchors gate the separate retired-term seal/member verification path.
The pending-root commit now references the durable snapshot and complete
pre-retirement anchor set.

`rotationinventory.ResumeRotation` requires a pending root and reopens that
exact root-referenced snapshot on every pass. Root-anchored historical
generation entries and plaintext entries remain exact snapshot bytes.
Mutable envelopes on `from_term` must match their pinned size and SHA-256
before the same buffer is context-opened and durably sealed onto `to_term`.
Policy and node-role sidecars are similarly renewed only after their exact
pinned document and retiring-term sidecar authenticate. On retry, an envelope
or sidecar already on `to_term` is accepted only after target-term
authentication succeeds. This makes a visible rename followed by a directory
sync error safely resumable and prevents a holder of the retiring term from
laundering substituted bytes. Reads are bounded and reject final-component
symlinks.

Resume reports durable progress but deliberately leaves the root pending and
the referenced snapshot present.

`rotationinventory.CompleteRotation` runs resume and then performs fresh K8
scans on both sides of baseline publication. Each scan must contain the exact
root-referenced snapshot, every cutover path, no unpinned path, exact
historical/plaintext bytes, and the pinned mutable kind/context under target
authority. A clean rollback cutover receives a baseline over the final
current-generation inventory; a diverged cutover never receives a new one.
The second scan requires the clean baseline to match that final inventory.
The only extra path permitted relative to the cutover snapshot is that
authenticated clean completion baseline when none existed at cutover.

`crypto.CloseRotation` preserves all resident terms and historical anchors
while atomically removing only the pending descriptor. The snapshot remains
until the settled root has been durably published and is then removed with a
directory sync. A visible close followed by directory-sync failure adopts the
settled root but retains the snapshot; retry authenticates the unreferenced
snapshot against the visible settled root, syncs the root directory, and
removes it. A pre-rename close failure leaves both in-memory and on-disk roots
pending. A snapshot-removal directory-sync failure is reported with the root
still settled; it never reopens retiring authority.

The settled-root cleanup distinguishes that post-close case from a pre-root
orphan. A same-term snapshot must authenticate and strictly parse under the
matching visible settled root before removal. A consecutive future-term
snapshot is removable only after the visible root is confirmed settled with
no descriptor; it is the unreferenced first half of start, not a completed
rotation.

Restore rollback calls `rotationinventory.EvaluateRollback`: only a baseline
that authenticates under the settled current term and names the current
rollback-eligible generation supersedes its at-mint manifest. Missing,
malformed, wrong-term, and wrong-generation records cannot assert cleanness.
After the guard accepts, rollback validates the sealed target through ordinary
current authority or its exact root historical anchor and mints a fresh
generation from only the seal-pinned member buffers. Envelopes are opened
through the corresponding ordinary or anchor-gated path and sealed under the
current term; plaintext members remain exact. The rollback manifest keeps the
outgoing generation as `parent_id` and records the content source separately
as `rollback_source_generation_id`. The superseded baseline is removed
durably only after the `CURRENT` flip.

`apstore changepass` invokes the durable transition under the identity
mutation lock. It first fences signing and clears the published runtime; only
verified completion plus reload may republish it, and a racing explicit lock
wins. Unlock and recovery entrypoints refuse to load or publish authority
while that maintenance fence is active, including the gap between unlock
reconciliation and its final key load. The new root is the point of no return:
it is published under the new
passphrase before consumer rewrap. A configured passphrase helper is updated
immediately after that commit. Helper failure is returned as a warning, never
as a rollback request or completion barrier. Any later error leaves a
resumable pending root and the runtime locked; the new passphrase is
authoritative and the next interactive or headless unlock resumes
automatically before enabling the identity. `changepass` itself refuses to
append over a pending root.
Results report migrated artifact counts, helper warnings, root-commit and
pending-rotation state, and the number of retained prior generations still
readable under historical terms. Post-commit failures preserve those fields
so clients can tell operators that the new passphrase is authoritative and
that unlock will resume the transition.

### Generation Store (`CURRENT` + `generations/`)

Owned by `internal/genstore`; the commit protocol and its invariants are
specified in [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md).

- `identities/<identity>/CURRENT` contains the active generation ID and is
  the sole commit record; the active `keys/` and `keytypes/` namespaces live
  inside the generation it names and are resolved via
  `genstore.ResolveActive`
- generation IDs match `gen-<unix-seconds>-<8 hex chars>`
  (`internal/storepaths.ValidateGenerationID`); directories under
  `generations/` with the `.staging-` prefix are unpublished mint state
- a generation holds exactly `manifest.json`, `seal.json` (once sealed), and
  the `keys/` and `keytypes/` namespace directories; both namespaces are
  required, entries are regular files, and symlinks and hardlinks are
  rejected everywhere
- `manifest.json` (schema `aplane.generation-manifest.v1`) is the immutable
  at-mint operation record: operation, operation ID, parent generation ID,
  and timestamps
- `seal.json` (schema `aplane.generation-seal.v2`) is written when a
  generation stops being current and is the content authority for sealed
  priors. It pins the SHA-256 of the exact immutable manifest bytes, records a
  positive `integrity_term`, and carries a canonical HMAC-SHA256 over all
  security-bearing seal fields and the full two-namespace inventory. Each
  inventory entry records `term`: zero for plaintext, or the positive
  term-envelope term. The seal MAC and canonical inventory digest bind
  `(path, digest, size, term)`. Rollback and retained-parent pruning verify it
  with an open identity keyring; an unanchored seal is accepted only when both
  its integrity term and every term-bearing entry use the current term.
- `crypto.HistoricalGenerationAnchor` pins a canonical generation ID and the
  exact seal byte size and SHA-256. `genstore.BuildHistoricalAnchor` creates
  one only after ordinary current-authority seal verification, so anchors are
  collected before that term retires.
- anchored historical validation verifies the exact seal anchor first, then
  accepts the seal MAC under its retained term, binds the exact manifest, and
  checks live inventory. `ReadAnchoredBytes` verifies the same member buffer's
  size, digest, and term before consumption; `OpenAnchoredEnvelope` then uses
  the dedicated historical open path. A retained key without its exact anchor
  is insufficient, as is an anchor without the retained key.
- single-file writes into the current generation's namespaces are the
  routine mutation path (key generation, template install); multi-file
  transactions (credential restore) commit by minting a new generation
  behind a single durable `CURRENT` rename
- generation reconciliation at unlock discards uncommitted attempts and
  staging residue (they are never resumed), validates the selected
  generation, and confirms the `CURRENT` flip's durability; any failure
  holds the identity in recovery mode with nothing deleted
- the outgoing generation is sealed immediately before the `CURRENT` flip,
  so a crash in that window leaves a seal on a generation that is still
  current. The precommit seal is tolerated: nothing consults a seal while
  its generation is current, current-generation validation ignores it, and
  the next flip rewrites it from a fresh inventory. The
  published-but-uncommitted successor from the same window is discarded by
  reconciliation

### Policy File (`policy.yaml`)

The identity-scoped active policy is stored at
`identities/<identity>/policy.yaml`. Signer nodes parse that file as
client-signing policy. Sentry nodes parse that same file as direct sentry
component policy. The JSON sidecar at `policy.yaml.hmac` authenticates the
exact YAML bytes.

The policy integrity key is derived inside `internal/crypto` from the named
identity term key with HKDF-SHA256 using info string
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
- `policy_mtime_ns`: accepted legacy diagnostic policy-file mtime. Current
  writers omit it; readers retain the field solely for strict-schema
  compatibility with existing sidecars.

Only `version`, `algorithm`, `key_id`, `integrity_term`, and `hmac` are
security fields. Sidecar JSON is strict: unknown fields, trailing documents,
and non-canonical MAC encodings are rejected.
`policy_sha256`, `signed_at_unix`, and `policy_mtime_ns` are diagnostic
metadata; tampering with those fields does not affect the policy integrity
decision.

Policy load behavior:

- unlock/reload verifies `policy.yaml.hmac` before parsing and applying policy
- missing `policy.yaml` or a missing/mismatched sidecar fails closed
- during initial locked startup, a policy integrity failure prevents the
  admin-auth unlock from completing and is reported as `auth_result` with
  `code:"unlock_failed"`
- reload failure keeps the previous in-memory policy active
- admin policy writes require an unlocked identity and replace the
  node-role-selected policy document
- direct YAML edits require offline `appolicy --save` or `apstore policy sign`
  before the signer trusts them
- `appolicy` defaults to `--target auto`; for store-backed operations, auto
  reads root `node.yaml` and targets the signer or sentry policy domain for
  the single `policy.yaml` file
- `appolicy --yaml` emits the exact verified selected document bytes;
  `appolicy --save` reads replacement YAML bytes from stdin, validates them in
  the selected policy domain, and writes those exact bytes plus a fresh sidecar
  under the store mutation lock; `--target signer|sentry` explicitly
  selects the domain; store-backed role-incompatible targets fail closed. A
  root-run offline edit of a production store restores the owner recorded in
  root-controlled `install/service-principal.json` before returning
- `apstore policy check|verify|sign` checks, verifies, or signs the active
  node-role policy
- `appolicy --online <draft.yaml>` rejects an empty draft, validates it through
  the daemon, loads the active snapshot as its optimistic-concurrency base,
  and opens the draft in the online editor; batch output/check flags validate
  the positional draft and exit without opening the editor

### Managed Credential Files (`.key` and `.sen`)

Both managed classes use the same encrypted envelope and canonical payload
schema. Their extension is fixed by payload category:

- `.key`: `ed25519`, `dsa_lsig`, and `generic_lsig` account authority,
  selected by a 58-character Algorand address;
- `.sen`: `witness` authority assigned to sentry custody, selected by a
  52-character Witness Key ID.

Managed credential files carry:

- envelope versioning: `envelope_version: 3`, carrying
  `{envelope_version, term, nonce, ciphertext}`,
- the object's own identity in the AEAD's authenticated data, so a credential
  filed under another name does not decrypt (see below),
- payload format versioning,
- enough metadata to recover address and key type after decryption,
- for LogicSig keys, enough signing metadata to assemble LogicSig args without
  trusting the registered template definition.

Categories:

- native signing keys,
- DSA-backed LogicSig keys,
- generic LogicSig template instances,
- signer-custodied witness keys serving the sentry role (durable category
  `witness`; used only through sentry-role `/sign/component`).

Generic LogicSig entries contain salted bytecode, `salt_counter`, and
parameters rather than a private signing key.

Bounded account key files retain category `dsa_lsig`, base key type, stored
bytecode, creation parameters, and signing metadata version 2. The injected
`bounded_admin_public_key` is immutable program input. The signer derives the
Contract Admin Key ID and program binding from durable metadata; neither is a
caller-selected creation parameter.

Decrypted key payloads use one canonical v1 JSON schema owned by
`internal/keys.ParsePayload` and `internal/keys.MarshalPayload`. Readers reject
unknown fields, duplicate JSON object members, non-canonical timestamps, and
noncanonical payload aliases. Creation parameters are stored only in `parameters`;
LogicSig bytecode is stored only in `lsig_bytecode`. The durable payload does
not store a separately trusted address, template name, entropy, derivation
record, or runtime-argument metadata under `runtime_args`.

This document uses **versioned signing-metadata keys** for key files that carry
`signing_metadata_version >= 1`. Non-bounded LogicSig keys use version 1;
bounded keys require version 2. LogicSig key payloads include:

- `signing_metadata_version` — required; key files lacking it are rejected for
  signing and restore
- `salt_counter` — required; the single-byte counter used to select the stored
  off-curve LogicSig bytecode/address
- `signing_args` — optional; the signing-time arg schema in TEAL argument
  order, represented internally by `internal/signingargs.Info`; absent and
  empty are equivalent and mean the key takes no runtime args
- `base_key_type` — required for composed DSA keys, pointing to the signer-side
  private signing primitive used for key-material signing and signature arg
  packing; v1 signing-metadata DSA keys also persist it when it equals
  `key_type`. This field does not say which provider owns account metadata,
  creation parameters, TEAL, or guarded assembly.
- `template_fingerprint` — optional; the behavior-only, versioned (`<n>:`
  prefix) compatibility fingerprint of the template/provider definition that
  created or was bundled with the key, when known. It depends on no user-facing
  identifier (base key types are projected to a stable `base_primitive` token)
  and is provenance only, never signing authority

Bounded signing-metadata version 2 additionally requires the canonical
`bounded_authorization` object:

- `contract`: `bounded1`
- `base_signature_arg_layout`: exact base arg count and per-position maximums
- `spend_effects`, `max_fee`, and typed `admin_operations`; every operation
  explicitly carries `policy_gate: none|layer3`, and external-admin operations
  require `none`
- `runtime_args` and `derived_args`: canonical declarations, possibly empty
- `argument_layout`: complete ordered slots with source, maximum, and all path masks
- `layer3_policy`: exactly `custom`, `fixed_allowlist`, or `merkle_allowlist`
- optional `sentry`: contract, witness key type, resolved public key and Witness
  Key ID, maximum signature size, and exact `[spend]` path; its argument slot
  source is `sentry`
- `admin_public_key`, `admin_key_id`, and `program_binding` when an operation
  uses `authorization: admin_key`; the key ID must derive from that public key,
  and the public key must equal `parameters.bounded_admin_public_key`
- `post_signing_lsig_size`: exact stored bytecode size plus every slot maximum;
  path-specific sizing subtracts slots forbidden on the selected path

Bounded payloads with metadata version 1, non-bounded payloads with metadata
version 2, unknown nested fields, duplicate object members, invalid or
colliding argument declarations, or inconsistent size/admin metadata are
rejected. Backup and restore preserve the object unchanged.

Stored LogicSig bytecode and stored signing metadata are authoritative for
signing:

- generic LogicSig signing reads bytecode and orders caller-supplied runtime
  args using stored `signing_args`
- DSA-backed LogicSig signing reads bytecode and stored `signing_args`, signs
  with the stored key material, and uses `base_key_type` to find the signer-side
  private signing primitive that packs the cryptographic signature args
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

Signer scanning binds accepted authority to the category-sensitive canonical
filename:

```text
CanonicalName(payload) = Selector(payload) || ExtensionForCategory(payload.category)
```

After decrypting a `.key` or `.sen` candidate, the scanner derives the payload
selector and category. It accepts the file only when the basename equals the
canonical name. A witness payload in `<id>.key`, an account payload in
`<address>.sen`, or any selector mismatch is skipped and reported; `.wit` and
`.wit.json` are never private-credential candidates. Writers and restore derive
the same canonical destination. Restore rejects a contradictory managed class
for the same selector even with `overwrite:true`; an exact canonical destination
is replaced only when overwrite is explicit.

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
  reference-compatible fixed `bytecblock` preamble, and
  `aplane.ed25519.v1` uses a fixed `bytecblock` preamble.
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
they are not consulted at sign time. `template_fingerprint` is provenance only:
behavior-only, versioned (`<n>:` prefix), and identifier-independent. Key
inventory surfaces may compare it with the registered local definition and
report a template conflict or unavailable template, but those notices do not
invalidate a key. The comparison is version-aware: only a same-version,
different-hash pair is a conflict; a different-version or malformed fingerprint
is "not comparable" and benign.

#### Signing Authority

The key file is the signing authority. Templates and live providers are not
consulted to reconstruct missing signing metadata.

- A v1 signing-metadata LogicSig key file persists the TEAL bytecode and the
  signing-time argument contract captured at generation.
- Generic LogicSig keys store bytecode, the `salt_counter` that selected the
  off-curve address, and runtime argument schema.
- DSA-backed LogicSig keys additionally store `base_key_type`; that private
  signing primitive must be available because the signer must produce and pack
  the DSA signature. The field is not a claim that the base provider owns the
  account's metadata, creation params, or LogicSig assembly. The composed
  template/provider for that `key_type` is not required to sign an
  already-created key.
- A LogicSig key file that contains bytecode but is not a v1 signing-metadata
  key is rejected for restore and signing.

Templates are used for key creation and LogicSig bytecode derivation, creation
parameter and runtime argument metadata in generation surfaces, key-type
catalog/library/install/enable/disable flows, optional backup bundling and
explicit template restore, backup import provenance validation (a bundled
template is recompiled with the bundled key's stored creation parameters and
must reproduce the key's stored LogicSig bytecode), and live provenance
comparison through `template_fingerprint`. `template_fingerprint` is
informational provenance only — behavior-only, versioned (`<n>:` prefix), and
identifier-independent — and the comparison is version-aware (a different-version
or malformed fingerprint is "not comparable" and benign, never a conflict).
Inventory surfaces may report a template conflict or unavailable template, but
that status does not invalidate the key or alter signing behavior.

#### Offline Identity Key Inventory

`apstore keys list` is a local, passphrase-gated inventory surface for the
current product identity's encrypted key files. It decrypts key metadata using
the identity store passphrase and lists successfully scanned key addresses or
Witness Key IDs with their key type, durable category, creation timestamp, and
key-file name.

The default human output must not emit private key material, mnemonic material,
or raw public-key hex. Sentry keys are identified by their Witness Key ID, not
by the raw sentry public key. Recoverable key-scan warnings may be reported
while still listing keys that scanned successfully.

#### Sentry Public Key Export Envelope

`apstore sentry export <witness-key-id> [output-json]` emits a public-only JSON
envelope for a sentry key. The command reads the
`keys/<witness-key-id>.wit.json` sidecar, verifies that `<witness-key-id>`
equals the canonical Witness Key ID derived from the public key, and never reads
or decrypts private key material. If the sidecar is missing or malformed,
export fails closed; the operator must regenerate the sentry key or run an
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
wire and sentry-reference records retain the field name `component_key`.
`public_key_hex` is the raw component
public key encoded in hex; it is the value embedded into guarded-account
LogicSig bytecode and supplied as `sentry_public_key` during guarded account
generation. The envelope makes no endpoint, policy, ownership, freshness, or
trust claim.

#### Sentry Public Key Reference Library

`apstore sentry import <export-json> <name>` imports an
`aplane.witness-key-public.v1` envelope into the target identity's public
sentry reference library:

```text
identities/<identity>/sentries/<name>.json
```

Reference names are normalized to lowercase and may contain lowercase letters,
digits, `.`, `-`, and `_`. The persisted record schema is:

```json
{
  "schema": "aplane.sentry-public-key-ref.v1",
  "name": "lab-sentry",
  "component_key": "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ",
  "key_type": "aplane.witness-falcon1024.v1",
  "public_key_encoding": "hex",
  "public_key_hex": "0000...0000",
  "public_key_size": 1793,
  "public_key_sha256": "d3a3deeec37ef5e50a463a2b1f8c9c6fc934a5c824a0c1cfd027d035a03b923a",
  "source": "manual",
  "imported_at": "2026-06-04T00:00:00Z"
}
```

Endpoint discovery may also populate this catalog through
`apshell endpoints sync-sentries`. Synced records use the same schema with
`source: "client_discovery"`, a deterministic generated name
`endpoint-<alias>-<component_key>`, `endpoint_alias`, `last_seen_at`, and
`synced_at`. They are public candidates derived from the client's
`endpoints.yaml`; they are not a sentry ownership proof.
Explicitly importing the identical authority under the same generated name
promotes the record to `source: "manual"`, clears discovery provenance, and
prevents a later discovery sync from removing it.
Human list output treats the Witness Key ID as the primary identifier
and shows generated endpoint-synced names only in detailed JSON views.

The library is a generation convenience and trust-input inventory for the user
signer. When generating a dedicated guarded account or a sentry-enabled bounded
template, callers may provide
`sentry=<witness-key-id>` instead of `sentry_public_key=<hex>`.
`sentry=<name>` is also accepted as a compatibility input. The signer resolves the
Witness Key ID or name to `public_key_hex`, verifies that the reference key type
matches the definition's required sentry key type,
rejects requests that provide both forms, and persists the resolved
`sentry_public_key` plus the template's other creation parameters in the key
file. `aplane.corridor.v1`, for example, persists its public recipient list and
complete bounded metadata; later signing does not require the YAML source to
remain installed.

Identity-scoped `/keytypes` metadata may expose imported references as a
creation parameter named `sentry` with `type:"select"` and `options[]`
containing Witness Key IDs whose sentry key type matches the guarded
account key type. This is UI metadata for generation clients such as `apadmin`;
the durable key file still stores the resolved `sentry_public_key`; other
provider-specific creation parameters remain exposed normally.

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

### Template Files (`.template`)

Encrypted YAML in the term envelope, bound to its key type. The parsed template spec
(`generictemplate.TemplateSpec`, which embeds `templatestore.BaseTemplateSpec`)
contains:

- `schema_version`
- `derivation_version` (optional; omitted means no generated salting)
- `template_type` (`generic` or `composed`)
- `base_key_type` (required for `composed`, rejected for `generic`)
- `publisher`
- `family`
- `version`
- `display_name`
- `description`
- `display_color`
- `template_mode` (`legacy`, `strict`, or `generated`) — carried on
  `TemplateSpec`, not on the embedded `BaseTemplateSpec`

Template capability notes:

- generic template YAML and custom composed DSA template YAML use their
  respective `schema_version: 1` contracts; composed schema v1 rejects a
  top-level `bounded` field
- bounded composed templates use `schema_version: 2`, require a typed `bounded`
  block, and reject unknown and duplicate fields at every nested level
- every APlane-bundled composed template uses schema v2; schema v1 remains a
  fully functional expert mode for imported custom DSA policies
- `bounded.layer3.policy: fixed_allowlist` owns complete pay/axfer Layer-3
  control flow; its typed parameter references are validated against declared
  parameter types and its template must omit `teal`
- schema selection occurs from the raw mapping before version-specific typed
  decoding; merge keys, aliases, multiple documents, and invalid schema
  selectors are rejected
- omitted `derivation_version` compiles the template without a generated salt
  anchor and therefore succeeds only when the unmodified bytecode already
  derives an off-curve LogicSig address
- `derivation_version: 1` uses the generated `pushbytes; pop` marker,
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
- `TOKEN_PROVISIONED`

Signing-audit semantics:

- `SIGN_APPROVED` is emitted only for transactions the signer actually signs
- foreign and passthrough entries may appear in `SIGN_REQUEST`/planning context, but are not recorded as `SIGN_APPROVED`
- signing audit over HTTP records `transport:"http"` and the token-authenticated identity as requester
- sentry-role component signing currently records approvals and policy
  rejections through `SIGN_APPROVED`/`SIGN_REJECTED`; `txn_auth` is the
  Witness Key ID, `txn_sender` is the decoded target sender, and
  `policy_rule_id` carries the deterministic sentry rule when present
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
- `CREDENTIAL_RESTORE_COMMIT_UNCERTAIN` distinguishes a visible `CURRENT`
  flip whose directory-sync durability could not be confirmed; signing stays
  recovery-blocked until reconciliation confirms the pointer and reloads the
  visible generation.
- `CREDENTIAL_RESTORE_ROLLBACK` records explicit rollback success or failure.
  Failed attempts use `outcome:"failed"` and `reason`.

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
- mutual proof of the identity-scoped API token

Normal clients send the non-secret identity ID as the SSH username. After SSH
verifies possession of an enrolled public key, the server returns partial
success and requires keyboard-interactive authentication. That exchange is
programmatic and has two rounds:

1. server asks `{"version":1,"step":"client_nonce"}` and the client returns a fresh 32-byte nonce as unpadded base64url
2. server returns a fresh 32-byte nonce and its proof; the client verifies that proof before returning its own proof

The v1 proof transcript is the concatenation of five uint32-big-endian
length-prefixed fields: `aplane-ssh-token-proof-v1`, identity ID,
SHA-256 of the canonical accepted SSH host-key blob, client nonce, and server
nonce. Each HMAC input is the length-prefixed role (`server` or `client`)
followed by the length-prefixed transcript. Proofs are HMAC-SHA256 keyed by the
raw token. JSON messages reject unknown or duplicate fields, non-canonical
base64url, wrong sizes, and trailing data. The shared conformance vector is
`test/contracts/sshtunnel/token_proof_v1.json`.

The server computes both role proofs under one token-authenticator read lock
and records that token generation on the authenticated connection. Clients
must verify that the server proof round completed even when the SSH library
reports authentication success; this rejects a wrongly trusted endpoint that
accepts the public key and skips token proof. The token itself is never sent in
the SSH username, metadata, challenge, or response.

That no-raw-token property applies to normal SSH authentication. The approved
`request-token` exception intentionally delivers the token over its constrained,
encrypted SSH provisioning channel. After normal authentication, HTTP requests
continue to carry `Authorization: aplane <token>` over loopback and the
authenticated SSH tunnel; the token remains a bearer credential at the HTTP
boundary.

Each authentication attempt generates fresh 32-byte client and server nonces
from a cryptographically secure random source. Nonces and proof state must not
be reused across attempts or reconnects. Clients discard proof-only state after
the authentication attempt succeeds or fails; garbage-collected runtimes provide
best-effort reference release rather than guaranteed memory zeroization. The
client retains its separate bearer-token state for subsequent HTTP requests.

`ssh.authorized_keys_path` is part of the server config surface; in product mode identity-scoped SSH authorization and enrollment are sourced from `identities/<identity>/.ssh/authorized_keys`.

Unavailable or invalid client token proofs incur a 5-second delay.

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

Token provisioning reads the target identity's existing token. It never
creates or rotates a token at request time: store initialization owns token
creation, and the authenticated revocation flow owns rotation. If the token
file is absent or unreadable, provisioning fails after key enrollment instead
of returning a credential that differs from the running authenticator.

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
- YAML-only `key_overrides` keyed by signing auth address or Witness Key ID

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

Client-signing and sentry component `transfer_policy` are both persisted in
`policy.yaml`, with schema selected by node role. Both domains are validated by
the normal policy load path and by `apstore policy check/sign/verify`.
`appolicy` auto-targets the node-role domain and `--target signer|sentry`
can explicitly select a domain for offline
work; `apadmin` uses the node-role target online through admin IPC. There is no
scalar policy-settings IPC; guided edits use the shared full-document editor
and are saved as whole-document YAML replacements. The `appolicy --yaml` /
`--save` CLI path remains the scriptable offline editor for byte-preserving
route-table edits.
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

- the identity directory, for `CURRENT` replacement and late directory
  creation
- the active generation's `keys/` and `keytypes/` directories, resolved
  through `genstore.ResolveActive`; when `CURRENT` cannot be resolved the
  watcher falls back to the identity-root `keys/` and `keytypes/` paths,
  which are not the live active store on a healthy generational store

Mechanism:

- reacts to Create, Write, Remove, and Rename on `.key`, `.sen`, and `.template` files
- a `CURRENT` replacement is a reload candidate; reload resolves the new
  active generation and re-arms the watcher on its directories
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

`identity.Runtime.reloadLocked` delegates through the production function wired
by `startup.WireReloadFunc` to `templates.ReloadService.Reload`. Its order is:

1. open or reuse the keyring
2. verify the node role and load authenticated policy
3. register templates
4. scan keys
5. validate scanned key classes against the node role
6. replace the runtime indexes
7. activate the key session
8. emit audit and IPC notifications

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
- a `version` field containing the current APlane plugin protocol version
  (`"1.0"`). It is distinct from the JSON-RPC protocol version (`"2.0"`), from
  `manifest_format` (`"1.0"`), and from the plugin's semantic package version.
  The plugin must echo the same value in `initialize.result.version`; mismatches
  fail plugin startup.

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

## Backup and Restore Contract

Backup and restore are implemented in `internal/backup`; live generation
orchestration is owned by `internal/signerapp/backupadmin`.

The authority boundary is:

> Backup owns credentials. The destination owns policy and configuration.

A backup preserves complete managed credential records, not only raw private
key bytes. This includes durable LogicSig bytecode, signing-argument contracts,
bounded authorization, and other versioned signing metadata carried by
`.key` and `.sen` payloads. Restore never imports operational authority from
the source.

### Export and archive shape

Export:

1. discovers canonical managed credentials from active `.key` and `.sen`
   files; external `.wit`, contract-admin, and deleted artifacts are excluded
2. opens each credential with its object-bound destination term envelope
3. parses and validates the complete credential payload, then canonicalizes it
4. re-encrypts the canonical payload with standalone envelope version 2 under
   the export passphrase
5. writes `apb/<selector>.apb`

An all-credentials backup is fail-hard: if any selected active credential
cannot be read, decrypted, canonicalized, or exported, no archive is
published. It never silently reports a partial archive as a complete backup.

A managed archive contains exactly:

- `README.md`
- one or more `apb/<selector>.apb` files
- `manifest.sealed`

The sealed manifest plaintext uses schema
`aplane.credential-backup.manifest.v1`, schema version 1. It records the
source node role, packaging time, and the complete member inventory
(`path`, `sha256`, `size`). It does not contain policy, approval defaults,
genesis-hash mappings, templates, endpoints, tokens, SSH enrollment, or other
operator configuration. The manifest is encrypted under the export passphrase.
Knowing that passphrase authenticates the archive as produced or endorsed by a
passphrase holder; it is not independent origin authentication.

Every archive reader authenticates the manifest and verifies exact membership
before trusting payload metadata. Missing, added, duplicated, non-canonical, or
altered members are rejected. Internal pre-release manifests, bundle wrappers,
and legacy envelope versions are unsupported; this is the first supported
backup contract and no migration from earlier internal tags is provided.

### Import and inspection

`apstore backup import` asks the daemon to validate an external tar archive
deeply before publishing it under `backups/<identity>/`. The commit request
carries the sensitive export passphrase; the daemon authenticates the archive
inventory and validates every credential payload, then zeros the passphrase
without persisting it. Client-side archive inspection is not an authorization
or integrity boundary. Commit is synchronous and can perform one memory-hard
credential verification per archive member, so first-party clients allow up to
30 minutes for that bounded request instead of applying the ordinary 30-second
admin timeout. Import does not compile or install templates because
templates are not archive members. The IPC transfer declares its exact source
size and SHA-256 at commit, is capped at 1 GiB while appending, and permits only
one writable upload per identity. Commit claims the completed upload under the
identity mutation lock, releases that lock for hashing and deep verification,
then reacquires it only for the final publish. A new import supersedes writable
upload residue without deleting an archive already undergoing validation;
daemon startup removes both kinds of residue left by a prior process. Deep
validation extracts into an owner-private reserved directory on the signer
store filesystem rather than the process-global temporary filesystem; normal
completion and daemon startup remove that validation residue.

`preview_restore` and `apstore restore preview` authenticate the archive
before revealing addresses or key types. Preview reports credential identity,
destination presence, and validation errors; it performs no store mutation.
Wrong-passphrase and unauthenticated failures share the restore rate limiter.
Authenticated `list_backups`, `read_backup_chunk`, and `preview_restore`
requests are accepted while the identity is either unlocked or
recovery-blocked, allowing an operator to select, export, and inspect repair
material without enabling signing. Locked identities remain rejected.

`apstore verify` is fail-closed: an archive verification error or any invalid
credential returns the stable local `verification_failed` code and a nonzero
process exit.

### Live direct restore

Admin protocol v4 exposes a direct credential restore:

- `restore_backup`: archive path, optional selectors, export passphrase, and
  optional `replace_existing`
- `restore_backup_result`: operation ID, archive SHA-256, resulting
  generation, restored/identical/conflicting credentials, key count, stable
  code, and error
- `rollback_restore`: rolls back only the latest clean, rollback-eligible
  credential restore
- `reconcile_store`: validates/reconciles the visible generation and exits
  recovery mode only when the store is clean

These operations remain authorized by the stable `identity.restore` action.
Restore, rollback, and reconciliation are callable while an authenticated
identity is recovery-blocked so they can repair or resolve store damage.

Restore validates the complete selected set before any write:

- archive/member authentication and format bounds
- payload/envelope versions and strict canonical decoding
- filename, selector, category, and key-type agreement
- public/private-key and address consistency
- LogicSig bytecode/address consistency and off-curve requirements
- complete standalone signing metadata for LogicSig credentials
- bounded-authorization consistency
- source/destination node-role compatibility
- required destination runtime/provider support
- duplicates and contradictory managed credential classes

Destination collision classification compares canonical decrypted plaintext,
not ciphertext. An identical credential is an idempotent no-op. A different
credential is a conflict requiring `replace_existing`. An existing
credential that cannot be decrypted or decoded is also a replaceable conflict,
which permits an explicitly authorized restore to repair damage in recovery
mode.

After validation, restore mints exactly one generation. The parent generation
is copied, selected credentials are applied into staged `keys/`, derived
witness public metadata is updated, the staged generation is validated and
synced, the outgoing generation is sealed, and one durable `CURRENT` rename
commits the operation. Restore never writes templates, key-type activation
records, policy, config, or network mappings.

The generation manifest operation is exactly `credential-restore`; it records
the archive SHA-256 and whether explicit rollback is eligible. Recovery-mode
repairs are not rollback-eligible because their damaged parent must never be
promoted back into service. A rollback mint uses
`credential-restore-rollback`, so a second rollback is refused.

Reload failure after a committed restore automatically rolls `CURRENT` back
to the sealed parent and reloads it. Uncertain commit durability, failed
rollback after mutation, or failed reconciliation enters recovery mode and
blocks signing. A crash after a complete `CURRENT` flip loads the committed
generation on restart; uncommitted staging is discarded.

Explicit rollback is allowed only when the current generation:

- was produced by exactly `credential-restore`
- is marked rollback-eligible
- still matches its authenticated effective inventory authority

Divergence refuses rollback rather than discarding later mutations. Rollback
reconstructs the sealed parent content into a fresh current-term generation; it
never repoints `CURRENT` at historical ciphertext.

Restored credentials immediately operate under the destination identity's
current policy, approval default, network mappings, endpoints, and installed
configuration. No source-policy comparison or unattended-signing
acknowledgement is part of restore. This matches bulk key import: the
credential operation does not modify destination policy, and the operator is
responsible for the destination policy under which restored authority runs.

### Offline rebuild

`apstore rebuild <archive-path> [--role signer|sentry]` remains the rescue
path for an absent identity store. It applies the same credential validation
and credential-only semantics into a newly staged first generation. The sealed
manifest source role supplies the default role; an explicit incompatible role
or role-conflicting credential is rejected.
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
- SDK-native prepared transaction models carry unsigned transaction bytes plus
  signer metadata such as effective auth address, optional LogicSig args,
  optional LogicSig size hints, optional app-call display metadata, and
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
- Guarded prepared signing is a special client-prep path because component
  signatures require canonical bytes before user and sentry signatures are
  requested. SDKs may mirror apshell's guarded client flow by classifying
  guarded targets, sizing LogicSig-budget dummies from signer-advertised
  `lsig_size` program+args budgets, fixing fees and group ID, signing
  dummy/passthrough slots locally, and then using `/sign/component` plus
  `/sign/assemble`. Final guarded assembly remains signer-owned. User-role
  `/sign/component` requests run the signer-domain approval gates and can
  block on operator approval, so SDK deadlines for them follow the same
  approval-aware rule as `/sign`, not the short sentry-role component
  deadline.
- Guarded simulation uses the same component and assembly flow as submission.
  The client obtains ordinary user and sentry component signatures, signs local
  non-guarded legs through `/sign`, assembles through `/sign/assemble`, verifies
  the frozen canonical bytes, and only then sends the exact executable group to
  its configured algod simulation endpoint.
- SDKs expose the authenticated `/status` DTO, including
  `protocol_version`, `build_version`, `keyset_revision`, and
  `approval_wait_seconds`, and include the matching signer API fixture in their
  contract suites.
- SDKs decode non-2xx HTTP bodies as `signerapi.ErrorResponse` with top-level
  `error` plus a stable machine-readable `code`
  (`pkg/signerapi/error_codes.go`). Clients classify failures by `code`
  (empty when the server does not supply one), never by `error` message text.
  Endpoint-specific success DTOs are not the error envelope.
- SDK/client `/sign` deadlines must be long enough for the identity-effective
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
  `PlanGroupResponse`, `GroupSignResponse`) rather
  than the base64-returning convenience layer. `SignResponse` is a
  source-compatibility type; the live `/sign` response is `GroupSignResponse`.
- `Config.NewAlgodClient(network)` is part of the supported Go SDK config surface
- `GroupPlanResponse`, `RuntimeArgInfo`, and `SigningArgInfo` are compatibility aliases for `PlanGroupResponse`, `RuntimeArg`, and `SigningArg`
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
