# Bounded Authorization Contracts

## Status

This document freezes the `bounded1` contract. The composer envelope, classifier, strict
composed schema v2, durable signing metadata, inventory projection,
contract-admin ceremony, framework-owned fixed allowlist, and static Layer-3
argument layout are implemented.

This is the first supported release of `bounded1`. Canonical encodings and
golden vectors that existed only in development branches before this release
were not a compatibility contract; preview or LocalNet keys derived from those
encodings must be recreated. The encodings and vectors in this document are
the v1 compatibility baseline.

## Purpose and Authority

A bounded authorization contract is a stateless LogicSig program that
defines the complete transaction envelope accepted for an account. Its
contract admin key is a separately custodied witness key that co-authorizes a
named administrative operation with the base spending key. It is not an
independent spending-key recovery key, Algorand Governance, the `apadmin`
client, or an ASA manager key. The key form is shared with sentry witnesses,
but an individual keypair should never be enrolled in both roles.

`bounded1` has three ordered regions:

1. **Authentication:** the base DSA signature is required on every path.
2. **Transaction envelope:** the composer enforces fee, transaction-type,
   administrative-effect, and admin-operation normal-form constraints.
3. **Layer 3 policy:** author or framework policy runs only for an admitted
   pure spend, and for a spending-key rekey only when its operation declares
   `policy_gate: layer3`.

Sentry-enabled bounded1 profiles are spend-gated profiles and may not declare
a spending-key-authorized rekey. V1 rejects that combination during template,
profile, and durable-metadata validation. Escaping a failed or compromised
sentry therefore uses an external contract-admin rekey, which still requires
the base spending signature. Loss of the spending key is not recoverable
through the contract-admin path.

For profile `P`:

```text
Envelope(P) = PureSpend(P) union enabled AdminOperation(P, kind)

Accepted(P) =
  {tx in PureSpend(P) where SpendingPolicy(tx)}
  union enabled AdminOperation(P, kind)
```

The guaranteed containment property is `Accepted(P) subset-of Envelope(P)`.
Enabling an admin operation widens the envelope; only Layer 3 is monotone
narrowing. The contract does not claim that an arbitrary custom Layer-3 policy
is a complete value-spending policy.

## Frozen V1 Decisions

| Property | `bounded1` value |
|---|---|
| Contract identifier | `bounded1` |
| Composed YAML schema | `schema_version: 2` |
| TEAL version | 13 |
| Spend effects | non-empty closed subset of `pay`, `axfer`, `asset_opt_in` |
| Admin operations | `rekey` only |
| Admin authorization | `spending_key` or `admin_key` |
| Admin policy gate | `none` or `layer3`; admin-key authorization requires `none` |
| Contract admin primitive | Falcon-1024 only |
| Contract admin public key | exactly 1,793 bytes |
| Contract admin signature | non-empty, at most 1,423 bytes |
| Maximum compiled `max_fee` | 10,000 microAlgos |
| Layer-3 arguments | declared static runtime and signer-derived slots |
| Signer-derived primitive | fixed-depth Merkle allowlist proof (512 bytes) |
| Framework Layer-3 policies | `fixed_allowlist`, `merkle_allowlist` |
| Inline recipient/asset maximum | 30 entries per list |
| Flow labels | `bounded1` without a sentry; `bounded-sentry1` with a spend sentry |
| Online sentry endpoints | `POST /sign/bounded-component`, `POST /sign/component`, `POST /sign/bounded-assemble` |
| Admin endpoint | `POST /sign/bounded-admin` |
| Bundled composed templates | five schema-v2 profiles listed below |

`bounded1` has no admin-key algorithm selector. `authorization: admin_key`
always means the profile's single Falcon-1024 contract admin key. Supporting
another admin primitive requires a new bounded-authorization contract.

The 10,000 microAlgo ceiling supports the currently measured Falcon/Falcon
fixed-list shape at a 1,000 microAlgo network minimum fee. It is an absolute
v1 profile ceiling, not a promise of viability on networks with a higher
minimum fee. Group size and network-fee viability are path-specific. The
planner resolves argument/opcode dummies and priced program bytes for the
active consensus profile, then rejects a transaction path whose finalized fee
exceeds the compiled ceiling.

The composer baseline uses a real Falcon spending verifier and a controlled
trivially true Layer-3 predicate. Every shipped Layer-3 policy adds its own
final-bytecode and selected-path resource cells before the key type can be
enabled. `TestBundledBoundedCompiledBudgetMatrix` compiles the shipped
templates with the pinned TEAL v13 toolchain, derives argument layouts from
durable bounded metadata, applies the conservative reviewed opcode ceiling,
and runs the production v42 resource solver.

The resulting fee includes transaction bases and priced program bytes. The
compiled 10,000 microAlgo `max_fee` applies to every path. A higher network
minimum fee is evaluated through the same unified fee calculation rather than
through a legacy `ceil(program + args)` projection.

Schema-v1 custom DSA policy is expert mode. Schema-v2 bounded templates may
also use custom Layer 3 TEAL, but the framework still owns the effect envelope,
fee ceiling, slot layout, and path routing. The bundled timelock and Merkle
allowlist are bounded custom Layer 3 policies.

## Bundled Profiles

All bundled composed templates use schema v2 and the same closed bounded1
effect surface:

| Key type | Layer 3 | Pure rekey | Extra slot |
|---|---|---|---|
| `aplane.falcon1024-allowlist.v1` | inline fixed recipient allowlist | spending key; no Layer 3 gate | none |
| `aplane.falcon1024-allowlist.v2` | fixed-depth Merkle recipient allowlist | spending key; no Layer 3 gate | optional signer-derived `merkle_proof` on spend |
| `aplane.falcon1024-timelock.v1` | `FirstValid >= unlock_round` | spending key; Layer 3 required | none |
| `aplane.falcon1024-allowlist-alock.v1` | inline recipient/asset/amount allowlist | external Falcon admin key | trailing admin signature |
| `aplane.corridor.v1` | framework Merkle recipient allowlist plus sentry spend gate | external Falcon admin key | Merkle proof, sentry signature, trailing admin signature |

Every profile rejects close, clawback, hybrid rekey, and non-transfer types.
The timelock intentionally prevents emergency spending-key rekey until its
Layer 3 condition passes. The rekey-locked allowlist provides a separately
co-authorized rekey path when that tradeoff is unsuitable, but that path still
requires the spending key.

Compiler-backed maximum-path measurements are frozen by
`TestBundledBoundedCompiledBudgetMatrix`:

| Key type | Final bytecode | Spend args / v42 group / fee | Admin args / v42 group / fee |
|---|---:|---:|---:|
| Falcon inline allowlist | 3,155 | 1,423 / 2 / 2,117 | n/a |
| Falcon Merkle allowlist | 2,184 | 1,935 / 2 / 2,019 | n/a |
| Falcon timelock | 1,943 | 1,423 / 2 / 2,000 | n/a |
| Falcon rekey-locked allowlist | 5,308 | 1,423 / 2 / 2,332 | 2,846 / 3 / 3,232 |
| Corridor | 5,936 | 3,358 / 4 / 4,196 | 2,846 / 3 / 3,295 |

Fees are microAlgos at a 1,000-microAlgo minimum fee and include v42 program
pricing. The table uses the conservative 20,000-opcode per-path ceiling; its
group count includes the resource dummies and their own program/opcode use.
The planner rejects a selected path before releasing a signature when its
finalized fee would exceed the profile ceiling.

## Effect Model

The independent machine-readable inventory is
[`BOUNDED1_PROTOCOL_INVENTORY.json`](BOUNDED1_PROTOCOL_INVENTORY.json). It is
maintained independently of renderer/classifier code and pinned to
go-algorand-sdk v2.11.2 pseudo-version `967fcacfacdf`, go-algorand reference
`68e036affd9e`, and AVM v13.
It separately freezes the flattened SDK transaction-field surface and parses
the pinned SDK source in tests to detect newly introduced transaction types.

The framework danger predicates are:

| Effect | Predicate |
|---|---|
| Rekey | `RekeyTo != ZeroAddress` |
| ALGO account close | `CloseRemainderTo != ZeroAddress` |
| ASA position close | `AssetCloseTo != ZeroAddress` |
| ASA clawback execution | `AssetSender != ZeroAddress` |

`Fee` is a bounded outflow, not an admin effect, and is checked on every path.
Unknown transaction types reject because the program admits only explicit
`pay` and `axfer` values. `keyreg`, `acfg`, `afrz`, `appl`, state proof, and
heartbeat transactions are denied.

The implementation manifest and the independent inventory have different
owners. The manifest drives code generation and off-chain classification. The
inventory detects an omitted manifest row. Tests must fail when a danger row is
removed, a known type is unclassified, or the pinned SDK/AVM field surface
changes without review.

## Normal Forms

### Pure spend

A pure spend:

- has `TypeEnum` in the profile's closed subset of `pay` and `axfer`;
- has all four danger fields equal to `ZeroAddress`;
- has `Fee <= max_fee`; and
- satisfies Layer 3.

### Pure rekey

A pure rekey:

- has `TypeEnum == pay`;
- has `Amount == 0`;
- has `Receiver == Sender`;
- has `RekeyTo != ZeroAddress`;
- has `CloseRemainderTo`, `AssetCloseTo`, and `AssetSender` equal to
  `ZeroAddress`;
- has `Fee <= max_fee`; and
- satisfies the configured `spending_key` or `admin_key` authorization.

Rekey detection runs before spend-type routing. Rekey-plus-transfer,
rekey-plus-close, and every other hybrid reject. A group may contain separate
normal-form transactions, but bounded1 guarantees only each protected
transaction's envelope, not group-wide semantic safety.

Spending-key authorization preserves pure shape but does not contain theft of
the spending key. Falcon contract-admin authorization contains spending-key
theft for rekey because both signatures are required.

## Canonical Encoding

All hashes in this section use SHA-512/256. `u32(x)` and `u64(x)` are unsigned
big-endian integers. `field(x)` is `u32(len(x)) || x`. Text is exact UTF-8
without a terminator or Unicode normalization. Lists carry a `u32` count and
then canonical elements. No JSON or YAML serialization is hashed.

### Canonical bounded profile

```text
canonical_bounded_profile =
  field("APLANE_BOUNDED_PROFILE_V1") ||
  field("bounded1") ||
  u32(count(spend_effects)) ||
    field(effect_0) || ... || field(effect_n) ||
  u64(max_fee) ||
  u32(count(admin_operations)) ||
    field(operation_0.kind) || field(operation_0.authorization) ||
    field(operation_0.policy_gate) || ... ||
  u32(sentry_present) ||
    if present: field("sentry1") ||
      field("aplane.witness-falcon1024.v1") || u32(1423) ||
      u32(1) || field("spend") ||
  field(layer3_policy) ||
  u32(base_signature_arg_count) || u32(base_arg_0_max) || ... ||
  u32(count(derived_args)) || canonical_derived_args ||
  u32(count(runtime_args)) || canonical_runtime_args ||
  u32(count(argument_layout)) || canonical_argument_slots
```

Spend effects use frozen order `pay`, `axfer`, `asset_opt_in`; admin operations
use frozen order `rekey`. Duplicates are invalid. Empty spend sets are invalid.
`asset_opt_in` is the zero-amount self-receiver asset-transfer form and is
authorized independently from `axfer`. `max_fee` must be present and no greater
than 10,000. The Layer 3 identity, argument declarations, maximum sizes, frozen
indexes, sources, and path masks are security-bearing and therefore part of
the canonical profile. `sentry_present` is exactly zero or one. The initial
optional sentry contract has the single ordered path list `[spend]`.

### Canonical behavior parameters

```text
canonical_behavior_parameters =
  field("APLANE_BOUNDED_BEHAVIOR_PARAMETERS_V1") ||
  u32(count(parameters)) ||
    field(parameter_name) ||
    field(parameter_type) ||
    field(canonical_value) || ...
```

Only behavior-bearing account-creation values are included, in parameter
definition order. A sentry-enabled profile includes the framework-injected
`sentry_public_key`; the program binding must therefore commit to the resolved
sentry key. The framework-injected `bounded_admin_public_key` is excluded
because the program binding carries it separately. Display metadata, file
paths, runtime values, and policy provenance are excluded.

Canonical scalar values are: address as raw 32 bytes; bytes as raw bytes;
unsigned integer as `u64`; boolean as one byte `0x00` or `0x01`; and string as
UTF-8. A missing or explicitly empty optional parameter has a zero-length
`canonical_value`; this is distinct from an explicit numeric zero, false, or
empty list. A list value is `u32(count) || field(element_0) || ...`. Nested or
new parameter types require a new encoding rule before use by bounded.

## Contract Admin Witness Identity and Transcript

The `contract_admin_key_id` field carries the uppercase unpadded base32 Witness
Key ID of the enrolled admin witness:

```text
SHA512_256(
  field("APLANE_WITNESS_KEY_ID_V1") ||
  field("aplane.witness-falcon1024.v1") ||
  field(falcon_admin_public_key)
)
```

The bounded program binding is:

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

For v1 rekey, the contract admin signs:

```text
admin_message = SHA512_256(
  field("APLANE_BOUNDED_ADMIN_AUTH_V1") ||
  field("rekey") ||
  field(bounded_program_binding) ||
  field(transaction_id)
)
```

The binding does not claim to prove arbitrary Layer-3 semantics. The full
versioned key type fixes the definition, canonical behavior values bind the
instance, and helper validation requires the exact supplied bytecode to derive
the current authorization address. The helper structurally validates every
composer-owned gate and verification site rather than searching for byte
substrings.

### Golden vector 1

The first implementation must freeze and test a vector using:

```text
full_key_type: aplane.falcon1024-allowlist-alock.v1
base_primitive: falcon1024
teal_version: 12
spending_public_key: 1,793 bytes of 0x11
falcon_admin_public_key: 1,793 bytes of 0x22
spend_effects: [pay, axfer, asset_opt_in]
max_fee: 10000
admin_operations: [{kind: rekey, authorization: admin_key, policy_gate: none}]
layer3_policy: custom
base_signature_arg_layout: {count: 1, max_sizes: [4]}
derived_args: []
runtime_args: []
argument_layout:
  - {index: 0, name: base_signature_0, source: base_signature, max_size: 4,
     paths: {spend: required, spending_rekey: required, admin_rekey: required}}
  - {index: 1, name: admin_signature, source: admin, max_size: 1423,
     paths: {spend: forbidden, spending_rekey: forbidden, admin_rekey: required}}
behavior parameter recipients (address[]): one 32-byte value of 0x33
transaction_id: 32 bytes of 0x44
```

Expected results:

```text
canonical_bounded_profile_length: 309
canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000961646d696e5f6b6579000000046e6f6e65000000000000000663
  7573746f6d000000010000000400000000000000000000000200000000000000
  10626173655f7369676e61747572655f300000000e626173655f7369676e6174
  7572650000000400000008726571756972656400000008726571756972656400
  0000087265717569726564000000010000000f61646d696e5f7369676e617475
  72650000000561646d696e0000058f00000009666f7262696464656e00000009
  666f7262696464656e000000087265717569726564

canonical_behavior_parameters_length: 116
canonical_behavior_parameters_hex:
  0000002541504c414e455f424f554e4445445f4245484156494f525f50415241
  4d45544552535f5631000000010000000a726563697069656e74730000000961
  6464726573735b5d000000280000000100000020333333333333333333333333
  3333333333333333333333333333333333333333

contract_admin_key_id:
  MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ

bounded_program_binding:
  bddc0ee16bac8ebad4519c1f138bbfc87e94817fc1d68119f310567fb98e5001

admin_message:
  dc6c476953d76d3fcea7ace82ef90624b170fa6aed699988d381ce790a613ce1
```

Whitespace and line wrapping above are presentation only. Code tests decode
the frozen canonical profile and behavior hexadecimal strings in
`TestBoundedGoldenVector`; that test is authoritative for every byte.

### Golden vector 2: Corridor

The integrated Corridor vector uses the shipped
`aplane.corridor.v1` template and these deterministic inputs:

```text
full_key_type: aplane.corridor.v1
base_key_type: aplane.falcon1024.v1
teal_version: 12
spending_public_key: 1,793 bytes of 0x11
sentry_public_key: 1,793 bytes of 0x22
falcon_admin_public_key: 1,793 bytes of 0x33
recipient input order:
  EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI
  CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM
transaction_id: 32 bytes of 0x44
sentry_present: 1
corridor_selected_proof_recipient:
  EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI
corridor_canonical_first_recipient:
  CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEI7JH2AYM
```

The deliberately reversed recipient input confirms that behavior-parameter
normalization and Merkle construction use the canonical ascending order. The
frozen argument layout is:

| Index | Name | Source | Max bytes | Spend | Spending rekey | Admin rekey |
|---:|---|---|---:|---|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | `required` | `required` | `required` |
| 1 | `merkle_proof` | `derived` | 512 | `optional` | `forbidden` | `forbidden` |
| 2 | `sentry_signature` | `sentry` | 1423 | `required` | `forbidden` | `forbidden` |
| 3 | `admin_signature` | `admin` | 1423 | `forbidden` | `forbidden` | `required` |

Expected canonical encodings:

```text
corridor_canonical_bounded_profile_length: 588
corridor_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000961646d696e5f6b6579000000046e6f6e65000000010000000773
  656e747279310000001c61706c616e652e7769746e6573732d66616c636f6e31
  3032342e76310000058f00000001000000057370656e64000000106d65726b6c
  655f616c6c6f776c697374000000010000058f000000010000000c6d65726b6c
  655f70726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f
  660000000a726563697069656e74730000020000000000000000040000000000
  000010626173655f7369676e61747572655f300000000e626173655f7369676e
  61747572650000058f0000000872657175697265640000000872657175697265
  64000000087265717569726564000000010000000c6d65726b6c655f70726f6f
  66000000076465726976656400000200000000086f7074696f6e616c00000009
  666f7262696464656e00000009666f7262696464656e00000002000000107365
  6e7472795f7369676e61747572650000000673656e7472790000058f00000008
  726571756972656400000009666f7262696464656e00000009666f7262696464
  656e000000030000000f61646d696e5f7369676e61747572650000000561646d
  696e0000058f00000009666f7262696464656e00000009666f7262696464656e
  000000087265717569726564

corridor_canonical_behavior_parameters_length: 1979
corridor_canonical_behavior_parameters_hex:
  0000002541504c414e455f424f554e4445445f4245484156494f525f50415241
  4d45544552535f5631000000020000000a726563697069656e74730000000961
  6464726573735b5d0000004c0000000200000020111111111111111111111111
  1111111111111111111111111111111111111111000000202222222222222222
  2222222222222222222222222222222222222222222222220000001173656e74
  72795f7075626c69635f6b657900000005627974657300000701222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  2222222222222222222222222222222222222222222222222222222222222222
  222222222222222222222222222222222222222222222222222222

corridor_canonical_behavior_parameters_sha256:
  8291e71b954d6b4815fd82f8a7dbb93e4a5124990e265b9c1a3a3c8060a7d64a
```

Expected authority, Merkle, binding, and transcript values:

```text
corridor_sentry_key_id:
  MM3VSIAUKJ2BT2JBNB7V3HX2YUP7SMLWRWGWDQPEGSZ4ZRK6SLVQ

corridor_contract_admin_key_id:
  WCM6OW66SGGHSCTSAYDHOUGOPEXJLK2YPFQVUSWX6UASKCWRC4DQ

corridor_merkle_root:
  ea4421efa4bc1d9d5bfaf9d578e25655591bd27af8658bf94eee1687ec9c5d8d

corridor_merkle_proof_hex:
  4635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e
  fe43d66afa4a9a5c4f9c9da89f4ffb52635c8f342e7ffb731d68e36c5982072a
  deb82e155954d6be14592c66ccf7a1ece193eeebcdabaf747b91f44519f09f47
  2960044c62f2354e945e8d78fdd220a05f2c0879f24df6f11ef5cc26b5270a0e
  4cfabc48c6898a30b1b5d12dda8e09a96e9ea17e80f4b2a050b8a8b4803fbd43
  7162ed848f19740e53766ce01ac099523b099d593e0782ddbc5296eece50ec50
  2be3cf0551cc6936d461e3dc43f3c4bf50cbee1bc091925254e879f4e7665e94
  12db5262a5500d2516b8f82362d2a87278d20f712ff1fce2019d42ecba17241d
  1a1a9265f869676c206824aa7bfc2fe8c7fe34691dddfb35797b6a321f977dfc
  6e0bb8243e268be3d2fa3ce83234b2f850c85162bd0fced30e919e069bd52df7
  0162892fa669b555682d4c5666f42c98f230e76406d646e6dbbcefb5d311e047
  fd5593f0bfde08caa41745a8a6b2d5dcaea03a5867e8432a995bea3a1fd4df56
  7bbcd27ae0b8f5d7c013dc6d13a2e586b58f83eac62aa62aa56f332288ad8bf4
  d6c82f90e341cc36aa0fb5f8d03bbb3e6d5148eb56fcf79eb415574aee7fa99a
  e2b649c4fa703c323fc2c929ad269dfdd150bde6862d9bcebe966244b983f20f
  48c12a8dd675e9dcd3c63141fbfde6d11056c392b4379c3bbdc79a8511d0e65b

corridor_bounded_program_binding:
  fea0a4e58434a64714bcde9762f19d674e98808192e1280b1fb85b6acd76eb0c

corridor_admin_message:
  076546841ec805465aa8bf90a201014b157be5775288b6958688267af2174a8f
```

Whitespace and line wrapping are presentation only.
`TestCorridorGoldenVector` derives every value from the shipped template and
production canonicalization functions, verifies the frozen constants, and
requires this document to contain the exact profile, behavior, proof, slot
masks, binding, and transcript.

## YAML Contract

Schema v1 describes the existing non-bounded composed layout and rejects a
top-level `bounded` field. Schema v2 requires `bounded` and uses strict
known-field and duplicate-key rejection at every nested level.

```yaml
schema_version: 2
derivation_version: 3
template_type: composed
template_mode: generated
base_key_type: aplane.falcon1024.v1
publisher: aplane
family: falcon1024-allowlist-alock
version: 1
display_name: Falcon-1024 Rekey-Locked Allowlist

bounded:
  contract: bounded1
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients
    asset_ids_parameter: asset_ids
    max_payment_amount_parameter: max_payment_amount
    max_asset_amount_parameter: max_asset_amount

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
  - name: asset_ids
    type: uint64[]
    required: false
    min_items: 1
    max_items: 30
  - name: max_payment_amount
    type: uint64
    required: false
    min: 1
  - name: max_asset_amount
    type: uint64
    required: false
    min: 1
```

`fixed_allowlist` is composer-owned and rejects a non-empty `teal` field. It
handles every effect in `spend_effects`: `pay` constrains `Receiver` and
optional `Amount`; `axfer` and `asset_opt_in` constrain `AssetReceiver` and
optionally `XferAsset` and `AssetAmount`. The sender is always a legal
self-recipient, but asset and amount limits still apply. Empty optional asset/amount values
omit only that named constraint. Both list parameters are canonicalized and
bounded to 30 entries. The policy uses no runtime proof or signer-derived arg.
A spending-key rekey with `policy_gate: layer3` requires `pay` in
`spend_effects`, because a pure rekey is payment-shaped and must enter the
framework policy's payment branch.

`merkle_allowlist` is also composer-owned and accepts only a required
`address[]` recipients parameter with 1-65,536 entries. It requires exactly one
512-byte `merkle_allowlist_proof` derived argument bound to that parameter,
computes the fixed-depth root during program generation, and verifies the
proof for every non-self payment or asset receiver. It accepts no asset-ID or
amount options and rejects author TEAL.

### Merkle Allowlist Compatibility Contract

The `bounded1` Merkle root and proof bytes are compatibility-bearing. Given the
`recipients` address list, implementations must use this exact algorithm:

1. Decode every Algorand address to its raw 32-byte public key. The list must
   contain 1 through 65,536 entries.
2. Reject duplicate public keys, then sort the unique public keys in ascending
   byte order. Duplicate input is invalid, so there is no duplicate proof
   selection rule.
3. Create a depth-16 tree with exactly 65,536 leaves. Place the sorted
   recipients in leaves `0` through `N-1`.
4. A recipient leaf is
   `SHA256(0x00 || recipient_public_key)`.
5. The empty-leaf value is `SHA256(0x00)`. Fill leaves `N` through `65,535`
   with that value.
6. An internal node is
   `SHA256(0x01 || min(left_hash, right_hash) || max(left_hash, right_hash))`,
   where `min` and `max` use ascending byte order.
7. Repeat the internal-node operation for sixteen levels. The sole remaining
   hash is the root compiled into the LogicSig.
8. A membership proof is the sibling at each level, beginning with the leaf
   sibling and proceeding upward to the root. Concatenate the sixteen 32-byte
   hashes in that order for exactly 512 bytes.
9. Verification starts with the recipient leaf and combines each proof hash in
   order using the same internal-node function. No index or direction bits are
   encoded or consumed because every child pair is canonicalized with
   `min`/`max`.

A non-member has no proof. The separate bounded transaction rule permits a
self receiver without a proof; that exception does not change root
construction. `internal/merkleallowlist` owns the implementation, and
`TestMerkleAllowlistCompatibilityVector` freezes a deterministic root and
proof.

`bounded_admin_public_key` is injected by the framework and cannot be declared
by the author. User parameters, variables, runtime args, and references using
the `bounded_` prefix reject. Author labels and executable references using
`__aplane_bounded1_` reject. Author TEAL cannot use `return` or escape the
composer-owned pure-spend boundary.

## Signature Arguments and Durable Metadata

The static slot order is base signatures, signer-derived Layer 3 arguments,
caller runtime Layer 3 arguments, an optional sentry signature, then an
optional external admin signature.
Every slot stores an index, source, maximum size, and required/optional/
forbidden rule for spend, spending-key rekey, and admin-key rekey paths.

Interior unused Layer 3 slots are explicit empty byte strings. Only unused
trailing slots may be omitted. Callers may populate only declared runtime
slots; they cannot populate derived or admin slots. The signer generates only
declared derived slots. The external helper fills only the frozen final admin
slot after independently validating the partial.

The planner classifies before group sizing, finalizes fee pooling, then
revalidates the finalized transactions at the single classification boundary.
The executor consumes that plan, checks that loaded durable metadata still
equals planned metadata, and assembles the declared slots without maintaining
a second classifier. Hybrid effects, disabled operations, final fee violations,
metadata races, and invalid caller slots fail before signature release.
Existing key signing is driven by durable key metadata, not an installed YAML
definition. The metadata contract includes the bounded contract, base layout,
profile, admin operation modes, `layer3_policy`, runtime and derived argument
declarations, static argument layout, Falcon admin public metadata and binding,
and the selected-path LogicSig argument and opcode ceilings. Program bytes come
from the final stored bytecode.

Non-bounded LogicSig keys use `signing_metadata_version: 1`. Bounded keys use
`signing_metadata_version: 2` and require the canonical
`bounded_authorization` object. The closed `layer3_policy` value is `custom`,
`fixed_allowlist`, or `merkle_allowlist`; declared runtime and derived arguments and their complete
slot masks are persisted. Top-level `signing_args` are ignored for bounded
keys. Scan, load, backup, and restore consume the stored object without
consulting the installed template.

## Routing and Approval

`/keys` and `/keytypes` advertise `signing_flow: bounded1` for profiles without
a sentry and `signing_flow: bounded-sentry1` for profiles whose durable
metadata contains `sentry.contract: sentry1`. Both expose the same typed
`bounded_authorization` object. `/keytypes` exposes definition-level
profile and base-layout capabilities. `/keys` additionally exposes the
instance Contract Admin Key ID, program binding, and structured selected-path
LogicSig resource profile. Clients route:

- non-sentry pure spend to ordinary `/sign`;
- sentry-gated pure spend through the first-party client's user-first
  `/sign/bounded-component`, sentry `/sign/component`, then signer
  `/sign/bounded-assemble` choreography;
- spending-key rekey to ordinary `/sign` with forced review;
- Falcon-admin rekey to `POST /sign/bounded-admin` and external completion; and
- malformed, hybrid, disabled, or unknown effects to local rejection.

Ordinary `/sign` rejects a sentry-gated bounded spend because it cannot finish
that flow alone. First-party clients do not support combining `sentry1` and
`bounded-sentry1` targets in one group because their assembly contracts differ;
this is a client orchestration limit, not a signer-side whole-group flow
invariant. Signer-side classification remains authoritative for each target it
signs or assembles. Unknown flow labels fail closed.
Every bounded admin operation triggers the stable unconditional
`bounded_admin_operation_requires_review` rule before blanket or self-no-op
autoapproval, regardless of warning configuration. A client intent to simulate
does not alter this requirement; apsigner sees an ordinary executable signing
request.

## Versioning

After first production deployment, a change to field classification, normal
forms, fee ceiling semantics, canonical encoding, program binding, transcript,
argument placement, endpoint choreography, or flow routing mints a new bounded
contract and key type. Existing LogicSig bytecode cannot learn about a future
authority-bearing field added to an existing transaction type; release review
must assess network-version safety before retaining containment claims.
