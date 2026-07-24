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
contract admin key is an independent witness key in standalone custody that
authorizes a named administrative operation. It is not Algorand Governance,
the `apadmin` client, or an ASA manager key. The key form is shared with sentry
witnesses, but an individual keypair should never be enrolled in both roles.

`bounded1` has three ordered regions:

1. **Authentication:** the base DSA signature is required on every path.
2. **Transaction envelope:** the composer enforces fee, transaction-type,
   administrative-effect, and admin-operation normal-form constraints.
3. **Layer 3 policy:** author or framework policy runs only for an admitted
   pure spend, and for a spending-key rekey only when its operation declares
   `policy_gate: layer3`.

Sentry-enabled bounded1 profiles are spend-gated profiles and may not declare
a spending-key-authorized rekey. V1 rejects that combination during template,
profile, and durable-metadata validation; recovery for a sentry-enabled
profile must use an external contract-admin rekey.

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
| TEAL version | 12 |
| Spend effects | non-empty closed subset of `pay`, `axfer`, `asset_opt_in` |
| Admin operations | `rekey` only |
| Admin authorization | `spending_key` or `admin_key` |
| Admin policy gate | `none` or `layer3`; admin-key authorization requires `none` |
| Contract admin primitive | Falcon-1024 only |
| Contract admin public key | exactly 1,793 bytes |
| Contract admin signature | non-empty, at most 1,280 bytes |
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
fixed-list shape at a 1,000 microAlgo network minimum fee, including the
largest current eight-transaction pooled-budget group. It is an absolute v1
profile ceiling, not a promise of viability on networks with a higher minimum
fee. The planner must reject a network/profile combination whose required
pooled fee exceeds the compiled ceiling.

The composer baseline uses a real Falcon spending verifier and a
controlled trivially true Layer-3 predicate. At a 1,000-byte LogicSig budget
contribution per group transaction, LocalNet compilation freezes:

| Profile | Bytecode | Spend bytes | Admin-rekey bytes | Required group |
|---|---:|---:|---:|---:|
| pay, rekey disabled | 1,882 | 3,162 | n/a | 4 |
| pay/axfer, spending-key rekey | 1,931 | 3,211 | n/a | 4 |
| pay/axfer, Falcon-admin rekey | 3,828 | 5,108 | 6,388 | 7 |

These are compiler/address regression cells, not final product-allowlist
budgets. Every shipped Layer-3 policy adds its own worst-case cells before the
key type can be enabled. The baseline proves that the contract-admin envelope
itself fits under the v1 fee ceiling with three group slots of headroom.

The shipped `aplane.falcon1024-allowlist-alock.v1` worst-case cell compiles
30 recipients, 30 asset IDs, both amount ceilings, a Falcon spending key, and
a Falcon contract admin key:

| Policy cell | Bytecode | Spend bytes | Admin-rekey bytes | Required group |
|---|---:|---:|---:|---:|
| fixed allowlist, audited maximum | 5,312 | 6,592 | 7,872 | 8 |
| Corridor Merkle+sentry | 5,940 | 9,012 | 8,500 | 10 |

At one protected LogicSig transaction, required pooled fee is `8 * min_fee`.
The 10,000 microAlgo profile ceiling accepts minimum fees through 1,250
microAlgos and rejects higher values before signing.

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
Layer 3 condition passes. The rekey-locked allowlist is the independent
recovery option when that tradeoff is unsuitable.

Compiler-backed maximum-path measurements are frozen by
`TestBundledBoundedCompiledBudgetMatrix`:

| Key type | Bytecode | Spend path | Admin path | Largest group |
|---|---:|---:|---:|---:|
| Falcon inline allowlist | 3,159 | 4,439 | n/a | 5 |
| Falcon Merkle allowlist | 2,188 | 3,980 | n/a | 4 |
| Falcon timelock | 1,947 | 3,227 | n/a | 4 |
| Falcon rekey-locked allowlist | 5,312 | 6,592 | 7,872 | 8 |
| Corridor | 5,940 | 9,012 | 8,500 | 10 |

At the 10,000 microAlgo ceiling, Corridor's ten-transaction group is viable at
the current 1,000 microAlgo network minimum fee. The planner rejects higher
minimum fees for this profile before releasing a signature.

## Effect Model

The independent machine-readable inventory is
[`BOUNDED1_PROTOCOL_INVENTORY.json`](BOUNDED1_PROTOCOL_INVENTORY.json). It is
maintained independently of renderer/classifier code and pinned to
go-algorand-sdk v2.11.0, go-algorand reference `589c761a1cfc`, and AVM v12.
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
      field("aplane.witness-falcon1024.v1") || u32(1280) ||
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
  - {index: 1, name: admin_signature, source: admin, max_size: 1280,
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
  72650000000561646d696e0000050000000009666f7262696464656e00000009
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
  23aebf3166f64d6a0e6467d0fde647191094907f733c60fb946129d7cc828509

admin_message:
  324dfa8eee495b7f4ddaa67f640c906184beb49abfd304d1336be233e84998b6
```

Whitespace and line wrapping above are presentation only. Code tests decode
the frozen canonical profile and behavior hexadecimal strings in
`TestBoundedGoldenVector`; that test is authoritative for every byte.

## YAML Contract

Schema v1 describes the existing non-bounded composed layout and rejects a
top-level `bounded` field. Schema v2 requires `bounded` and uses strict
known-field and duplicate-key rejection at every nested level.

```yaml
schema_version: 2
derivation_version: 2
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
and maximum post-signing LogicSig size.

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
instance Contract Admin Key ID, program binding, and maximum post-signing
LogicSig size. Clients route:

- non-sentry pure spend to ordinary `/sign`;
- sentry-gated pure spend through user-first `/sign/bounded-component`, sentry
  `/sign/component`, then signer `/sign/bounded-assemble`;
- spending-key rekey to ordinary `/sign` with forced review;
- Falcon-admin rekey to `POST /sign/bounded-admin` and external completion; and
- malformed, hybrid, disabled, or unknown effects to local rejection.

Ordinary `/sign` rejects a sentry-gated bounded spend because it cannot finish
that flow alone. The client must not combine `sentry1` and `bounded-sentry1`
targets in one group. Signer-side classification is authoritative. Unknown
flow labels fail closed.
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
