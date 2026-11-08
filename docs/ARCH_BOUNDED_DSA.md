# Bounded Authorization Contracts

## Status

This document freezes the `bounded1` contract. The composer envelope, classifier, strict
composed schema v2, durable signing metadata, inventory projection,
framework-owned fixed allowlist, and static Layer-3 argument layout are
implemented.

This is the first supported release of `bounded1`. Canonical encodings and
golden vectors that existed only in development branches before this release
were not a compatibility contract; preview or LocalNet keys derived from those
encodings must be recreated. The encodings and vectors in this document are
the v1 compatibility baseline.

## Purpose and Authority

A bounded authorization contract is a stateless LogicSig program that
defines the complete transaction envelope accepted for an account. The base
spending key authorizes every path. The only administrative operation is a
pure rekey, which a profile may enable under the spending key or omit.

`bounded1` has three ordered regions:

1. **Authentication:** the base DSA signature is required on every path.
2. **Transaction envelope:** the composer enforces fee, transaction-type,
   administrative-effect, and admin-operation normal-form constraints.
3. **Layer 3 policy:** framework policy, author TEAL, or a framework allowlist
   followed by author TEAL runs only for an admitted
   pure spend, and for a spending-key rekey only when its operation declares
   `policy_gate: layer3`.

Cosigner-enabled bounded1 profiles are spend-gated profiles and may not declare
a spending-key-authorized rekey. The combination would bypass the spend-only
cosigner gate and is not routable through `bounded-cosigner1`; V1 rejects it
during template, profile, and durable-metadata validation. A cosigner-enabled
profile therefore declares no rekey operation, and its account can never be
rekeyed. A lost or compromised cosigner cannot be escaped, and the program
cannot be replaced; a later release adds a rekey-to list for this.

For profile `P`:

```text
Envelope(P) = PureSpend(P) union enabled AdminOperation(P, kind)

Accepted(P) =
  {tx in PureSpend(P) where SpendingPolicy(tx)}
  union {tx in enabled AdminOperation(P, kind)
         where operation authentication and its declared policy gate pass}
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
| Admin operations | `rekey` only, or none |
| Admin authorization | `spending_key` only |
| Admin policy gate | `none` or `layer3` |
| Maximum compiled `max_fee` | 10,000 microAlgos |
| Layer-3 arguments | declared static runtime and signer-derived slots |
| Signer-derived primitive | fixed-depth Merkle allowlist proof (512 bytes) |
| Framework Layer-3 policies | `fixed_allowlist`, `merkle_allowlist`, `timelock`, `fixed_allowlist_timelock`, `merkle_allowlist_timelock` |
| Framework allowlist with author TEAL | `fixed_allowlist_custom`, `merkle_allowlist_custom` |
| Inline recipient maximum | 30 entries |
| Flow labels | `bounded1` without a cosigner; `bounded-cosigner1` with a spend cosigner |
| Online cosigner endpoints | `POST /plan`, `POST /sign/component`, `POST /sign/assemble` |
| Bundled composed templates | three schema-v2 profiles listed below |

`bounded1` is the only bounded-authorization contract and has no protocol
aliases.

Generation also refuses a workflow the spending base can't complete. The
bounded cosigner flow needs a Falcon-1024 spending key, so a cosigner on another
base is refused, as is any bounded profile on a base the support policy doesn't
list. The policy is keyed by
the base's signature construction from `internal/sigconstruction`, so a registered
base with no construction is refused too. This is an admission decision for new
accounts, separate from structural validity, and it runs only from `GenerateTEAL`. `ValidateTemplateSpec` and `validateBoundedConfig` stay
structural, because installed templates reach both on load: an error there changes
the template's compatibility fingerprint, which makes it a content defect, and that
sends unlock to recovery mode and blocks store commits.

Signing sites don't read that policy. Admission can narrow over time, and an existing
account must keep signing, so the signer keeps its own table of the spending
constructions each workflow completes
(`internal/signerapp/signing/bounded_construction.go`). It resolves an account's
construction from its durable contract and `base_key_type`. The cosigner flow
completes Falcon-1024 only. A valid signature on any other base is refused where it
always was, before an assembly it couldn't finish. Admission must stay within
the signer's table, or it would create accounts the signer can't complete;
`TestBoundedGenerationAdmitsOnlySignableWorkflows` checks that. Verification itself
is in `internal/sigconstruction/verify`, which takes public inputs only, and signing
stays at its existing role-specific sites.

A witness key must differ from the spending key and from each of its components, so a
key reused inside a larger construction is caught. That compares known keys only, and
it can't show that custody or seeds are independent.

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

Every profile rejects close, clawback, hybrid rekey, and non-transfer types.
The timelock intentionally prevents emergency spending-key rekey until its
Layer 3 condition passes.

Compiler-backed maximum-path measurements are frozen by
`TestBundledBoundedCompiledBudgetMatrix`:

| Key type | Final bytecode | Spend args / v42 group / fee |
|---|---:|---:|
| Falcon inline allowlist | 3,142 | 1,423 / 2 / 2,115 |
| Falcon Merkle allowlist | 2,161 | 1,935 / 2 / 2,017 |
| Falcon timelock | 1,934 | 1,423 / 2 / 2,000 |

Fees are microAlgos at a 1,000-microAlgo minimum fee and include v42 program
pricing. The table uses the conservative 20,000-opcode per-path ceiling; its
group count includes the resource dummies and their own program/opcode use.
The planner rejects a selected path before releasing a signature when its
finalized fee would exceed the profile ceiling.

`TestTimelockPolicyCompiledBudgetMatrix` freezes the framework timelock policies on the
same terms, with full inline lists and the largest unlock round. These are template
compositions, not bundled profiles. Each row gives the final bytecode, then the group
size and fee of the spend path.

| Policy | Rekey authority | Final bytecode | Spend group / fee |
|---|---|---:|---:|
| `timelock` | spending key | 1,932 | 2 / 2,000 |
| `fixed_allowlist_timelock` | spending key | 3,153 | 2 / 2,116 |
| `merkle_allowlist_timelock` | spending key | 2,196 | 2 / 2,021 |

## Effect Model

The independent machine-readable inventory has two parts.
[`PROTOCOL_EFFECT_INVENTORY.json`](PROTOCOL_EFFECT_INVENTORY.json) is the
contract-neutral protocol surface: the SDK transaction types and fields and the
AVM transaction fields. [`BOUNDED1_EFFECT_CLASSIFICATIONS.json`](BOUNDED1_EFFECT_CLASSIFICATIONS.json)
is bounded1's judgment of that surface: which types it admits, and which fields
are danger predicates, spend policy, rekey normal form and so on. A later contract
adds its own classification file against the same surface. Both are maintained
independently of renderer/classifier code, must not be generated from the
implementation manifest, and are pinned to go-algorand-sdk v2.11.2 pseudo-version
`967fcacfacdf`, go-algorand reference `68e036affd9e`, and AVM v13.
It separately freezes the flattened SDK transaction-field surface and parses
the pinned SDK source in tests to detect newly introduced transaction types.

`txeffects.ClassifyFor` decides a transaction's path from the account's path
declaration (`boundedmeta.PathDeclaration`: spend effects, fee ceiling, Layer 3
policy, rekey setting, cosigner) rather than from bounded1's fixed shapes. Every
decision names its rule, and `TestClassifyForReachesAnExplicitRuleForEveryEffect`
runs every declaration the general grammar produces against every transaction type
of the surface, with every combination of rekey, close, asset-close and clawback
fields, so no effect reaches a default branch (O12).
`TestClassifyForAgreesWithTheSignerClassifier` pins that it decides exactly as the
signer's classifier does today.

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
- satisfies the `spending_key` authorization and its declared policy gate.

A profile that declares no rekey operation has no rekey path, so every
transaction with a nonzero `RekeyTo` rejects.

Rekey detection runs before spend-type routing. Rekey-plus-transfer,
rekey-plus-close, and every other hybrid reject. A group may contain separate
normal-form transactions, but bounded1 guarantees only each protected
transaction's envelope, not group-wide semantic safety.

Spending-key authorization preserves pure shape but does not contain theft of
the spending key. A profile that declares no rekey operation keeps a stolen
spending key inside the spend envelope.

## Canonical Encoding

All hashes in this section use SHA-512/256. `u32(x)` and `u64(x)` are unsigned
big-endian integers. `field(x)` is `u32(len(x)) || x`. Text is exact UTF-8
without a terminator or Unicode normalization. Lists carry a `u32` count and
then canonical elements. No JSON or YAML serialization is hashed. The canonical
profile enters a template's compatibility fingerprint, and both canonical
encodings enter the [general boundary digest](#general-boundary-digest).

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
  u32(cosigner_present) ||
    if present: field("cosigner1") ||
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
the canonical profile. Each derived argument record is `field(name) ||
field(kind) || field(parameter) || u32(max_size)`; each runtime argument record
is `field(name) || field(type) || u32(required) || u32(byte_length) ||
u32(max_size)`; each argument slot record is `u32(index) || field(name) ||
field(source) || u32(max_size)` followed by `field` of its spend,
spending-rekey, and admin-rekey path rules. No authority uses the admin-rekey
path; it stays in every slot record so that the encoding, and every existing
fingerprint and digest, does not change. `cosigner_present` is exactly zero
or one. The initial
optional cosigner contract has the single ordered path list `[spend]`.

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
definition order. A cosigner-enabled profile includes the framework-injected
`cosigner_public_key`, so the encoding commits to the resolved cosigner key.
Display metadata, file paths, runtime values, and policy provenance are
excluded.

Canonical scalar values are: address as raw 32 bytes; bytes as raw bytes;
unsigned integer as `u64`; boolean as one byte `0x00` or `0x01`; and string as
UTF-8. A missing or explicitly empty optional parameter has a zero-length
`canonical_value`; this is distinct from an explicit numeric zero, false, or
empty list. A list value is `u32(count) || field(element_0) || ...`. Nested or
new parameter types require a new encoding rule before use by bounded.

### Bounded-cosigner assembly receipt

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

### Golden vector 1: allowlist with author TEAL

These vectors freeze the two combined `layer3_policy` values. Both use a Falcon-1024
base, `spend_effects: [pay, axfer, asset_opt_in]`, `max_fee: 10000`, one spending-key
rekey with `policy_gate: layer3`, no cosigner, and a required 1-to-64-byte `preimage`
runtime argument on spend and rekey. The Merkle vector adds the `merkle_proof` derived
argument bound to `recipients`.

| Index | Name | Source | Max bytes | Spend | Spending rekey | Admin rekey |
|---:|---|---|---:|---|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required | required |
| 1 | `preimage` | `runtime` | 64 | required | required | forbidden |

```text
author_fixed_canonical_bounded_profile_length: 357
author_fixed_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000c7370656e64696e675f6b6579000000066c617965723300000000
  0000001666697865645f616c6c6f776c6973745f637573746f6d000000010000
  058f000000000000000100000008707265696d61676500000005627974657300
  0000010000000000000040000000020000000000000010626173655f7369676e
  61747572655f300000000e626173655f7369676e61747572650000058f000000
  0872657175697265640000000872657175697265640000000872657175697265
  640000000100000008707265696d6167650000000772756e74696d6500000040
  00000008726571756972656400000008726571756972656400000009666f7262
  696464656e
```

| Index | Name | Source | Max bytes | Spend | Spending rekey | Admin rekey |
|---:|---|---|---:|---|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required | required |
| 1 | `merkle_proof` | `derived` | 512 | optional | forbidden | forbidden |
| 2 | `preimage` | `runtime` | 64 | required | required | forbidden |

```text
author_merkle_canonical_bounded_profile_length: 491
author_merkle_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000c7370656e64696e675f6b6579000000066c617965723300000000
  000000176d65726b6c655f616c6c6f776c6973745f637573746f6d0000000100
  00058f000000010000000c6d65726b6c655f70726f6f66000000166d65726b6c
  655f616c6c6f776c6973745f70726f6f660000000a726563697069656e747300
  0002000000000100000008707265696d61676500000005627974657300000001
  0000000000000040000000030000000000000010626173655f7369676e617475
  72655f300000000e626173655f7369676e61747572650000058f000000087265
  7175697265640000000872657175697265640000000872657175697265640000
  00010000000c6d65726b6c655f70726f6f660000000764657269766564000002
  00000000086f7074696f6e616c00000009666f7262696464656e00000009666f
  7262696464656e0000000200000008707265696d6167650000000772756e7469
  6d65000000400000000872657175697265640000000872657175697265640000
  0009666f7262696464656e
```

`TestAllowlistWithAuthorTEALGoldenVectors` is authoritative for every byte. The
expected values were computed from the encoding in this document by a separate
encoder, so they do not simply restate the implementation's output.

### Golden vector 2: timelock policies

These vectors freeze the three timelock `layer3_policy` values. Each uses a Falcon-1024
base, `spend_effects: [pay, axfer, asset_opt_in]`, `max_fee: 10000`, one spending-key
rekey with `policy_gate: layer3`, no cosigner, and no runtime arguments. The unlock round
and recipients are behavior parameters, so they do not appear in the profile.
`timelock` and `fixed_allowlist_timelock` have the single-slot layout. The Merkle vector
adds the `merkle_proof` derived argument bound to `recipients`.

| Index | Name | Source | Max bytes | Spend | Spending rekey | Admin rekey |
|---:|---|---|---:|---|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required | required |
| 1 | `merkle_proof` | `derived` | 512 | optional | forbidden | forbidden |

```text
timelock_canonical_bounded_profile_length: 242
timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000c7370656e64696e675f6b6579000000066c617965723300000000
  0000000874696d656c6f636b000000010000058f000000000000000000000001
  0000000000000010626173655f7369676e61747572655f300000000e62617365
  5f7369676e61747572650000058f000000087265717569726564000000087265
  717569726564000000087265717569726564
```

```text
fixed_allowlist_timelock_canonical_bounded_profile_length: 258
fixed_allowlist_timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000c7370656e64696e675f6b6579000000066c617965723300000000
  0000001866697865645f616c6c6f776c6973745f74696d656c6f636b00000001
  0000058f0000000000000000000000010000000000000010626173655f736967
  6e61747572655f300000000e626173655f7369676e61747572650000058f0000
  0008726571756972656400000008726571756972656400000008726571756972
  6564
```

```text
merkle_allowlist_timelock_canonical_bounded_profile_length: 392
merkle_allowlist_timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5631000000
  08626f756e646564310000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e0000000000002710000000010000000572656b
  65790000000c7370656e64696e675f6b6579000000066c617965723300000000
  000000196d65726b6c655f616c6c6f776c6973745f74696d656c6f636b000000
  010000058f000000010000000c6d65726b6c655f70726f6f66000000166d6572
  6b6c655f616c6c6f776c6973745f70726f6f660000000a726563697069656e74
  730000020000000000000000020000000000000010626173655f7369676e6174
  7572655f300000000e626173655f7369676e61747572650000058f0000000872
  6571756972656400000008726571756972656400000008726571756972656400
  0000010000000c6d65726b6c655f70726f6f6600000007646572697665640000
  0200000000086f7074696f6e616c00000009666f7262696464656e0000000966
  6f7262696464656e
```

`TestTimelockPolicyGoldenVectors` is authoritative for every byte. The separate encoder
reproduced both author-TEAL vectors before computing these.

## YAML Contract

Schema v1 describes the existing non-bounded composed layout and rejects a
top-level `bounded` field. Schema v2 requires `bounded`. Every schema version
uses strict known-field and duplicate-key rejection at every nested level.
`bounded.runtime_args` and `bounded.derived_args` declare the only permitted
Layer 3 slots. V1 supports caller runtime values with explicit maximum/exact
length contracts and the signer-derived `merkle_allowlist_proof` primitive.

```yaml
schema_version: 2
derivation_version: 3
template_type: composed
template_mode: generated
base_key_type: aplane.falcon1024.v1
publisher: aplane
family: falcon1024-allowlist
version: 1
display_name: Falcon-1024 Allowlist

bounded:
  contract: bounded1
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: spending_key
      policy_gate: none
  layer3:
    policy: fixed_allowlist
    recipients_parameter: recipients

parameters:
  - name: recipients
    type: address[]
    required: true
    min_items: 1
    max_items: 30
```

An empty or omitted `admin_operations` declares no rekey operation, so the
program has no rekey path.

`fixed_allowlist` is composer-owned. It
handles every effect in `spend_effects`: `pay` constrains `Receiver`; `axfer`
and `asset_opt_in` constrain `AssetReceiver`. The sender is always a legal
self-recipient. The recipients parameter is canonicalized and bounded to 30
entries. The policy uses no runtime proof or signer-derived arg.

Neither framework policy compiles an asset or amount check. One program is
valid on every network, while an asset ID names an asset on one chain only and
a base-unit amount means nothing across assets. Per-network asset and amount
limits belong to signer policy.
A spending-key rekey with `policy_gate: layer3` requires `pay` in
`spend_effects`, because a pure rekey is payment-shaped and must enter the
framework policy's payment branch.

`merkle_allowlist` is also composer-owned and accepts only a required
`address[]` recipients parameter with 1-65,536 entries. It requires exactly one
512-byte `merkle_allowlist_proof` derived argument bound to that parameter,
computes the fixed-depth root during program generation, and verifies the
proof for every non-self payment or asset receiver.
Omitting `bounded.layer3` selects contained custom author TEAL.

A template may declare `bounded.layer3` with either allowlist and also supply `teal`.
The framework allowlist runs first and falls through to the author TEAL, and both must
pass, so the author TEAL can only narrow what the allowlist admits. It cannot skip the
list: the existing containment rules forbid `return` and any reference to reserved
bounded labels. Author parameters may sit beside the recipients parameter, and runtime
arguments beside a Merkle proof, in the static slot order above. The template declares
only the plain policy; durable metadata records `fixed_allowlist_custom` or
`merkle_allowlist_custom`, which a template cannot declare directly. These values amend
this contract under `bounded1` and signing metadata version 2: the encoding and
authorization flows do not change. A policy gate of `layer3` applies the author rule to
a spending-key rekey too, and a gate of `none` skips both. An allowlist with no `teal`
rejects extra parameters and runtime arguments, because nothing would read them.

`timelock` requires `FirstValid >= unlock_round` and reads no recipient list.
`fixed_allowlist_timelock` and `merkle_allowlist_timelock` apply the same check, then
render exactly the recipient check of the matching allowlist, under the same list limits
and Merkle proof contract. These policies name the unlock round through
`unlock_round_parameter`, which must identify a required `uint64` parameter with
`min: 1`, and they reject a `recipients_parameter` or `unlock_round_parameter` they do not
use. A round compiles the same way on every network but means a different time on each,
and it does not bind the program to one network.

The timelock also applies to self-receivers, which the recipient check would otherwise
admit. It applies to a rekey only through a `policy_gate` of `layer3`, which requires
`pay` in `spend_effects`. A spending-key rekey with a gate of `none` skips it, so it can
move the account before the unlock round.

Timelock policies reject author TEAL, parameters they do not read, and runtime arguments.
An author who needs a list and custom time conditions uses a plain allowlist and writes
those conditions in the TEAL. These values amend this contract under `bounded1` and
signing metadata version 2: the encoding and authorization flows do not change. Older
binaries reject the new values.

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

`cosigner_public_key` is injected by the framework. An author parameter or
runtime argument named `cosigner` or starting with `cosigner_` rejects. User
parameters, variables, runtime args, and references using
the `bounded_` prefix reject. Author labels and executable references using
`__aplane_bounded1_` reject. Author TEAL cannot use `return` or escape the
composer-owned pure-spend boundary.

## Signature Arguments and Durable Metadata

The static slot order is base signatures, signer-derived Layer 3 arguments,
caller runtime Layer 3 arguments, then an optional cosigner signature.
Every slot stores an index, source, maximum size, and required/optional/
forbidden rule for spend, spending-key rekey, and admin-rekey paths. No
authority uses the admin-rekey path; it stays for encoding stability.

Interior unused Layer 3 slots are explicit empty byte strings. Only unused
trailing slots may be omitted. Callers may populate only declared runtime
slots; they cannot populate derived or cosigner slots. The signer generates only
declared derived slots. Ordinary `/sign` rejects caller-supplied cosigner or
signer-derived values.

The planner classifies before group sizing, finalizes fee pooling, then
revalidates the finalized transactions at the single classification boundary.
The executor consumes that plan, checks that loaded durable metadata still
equals planned metadata, and assembles the declared slots without maintaining
a second classifier. Hybrid effects, disabled operations, final fee violations,
metadata races, and invalid caller slots fail before signature release.
Existing key signing is driven by durable key metadata, not an installed YAML
definition. The metadata contract includes the bounded contract, base layout,
profile, admin operation modes, `layer3_policy`, runtime and derived argument
declarations, static argument layout, optional cosigner authorization, and the
selected-path LogicSig argument and opcode ceilings. Program bytes come
from the final stored bytecode.

Non-bounded LogicSig keys use `signing_metadata_version: 1`. Bounded keys use
`signing_metadata_version: 2` and require the canonical
`bounded_authorization` object. The closed `layer3_policy` value is `custom`,
`fixed_allowlist`, `merkle_allowlist`, `fixed_allowlist_custom`,
`merkle_allowlist_custom`, `timelock`, `fixed_allowlist_timelock`, or
`merkle_allowlist_timelock`; declared runtime and derived arguments and their complete
slot masks are persisted. Top-level `signing_args` are ignored for bounded
keys. Scan, load, backup, and restore consume the stored object without
consulting the installed template.

## Routing and Approval

`/keys` and `/keytypes` advertise `signing_flow: bounded1` for profiles without
a cosigner and `signing_flow: bounded-cosigner1` for profiles whose durable
metadata contains `cosigner.contract: cosigner1`. Both expose the same typed
`bounded_authorization` object. `/keytypes` exposes definition-level
profile and base-layout capabilities. `/keys` additionally exposes the
structured selected-path LogicSig resource profile. Clients route:

- non-cosigner pure spend to ordinary `/sign`;
- cosigner-gated pure spend through the first-party client's user-first
  `/plan`, kind-tagged signer and cosigner `/sign/component`, then signer
  `/sign/assemble` choreography;
- spending-key rekey to ordinary `/sign` with forced review; and
- malformed, hybrid, disabled, or unknown effects to local rejection.

Ordinary `/sign` rejects a cosigner-gated bounded spend because it cannot finish
that flow alone. First-party clients do not support combining `cosigner1` and
`bounded-cosigner1` targets in one group because their assembly contracts differ;
this is a client orchestration limit, not a signer-side whole-group flow
invariant. Signer-side classification remains authoritative for each target it
signs or assembles. Unknown flow labels fail closed.
Every bounded admin operation, which is a spending-key rekey, triggers the
stable unconditional `bounded_admin_operation_requires_review` rule before
policy self-no-op autoapproval, regardless of warning configuration. User
Auto-Approve satisfies this review requirement without a prompt. A client intent to simulate
does not alter this requirement; apsigner sees an ordinary executable signing
request.

## General Boundary Digest

`aplane.falcon1024-b.v1` accounts have a comparison digest. Using the field encoding above:

```text
SHA512/256(
  field("APLANE_GENERAL_BOUNDARY_V1") ||
  field("aplane.boundary.v1") ||
  field(selected_shape_fingerprint) ||
  field(base_primitive) ||
  field(canonical_bounded_profile) ||
  field(canonical_behavior_parameters) ||
  field("")
)
```

The last field is always empty. It is unused and stays so that every shape keeps
its digest. A cosigner key is a behavior parameter, so it
is covered there. The digest excludes the spending key, filenames, reference names,
and labels, and it binds the selected shape rather than the whole grammar, so an
unrelated new rule leaves it unchanged.

It is a comparison value. It does not assert that two accounts have the same address,
and it replaces no signing transcript. It is
defined only for this key type: custom Layer 3 code is not bound by it.

### Golden vector 3: general boundary digest

This vector uses the Corridor shape: all three transfer kinds, `merkle_allowlist`,
rekeys refused, and a cosigner. The two recipients are the addresses whose 32 raw bytes
are all zero except `[1] = 1, [31] = 1` and `[1] = 2, [31] = 1`. The cosigner key is
1,793 bytes of `0x41`.

An independent Python encoder reproduces the profile and the digest from the rules in
this document. The shape fingerprint is an input to that check: it comes from the
provider's own configuration hash, which this document does not define byte for byte.

```text
selected_shape_fingerprint:
  1:0f98cccfa0a7769946e94e6d40954e50de6a14751c0f7268a02cdf6fa0252be9
base_primitive: falcon1024-v1
canonical_bounded_profile_length: 490
canonical_bounded_profile_sha512_256:
  160183e56fc444014164ae5f541b87ccce8d598827a6e5f5054bb7b6625820c3
canonical_behavior_parameters_length: 1981
canonical_behavior_parameters_sha512_256:
  3e37447008e20eab3259c3c109224f012ebd3bee4061db71b97298205665fdc9
boundary_digest:
  94ed73af648eb35f51ec8122cbb9cd6d6cdfc378f8536afe448cd3309fe49544
```

## Versioning

After first production deployment, a change to field classification, normal
forms, fee ceiling semantics, canonical encoding, transcript,
argument placement, endpoint choreography, or flow routing mints a new bounded
contract and key type. Existing LogicSig bytecode cannot learn about a future
authority-bearing field added to an existing transaction type; release review
must assess network-version safety before retaining containment claims.
