# Bounded Authorization Contracts

## Status

This document freezes the `bounded2` contract. The composer envelope, the path
declaration and its classifier, strict composed schema v2, durable signing
metadata, inventory projection, framework-owned Layer 3 policies, and static
Layer-3 argument layout are implemented.

Canonical encodings and golden vectors from development builds are not a
compatibility contract; keys derived from them must be recreated. The encodings
and vectors in this document are the `bounded2` compatibility baseline.

## Purpose and Authority

A bounded authorization contract is a stateless LogicSig program that
defines the complete transaction envelope accepted for an account. The base
spending key authorizes every path. An account's rekey setting is `refused`,
which gives it no rekey path, or `spending_key`, which lets the spending key
alone authorize a pure rekey.

`bounded2` has three ordered regions:

1. **Authentication:** the base DSA signature is required on every path.
2. **Transaction envelope:** the composer checks the fee ceiling, then
   dispatches on `RekeyTo`. A rekey is accepted in pure rekey normal form when
   the account declares `rekey: spending_key`, and rejected otherwise. Every
   other transaction must have zero danger fields and an admitted spend type.
3. **Layer 3 policy:** framework policy, author TEAL, or a framework allowlist
   followed by author TEAL runs only for an admitted pure spend.

No host rule gates a rekey. The rekey path accepts or rejects before any
Layer 3, cosigner, or author code runs, so no Layer 3 policy applies to a
rekey. The framework timelock policies therefore require `rekey: refused`: a
spending-key rekey would leave the lock before the unlock round.

Cosigner-enabled bounded profiles gate spends only and require
`rekey: refused`. A spending-key rekey would bypass the spend-only cosigner gate
and is not routable through `bounded-cosigner1`; template, profile, and
durable-metadata validation reject it. A cosigner-enabled account can therefore
never be rekeyed. A lost or compromised cosigner cannot be escaped, and the
program cannot be replaced; a later release adds a rekey-to list for this.

For profile `P`:

```text
Envelope(P) = PureSpend(P) union PureRekey(P)
  where PureRekey(P) is empty when P declares rekey: refused

Accepted(P) =
  {tx in PureSpend(P) where SpendingPolicy(tx)}
  union {tx in PureRekey(P)}
```

The guaranteed containment property is `Accepted(P) subset-of Envelope(P)`.
A spending-key rekey widens the envelope; only Layer 3 is monotone narrowing.
The contract does not claim that an arbitrary custom Layer-3 policy is a
complete value-spending policy.

## Frozen Decisions

| Property | `bounded2` value |
|---|---|
| Contract identifier | `bounded2` |
| Composed YAML schema | `schema_version: 2` |
| TEAL version | 13 |
| Spend effects | non-empty closed subset of `pay`, `axfer`, `asset_opt_in` |
| Rekey setting | `refused` or `spending_key` |
| Rekey and Layer 3 | a rekey never reaches Layer 3 or the cosigner check |
| Maximum compiled `max_fee` | 10,000 microAlgos |
| Layer-3 arguments | declared static runtime (spend only) and signer-derived slots |
| Signer-derived primitive | fixed-depth Merkle allowlist proof (512 bytes) |
| Framework Layer-3 policies | `fixed_allowlist`, `merkle_allowlist`, `timelock`, `fixed_allowlist_timelock`, `merkle_allowlist_timelock`; `none` for the general type only |
| Framework allowlist with author TEAL | `fixed_allowlist_custom`, `merkle_allowlist_custom` |
| Inline recipient maximum | 30 entries |
| Flow labels | `bounded1` without a cosigner; `bounded-cosigner1` with a spend cosigner |
| Online cosigner endpoints | `POST /plan`, `POST /sign/component`, `POST /sign/assemble` |
| Bundled composed templates | none; the general type `aplane.falcon1024-b.v1` offers the allowlist, timelock and limits-only shapes |

`bounded2` is the only bounded-authorization contract and has no protocol
aliases. Flow labels version the client/server choreography, not the contract,
so a `bounded2` account still advertises `bounded1` or `bounded-cosigner1`.

Generation also refuses a workflow the spending base can't complete. The
bounded cosigner flow needs a Falcon-1024 spending key, so a cosigner on another
base is refused, as is any bounded profile on a base the support policy doesn't
list. The policy is keyed by
the base's signature construction from `internal/sigconstruction`, so a registered
base with no construction is refused too. This is an admission decision for new
accounts, separate from structural validity, and it runs only from `GenerateTEAL`. `ValidateTemplateSpec` and `validateBoundedConfig` stay
structural, because installed templates reach both on load: an error there changes
the template's compatibility fingerprint, which makes it a content defect, and that
sends unlock to recovery mode and blocks store commits. Two tests pin this:
`TestAdmissionStaysOutOfLoadAndFingerprint` on the composer, and
`TestInstalledTemplateOutsideGenerationSupportKeepsTheStoreUsable` on a real store,
with a template on a base the policy doesn't list.

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
profile ceiling, not a promise of viability on networks with a higher
minimum fee. Group size and network-fee viability are path-specific. The
planner resolves argument/opcode dummies and priced program bytes for the
active consensus profile, then rejects a transaction path whose finalized fee
exceeds the compiled ceiling.

The composer baseline uses a real Falcon spending verifier and a controlled
trivially true Layer-3 predicate. Every Layer-3 policy adds its own
final-bytecode and selected-path resource cells before a key type that uses it
can be enabled. `TestBoundedFixtureCompiledBudgetMatrix` compiles fixture
templates with the pinned TEAL v13 toolchain, derives argument layouts from
durable bounded metadata, applies the conservative reviewed opcode ceiling,
and runs the production v42 resource solver.

The resulting fee includes transaction bases and priced program bytes. The
compiled 10,000 microAlgo `max_fee` applies to every path. A higher network
minimum fee is evaluated through the same unified fee calculation rather than
through a legacy `ceil(program + args)` projection.

Schema-v1 custom DSA policy is expert mode. Schema-v2 bounded templates may
also use custom Layer 3 TEAL, but the framework still owns the effect envelope,
fee ceiling, slot layout, and path routing.

## Compiled Budgets

No bounded template is bundled. The general type `aplane.falcon1024-b.v1`
(see [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md)) offers the allowlist and timelock
shapes. Compiler-backed maximum-path measurements for three fixture templates
are frozen by `TestBoundedFixtureCompiledBudgetMatrix`:

| Fixture | Layer 3 | Rekey | Final bytecode | Spend args / v42 group / fee |
|---|---|---|---:|---:|
| Fixed allowlist | `fixed_allowlist`, 30 recipients | spending key | 3,142 | 1,423 / 2 / 2,115 |
| Merkle allowlist | author TEAL with a signer-derived proof | spending key | 2,161 | 1,935 / 2 / 2,017 |
| Custom timelock | author TEAL `FirstValid >= unlock_round` | refused | 1,894 | 1,423 / 2 / 2,000 |

Every profile rejects close, clawback, hybrid rekey, and non-transfer types.

Fees are microAlgos at a 1,000-microAlgo minimum fee and include v42 program
pricing. The table uses the conservative 20,000-opcode per-path ceiling; its
group count includes the resource dummies and their own program/opcode use.
The planner rejects a selected path before releasing a signature when its
finalized fee would exceed the profile ceiling.

`TestTimelockPolicyCompiledBudgetMatrix` freezes the framework timelock policies on the
same terms, with full inline lists and the largest unlock round. A timelock refuses
rekeys, so its two arrangements are rekeys refused, with or without a cosigner. Each
row gives the final bytecode, then the group size and fee of the spend path.

| Policy | Arrangement | Final bytecode | Spend group / fee |
|---|---|---:|---:|
| `timelock` | rekeys refused | 1,889 | 2 / 2,000 |
| `timelock` | rekeys refused, cosigner | 3,734 | 3 / 3,075 |
| `fixed_allowlist_timelock` | rekeys refused | 3,110 | 2 / 2,112 |
| `fixed_allowlist_timelock` | rekeys refused, cosigner | 4,952 | 3 / 3,197 |
| `merkle_allowlist_timelock` | rekeys refused | 2,153 | 2 / 2,016 |
| `merkle_allowlist_timelock` | rekeys refused, cosigner | 3,995 | 4 / 4,002 |

## Effect Model

The independent machine-readable inventory has two parts.
[`PROTOCOL_EFFECT_INVENTORY.json`](PROTOCOL_EFFECT_INVENTORY.json) is the
contract-neutral protocol surface: the SDK transaction types and fields and the
AVM transaction fields. [`BOUNDED_EFFECT_CLASSIFICATIONS.json`](BOUNDED_EFFECT_CLASSIFICATIONS.json)
is `bounded2`'s judgment of that surface: which types it admits, and which fields
are danger predicates, spend policy, rekey normal form and so on. A later contract
adds its own classification file against the same surface. Both are maintained
independently of renderer/classifier code, must not be generated from the
implementation manifest, and are pinned to go-algorand-sdk v2.11.2 pseudo-version
`967fcacfacdf`, go-algorand reference `68e036affd9e`, and AVM v13.
The surface separately freezes the flattened SDK transaction-field surface, and
tests parse the pinned SDK source to detect newly introduced transaction types.

### Path declaration

An account's path declaration (`boundedmeta.PathDeclaration`) states what it
allows: its spend effects, fee ceiling, Layer 3 policy, rekey setting, and
cosigner. `Metadata.Declaration()` projects it from stored metadata, and the
signer classifies every bounded target against it through
`txeffects.ClassifyFor` (`classifyBoundedPath` in
`internal/signerapp/signing/bounded.go`). An invalid declaration is an error, not
a refusal.

`ClassifyFor` checks the fee ceiling first, then the transaction's shape. Every
decision names its rule:

| Rule | Path | When |
|---|---|---|
| `fee_ceiling` | refused | `Fee` exceeds the declared ceiling |
| `spend_allowed` | spend | a pure spend of a declared effect |
| `spend_not_declared` | refused | a pure spend of an effect the account does not declare |
| `rekey_allowed` | spending rekey | a pure rekey under `rekey: spending_key` |
| `rekey_refused` | refused | a pure rekey under `rekey: refused` |
| `hybrid_rekey` | refused | a nonzero `RekeyTo` on anything but a pure rekey |
| `denied_effect` | refused | a close, asset close, or clawback |
| `denied_type` | refused | any other transaction type than `pay` and `axfer` |

A refusal names the contract, for example "bounded2 account permanently disables
rekey". `TestClassifyForReachesAnExplicitRuleForEveryEffect` runs every
declaration the general grammar produces against every transaction type of the
surface, with every combination of rekey, close, asset-close and clawback fields,
and requires an explicit allow or refuse rule for each, never a default branch.

The framework danger predicates are:

| Effect | Predicate |
|---|---|
| Rekey | `RekeyTo != ZeroAddress` |
| ALGO account close | `CloseRemainderTo != ZeroAddress` |
| ASA position close | `AssetCloseTo != ZeroAddress` |
| ASA clawback execution | `AssetSender != ZeroAddress` |

`Fee` is a bounded outflow, not an authority effect, and is checked on every path.
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
- belongs to an account that declares `rekey: spending_key`.

No Layer 3 policy, author TEAL, or cosigner check applies to a pure rekey. A
profile that declares `rekey: refused` has no rekey path, so every transaction
with a nonzero `RekeyTo` rejects.

The program checks the spending signature, then the fee ceiling, then dispatches
on `RekeyTo`, before the other danger fields and spend-type routing. The rekey
branch either asserts the pure rekey form and accepts, or rejects. Rekey-plus-transfer,
rekey-plus-close, and every other hybrid reject. A group may contain separate
normal-form transactions, but `bounded2` guarantees only each protected
transaction's envelope, not group-wide semantic safety.

Spending-key authorization preserves pure shape but does not contain theft of
the spending key. A profile that declares `rekey: refused` keeps a stolen
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
  field("APLANE_BOUNDED_PROFILE_V2") ||
  field("bounded2") ||
  u32(count(spend_effects)) ||
    field(effect_0) || ... || field(effect_n) ||
  u64(max_fee) ||
  field(rekey) ||
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

Spend effects use frozen order `pay`, `axfer`, `asset_opt_in`. Duplicates are
invalid. Empty spend sets are invalid. `asset_opt_in` is the zero-amount
self-receiver asset-transfer form and is authorized independently from `axfer`.
`max_fee` must be present and no greater than 10,000. `rekey` is the text
`refused` or `spending_key`. The Layer 3 identity, argument declarations, maximum
sizes, frozen indexes, sources, and path masks are security-bearing and therefore
part of the canonical profile. Each derived argument record is `field(name) ||
field(kind) || field(parameter) || u32(max_size)`; each runtime argument record
is `field(name) || field(type) || u32(required) || u32(byte_length) ||
u32(max_size)`; each argument slot record is `u32(index) || field(name) ||
field(source) || u32(max_size) || field(spend_rule) || field(spending_rekey_rule)`,
where each rule is `required`, `optional`, or `forbidden`. `cosigner_present` is
exactly zero or one. The optional cosigner contract has the single ordered path
list `[spend]`.

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
base, `spend_effects: [pay, axfer, asset_opt_in]`, `max_fee: 10000`, `rekey: spending_key`,
no cosigner, and a 1-to-64-byte `preimage` runtime argument required on spend and
forbidden on the rekey path. The Merkle vector adds the `merkle_proof` derived
argument bound to `recipients`.

| Index | Name | Source | Max bytes | Spend | Spending rekey |
|---:|---|---|---:|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required |
| 1 | `preimage` | `runtime` | 64 | required | forbidden |

```text
author_fixed_canonical_bounded_profile_length: 339
author_fixed_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5632000000
  08626f756e646564320000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e00000000000027100000000c7370656e64696e
  675f6b657900000000000000000000001666697865645f616c6c6f776c697374
  5f637573746f6d000000010000058f000000000000000100000008707265696d
  6167650000000562797465730000000100000000000000400000000200000000
  00000010626173655f7369676e61747572655f300000000e626173655f736967
  6e61747572650000058f00000008726571756972656400000008726571756972
  65640000000872657175697265640000000100000008707265696d6167650000
  000772756e74696d650000004000000008726571756972656400000009666f72
  62696464656e00000009666f7262696464656e
```

| Index | Name | Source | Max bytes | Spend | Spending rekey |
|---:|---|---|---:|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required |
| 1 | `merkle_proof` | `derived` | 512 | optional | forbidden |
| 2 | `preimage` | `runtime` | 64 | required | forbidden |

```text
author_merkle_canonical_bounded_profile_length: 473
author_merkle_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5632000000
  08626f756e646564320000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e00000000000027100000000c7370656e64696e
  675f6b65790000000000000000000000176d65726b6c655f616c6c6f776c6973
  745f637573746f6d000000010000058f000000010000000c6d65726b6c655f70
  726f6f66000000166d65726b6c655f616c6c6f776c6973745f70726f6f660000
  000a726563697069656e7473000002000000000100000008707265696d616765
  0000000562797465730000000100000000000000400000000300000000000000
  10626173655f7369676e61747572655f300000000e626173655f7369676e6174
  7572650000058f00000008726571756972656400000008726571756972656400
  0000087265717569726564000000010000000c6d65726b6c655f70726f6f6600
  0000076465726976656400000200000000086f7074696f6e616c00000009666f
  7262696464656e00000009666f7262696464656e000000020000000870726569
  6d6167650000000772756e74696d650000004000000008726571756972656400
  000009666f7262696464656e00000009666f7262696464656e
```

`TestAllowlistWithAuthorTEALGoldenVectors` is authoritative for every byte. The
expected values were computed from the encoding in this document by a separate
encoder, so they do not simply restate the implementation's output.

### Golden vector 2: timelock policies

These vectors freeze the three timelock `layer3_policy` values. Each uses a Falcon-1024
base, `spend_effects: [pay, axfer, asset_opt_in]`, `max_fee: 10000`, `rekey: refused`,
no cosigner, and no runtime arguments. The unlock round and recipients are behavior
parameters, so they do not appear in the profile.
`timelock` and `fixed_allowlist_timelock` have the single-slot layout. The Merkle vector
adds the `merkle_proof` derived argument bound to `recipients`.

| Index | Name | Source | Max bytes | Spend | Spending rekey |
|---:|---|---|---:|---|---|
| 0 | `base_signature_0` | `base_signature` | 1423 | required | required |
| 1 | `merkle_proof` | `derived` | 512 | optional | forbidden |

```text
timelock_canonical_bounded_profile_length: 218
timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5632000000
  08626f756e646564320000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e00000000000027100000000772656675736564
  00000000000000000000000874696d656c6f636b000000010000058f00000000
  00000000000000010000000000000010626173655f7369676e61747572655f30
  0000000e626173655f7369676e61747572650000058f00000008726571756972
  6564000000087265717569726564000000087265717569726564
```

```text
fixed_allowlist_timelock_canonical_bounded_profile_length: 234
fixed_allowlist_timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5632000000
  08626f756e646564320000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e00000000000027100000000772656675736564
  00000000000000000000001866697865645f616c6c6f776c6973745f74696d65
  6c6f636b000000010000058f0000000000000000000000010000000000000010
  626173655f7369676e61747572655f300000000e626173655f7369676e617475
  72650000058f0000000872657175697265640000000872657175697265640000
  00087265717569726564
```

```text
merkle_allowlist_timelock_canonical_bounded_profile_length: 368
merkle_allowlist_timelock_canonical_bounded_profile_hex:
  0000001941504c414e455f424f554e4445445f50524f46494c455f5632000000
  08626f756e646564320000000300000003706179000000056178666572000000
  0c61737365745f6f70745f696e00000000000027100000000772656675736564
  0000000000000000000000196d65726b6c655f616c6c6f776c6973745f74696d
  656c6f636b000000010000058f000000010000000c6d65726b6c655f70726f6f
  66000000166d65726b6c655f616c6c6f776c6973745f70726f6f660000000a72
  6563697069656e74730000020000000000000000020000000000000010626173
  655f7369676e61747572655f300000000e626173655f7369676e617475726500
  00058f0000000872657175697265640000000872657175697265640000000872
  65717569726564000000010000000c6d65726b6c655f70726f6f660000000764
  65726976656400000200000000086f7074696f6e616c00000009666f72626964
  64656e00000009666f7262696464656e
```

`TestTimelockPolicyGoldenVectors` is authoritative for every byte. The separate encoder
reproduced both author-TEAL vectors before computing these.

## YAML Contract

Schema v1 describes the existing non-bounded composed layout and rejects a
top-level `bounded` field. Schema v2 requires `bounded`. Every schema version
uses strict known-field and duplicate-key rejection at every nested level.
`bounded.rekey` is required and is `refused` or `spending_key`.
`bounded.runtime_args` and `bounded.derived_args` declare the only permitted
Layer 3 slots. Caller runtime values carry explicit maximum/exact length
contracts, and every runtime argument declares `required_on: [spend]`, because
a rekey never reaches Layer 3. The one signer-derived primitive is
`merkle_allowlist_proof`.

```yaml
schema_version: 2
derivation_version: 3
template_type: composed
template_mode: generated
base_key_type: aplane.falcon1024.v1
publisher: example
family: falcon1024-allowlist
version: 1
display_name: Falcon-1024 Allowlist

bounded:
  contract: bounded2
  spend_effects: [pay, axfer, asset_opt_in]
  max_fee: 10000
  rekey: spending_key
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

`rekey: refused` gives the program no rekey path. A cosigner requires
`rekey: refused`. A refused profile can neither close nor be rekeyed, so it must
keep a transfer for what it holds: `spend_effects` includes `pay`, and `axfer`
whenever it includes `asset_opt_in`. The profile check and durable metadata
validation both enforce this (`boundedmeta.ValidateRefusedExit`), for expert
templates and the general type alike, and durable validation also refuses a
timelock policy beside `rekey: spending_key`.

`fixed_allowlist` is composer-owned. It
handles every effect in `spend_effects`: `pay` constrains `Receiver`; `axfer`
and `asset_opt_in` constrain `AssetReceiver`. The sender is always a legal
self-recipient. The recipients parameter is canonicalized and bounded to 30
entries. The policy uses no runtime proof or signer-derived arg.

Neither framework policy compiles an asset or amount check. One program is
valid on every network, while an asset ID names an asset on one chain only and
a base-unit amount means nothing across assets. Per-network asset and amount
limits belong to signer policy.

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
`merkle_allowlist_custom`, which a template cannot declare directly. Neither the
allowlist nor the author rule applies to a rekey. An allowlist with no `teal` rejects
extra parameters and runtime arguments, because nothing would read them.

`timelock` requires `FirstValid >= unlock_round` and reads no recipient list.
`fixed_allowlist_timelock` and `merkle_allowlist_timelock` apply the same check, then
render exactly the recipient check of the matching allowlist, under the same list limits
and Merkle proof contract. These policies name the unlock round through
`unlock_round_parameter`, which must identify a required `uint64` parameter with
`min: 1`, and they reject a `recipients_parameter` or `unlock_round_parameter` they do not
use. A round compiles the same way on every network but means a different time on each,
and it does not bind the program to one network.

The timelock also applies to self-receivers, which the recipient check would otherwise
admit. Every timelock policy requires `rekey: refused`, because a spending-key rekey
would leave the lock before the unlock round.

Timelock policies reject author TEAL, parameters they do not read, and runtime arguments.
An author who needs a list and custom time conditions uses a plain allowlist and writes
those conditions in the TEAL. Author TEAL never runs on a rekey, so such a condition
holds a spending-key rekey back only if the template declares `rekey: refused`.

`none` renders no Layer 3: after the envelope and the spending signature (and the
cosigner check, when the profile has one) a spend goes straight to the accept block, so
the fee ceiling, spend effects, and zero close and clawback fields are the whole
spending rule. It reads no parameter and declares no derived or runtime argument, and it
rejects author TEAL, which would make the program `custom` under a second name. Only the
general type offers it, for its limits-only shapes: `composeddsa.ParseTemplateSpec`
refuses a template that declares it, so every YAML route (the library, keystore
registration, and the semantic fingerprint) does too. A `none` account has no recipient
list, so it is never contained.

### Merkle Allowlist Compatibility Contract

The bounded Merkle root and proof bytes are compatibility-bearing. Given the
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
Every slot stores an index, source, maximum size, and a required, optional, or
forbidden rule for each of the two paths, spend and spending-key rekey. Base
signature slots are required on both. Derived, runtime, and cosigner slots are
forbidden on the rekey path, because a rekey never reaches Layer 3 or the
cosigner check.

Interior unused Layer 3 slots are explicit empty byte strings. Only unused
trailing slots may be omitted. Callers may populate only declared runtime
slots; they cannot populate derived or cosigner slots. The signer generates only
declared derived slots. Ordinary `/sign` rejects caller-supplied cosigner or
signer-derived values.

The planner classifies before group sizing, finalizes fee pooling, then
revalidates the finalized transactions at the single classification boundary.
The executor consumes that plan, checks that loaded durable metadata still
equals planned metadata, and assembles the declared slots without maintaining
a second classifier. Hybrid effects, refused rekeys, final fee violations,
metadata races, and invalid caller slots fail before signature release.
Existing key signing is driven by durable key metadata, not an installed YAML
definition. The metadata contract includes the bounded contract, base layout,
profile, rekey setting, `layer3_policy`, runtime and derived argument
declarations, static argument layout, optional cosigner authorization, and the
selected-path LogicSig argument and opcode ceilings. Program bytes come
from the final stored bytecode.

Non-bounded LogicSig keys use `signing_metadata_version: 1`. Bounded keys use
`signing_metadata_version: 2` and require the canonical
`bounded_authorization` object. The closed `layer3_policy` value is `custom`,
`fixed_allowlist`, `merkle_allowlist`, `fixed_allowlist_custom`,
`merkle_allowlist_custom`, `timelock`, `fixed_allowlist_timelock`,
`merkle_allowlist_timelock`, or `none`; declared runtime and derived arguments and their complete
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
- malformed, hybrid, refused, or unknown effects to local rejection.

Ordinary `/sign` rejects a cosigner-gated bounded spend because it cannot finish
that flow alone. First-party clients do not support combining `cosigner1` and
`bounded-cosigner1` targets in one group because their assembly contracts differ;
this is a client orchestration limit, not a signer-side whole-group flow
invariant. Signer-side classification remains authoritative for each target it
signs or assembles. Unknown flow labels fail closed.
Every bounded spending-key rekey triggers the
stable unconditional `bounded_rekey_requires_review` rule before
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
  field(canonical_behavior_parameters)
)
```

A cosigner key is a behavior parameter, so it is covered there. The digest excludes
the spending key, filenames, reference names, and labels, and it binds the selected
shape rather than the whole grammar, so an unrelated new rule leaves it unchanged.

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
  1:e15126819ade64513db6f8708fa9b0340f56d438e44d619605377fd53b1e6550
base_primitive: falcon1024-v1
canonical_bounded_profile_length: 501
canonical_bounded_profile_sha512_256:
  c8d53bdae84a9a3d2c6efbe1eac33fb6ab0cb6fad28614b1353fcb00afc2249a
canonical_behavior_parameters_length: 1981
canonical_behavior_parameters_sha512_256:
  3e37447008e20eab3259c3c109224f012ebd3bee4061db71b97298205665fdc9
boundary_digest:
  774b41e54991edc7532ac1c0375d9415faf6767255b746ab95a0920b3fbe5209
```

## Versioning

After first production deployment, a change to field classification, normal
forms, fee ceiling semantics, canonical encoding, transcript,
argument placement, endpoint choreography, or flow routing mints a new bounded
contract and key type. Existing LogicSig bytecode cannot learn about a future
authority-bearing field added to an existing transaction type; release review
must assess network-version safety before retaining containment claims.
