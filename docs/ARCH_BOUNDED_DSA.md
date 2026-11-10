# Bounded Authorization Contracts

## Status

This document freezes the `bounded2` contract. The composer envelope, the path
declaration and its classifier, strict composed schema v2, durable signing
metadata, inventory projection, framework-owned Layer 3 policies, static
Layer-3 argument layout, the rekey-to list, and the cosigner's rekeys (cosigned
rekeys, and listed rekeys on a cosigned account) are implemented.

It also freezes `plain1`, the plain host's contract, which shares `bounded2`'s
durable record, overlays, argument layout and planner and differs only in what
the host allows: see [The plain1 contract](#the-plain1-contract). Everything
else in this document describes `bounded2` unless it names `plain1`.

Canonical encodings and golden vectors from development builds are not a
compatibility contract; keys derived from them must be recreated. The encodings
and vectors in this document are the `bounded2` compatibility baseline.

## Purpose and Authority

A bounded authorization contract is a stateless LogicSig program that
defines the complete transaction envelope accepted for an account. The base
spending key authorizes every path. An account's rekey setting is `refused`,
which gives it no rekey path, or `spending_key`, which lets the spending key
authorize a pure rekey: alone, or with the cosigner on a cosigned account (a
*cosigned rekey*). An account may also carry a
[rekey-to list](#rekey-to-list-compatibility-contract). Beside `refused` it is
offered as *only these addresses* (`only_these`): a pure rekey may then go to a
listed address, with the spending key and a list proof, and every other rekey is
refused. Beside `spending_key` on a cosigned account it is *these addresses, plus
others with the cosigner* (`plus_cosigned`): a listed target takes the spending
key and a list proof, and any other target the spending key and the cosigner. A
listed rekey never asks the cosigner.

| Rekey setting | Cosigner | Spend needs | Rekey needs |
|---|---|---|---|
| `refused` | no or yes | spending key, plus the cosigner if any | refused |
| `spending_key` | no | spending key | spending key, any target |
| `spending_key` | yes | spending key + cosigner | spending key + cosigner; the cosigner's `rekey_policy` picks targets |
| `only_these` | no | spending key | spending key; target on the list |
| `only_these` | yes | spending key + cosigner | spending key; target on the list; the cosigner is not asked |
| `plus_cosigned` | yes | spending key + cosigner | spending key alone to a listed target, or spending key + cosigner to any target the cosigner's policy allows |

The table is what the program requires. A cosigned rekey must also pass this
signer's own `rekeys` setting before the cosigner is asked: under the default
`reject_foreign_rekey`, a target this signer doesn't hold and the account doesn't
list is refused, so a cosigned rekey to an outside address needs `allow_rekeys`
on the account's own policy.

`plus_cosigned` without a cosigner is refused: the spending key could already
rekey anywhere, so the list would add nothing. Only `refused` and `only_these`
bound where authority can go independently of the online keys. A cosigned
`spending_key` account and a `plus_cosigned` one are exactly as strong as the
spending key and the cosigner together: whoever holds both, or controls the
cosigner node's policy, can rekey the account anywhere. The plain hosts
`aplane.falcon1024.v1` and `aplane.ed25519.v1` offer every row, with bounds
(`bounded2`) or without (`plain1`); expert templates may declare any row.

`bounded2` has three ordered regions:

1. **Authentication:** the base DSA signature is required on every path.
2. **Transaction envelope:** the composer checks the fee ceiling, then
   dispatches on `RekeyTo`. A rekey is accepted in pure rekey normal form when
   the account declares `rekey: spending_key` (with the cosigner's signature on a
   cosigned account), or when it has a rekey-to list and the proof shows the
   target is on it, and rejected otherwise. Every other transaction must have
   zero danger fields and an admitted spend type.
3. **Layer 3 policy:** framework policy, author TEAL, or a framework allowlist
   followed by author TEAL runs only for an admitted pure spend.

No host rule gates a rekey. The rekey path accepts or rejects before any
Layer 3 or author code runs, so no Layer 3 policy applies to a rekey. The
cosigner check is the only check outside the rekey path that a rekey can
reach, and only a cosigned rekey reaches it.

On a cosigned account the cosigner signs every spend and every rekey the
spending key declares (`spending_rekey`), and never a listed rekey. Its record's
`required_on` is `[spend]`, or `[spend, spending_rekey]` when the account
declares `rekey: spending_key`; template, profile, and durable-metadata
validation require exactly that list. Such an account signs through the
`cosigned1` flow, which carries spends, cosigned rekeys and listed rekeys. A
cosigned account that declares `rekey: refused` with no list can never be
rekeyed: a lost or compromised cosigner cannot be escaped, and the program
cannot be replaced. A plain host makes one with a cosigner and
`rekey_authority=refused`, and an expert template can declare one. Under `only_these`
or `plus_cosigned`, a listed key can still take the account after its cosigner
is lost.

For profile `P`:

```text
Envelope(P) = PureSpend(P) union PureRekey(P)
  where PureRekey(P) is empty when P declares rekey: refused with no list,
  holds only rekeys whose RekeyTo is on the list under only_these,
  and holds every pure rekey under spending_key, with or without a list

Accepted(P) =
  {tx in PureSpend(P) where SpendingPolicy(tx) and CosignerSigned(P, tx)}
  union {tx in PureRekey(P) where RekeyTo is listed or CosignerSigned(P, tx)}
  where CosignerSigned(P, tx) is true when P has no cosigner
```

The guaranteed containment property is `Accepted(P) subset-of Envelope(P)`.
A spending-key rekey widens the envelope to any authority, and a listed rekey
to the listed addresses; only Layer 3 and the cosigner are monotone narrowing.
The contract does not claim that an arbitrary custom Layer-3 policy is a
complete value-spending policy.

## Frozen Decisions

| Property | `bounded2` value |
|---|---|
| Contract identifier | `bounded2` |
| Composed YAML schema | `schema_version: 2` |
| TEAL version | 13 |
| Spend effects | non-empty closed subset of `pay`, `axfer`, `asset_opt_in` |
| Rekey setting | `refused` or `spending_key`; `refused` may carry a rekey-to list (`only_these`), and `spending_key` may on a cosigned account (`plus_cosigned`) |
| Rekey-to list | contract `rekey_list1`: a salted hiding tree of depth 4, 1 to 16 addresses |
| Rekey and Layer 3 | a rekey never reaches Layer 3; only a cosigned rekey reaches the cosigner check |
| Cosigner paths | `required_on: [spend]`, or `[spend, spending_rekey]` beside `rekey: spending_key`; never `listed_rekey` |
| Compiled `max_fee` | required; any value from 0 to 2^53 - 1. The plain hosts' shapes default to 10,000 microAlgos |
| Layer-3 arguments | declared static runtime (spend only) and signer-derived slots |
| Signer-derived primitives | fixed-depth Merkle allowlist proof (512 bytes, spend); rekey-to list proof (160 bytes, listed rekey) |
| Framework Layer-3 policies | `fixed_allowlist`, `merkle_allowlist`; `none` for the plain hosts' limits-only shapes only |
| Framework allowlist with author TEAL | `fixed_allowlist_custom`, `merkle_allowlist_custom` |
| Inline recipient maximum | 30 entries |
| Flow labels | `bounded1` without a cosigner; `cosigned1` with a cosigner |
| Online cosigner endpoints | `POST /plan`, `POST /sign/component`, `POST /sign/assemble` |
| Bundled composed templates | none; the plain hosts `aplane.falcon1024.v1` and `aplane.ed25519.v1` offer the allowlist and limits-only shapes |

`bounded2` is the only contract a bounded shape or template declares (a plain host
account without bounds declares `plain1`), and neither has protocol aliases. Flow labels version the client/server choreography, not the contract,
so a `bounded2` account without a cosigner still advertises `bounded1`. A cosigned
account advertises `cosigned1`, which replaced `bounded-cosigner1` when the flow
began to carry rekeys: a client that knows only the spend-only choreography then
refuses a cosigned key instead of asking the cosigner to sign a listed rekey.

Generation also refuses a workflow the spending base can't complete. The
cosigner flow needs a Falcon-1024 or Ed25519 spending key, on `bounded2` and
`plain1` alike, so a cosigner on another base is refused, as is any
bounded profile on a base the support policy doesn't list. The policy is keyed by
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
completes Falcon-1024 and Ed25519 on `bounded2` and `plain1`. A valid signature on any other base is refused where it
always was, before an assembly it couldn't finish. Admission must stay within
the signer's table, or it would create accounts the signer can't complete;
`TestBoundedGenerationAdmitsOnlySignableWorkflows` checks that. Verification itself
is in `internal/sigconstruction/verify`, which takes public inputs only, and signing
stays at its existing role-specific sites.

A witness key must differ from the spending key and from each of its components, so a
key reused inside a larger construction is caught. That compares known keys only, and
it can't show that custody or seeds are independent.

`max_fee` has no budget limit, only a wire limit:

- A template states its own `max_fee`, and a plain host request may state one
  (`max_fee`, absent means 10,000 microAlgos). Any value is valid, 0 included,
  up to 9,007,199,254,740,991 (2^53 - 1), the largest value every client reads exactly as a JSON number.
- The 10,000 microAlgo default supports the currently measured Falcon/Falcon
  fixed-list shape at a 1,000 microAlgo network minimum fee. It is not a promise
  of viability on networks with a higher minimum fee.
- A ceiling below what a path costs as a lone transaction is not refused. The
  account then can't send that transaction alone: other signer-controlled
  transactions in the group, its own or another account's, must take the rest
  of the charge (see [FEE_HANDLING.md](FEE_HANDLING.md)). On a plain host
  the generation review warns about it; see
  [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#the-bounds).
- Generation still refuses a program with a path that doesn't fit one
  transaction's resource limits.

Group size and network-fee viability are path-specific. The
planner resolves argument/opcode dummies and priced program bytes for the
active consensus profile, and never raises a bounded transaction's fee above
the compiled ceiling: planning fails when no other signer-controlled transaction
in the group can take the charge.

The composer baseline uses a real Falcon spending verifier and a controlled
trivially true Layer-3 predicate. Every Layer-3 policy adds its own
final-bytecode and selected-path resource cells before a key type that uses it
can be enabled. `TestBoundedFixtureCompiledBudgetMatrix` compiles fixture
templates with the pinned TEAL v13 toolchain, derives argument layouts from
durable bounded metadata, applies the conservative reviewed opcode ceiling,
and runs the production v42 resource solver.

The resulting fee includes transaction bases and priced program bytes. The
compiled `max_fee` applies to every path. A higher network
minimum fee is evaluated through the same unified fee calculation rather than
through a legacy `ceil(program + args)` projection.

Schema-v1 custom DSA policy is expert mode. Schema-v2 bounded templates may
also use custom Layer 3 TEAL, but the framework still owns the effect envelope,
fee ceiling, slot layout, and path routing.

## Compiled Budgets

No bounded template is bundled. The plain hosts
(see [ARCH_KEYTYPES.md](ARCH_KEYTYPES.md#the-bounds)) offer the allowlist
and limits-only shapes. Compiler-backed maximum-path measurements for three fixture templates
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

## Effect Model

The independent machine-readable inventory has two parts.
[`PROTOCOL_EFFECT_INVENTORY.json`](PROTOCOL_EFFECT_INVENTORY.json) is the
contract-neutral protocol surface: the SDK transaction types and fields and the
AVM transaction fields. [`BOUNDED_EFFECT_CLASSIFICATIONS.json`](BOUNDED_EFFECT_CLASSIFICATIONS.json)
is `bounded2`'s judgment of that surface: which types it admits, and which fields
are danger predicates, spend policy, rekey normal form and so on.
[`PLAIN_EFFECT_CLASSIFICATIONS.json`](PLAIN_EFFECT_CLASSIFICATIONS.json) is
`plain1`'s, against the same surface; a later contract adds its own. Both are maintained
independently of renderer/classifier code, must not be generated from the
implementation manifest, and are pinned to go-algorand-sdk v2.11.2 pseudo-version
`967fcacfacdf`, go-algorand reference `68e036affd9e`, and AVM v13.
The surface separately freezes the flattened SDK transaction-field surface, and
tests parse the pinned SDK source to detect newly introduced transaction types.

### Path declaration

An account's path declaration (`boundedmeta.PathDeclaration`) states what it
allows: its spend effects, fee ceiling, Layer 3 policy, rekey setting, whether it
has a rekey-to list, and cosigner. `Metadata.Declaration()` projects it from stored
metadata, and the signer classifies every bounded target against it through
`txeffects.ClassifyFor` (`classifyBoundedPath` in
`internal/signerapp/signing/bounded.go`). An invalid declaration is an error, not
a refusal.

`ClassifyFor` checks the fee ceiling first, then the transaction's shape. Every
decision names its rule:

| Rule | Path | When |
|---|---|---|
| `fee_ceiling` | refused | `Fee` exceeds the declared ceiling (`bounded2`; `plain1` declares none) |
| `open_spend` | spend | on `plain1`, any transaction without `RekeyTo`: every type, closes, asset closes and clawback included |
| `spend_allowed` | spend | a pure spend of a declared effect |
| `spend_not_declared` | refused | a pure spend of an effect the account does not declare |
| `rekey_allowed` | spending rekey | a pure rekey under `rekey: spending_key`, with or without a list |
| `rekey_listed` | listed rekey | a pure rekey under `rekey: refused` on an account with a rekey-to list |
| `rekey_refused` | refused | a pure rekey under `rekey: refused` with no list |
| `hybrid_rekey` | refused | a nonzero `RekeyTo` on anything but a pure rekey |
| `denied_effect` | refused | a close, asset close, or clawback |
| `denied_type` | refused | any other transaction type than `pay` and `axfer` |

The declaration says only that a list exists. Whether a target is on it is the
signer's to check, against the account's stored entries, when it plans the listed
path (see [Signature Arguments and Durable Metadata](#signature-arguments-and-durable-metadata)).
So under `plus_cosigned` the classifier sends every pure rekey to the spending
rekey, and the signer moves a listed target to the listed rekey; an unlisted
target stays on the cosigned path.

A refusal names the contract, for example "bounded2 account permanently disables
rekey". `TestClassifyForReachesAnExplicitRuleForEveryEffect` runs every
declaration the plain host's `bounded2` shapes produce against every transaction type of the
surface, with every combination of rekey, close, asset-close and clawback fields,
and requires an explicit allow or refuse rule for each, never a default branch. It
runs the `plain1` declarations too, and requires `open_spend` for exactly the
transactions without `RekeyTo`.

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
- belongs to an account that declares `rekey: spending_key`, or has a rekey-to
  list that holds `RekeyTo`.

No Layer 3 policy or author TEAL applies to a pure rekey, and the cosigner check
applies only to a cosigned rekey. A profile that declares `rekey: refused` with no
list has no rekey path, so every transaction with a nonzero `RekeyTo` rejects.

The program checks the spending signature, then the fee ceiling, then dispatches
on `RekeyTo`, before the other danger fields and spend-type routing. The rekey
branch has one body, chosen by the profile:

| Profile | Rekey body |
|---|---|
| `spending_key`, no cosigner | the pure rekey form, then accept |
| `spending_key`, cosigner | the pure rekey form, `callsub` the cosigner check, then accept |
| `only_these`, with or without a cosigner | the pure rekey form, the listed check, then accept |
| `plus_cosigned` | the pure rekey form; if the list proof slot is non-empty, the listed check, then accept; otherwise `callsub` the cosigner check, then accept |
| `refused`, no list | reject |

Rekey-plus-transfer, rekey-plus-close, and every other hybrid reject. A group may
contain separate normal-form transactions, but `bounded2` guarantees only each
protected transaction's envelope, not group-wide semantic safety.

The listed check reads the rekey-list proof argument and requires it to be exactly
160 bytes. It forms the leaf `SHA256(0x02 || salt || RekeyTo)` from the proof's
first 32 bytes, folds in the four 32-byte siblings that follow as sorted pairs
(`SHA256(0x01 || min || max)`), and asserts that the result equals the root
compiled into the program. That fold is the Merkle recipient tree's too, so a
program with a Merkle allowlist renders it once, as
`__aplane_bounded1_merkle_combine`, and the listed check calls it; any other
program carries it as `__aplane_bounded1_rekey_list_combine`. Nothing else runs
on that path; on a cosigned account the cosigner is not asked. The tree is defined under
[Rekey-To List Compatibility Contract](#rekey-to-list-compatibility-contract).

Under `plus_cosigned` the program branches on which arguments were sent, because
the AVM cannot count LogicSig arguments and a list can't be tested without its
proof. A non-empty proof slot commits the rekey to the listed branch: the proof
must verify, or the transaction is rejected, and it never falls through to the
cosigner. Each branch checks everything it needs, so choosing a branch gains an
attacker nothing. The layout's source order (base, derived, runtime, cosigner)
puts the proof slot before the cosigner slot, so on a cosigned rekey the empty
proof is an interior slot and is present even when trailing empty slots are
trimmed; on a listed rekey the trimmed cosigner slot is never read.

The cosigner check is rendered once, as the subroutine `__aplane_bounded1_cosigner`.
The spend path calls it before Layer 3, and a cosigned rekey calls it from the
rekey body, so the cosigner's public key compiles into the program once.

Spending-key authorization preserves pure shape but does not contain theft of
the spending key. A profile that declares `rekey: refused` keeps a stolen
spending key inside the spend envelope. With a rekey-to list, a stolen spending
key can also hand the account to a listed address, and gains control only if it
holds that address's key too. A cosigned `spending_key` or `plus_cosigned`
profile keeps a stolen spending key in the envelope only while the cosigner
holds: with both keys, or the cosigner node's policy, an attacker can rekey
anywhere.

## The plain1 contract

`plain1` is the plain host's contract, which the plain types `aplane.falcon1024.v1`
and `aplane.ed25519.v1` render when they are given overlay parameters and no bounds
(see [plain hosts](ARCH_KEYTYPES.md#plain-hosts)); with any bounds parameter they
render a `bounded2` shape instead. It is stored in the same
`bounded_authorization` record as `bounded2` (`signing_metadata_version: 2`), so the
cosigner and rekey-to list overlays, the static argument layout, the planner and
assembly work unchanged. It differs only in what the host allows:

| Property | `plain1` value |
|---|---|
| Contract identifier | `plain1` |
| Spending bases | Falcon-1024 and Ed25519; an Ed25519 spending key is classical |
| TEAL version | 13 |
| Spend | every transaction without `RekeyTo`, of any type, closes, asset closes and clawback included (`open_spend`) |
| Spend effects | none declared: `spend_effects` is empty |
| Fee ceiling | none: `max_fee` is absent |
| Layer 3 | `none`, with no author TEAL |
| Rekey setting | as `bounded2`: `refused` or `spending_key`, either with a rekey-to list (`only_these`, `plus_cosigned`) |
| Cosigner | optional; `plus_cosigned` needs one |
| Templates | cannot declare `plain1` |
| Flow labels | `bounded1` without a cosigner; `cosigned1` with a cosigner |

The program has no envelope. After the spending-key check it dispatches on
`RekeyTo`: a transaction that doesn't rekey goes straight to the spend path, which
calls the cosigner subroutine on a cosigned account and accepts. A rekey takes the
same rekey body as on `bounded2` (see [Pure rekey](#pure-rekey)), so it passes only
in pure rekey normal form, without a fee bound, on the paths the rekey setting
gives. A rekey still can't carry a close, an asset close or a clawback, and
`refused` without a list refuses every rekey but leaves closes, so the spending key
can still empty the account.

Without a cosigner the spending key alone decides every spend. With one, the
cosigner's policy is the only restriction on spends, so the cosigner sees every
transaction type and effect; `PLAIN_EFFECT_CLASSIFICATIONS.json` lists the fields it
judges under `cosigner_policy`.

Durable validation requires `max_fee` absent, an empty spend-effect list and
`layer3_policy: none` on `plain1`, and refuses an unknown contract;
`txeffects.ClassifyFor` does too rather than treating it as `bounded2`. The
classifier's plain manifest (`txeffects.PlainManifest`) and the independent
classification file have different owners, like `bounded2`'s;
`TestIndependentPlainInventoryMatchesManifest`,
`TestIndependentPlainInventoryDetectsEveryRemovedEntry` and
`TestIndependentPlainInventoryClassifiesEveryAVMField` compare them.

With no parameters a plain type renders the plain program instead: the spending-key
check alone, with no bounded record (`signing_metadata_version: 1`). It is the
composition base every bounded account names, the program of restored plain keys,
and an account of its own once the type is enabled.

## Canonical Encoding

All hashes in this section use SHA-512/256. `u32(x)` and `u64(x)` are unsigned
big-endian integers. `field(x)` is `u32(len(x)) || x`. Text is exact UTF-8
without a terminator or Unicode normalization. Lists carry a `u32` count and
then canonical elements. No JSON or YAML serialization is hashed. The canonical
profile enters a template's compatibility fingerprint, and both canonical
encodings enter the [host boundary digest](#host-boundary-digest).

### Canonical bounded profile

```text
canonical_bounded_profile =
  field("APLANE_BOUNDED_PROFILE_V2") ||
  field(contract) ||
  u32(count(spend_effects)) ||
    field(effect_0) || ... || field(effect_n) ||
  u64(max_fee) ||                      (bounded2 only)
  field(rekey) ||
  u32(rekey_list_present) ||
    if present: field("rekey_list1") || u32(4) ||
  u32(cosigner_present) ||
    if present: field("cosigner1") ||
      field("aplane.witness-falcon1024.v1") || u32(1423) ||
      u32(count(required_on)) || field(path_0) || ... ||
  field(layer3_policy) ||
  u32(base_signature_arg_count) || u32(base_arg_0_max) || ... ||
  u32(count(derived_args)) || canonical_derived_args ||
  u32(count(runtime_args)) || canonical_runtime_args ||
  u32(count(argument_layout)) || canonical_argument_slots
```

`contract` is `bounded2` or `plain1`. Spend effects use frozen order `pay`, `axfer`,
`asset_opt_in`. Duplicates are invalid. On `bounded2` empty spend sets are invalid;
on `plain1` the set is always empty. `asset_opt_in` is the zero-amount
self-receiver asset-transfer form and is authorized independently from `axfer`.
On `bounded2` `max_fee` must be present; any value from 0 to 2^53 - 1 is valid. A `plain1`
profile has no fee field: the contract name leads the encoding, so it omits
`u64(max_fee)` rather than writing a placeholder, and `bounded2`'s encoding and
golden vectors are unchanged. `rekey` is the text
`refused` or `spending_key`; an *only these* account encodes `refused` and sets the
list marker, and a *plus cosigned* account encodes `spending_key` and sets it. The
Layer 3 identity, argument declarations, maximum
sizes, frozen indexes, sources, and path masks are security-bearing and therefore
part of the canonical profile. Each derived argument record is `field(name) ||
field(kind) || field(parameter) || u32(max_size)`; each runtime argument record
is `field(name) || field(type) || u32(required) || u32(byte_length) ||
u32(max_size)`; each argument slot record is `u32(index) || field(name) ||
field(source) || u32(max_size) || field(spend_rule) || field(spending_rekey_rule) ||
field(listed_rekey_rule)`, where each rule is `required`, `optional`, or
`forbidden`. Every profile carries all three rules per slot, whether or not it can
take a listed rekey. `rekey_list_present` and `cosigner_present` are each exactly
zero or one. The list record carries the contract and depth, never the root: the
root depends on the spending key and is an instance value, so the review digest
binds the list's entries instead, which are behavior parameters. The optional
cosigner contract carries its ordered `required_on` list: `[spend]`, or
`[spend, spending_rekey]` beside `rekey: spending_key`.

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
`cosigner_public_key`, so the encoding commits to the resolved cosigner key. A
profile with a rekey-to list includes the framework-injected `rekey_to`, so the
encoding commits to the list's entries. The list root
(`bounded_rekey_to_root`) is not a creation parameter and is excluded.
Display metadata, file paths, runtime values, and policy provenance are
excluded.

Canonical scalar values are: address as raw 32 bytes; bytes as raw bytes;
unsigned integer as `u64`; boolean as one byte `0x00` or `0x01`; and string as
UTF-8. A missing or explicitly empty optional parameter has a zero-length
`canonical_value`; this is distinct from an explicit numeric zero, false, or
empty list. A list value is `u32(count) || field(element_0) || ...`; an `address[]`
list is in ascending order of the addresses' base32 text, which is not always their
byte order. Nested or
new parameter types require a new encoding rule before use by bounded.

### Bounded-cosigner assembly receipt

For `cosigned1`, the user signer also returns a Falcon-signed assembly
receipt on every path, listed rekeys included. With `field` as above, `metadata_json` equal to JSON encoding of the
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
accepts the base component or cosigner signature. The domain and message are
the ones `bounded-cosigner1` used.

### Golden vector 1: allowlist with author TEAL

These vectors freeze the two combined `layer3_policy` values. Both use a Falcon-1024
base, `spend_effects: [pay, axfer, asset_opt_in]`, `max_fee: 10000`, `rekey: spending_key`,
no rekey-to list, no cosigner, and a 1-to-64-byte `preimage` runtime argument required on
spend and forbidden on both rekey paths. The Merkle vector adds the `merkle_proof` derived
argument bound to `recipients`. The slot tables in this and the next vector show the
spend and spending-rekey rules; each slot's `listed_rekey` rule, which the hex also
encodes, is `required` for the base signature and `forbidden` for every other slot.

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

## YAML Contract

Schema v1 describes the existing non-bounded composed layout and rejects a
top-level `bounded` field. Schema v2 requires `bounded`. Every schema version
uses strict known-field and duplicate-key rejection at every nested level.
`bounded.rekey` is required and is `refused`, `spending_key`, `only_these`, or
`plus_cosigned`.
`bounded.runtime_args` and `bounded.derived_args` declare the only permitted
Layer 3 slots. Caller runtime values carry explicit maximum/exact length
contracts, and every runtime argument declares `required_on: [spend]`, because
a rekey never reaches Layer 3. The one signer-derived primitive a template
declares is `merkle_allowlist_proof`.

The argument layout stays inside the network's limits on one LogicSig: at most 255
slots, and no slot over 4,096 bytes. The whole layout counts: signatures, proofs,
runtime arguments and the cosigner's signature. Three checks enforce this, each at
its own time:

- At install: `composeddsa.ValidateTemplateAdmission` refuses a template whose
  layout is past either limit (`Metadata.ValidateNetworkLimits`), or that declares a
  runtime argument `max_size` over 4,096 bytes. The same admission check refuses a
  template that breaks its template-level contract, such as a parameter with the
  reserved `bounded_` prefix or a `rekey_to` that isn't the framework's.
- At key generation: `BuildBoundedAuthorizationMetadata` runs
  `Metadata.ValidateNetworkLimits` on the account's layout, and generation enforces
  the template-level contract as it always has.
- At signing: a supplied runtime argument over 4,096 bytes is refused, whatever
  maximum the account declares. An argument that isn't supplied isn't checked.

None of them runs at load. `ValidateNetworkLimits` is not part of durable
validation, and a store reload builds an installed template without the admission
check. A stored account past a limit still loads, because a path that doesn't carry
the oversized argument, such as a rekey, may still work. An installed template past
a limit still loads too: reload fails closed on a template defect, so a limit
applied there would let one template take the whole store down. A store never fails
to load over a limit added after its contents were written.

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

`rekey: refused` gives the program no rekey path. A refused profile without a
list can neither close nor be rekeyed, so only a transfer moves what it holds:
without `pay` in `spend_effects` its ALGO can never leave, and with
`asset_opt_in` but no `axfer` an asset it opts into can never leave. That is the
author's choice. Neither the profile check nor durable metadata validation
refuses it: durable validation checks structure only, so a check
for a combination's wisdom, if one returns, belongs at generation, where
accounts created without it keep loading. The plain hosts offer it too, as
they offer every combination the contract allows.

A cosigner's `required_on` must name every path the cosigner signs: `[spend]`
beside `rekey: refused` or `only_these`, and `[spend, spending_rekey]` beside
`rekey: spending_key` or `plus_cosigned`, where a cosigned rekey needs the
cosigner too. The framework then requires the cosigner signature slot on exactly
those paths and forbids it on `listed_rekey`.

`rekey: only_these` is `refused` plus a rekey-to list, and is stored that way:
`rekey: refused` and `rekey_list: {contract: rekey_list1, depth: 4}`. The framework
injects the required `rekey_to` parameter (`address[]`, 1 to 16 distinct nonzero
addresses); an author parameter of that name must match the injected contract. It
also appends the derived argument `rekey_list_proof` (kind `rekey_list_proof`, bound
to `rekey_to`, 160 bytes) after any Layer 3 derived argument, so a runtime argument
moves one slot later than it would without the list; a template cannot declare that
kind itself. A listed address is a way out, so a spend subset without a transfer
still leaves the account an exit. A cosigner beside
`only_these` is not asked for a listed rekey.

`rekey: plus_cosigned` is `spending_key` plus the same list, and is stored that
way: `rekey: spending_key` and `rekey_list`. It needs a cosigner, whose
`required_on` is `[spend, spending_rekey]`; without one the profile is refused,
since the spending key could already rekey anywhere. The framework injects the
same `rekey_to` parameter and `rekey_list_proof` argument. Durable validation
refuses a stored list beside `rekey: spending_key` without a cosigner.

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

The framework has no time policy.
An author who needs a time condition writes it in the TEAL, alone as a `custom` policy
or after a plain allowlist. Author TEAL never runs on a rekey, so such a condition
holds a spending-key rekey back only if the template declares `rekey: refused` or
`only_these`, and it never holds back a listed rekey.

`none` renders no Layer 3: after the envelope and the spending signature (and the
cosigner check, when the profile has one) a spend goes straight to the accept block, so
the fee ceiling, spend effects, and zero close and clawback fields are the whole
spending rule. It reads no parameter and declares no derived or runtime argument, and it
rejects author TEAL, which would make the program `custom` under a second name. Only the
plain hosts offer it, for their limits-only shapes: `composeddsa.ParseTemplateSpec`
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
runtime argument named `cosigner` or starting with `cosigner_` rejects. Under
`only_these` or `plus_cosigned`, `rekey_to` is the framework's too. User
parameters, variables, runtime args, and references using
the `bounded_` prefix reject, which covers the generator's `bounded_rekey_to_root`.
Author labels and executable references using
`__aplane_bounded1_` reject. Author TEAL cannot use `return` or escape the
composer-owned pure-spend boundary.

### Rekey-To List Compatibility Contract

A rekey-to list (contract `rekey_list1`) is a salted Merkle tree that hides its
entries. Unlike the recipient tree above, which makes no privacy claim, every leaf
carries a secret salt and every unused leaf is pseudorandom, so the root reveals
nothing about the list, not even its size, and a proof reveals only the entry it
proves. The root and proof bytes are compatibility-bearing: a change moves the
address of every account with a list. Given the entries and the account's spending
private key, implementations must use this exact algorithm, where `u32` is
big-endian and labels are ASCII:

1. Decode every address to its raw 32-byte public key. The list holds 1 through
   16 entries, none of them the zero address. Reject duplicates, then sort the
   entries in ascending byte order.
2. The seed is `HMAC-SHA256(key = spending private key, "APLANE_REKEY_LIST_SEED_V1")`,
   keyed by the private key's bytes as the account's key file stores them.
3. `derive(label, i) = HMAC-SHA256(key = seed, label || u32(i))`.
4. Create a depth-4 tree with exactly 16 leaves. Leaf `i` for an entry is
   `SHA256(0x02 || salt_i || entry_i)`, with `salt_i = derive("APLANE_REKEY_LIST_SALT_V1", i)`.
   Leaves `N` through `15` are `derive("APLANE_REKEY_LIST_PAD_V1", i)`. The leaf prefix
   `0x02` keeps these leaves apart from the recipient tree's `0x00`.
5. An internal node is `SHA256(0x01 || min(left, right) || max(left, right))`, the
   recipient tree's node function. Four levels give the root.
6. A proof for entry `i` is `salt_i` followed by the sibling at each level from the
   leaf upward: 32 + 4 x 32 = 160 bytes.
7. Verification builds the leaf from the proof's salt and the target, folds in each
   sibling with the node function, and compares the result with the root.

The seed is derived from the spending key, so nothing extra is stored, every backup
of the key carries it, and no secret travels in creation parameters. The list's
privacy rests on the spending key staying secret. Key generation computes the root
once the keypair exists and adds it as the reserved parameter
`bounded_rekey_to_root` before rendering; durable metadata records it as
`rekey_list.root`. It is not a creation parameter, so no request can set it. The
account's provenance is computed from the request's own parameters, without it.
`internal/rekeylist` owns the implementation.

### Golden vector 4: rekey-to list

The vector starts from the seed, so step 2 is not part of it. The seed is 32 bytes of
`0x5a`. The entries are the three addresses whose 32 raw bytes are all zero except
`[0] = 1, [31] = 1`, `[0] = 2, [31] = 1`, and `[0] = 3, [31] = 1`, given in the order
3, 1, 2. The proof is for the address with `[0] = 2`, and the vector gives the SHA-256
of its 160 bytes.

```text
rekey_list_root:
  4d250f6cd7cf1576f88827ac394e3e93f4e178230f90ea4c1beefa734eaba78c
rekey_list_proof_sha256:
  2b6dec15d0822cffecacf19aca00b29954546e3000e97da23f37ccab23e499f1
```

`TestGoldenVector` in `internal/rekeylist` is authoritative for both values, which an
independent encoder written from this algorithm reproduces.

## Signature Arguments and Durable Metadata

The static slot order is base signatures, signer-derived arguments (Layer 3's, then
the rekey-list proof), caller runtime Layer 3 arguments, then an optional cosigner
signature. Every slot stores an index, source, maximum size, and a required,
optional, or forbidden rule for each of the three paths: spend, spending-key rekey
(`spending_rekey`), and listed rekey (`listed_rekey`). Every bounded account carries
all three, whether or not it can take a given rekey. Base signature slots are
required on all three. Recipient-proof and runtime slots are forbidden on both
rekey paths, because a rekey never reaches Layer 3. The cosigner slot is required
on exactly the paths its record's `required_on` names (`spend`, and
`spending_rekey` beside `rekey: spending_key`) and forbidden on the rest, always
including `listed_rekey`. The rekey-list proof slot is required on `listed_rekey`
and forbidden on the other two, so it is empty on a cosigned rekey.

Interior unused Layer 3 slots are explicit empty byte strings. Only unused
trailing slots may be omitted. Callers may populate only declared runtime
slots; they cannot populate derived or cosigner slots. The signer generates only
declared derived slots. Ordinary `/sign` rejects caller-supplied cosigner or
signer-derived values.

The planner classifies before group sizing, finalizes fee pooling, then
revalidates the finalized transactions at the single classification boundary.
For a pure rekey under `only_these` it takes `listed_rekey`, sized from that
path's resource profile, and refuses a target that is not on the stored list with
`bounded_rekey_target_not_listed` (HTTP 400), before anything is signed, instead
of building a transaction the program would reject. Under `plus_cosigned` it moves
a listed target from `spending_rekey` to `listed_rekey`, and an unlisted target
stays on the cosigned path. Cosigned assembly decides the path again through the
same function (`boundedAccountPath`), so a component and its assembly cannot
disagree about whether the cosigner signs. The executor consumes
that plan, checks that loaded durable metadata still equals planned metadata, and
assembles the declared slots without maintaining a second classifier. On the listed
path it rebuilds the list from the spending private key it already holds and the
stored `rekey_to` entries, requires the rebuilt root to equal the stored
`rekey_list.root`, and places the target's proof in the list-proof slot; recipient
proofs stay empty. Only the account's own signer can build that proof, because the
salts come from the spending key. Hybrid effects, refused rekeys, unlisted targets,
final fee violations, metadata races, and invalid caller slots fail before
signature release.
Existing key signing is driven by durable key metadata, not an installed YAML
definition. The metadata contract includes the bounded contract, base layout,
profile, rekey setting, optional rekey-to list record (`rekey_list`: `contract`,
`depth`, `root`), `layer3_policy`, runtime and derived argument
declarations, static argument layout, optional cosigner authorization, and the
selected-path LogicSig argument and opcode ceilings. The list's entries are the
stored `rekey_to` creation parameter. Program bytes come
from the final stored bytecode.

Non-bounded LogicSig keys use `signing_metadata_version: 1`. Bounded keys use
`signing_metadata_version: 2` and require the canonical
`bounded_authorization` object. The closed `layer3_policy` value is `custom`,
`fixed_allowlist`, `merkle_allowlist`, `fixed_allowlist_custom`,
`merkle_allowlist_custom`, or `none`; declared runtime and derived arguments and their complete
slot masks are persisted. Top-level `signing_args` are ignored for bounded
keys. Scan, load, backup, and restore consume the stored object without
consulting the installed template.

## Routing and Approval

`/keys` and `/keytypes` advertise `signing_flow: bounded1` for profiles without
a cosigner and `signing_flow: cosigned1` for profiles whose durable
metadata contains `cosigner.contract: cosigner1`. Both expose the same typed
`bounded_authorization` object. `/keytypes` exposes definition-level
profile and base-layout capabilities. `/keys` additionally exposes the
structured selected-path LogicSig resource profile, with `spend`,
`spending_rekey`, and `listed_rekey` cells. An account with a rekey-to list
carries `bounded_authorization.rekey_list` with its `contract` and `depth`, and in
`/keys` its `root`; the entries are never projected, so a client cannot tell
whether a target is listed before it asks. Asking does tell it: the signer
refuses an unlisted target under *only these* by name, and under *plus
cosigned* a listed and an unlisted target plan different paths, both before any
approval. The list hides its entries from the chain and from inventory, not from
an enrolled client of the account's own signer, which can already ask for the
rekey. Clients route:

- a pure spend or rekey of an account without a cosigner to ordinary `/sign`,
  rekeys with forced review; the signer refuses an unlisted target with
  `bounded_rekey_target_not_listed`;
- every pure spend and pure rekey of a cosigned account through the first-party
  client's user-first `/plan`, kind-tagged signer and cosigner `/sign/component`,
  then signer `/sign/assemble` choreography (`cosigned1`); and
- malformed, hybrid, refused, or unknown effects to local rejection.

In `cosigned1`, each bounded-base component in the `/sign/component` response
carries `path`: `spend`, `spending_rekey` or `listed_rekey`, the path the signer
classified. The client asks the cosigner for every target except a
`listed_rekey` one, sends no cosigner request when no target needs one, and
budgets a cosigned position in a mixed group on its component's path. The mark
routes the request only. `/sign/assemble` classifies the canonical transaction
against stored metadata again, through the planner's function, then requires a
cosigner signature on `spend` and `spending_rekey` and refuses one on
`listed_rekey`, so `cosigner_signature` is optional on a `bounded-cosigner`
assembly target. A wrong mark can stall a request, never weaken it. The cosigner
node decides a cosigned rekey as it decides any rekey, by its `reject_rekey`,
`rekey_policy` edge and pure-shape check; a listed rekey never reaches it.

Ordinary `/sign` rejects every target of a cosigned account
(`bounded_cosigner_required`), a listed rekey included, because only the cosigned
flow carries that account. Signer-side classification remains authoritative for
each target it signs or assembles. Unknown flow labels fail closed, the retired
`cosigner1` flow label among them.
Every bounded rekey, spending-key, cosigned or listed, on either flow, triggers the
stable unconditional `bounded_rekey_requires_review` rule before
policy self-no-op autoapproval, regardless of warning configuration. User
Auto-Approve satisfies this review requirement without a prompt. A client intent to simulate
does not alter this requirement; apsigner sees an ordinary executable signing
request. How signer policy and the approval text treat a listed target is in
[ARCH_POLICY.md](ARCH_POLICY.md#bounded-authorization-interaction).

## Host Boundary Digest

Every plain host account with a contract, `plain1` or `bounded2`, has a comparison
digest. Using the field encoding above:

```text
SHA512/256(
  field("APLANE_HOST_BOUNDARY_V1") ||
  field("aplane.boundary.v1") ||
  field(selected_fingerprint) ||
  field(base_primitive) ||
  field(canonical_bounded_profile) ||
  field(canonical_behavior_parameters)
)
```

`selected_fingerprint` is the selected arrangement's or shape's fingerprint. A cosigner
key is a behavior parameter, so it is covered there, and so are a rekey-to list's
entries. The digest excludes the list's root, which depends on the spending key, the
spending key itself, filenames, reference names, and labels, and it binds the selected
arrangement or shape rather than the whole grammar, so an unrelated new rule leaves it
unchanged.

It is a comparison value. It does not assert that two accounts have the same address,
and it replaces no signing transcript. It is defined only for the plain hosts: custom
Layer 3 code is not bound by it. `TestBoundsFingerprintGoldens` and
`TestPlainHostGrammarGoldens` in `lsig/plainhost` pin the shape fingerprints, the
digest below, and the grammar fingerprint of each base.

### Golden vector 3: host boundary digest

This vector uses the fullest `bounded2` shape of `aplane.falcon1024.v1`: all three
transfer kinds, `merkle_allowlist`, a cosigner, and `plus_cosigned`. The two recipients
are the addresses whose 32 raw bytes are all zero except `[1] = 1, [31] = 1` and
`[1] = 2, [31] = 1`. The rekey-to list holds the two addresses whose 32 raw bytes are
all zero except `[0] = 0x08, [31] = 2` and `[0] = 0xd0, [31] = 2`; their address texts
start with `B` and `2`, so the behavior encoding lists the `0xd0` address first. The
cosigner key is 1,793 bytes of `0x44`. The profile encodes `rekey: spending_key` with
the list marker, the cosigner's `required_on` is `[spend, spending_rekey]`, and the
argument layout is the base signature, the recipient proof, the rekey-list proof and
the cosigner signature, which is required on `spend` and `spending_rekey`.

The digest below is reproduced from the profile and behavior bytes by the rules in this
document. The shape fingerprint is an input to that check: it comes from the
provider's own configuration hash, which this document does not define byte for byte.
`TestBoundsFingerprintGoldens` pins the shape fingerprint and the digest.

```text
selected_fingerprint:
  1:b4efb8a343077eb838ca3646354fc98e02a6bc2cc6e455048afc484ed0b9b263
base_primitive: falcon1024-v1
canonical_bounded_profile_length: 675
canonical_bounded_profile_sha512_256:
  da645191069b2b95194e56f1a36d64565858cab9b61b8316f5d0de95c78ccff6
canonical_behavior_parameters_length: 2086
canonical_behavior_parameters_sha512_256:
  992e720dfd177c63c9e46df2c45fe06f87dd1bfd55173337950d08de4ebc6d74
boundary_digest:
  fc7c7b20998e33024636c11e56653a24320c16028330fab2b2c6e7dc8e95ff38
```

## Versioning

After first production deployment, a change to field classification, normal
forms, fee ceiling semantics, canonical encoding, transcript,
argument placement, endpoint choreography, or flow routing mints a new bounded
contract and key type. Existing LogicSig bytecode cannot learn about a future
authority-bearing field added to an existing transaction type; release review
must assess network-version safety before retaining containment claims.
