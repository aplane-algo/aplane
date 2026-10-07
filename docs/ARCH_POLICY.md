# Policy Architecture

This document describes the policy system. Compatibility-bearing details live
in [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Status

This document covers two domains:

- the **client-signing** policy: tier-based verdicts over
  signer-controlled transactions with an operator default fallback,
- the **cosigner** policy implemented for cosigner component signing:
  policy-as-authorization for `/sign/component`, no operator default, no
  review verdict.

The client-signing domain applies to ordinary `/sign` requests and to
user-role `/sign/component` requests: guarded user-component signing runs the
same hard rejection, always-review, and operator approval sequence, with the
guarded account as the per-target policy key and non-target group positions
evaluated as foreign context. Cosigner-role `/sign/component` requests use the
cosigner domain (see [ARCH_COSIGNER.md](ARCH_COSIGNER.md)).

Both domains are written as v1 JSON policy documents, specified in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md), and share one decoder, one
compiler, one fixture corpus, and one verdict-model description. Fields that
apply to only one domain are tagged inline.

## Scope

A policy document governs a set of accounts. On a signer node the set is the
accounts the node holds, and one document (`policy.json`) covers them all,
including the user side of guarded keys; membership changes with key
generation, import, and deletion, and per-account rules are routes whose
`sources` name the account. On a cosigner node the set is every account whose
guarded key was composed with one cosigner key, and that key's document
(`policies/<WitnessKeyID>.json`) covers them. The cosigner set is virtual:
the node does not hold those accounts, cannot enumerate them, and learns of
one when a `/sign/component` request names it, so the document's `sources`
are the cosigner operator's only control over membership. A guarded account
is in both sets, and both documents must allow a movement.

Signer policy decides what `apsigner` may produce a signature for after
request planning has identified the signable units. For client signing, the
unit is a signer-controlled transaction; for cosigner, the unit is a
target transaction in `/sign/component`. Policy is separate from:

- authentication and authorization, which decide who may ask for signing,
- key ownership and unlock state, which decide whether signing keys are usable,
- the operator default, which decides whether unmatched client-signing requests
  need manual review. Cosigner has no operator default.

## Storage

Policy is product-scoped and stored in the selected generation under the
retained product namespace. The root `node.yaml` role decides which documents
exist:

```text
# signer node
identities/default/generations/<selected-generation>/policy.json
identities/default/generations/<selected-generation>/policy.json.hmac

# cosigner node, one pair per cosigner key
identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json
identities/default/generations/<selected-generation>/policies/<WitnessKeyID>.json.hmac
```

A signer generation holds exactly one `policy.json` and no `policies/`
documents; a new signer store starts with `policy.InitialSignerPolicy`, which
enables routing with one `self-transfer` route (any account to itself, any
asset, any network) and `on_no_route: reject`, so a fresh signer allows
self-sends and opt-ins and rejects every other transfer until a route is
added. A cosigner generation holds no `policy.json`; a new cosigner store has
no documents, so every cosigner key rejects every request until its document
is applied, and the starting document offered for a key holds the same
`self-transfer` route. Deleting a cosigner key archives its
document pair under `deleted/policies/` in the same generation.

Each `.hmac` sidecar covers the exact document bytes and uses a key derived
from the product store's current term key. Sidecar metadata such as signing time
and policy SHA-256 is diagnostic; the HMAC is the security check. A missing or
mismatched sidecar, or a document that fails decoding or semantic validation,
fails the whole policy load: the node refuses to unlock or reload rather than
loading defaults or skipping the document. On reload failure, the previous
in-memory policy remains active.

The sidecar authenticates only the document bytes. Diagnostic metadata fields
in the sidecar can be edited without invalidating the policy HMAC; they are
not security inputs to the verification decision.

Product runtime settings such as `user_auto_approve`,
`lock_on_disconnect`, and `passphrase_timeout` live separately in:

```text
identities/default/config.yaml
```

`user_auto_approve` is shown in `apadmin` as `User Auto-Approve`. It is not a
policy rule; it is the user/operator default used only when policy has no
matching verdict.

On signer nodes, `policy.json` is the client-signing policy
(`"format": "aplane.signer-policy.v1"`). It is sparse. Absent fields resolve
through product defaults: `reject_foreign_rekey` defaults to `true`, while
`reject_close_remainder`, `reject_asset_close`, `reject_clawback`,
`always_review_warnings`, and `auto_approve_self_noop_transfer` default to
`false`. An absent `max_fee_microalgos` means no fee ceiling, and absent
`limits` sets no document-level thresholds. `transfer_policy` may be absent
entirely; if it is present, it must satisfy the routing schema below.

On cosigner nodes, each `policies/<WitnessKeyID>.json` is the cosigner
component policy for that one key (`"format": "aplane.cosigner-policy.v1"`).
Its signed `key` field must equal the Witness Key ID in its file name. Each
document is self-contained: sets, limits, and routes are not shared between
keys, and there is no node-wide cosigner policy or per-key overlay.
Review-producing fields do not exist in this document type, and route misses
always reject.

The policy loader validates schema and domain constraints independent of the
product runtime's current key inventory. Validation runs at unlock/reload and at
every `check` and `apply`; failures fail closed with the previous in-memory
policy snapshot left active, exactly like sidecar verification failure.

## Verdict Model

Policy verdicts override the operator default. Among policy verdicts, the most
restrictive matching verdict wins.

| Tier | Decision owner | Effect |
|------|----------------|--------|
| Always Deny | Policy | Reject the request before approval |
| Always Review | Policy | Require operator approval |
| Always Approve | Policy | Sign without operator approval |
| Operator Default | Admin setting | Review or approve according to `user_auto_approve` |

Precedence:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

Operational flow:

1. Evaluate policy rules.
2. If any Always Deny rule matches, reject.
3. Else if any Always Review rule matches, require approval.
4. Else if any Always Approve rule matches, sign.
5. Else use Operator Default:
   - `user_auto_approve:false` requires approval.
   - `user_auto_approve:true` signs without approval.

For client signing, Always Review blocks both `user_auto_approve:true` and any
matching Always Approve rule. Cosigner rejects review-producing policy
instead of treating it as a promptable phase.

### Verdict Mapping By Role

The four-tier model is the canonical shape for **client-signing** requests.
**Cosigner** is policy-as-authorization with no human in the loop, so its
normal verdict surface has two outcomes (reject or sign). The shared phase
order is still used, but review is not a valid cosigner outcome:

| Phase | Client signing | Cosigner |
|-------|----------------|-------------|
| Always Deny | Reject | Reject |
| Always Review | Require operator approval | Invalid outcome; fail closed as config error |
| Always Approve | Sign without approval | Sign |
| Operator Default | Per `user_auto_approve` | Not applicable; unmatched cosigner requests reject |

The deterministic cosigner surface is enforced by the cosigner document type:
it has no `always_review_warnings`, no `review_above` thresholds, and no
`on_no_route`, `close_on_no_route`, or `clawback_on_no_route` fields, and
unknown fields are rejected. If implementation ever
encounters a review verdict while evaluating a cosigner component request,
the request fails closed as a policy configuration error rather than waiting
for a prompt.

`user_auto_approve` is client-signing-only. It lives in
`identities/default/config.yaml` and has no cosigner analog.

## Role Domains

Policy has two document types, selected by the `format` field and required to
match the node role.

The signer `policy.json` is the client-signing document:

```json
{
  "format": "aplane.signer-policy.v1",
  "reject_foreign_rekey": true,
  "auto_approve_self_noop_transfer": true,
  "always_review_warnings": true,
  "max_fee_microalgos": "1000",
  "limits": {
    "mainnet": { "algo": { "review_above": "100000000" } }
  },
  "transfer_policy": {
    "enabled": true,
    "on_no_route": "reject",
    "routes": []
  }
}
```

A cosigner `policies/<WitnessKeyID>.json` is one key's component policy:

```json
{
  "format": "aplane.cosigner-policy.v1",
  "key": "<WitnessKeyID>",
  "transfer_policy": { "routes": [] },
  "rekey_policy": {
    "allowed": [
      { "sender": "<address-or-@set>", "targets": ["<address-or-@set>"] }
    ]
  }
}
```

The signer document accepts the client-signing field set and
`key_overrides`; it has no `reject_rekey` or `rekey_policy`, which belong to the
cosigner document. The cosigner document accepts the cosigner field set; it
has no `key_overrides`. Field tables for both are in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md). Unknown fields fail
validation at every level, and a document whose `format` does not match the
node role is rejected.

Client-signing semantics:

- Some fields are valid only in the signer document because their semantics
  reference "this signer owns the account" (`reject_foreign_rekey`,
  `auto_approve_self_noop_transfer`) or their verdict only makes sense with an
  operator above the signer (`always_review_warnings`, `review_above`
  thresholds, `on_no_route: review`).

Cosigner semantics:

- `reject_rekey` and `rekey_policy` are valid only in the cosigner document.
- `reject_foreign_rekey`, `always_review_warnings`,
  `auto_approve_self_noop_transfer`, and `review_above` do not exist there.
- `transfer_policy` is required and is the positive authorization surface.
  Route misses, unallowed close-outs, and unallowed clawbacks always reject.
- `rekey_policy` is the positive authorization surface for non-zero `RekeyTo`
  transactions when `reject_rekey` is absent or false. It authorizes only pure
  0 ALGO self-payment rekeys whose sender and target match an allowed edge.
  Bounded-cosigner v1 does not invoke cosigner policy for rekeys; its cosigner slot
  is spend-only and forbidden on administrative paths.

Both document types are validated by schema and semantic rules, not by the
product runtime's current key inventory. A cosigner node can hold a document
for a Witness Key ID before that cosigner key is installed; `check` reports it.

A signer document's `transfer_policy` that contains review-producing behavior
(`on_no_route: review`, `review_above`, and similar fields) is valid for client
signing, but it is not a cosigner allow-list. Cosigner authorization comes only
from the requested key's own cosigner document.

## Bounded Authorization Interaction

Bounded1's on-chain envelope is independent of signer policy. Signer policy may
reject a transaction admitted by the LogicSig but can never widen the compiled
envelope or raise its `max_fee`.

Every transaction classified onto a bounded1 admin-operation path triggers the
stable client-signing Always Review rule
`bounded_admin_operation_requires_review`. The rule runs after hard rejection
and before every Always Approve or Operator Default path. It therefore blocks
`user_auto_approve:true`, `auto_approve_self_noop_transfer`, and warning
configuration for both spending-key and Falcon contract-admin rekeys.
A client intent to simulate is not an exception because apsigner releases the
same executable signatures and receives no simulation designation.

The approval description names the operation, sender, rekey target,
transaction fee and compiled ceiling, authorization mode, and Contract Admin
Key ID when applicable. The external contract-admin confirmation is an
additional authorization after signer approval; it cannot override policy
rejection, cancellation, or operator denial. See
[ARCH_BOUNDED_DSA.md](ARCH_BOUNDED_DSA.md).

## Runtime Snapshot Semantics

The product runtime publishes policy updates atomically. Readers see either
the previous policy snapshot or the replacement snapshot; they must not observe
a partially applied policy.

Each signing request captures the effective policy snapshot when its signing
service is constructed. That snapshot governs the request through policy
evaluation, approval waiting, and final signature execution. A later successful
policy reload or `apadmin` online policy apply applies only to signing requests
that start after the new snapshot is published. In-flight requests are not
re-evaluated or canceled merely because the policy changed while they were
waiting for approval. This is a deliberate contract, not a gap: deny and
review verdicts are decided with the policy at the time the request is
presented, not at the time the operator approves it. A request whose prompt
is in front of the operator, or queued behind another prompt for up to
`approval_wait`, signs under the policy it was evaluated against when
approved. An operator who needs a tighter policy to cover requests already
waiting rejects those prompts or locks the signer, which fails every pending
approval (see [USER_POLICY.md](USER_POLICY.md), "Editing Policy").

## Always Deny

Always Deny rules are hard safety guards. They cannot be approved by an
operator prompt and are evaluated before all other policy or approval phases.

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `reject_foreign_rekey` | signer | Reject transactions whose non-zero `RekeyTo` target is not held by the product signer runtime |
| `reject_rekey` | cosigner | Coarse deny-all switch for transactions with non-zero `RekeyTo` |
| `rekey_policy` | cosigner | Allow-list for pure 0 ALGO self-payment rekeys by sender and rekey target |
| `reject_close_remainder` | common | Reject payment transactions with non-zero `CloseRemainderTo` |
| `reject_asset_close` | common | Reject ASA transfers with non-zero `AssetCloseTo` |
| `reject_clawback` | common | Reject ASA clawback transactions using `AssetSender` |
| `max_fee_microalgos` | common | Reject transactions whose raw microAlgo fee exceeds the configured ceiling |
| `limits` `reject_above` | common | Per-network, per-asset raw ceilings for ALGO payments (microAlgos) and ASA transfers (base units) |
| `transfer_policy` | common | For client signing, produces deny verdicts for blocked destinations, route misses, close/clawback misses, and `reject_above`; for cosigner, routing is the positive authorization surface |

`reject_foreign_rekey` evaluates the rekey target against the set of addresses
held by the current signer, which is meaningful only when the signer owns the
sender. `reject_rekey` is the cosigner coarse-deny analog and ignores key
ownership: when true, any non-zero `RekeyTo` rejects. When it is absent or
false, the cosigner still fails closed unless `rekey_policy.allowed` authorizes
the exact sender-to-target edge and the target transaction is a pure 0 ALGO
self-payment with no close remainder.
This cosigner-domain rekey surface applies to dedicated `cosigner1` guarded
accounts. Corridor v1 uses a distinct external contract-admin witness for its
bounded pure-rekey path and never asks cosigner policy to authorize that target.

Network-scoped rules derive transaction network identity from `GenesisHash`,
not `GenesisID`. Unknown genesis hashes fail closed when a network-scoped rule
must be evaluated. For cosigner, an unknown genesis hash always fails
closed regardless of which rules are configured, because cosigner is
authorization rather than a guardrail and cannot fall through to operator
default.

Document-level `limits.<network>.<asset>.reject_above` is the deny side of
transfer guards. If a matching `review_above` is also configured, `reject_above`
must be greater than or equal to it. This invariant is checked at acceptance: a
document that violates it fails `check`, `apply`, and load. For signer key
overrides, the invariant is checked on each key's merged effective `limits`
(see [Key Overrides](#key-overrides)).

`transfer_policy` is a route table for direct `pay` and `axfer`
movements. When enabled, it can reject blocked destinations, route misses,
close-out misses according to `close_on_no_route`, clawback misses according to
`clawback_on_no_route`, matched close-out movements without `allow_close:true`,
matched clawback movements without `allow_clawback:true`, and matching
movements above a route's `reject_above` threshold. For client signing, routes
never auto-approve a request; a route match only lets the movement continue
through the remaining policy phases. For cosigner, routing is the positive
authorization surface. See [Transfer Routing](#transfer-routing).

## Always Review

Always Review rules force a human approval prompt even when the operator default
is configured to skip review. The whole tier is client-signing-only: the
cosigner domain has no operator above the signer, so the cosigner document type
has no review-producing fields. If a
review verdict is reachable while evaluating a cosigner
component request, the request fails closed as a policy configuration error.
See [Verdict Mapping By Role](#verdict-mapping-by-role).

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `always_review_warnings` | signer | Require operator review when warning analysis finds risk markers |
| `limits` `review_above` | signer | Per-network, per-asset raw thresholds that require review for ALGO payments and ASA transfers |
| `transfer_policy.on_no_route: review` | signer | Forces ordinary route misses to review for client signing |
| `transfer_policy.close_on_no_route: review` | signer | Forces close-out route misses to review for client signing |
| `transfer_policy.clawback_on_no_route: review` | signer | Forces clawback route misses to review for client signing |
| `transfer_policy` `review_above` | signer | Route-level review threshold |

Document-level `review_above` thresholds are the review side of transfer
guards. They are evaluated after Always Deny. For example, an ASA transfer above
`limits.testnet["asa:10458941"].review_above` requires approval unless it has
already been rejected by the matching `reject_above` threshold.

For client signing, unknown genesis hashes trigger a distinct fail-closed rule
that forces review when a configured transfer-guard review threshold cannot be
mapped to a network token. This rule is independent of the configured threshold
values. Cosigner rejects unknown genesis hashes when network-scoped policy
must be evaluated because it has no review fallback.

Transfer routing review outcomes are evaluated after hard-reject policy passes
and before auto-approval. Routing review applies only to signer-controlled
direct transfer movements; passthrough and foreign request slots are not
governed by this signer's route table. See
[Transfer Routing](#transfer-routing).

Warning analysis currently covers:

- rekey fields,
- ALGO close-out fields,
- ASA close-out fields,
- ASA clawback fields,
- unusually high fees above 1 ALGO.

Warnings are still displayed when `always_review_warnings:false`; they simply
do not force review in that mode.

## Always Approve

Always Approve rules are explicit low-risk rules stored in policy. They are
evaluated only after Always Deny and Always Review have not matched.

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `auto_approve_self_noop_transfer` | signer | Auto-approve a tightly constrained self no-op transfer |

`auto_approve_self_noop_transfer` is client-signing-only because its "self"
predicate references the signer-owned account. It has no defined meaning for
cosigner: a cosigner is not the owner of the sender it is authorizing.
The field does not exist in the cosigner document type. If an invalid
effective cosigner policy is injected in tests, the
rule simply does not match a cosigner request because no signer-owned address
is in scope to compare against.

`auto_approve_self_noop_transfer` applies only to a single signer-controlled
request with no caller-provided group, no passthrough or foreign slots, no
rekey, no close remainder, no asset close, no clawback sender, no note, no
lease, and normalized fee at most 1000 microAlgos.

The real transaction must be one of:

- a 0 ALGO payment to self,
- a 0-unit ASA transfer to self.

Signer-generated LogicSig-budget dummy transactions are allowed only when they
use APlane's embedded dummy LogicSig address, match the real transaction's
network and validity window, carry no fee, and the real transaction's fee
increase exactly covers those dummies.

The exact self no-op shape, including signer-generated budget dummies, is
exempt from transfer routing regardless of whether
`auto_approve_self_noop_transfer` is enabled. The auto-approval rule still
controls only whether that shape skips manual approval.

## Operator Default

Operator Default is not policy. It is the fallback behavior for client-signing
requests that did not match Always Deny, Always Review, or Always Approve. It
does not apply to cosigner: an unmatched cosigner component request is
Always Deny per [Verdict Mapping By Role](#verdict-mapping-by-role).

The setting is:

```yaml
user_auto_approve: false
```

Location:

```text
identities/default/config.yaml
```

Behavior:

- `user_auto_approve:false`: unmatched client-signing requests require operator review.
- `user_auto_approve:true`: unmatched client-signing requests sign without operator review.
- cosigner component requests: ignored; the verdict is reject.

## Transfer Routing

`transfer_policy` is the implemented v1 route table for direct transfer
movements. The same routing engine applies to both client-signing and
cosigner evaluation. Client-signing routes live in the signer `policy.json`;
cosigner component routes live in each cosigner key's own document. Transfer
routing is not projected through admin IPC as separate settings; it travels only
inside whole policy documents.

For client signing, a route match means "allowed to continue through the
normal policy phases"; it does not approve signing and never produces an
Always Approve verdict.

For cosigner, routing is the positive authorization surface. A cosigner
component request is eligible to sign only when all evaluated target
transactions are supported transfer shapes, every extracted target movement is
covered by a matching route, and no route or transaction guard produces a deny
verdict. The key's document cannot express review-producing behavior, so a
cosigner route outcome is always sign or reject. In other words: for client signing, routing is a
guardrail; for cosigner, routing is an allow-list.

Always Deny and deterministic transaction guards run before cosigner
allow-list success. A route match cannot rescue a target rejected by rekey,
close-out, clawback, fee, amount, blocked-destination, or unsupported-shape
rules.

In the signer document, `transfer_policy` holds the client-signing routes and
the route-miss choices `on_no_route`, `close_on_no_route`, and
`clawback_on_no_route`. In a cosigner document, `transfer_policy` is that
key's allow-list and holds only `blocked_destinations` and `routes`: route-miss
behavior is not configurable and is always `reject`, and route `limits` carry
only `reject_above`.

For client-signing evaluation, an `on_no_route: review` miss produces Always
Review. Cosigner documents cannot express review or operator-default routing
outcomes. If a review verdict is nevertheless reached while evaluating a
cosigner request, the request fails closed as a policy configuration error.
Operators keep review behavior in the signer `policy.json` and write a
deterministic allow-list in each cosigner key's document.

For operator examples and troubleshooting, see
[USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

Routing's shape is deliberately conservative:

- For client signing, it produces only Always Deny or Always Review verdicts.
  A matching route is allow-to-continue, not approval, because fee, rekey,
  close-out, clawback, warning, threshold-guard, and Operator Default
  behavior must still be able to apply.
- For cosigner, it is an allow-list: every target movement must be covered
  by a matching route, and any deny verdict rejects the request.
- It denies by absence rather than by general explicit deny routes. In v1,
  operators grant allowed source/asset/destination paths. In the signer
  document, `on_no_route` decides what a miss means; in a cosigner document,
  every miss rejects. The narrow exception is `blocked_destinations`,
  a global concrete-address deny list that runs before route matching. This
  avoids source-scoped and route-local deny/allow precedence rules.
  `on_no_route: review` lets client signing send route misses to operator review.
- Threshold-map transfer guards are evaluated independently. Their review/deny
  thresholds and audit rule IDs apply, and routes cannot weaken them.
- Close/clawback reject booleans are evaluated independently. Route-level
  `allow_close:true` and `allow_clawback:true` permit matching movements only
  within routing; they do not override `reject_close_remainder`,
  `reject_asset_close`, or `reject_clawback`. This overlap is permitted rather
  than rejected: the reject booleans always win, so a route allow flag cannot
  weaken them. `check` and `apply` report the overlap as a warning
  (`internal/policy/advisory.go`); it never blocks an apply.
- Limits never mix units. Route and document `limits` are keyed by network and
  then by asset, so each threshold applies to exactly one asset in its own base
  units.

In the signer document, routing is disabled unless
`transfer_policy.enabled:true`; `enabled` is required whenever
`transfer_policy` is present, and `on_no_route` is required when routing is
enabled. `close_on_no_route` and `clawback_on_no_route` default to `reject`
and may be set explicitly. A cosigner document always enforces its routes.
Unknown fields under `transfer_policy` or route entries fail validation.

Signer `transfer_policy` schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `enabled` | yes | Enables routing when `true`; disables routing when `false` |
| `on_no_route` | when enabled | Route-miss verdict: `reject`, `review`, or `operator_default` |
| `close_on_no_route` | no | Close-out route-miss verdict; defaults to `reject` |
| `clawback_on_no_route` | no | Clawback route-miss verdict; defaults to `reject` |
| `blocked_destinations` | no | Global concrete-address deny list evaluated before route matching |
| `routes` | no | Ordered route definitions; order does not grant priority |

A cosigner `transfer_policy` holds `blocked_destinations` and a required
`routes` list. Named sets are top-level document fields, `address_sets` and
`asset_sets`, in both document types.

Route schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable route identifier used in policy rule IDs |
| `description` | no | Operator-facing note |
| `networks` | yes | Either `["*"]` or concrete network context tokens |
| `sources` | yes | Sender terms: address, `@address_set`, or `*` |
| `asset_sources` | clawback only | Allowed ASA `AssetSender` terms; requires `allow_clawback:true` |
| `assets` | yes | Asset terms: `algo`, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | yes | Receiver terms: address, `@address_set`, `self`, or `*` |
| `limits` | no | Per-network, per-asset `review_above` (signer only) and `reject_above` raw thresholds |
| `allow_close` | no | Allows matching ALGO/ASA close-out movements; defaults to false |
| `allow_clawback` | no | Allows matching ASA clawback movements; defaults to false |

Route IDs must match `^[a-z0-9][a-z0-9_-]*$`. Network names are APlane network
context tokens as defined in [ARCH_NETWORKS.md](ARCH_NETWORKS.md). A route's
`networks` field may be exactly `["*"]` or a list of concrete tokens, but not a
mix of `*` and concrete tokens.

Address sets accept either a flat list, which applies on every network, or a
map keyed by network context token. `*` is not a valid network key inside an
address set; use the flat-list shape for all-network membership. Asset sets
are maps from network context token to `asa:<id>` terms; they do not accept a
flat-list shape because ASA IDs are network-local.

`blocked_destinations` is a flat list of concrete Algorand addresses. It does
not accept `self`, `*`, or `@address_set` terms. The list is global in v1:
it is not source-scoped, asset-scoped, or network-scoped. Signer key overrides
cannot change it.

Routing extracts movements only from direct payment and asset-transfer
transactions:

- `pay` creates a normal ALGO movement from `Sender` to `Receiver`.
- non-zero `CloseRemainderTo` creates an additional `pay_close` movement.
- normal `axfer` creates an ASA movement from `Sender` to `AssetReceiver`.
- an ASA opt-in is represented as `axfer_optin` when the receiver is the
  sender, amount is zero, `AssetSender` is zero, and `AssetCloseTo` is zero.
- non-zero `AssetCloseTo` creates an additional `asset_close` movement.
- clawback is represented as `clawback` when `AssetSender` is non-zero and not
  equal to `Sender`; the route must match `sources`, `asset_sources`, `assets`,
  and `destinations`.

Together, `pay`, `pay_close`, `axfer`, `axfer_optin`, `asset_close`, and
`clawback` are the supported cosigner transfer-movement surface. A pure rekey
uses the separate `rekey_policy.allowed` authorization path; other target
transactions must extract at least one supported movement.

For client signing, other transaction types produce no routing movement and
continue through the remaining policy phases. For cosigner, target
transactions that produce no supported movement and are not an allowed pure
rekey are rejected because no policy path can authorize them. Passthrough, foreign, and
non-target group slots are not governed by this signer's route table because
this signer is not producing signatures for those slots.

For each extracted movement, routing checks `blocked_destinations` before
network-dependent route matching. The block applies to normal ALGO payment
receivers, ALGO close remainder destinations, normal ASA transfer receivers,
ASA close-out destinations, and ASA clawback receivers. ASA opt-ins are not
blocked by this field. Because the blocked list is global, it can reject even
when the transaction `GenesisHash` is unknown.

After that check, routing resolves the transaction `GenesisHash` to a network
token. If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash`. In the signer document its tier follows
`on_no_route`: Always Deny for `reject`, Always Review for `review`, and no
routing verdict for `operator_default`. In a cosigner document it is always
Always Deny.

Verdict production for each movement:

1. Routing sits out when the signer document's `transfer_policy` is absent or
   disabled, or the movement is routing-exempt. A cosigner document always
   carries an enforced `transfer_policy`.
2. If the movement kind is covered by `blocked_destinations` and the movement
   destination is blocked, Always Deny.
3. Matching routes are collected by network, source, asset, destination, and,
   for clawback only, asset source.
4. If no route matches a close-out movement, apply `close_on_no_route`.
5. If no route matches a clawback movement, apply `clawback_on_no_route`.
6. If no route matches any other movement, apply `on_no_route`.

   A cosigner document has none of these three fields; every miss in steps 4
   to 6 is Always Deny.
7. A close-out movement with matching routes is Always Deny unless at least one
   matching route has `allow_close:true`.
8. A clawback movement with matching routes is Always Deny unless at least one
   matching route has `allow_clawback:true`.
9. If the amount is known and any matching route has a `reject_above` for the
   movement's network and asset, the lowest such threshold wins; amounts
   strictly greater than that value are Always Deny.
10. If the amount is known and any matching route has a `review_above` for the
   movement's network and asset, the lowest such threshold wins; amounts
   strictly greater than that value are Always Review.
11. Otherwise, client-signing routing produces no verdict and the request
   continues to warning review, explicit auto-approval, or Operator Default.
   For cosigner routing, a target movement that reaches this step is
   covered by policy; if every target movement is covered and no deny guard
   matched, the transfer-policy portion of cosigner authorization succeeds.

Route `limits` name only networks and assets the route covers. If both review
and reject thresholds are set for one asset, `reject_above` must be greater than
or equal to `review_above`. Amounts are decimal strings in raw on-chain units:
microAlgos for ALGO and base units for ASAs. An asset a route covers but its
`limits` does not mention has no route-level threshold; document-level `limits`
still apply to it.

The exact self no-op shape used by `auto_approve_self_noop_transfer`, including
signer-generated LogicSig-budget dummy transactions, is routing-exempt. Routing
exemption suppresses all routing verdicts for that shape. Non-routing guards
such as warning analysis, fee checks, rekey/close/clawback guards, and the
self no-op auto-approval predicate still apply according to their own rules.
For cosigner, the self no-op predicate never fires because it requires
signer-owned address context.

Routing rule IDs:

- `transfer_policy:blocked_destination`
- `transfer_policy:route_miss`
- `transfer_policy:unknown_genesis_hash`
- `transfer_policy:close_route_miss`
- `transfer_policy:clawback_route_miss`
- `transfer_policy:close_rejected`
- `transfer_policy:clawback_rejected`
- `transfer_policy:<route_id>:close_rejected`
- `transfer_policy:<route_id>:clawback_rejected`
- `transfer_policy:<route_id>:reject_above`
- `transfer_policy:<route_id>:review_above`

The per-route IDs use the stable grammar
`transfer_policy:<route_id>:<outcome>`, where `<outcome>` is one of
`close_rejected`, `clawback_rejected`, `reject_above`, or `review_above`.
`review_above` rule IDs are client-signing-only. Cosigner can emit
blocked-destination, route-miss, close/clawback rejection, unknown-genesis, and
`reject_above` IDs, but review-producing route outcomes are invalid for
cosigner component requests.

Cosigner component policy selection runs before any rule evaluation. The
request's `component_key` must name a cosigner key the node holds; otherwise
the request fails as a bad request (`Witness Key ID "<id>" not found`) with no
policy verdict. The held key must then have a verified policy document;
otherwise the request is rejected with `cosigner_policy:key_has_no_policy`.
Only then is that key's document evaluated, and only after it authorizes the
request is the cosigner key loaded for signing. There is no node-wide cosigner
policy to fall back to.

Cosigner component policy rule IDs:

- `cosigner_policy:key_has_no_policy`
- `cosigner_policy:transfer_policy_required`
- `cosigner_policy:deterministic_routing_required`
- `cosigner_policy:non_transfer`
- `cosigner_policy:reject_rekey`

These rule IDs are emitted when the requested cosigner key has no policy
document, its compiled policy lacks an enabled positive transfer policy or has
route-miss behavior that is not deterministic `reject` (the cosigner document
type cannot express either, so these are defense-in-depth checks), the request
asks it to attest a target with no supported transfer movement, or it rejects a
non-zero `RekeyTo` because the coarse deny switch is set, the rekey shape is
unsupported, or `rekey_policy.allowed` has no matching sender-to-target edge.

## Key Overrides

Only the signer document has `key_overrides`: a map from Algorand auth address
to a sparse block of scalar settings (`reject_*`, `always_review_warnings`,
`auto_approve_self_noop_transfer`, `max_fee_microalgos`) and `limits`.
Overrides carry no sets, no `transfer_policy`, and no nesting; per-account
routing is expressed with route `sources`. Cosigner documents have no
overrides because each cosigner key already has its own document.

During normal transaction signing, the effective policy is selected by the
`auth_address` key that will sign, not by transaction sender. This matters for
rekeyed accounts: the auth address controls the override. During cosigner
component signing, the policy is selected by the request `component_key`
Witness Key ID, which picks that key's document.

An override scalar replaces the document value and an omitted scalar inherits
it. Override `limits` merge per network, per asset, and per threshold; a `null`
threshold removes the inherited one. Validation runs on each key's merged
effective `limits`. If no override matches, the document-level policy applies.
The exact merge rules are in
[ARCH_POLICY_FORMAT.md](ARCH_POLICY_FORMAT.md#key-override-inheritance).

## Transaction Scope

For client signing, Always Deny, Always Review, and Always Approve rules
evaluate signer-controlled request slots only. Passthrough and foreign slots
are not signed by this signer, so they are not evaluated by this signer's
transaction-level policy. They still participate in request planning, group
context, warning display, and approval rendering.

For cosigner, the evaluated slots are the `target_indices` of a
`/sign/component` request. The cosigner node does not own the sender
account; "target" means "transaction this cosigner is being asked to authorize"
rather than "transaction signed by a key this identity holds." Non-target
group members (including passthrough slots prepared by the user signer and
foreign slots) participate in group context, warning display, and the
operator-facing approval description, but they do not receive their own
cosigner policy verdict.

Groups receive group-level approval. A grouped request does not fan out into
separate per-transaction human approvals. For cosigner this is trivially
true because no human approval is involved.

## Admin Surface

`apadmin policy` operates against the live signer through admin IPC. Policy
documents are written outside the node, reviewed with
`apadmin policy check FILE...`, and installed with `apadmin policy apply
FILE...` (or `apadmin policy rescue check|apply` while the daemon is stopped).
There is no policy editor in the node and no scalar policy-settings IPC.

The admin protocol and `internal/signerapp/admin` expose four policy messages:
`get_policy`, `get_policy_document`, `check_policy`, and `apply_policy`. The
node role decides which documents a request may carry; there is no target
selector. `get_policy` returns a summary: each document's SHA-256, size, and
applied time, the cosigner key coverage, and `policy_set_sha256`, a digest over
the whole document set. `get_policy_document` returns one document's exact
bytes.
`check_policy` validates candidate documents without writing and returns
errors and warnings. `apply_policy` requires `expected_policy_set_sha256` for
optimistic concurrency, validates the resulting document set, and, when the resulting set changes, commits it as
one new generation (operation `policy-apply`); the runtime publishes the new
policy immediately. On a signer node an apply carries exactly one document; on a
cosigner node it adds or replaces the listed keys' documents, deletes the keys in
`remove`, and keeps every other key's document. Every digest covers exact
document bytes. Message payloads are in
[ARCH_ADMIN_PROTOCOL.md](ARCH_ADMIN_PROTOCOL.md); generation behavior is in
[ARCH_GENERATIONS.md](ARCH_GENERATIONS.md).

`apadmin policy` requires a verb:

| Verb | Behavior |
|------|----------|
| `status` | List the node's documents (size, SHA-256, applied time) and, on a cosigner node, each key's coverage: `active`, `no_policy`, or `key_not_held` |
| `export [--key ID]` | Write one stored document exactly as stored; `--key` selects a cosigner key's document |
| `check FILE...\|-` | Validate documents against the node; print errors and warnings |
| `diff FILE...\|-` | Describe how the files differ from the active documents, without writing |
| `apply FILE...\|-` | Run `check`, stop on errors, print the diff, confirm, then apply against the current `policy_set_sha256` |
| `remove ID...` | Print the diff, confirm, then delete cosigner keys' documents (cosigner nodes only) |

`diff` compares decoded documents (`policy.DiffSignerPolicyV1`,
`policy.DiffCosignerPolicyV1`), so formatting and key order never appear as
changes. Each change names a path (routes by id, key overrides by address) and
is marked `tightened`, `loosened`, or `changed`: raising or removing a threshold,
clearing a `reject_*` flag, adding a route, route term, or member of a set a
route uses, relaxing a route-miss action, or removing a blocked destination
loosens; the reverse tightens. A fee cap of `"0"` is compared as no cap,
matching enforcement. Address sets are compared on the members they cover on
each network, so moving between flat and per-network forms is described by
what changes where. Key overrides are compared on the values that take effect
for that key, and a field moving between inherited and set explicitly is
reported as `changed` even when its value is the same, because it decides
whether later document changes reach the key. A cosigner key gaining its first
document loosens (it rejected every request); removing one tightens. `apply`
and `remove` ask for confirmation on the controlling terminal, never stdin;
`--yes` skips it. `apply` skips the commit only when every submitted document
decodes identical to the active one; a document that differs only in term order
is still applied.

A signer node takes one file. Each cosigner file is one key's document and names
that key in its `key` field. Online verbs authenticate through admin IPC and
unlock a locked identity with the authenticated passphrase before policy access;
this applies to read-only verbs too.

`apadmin policy rescue VERB` runs the same verbs directly against the store with
the same rules as the daemon (the shared `internal/signerapp/policyapply`
package). It reads root `node.yaml` for the role and verifies the policy
sidecars with the store passphrase. Read verbs hold the shared store lock;
`apply` and `remove` hold the exclusive store mutation lock and therefore
require a stopped daemon. On a systemd store, offline use requires root. Local
non-interactive rescue may use `APSIGNER_PASSPHRASE`; remote policy commands
require the controlling terminal.

For deliberately hand-placed documents in a stopped store, `apstore policy
check` validates the stored documents without verifying sidecars and warns about
cosigner keys without documents and documents for keys not held; `apstore
policy sign` re-signs the sidecars (signer: `policy.json`; cosigner: every
`policies/*.json`); `apstore policy verify` verifies the sidecars with the store
passphrase and compiles the documents. `apstore policy sign` is an offline store
mutation and requires the store mutation lock. Hand-placed documents take effect
only after the next successful reload, unlock, or restart.

## Backup and Restore

A cosigner key's policy travels with the key. A backup of a cosigner key that
has a policy carries `policies/<WitnessKeyID>.apb`: the exact v1 document,
encrypted under the export passphrase and listed in the sealed manifest. Restore
validates it against the key and installs it with a sidecar signed by the
destination store, in the same generation commit as the credential:

| Destination | Archive | Result |
|---|---|---|
| no policy for the key | policy | installed |
| the same policy | same | nothing to do |
| a different policy | policy | conflict; `replace_existing` replaces it |
| a policy | none | the destination's policy is kept |

A restored cosigner key without an archived or existing policy rejects every
request until one is applied. Restore rollback restores the source generation's
cosigner policies along with its keys.

Backups carry no signer `policy.json`, approval setting, network mapping, or
other operational configuration: a signer's restored credentials run under the
destination's current policy, which the operator owns. Restore requires the
admin authorization action `identity.restore`.

## Audit and Observability

Signing outcome audit records carry the matching policy rule in `policy_rule_id`:

- Always Deny matches produce `sign_rejected` records with the rejecting rule.
- Always Review matches produce `sign_approved` or `sign_rejected` records with
  the forcing rule, depending on the operator's decision.
- Always Approve matches produce `sign_approved` records with the approving rule.
- Operator Default outcomes produce records with no `policy_rule_id`.

The signer also prints `[POLICY] ...` lines to its console output for each
policy decision:

- `[POLICY] Group/Txn auto-approved (<rule_id>)` when an Always Approve rule
  matches.
- `[POLICY] Group/Txn requires manual review (<rule_id>)` when an Always Review
  rule forces a prompt.
- `[USER AUTO-APPROVE] ...` when Operator Default approves without prompting.

Cosigner component signing uses the same policy rule identifiers for decoded
transaction facts. Cosigner component approvals and policy rejections are
recorded through existing `SIGN_APPROVED`/`SIGN_REJECTED` audit events with the
Witness Key ID in `txn_auth`, the decoded sender in `txn_sender`, and the
policy rule in `policy_rule_id` when applicable. The
architecture overview is in [ARCH_COSIGNER.md](ARCH_COSIGNER.md);
compatibility-bearing audit details live in
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Source Files

Implementation source of truth:

- `internal/policy/config.go`: effective (compiled) policy model.
- `internal/policy/lint.go`: Always Deny transaction checks.
- `internal/policy/review.go`: Always Review transfer guard checks.
- `internal/policy/transfer_routing.go`: compiled transfer routing model and
  validation.
- `internal/policy/transfer_routing_eval.go`: direct transfer movement
  extraction and route evaluation.
- `internal/policy/doc_v1.go`, `internal/policy/doc_v1_compile.go`: v1 document
  decoding, semantic validation, and compilation.
- `internal/policy/store_v1.go`: policy document storage, sidecars, and the
  policy-set digest.
- `internal/signerapp/policyruntime`: verified per-role policy load.
- `internal/signerapp/policyapply`: shared check and generation-commit rules for
  online apply, rescue, and `apstore`.
- `cmd/apadmin/policy.go`: policy command adapter and local IPC transport selection.
- `internal/signerapp/policycmd`: online and offline-rescue policy workflows.
- `internal/signerapp/signing/cosigner_policy.go`: cosigner key and policy
  selection and evaluation.
- `internal/signerapp/signing/always_review.go`: Always Review evaluation.
- `internal/signerapp/signing/approval.go`: approval prompts and operator default behavior.
- `internal/signerapp/signing/service.go`: phase ordering.
- `internal/signerapp/admin/policy.go`: admin policy read, check, and apply
  service.
