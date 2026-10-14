# Policy Architecture

> The signer policy system on both node roles: the verdict model that decides
> what `apsigner` may sign, the v1 policy document format
> (`aplane.policy.v1`) that expresses it, how documents are stored and
> accepted, and the operator surface that changes them.

This document holds the approval and policy compatibility contracts. A node
accepts, signs, and enforces exactly what the format and its semantic checks
admit; the verdict model below says what the accepted rules mean.

## Contents

- Verdict model: [Status](#status), [Scope](#scope),
  [Verdict Model](#verdict-model), [Policy Selection](#policy-selection),
  [Runtime Snapshot Semantics](#runtime-snapshot-semantics)
- Rules by tier: [Always Deny](#always-deny), [Always Review](#always-review),
  [Always Approve](#always-approve), [Operator Default](#operator-default),
  [Transfer Routing](#transfer-routing), [Transaction Scope](#transaction-scope),
  [Bounded Authorization Interaction](#bounded-authorization-interaction),
  [Rotating Account Interaction](#rotating-account-interaction)
- Document format: [The Boundary](#the-boundary), [Role Domains](#role-domains),
  [Parsing](#parsing), [Terms](#terms), [Fields](#fields), [Routes](#routes),
  [Limits](#limits), [Semantic Rules](#semantic-rules),
  [Embedded Defaults](#embedded-defaults)
- Storage and acceptance: [Storage](#storage),
  [Storage and Acceptance](#storage-and-acceptance)
- Operations: [Admin Surface](#admin-surface),
  [Backup and Restore](#backup-and-restore),
  [Audit and Observability](#audit-and-observability),
  [Changes From `policy.yaml`](#changes-from-policyyaml),
  [Source Files](#source-files)

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
cosigner domain (see [ARCH_GUARDED.md](ARCH_GUARDED.md)).

Both domains are written in one v1 JSON document format, `aplane.policy.v1`,
specified in [The Boundary](#the-boundary) through
[Embedded Defaults](#embedded-defaults). The document's
`role` field says which domain it is for, and the two roles share one
decoder, one compiler, one differ, one fixture corpus, one storage layout,
and one verdict-model description. Fields that apply to only one domain are
tagged inline.

The format is implemented. The decoder, semantic validation, and compiler live in `internal/policy` (`jsontree.go`,
`doc_v1.go`, `doc_v1_compile.go`), storage and sidecar handling in
`internal/policy/store_v1.go`, the shipped defaults in
`internal/policy/defaults/`, and the shared check/commit rules in
`internal/signerapp/policyapply`. Every contract fixture is checked against
both the JSON Schema and the decoder. The system is unreleased, so v1 does
not read or migrate `policy.yaml`.

## Scope

Policy governs keys. Every node has one **default** document, the complete
rulebook for every key that has no document of its own, and zero or one
complete document per key. A key with a document of its own is governed by
that document alone; a key without one is governed by the default. There is
no inheritance, no merge, and no per-field override between the two: a key's
document replaces the default wholesale.

On a signer node a key is an account the node holds, selected by its Algorand
address; its document covers all signing by that account, including the user
side of a guarded key. Membership changes with key generation, import, and
deletion, and per-account rules live either in the account's own document or
in routes whose `sources` name the account. On a cosigner node a key is a
cosigner key, selected by its Witness Key ID; its document covers component
signing by that key for every account whose guarded key was composed with it.
That set is virtual: the node does not hold those accounts, cannot enumerate
them, and learns of one when a `/sign/component` request names it, so the
document's `sources` are the cosigner operator's only control over
membership. A guarded account is in both a signer key's scope and a cosigner
key's scope, and both documents must allow a movement.

Signer policy decides what `apsigner` may produce a signature for after
request planning has identified the signable units. For client signing, the
unit is a signer-controlled transaction; for cosigner, the unit is a
target transaction in `/sign/component`. Policy is separate from:

- authentication and authorization, which decide who may ask for signing,
- key ownership and unlock state, which decide whether signing keys are usable,
- the operator default, which decides whether unmatched client-signing requests
  need manual review. Cosigner has no operator default.

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

1. Evaluate policy rules. Inside Always Deny and Always Review the
   transaction-type verdict runs first and alone, so a rejected or reviewed
   type names the type rather than a later rule.
2. If any Always Deny rule matches, reject.
3. Else if any Always Review rule matches, require approval.
4. Else if any Always Approve rule matches, sign.
5. Else use Operator Default:
   - `user_auto_approve:false` requires approval.
   - `user_auto_approve:true` signs without approval.

The engine is ordered and short-circuiting. In `internal/signerapp/signing`,
`EvaluateAutoRejectionRules` runs the Always Deny rules, then
`EvaluateAlwaysReviewRules` the Always Review rules, then
`EvaluateAutoApprovalRules` the Always Approve rules; any Always Deny
violation rejects the request and no later phase can approve it.

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

The deterministic cosigner surface is enforced at decode on a cosigner node:
a cosigner document has no `always_review_warnings`, no `review_above`
thresholds, no `on_no_route`, `close_on_no_route`, or `clawback_on_no_route`
fields, no `review` value in `transaction_types`, and unknown fields are
rejected. If implementation ever encounters a review verdict while
evaluating a cosigner component request, the request fails closed as a
policy configuration error rather than waiting for a prompt.

`user_auto_approve` is client-signing-only. It lives in
`identities/default/config.yaml` and has no cosigner analog.

## Policy Selection

The daemon compiles a `policyruntime.NodePolicy` snapshot per generation:
`{Role, Documents, Default, Keys}`, where `Default` is the compiled node
default and `Keys` maps each selector with a document of its own to its
compiled policy. `PolicyFor(selector)` returns `Keys[selector]` when present
and `Default` otherwise. Selection is by the key that signs, never by the
transaction sender:

- ordinary `/sign` requests select by the request's `auth_address`, so a
  rekeyed account uses the policy of its auth address;
- user-role `/sign/component` requests select by the guarded account;
- cosigner-role `/sign/component` requests select by the `component_key`
  Witness Key ID. A key the node does not hold fails as a bad request
  (`Witness Key ID "<id>" not found`) before any policy evaluation. The held
  key's policy is then resolved (its own document, or the node default, which
  ships deny-all), and only after it authorizes the request is the cosigner
  key loaded for signing.

Every slot of a request resolves through the same resolver, so a mixed group
whose slots sign under different keys evaluates each slot under its own key's
document. A policy that cannot be resolved (policy not loaded) fails closed.

## Runtime Snapshot Semantics

The product runtime publishes policy updates atomically. Readers see either
the previous policy snapshot or the replacement snapshot; they must not observe
a partially applied policy.

Each signing request captures one `NodePolicy` snapshot when its signing
service is constructed, and the service's `PolicyFor` resolver closes over
that value. It never reads the runtime's current policy per call, so every
slot of a group resolves against the same snapshot, and two resolutions on
one service return the same policy even if a reload lands between them. That
snapshot governs the request through policy evaluation, approval waiting, and
final signature execution. A later successful policy reload or `apadmin`
online policy apply applies only to signing requests that start after the new
snapshot is published. In-flight requests are not re-evaluated or canceled
merely because the policy changed while they were waiting for approval. This
is a deliberate contract, not a gap: deny and review verdicts are decided with
the policy at the time the request is presented, not at the time the operator
approves it. A request whose prompt is in front of the operator, or queued
behind another prompt for up to `approval_wait`, signs under the policy it
was evaluated against when approved. An operator who needs a tighter policy
to cover requests already waiting rejects those prompts or locks the signer,
which fails every pending approval (see [USER_POLICY.md](USER_POLICY.md),
"Editing Policy").

## Always Deny

Always Deny rules are hard safety guards. They cannot be approved by an
operator prompt and are evaluated before all other policy or approval phases.

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `transaction_types` `reject` | common | Reject every transaction of that type; evaluated first and alone, so nothing else is reported for a rejected type |
| `reject_foreign_rekey` | signer | Reject transactions whose non-zero `RekeyTo` target is not held by the product signer runtime |
| `reject_rekey` | cosigner | Coarse deny-all switch for transactions with non-zero `RekeyTo` |
| `rekey_policy` | cosigner | Allow-list for pure 0 ALGO self-payment rekeys by sender and rekey target |
| `reject_close_remainder` | common | Reject payment transactions with non-zero `CloseRemainderTo` |
| `reject_asset_close` | common | Reject ASA transfers with non-zero `AssetCloseTo` |
| `reject_clawback` | common | Reject ASA clawback transactions using `AssetSender` |
| `max_fee_microalgos` | common | Reject transactions whose raw microAlgo fee exceeds the configured ceiling; `"0"` is no ceiling |
| `limits` `reject_above` | common | Per-network, per-asset raw ceilings for ALGO payments (microAlgos) and ASA transfers (base units) |
| `transfer_policy` | common | For client signing, produces deny verdicts for blocked destinations, route misses, close/clawback misses, and `reject_above`; for cosigner, routing is the positive authorization surface |

The transaction-type rule emits `transaction_type:<type>`, where `<type>` is
the Algorand type string (`pay`, `axfer`, `acfg`, `afrz`, `keyreg`, `appl`,
`stpf`, `hb`). The map's `*` entry decides every type it does not name. On a
cosigner node decode refuses `allow` for anything but `pay` and `axfer`, so
every non-transfer type a cosigner is asked to attest is rejected here.

`reject_foreign_rekey` evaluates the rekey target against the set of addresses
held by the current signer, which is meaningful only when the signer owns the
sender. `reject_rekey` is the cosigner coarse-deny analog and ignores key
ownership: when true, any non-zero `RekeyTo` rejects. When it is false, the
cosigner still fails closed unless `rekey_policy.allowed` authorizes the exact
sender-to-target edge and the target transaction is a pure 0 ALGO
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
must be greater than or equal to it ([Semantic Rules](#semantic-rules)).

Policy documents store amounts as decimal strings in base units (microAlgos
for ALGO); review and rejection text use display units.

`transfer_policy` is a route table for direct `pay` and `axfer`
movements. It can reject blocked destinations, route misses,
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
cosigner domain has no operator above the signer, so decode refuses every
review-producing field and value in a cosigner document. If a
review verdict is reachable while evaluating a cosigner
component request, the request fails closed as a policy configuration error.
See [Verdict Mapping By Role](#verdict-mapping-by-role).

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `transaction_types` `review` | signer | Require operator review for every transaction of that type; evaluated first in this tier, so the prompt names the type |
| `always_review_warnings` | signer | Require operator review when warning analysis finds risk markers |
| `limits` `review_above` | signer | Per-network, per-asset raw thresholds that require review for ALGO payments and ASA transfers |
| `transfer_policy.on_no_route: review` | signer | Forces ordinary route misses to review for client signing |
| `transfer_policy.close_on_no_route: review` | signer | Forces close-out route misses to review for client signing |
| `transfer_policy.clawback_on_no_route: review` | signer | Forces clawback route misses to review for client signing |
| `transfer_policy` `review_above` | signer | Route-level review threshold |

The transaction-type rule emits the same `transaction_type:<type>` ID as its
deny counterpart; the phase that emits it says which. A type `review` is
Always Review, so it defeats `auto_approve_self_noop_transfer` and
`user_auto_approve:true` like every other rule in this tier.

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

Warning analysis (`internal/signerapp/approvalpolicy/warnings.go`) covers:

- rekey fields,
- ALGO close-out fields,
- ASA close-out fields,
- ASA clawback fields,
- application delete, clear-state, and update (`OnCompletion`
  `DeleteApplication`, `ClearState`, `UpdateApplication`),
- asset reconfigure (`acfg` naming an existing asset; the warning names the
  resulting Manager, Reserve, Freeze, and Clawback addresses, with
  `(cleared)` for a zeroed role) and asset destroy,
- asset freeze and unfreeze (`afrz`),
- unusually high fees above 1 ALGO.

`always_review_warnings` governs only the signer's own legs. A warning on a
passthrough or foreign leg of a group this signer co-signs always forces
review, even with the setting off and even under `user_auto_approve:true`.
Warnings on the signer's own legs are still displayed when
`always_review_warnings:false`; they simply do not force review in that mode.

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
The field does not exist in a cosigner document. If an invalid
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

Priced program bytes and native-PQ fee contributions disable this narrow
auto-approval. The ASA form may opt into an asset if the account does not
already hold it.

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

Under the shipped signer default, route misses and non-transfer types produce
no verdict, so with the switch on a key with no document of its own signs
whatever the default does not reject or force to review, and with it off a
human approves. Turning the switch on without per-key documents is that
choice.

## Transfer Routing

`transfer_policy` is the implemented v1 route table for direct transfer
movements. The same routing engine applies to both client-signing and
cosigner evaluation, reading the document that governs the signing key: its
own, or the node default. Transfer routing is not projected through admin IPC
as separate settings; it travels only inside whole policy documents.

For client signing, a route match means "allowed to continue through the
normal policy phases"; it does not approve signing and never produces an
Always Approve verdict.

For cosigner, routing is the positive authorization surface. A cosigner
component request is eligible to sign only when all evaluated target
transactions are supported transfer shapes, every extracted target movement is
covered by a matching route, and no route or transaction guard produces a deny
verdict. A cosigner document cannot express review-producing behavior, so a
cosigner route outcome is always sign or reject. In other words: for client signing, routing is a
guardrail; for cosigner, routing is an allow-list.

Always Deny and deterministic transaction guards run before cosigner
allow-list success. A route match cannot rescue a target rejected by type,
rekey, close-out, clawback, fee, amount, blocked-destination, or
unsupported-shape rules.

For client-signing evaluation, an `on_no_route: review` miss produces Always
Review. Cosigner documents cannot express review or operator-default routing
outcomes, so operators keep review behavior in signer documents and write a
deterministic allow-list in cosigner documents.

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
  operators grant allowed source/asset/destination paths. In a signer
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
  ([Advisories](#advisories)); it never blocks an apply.

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
`clawback` are the supported cosigner transfer-movement surface in MVP; a
target transaction must extract at least one of these movements to be eligible
for cosigner-role component signing.

For client signing, other transaction types produce no routing movement and
continue through the remaining policy phases once `transaction_types` allows
them. On a cosigner node they never reach routing: decode refuses to `allow`
any type but `pay` and `axfer`, so the transaction-type rule rejects them
first. Passthrough, foreign, and non-target group slots are not governed by
this signer's route table because this signer is not producing signatures for
those slots.

For each extracted movement, routing checks `blocked_destinations` before
network-dependent route matching. The block applies to normal ALGO payment
receivers, ALGO close remainder destinations, normal ASA transfer receivers,
ASA close-out destinations, and ASA clawback receivers. ASA opt-ins are not
blocked by this field. Because the blocked list is global, it can reject even
when the transaction `GenesisHash` is unknown.

After that check, routing resolves the transaction `GenesisHash` to a network
token. If the hash cannot be resolved, routing emits
`transfer_policy:unknown_genesis_hash`. In a signer document its tier follows
`on_no_route`: Always Deny for `reject`, Always Review for `review`, and no
routing verdict for `operator_default`. In a cosigner document it is always
Always Deny.

Verdict production for each movement:

1. Routing sits out when the movement is routing-exempt (the self no-op
   shape below).
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

Cosigner component policy rule IDs are the common rule IDs above (type,
reject flags, fee, limits, routing) plus one cosigner-only ID:

- `cosigner_policy:reject_rekey`

It is emitted when the cosigner rejects a non-zero `RekeyTo` because
`reject_rekey` is set, the rekey shape is unsupported (not a pure 0 ALGO
self-payment without close remainder), or `rekey_policy.allowed` has no
matching sender-to-target edge. A cosigner key with no document of its own is
governed by the default like any other key; under the shipped deny-all
default every request is rejected with `transaction_type:<type>`.

## Transaction Scope

For client signing, Always Deny, Always Review, and Always Approve rules
evaluate signer-controlled request slots only. Passthrough and foreign slots
are not signed by this signer, so they are not evaluated by this signer's
transaction-level policy (the transaction-type rule included). They still
participate in request planning, group consistency checks, group context,
warning display, approval rendering, and audit visibility, and a warning on a passthrough or foreign leg always forces
review, whatever `always_review_warnings` says.

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

Broader group-level or structural policy constraints are not part of this compatibility surface.

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

## Rotating Account Interaction

A rotating account (`signing_flow: rotating1`) rekeys on every spend. The
rotation target is the signer's own next stage, derived from the account's
seed but never stored as a key file. For that request only, the signer adds
the target to the held-address set, so `reject_foreign_rekey` and the rekey
warning treat it as the signer's own address. Every other rule applies
unchanged, including `always_review_warnings`, which still flags each
rotation because a rekey is always a warning. The approval description
names the signing stage, the target stage and the target address.

There is no exit from the scheme: a rotating account leaves it by moving
its funds out, never by rekeying to an outside address, so no rule needs to
distinguish one rekey target from another. See
[ARCH_SIGNING.md](ARCH_SIGNING.md#rotating-accounts-rotating1).

## The Boundary

The policy document is the signer/cosigner interface. A node accepts, signs,
and enforces exactly what this format and its semantic checks admit; it does
not care what produced the document. People, LLMs, scripts, and external tools
are all producers outside the boundary.

Consequences:

- Every rule the node relies on is checked at acceptance (`apadmin policy
  check`/`apply`, `apstore policy check`/`sign`, and every load), never only by
  a producer.
- Errors name the failing location as a JSON Pointer, so any producer can fix
  the exact field.
- The schema is a versioned contract. Changing it is a deliberate new
  `format` version.
- There is no policy editor in the node. Review happens through `check` and
  `diff` before `apply`, which shows the same diff and asks for confirmation.
- Comments are a producer convenience, not part of the format. The apadmin
  policy commands and the apadmin TUI accept `//` and `/* */` comments
  outside strings and remove them (`policyreview.StripComments`) before the
  document is sent, so the node never sees or stores them. `apstore policy
  check|sign` act on documents already in the store, which must be strict
  JSON.
- Nothing in a document is implied. Every verdict-bearing field is required,
  and the decoder fills in no defaults. Optional fields are only those whose
  absence means "no such thing": no description, no thresholds, no sets, no
  blocked destinations, no rekey edges.

The machine-readable schema is
[`pkg/policyschema/policy.v1.schema.json`](../pkg/policyschema/policy.v1.schema.json)
(JSON Schema 2020-12). It is a `oneOf` over a signer variant and a cosigner
variant discriminated by `role`, each with `additionalProperties: false`, so
a field the role does not support fails the schema before it reaches the
node. Examples are in
[`test/contracts/policy/v1/`](../test/contracts/policy/v1/): valid documents at
the top level, named for the role and shape they exercise
(`signer_default.json`, `signer_key_full.json`, `signer_key_minimal.json`,
`signer_uint64_max.json`, `cosigner_default.json`, `cosigner_key_full.json`,
`cosigner_key_minimal.json`); schema-invalid documents in `invalid/`; and
documents the schema accepts but the node's semantic rules reject in
`semantic_invalid/`. The fixture test decodes each valid document against the
role its name states.

## Role Domains

One document format serves both roles. The `role` field selects the field
set and must match the node role; the `key` field says whether the document
is the node default or one key's own.

A signer document:

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": true,
  "max_fee_microalgos": "1000",
  "transaction_types": { "*": "allow", "appl": "review" },
  "limits": {
    "mainnet": { "algo": { "review_above": "100000000" } }
  },
  "transfer_policy": {
    "on_no_route": "reject",
    "close_on_no_route": "reject",
    "clawback_on_no_route": "reject",
    "routes": []
  }
}
```

A cosigner document, here for one key:

```json
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "<WitnessKeyID>",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": false,
  "max_fee_microalgos": "2000",
  "transaction_types": { "*": "reject", "pay": "allow", "axfer": "allow" },
  "transfer_policy": { "routes": [] },
  "rekey_policy": {
    "allowed": [
      { "sender": "<address-or-@set>", "targets": ["<address-or-@set>"] }
    ]
  }
}
```

The signer field set has no `reject_rekey` or `rekey_policy`, which belong to
the cosigner field set; the cosigner field set has none of the signer's
review-producing or ownership-referencing fields. Field tables with the
required/optional/rejected column per role are in
[Fields](#fields).

Client-signing semantics:

- Some fields are valid only in a signer document because their semantics
  reference "this signer owns the account" (`reject_foreign_rekey`,
  `auto_approve_self_noop_transfer`) or their verdict only makes sense with an
  operator above the signer (`always_review_warnings`, `review_above`
  thresholds, `on_no_route: review`, `transaction_types` `review`).

Cosigner semantics:

- `reject_rekey` and `rekey_policy` are valid only in a cosigner document.
- `reject_foreign_rekey`, `always_review_warnings`,
  `auto_approve_self_noop_transfer`, `review_above`, and the three route-miss
  actions do not exist there.
- `transaction_types` may `allow` only `pay` and `axfer`; `*` and every
  non-transfer type must be `reject`.
- `transfer_policy` is required and is the positive authorization surface.
  Route misses, unallowed close-outs, and unallowed clawbacks always reject.
- `rekey_policy` is the positive authorization surface for non-zero `RekeyTo`
  transactions when `reject_rekey` is false. It authorizes only pure
  0 ALGO self-payment rekeys whose sender and target match an allowed edge.
  Bounded-cosigner v1 does not invoke cosigner policy for rekeys; its cosigner slot
  is spend-only and forbidden on administrative paths.

A signer document's `transfer_policy` that contains review-producing behavior
(`on_no_route: review`, `review_above`, and similar fields) is valid for client
signing, but it is not a cosigner allow-list. Cosigner authorization comes only
from the document that governs the requested cosigner key.

## Parsing

- UTF-8 JSON object, at most 1 MiB. No comments: a producer that accepts
  them removes them before sending (see [The Boundary](#the-boundary)).
- Unknown fields are rejected at every level, including fields the other
  role supports.
- **Duplicate object keys are rejected.** Standard decoders silently keep the
  last value, so the node uses a decoder that detects duplicates.
- Trailing data after the document is rejected.
- `format` is required and must be `aplane.policy.v1`.
- `role` is required and must be `signer` or `cosigner`, and must equal the
  node role: a signer document is not accepted on a cosigner node, nor the
  reverse. The role selects which fields are required and which are
  rejected.
- `key` is required and must be `default` or the selector of a key the role
  can hold: an Algorand address (checksum verified) on a signer node, a
  Witness Key ID on a cosigner node. It must equal the file name the
  document is stored as, or the key the request names it for.
- Amounts are decimal strings in base units (microAlgos for ALGO, base units
  for an ASA), e.g. `"5000000"`, from `0` through `18446744073709551615`
  (uint64) without leading zeros. ASA IDs in `asa:<id>` share that range,
  starting at `1`. JSON numbers are rejected because many producers lose
  precision above 2^53. The schema enforces the exact range, so producers
  catch overflow before the node does.

## Terms

| Term | Syntax | Meaning |
|------|--------|---------|
| Address | 58-character Algorand address | One account; checksum is verified |
| Witness Key ID | 52-character uppercase base32 | One cosigner key |
| Network | `^[a-z0-9][a-z0-9_-]*$`, max 64 | A configured network token, e.g. `mainnet` |
| Asset | `algo` or `asa:<id>` | One asset; ASA IDs are network-specific |
| Set reference | `@<name>` | A named set defined in the same document |
| Wildcard | `*` | Any value in that position |
| `self` | `self` | Destinations only: the movement's own source |
| Transaction type | `pay`, `axfer`, `acfg`, `afrz`, `keyreg`, `appl`, `stpf`, `hb`, or `*` | A `transaction_types` entry; `*` covers every type the map does not name |

Bare numeric ASA IDs are not accepted; write `asa:<id>`.

## Fields

One document type serves both roles. The role column says whether a field is
required, optional, or rejected on each role; a rejected field fails the
schema and the decoder. Nothing has a default: a required field that is
absent is an error, and an optional field that is absent means none.

| Field | Type | Signer | Cosigner | Meaning |
|-------|------|--------|----------|---------|
| `format` | `"aplane.policy.v1"` | required | required | Document format |
| `role` | `"signer"` \| `"cosigner"` | required | required | Node role the document is for; must equal the node's |
| `key` | `"default"` or selector | required | required | The document this is: the node default, or one key's own; must equal the file name |
| `description` | string, at most 1024 characters | optional | optional | Notes for reviewers |
| `reject_foreign_rekey` | bool | required | rejected | Reject a rekey to an address this signer does not hold |
| `reject_close_remainder` | bool | required | required | Reject ALGO close-outs |
| `reject_asset_close` | bool | required | required | Reject ASA close-outs |
| `reject_clawback` | bool | required | required | Reject ASA clawbacks |
| `reject_rekey` | bool | rejected | required | Reject every rekey; when false, `rekey_policy` decides |
| `always_review_warnings` | bool | required | rejected | Send warning findings to operator review |
| `auto_approve_self_noop_transfer` | bool | required | rejected | Auto-approve a constrained self no-op transfer |
| `max_fee_microalgos` | amount | required | required | Reject a higher transaction fee; `"0"` is no cap |
| `transaction_types` | map | required | required | Per-type verdict, evaluated before every other rule; see [Transaction Types](#transaction-types) |
| `limits` | limits | optional | optional | Per-network, per-asset thresholds: `review_above` and `reject_above` on a signer node, `reject_above` only on a cosigner node |
| `address_sets` | sets | optional | optional | Named address sets for routes and rekey edges |
| `asset_sets` | sets | optional | optional | Named asset sets for routes |
| `transfer_policy` | object | required | required | Transfer routing; see below |
| `rekey_policy` | object | rejected | optional | `allowed: [{sender, targets}]` rekey edges |

`transfer_policy`:

| Field | Type | Signer | Cosigner | Meaning |
|-------|------|--------|----------|---------|
| `on_no_route` | `reject` \| `review` \| `operator_default` | required | rejected | Verdict for an unmatched movement |
| `close_on_no_route` | same | required | rejected | Verdict for a close-out no route allows |
| `clawback_on_no_route` | same | required | rejected | Verdict for a clawback no route allows |
| `blocked_destinations` | addresses | optional | optional | Always rejected as destinations; checked before route matching |
| `routes` | routes | required | required | The allow-list; may be empty; order does not grant priority |

A document always routes: there is no switch that turns routing off. A
signer document that wants routing to decide nothing sets one `*` to `*`
route for every asset and `operator_default` for the three miss actions; a
document with no routes and `on_no_route: reject` rejects every transfer.

Each document is self-contained; sets are not shared between documents, and
a key's document does not see the default's sets.

### Transaction Types

`transaction_types` maps a transaction type, or `*`, to `allow`, `review`,
or `reject`. The `*` entry is required and covers every type the map does not
name. The verdict is evaluated first, before every other rule: `reject` is
Always Deny and `review` is Always Review, both with rule ID
`transaction_type:<type>`; `allow` lets the transaction continue through the
other rules (routing and limits for `pay` and `axfer`). A compiled policy
with no map rejects every type.

On a cosigner node every value is `allow` or `reject`, and `allow` is
accepted only for `pay` and `axfer`, the types routing governs: `*` and every
non-transfer type must be `reject`. Routing is the cosigner's only
authorization surface, and a type permission with no route table behind it
would authorize application calls from any account composed with the key.

```json
"transaction_types": { "*": "reject", "pay": "allow", "axfer": "allow", "keyreg": "review" }
```

## Routes

| Field | Type | Meaning |
|-------|------|---------|
| `id` | `^[a-z0-9][a-z0-9_-]*$`, max 64 | Unique within the document; appears in rule IDs |
| `description` | string | Notes for reviewers |
| `networks` | `["*"]` or network list | Networks the route applies to |
| `sources` | address terms | Senders the route covers |
| `assets` | asset terms | Assets the route covers |
| `destinations` | address terms or `self` | Receivers the route allows |
| `limits` | limits | Thresholds for this route; `reject_above` only on a cosigner node |
| `allow_close` | bool | Allow close-outs to these destinations |
| `allow_clawback` | bool | Allow clawbacks; requires `asset_sources` |
| `asset_sources` | address terms | Accounts assets may be clawed back from |

`id`, `networks`, `sources`, `assets`, and `destinations` are required.

Network names are APlane network context tokens as defined in
[ARCH_NETWORKS.md](ARCH_NETWORKS.md). A route's
`networks` field may be exactly `["*"]` or a list of concrete tokens, but not a
mix of `*` and concrete tokens.

Address sets accept either a flat list, which applies on every network, or a
map keyed by network context token. `*` is not a valid network key inside an
address set; use the flat-list shape for all-network membership. Asset sets
are maps from network context token to `asa:<id>` terms; they do not accept a
flat-list shape because ASA IDs are network-local.

`blocked_destinations` is a flat list of concrete Algorand addresses. It does
not accept `self`, `*`, or `@address_set` terms. The list is global in v1:
it is not source-scoped, asset-scoped, or network-scoped.

## Limits

```json
"limits": {
  "mainnet": {
    "algo":         { "review_above": "100000000", "reject_above": "1000000000" },
    "asa:31566704": { "reject_above": "5000000000" }
  }
}
```

Limits are keyed by network, then by asset, so a threshold always applies to
exactly one asset in its own base units. The same shape is used at document
level and on routes. Each threshold object sets at least one of
`review_above` and `reject_above`; on a cosigner node `review_above` is
rejected and `reject_above` is required.

Document-level and route-level limits are separate checks and both apply: a
movement is rejected or sent to review if it exceeds the document's threshold
for its asset or the strictest threshold among its matching routes. An asset a
route covers but its `limits` does not mention has no route-level threshold;
document-level limits still apply to it.

## Semantic Rules

Checked at acceptance in addition to the schema:

1. Every address checksum is valid; every amount and ASA ID is within the
   uint64 range (also enforced by the schema).
2. `role` equals the node role, and `key` equals the file name or the key
   the request names the document for.
3. Every `@name` reference resolves to a set of the matching kind in the same
   document.
4. Route IDs are unique.
5. In each threshold, `review_above` ≤ `reject_above` when both are set.
6. Route `limits` name only networks the route covers (any network when
   `networks` is `["*"]`) and only assets the route covers on that network
   (directly, through a referenced set, or through `*`).
7. `allow_clawback` and `asset_sources` appear together; `self` is not
   allowed in `asset_sources` or in a clawback route's destinations.
8. `allow_close` is not combined with wildcard `destinations`.
9. `blocked_destinations` holds addresses only (no sets, `self`, or `*`).
10. `rekey_policy` references only flat address sets; rekey edges are not
    network-scoped.

Errors report the JSON Pointer of the failing value, for example
`/transfer_policy/routes/1/limits/mainnet/asa:31566704/reject_above`.

### Advisories

A valid document can still have a shape that surprises, because one policy
layer cannot weaken another. `check` and `apply` report these as warnings
(`internal/policy/advisory.go`); they never block an apply:

| Rule ID | Condition |
|---------|-----------|
| `policy_overlap:reject_close_remainder:route_close_allow` | `reject_close_remainder` is true and a route sets `allow_close` |
| `policy_overlap:reject_asset_close:route_close_allow` | `reject_asset_close` is true and a route sets `allow_close` |
| `policy_overlap:reject_clawback:route_clawback_allow` | `reject_clawback` is true and a route sets `allow_clawback` |
| `policy_overlap:transaction_types:route_unreachable` | The document has routes but `transaction_types` rejects `pay` or `axfer`, so no route can match that type |
| `policy_fee:cosigner_routes_without_fee_cap` | A cosigner document has routes and `max_fee_microalgos` is `"0"`; a cosigner has no warning review, so a permitted self-payment could carry any fee |

## Embedded Defaults

The shipped defaults live at `internal/policy/defaults/signer.json` and
`internal/policy/defaults/cosigner.json` (`go:embed`, `policy.EmbeddedDefault`)
and are decoded in a test so they can never drift from the format. They seed
`default.json` when a store is created and are what
`apadmin policy template --embedded` prints.

The shipped signer default rejects a foreign rekey, sends warning-level
findings to review, routes self-transfers and opt-ins, and leaves every other
transfer and every non-transfer type to the operator default, so a fresh
signer key behaves like most signers: it signs under `user_auto_approve: true`
and prompts under `false`, except that a foreign rekey is always rejected and
a rekey, close-out, clawback, app update or delete, asset reconfigure, asset
freeze, or high fee always prompts.

```json
{
  "format": "aplane.policy.v1",
  "role": "signer",
  "key": "default",
  "reject_foreign_rekey": true,
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "always_review_warnings": true,
  "auto_approve_self_noop_transfer": false,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "allow" },
  "transfer_policy": {
    "on_no_route": "operator_default",
    "close_on_no_route": "operator_default",
    "clawback_on_no_route": "operator_default",
    "routes": [
      {
        "id": "self-transfer",
        "description": "Any account may send any asset to itself",
        "networks": ["*"],
        "sources": ["*"],
        "assets": ["*"],
        "destinations": ["self"]
      }
    ]
  }
}
```

The cosigner default rejects everything: a cosigner has no operator to ask
and no warning review, so a key signs nothing until its operator writes every
allowance, fee ceiling included.

```json
{
  "format": "aplane.policy.v1",
  "role": "cosigner",
  "key": "default",
  "reject_close_remainder": false,
  "reject_asset_close": false,
  "reject_clawback": false,
  "reject_rekey": true,
  "max_fee_microalgos": "0",
  "transaction_types": { "*": "reject" },
  "transfer_policy": {
    "routes": []
  }
}
```

Neither default carries a description, which would outlive the starting
state. The integration test environment (`test/setup-test-env.sh`) replaces
the signer default with a permissive one (every `reject_*` false,
`always_review_warnings` false, `*` allowed, one `*` to `*` route, route
misses `operator_default`) so test keys need no per-key documents.

## Storage

Policy is product-scoped and stored in the selected generation under the
retained product namespace. The layout is the same on both node roles; the
root `node.yaml` role decides which documents are accepted:

```text
identities/default/generations/<selected-generation>/default.json
identities/default/generations/<selected-generation>/default.json.hmac
identities/default/generations/<selected-generation>/policies/<selector>.json
identities/default/generations/<selected-generation>/policies/<selector>.json.hmac
identities/default/generations/<selected-generation>/deleted/policies/<selector>.json[.hmac]
```

`<selector>` is an Algorand address on a signer node and a Witness Key ID on a
cosigner node. `deleted/policies/` holds the archived pair of a deleted key.
Every generation holds `default.json`; a load without it fails closed. A new
store's `default.json` is seeded from the embedded default for
the node role at `apstore initialize` and `apstore rebuild`
(`policy.WriteEmbeddedDefault`); see [Embedded Defaults](#embedded-defaults).
The default can be replaced but never removed.

`policies/` may hold only `<selector>.json` pairs; the selector is checked by
shape (`storepaths.ValidatePolicySelector`: a 58-character address or a
52-character Witness Key ID) before the decoder checks the checksum and the
role. A document for a key the node does not hold is accepted, so policy can
be installed before its key, and reported by `check` and `status`.

Product runtime settings such as `user_auto_approve`,
`lock_on_disconnect`, and `passphrase_timeout` live separately in:

```text
identities/default/config.yaml
```

`user_auto_approve` is shown in `apadmin` as `User Auto-Approve`. It is not a
policy rule; it is the user/operator default used only when policy has no
matching verdict.

### Sidecars

Each `.hmac` sidecar authenticates the exact document bytes with the
`internal/integritysidecar` format, using a key derived from the product
store's current term key. A missing or mismatched sidecar, or a document that
fails decoding or semantic validation, fails the whole policy load: the node
refuses to unlock or reload rather than loading defaults or skipping the
document. On reload failure, the previous in-memory policy remains active.

The sidecar authenticates only the document bytes. The HMAC is not bound to a
file name, so every document carries a signed `key` field that must equal the
file it is stored as: `default` for `default.json`, the selector for
`policies/<selector>.json`. A mismatch is rejected.

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
decision.

### Key Lifecycle

- Deleting a key (`storemut.DeleteKey`) archives its policy pair under
  `deleted/policies/` in the same generation, on both roles.
- A key's document travels with it in backups (`policies/<selector>.apb`) and
  is installed with it on restore; the default is never in a backup (see
  [Backup and Restore](#backup-and-restore)).
- Changing several documents lands in one generation commit.

## Storage and Acceptance

- Every apply or removal, online or rescue, verifies the active policy and
  mints a new generation with manifest operation `policy-apply` through
  `genstore.Mint`. An apply that
  leaves the policy set unchanged commits nothing. Each committed apply
  leaves the outgoing generation retained until explicit generation pruning.
- `default.json` and `default.json.hmac` are generation authority files,
  pinned in the generation manifest and seal. `policies/` and
  `deleted/policies/` are generation leaf namespaces.
- During initial locked startup, a policy integrity failure prevents the
  admin-auth unlock from completing and is reported as `auth_result` with
  `code:"unlock_failed"`.
- Online changes require an unlocked signer store and reload the runtime
  from the committed generation.
- Every digest covers the exact stored bytes; there is no canonical
  re-serialization. `policy_set_sha256` is the lowercase hex SHA-256 over the
  sorted lines `<key> <document sha256>\n`, one per document, where `<key>`
  is `default` or the selector. `apply_policy` requires it as the
  optimistic-concurrency base.
- A node holds at most 8,192 per-key documents (`policyapply.MaxPolicies`);
  a change past the cap is rejected with `policy_set_too_large` before
  anything is written. The default does not count.
- Passphrase rotation re-signs every policy sidecar: the default, every
  per-key document, and the archived documents under `deleted/policies/`.
  Restore rollback restores `keys/`, `keytypes/`, and `policies/` (re-signed
  under the current term) and keeps the outgoing default.
- Store validation (`storevalidate`) loads and verifies the policy and verifies archived policy
  sidecars.

Acceptance of a candidate change (`policyapply.Candidate`, shared by the
daemon, rescue, and `apstore`):

1. The request names at least one document or removal. `default` cannot be
   removed; a removed key must have a document of its own; a key may appear
   only once across documents and removals; every non-default key is a
   well-formed selector.
2. The resulting set holds a default and at most `MaxPolicies` per-key
   documents.
3. Each submitted document decodes for the node role and its key
   ([Parsing](#parsing), [Fields](#fields), [Semantic Rules](#semantic-rules)).
   Decode errors are returned as problems with the document key and the
   JSON Pointer of the failing value.
4. The resulting set compiles.
5. `check` additionally reports warnings, which never block an apply:
   advisories for each submitted document ([Advisories](#advisories)) and
   key coverage, where a document for a key the node does not hold is
   reported as "policy is for a key this node does not hold". A key on the
   default is covered, not a gap.

## Admin Surface

`apadmin policy` operates against the live signer through admin IPC. Policy
documents are written outside the node, reviewed with
`apadmin policy check FILE...`, and installed with `apadmin policy apply
FILE...` (or `apadmin policy rescue check|apply` while the daemon is stopped).
There is no policy editor in the node and no scalar policy-settings IPC.

The admin protocol and `internal/signerapp/admin` expose four policy messages:
`get_policy`, `get_policy_document`, `check_policy`, and `apply_policy`. The
node role decides which documents a request may carry; there is no target
selector. `get_policy` returns a summary: each document's key, SHA-256, size,
and applied time (the default first), each held key's coverage (`own`,
`default`, or `key_not_held` for a stored document whose key is not held),
and `policy_set_sha256`, a digest over the whole document set.
`get_policy_document` returns one document's exact bytes by key (`default` or
a selector). `check_policy` validates candidate documents and removals
without writing and returns errors and warnings. `apply_policy` requires
`expected_policy_set_sha256` for optimistic concurrency, validates the
resulting document set, and commits it as one new generation (operation
`policy-apply`); the runtime publishes the new policy immediately. An apply
adds or replaces each listed document (each names its key), deletes the keys
in `remove`, and keeps every other document; `default` can be replaced but
not removed. Every digest covers exact document bytes. Message payloads are
in [ARCH_ADMIN.md](ARCH_ADMIN.md#policy-messages); generation behavior is
in [ARCH_STORE.md](ARCH_STORE.md#generations).

`apadmin policy` requires a verb; the same verbs run online and under
`apadmin policy rescue` against a stopped store:

| Verb | Behavior |
|------|----------|
| `status` | Print `<role> policy`, the default's digest, size, and applied time, then `keys (<n>)` with each held key as `own policy` (with its document summary) or `default`, each stored document for a key not held as `key not held`, and `policy_set_sha256` |
| `export [--key K]` | Write one stored document exactly as stored: the default, or key `K`'s own document |
| `check FILE...\|-` | Validate documents against the node; print errors and warnings |
| `diff FILE...\|-` | Describe how the files differ from the policy that governs each key now, without writing |
| `apply [--yes] FILE...\|-` | Run `check`, stop on errors, print the diff, confirm, then apply against the current `policy_set_sha256` |
| `remove [--yes] K...` | Run `check`, stop on errors, print the diff, confirm, then delete keys' own documents; the keys follow the default. `default` is refused |
| `template [--key K]` | Write the node's current default as the starting document for key `K`, or annotated as the default itself |
| `template --embedded signer\|cosigner [--key K]` | Write the shipped default for that role instead; the only form that needs no node and no passphrase |

Each file is one document and names its key in its `key` field; several
files apply in one commit. Diffs are effective: `diff` compares decoded
documents (`policy.DiffPolicyV1`, through `policyreview.DiffCandidate` and
`DiffRemoval`), so formatting and key order never appear as changes, and each
key's candidate is compared with the document that governs the key now. A
new per-key document is compared with the default the key followed (summary
"the key gets a policy of its own; compared with the node default it
followed"); a replacement with the key's own document; a removal with the
default the key will follow after the change, which is the submitted default
when the same apply replaces it ("policy of its own removed; the key follows
the node default"). A change to the default also names the held keys it
reaches ("governs N held key(s): ..." or "governs no held key; every held
key has a policy of its own"). Each change names a path (routes by id) and
is marked `tightened`, `loosened`, or `changed`: raising or removing a
threshold, clearing a `reject_*` flag, moving a type toward `allow`, adding
a route, route term, or member of a set a route uses, relaxing a route-miss
action, or removing a blocked destination loosens; the reverse tightens. A
fee cap of `"0"` is compared as no cap, matching enforcement. Address sets
are compared on the members they cover on each network, so moving between
flat and per-network forms is described by what changes where. Removing a
restrictive per-key document can loosen (on a signer node it can enable
silent outbound signing under auto-approve); the preview shows that as
loosened lines against the default, never as a bare "policy removed".
`apply` and `remove` ask for confirmation on the controlling terminal, never
stdin; `--yes` skips it. Output names the committed generation or reports
`policy unchanged`. `apply` skips the commit only when every submitted
document decodes identical to the active one; a document that differs only
in term order is still applied.

Online verbs authenticate through admin IPC and unlock a locked identity with
the authenticated passphrase before policy access; this applies to read-only
verbs too.

Templates: `apadmin policy template [--key K]` prints the node's current
`default.json` (online, or from the stopped store under `rescue`) with `key`
set to `K`, or annotated as the default itself when `--key` is omitted. A
key that gets a document of its own therefore starts from exactly what it was
already doing. `apadmin policy template --embedded signer|cosigner [--key K]`
prints the shipped default instead and is the only form that needs no node,
store, or passphrase; the online and rescue forms fail rather than fall back
to it, so a customized node default is never silently replaced by the shipped
one. Each template carries a header comment; stripped of it, a template
decodes equal to the document it stands for (`policyreview.Template`,
`policyreview.EmbeddedTemplate`).

`apadmin policy rescue VERB` runs the same verbs directly against the store with
the same rules as the daemon (the shared `internal/signerapp/policyapply`
package). It reads root `node.yaml` for the role, verifies the policy
sidecars with the store passphrase, and rejects `--ipc-path`. Read verbs hold
the shared store lock; `apply` and `remove` hold the exclusive store mutation
lock and therefore require a stopped daemon. On a systemd store, offline use
requires root. A root-run rescue change of a production store restores the
owner recorded in root-controlled `install/service-principal.json` before
returning. Local
non-interactive rescue may use `APSIGNER_PASSPHRASE`; remote policy commands
require the controlling terminal.

For deliberately hand-placed documents in a stopped store, `apstore policy
check` validates every stored document (the default and each per-key file)
without verifying sidecars, warns about missing sidecars, and warns about
documents for keys not held; `apstore policy sign` validates and re-signs every sidecar in the selected
generation;
`apstore policy verify` verifies the sidecars with the store passphrase and
compiles the documents. `apstore policy sign` is an offline store mutation
and requires the store mutation lock. Hand-placed documents take effect only
after the next successful reload, unlock, or restart.

The apadmin TUI Policies view lists the default first (labelled "node
default (governs every key without its own policy)"), then every held key as
"own policy" or "default", then stored documents for keys not held. Enter
opens a document; `e` edits it (a key on the default opens the editor on the
default with the key filled in, marked "No policy of its own yet"); `a`
loads a file; review shows the effective diff; `y` applies.

## Backup and Restore

A key's own policy travels with the key, on both roles. A backup of a key
that has a document of its own carries `policies/<selector>.apb`: the exact v1
document, encrypted under the export passphrase and listed in the sealed
manifest. Restore validates it against the key and installs it with a
sidecar signed by the destination store, in the same generation commit as
the credential:

| Destination | Archive | Result |
|---|---|---|
| no document for the key | document | installed |
| the same document | same | nothing to do |
| a different document | document | conflict; `replace_existing` replaces it |
| a document | none | the destination's document is kept |

A restored key without an archived or existing document follows the
destination's default: on a cosigner node that is deny-all, so the key
rejects every request until a document is applied; on a signer node it is the
shipped permissive default unless the operator changed it. Restore rollback
removes the per-key documents restore installed along with its keys.

Backups carry no `default.json`, approval setting, network mapping, or other
operational configuration: a restored key with no document of its own runs
under the destination's current default, which the operator owns. Restore
requires the admin authorization action `identity.restore`.

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
architecture overview is in [ARCH_GUARDED.md](ARCH_GUARDED.md);
compatibility-bearing audit details live in
[ARCH_SECURITY.md](ARCH_SECURITY.md#audit-logger).

## Changes From `policy.yaml`

| `policy.yaml` | v1 |
|---------------|----|
| YAML | JSON with `format`, `role`, and `key` |
| `review_algo_payments`, `max_algo_payments`, `review_asa_amounts`, `max_asa_amounts` | One `limits` field |
| Route `limits` + `limits_by_network`, with a one-asset-per-network rule | Route `limits` keyed by network and asset |
| `transfer_policy.address_sets` / `asset_sets` | Top-level `address_sets` / `asset_sets` |
| `transfer_policy.schema_version` | Removed; `format` versions the document |
| Route `close: {allow}` / `clawback: {allow}` | `allow_close` / `allow_clawback` |
| Route `enabled` | Removed; omit a route to disable it |
| `transfer_policy.enabled` | Removed; a document always routes |
| Bare numeric ASA IDs | `asa:<id>` only |
| Cosigner `on_no_route` / `close_on_no_route` / `clawback_on_no_route` (must be `reject`) | Removed; always reject |
| Absent fields resolved through product defaults | Every verdict-bearing field required; nothing implied |
| One document per node with `key_overrides` by address or Witness Key ID | One node default plus zero or one complete document per key; no inheritance |
| Implicit transaction-type behavior | `transaction_types` with a required `*` entry |
| Sidecar `policy_mtime_ns` | Removed (already gone) |

## Source Files

Implementation source of truth:

- `internal/policy/config.go`: effective (compiled) policy model, including
  the per-type verdict map.
- `internal/policy/lint.go`: Always Deny transaction checks, type rule first.
- `internal/policy/review.go`: Always Review checks, type rule first.
- `internal/policy/ruleids.go`: stable rule IDs, including
  `TransactionTypeRuleID`.
- `internal/policy/transfer_routing.go`: compiled transfer routing model and
  validation.
- `internal/policy/transfer_routing_eval.go`: direct transfer movement
  extraction and route evaluation.
- `internal/policy/jsontree.go`, `internal/policy/doc_v1.go`,
  `internal/policy/doc_v1_compile.go`: v1 document decoding, role gating,
  semantic validation, and compilation.
- `internal/policy/defaults.go`, `internal/policy/defaults/*.json`: the
  embedded defaults that seed `default.json`.
- `internal/policy/advisory.go`: non-blocking document advisories.
- `internal/policy/diff_v1.go`: decoded-document differ.
- `internal/policy/store_v1.go`: policy document storage, sidecars, archive,
  and the policy-set digest.
- `internal/signerapp/policyruntime`: `NodePolicy` load, compile, and
  `PolicyFor`.
- `internal/signerapp/policyapply`: shared check and generation-commit rules for
  online apply, rescue, and `apstore`.
- `internal/signerapp/policyreview`: templates, comment stripping, and the
  effective per-key diff.
- `internal/signerapp/approvalpolicy/warnings.go`: warning analysis.
- `cmd/apadmin/policy.go`: policy command adapter and local IPC transport selection.
- `internal/signerapp/policycmd`: online and offline-rescue policy workflows.
- `internal/signerapp/signing/cosigner_policy.go`: cosigner key and policy
  selection and evaluation.
- `internal/signerapp/signing/always_review.go`: Always Review evaluation.
- `internal/signerapp/signing/approval.go`: policy resolution per slot,
  approval prompts, and operator default behavior.
- `internal/signerapp/signing/service.go`: phase ordering and the per-request
  `PolicyFor` snapshot.
- `internal/signerapp/admin/policy.go`: admin policy read, check, and apply
  service.
