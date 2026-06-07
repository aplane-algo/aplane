# Policy Architecture

This document describes the policy system. It is the current-state companion to
[ARCH_CONTRACTS.md](ARCH_CONTRACTS.md).

## Status

This document covers two domains:

- the **client-signing** policy implemented today: tier-based verdicts over
  signer-controlled transactions with an operator default fallback,
- the **attestation** policy implemented for attestor component signing:
  policy-as-authorization for `/sign/component`, no operator default, no
  review verdict.

Both domains share one YAML grammar, one parser, one fixture corpus, and one
verdict-model description. Fields that apply to only one domain are tagged
inline.

## Scope

Signer policy decides what `apsigner` may produce a signature for after
request planning has identified the signable units. For client signing, the
unit is a signer-controlled transaction; for attestation, the unit is a
target transaction in `/sign/component`. Policy is separate from:

- authentication and authorization, which decide who may ask for signing,
- key ownership and unlock state, which decide whether signing keys are usable,
- the operator default, which decides whether unmatched client-signing requests
  need manual review. Attestation has no operator default.

## Storage

Policy is identity-scoped and stored in two documents:

```text
identities/<identity>/policy.yaml
identities/<identity>/attestation.yaml
```

The signer keeps sibling integrity sidecars:

```text
identities/<identity>/policy.yaml.hmac
identities/<identity>/attestation.yaml.hmac
```

The HMAC covers the exact YAML bytes for its document and uses a key derived
from the identity master key. Sidecar metadata such as signing time, policy
SHA-256, and file mtime is diagnostic; the HMAC is the security check. After
the signed baseline exists, a missing or mismatched sidecar fails closed
instead of loading defaults. On reload failure, the previous in-memory policy
remains active.

The sidecar authenticates only the YAML bytes. Diagnostic metadata fields in the
sidecar can be edited without invalidating the policy HMAC; they are not
security inputs to the verification decision.

Identity-scoped runtime settings such as `user_auto_approve`,
`lock_on_disconnect`, and `passphrase_timeout` live separately in:

```text
identities/<identity>/config.yaml
```

`user_auto_approve` is shown in `apadmin` as `User Auto-Approve`. It is not a
policy rule; it is the user/operator default used only when policy has no
matching verdict.

Signing and attestor component policy are stored as separate signed YAML
documents:

```text
identities/<identity>/policy.yaml
identities/<identity>/policy.yaml.hmac
identities/<identity>/attestation.yaml
identities/<identity>/attestation.yaml.hmac
```

Both sidecars use the policy integrity key derived from the identity master
key. Unlock/reload verifies both documents before publishing runtime state; a
missing, malformed, or mismatched sidecar fails closed.

`policy.yaml` is the client-signing policy. It is a sparse map. Absent fields
resolve through product defaults: `reject_foreign_rekey` defaults to `true`,
while `reject_close_remainder`, `reject_asset_close`, `reject_clawback`,
`always_review_warnings`, and `auto_approve_self_noop_transfer` default to
`false`. An absent `max_fee_microalgos` means no fee ceiling, and absent
transfer-guard maps are empty. `transfer_policy` may be absent entirely; if it
is present, it must satisfy the explicit routing schema below.

`attestation.yaml` is the attestor component policy. It uses the same sparse
field names but is direct: there is no top-level `attestation:` wrapper.
Review-producing fields are invalid in this document, and route misses default
to deterministic `reject` when `transfer_policy.enabled:true`.

The policy loader validates schema and domain constraints independent of the
identity's current key inventory. Validation runs at unlock/reload and at any
admin replacement attempt; failures fail closed with the previous in-memory
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
matching Always Approve rule. Attestation rejects review-producing policy
instead of treating it as a promptable phase.

### Verdict Mapping By Role

The four-tier model is the canonical shape for **client-signing** requests.
**Attestation** is policy-as-authorization with no human in the loop, so its
normal verdict surface has two outcomes (reject or sign). The shared phase
order is still used, but review is not a valid attestation outcome:

| Phase | Client signing | Attestation |
|-------|----------------|-------------|
| Always Deny | Reject | Reject |
| Always Review | Require operator approval | Invalid outcome; fail closed as config error |
| Always Approve | Sign without approval | Sign |
| Operator Default | Per `user_auto_approve` | Not applicable; unmatched attestor requests reject |

The deterministic attestation surface is enforced by keeping review-producing
fields out of `attestation.yaml`. Policy load rejects
`always_review_warnings`, `review_algo_payments`, `review_asa_amounts`,
`transfer_policy.on_no_route: review`, route `review_above`, and equivalent
review-producing behavior in attestor policy. If implementation ever
encounters a review verdict while evaluating an attestor component request,
the request fails closed as a policy configuration error rather than waiting
for a prompt.

`user_auto_approve` is client-signing-only. It lives in
`identities/<identity>/config.yaml` and has no attestation analog.

## Role Domains

Policy has two document domains.

`policy.yaml` is the client-signing document:

```yaml
reject_foreign_rekey: true
max_fee_microalgos: 1000
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes: [...]

client_signing:
  auto_approve_self_noop_transfer: true
  always_review_warnings: true
  review_algo_payments:
    mainnet: 100000000
  # client_signing may nest transfer_policy / amount guards that override
  # top-level client-signing values.
```

`attestation.yaml` is the attestor component policy document:

```yaml
reject_rekey: true
transfer_policy:
  schema_version: 1
  enabled: true
  routes: [...]
  # on_no_route, close_on_no_route, and clawback_on_no_route may be omitted;
  # when enabled, omitted values are interpreted as reject.
```

The accepted top-level keys in `policy.yaml` are the client-signing field set,
`client_signing`, and `key_overrides`. `policy.yaml` rejects `attestation:`
and top-level `reject_rekey`; those belong to `attestation.yaml`.

The accepted top-level keys in `attestation.yaml` are the attestation field
set and `key_overrides`. `attestation.yaml` rejects `client_signing:` and
`attestation:` wrappers. Unknown top-level keys fail validation in both
documents.

Client-signing semantics:

- Top-level client-signing fields apply to normal account signing.
- **`client_signing:`** holds fields whose semantics reference "this signer
  owns the account" (`reject_foreign_rekey`, `auto_approve_self_noop_transfer`)
  or whose verdict only makes sense with an operator above the signer
  (`always_review_warnings`, `review_*` thresholds, route `review_above`,
  `on_no_route: review`). It may also nest its own `transfer_policy:` /
  amount-guard maps that override common values for client-signing evaluation.

Attestation semantics:

- Top-level fields in `attestation.yaml` are the attestor policy.
- `reject_rekey` is valid only here.
- `reject_foreign_rekey`, `always_review_warnings`,
  `auto_approve_self_noop_transfer`, `review_algo_payments`, and
  `review_asa_amounts` are invalid here.
- `transfer_policy` is the positive authorization surface. If enabled, route
  miss behavior is deterministic reject.

Both documents are validated by schema and domain, not by the identity's
current key inventory. An identity can carry `attestation.yaml` before an
attestor key is installed, and it can carry `policy.yaml` even when it is
hosted on an attestor node.

Legacy compatibility: a `policy.yaml` written before role domains existed
places all client-signing-only fields at the top level. The loader treats
top-level `reject_foreign_rekey` and `auto_approve_self_noop_transfer` as
sugar for an implicit `client_signing:` block.
Review-producing fields at the top level (`always_review_warnings`,
`review_*`) are similarly treated as implicit client-signing. Operators
migrating an existing policy can move these fields explicitly under
`client_signing:` without semantic change. A top-level `transfer_policy` that
contains review-producing behavior (`on_no_route: review`, `review_above`,
and similar fields) is valid for client signing, but it is not a complete
attestation allow-list; an attestation request that would need those review
outcomes fails closed unless `attestation.yaml` supplies a
deterministic replacement.

## Runtime Snapshot Semantics

The identity runtime publishes policy updates atomically. Readers see either
the previous policy snapshot or the replacement snapshot; they must not observe
a partially applied policy.

Each signing request captures the effective policy snapshot when its signing
service is constructed. That snapshot governs the request through policy
evaluation, approval waiting, and final signature execution. A later successful
policy reload or `apadmin` whole-file hot replacement applies only to signing
requests that start after the new snapshot is published. In-flight requests are
not re-evaluated or canceled merely because the policy changed while they were
waiting for approval.

## Always Deny

Always Deny rules are hard safety guards. They cannot be approved by an
operator prompt and are evaluated before all other policy or approval phases.

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `reject_foreign_rekey` | client_signing | Reject transactions whose non-zero `RekeyTo` target is not held by the current signer identity |
| `reject_rekey` | attestation | Reject any transaction with non-zero `RekeyTo` |
| `reject_close_remainder` | common | Reject payment transactions with non-zero `CloseRemainderTo` |
| `reject_asset_close` | common | Reject ASA transfers with non-zero `AssetCloseTo` |
| `reject_clawback` | common | Reject ASA clawback transactions using `AssetSender` |
| `max_fee_microalgos` | common | Reject transactions whose raw microAlgo fee exceeds the configured ceiling |
| `max_algo_payments` | common | Per-network raw microAlgo ceilings for ALGO payments |
| `max_asa_amounts` | common | Per-network raw unit ceilings for ASA transfers |
| `transfer_policy` | common | For client signing, produces deny verdicts for blocked destinations, route misses, close/clawback misses, and `reject_above`; for attestation, routing is the positive authorization surface |

`reject_foreign_rekey` evaluates the rekey target against the set of addresses
held by the current signer, which is meaningful only when the signer owns the
sender. `reject_rekey` is the attestor analog and ignores key ownership: any
non-zero `RekeyTo` rejects. The MVP attestation default is `reject_rekey:true`;
allowing attested rekeys requires explicit policy that does not yet exist.

Network-scoped rules derive transaction network identity from `GenesisHash`,
not `GenesisID`. Unknown genesis hashes fail closed when a network-scoped rule
must be evaluated. For attestation, an unknown genesis hash always fails
closed regardless of which rules are configured, because attestation is
authorization rather than a guardrail and cannot fall through to operator
default.

`max_algo_payments` and `max_asa_amounts` are the deny side of transfer guards.
If a matching review threshold is also configured, the deny threshold must be
greater than or equal to the review threshold. This invariant is enforced at
config apply time: a `policy.yaml` that violates it fails to load.
With role domains, the invariant is checked on each effective role policy after
common, role-specific, and key override resolution; it is not a raw
cross-block comparison between unrelated domains.

`transfer_policy` is a YAML-driven route table for direct `pay` and `axfer`
movements. When enabled, it can reject blocked destinations, route misses,
close-out misses according to `close_on_no_route`, clawback misses according to
`clawback_on_no_route`, matched close-out movements without `close.allow:true`,
matched clawback movements without `clawback.allow:true`, and matching
movements above a route's `reject_above` threshold. For client signing, routes
never auto-approve a request; a route match only lets the movement continue
through the remaining policy phases. For attestation, routing is the positive
authorization surface. See [Transfer Routing](#transfer-routing).

## Always Review

Always Review rules force a human approval prompt even when the operator default
is configured to skip review. The whole tier is client-signing-only: the
attestation domain has no operator above the signer, so review-producing
fields are rejected in `attestation.yaml` at policy load time.
Legacy top-level review-producing fields are client-signing-only compatibility
fields. If a review verdict is still reachable while evaluating an attestor
component request, the request fails closed as a policy configuration error.
See [Verdict Mapping By Role](#verdict-mapping-by-role).

Policy fields by domain:

| Field | Domain | Meaning |
|-------|--------|---------|
| `always_review_warnings` | client_signing | Require operator review when warning analysis finds risk markers |
| `review_algo_payments` | client_signing | Per-network raw microAlgo thresholds that require review for ALGO payments |
| `review_asa_amounts` | client_signing | Per-network raw unit thresholds that require review for ASA transfers |
| `transfer_policy.on_no_route: review` | client_signing | Forces ordinary route misses to review for client signing |
| `transfer_policy.close_on_no_route: review` | client_signing | Forces close-out route misses to review for client signing |
| `transfer_policy.clawback_on_no_route: review` | client_signing | Forces clawback route misses to review for client signing |
| `transfer_policy` `review_above` | client_signing | Route-level review threshold |

`review_algo_payments` and `review_asa_amounts` are the review side of transfer
guards. They are evaluated after Always Deny. For example, an ASA transfer above
`review_asa_amounts.testnet["10458941"]` requires approval unless it has already
been rejected by a matching `max_asa_amounts` threshold.

For client signing, unknown genesis hashes trigger a distinct fail-closed rule
that forces review when a configured transfer-guard review threshold cannot be
mapped to a network token. This rule is independent of the configured threshold
values. Attestation rejects unknown genesis hashes when network-scoped policy
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
| `auto_approve_self_noop_transfer` | client_signing | Auto-approve a tightly constrained self no-op transfer |

`auto_approve_self_noop_transfer` is client-signing-only because its "self"
predicate references the signer-owned account. It has no defined meaning for
attestation: an attestor is not the owner of the sender it is authorizing.
The field is rejected at load time in `attestation.yaml`. If an invalid
effective attestor policy is injected in tests or by compatibility code, the
rule simply does not match an attestor request because no signer-owned address
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
does not apply to attestation: an unmatched attestor component request is
Always Deny per [Verdict Mapping By Role](#verdict-mapping-by-role).

The setting is:

```yaml
user_auto_approve: false
```

Location:

```text
identities/<identity>/config.yaml
```

Behavior:

- `user_auto_approve:false`: unmatched client-signing requests require operator review.
- `user_auto_approve:true`: unmatched client-signing requests sign without operator review.
- attestor component requests: ignored; the verdict is reject.

## Transfer Routing

`transfer_policy` is the implemented v1 route table for direct transfer
movements. The same routing engine applies to both client-signing and
attestation evaluation. Client-signing routes live in `policy.yaml`; attestor
component routes live in `attestation.yaml`. Transfer routing is not projected
through admin IPC.

For client signing, a route match means "allowed to continue through the
normal policy phases"; it does not approve signing and never produces an
Always Approve verdict.

For attestation, routing is the positive authorization surface. An attestor
component request is eligible to sign only when all evaluated target
transactions are supported transfer shapes, every extracted target movement is
covered by a matching route, no route or transaction guard produces a deny
verdict, and the effective attestation routing block contains no
review-producing behavior. In other words: for client signing, routing is a
guardrail; for attestation, routing is an allow-list.

Always Deny and deterministic transaction guards run before attestation
allow-list success. A route match cannot rescue a target rejected by rekey,
close-out, clawback, fee, amount, blocked-destination, or unsupported-shape
rules.

In `policy.yaml`, a `transfer_policy:` block may also be nested inside
`client_signing:` to override the top-level client-signing routes. In
`attestation.yaml`, the top-level `transfer_policy:` is the attestor
allow-list. These blocks follow the same schema, validation, and overlay rules
except for attestation route-miss boilerplate. In `attestation.yaml`,
route-miss behavior is not configurable:
`on_no_route`, `close_on_no_route`, and `clawback_on_no_route` may be omitted
and are interpreted as `reject`; if present, the only accepted value is
`reject`. `review_above` under `limits` or `limits_by_network` is rejected.

For client-signing evaluation, an `on_no_route: review` miss produces Always
Review. For attestation evaluation, review or operator-default routing outcomes
are not valid authorization outcomes. Examples include `on_no_route: review`,
`close_on_no_route: operator_default`, and route-level `review_above`. If such
behavior appears in the effective attestation routing block, the attestor
request fails closed as a policy configuration error. Operators can keep review
behavior in `policy.yaml` and provide a deterministic `attestation.yaml`
transfer policy for attestor component signing.

For example, a legacy top-level `transfer_policy` with one deterministic
`A -> B` route and `on_no_route: review` can authorize an attestor request for
`A -> B` if no other guard denies it. A request for `A -> D` fails closed
because the route miss would need a review verdict, which attestation cannot
produce.

For operator examples and troubleshooting, see
[USER_TRANSFER_ROUTING.md](USER_TRANSFER_ROUTING.md).

Routing's shape is deliberately conservative:

- For client signing, it produces only Always Deny or Always Review verdicts.
  A matching route is allow-to-continue, not approval, because fee, rekey,
  close-out, clawback, warning, legacy transfer-guard, and Operator Default
  behavior must still be able to apply.
- For attestation, it is an allow-list: every target movement must be covered
  by a matching route, and any deny verdict rejects the request.
- It denies by absence rather than by general explicit deny routes. In v1,
  operators grant allowed source/asset/destination paths and use `on_no_route`
  to decide what a miss means. The narrow exception is `blocked_destinations`,
  a global concrete-address deny list that runs before route matching. This
  avoids source-scoped and route-local deny/allow precedence rules while
  preserving a clear migration path through `on_no_route: review`.
- It coexists with legacy transfer guards. Existing review/deny thresholds keep
  their behavior and audit rule IDs, and routes cannot weaken them.
- It coexists with legacy close/clawback reject booleans. Route-level
  `close.allow:true` and `clawback.allow:true` permit matching movements only
  within routing; they do not override `reject_close_remainder`,
  `reject_asset_close`, or `reject_clawback`. Stored-policy advisory checks
  flag this overlap as a warning rather than rejecting the policy.
- It rejects mixed-unit limits. ALGO microAlgos and ASA raw units are not
  comparable, so a route with amount limits must resolve to one asset unit per
  network.

Routing is disabled unless `transfer_policy.enabled:true`. If a
`transfer_policy` block is present, `schema_version: 1` and an explicit
`enabled: true` or `enabled: false` are required. Unknown fields under
`transfer_policy` or route entries fail validation. For top-level and
`client_signing.transfer_policy` blocks, `on_no_route` must be explicit when
routing is enabled unless the block is a key override that inherits an
identity-wide `on_no_route` value. `attestation.yaml` omits that choice and
treats route misses as `reject`. For top-level and
`client_signing.transfer_policy` blocks, `close_on_no_route` and
`clawback_on_no_route` default to `reject` and may be set explicitly to
document or override the stricter close-out and clawback route-miss behavior.
For `attestation.yaml` transfer policy, those values are implicit `reject` as
described above.

Top-level routing schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `schema_version` | yes | Routing schema version; v1 only |
| `enabled` | yes | Enables routing when `true`; disables routing when `false` |
| `on_no_route` | when enabled | Route-miss verdict: `reject`, `review`, or `operator_default` |
| `close_on_no_route` | no | Close-out route-miss verdict; defaults to `reject` |
| `clawback_on_no_route` | no | Clawback route-miss verdict; defaults to `reject` |
| `blocked_destinations` | no | Global concrete-address deny list evaluated before route matching |
| `address_sets` | no | Named address lists or network-scoped address lists |
| `asset_sets` | no | Named network-scoped ASA ID lists |
| `routes` | no | Ordered route definitions; order does not grant priority |

Route schema:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable route identifier used in policy rule IDs |
| `description` | no | Operator-facing note |
| `enabled` | no | Defaults to `true`; disabled routes are ignored |
| `networks` | yes | Either `["*"]` or concrete network context tokens |
| `sources` | yes | Sender terms: address, `@address_set`, or `*` |
| `asset_sources` | clawback only | Allowed ASA `AssetSender` terms; requires `clawback.allow:true` |
| `assets` | yes | Asset terms: `algo`, ASA ID, `asa:<id>`, `@asset_set`, or `*` |
| `destinations` | yes | Receiver terms: address, `@address_set`, `self`, or `*` |
| `limits.review_above` | no | Always Review when amount is strictly greater than this raw threshold |
| `limits.reject_above` | no | Always Deny when amount is strictly greater than this raw threshold |
| `limits_by_network` | no | Per-network threshold overrides |
| `close.allow` | no | Allows matching ALGO/ASA close-out movements; defaults to false |
| `clawback.allow` | no | Allows matching ASA clawback movements; defaults to false |

Route IDs must match `^[a-z0-9][a-z0-9_-]*$`. Network names are APlane network
context tokens as defined in [ARCH_NETWORKS.md](ARCH_NETWORKS.md). A route's
`networks` field may be exactly `["*"]` or a list of concrete tokens, but not a
mix of `*` and concrete tokens.

Address sets accept either a flat list, which applies on every network, or a
map keyed by network context token. `*` is not a valid network key inside an
address set; use the flat-list shape for all-network membership. Asset sets
are maps from network context token to ASA IDs; they do not accept a flat-list
shape because ASA IDs are network-local.

`blocked_destinations` is a flat list of concrete Algorand addresses. It does
not accept `self`, `*`, or `@address_set` terms. The list is global in v1:
it is not source-scoped, asset-scoped, or network-scoped. A key override
inherits the identity-wide blocked list and may add addresses, but it cannot
remove identity-wide blocked destinations.

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
`clawback` are the supported attestation transfer-movement surface in MVP; a
target transaction must extract at least one of these movements to be eligible
for attestor-role component signing.

For client signing, other transaction types produce no routing movement and
continue through the remaining policy phases. For attestation MVP, target
transactions that produce no supported transfer movement are rejected because
there is no route coverage that can authorize them. Passthrough, foreign, and
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
`transfer_policy:unknown_genesis_hash` at the tier selected by `on_no_route`:
Always Deny for `reject`, Always Review for `review`, and no routing verdict
for `operator_default`.

Verdict production for each movement:

1. Routing sits out when `transfer_policy` is absent, disabled, or the movement
   is routing-exempt.
2. If the movement kind is covered by `blocked_destinations` and the movement
   destination is blocked, Always Deny.
3. Matching routes are collected by network, source, asset, destination, and,
   for clawback only, asset source.
4. If no route matches a close-out movement, apply `close_on_no_route`.
5. If no route matches a clawback movement, apply `clawback_on_no_route`.
6. If no route matches any other movement, apply `on_no_route`.
7. A close-out movement with matching routes is Always Deny unless at least one
   matching route has `close.allow:true`.
8. A clawback movement with matching routes is Always Deny unless at least one
   matching route has `clawback.allow:true`.
9. If the amount is known and any matching route has `reject_above`, the lowest
   effective reject threshold wins; amounts strictly greater than that value
   are Always Deny.
10. If the amount is known and any matching route has `review_above`, the lowest
   effective review threshold wins; amounts strictly greater than that value
   are Always Review.
11. Otherwise, client-signing routing produces no verdict and the request
   continues to warning review, explicit auto-approval, or Operator Default.
   For attestation routing, a target movement that reaches this step is
   covered by policy; if every target movement is covered and no deny guard
   matched, the transfer-policy portion of attestation authorization succeeds.

`limits_by_network` overrides global `limits` for that network. If both review
and reject thresholds are set, `reject_above` must be greater than or equal to
`review_above`. Amounts are raw on-chain units: microAlgos for ALGO and raw
ASA units for ASAs. A route with active amount limits must resolve to at most
one asset unit per network; wildcard assets and mixed ALGO/ASA units are
invalid with limits.

The exact self no-op shape used by `auto_approve_self_noop_transfer`, including
signer-generated LogicSig-budget dummy transactions, is routing-exempt. Routing
exemption suppresses all routing verdicts for that shape. Non-routing guards
such as warning analysis, fee checks, rekey/close/clawback guards, and the
self no-op auto-approval predicate still apply according to their own rules.
For attestation, the self no-op predicate never fires because it requires
signer-owned address context.

Key override routing blocks are sparse overlays, except `enabled` must be
explicit in every `transfer_policy` block. Unset `on_no_route`,
`close_on_no_route`, `clawback_on_no_route`, `blocked_destinations`,
`address_sets`, and `asset_sets` inherit from the
identity-wide effective policy. Override `blocked_destinations` are unioned with
the inherited blocked list. Override address and asset sets add to or replace
inherited set names. Routes inherit unless the override explicitly provides a
`routes` field, in which case the override's route list replaces the inherited
route list for that key.

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
`review_above` rule IDs are client-signing-only. Attestation can emit
blocked-destination, route-miss, close/clawback rejection, unknown-genesis, and
`reject_above` IDs, but review-producing route outcomes are invalid for
attestor component requests.

Attestor component policy rule IDs:

- `attestation_policy:missing`
- `attestation_policy:transfer_policy_required`
- `attestation_policy:deterministic_routing_required`
- `attestation_policy:non_transfer`
- `attestation_policy:reject_rekey`

These rule IDs are emitted when the attestor role has no effective
`attestation.yaml` policy, lacks an enabled positive transfer policy, has
route-miss behavior that is not deterministic `reject`, is asked to attest a
target with no supported transfer movement, or sees a non-zero `RekeyTo`.

## Key Overrides

Both `policy.yaml` and `attestation.yaml` may contain `key_overrides`, a map
from concrete signing authority selector to sparse policy blocks. In
`policy.yaml`, selectors are Algorand auth addresses for client signing. In
`attestation.yaml`, selectors are `a_...` attestor component-key selectors.

During normal transaction signing, the effective policy is selected by the
`auth_address` key that will sign, not by transaction sender. This matters for
rekeyed accounts: the auth address controls the override. During attestor
component signing, the effective policy is selected by the request
`component_key` selector.

At the stored-policy level, overrides are sparse: unset fields inherit from the
identity-wide policy. Nested overrides are rejected. If an override includes a
`transfer_policy` block, that block still requires `schema_version` and
explicit `enabled`; the remaining transfer routing fields use the overlay rules
described in [Transfer Routing](#transfer-routing).

If no matching selector exists, the identity-wide effective policy for that
document applies. Override blocks in `attestation.yaml` are direct sparse
attestor policy blocks and must satisfy the same validation as the
identity-wide attestation document: no review-producing route outcomes.

## Transaction Scope

For client signing, Always Deny, Always Review, and Always Approve rules
evaluate signer-controlled request slots only. Passthrough and foreign slots
are not signed by this signer, so they are not evaluated by this signer's
transaction-level policy. They still participate in request planning, group
context, warning display, and approval rendering.

For attestation, the evaluated slots are the `target_indices` of a
`/sign/component` request. The attestor identity does not own the sender
account; "target" means "transaction this attestor is being asked to attest"
rather than "transaction signed by a key this identity holds." Non-target
group members (including passthrough slots prepared by the user signer and
foreign slots) participate in group context, warning display, and the
operator-facing approval description, but they do not receive their own
attestor policy verdict.

Groups receive group-level approval. A grouped request does not fan out into
separate per-transaction human approvals. For attestation this is trivially
true because no human approval is involved.

## Admin Surface

`apadmin` exposes a viewer for the active signer-owned stored policy snapshot
and one live mutation: wholesale replacement from a local YAML file. It is not a
field editor and it does not merge policy fragments. The replacement path
requires an unlocked identity, verifies the current sidecar, validates the
submitted YAML with the signer runtime compiler, writes the exact submitted
bytes plus a fresh sidecar, and updates the active runtime policy immediately.
Guided policy edits remain centered on `appolicy`, the local offline policy
editor. This avoids maintaining two mutable operator-facing field-editing
models while transfer routing becomes the canonical configuration surface.

The admin protocol and `internal/signerapp/admin` still retain policy
read/write messages for compatibility and existing service boundaries, plus
`get_policy_snapshot` for live inspection and `replace_policy` for deliberate
whole-file hot replacement. New guided field-editing UI work should target
`appolicy` rather than adding route editors back to `apadmin`.

Client-signing `transfer_policy` is persisted in `policy.yaml`; attestor
component `transfer_policy` is persisted in `attestation.yaml`. Both are
validated by the policy load path and by `apstore policy check/sign/verify`.
`appolicy` and apadmin whole-file replacement currently target `policy.yaml`.
Transfer policy is not projected through the mutable admin IPC policy settings
payload and has no guided `apadmin` editor; the apadmin viewer renders it from
the active signing-policy snapshot.

`appolicy` is the local offline policy editor. In production mode it loads the
identity policy, verifies the HMAC sidecar with the store passphrase, validates
changes through the same runtime compiler as `apsigner`, and applies the draft
to production by saving `policy.yaml` plus a fresh sidecar while holding the
store mutation lock. When opened with a standalone YAML file, it validates the
file without unlocking the production store; applying that file-backed draft to
production is the operation that asks for the passphrase. The TUI exposes
common policy fields as effective values with a source column, such as
`default`, `explicit`, or `absent`, rather than showing YAML-null markers as
values. Values that match the product default can still be omitted from saved
YAML. For common and client-signing transfer policies, transfer settings edit
the required binary `transfer_policy.enabled` switch and the route-miss
fallback fields. Guard, transfer-settings, and asset-set field editors
validate and commit successful edits into the in-memory draft as each field
editor closes; applying the draft to production remains a separate `a` action.

A normal transfer guard is a UI projection of adjacent stored routes with the
same derived guard name and network/source/destination/close shape. Group-level
fields edit the shared shape: guard name, description, enabled, networks,
sources, destinations, and close allowance. The route row table edits one real
route per asset row: asset term and optional review/reject thresholds. Appolicy
derives stored route IDs as `<guard>_<asset>`, with asset-set references using
the set name without `@`. Existing route IDs that do not follow that generated
convention are preserved on no-op guard edits because route IDs are persistent
audit identifiers; changing the guard name or asset row intentionally writes
the generated convention.
The Transfer Guards screen also exposes the global `blocked_destinations` list
and owns an Asset Sets editor for the `asset_sets` map; route asset cells
accept bare set names and store them as `@name` in YAML. New transfer policies
and existing transfer policies with no asset sets are seeded with a `usdc` set
from APlane's built-in mainnet/testnet ASA metadata when the Asset Sets editor
opens. Thresholds are still stored in raw YAML units, but appolicy edits ALGO,
concrete ASA, and eligible single-asset-per-network asset-set thresholds in
display units and uses signer-side ASA metadata to convert ASA values.
Multi-network asset-set guard rows are written as uniform `limits_by_network`
entries.
Advanced routing structures that are not yet surfaced in the guard editor
still round-trip through YAML and can be edited directly with
`apstore policy check/sign/verify`. For non-interactive use,
`APPOLICY_PASSPHRASE` is checked before `APSIGNER_PASSPHRASE`.
The `client_signing:` block follows the same rule: until guided role-aware
editing lands in `appolicy`, it is preserved through YAML round-trip and edited
directly through checked/signed YAML. `appolicy` edits `policy.yaml`; direct
`attestation.yaml` edits are checked and signed with
`appolicy --save-attestation` or `apstore policy`.
`appolicy --sha256` verifies the sidecar and prints the SHA-256 digest of the
exact trusted `policy.yaml` bytes. `appolicy --yaml` verifies the sidecar and
emits those bytes to stdout. `appolicy --save-policy` reads exact replacement
signing-policy YAML bytes from stdin, parses and runtime-validates them, and
writes `policy.yaml` plus a fresh sidecar while holding the same lock.
`appolicy --save-attestation` performs the same exact-byte replacement flow for
direct `attestation.yaml`. The older `appolicy --save` flag remains a
compatibility alias for `--save-policy`.
`appolicy --to-attestation` parses and runtime-validates a signing
`policy.yaml`, projects the deterministic "could allow" envelope into direct
`attestation.yaml`, and prints the result to stdout. The projection preserves
hard-reject bounds and transfer routes, removes review-only route thresholds,
and fails closed for route-miss `review` or `operator_default` behavior because
attestor policy has no human-review verdict.
With a positional YAML file, `--check`, `--yaml`, and `--sha256` parse and
runtime-validate the file without reading the production sidecar or requesting
the store passphrase.
Inside the TUI, `a` applies the current in-memory draft to production. `w`
exports the current draft to an operator-selected YAML file only; it does not
write a sidecar, update the signer store, or mark the draft clean.

The signer retains compatibility support for authenticated admin IPC policy
changes. The identity must be unlocked so the signer can verify the current
policy and write a fresh sidecar. `apadmin` exposes only live snapshot viewing
and whole-file replacement, not direct field editing. Its policy viewer displays
the policy currently held by the signer runtime.
For deliberate direct YAML edits, use `apstore policy check`, review the file,
then run `apstore policy sign`; `apstore policy verify` checks the sidecar with
the store passphrase. `apstore policy sign` is an offline store mutation and
requires the store mutation lock, so direct YAML edits are normally signed while
`apsigner` is stopped or before starting it. Direct YAML edits take effect only
after the next successful reload, unlock, or restart.

## Backup and Restore

Managed backups include a policy snapshot:

```text
policy/policy.yaml
policy/policy.yaml.hmac
policy/attestation.yaml
policy/attestation.yaml.hmac
```

The backup path verifies the live policy before copying that snapshot. Restore
paths do not install policy files automatically: `apconsole` admin restore and
`apstore restore apply` restore keys and required key-type/template state only.

The archived sidecars are source-store provenance material, not destination
sidecars. If an operator deliberately restores archived policy YAML, the
restored YAML must be reviewed, installed explicitly while the destination
store is not being mutated by the signer, re-signed on the destination store
with `apstore policy sign`, and then loaded by a signer reload, unlock, or
restart. Existing destination policy files must not be overwritten implicitly.

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

Attestor component signing uses the same policy rule identifiers for decoded
transaction facts. In the current MVP, attestor component approvals and policy
rejections are recorded through existing `SIGN_APPROVED`/`SIGN_REJECTED` audit
events with the component selector in `txn_auth`, the decoded sender in
`txn_sender`, and the policy rule in `policy_rule_id` when applicable. Richer
component-specific audit events are deferred in
[ARCH_ATTESTOR_SPEC.md §17](ARCH_ATTESTOR_SPEC.md#17-audit).

## Source Files

Implementation source of truth:

- `internal/policy/config.go`: effective and stored policy model.
- `internal/policy/lint.go`: Always Deny transaction checks.
- `internal/policy/review.go`: Always Review transfer guard checks.
- `internal/policy/transfer_routing.go`: transfer routing YAML schema,
  compilation, and validation.
- `internal/policy/transfer_routing_eval.go`: direct transfer movement
  extraction and route evaluation.
- `cmd/appolicy`: offline policy checker/editor binary.
- `internal/policyeditor`: offline policy load, validate, save, and lock
  handling for `appolicy`.
- `internal/policytui`: terminal UI model for offline policy editing.
- `internal/signerapp/signing/always_review.go`: Always Review evaluation.
- `internal/signerapp/signing/approval.go`: approval prompts and operator default behavior.
- `internal/signerapp/signing/service.go`: phase ordering.
- `internal/signerapp/admin/service.go`: compatibility admin policy read/write service.
