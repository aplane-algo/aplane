# Formal Policy Model

> Status: precise English model, not machine-checked.
> This document formalizes the current client-signing policy verdict semantics
> used by APlane after transaction planning.
> Invariant status (implemented / intended / derived / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_POLICY.md](ARCH_POLICY.md): policy storage, verdict precedence, snapshot
  semantics, rule inventory, transfer routing, per-key policy selection, and
  transaction scope.
- [ARCH_POLICY.md](ARCH_POLICY.md#verdict-model): compatibility-bearing approval and
  policy contract.
- [ARCH_SIGNING.md](ARCH_SIGNING.md): finalized transaction data and policy
  placement in the signing flow.
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md): network context selection from
  `GenesisHash`.
- [ARCH_SECURITY.md](ARCH_SECURITY.md#authorization): authentication and
  authorization separation from signing policy.
- [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md):
  cancellation, timeout, fail-all, and operator-delivery behavior.

This model does not replace [ARCH_POLICY.md](ARCH_POLICY.md). It extracts the
decision procedure and invariants that should remain stable as implementation
code moves.

## Notation

Pseudo-formal snippets in this document are relational pseudocode. `Reject(...)`
means no successful approval/signing path exists for that input. `Decide(...) =
Verdict` means the decision procedure returns that verdict.

The machine-checked companion `policy_precedence.tla`
([FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md))
abstracts the rule inventory as deny, review, and approve families. Policy
selection and the transaction-type rule below add members to those families
and change neither the families nor their precedence, so the spec needs no
change for them.

## Scope

Client-signing policy decides whether a planned signing request is:

- rejected before approval,
- forced to manual review,
- explicitly approved without manual review,
- handled by the operator default.

Cosigner policy is a separate deterministic surface with the same document
set (a node default plus per-key documents selected by Witness Key ID): no
manual-review verdict and no operator default. This document defines the
shared snapshot and policy-selection vocabulary; the cosigner-specific
decision rules are modeled in
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md).

Client simulation obtains signatures through ordinary signing, so every policy
tier and operator-approval rule applies exactly as it does for submission. The
signer receives no simulation designation.

Policy is separate from:

- HTTP or IPC authentication,
- principal/action authorization,
- key ownership and unlock state,
- cryptographic signing correctness,
- operator behavior during manual approval.

## Abstract Objects

### Policy Snapshot

`PolicySnapshot` is the immutable effective policy observed by one signing
request. It is one compiled `NodePolicy` for the node's selected generation.
For client-signing requests it includes:

- `role`: the node role every document was decoded for,
- `default`: the compiled node default document (`default.json`),
- `own`: a partial map from key selector to that key's own compiled document
  (`policies/<selector>.json`; the selector is the signing address on a
  signer node and the Witness Key ID on a cosigner node),
- transfer routing configuration carried inside each compiled document,
- the product runtime's operator default input `user_auto_approve`, even though that
  setting is stored outside the policy documents.

Every verdict-bearing field is present in each stored document; the decoder
fills in no defaults. A key's own document replaces the node default wholesale.
There is no overlay, inheritance, or merge between the two.

Each document is trusted only after its own sidecar verification. A missing
or mismatched `.hmac` sidecar on any document, default or per-key, fails the
whole load closed; no partial document set is ever installed. A reload failure
keeps the previous in-memory snapshot active.

### Planned Request

`PlannedRequest` is the finalized group from
[FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md). Policy observes:

- finalized transaction bytes,
- adjusted fees,
- final group IDs,
- signer-controlled slots,
- passthrough and foreign slots as context,
- server-added dummy effects,
- auth addresses for signer-controlled slots.

Policy does not evaluate caller drafts that were changed by planning.

### Slot Classes

`SlotClass` extends the planning model's three-valued request `Mode` with a
fourth value for server-added positions. Each finalized group position is one
of:

- `sign`: signer-controlled request slot (Mode `sign`),
- `passthrough`: already-signed external slot (Mode `passthrough`),
- `foreign`: unsigned external slot (Mode `foreign`),
- `dummy`: signer-generated LogicSig-budget slot (no request mode).

The first three classes are 1:1 with the planning model's `Mode` for caller
request positions. Dummies have no request index and therefore no `Mode`;
their slot class is determined by planning.

Hard-reject and configured amount/routing rules evaluate signer-controlled
request slots only. Passthrough and foreign slots are not governed by those
rules because this signer is not signing them. They still participate in group
context, approval rendering, audit visibility, and a load-bearing cross-party
Always Review check: warning-bearing rekey, close, clawback, and related danger
fields force operator review even when `user_auto_approve:true`. Dummies are
signer-generated minimum-effect transactions and are not independent
user-facing policy subjects.

### Rule Classification

Rules in the current inventory fall into two structural shapes:

- **Per-position transaction-level rules.** Always Deny and configured
  signer-policy review rules evaluate signer-controlled slots. The separate
  cross-party warning-review guard evaluates passthrough and foreign slots so
  dangerous context cannot ride through the operator default.
- **Plan-shape predicates.** Always Approve is currently a single rule:
  `auto_approve_self_noop_transfer`, and it is not per-position. It matches
  on the overall planned request: single caller request, no passthrough or
  foreign entries, not pre-grouped, exact dummy/LSig structure, and the
  caller transaction matches a self-no-op-transfer shape.

```text
TransactionLevelPolicyCandidate(i) holds only for Always Deny and Always
Review evaluations on signer-controlled positions.

Always Approve evaluation takes the whole PlannedRequest, not a position
index.
```

When the rule inventory adds further group-level or plan-shape predicates,
the classification list above should be updated. P8 covers only the
per-position case.

### Verdict

`Verdict` is one of:

```text
Reject(rule_id)
Review(rule_id)
Approve(rule_id)
DefaultReview
DefaultApprove
```

`rule_id` is present for policy verdicts and absent for operator-default
outcomes.

## Decision Procedure

Define:

```text
Decide(policy_snapshot, planned_request) -> Verdict
```

The procedure is ordered and short-circuiting:

1. Evaluate Always Deny rules.
2. If any Always Deny rule matches, return `Reject(rule_id)`.
3. Evaluate Always Review rules.
4. If any Always Review rule matches, return `Review(rule_id)`.
5. Evaluate Always Approve rules.
6. If any Always Approve rule matches, return `Approve(rule_id)`.
7. Use Operator Default:
   - `user_auto_approve:false` returns `DefaultReview`.
   - `user_auto_approve:true` returns `DefaultApprove`.

The precedence is:

```text
Always Deny > Always Review > Always Approve > Operator Default
```

Among policy verdicts, the most restrictive matching verdict wins. Therefore an
Always Review match blocks both Always Approve and `user_auto_approve:true`, and
an Always Deny match blocks every later phase.

Inside Always Deny and Always Review, the transaction-type rule is evaluated
first and alone (see Transaction Type Rule below). The order of the remaining
rules within a phase affects only which `rule_id` is projected, not the
verdict.

## Policy Phases

### Always Deny

Always Deny rules are hard safety guards. Current deny sources include:

- `transaction_types` entries with verdict `reject` (rule id
  `transaction_type:<type>`), evaluated first,
- `reject_foreign_rekey`,
- `reject_close_remainder`,
- `reject_asset_close`,
- `reject_clawback`,
- `max_fee_microalgos`,
- network- and asset-scoped `limits` `reject_above` thresholds,
- transfer routing blocked destinations, route misses, close/clawback denials,
  and `reject_above` thresholds.

### Always Review

Always Review rules force operator approval even when the operator default would
otherwise auto-approve. Current review sources include:

- `transaction_types` entries with verdict `review` (rule id
  `transaction_type:<type>`), evaluated first,
- `always_review_warnings`,
- network- and asset-scoped `limits` `review_above` thresholds,
- transfer routing `on_no_route: review` and `review_above` thresholds,
- bounded administrative operations, which always require review (rule id
  `bounded_admin_operation_requires_review`).

Warnings are displayed even when they do not force review.

### Always Approve

Always Approve rules are explicit low-risk policy rules. Current approval
source:

- `auto_approve_self_noop_transfer`.

This rule is evaluated only after Always Deny and Always Review do not match.
Transfer routing never produces an Always Approve verdict; a route match only
allows the movement to continue through later phases.

### Operator Default

The operator default is not policy. It is reached only when no policy verdict
matched. It is controlled by `user_auto_approve` in
`identities/default/config.yaml`.

### Transaction Type Rule

Every document carries `transaction_types`, a total map from transaction type
(`pay`, `axfer`, `acfg`, `afrz`, `appl`, `keyreg`, `stpf`, `hb`, with `*` as
the required fallback) to one of `allow`, `review`, `reject`. For a
signer-controlled slot the verdict for its transaction type is read before any
other rule of the phase:

```text
TypeVerdict(policy, txn) = policy.transaction_types[txn.type]
                           if defined, else policy.transaction_types["*"]

TypeVerdict = reject => Reject(transaction_type:<type>)
                        (Always Deny, before every other deny rule;
                         no other deny rule is evaluated for the slot)
TypeVerdict = review => Review(transaction_type:<type>)
                        (Always Review, before every other review rule;
                         no other review rule is evaluated for the slot)
TypeVerdict = allow  => the slot continues to the remaining rules
```

`allow` grants nothing by itself: the remaining deny, review, approve, and
operator-default phases still apply. The same `rule_id` is emitted at the deny
and review tiers; the phase that emits it says which.

## Effective Policy Selection

Every signer-controlled slot is judged against exactly one document: the
signing key's own document when the snapshot holds one, otherwise the node
default.

```text
PolicyFor(snapshot, selector) =
  snapshot.own[selector]   if defined
  snapshot.default         otherwise
```

Client-signing rules:

1. The selector is the signing auth address.
2. The auth address is selected from the key that will sign, not from the
   transaction sender.
3. This matters for rekeyed accounts: the auth address selects the document.
4. Missing key-type metadata for a signer-controlled slot still fails closed before a
   policy decision can silently fall back to the wrong document.
5. Selection is total within a loaded snapshot: a key with no document of its
   own follows the default, with no field inherited from one document into
   the other. `PolicyFor` is undefined only when no snapshot is loaded, and
   then every request fails closed.
6. The resolver is bound to one snapshot for the life of the request's signing
   service (P2), so every slot of one request is judged against the same
   document set.

Cosigner policy uses the same selection with the Witness Key ID as the
selector and the cosigner node default as the fallback; the cosigner-role
component-signing flow is modeled in
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md).

## Network Selection

Network-scoped policy is a function of transaction `GenesisHash` alone.
`GenesisID` is display and diagnostic data; it is not an input to policy
network selection.

```text
forall txn1, txn2:
  txn1.GenesisHash = txn2.GenesisHash =>
    NetworkToken(txn1) = NetworkToken(txn2)
```

Unknown genesis hashes fail closed in planning before a request can use the
wrong policy bucket. Transfer-routing unknown-hash behavior is still modeled for
the policy layer because it has explicit rule IDs and tier behavior when route
evaluation sees an unresolved hash.

## Runtime Snapshot Semantics

Policy updates are atomic from the perspective of signing requests:

1. Readers observe either the previous snapshot or the replacement snapshot.
2. No request observes a partially applied policy.
3. A signing request captures its effective policy snapshot when its signing
   service is constructed.
4. That snapshot governs policy evaluation, approval waiting, and final
   signature execution for the request.
5. Later reloads or policy applies affect only later requests.
6. In-flight requests are not re-evaluated or canceled only because policy
   changed while they waited for approval.

`user_auto_approve` is captured at the same point even though it is sourced
from product config (`identities/default/config.yaml`) rather
than from the policy documents. Admin RPCs that toggle `user_auto_approve` are
visible to subsequent signing requests but do not propagate into a request
that has already captured its snapshot.

## Invariants

### P1: Trusted Snapshot Only

An active policy snapshot is either the previous trusted snapshot or a newly
verified replacement in which every document, default and per-key, passed
sidecar verification. A failed verification of any one document, or a failed
reload, cannot install an untrusted or partial policy.

```text
ActivePolicyAfterReload in {PreviousTrustedPolicy, VerifiedReplacementPolicy}
```

### P2: Snapshot Stability

One signing request uses one policy snapshot from evaluation through final
signature execution.

```text
RequestStarted(snapshot) =>
  PolicyForEvaluation = snapshot and
  PolicyForApprovalWait = snapshot and
  PolicyForFinalSigning = snapshot
```

### P3: Finalized Data Input

Policy observes planned transaction data, not pre-planning drafts.

```text
PolicyInput(request) = Plan(snapshot, request).finalized_group
```

### P4: Deny Dominance

Any Always Deny match rejects the request before approval and cannot be
overridden.

```text
ExistsAlwaysDeny(policy, planned) => Decide(policy, planned) = Reject(rule_id)
```

### P5: Review Dominance Over Approval

If no Always Deny rule matches and at least one Always Review rule matches,
manual review is required. Always Approve and `user_auto_approve:true` cannot
skip that prompt.

```text
not ExistsAlwaysDeny(policy, planned) and
ExistsAlwaysReview(policy, planned) =>
  Decide(policy, planned) = Review(rule_id)
```

### P6: Explicit Approval Only After Deny/Review Pass

Always Approve can sign without manual review only when no Always Deny or
Always Review rule matched.

```text
not ExistsAlwaysDeny(policy, planned) and
not ExistsAlwaysReview(policy, planned) and
ExistsAlwaysApprove(policy, planned) =>
  Decide(policy, planned) = Approve(rule_id)
```

### P7: Operator Default Is Last

The operator default is reached only when no policy verdict matched.

```text
NoPolicyVerdict(policy, planned) and user_auto_approve = false =>
  Decide(policy, planned) = DefaultReview

NoPolicyVerdict(policy, planned) and user_auto_approve = true =>
  Decide(policy, planned) = DefaultApprove
```

### P8: Passthrough and Foreign Policy Scope

Signer-owned hard-reject/threshold/routing rules do not govern passthrough or
foreign slots, but warning-bearing external slots force review.

```text
ModeAt(i) in {passthrough, foreign} =>
  not SignerOwnedRuleCandidate(i) and
  (DangerousWarning(i) => Decide(request) = Review(always_review_warnings))
```

Those slots also affect group context, approval rendering, and audit visibility.

### P9: Route Verdict Excludes Approve

Transfer routing produces only `Reject`, `Review`, or `None`. It never
produces an Always Approve verdict.

```text
TransferRouteEval(movement) => RoutingVerdict in {Reject, Review, None}
```

This is a property of the routing verdict itself, not of the final request
outcome. A `None` routing verdict means routing contributes no policy
verdict; the request still proceeds through the remaining decision phases.
If no later phase matches and `user_auto_approve:true`, the request can still
be auto-approved via Operator Default. Routing does not *grant* auto-approval,
but it does not *block* it either.

### P10: Auth Key Selects The Document

For signer-controlled slots, the governing document is selected by the signing
auth address: the key's own document if present, else the node default.

```text
EffectivePolicyForSlot(slot) = PolicyFor(snapshot, AuthAddress(slot))
```

## Assumptions

This model assumes:

- planning has already validated request shape and network consistency,
- auth key type metadata is accurate for signer-controlled slots,
- policy parsing and sidecar verification are implemented according to
  [ARCH_POLICY.md](ARCH_POLICY.md),
- raw-unit amount conversion is already complete before policy compares
  thresholds,
- operator approval or rejection, when required, is supplied by a separate
  approval model.

## Non-Goals

This model does not prove:

- HTTP authentication or principal authorization,
- policy JSON document decoding and schema validation in full detail,
- HMAC algorithm correctness,
- algod transaction validity,
- transfer-route schema validation in full detail,
- manual operator decision quality,
- cancellation and timeout behavior,
- server shutdown and runtime destruction ordering.

## Code and Test Anchors

These anchors are advisory pointers for traceability. They are not part of the
model and should be refreshed when code is renamed or ownership moves.

Implementation areas that should remain aligned with this model:

- `internal/policy/config.go`
- `internal/policy/doc_v1.go`
- `internal/policy/doc_v1_compile.go`
- `internal/policy/lint.go`
- `internal/policy/review.go`
- `internal/policy/transfer_routing.go`
- `internal/policy/transfer_routing_eval.go`
- `internal/signerapp/policyruntime/policy.go`
- `internal/signerapp/signing/service.go`
- `internal/signerapp/signing/approval.go`
- `internal/signerapp/signing/always_review.go`
- `internal/signerapp/admin/service.go`

High-value test anchors:

- a malformed or unsigned document, default or per-key, fails the whole load
  closed,
- reload failure keeps the previous policy snapshot,
- one request uses one captured snapshot through approval and signing,
- Always Deny wins over manual approval and auto-approval,
- Always Review blocks `user_auto_approve:true`,
- Always Approve is evaluated only after deny and review pass,
- Operator Default is reached only when no policy verdict matched,
- passthrough and foreign slots are skipped by signer-owned policy but warning-bearing danger fields force review,
- routing matches do not auto-approve,
- the signing auth address, not the transaction sender, selects the key's own
  document or the default,
- a key's own document replaces the default wholesale; no field is inherited,
- a `transaction_types` reject names the type and precedes every other deny
  rule; a `review` entry precedes every other review rule,
- network-scoped thresholds use `GenesisHash`, not `GenesisID`.

## Open Questions

These should be answered before a machine-checkable model:

1. Define deterministic selection of `rule_id` when multiple rules in the same
   tier match and only one rule ID is projected.
2. Decide whether transfer routing should be modeled as an abstract verdict
   source or expanded into a separate route-table model first.
3. Inventory existing tests against each invariant before adding new tests.
