# Formal Policy Model

> Status: precise English model, not machine-checked.
> This document formalizes the current client-signing policy verdict semantics
> used by APlane after transaction planning.
> Invariant status (implemented / intended / derived / etc.) is tracked in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Sources

Normative inputs:

- [ARCH_POLICY.md](ARCH_POLICY.md): policy storage, verdict precedence, snapshot
  semantics, rule inventory, transfer routing, key overrides, and
  transaction scope.
- [ARCH_CONTRACTS.md](ARCH_CONTRACTS.md): compatibility-bearing approval and
  policy contract.
- [ARCH_TXNFLOW.md](ARCH_TXNFLOW.md): finalized transaction data and policy
  placement in the signing flow.
- [ARCH_NETWORKS.md](ARCH_NETWORKS.md): network context selection from
  `GenesisHash`.
- [ARCH_AUTHORIZATION.md](ARCH_AUTHORIZATION.md): authentication and
  authorization separation from signing policy.
- [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md): lifecycle behavior
  while a request waits for approval or reaches final signing.

This model does not replace [ARCH_POLICY.md](ARCH_POLICY.md). It extracts the
decision procedure and invariants that should remain stable as implementation
code moves.

## Notation

Pseudo-formal snippets in this document are relational pseudocode. `Reject(...)`
means no successful approval/signing path exists for that input. `Decide(...) =
Verdict` means the decision procedure returns that verdict.

## Scope

Client-signing policy decides whether a planned signing request is:

- rejected before approval,
- forced to manual review,
- explicitly approved without manual review,
- handled by the operator default.

Attestor component policy is a separate deterministic surface stored in
`attestation.yaml`: no manual-review verdict and no operator default. This
document defines the shared snapshot and sparse-override vocabulary; the
attestor-specific decision rules are modeled in
[FORMAL_ATTESTED_SIGNING_MODEL.md](FORMAL_ATTESTED_SIGNING_MODEL.md).

Policy also gates `/simulate`, but only at the Always Deny tier. `/simulate`
does not wait on operator approval and does not block on Always Review
matches; see [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md) IS2
and IS3 for the simulate-specific boundary.

Policy is separate from:

- HTTP or IPC authentication,
- principal/action authorization,
- key ownership and unlock state,
- cryptographic signing correctness,
- operator behavior during manual approval.

## Abstract Objects

### Policy Snapshot

`PolicySnapshot` is the immutable effective policy observed by one signing
request. For client-signing requests it includes:

- identity-wide policy fields,
- YAML-only `key_overrides`,
- transfer routing configuration,
- policy defaults for absent fields,
- the identity's operator default input `user_auto_approve`, even though that
  setting is stored outside `policy.yaml`.

The policy YAML is trusted only after sidecar verification. A missing or
mismatched `policy.yaml.hmac` fails closed once a signed baseline exists. A
reload failure keeps the previous in-memory snapshot active.

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

Transaction-level policy rules evaluate signer-controlled request slots only.
Passthrough and foreign slots are not governed by this signer's
transaction-level policy because this signer is not signing them. They still
participate in group context, approval rendering, warning display, and audit
visibility. Dummies are signer-generated minimum-effect transactions; they are
not subject to user-facing transaction-level policy.

### Rule Classification

Rules in the current inventory fall into two structural shapes:

- **Per-position transaction-level rules.** All Always Deny rules and all
  Always Review rules evaluate one signer-controlled slot at a time. P8's
  `TransactionLevelPolicyCandidate(i)` predicate refers to these rules:
  passthrough and foreign slots are excluded from candidacy.
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

## Policy Phases

### Always Deny

Always Deny rules are hard safety guards. Current deny sources include:

- `reject_foreign_rekey`,
- `reject_close_remainder`,
- `reject_asset_close`,
- `reject_clawback`,
- `max_fee_microalgos`,
- network-scoped `max_algo_payments`,
- network-scoped `max_asa_amounts`,
- transfer routing blocked destinations, route misses, close/clawback denials,
  and `reject_above` thresholds.

### Always Review

Always Review rules force operator approval even when the operator default would
otherwise auto-approve. Current review sources include:

- `always_review_warnings`,
- network-scoped `review_algo_payments`,
- network-scoped `review_asa_amounts`,
- transfer routing `on_no_route: review` and `review_above` thresholds.

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
`identities/<identity>/config.yaml`.

## Effective Policy Selection

For signer-controlled slots, the effective policy may be modified by
`key_overrides`.

Client-signing rules:

1. Client-signing overrides are keyed by the signing auth address.
2. The auth address is selected from the key that will sign, not from the
   transaction sender.
3. This matters for rekeyed accounts: the auth address controls the override.
4. Missing key-type metadata for a signer-controlled slot still fails closed before a
   policy decision can silently fall back to the wrong override.
5. Override fields are sparse overlays over the identity-wide policy; nested
   overrides are rejected.

Attestor component overrides are keyed by the `a_...` component selector and
are consumed only by the attestor-role component-signing flow modeled in
[FORMAL_ATTESTED_SIGNING_MODEL.md](FORMAL_ATTESTED_SIGNING_MODEL.md).

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
5. Later reloads or whole-file replacements affect only later requests.
6. In-flight requests are not re-evaluated or canceled only because policy
   changed while they waited for approval.

`user_auto_approve` is captured at the same point even though it is sourced
from identity-scoped config (`identities/<identity>/config.yaml`) rather
than from `policy.yaml`. Admin RPCs that toggle `user_auto_approve` are
visible to subsequent signing requests but do not propagate into a request
that has already captured its snapshot.

## Invariants

### P1: Trusted Snapshot Only

An active policy snapshot is either the previous trusted snapshot or a newly
verified replacement. A failed verification or reload cannot install an
untrusted policy.

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

Transaction-level policy rules do not govern passthrough or foreign slots.

```text
ModeAt(i) in {passthrough, foreign} =>
  not TransactionLevelPolicyCandidate(i)
```

Those slots may still affect group context, warning display, approval
rendering, and audit visibility.

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

### P10: Auth Key Selects Overrides

For signer-controlled slots, key overrides are selected by the signing auth
address.

```text
EffectivePolicyForSlot(slot) =
  Overlay(identity_policy, key_overrides[AuthAddress(slot)])
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
- policy YAML parser correctness,
- HMAC algorithm correctness,
- algod transaction validity,
- transfer-route schema validation in full detail,
- manual operator decision quality,
- cancellation and timeout behavior,
- runtime decommission behavior.

## Code and Test Anchors

These anchors are advisory pointers for traceability. They are not part of the
model and should be refreshed when code is renamed or ownership moves.

Implementation areas that should remain aligned with this model:

- `internal/policy/config.go`
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

- malformed or unsigned policy files fail closed,
- reload failure keeps the previous policy snapshot,
- one request uses one captured snapshot through approval and signing,
- Always Deny wins over manual approval and auto-approval,
- Always Review blocks `user_auto_approve:true`,
- Always Approve is evaluated only after deny and review pass,
- Operator Default is reached only when no policy verdict matched,
- passthrough and foreign slots are skipped by transaction-level policy,
- routing matches do not auto-approve,
- key overrides use auth address rather than transaction sender,
- network-scoped thresholds use `GenesisHash`, not `GenesisID`.

## Open Questions

These should be answered before a machine-checkable model:

1. Define deterministic selection of `rule_id` when multiple rules in the same
   tier match and only one rule ID is projected.
2. Decide whether transfer routing should be modeled as an abstract verdict
   source or expanded into a separate route-table model first.
3. Inventory existing tests against each invariant before adding new tests.
