# Approval Coordinator Machine-Checkable Model

> Status: TLC checked with `Requests = {r1, r2, r3}` and symmetry over the
> request set; the recorded run generated 196 distinct reachable states,
> reached depth 11, and found no counterexamples for `Safety`.

This is the fifth machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md), and the machine-checked
counterpart to [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md)
(Track B2). It models the runtime approval coordinator's per-request state
machine: each transaction-signing approval request moves through `Queued`
(waiting for the single delivery turn) and `Delivered` (shown to the one
operator, awaiting a decision) to exactly one terminal outcome.

The spec lives at [formal/approval_coordinator.tla](formal/approval_coordinator.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| AP4: Single Delivery In Flight | FORMAL_APPROVAL_COORDINATOR_MODEL.md | `AP4_SingleDelivery` |
| AP5: Cancellation Always Enabled | FORMAL_APPROVAL_COORDINATOR_MODEL.md | `AP5_CancelAlwaysEnabled` |
| AP6: Decommission Leaves No Pending | FORMAL_APPROVAL_COORDINATOR_MODEL.md | `AP6_DecommissionLeavesNoPending` |
| L8: No Approval After Decommission | FORMAL_LIFECYCLE_MODEL.md (L8) | `L8_NoApproveAfterDecommission` |
| turn/state consistency | (TypeOK) | `TypeOK` |

**L8 is the headline win.** It was the only `deferred` invariant in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md), explicitly held back because
it crosses the lifecycle/approval boundary and needs a pending-approval state
machine to check meaningfully. This module supplies that state machine. L8 is
checked via the history flag `badApproveAfterDecommission`, set if any `Approve`
fires while `decommissioned` is true; the flag stays false under the current
guards because `Decommission` fails the delivered request and blocks further
delivery, so no request can be approved after the mark.

AP6 is a direct state predicate (`decommissioned => DeliveredSet = {}`). AP5
uses `ENABLED`-style reasoning over the `Cancel` action. AP4 bounds the
delivered set, with the turn token tied to that set in `TypeOK`.

The L8/AP6 invariants are validated by mutation testing: removing the
`~decommissioned` guard from the `Deliver` action lets a request be delivered
(and then approved) after the decommission mark, which produces a TLC
counterexample. The restored spec passes.

## Modeled by construction (not separate predicates)

- **AP1 (Single Terminal Resolution).** Terminal states are absorbing: no
  action takes a `Terminal` state as its source guard, so each request resolves
  at most once. The runtime's delete-before-deliver and at-most-once channel
  send (which drop a late operator response) are covered by the Go test cited
  in the traceability AP1 row.
- **AP2 (Only Operator Approve Permits A Signature).** `Approve` is the only
  action producing the `Approved` state; every other terminal outcome is
  not-approved.
- **AP3 (Response Identity Binding).** Each operator action targets one request
  by identity (`Approve(r)`, `Reject(r)`), so a response is bound to its request
  by construction.

## What it deliberately does not cover

- **FIFO fairness of the delivery queue.** The single turn is a boolean token;
  which queued request is granted next is a liveness/fairness concern, deferred.
- **Real timer durations.** `Timeout` is a nondeterministic event, not
  wall-clock time.
- **Token-provisioning issuance policy.** Token requests share the same delivery
  turn and the same fail-all; their issuance policy is a separate concern. The
  shared serialization is modeled abstractly by the single turn.
- **The verdict decision** that decides whether the operator is consulted at all
  ([FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)). This module begins once a
  consult occurs.
- **Composition with `policy_precedence.tla`** — replacing its free four-valued
  `approval` oracle with the outcome derived here (Track B3).

## Modeling choices

### Real transitions, not one-shot

Like [formal/lifecycle.tla](formal/lifecycle.tla) and unlike the three one-shot
specs (`sign_boundary`, `policy_precedence`, `composition`), this module has a
real `Next` relation. Several requests interleave over a shared single-delivery
turn with operator decisions, timeout, cancellation, operator-client disconnect,
and decommission. TLC's depth of 11 reflects genuine state-space exploration
across action interleavings.

### Single delivery turn as a token

The real coordinator holds the delivery turn for the entire operator wait
(`acquireDeliveryTurnContext` ... deferred `releaseDeliveryTurn`), so at most one
request is delivered at a time and `pendingRequests` holds at most one entry
while serialized. The model represents the turn as a single boolean `turnHeld`
tied to the delivered set in `TypeOK`; the FIFO ordering of waiters is abstracted
away because the safety invariants depend only on mutual exclusion, not order.

### History flag for L8

`badApproveAfterDecommission` mirrors the `lifecycle.tla` L6 pattern
(`badAcquireAfterDecommission`): a regression guard that is tautologically false
under the correct guards and flips if a future edit weakens them. This makes L8
a concrete, falsifiable property rather than a structural observation.

### Decommission and disconnect both fail-all

The coordinator's `FailAllPendingRequests` has two triggers in the code:
successful decommission (`Runtime.Decommission`) and operator-client disconnect
(`daemon/ipc.go`). The model includes both: `Decommission` (mark + fail-all,
fires once, blocks further delivery) and `OperatorDisconnect` (fail-all without
decommission, recoverable). Both move the delivered request to `Failed` and
release the turn.

### Symmetry and deadlock

Requests are interchangeable for the safety invariants, so `SYMMETRY
RequestSymmetry` (`Permutations(Requests)`) prunes the state space. The workflow
terminates (all requests terminal, or `New` under decommission), so
`CHECK_DEADLOCK FALSE` keeps TLC from flagging the terminal state.

## How to check

```sh
make formal-test TLA2TOOLS_JAR=/path/to/tla2tools.jar
```

or directly:

```sh
java -jar tla2tools.jar -config docs/formal/approval_coordinator.cfg \
    docs/formal/approval_coordinator.tla
```

Expected: `Model checking completed. No error has been found.`, 196 distinct
states, depth 11. Sub-second runtime.

## What this proves vs. doesn't

It proves that, over every interleaving of up to three requests, the modeled
coordinator never delivers two requests to the operator at once (AP4), always
admits cancellation of a non-terminal request (AP5), never leaves a pending
request after decommission (AP6), and never approves a request once
decommissioned (L8). It does not prove liveness (that a queued request
eventually delivers), and — like the other one-shot/temporal modules — the
mapping from this abstract state machine to the Go coordinator is a code-review
responsibility, anchored by the Go tests in the traceability AP rows.

## Linking back

- Prose model: [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md).
- L8 lives in [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md); its
  machine-check was deferred from [formal/lifecycle.tla](formal/lifecycle.tla)
  to this module.
- The `approval` input this coordinator produces is the four-valued free oracle
  in [formal/policy_precedence.tla](formal/policy_precedence.tla); deriving that
  oracle here instead of treating it as free is Track B3.

## Extension plan

- **Approval-aware composition (Track B3).** Join this module with
  `policy_precedence.tla`, replacing its free `approval` oracle with the outcome
  derived here, and re-check that hard deny still dominates and that decommission
  yields no signed output end to end. This mirrors how `composition.tla` derived
  `policy_precedence`'s verdict from rule application, and carries the same
  temporal-vs-one-shot reconciliation noted for lifecycle-aware composition.
- **Liveness.** Add weak fairness on `Deliver` and the terminal actions and
  verify every queued request eventually resolves.
