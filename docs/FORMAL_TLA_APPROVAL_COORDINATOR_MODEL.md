# Approval Coordinator Machine-Checkable Model

> Status: TLC checked with `Requests = {r1, r2, r3}`. The safety run (with
> symmetry over the request set) generated 196 distinct reachable states at
> depth 11 with no counterexamples for `Safety`. The liveness run
> (`approval_coordinator_liveness.cfg`, no symmetry — TLC's liveness checking
> is unsound under symmetry reduction) generated 833 distinct states at depth
> 11 and verified the `Progress` temporal property under `LiveSpec`.

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
| AP7: No Orphaned Delivery On Displacement | FORMAL_APPROVAL_COORDINATOR_MODEL.md | `AP7_NoOrphanedDelivery` |
| Progress (liveness): every queued/delivered request terminates | FORMAL_APPROVAL_COORDINATOR_MODEL.md | `Progress` under `LiveSpec` |
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

**AP7 is the displacement regression guard.** The daemon fails the pending
approval (`FailAllPendingApprovals("apadmin displaced")`) before replacing the
active apadmin session, because a delivered prompt was shown to the old client
only — the replacement has no way to render or answer it. The `Displace`
action models that fixed semantics; the `orphanedDelivery` history flag flips
if a future edit lets a delivered request survive client replacement (the
pre-fix orphan, which head-of-line-blocked every later approval until the
`ApprovalWait` timer freed the turn).

The invariants and the liveness property are validated by mutation testing:

- **L8/AP6**: removing the `~decommissioned` guard from `Deliver` lets a
  request be delivered (and then approved) after the decommission mark — TLC
  counterexample.
- **AP7**: changing `Displace` to the pre-fix semantics (client replaced,
  delivered request left in place) flips `orphanedDelivery` in the very next
  state — TLC reports the safety violation with a four-step trace.
- **Progress**: dropping the `WF_vars(\E r : Timeout(r))` fairness conjunct
  produces a lasso counterexample where a delivered request never resolves —
  the model's way of saying the timer is the only *guaranteed* exit from
  `Delivered` (operator decisions are choices). The displacement fix matters
  precisely because a prompt whose operator is gone would otherwise sit on
  that timer.

The restored spec passes all runs.

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
  `Progress` asserts that every queued request eventually terminates, not that
  requests are granted in arrival order.
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

### Decommission, disconnect, and displacement all fail-all

The coordinator's `FailAllPendingRequests` has three triggers in the code:
successful decommission (`Runtime.Decommission`), operator-client disconnect,
and client displacement (both in `daemon/ipc.go`; explicit lock also calls it,
via `adminserver/handlers.go`, and behaves like `OperatorDisconnect` here).
The model includes them as `Decommission` (mark + fail-all, fires once, blocks
further delivery), `OperatorDisconnect` (fail-all without decommission,
recoverable), and `Displace` (fail-all plus the AP7 `orphanedDelivery` guard,
recoverable — the new client takes over). All move the delivered request to
`Failed` and release the turn.

### History-flag assignments must parenthesize their disjunction

In TLA+, `=` binds tighter than `\/`, so `flag' = flag \/ P` parses as
`(flag' = flag) \/ P` — a *disjunction of actions*, not an assignment. When
`P` is true, TLC can satisfy the second disjunct without assigning `flag'`
and fails with "successor state is not completely specified" instead of
flipping the flag. Both guard flags are therefore written
`flag' = (flag \/ P)`. This was found when the AP7 mutation made the bad
state reachable; the L8 flag had the same latent form and was fixed alongside.

### Symmetry and deadlock

Requests are interchangeable for the safety invariants, so `SYMMETRY
RequestSymmetry` (`Permutations(Requests)`) prunes the state space. The workflow
terminates (all requests terminal, or `New` under decommission), so
`CHECK_DEADLOCK FALSE` keeps TLC from flagging the terminal state.

The liveness config drops `SYMMETRY`: TLC's liveness checking is unsound under
symmetry reduction. The safety config keeps the symmetric fast path; the
liveness run explores the full permutation space (833 distinct states — still
sub-second).

### Fairness only where the code guarantees progress

`LiveSpec` adds weak fairness on `Deliver` (the delivery loop always retries
while a queued request exists and the turn is free), `Timeout` (the
`ApprovalWait` timer always eventually fires on a delivered request), and
`FailQueuedWhileDecommissioned` (the decommission drain completes). Operator
`Approve`/`Reject` and client `Cancel` carry no fairness — they are choices,
not guarantees — and `Request` carries none either, which is why `Progress`
is scoped to requests that reached `Queued`.

## How to check

```sh
make formal-test TLA2TOOLS_JAR=/path/to/tla2tools.jar
```

or directly:

```sh
java -jar tla2tools.jar -config docs/formal/approval_coordinator.cfg \
    docs/formal/approval_coordinator.tla
java -jar tla2tools.jar -config docs/formal/approval_coordinator_liveness.cfg \
    docs/formal/approval_coordinator.tla
```

Expected: `Model checking completed. No error has been found.` for both — the
safety run at 196 distinct states, the liveness run at 833 (no symmetry),
both depth 11, sub-second runtime. `make formal-test` runs both (the liveness
config is listed in the Makefile's `TLA_LIVENESS_SPECS`).

## What this proves vs. doesn't

It proves that, over every interleaving of up to three requests, the modeled
coordinator never delivers two requests to the operator at once (AP4), always
admits cancellation of a non-terminal request (AP5), never leaves a pending
request after decommission (AP6), never approves a request once decommissioned
(L8), never leaves a delivered prompt orphaned by client displacement (AP7),
and — under the stated fairness assumptions — resolves every request that
reaches the coordinator (`Progress`). The fairness assumptions are themselves
claims about the code (the delivery loop retries; the `ApprovalWait` timer
fires; the decommission drain completes); they are not checked by TLC, and —
like the other modules — the mapping from this abstract state machine to the
Go coordinator is a code-review responsibility, anchored by the Go tests in
the traceability AP rows.

## Linking back

- Prose model: [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md).
- L8 lives in [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md); its
  machine-check was deferred from [formal/lifecycle.tla](formal/lifecycle.tla)
  to this module.
- The `approval` input this coordinator produces is the four-valued free oracle
  in [formal/policy_precedence.tla](formal/policy_precedence.tla); deriving that
  oracle here instead of treating it as free is Track B3.

## Extension plan

- **Approval-aware composition (Track B3) — shipped** as
  [formal/approval_composition.tla](formal/approval_composition.tla)
  ([FORMAL_TLA_APPROVAL_COMPOSITION_MODEL.md](FORMAL_TLA_APPROVAL_COMPOSITION_MODEL.md)).
  It joins this module's outcome with `policy_precedence.tla`, replacing the free
  `approval` oracle with the value derived here, and machine-checks that hard deny
  still dominates and that a fail-all (disconnect / decommission) yields no signed
  output end to end. It stays one-shot by consuming only the terminal outcome,
  which is why this module's temporal invariants live here.
- **Liveness — shipped.** `LiveSpec` (weak fairness on `Deliver`, `Timeout`,
  and `FailQueuedWhileDecommissioned`) verifies `Progress`: every request that
  reaches the coordinator eventually resolves. Checked by
  [formal/approval_coordinator_liveness.cfg](formal/approval_coordinator_liveness.cfg)
  in `make formal-test`.
