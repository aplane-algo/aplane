# Approval-Aware Composition Machine-Checkable Model

> Status: TLC checked with `MaxRequestEntries = 3` and `MaxDummies = 2`; the
> recorded run generated 47,304 distinct states, reached depth 1, and found no
> counterexamples for `Safety`.

This is the sixth machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md) (Track B3).
[formal/composition.tla](formal/composition.tla) derived the policy `verdict`
that `sign_boundary.tla` treats as a free oracle, but still left the operator
`approval` channel as a free four-valued input. This module closes that gap: it
replaces the free `approval` oracle with the terminal outcome of the approval
coordinator (from [formal/approval_coordinator.tla](formal/approval_coordinator.tla))
and feeds it end to end into the planned-group signing output.

The spec lives at [formal/approval_composition.tla](formal/approval_composition.tla).

## What it covers

| Claim | TLA+ predicate | Kind |
|---|---|---|
| Coordinator consulted iff review-class verdict | `ConsultedIffReview` | structural |
| `approval` derived from coordinator outcome | `ApprovalDerivedFromCoordinator` | derivation |
| Review-class signs only if coordinator approved | `CoordinatorApproveRequiredToSign` | seam (AP2) |
| Every non-approve coordinator outcome rejects | `NonApproveCoordinatorRejects` | seam (refinement) |
| Fail-all yields no signed output | `FailAllProducesNoSignedOutput` | seam (AP6) |
| Hard deny dominates the coordinator | `HardDenyDominatesCoordinator` | seam (I9) |
| Policy outcome binds signing output | `PolicyOutcomeBindsOutput` | bridge (carried) |

The headline is the **end-to-end approval seam**: the coordinator's six terminal
outcomes (Approved, Rejected, TimedOut, Canceled, Failed, NotConsulted) are
mapped to the policy `approval` value, and the module checks that only `Approved`
yields a signed output for a review-class verdict, that every non-approve outcome
rejects, and — most importantly — that a `Failed` outcome (the fail-all
mechanism used for disconnect, displacement, lock, or shutdown) produces no
signed output anywhere in the pipeline. This lifts AP6 and AP2 from the
coordinator into an end-to-end claim and demonstrates the soundness of the
coarser four-valued `approval` oracle that `policy_precedence.tla` uses.

Validated by mutation test: changing `CoordToApproval("Failed")` to `"approve"`
(treating a fail-all as an operator approval) produces a counterexample where a
fail-all'd review-class request signs. The restored spec passes.

## Modeling choices

### One-shot, consuming the coordinator's outcome

`approval_coordinator.tla` is the temporal model that proves *how* the
coordinator reaches each terminal outcome (AP1–AP7). This module consumes
only that *outcome*, so it stays one-shot like `composition.tla`: `Init`
enumerates the inputs and derives the rest, with `Next == UNCHANGED vars`. The
split keeps each concern in its place — the temporal mechanics in
`approval_coordinator.tla`, the end-to-end seam here — and avoids reconciling
temporal-transition state with one-shot Init state inside a single module.

### Consult consistency

`Init` constrains the coordinator outcome to match the verdict: a review-class
verdict (`Review` or `DefaultReview`) yields a real consulted outcome; every
other verdict yields `NotConsulted`. This mirrors the code, where the coordinator
is consulted only when the verdict requires operator input.

### Copied operators

Like `composition.tla`, the sign_boundary and policy_precedence operators are
copied, not imported, because the component modules declare colliding variable
names. Copy drift is checked by `make formal-copy-sync-check`, which also runs
before TLC in `make formal-test`.

## How to check

```sh
make formal-test TLA2TOOLS_JAR=/path/to/tla2tools.jar
```

or directly:

```sh
java -jar tla2tools.jar -config docs/formal/approval_composition.cfg \
    docs/formal/approval_composition.tla
```

Expected: `Model checking completed. No error has been found.`, 47,304 distinct
states, depth 1.

## What this proves vs. doesn't

It proves that, with both the policy verdict and the operator approval derived
(not free), a hard deny always suppresses output, only an operator approval
through the coordinator signs a review-class request, and a fail-all
(regardless of reason) never yields a signed output. It does not re-prove the
coordinator's temporal invariants (those are in `approval_coordinator.tla`) or
the per-slot output rules (in `sign_boundary.tla` / `composition.tla`). As with
the other composed modules, operator-copy drift is checked before TLC by
`make formal-test`.

## Linking back

- Coordinator (temporal): [formal/approval_coordinator.tla](formal/approval_coordinator.tla),
  [FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md](FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md).
- Verdict composition: [formal/composition.tla](formal/composition.tla),
  [FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md).
- Prose refinement: [FORMAL_APPROVAL_COORDINATOR_MODEL.md](FORMAL_APPROVAL_COORDINATOR_MODEL.md),
  "Approval Input Refinement".
