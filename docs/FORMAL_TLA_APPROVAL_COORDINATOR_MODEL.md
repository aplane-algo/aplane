# TLA+ Approval Coordinator Model

> Status: TLC checked across four recorded configurations: `Safety` at 1,464
> distinct states (depth 13) normal and 4,681 (depth 16) deep, and `Progress`
> liveness at 552 distinct states (depth 10) normal and 4,776 (depth 13) deep,
> with no counterexamples. `docs/formal/metrics.json` and
> `docs/formal/metrics_deep.json` remain the authoritative run inventory.

> **Drift note (October 2026):** the production coordinator serves signing
> requests only; SSH client enrollment is queued on disk and never takes the
> delivery turn. The token requests, `Preempt`, and AP8 below describe
> behavior the code no longer has. The model has not yet been reduced; see
> the drift note in `FORMAL_APPROVAL_COORDINATOR_MODEL.md`.

The executable model is
[`formal/approval_coordinator.tla`](formal/approval_coordinator.tla); the design
and code anchors are in
[`FORMAL_APPROVAL_COORDINATOR_MODEL.md`](FORMAL_APPROVAL_COORDINATOR_MODEL.md).

## Configurations

| Configuration | Purpose |
|---|---|
| `approval_coordinator.cfg` | normal safety run, 2 signing + 2 token requests, per-kind symmetry |
| `approval_coordinator_deep.cfg` | deeper safety run, 3 signing + 2 token requests, per-kind symmetry |
| `approval_coordinator_liveness.cfg` | normal `Progress` run, 2 signing + 1 token request, no symmetry |
| `approval_coordinator_liveness_deep.cfg` | deeper `Progress` run, 2 signing + 2 token requests, no symmetry |

`Safety` checks `TypeOK`, AP4, AP5, AP6, AP7, and AP8. AP1–AP3 hold by
construction: terminal states are absorbing, only `Approve` produces
`Approved`, and every decision action names its request.

AP6 is mutation-sensitive. `badPendingAfterFailAll` is updated by every
modeled fail-all action from the post-action delivered set, and
`AP6_FailAllLeavesNoPending` requires that sticky flag to remain false. AP7
uses its own sticky flag because surviving client displacement is also a
session-ownership and queue-visibility failure.

AP8 is mutation-sensitive too. `Deliver` sets the sticky
`tokenOvertookSigning` flag when it delivers a token request while a signing
request is queued; the priority conjunct keeps it false. Dropping that
conjunct makes TLC report a Safety violation. `Preempt` withdraws a delivered
token prompt in the same step that releases the turn, so AP4 holds across
preemption.

`LiveSpec` adds weak fairness for `Deliver`, `Timeout`, and `Preempt`; `Progress` requires
every queued or delivered request eventually to become terminal. The
single-product runtime has no identity-decommission drain, so the model has no
corresponding state or fairness assumption.

Run both inventories with:

```bash
make formal-test
make formal-test-deep
```

Recorded state counts live in `docs/formal/metrics.json` and
`docs/formal/metrics_deep.json` and must change in the same commit as model edits.
