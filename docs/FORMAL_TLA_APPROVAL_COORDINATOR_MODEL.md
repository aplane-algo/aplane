# TLA+ Approval Coordinator Model

The executable model is
[`formal/approval_coordinator.tla`](formal/approval_coordinator.tla); the design
and code anchors are in
[`FORMAL_APPROVAL_COORDINATOR_MODEL.md`](FORMAL_APPROVAL_COORDINATOR_MODEL.md).

## Configurations

| Configuration | Purpose |
|---|---|
| `approval_coordinator.cfg` | normal safety run with request symmetry |
| `approval_coordinator_deep.cfg` | deeper safety run with request symmetry |
| `approval_coordinator_liveness.cfg` | normal `Progress` run without symmetry |
| `approval_coordinator_liveness_deep.cfg` | deeper `Progress` run without symmetry |

`Safety` checks `TypeOK`, AP4, AP5, AP6, and AP7. AP1–AP3 hold by
construction: terminal states are absorbing, only `Approve` produces
`Approved`, and every decision action names its request.

AP6 is mutation-sensitive. `badPendingAfterFailAll` is updated by every
modeled fail-all action from the post-action delivered set, and
`AP6_FailAllLeavesNoPending` requires that sticky flag to remain false. AP7
uses its own sticky flag because surviving client displacement is also a
session-ownership and queue-visibility failure.

`LiveSpec` adds weak fairness for `Deliver` and `Timeout`; `Progress` requires
every queued or delivered request eventually to become terminal. The removed
per-identity decommission drain is not part of the single-product runtime and
therefore supplies neither state nor a fairness assumption.

Run both inventories with:

```bash
make formal-test
make formal-test-deep
```

Recorded state counts live in `formal/metrics.json` and
`formal/metrics_deep.json` and must change in the same commit as model edits.
