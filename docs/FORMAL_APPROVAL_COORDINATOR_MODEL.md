# Approval Coordinator Model

Status: implemented and machine-checked by
[`formal/approval_coordinator.tla`](formal/approval_coordinator.tla).

## Scope

The approval coordinator serializes delivery to one operator. A request moves
from `New` to `Queued` to `Delivered`, then to exactly one terminal state:
`Approved`, `Rejected`, `TimedOut`, `Canceled`, or `Failed`.

The model includes operator decisions, timeout, cancellation, operator-client
disconnect, and authenticated client displacement. Disconnect and displacement
are modeled as reason-independent fail-all actions. Runtime lock, server
shutdown, and other production callers use the same
`Coordinator.FailAllPendingRequests` mechanism and therefore share the same Go
contract even though their reason strings are not separate model states.

## Claims

| ID | Claim | Model operator |
|---|---|---|
| AP1 | A request has one terminal resolution. | terminal states are absorbing |
| AP2 | Only an operator approval yields `Approved`. | `Approve` |
| AP3 | A decision is bound to its request ID. | request-indexed actions |
| AP4 | At most one request is delivered. | `AP4_SingleDelivery` |
| AP5 | Every non-terminal request can be canceled. | `AP5_CancelAlwaysEnabled` |
| AP6 | Every modeled fail-all leaves no delivered request. | `AP6_FailAllLeavesNoPending` |
| AP7 | Displacement cannot orphan a delivered request. | `AP7_NoOrphanedDelivery` |

AP6 uses the sticky `badPendingAfterFailAll` history flag. Both
`OperatorDisconnect` and `Displace` update it from the post-action delivered
set, so a mutation that lets a prompt survive either fail-all action remains
visible to TLC. AP7 separately records whether displacement orphaned a prompt;
it retains the security-specific head-of-line blocking regression guard.

## Liveness

`LiveSpec` assumes weak fairness for `Deliver` and `Timeout`. Under those
runtime guarantees, every request that reaches `Queued` or `Delivered`
eventually reaches a terminal state. Operator approve/reject and client cancel
are choices and intentionally carry no fairness.

Safety runs use request symmetry. Liveness runs do not, because symmetry
reduction is unsound for TLC temporal checking. The normal and deep safety and
liveness configurations are all recorded in `formal/metrics*.json`.

## Implementation anchors

- `internal/signerapp/approval/coordinator.go`: serialized request delivery,
  cancellation, terminal resolution, and `FailAllPendingRequests`.
- `internal/signerapp/approval/coordinator_test.go`:
  `TestCoordinatorFailAllClearsPendingMaps` and
  `TestCoordinatorFailAllUnblocksPendingRequest`.
- `internal/signerapp/daemon/hub_test.go`: daemon-level fail-all forwarding.
- `internal/signerapp/daemon/ipc.go`: displacement fails pending approvals
  before changing the active operator session.
- `internal/signerapp/signing/service_test.go`:
  `TestSignGroupWithPlanStopsBeforeExecute` proves a rejected final-execution
  gate produces no signer output.

The end-to-end mapping from approval outcome to signing output is checked in
[`formal/approval_composition.tla`](formal/approval_composition.tla). A
`Failed` coordinator outcome is not approval and produces no signed output,
independent of whether the production reason was disconnect, displacement,
lock, or shutdown.

## Run

```bash
make formal-test
make formal-test-deep
```
