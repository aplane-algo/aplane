# Formal Approval Coordinator Model

> Status: precise English model (M3 companion). Not machine-checked.
> Its machine-checkable counterpart is the planned `approval_coordinator.tla`
> module (see Machine-Checkable Successor); this document defines that module's
> state, transitions, and invariants first.

## Sources

- [ARCH_HTTP_API.md](ARCH_HTTP_API.md): the `/sign` manual-approval wait and the
  `/sign/cancel` endpoint.
- [ARCH_POLICY.md](ARCH_POLICY.md): the verdict model that decides whether the
  operator approval channel is consulted at all.
- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md) and
  [formal/policy_precedence.tla](formal/policy_precedence.tla): the four-valued
  `approval` input this model refines from a free oracle into a derived value.
- [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md): invariant L8 (pending
  approvals fail on successful decommission), whose mechanism this model owns.
- Code: `internal/signerapp/approval/coordinator.go`, `.../approval/types.go`;
  `internal/signerapp/signing/approval.go`;
  `internal/signerapp/identity/runtime.go`.

## Scope

This model covers the runtime approval coordinator for **transaction signing**
approvals:

- the per-request lifecycle from approval request to a single terminal outcome,
- the single-delivery-turn serialization that presents one request to the one
  connected operator client at a time,
- operator approve/reject, timeout, client cancellation (`/sign/cancel`), and
  fail-all (successful decommission or operator-client disconnect),
- how the coordinator's terminal outcomes refine the `approval` input consumed by
  [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md).

Token-provisioning approvals share the same coordinator and the same delivery
queue and behave analogously. This model treats them only where they interact
with signing through shared serialization and fail-all; their issuance policy is
a separate concern.

It does not model:

- IPC/SSH transport reliability or message framing — the send-to-client step is
  an abstract predicate that may succeed or fail,
- real timer durations — timeout is a nondeterministic event, not wall-clock
  time,
- operator decision-making or apadmin UI,
- the policy decision procedure that selects whether to consult the operator
  (that is [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)); this model begins
  at the point a request either consults the operator or is resolved without
  consultation.

## Notation

Relational pseudocode, as in the other `FORMAL_*_MODEL.md` files. `NotApproved`
means no successful approval result is produced (the signer signs nothing for
that request). A request "terminates" when it reaches a terminal outcome;
terminal outcomes are final.

## Abstract Objects

### Sign Approval Request

A `SignApprovalRequest` is identified by a `request_id` and carries the display
fields the operator sees (address, sender, description, validity window, policy
violations). Its observable state is one of:

- `queued` — registered, waiting for the delivery turn,
- `delivered` — holds the delivery turn, sent to the operator client, awaiting a
  response,
- terminal: `approved`, `rejected`, `timed_out`, `canceled`, or `failed`.

### Coordinator State

The coordinator owns, under one lock for the request maps:

- `pending[request_id]` — the response channel for each request currently in the
  `delivered` state (registered after the turn is acquired and the request is
  sent),
- `active[request_id]` — the set of live request contexts that
  `CancelSignRequest` can cancel; one `request_id` may have more than one
  in-flight attempt,
- `canceled[request_id]` — a bounded memory of cancellations that arrived before
  their wait began, consumed when the wait starts,

and, under a separate delivery lock:

- `delivery_in_flight` (bool) and `delivery_queue` (a FIFO of waiters) — the
  single delivery turn, shared across signing and token-provisioning requests.

### Operator Channel

There is at most one connected operator (approver) client. `has_client` reports
whether one is connected; `send_sign_request` delivers a request to it and may
fail; `HandleSignResponse(response)` carries the operator's decision back, keyed
by `request_id`, with `approved ∈ {true, false}`.

### Fail-All Signal

`FailAllPendingRequests(reason)` is a single event that resolves every
then-`delivered` request (signing and token) to not-approved with `reason`,
atomically clearing the pending maps. The runtime raises it on **successful
decommission** (`identity decommissioned`, after the decommission mark) and on
**operator-client disconnect** (`apadmin disconnected`).

## Transitions

### Consult Decision (precondition)

The signer consults the operator only when the policy verdict requires it: a
`review` verdict, or an `approve` verdict without `user_auto_approve`. When the
verdict is `deny`, or `approve` under `user_auto_approve`, the operator channel
is not consulted and the approval input is `none`. This boundary is owned by
[FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md); the transitions below begin
once a consult occurs.

### Request Approval

On a consult the coordinator, in order:

1. rejects an empty `request_id`,
2. if `canceled[request_id]` is set, consumes it and terminates `canceled`
   without delivering,
3. if no operator client is connected, terminates the request not-approved (no
   approval is possible),
4. otherwise acquires the delivery turn.

### Acquire Delivery Turn

A request becomes `delivered` only after taking the single turn. If
`delivery_in_flight` is false and the queue is empty, it takes the turn
immediately; otherwise it joins the FIFO `delivery_queue` and waits. While
queued it can be canceled (its request context is done): it is removed from the
queue, and if it had concurrently been granted the turn it releases the turn.
After acquiring the turn the coordinator re-checks cancellation and client
presence before delivering.

### Deliver

The coordinator registers `pending[request_id]` and sends the request to the
operator client. A send failure terminates the request not-approved (no IPC
delivery).

### Operator Decide

`HandleSignResponse(response)` for a `delivered` `request_id` removes it from
`pending` and delivers the response exactly once. `approved = true` →
`approved`; `approved = false` without a cancellation reason → `rejected`. A
response whose ID is not pending is ignored.

### Timeout

If no response arrives within the request's timeout, the request terminates
`timed_out`, and the coordinator notifies the operator client that the request
is no longer actionable (reason `timeout`).

### Cancel

`CancelSignRequest(request_id, reason)`:

- if the request is `delivered`, removes it from `pending` and delivers a
  cancellation to its channel,
- cancels every `active[request_id]` context, terminating a request that is
  still `queued` or otherwise mid-wait,
- records `canceled[request_id]` so a wait that has not yet begun consumes it,
- returns `canceled` if any of the above applied, else `not_found`.

### Fail-All

`FailAllPendingRequests(reason)` swaps the pending maps to empty and delivers
not-approved (with `reason`) to every previously-`delivered` request. Requests
that already terminated are untouched.

### Release Turn

When a `delivered` request terminates it releases the turn: the next non-canceled
waiter in the FIFO `delivery_queue` is granted the turn; if none remain,
`delivery_in_flight` becomes false.

## Invariants

### AP1: Single Terminal Resolution

Each sign approval request reaches at most one terminal outcome in
`{approved, rejected, timed_out, canceled, failed}`. Once a request terminates,
later events for the same `request_id` — a late operator response, a second
cancel, a fail-all — do not change its outcome. The response channel is removed
from `pending` before any value is delivered, and delivery is non-blocking and
closes the channel, so a response that races a prior terminal outcome is dropped.

### AP2: Only Operator Approve Permits A Signature

A request yields `approved = true` only through an operator approve response
delivered by `HandleSignResponse` for the exact `request_id`. Every other
terminal outcome — operator reject, timeout, client cancel, fail-all — yields
not-approved, and the signer produces no signature for that request. This is the
approval-side half of the composition seam
`SignedOutputRequiresPolicyApproval`.

### AP3: Response Identity Binding

An operator response satisfies a pending request only when its `request_id`
matches. A response carrying a different ID does not resolve any other request.

### AP4: Single Delivery In Flight

At most one approval request is `delivered` (awaiting an operator decision) at
any time. Concurrent requests serialize through the FIFO `delivery_queue`, and
the queue is shared across signing and token-provisioning requests, so the two
kinds never present two prompts at once.

### AP5: Cancellation Reaches Queued, Delivered, And Not-Yet-Waiting Requests

`CancelSignRequest` terminates a request whether it is `queued` (canceled via its
active request context and removed from the delivery queue, releasing the turn if
held), `delivered` (its pending channel receives a cancellation), or has not yet
begun its wait (the cancellation is remembered and consumed when the wait
starts). Cancelling an unknown `request_id` reports `not_found` and resolves
nothing.

### AP6: Fail-All Terminates Every Pending Request (Lifecycle L8)

A single `FailAllPendingRequests(reason)` resolves every then-`delivered`
signing and token request to not-approved with `reason`, clearing the pending
maps atomically; requests that already terminated keep their outcome. This is the
mechanism behind lifecycle invariant
[L8](FORMAL_LIFECYCLE_MODEL.md): on successful decommission the runtime marks
itself decommissioned (after which new approval requests are rejected up front,
per L3) and then fails the pending set, so no approval pending at the mark point
can still resolve `approved`. The same event also fires on operator-client
disconnect.

## Approval Input Refinement

This model derives the `approval` input that
[formal/policy_precedence.tla](formal/policy_precedence.tla) currently treats as
a free oracle, `Approval == {"approve", "reject", "timeout", "none"}`. The
coordinator's terminal outcomes map onto that set as:

| Coordinator outcome | `approval` value | Signature |
|---|---|---|
| operator approve | `approve` | permitted (subject to verdict) |
| operator reject | `reject` | none |
| timeout | `timeout` | none |
| client cancel (`/sign/cancel`) | `reject` (not-approved) | none |
| fail-all (decommission / disconnect) | `reject` (not-approved) | none |
| operator not consulted (auto-approve, or hard deny) | `none` | per verdict |

**Soundness of the four-valued oracle.** Every coordinator outcome that is not
operator-approve denies the signature, so collapsing `{reject, client-cancel,
fail-all}` into `reject` loses no signing-relevant distinction:
`ApplyApproval(v, reject)` is `rejected` for every verdict `v`. The coordinator
keeps the finer distinctions (cancel vs. reject vs. fail) only for operator
notification and error classification (`ErrApprovalCanceled`,
`ErrApprovalTimeout`), not for the sign / no-sign decision. Machine-checking this
refinement against `policy_precedence.tla` — replacing its free oracle with the
derived value — is the composition step deferred to Track B3.

## Assumptions

- At most one operator client is connected at a time (single-operator product);
  `has_client` is a boolean and the model does not represent multiple competing
  approvers.
- The runtime rejects new approval requests once decommissioned (lifecycle L3 and
  the `decommissioned` check in
  `Runtime.RequestSigningApprovalResponseContext`), so fail-all on decommission
  races no new arrivals after the mark.
- Channel delivery is non-blocking and at-most-once: the send helper delivers one
  value and closes the channel, so a late operator response after a terminal
  outcome is discarded rather than blocking or double-resolving.

## Non-Goals

- Transport reliability, message framing, retry, and ordering on the IPC/SSH
  channel.
- Real time: timeout is modeled as a nondeterministic event.
- The operator's decision logic and the apadmin approval UI.
- Token-provisioning issuance policy beyond shared serialization and fail-all.
- The verdict decision procedure that decides whether to consult the operator
  (owned by [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)).

## Code and Test Anchors

| Invariant | Code anchor | Test anchor |
|---|---|---|
| AP1 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (delete-before-deliver); `::trySendSignResponse` (non-blocking, closes) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorLateResponseAfterTimeoutIsIgnored` |
| AP2 | `internal/signerapp/approval/coordinator.go::RequestSigningApprovalResponseContext` (select over response/timeout/ctx); `internal/signerapp/signing/approval.go::requestSigningApproval` (returns `response.Approved`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestDismissesPendingApproval`; `::TestCoordinatorFailAllUnblocksPendingRequest` |
| AP3 | `internal/signerapp/approval/coordinator.go::HandleSignResponse` (keyed by `msg.ID`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorMismatchedResponseIDDoesNotSatisfyActiveRequest` |
| AP4 | `internal/signerapp/approval/coordinator.go::acquireDeliveryTurnContext`; `::releaseDeliveryTurn` (`deliveryInFlight`, `deliveryQueue`) | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorSerializesSigningRequests`; `::TestCoordinatorSerializesAcrossApprovalTypes` |
| AP5 | `internal/signerapp/approval/coordinator.go::CancelSignRequest`; `::BeginSignRequest`; `::consumeCanceledSignRequest` | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorCancelSignRequestBeforeApprovalIsPending`; `::TestCoordinatorQueuedSigningApprovalContextCancelReturnsBeforeDeliveryTurn`; `::TestCoordinatorCancelSignRequestCancelsConcurrentSameIDRequests`; `::TestCoordinatorCancelSignRequestUnknownIsNotFound` |
| AP6 | `internal/signerapp/approval/coordinator.go::FailAllPendingRequests`; raised by `internal/signerapp/identity/runtime.go::Decommission` (`runtime.go:536`) and `internal/signerapp/daemon/ipc.go:163` | `internal/signerapp/approval/coordinator_test.go::TestCoordinatorFailAllClearsPendingMaps`; `::TestCoordinatorFailAllUnblocksPendingRequest`; `internal/signerapp/daemon/hub_test.go::TestFailAllPendingRequests`; `internal/signerapp/identity/identity_test.go::TestDecommissionFailsPendingApprovals` |

## Machine-Checkable Successor

The machine-checkable counterpart is `docs/formal/approval_coordinator.tla`
(Track B2). It will encode this coordinator as a temporal-transition spec in the
style of [formal/lifecycle.tla](formal/lifecycle.tla) — a real `Next` relation
with deliver, operator-decide, timeout, cancel, and fail-all actions over a
bounded set of requests — and machine-check AP1–AP6 and lifecycle L8. Replacing
`policy_precedence.tla`'s free `approval` oracle with the value derived here is a
further composition step (Track B3), which must reconcile temporal-transition
state with the one-shot policy model — the same reconciliation noted for
lifecycle-aware composition.
