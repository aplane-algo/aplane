---------------------- MODULE approval_coordinator ----------------------
(*
Fifth machine-checkable model in the APlane formalization roadmap (M4),
and the machine-checked counterpart to FORMAL_APPROVAL_COORDINATOR_MODEL.md
(Track B2).

It models the runtime approval coordinator's per-request state machine.
Each transaction-signing approval request moves through Queued (waiting
for the single delivery turn) and Delivered (shown to the one operator,
awaiting a decision) to exactly one terminal outcome: Approved, Rejected,
TimedOut, Canceled, or Failed.

Like lifecycle.tla (and unlike the three one-shot specs), this module has
real transitions in Next: several requests interleave over a shared
single-delivery turn, with operator decisions, timeouts, cancellation,
operator-client disconnect (fail-all), and decommission (mark + fail-all).

Invariants:
  - AP4 : at most one request is delivered to the operator at a time.
  - AP5 : a non-terminal request can always be canceled.
  - AP6 : decommission leaves no delivered (pending) request.
  - L8  : no request is approved once the signer is decommissioned
          (history flag badApproveAfterDecommission, the regression guard).
  - AP7 : no delivered request survives replacement of the operator client
          (history flag orphanedDelivery; the displacement regression guard).

Liveness (checked by approval_coordinator_liveness.cfg under LiveSpec):
  - Progress : every request that reaches the coordinator (Queued or
    Delivered) eventually reaches a terminal outcome, under fairness on
    Deliver (the delivery loop retries), Timeout (the ApprovalWait timer
    fires), and FailQueuedWhileDecommissioned (the decommission drain
    completes). Operator decisions carry no fairness: they are choices,
    not guarantees.

AP1 (single terminal resolution) and AP3 (response-to-request ID binding)
are modeled by construction: terminal states are absorbing (no action
takes a terminal state as its source), and each operator action targets
one request by identity. AP2 (only an operator approve yields Approved)
holds because Approve is the only action producing the Approved state.

The module intentionally omits FIFO fairness of the delivery queue (the
turn is a single token; Progress only asserts eventual termination, not
queue order), real timer durations (timeout is a nondeterministic event),
token-provisioning issuance policy (it shares the same turn and fail-all),
explicit lock (handled by lifecycle.tla; its FailAllPendingApprovals call
behaves like OperatorDisconnect here), and the policy verdict that decides
whether the operator is consulted at all (FORMAL_POLICY_MODEL.md).
Composing the derived approval outcome with policy_precedence.tla is the
further Track B3 step.

See FORMAL_APPROVAL_COORDINATOR_MODEL.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Requests   \* set of approval-request model values, e.g. {r1, r2, r3}

----------------------------------------------------------------------------
(* State sets *)

NonTerminal == {"New", "Queued", "Delivered"}
Terminal    == {"Approved", "Rejected", "TimedOut", "Canceled", "Failed"}
ReqState    == NonTerminal \cup Terminal

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    procState,                    \* function: Requests -> ReqState
    turnHeld,                     \* BOOLEAN: the single delivery turn is held
    decommissioned,               \* BOOLEAN
    badApproveAfterDecommission,  \* BOOLEAN: L8 regression-guard flag
    orphanedDelivery              \* BOOLEAN: AP7 regression-guard flag

vars == <<procState, turnHeld, decommissioned, badApproveAfterDecommission,
          orphanedDelivery>>

DeliveredSet == {r \in Requests : procState[r] = "Delivered"}

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ procState = [r \in Requests |-> "New"]
    /\ turnHeld = FALSE
    /\ decommissioned = FALSE
    /\ badApproveAfterDecommission = FALSE
    /\ orphanedDelivery = FALSE

----------------------------------------------------------------------------
(* Request lifecycle actions *)

\* Request models a consult reaching the coordinator: a New request joins
\* the delivery queue. Disabled once decommissioned, because the runtime
\* rejects new approval requests up front (lifecycle L3), so no new pending
\* can appear after the decommission mark.
Request(r) ==
    /\ procState[r] = "New"
    /\ ~decommissioned
    /\ procState' = [procState EXCEPT ![r] = "Queued"]
    /\ UNCHANGED <<turnHeld, decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* Deliver takes the single delivery turn and shows the request to the
\* operator. It requires the turn to be free, which is the AP4 serialization
\* guard. Disabled once decommissioned.
Deliver(r) ==
    /\ procState[r] = "Queued"
    /\ ~turnHeld
    /\ ~decommissioned
    /\ turnHeld' = TRUE
    /\ procState' = [procState EXCEPT ![r] = "Delivered"]
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* Approve is the operator approving the delivered request; it releases the
\* turn. The badApproveAfterDecommission disjunct is the load-bearing L8
\* regression guard: it is tautologically FALSE here, because a delivered
\* request cannot coexist with decommissioned (Decommission fails the
\* delivered request and blocks further delivery), so the flag stays FALSE.
\* If a future edit lets a decommissioned signer hold or deliver a request
\* through to approval, this assignment flips the flag and L8 fires.
Approve(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Approved"]
    /\ turnHeld' = FALSE
    /\ badApproveAfterDecommission' = (badApproveAfterDecommission \/ decommissioned)
    /\ UNCHANGED <<decommissioned, orphanedDelivery>>

\* Reject is the operator rejecting the delivered request.
Reject(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Rejected"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* Timeout fires when no operator decision arrives within the request timeout.
Timeout(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "TimedOut"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* Cancel models /sign/cancel. It terminates a request in any non-terminal
\* state -- queued, delivered, or not yet waiting (New) -- and releases the
\* turn only if the request was the delivered one.
Cancel(r) ==
    /\ procState[r] \in NonTerminal
    /\ procState' = [procState EXCEPT ![r] = "Canceled"]
    /\ turnHeld' = IF procState[r] = "Delivered" THEN FALSE ELSE turnHeld
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* OperatorDisconnect models the apadmin client dropping: FailAllPendingRequests
\* fails the (single) delivered request and releases the turn. The signer is
\* not decommissioned, so later requests may still proceed.
OperatorDisconnect ==
    /\ DeliveredSet # {}
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

\* Displace models a new apadmin client replacing the active one after the
\* operator confirms displacement (daemon/ipc.go calls
\* FailAllPendingApprovals("apadmin displaced") before DisplaceSession).
\* A delivered prompt was shown to the OLD client only -- the replacement
\* has no way to render or answer it -- so it must be failed in the same
\* step that the client is replaced. Otherwise the prompt is orphaned: it
\* holds the delivery turn, invisible to the new client, and every later
\* request queues behind it until the timer frees the turn.
\*
\* The orphanedDelivery disjunct is the AP7 regression guard (same pattern
\* as badApproveAfterDecommission): it is tautologically FALSE here because
\* the delivered request is failed by this same action. If a future edit
\* lets a delivered request survive client replacement, the flag flips and
\* AP7 fires.
Displace ==
    /\ DeliveredSet # {}
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
    /\ orphanedDelivery' = (orphanedDelivery \/ \E r \in Requests : procState'[r] = "Delivered")
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission>>

\* Decommission models successful decommission: mark decommissioned, then fail
\* the pending (delivered) request via FailAllPendingApprovals. Afterwards
\* Request and Deliver are disabled, so no request can be delivered or approved.
Decommission ==
    /\ ~decommissioned
    /\ decommissioned' = TRUE
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badApproveAfterDecommission, orphanedDelivery>>

\* FailQueuedWhileDecommissioned drains a request still queued when the signer
\* is decommissioned: it can never be delivered, so it fails.
FailQueuedWhileDecommissioned(r) ==
    /\ decommissioned
    /\ procState[r] = "Queued"
    /\ procState' = [procState EXCEPT ![r] = "Failed"]
    /\ UNCHANGED <<turnHeld, decommissioned, badApproveAfterDecommission,
                   orphanedDelivery>>

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E r \in Requests : Request(r)
    \/ \E r \in Requests : Deliver(r)
    \/ \E r \in Requests : Approve(r)
    \/ \E r \in Requests : Reject(r)
    \/ \E r \in Requests : Timeout(r)
    \/ \E r \in Requests : Cancel(r)
    \/ OperatorDisconnect
    \/ Displace
    \/ Decommission
    \/ \E r \in Requests : FailQueuedWhileDecommissioned(r)

Spec == Init /\ [][Next]_vars

\* Requests are interchangeable for the safety invariants; TLC prunes the
\* state space by treating any permutation of requests as the same state.
RequestSymmetry == Permutations(Requests)

----------------------------------------------------------------------------
(* Invariants *)

\* TypeOK pins each variable to its domain and ties the redundant turn token
\* to the per-request state: the turn is held exactly when one request is
\* delivered. Drift between turnHeld and the delivered set would otherwise
\* slip past the higher-level checks.
TypeOK ==
    /\ procState \in [Requests -> ReqState]
    /\ turnHeld \in BOOLEAN
    /\ decommissioned \in BOOLEAN
    /\ badApproveAfterDecommission \in BOOLEAN
    /\ orphanedDelivery \in BOOLEAN
    /\ turnHeld <=> (DeliveredSet # {})

\* AP4: at most one request is delivered to the operator at a time.
AP4_SingleDelivery ==
    Cardinality(DeliveredSet) <= 1

\* AP5: a non-terminal request can always be canceled.
AP5_CancelAlwaysEnabled ==
    \A r \in Requests : procState[r] \in NonTerminal => ENABLED Cancel(r)

\* AP6: after decommission, no request is delivered (pending). The pending
\* request at the mark point was failed and no new delivery is possible.
AP6_DecommissionLeavesNoPending ==
    decommissioned => DeliveredSet = {}

\* L8: no request is approved once the signer is decommissioned. The flag
\* stays FALSE under the current guards; it flips if a future edit lets a
\* decommissioned signer hold or deliver a request through to approval.
L8_NoApproveAfterDecommission ==
    ~badApproveAfterDecommission

\* AP7: no delivered request survives replacement of the operator client.
\* The flag stays FALSE because Displace fails the delivered request in the
\* same step; it flips if a future edit lets the prompt outlive its client
\* (the pre-fix displacement orphan, which head-of-line-blocked every later
\* approval until the ApprovalWait timer freed the turn).
AP7_NoOrphanedDelivery ==
    ~orphanedDelivery

Safety ==
    /\ TypeOK
    /\ AP4_SingleDelivery
    /\ AP5_CancelAlwaysEnabled
    /\ AP6_DecommissionLeavesNoPending
    /\ L8_NoApproveAfterDecommission
    /\ AP7_NoOrphanedDelivery

----------------------------------------------------------------------------
(* Liveness *)

\* Fairness assumptions for the liveness check (approval_coordinator_liveness.cfg):
\*  - Deliver: the coordinator's delivery loop always retries while a queued
\*    request exists and the turn is free.
\*  - Timeout: the ApprovalWait timer always eventually fires on a delivered
\*    request. This is the only guaranteed exit from Delivered -- operator
\*    Approve/Reject and client Cancel are choices, not guarantees, so they
\*    carry no fairness.
\*  - FailQueuedWhileDecommissioned: the decommission drain completes.
\* Request carries no fairness either: submitting a consult is the client's
\* choice, which is why Progress is scoped to requests that reached Queued.
Fairness ==
    /\ WF_vars(\E r \in Requests : Deliver(r))
    /\ WF_vars(\E r \in Requests : Timeout(r))
    /\ WF_vars(\E r \in Requests : FailQueuedWhileDecommissioned(r))

LiveSpec == Spec /\ Fairness

\* Progress: every request that reaches the coordinator eventually reaches a
\* terminal outcome. This is the head-of-line-blocking guard in temporal
\* form: because requests are one-shot and the turn is released by every
\* terminal transition, the only way to violate it is a state that can
\* stutter forever with a request stuck in Queued or Delivered. Dropping
\* the Timeout fairness conjunct is the documented mutation: TLC then
\* reports a lasso where a delivered request never resolves -- the model's
\* way of saying the timer is the only guaranteed exit from Delivered.
Progress ==
    \A r \in Requests :
        (procState[r] \in {"Queued", "Delivered"}) ~> (procState[r] \in Terminal)

============================================================================
