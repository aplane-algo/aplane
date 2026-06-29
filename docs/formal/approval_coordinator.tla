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

AP1 (single terminal resolution) and AP3 (response-to-request ID binding)
are modeled by construction: terminal states are absorbing (no action
takes a terminal state as its source), and each operator action targets
one request by identity. AP2 (only an operator approve yields Approved)
holds because Approve is the only action producing the Approved state.

The module intentionally omits FIFO fairness of the delivery queue (a
liveness property; the turn is a single token), real timer durations
(timeout is a nondeterministic event), token-provisioning issuance policy
(it shares the same turn and fail-all), and the policy verdict that decides
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
    badApproveAfterDecommission   \* BOOLEAN: L8 regression-guard flag

vars == <<procState, turnHeld, decommissioned, badApproveAfterDecommission>>

DeliveredSet == {r \in Requests : procState[r] = "Delivered"}

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ procState = [r \in Requests |-> "New"]
    /\ turnHeld = FALSE
    /\ decommissioned = FALSE
    /\ badApproveAfterDecommission = FALSE

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
    /\ UNCHANGED <<turnHeld, decommissioned, badApproveAfterDecommission>>

\* Deliver takes the single delivery turn and shows the request to the
\* operator. It requires the turn to be free, which is the AP4 serialization
\* guard. Disabled once decommissioned.
Deliver(r) ==
    /\ procState[r] = "Queued"
    /\ ~turnHeld
    /\ ~decommissioned
    /\ turnHeld' = TRUE
    /\ procState' = [procState EXCEPT ![r] = "Delivered"]
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission>>

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
    /\ badApproveAfterDecommission' = badApproveAfterDecommission \/ decommissioned
    /\ UNCHANGED <<decommissioned>>

\* Reject is the operator rejecting the delivered request.
Reject(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Rejected"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission>>

\* Timeout fires when no operator decision arrives within the request timeout.
Timeout(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "TimedOut"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission>>

\* Cancel models /sign/cancel. It terminates a request in any non-terminal
\* state -- queued, delivered, or not yet waiting (New) -- and releases the
\* turn only if the request was the delivered one.
Cancel(r) ==
    /\ procState[r] \in NonTerminal
    /\ procState' = [procState EXCEPT ![r] = "Canceled"]
    /\ turnHeld' = IF procState[r] = "Delivered" THEN FALSE ELSE turnHeld
    /\ UNCHANGED <<decommissioned, badApproveAfterDecommission>>

\* OperatorDisconnect models the apadmin client dropping: FailAllPendingRequests
\* fails the (single) delivered request and releases the turn. The signer is
\* not decommissioned, so later requests may still proceed.
OperatorDisconnect ==
    /\ DeliveredSet # {}
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
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
    /\ UNCHANGED <<badApproveAfterDecommission>>

\* FailQueuedWhileDecommissioned drains a request still queued when the signer
\* is decommissioned: it can never be delivered, so it fails.
FailQueuedWhileDecommissioned(r) ==
    /\ decommissioned
    /\ procState[r] = "Queued"
    /\ procState' = [procState EXCEPT ![r] = "Failed"]
    /\ UNCHANGED <<turnHeld, decommissioned, badApproveAfterDecommission>>

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

Safety ==
    /\ TypeOK
    /\ AP4_SingleDelivery
    /\ AP5_CancelAlwaysEnabled
    /\ AP6_DecommissionLeavesNoPending
    /\ L8_NoApproveAfterDecommission

============================================================================
