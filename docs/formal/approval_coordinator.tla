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

Several requests interleave over a shared single-delivery turn, with
operator decisions, timeouts, cancellation, and two fail-all events:
operator-client disconnect and operator-client displacement.

Invariants:
  - AP4 : at most one request is delivered to the operator at a time.
  - AP5 : a non-terminal request can always be canceled.
  - AP6 : a fail-all event leaves no delivered (pending) request.
  - AP7 : no delivered request survives replacement of the operator client
          (history flag orphanedDelivery; the displacement regression guard).

Liveness (checked by approval_coordinator_liveness.cfg under LiveSpec):
  - Progress : every request that reaches the coordinator (Queued or
    Delivered) eventually reaches a terminal outcome, under fairness on
    Deliver (the delivery loop retries), Timeout (the ApprovalWait timer
    fires). Operator decisions carry no fairness: they are choices, not
    guarantees.

AP1 (single terminal resolution) and AP3 (response-to-request ID binding)
are modeled by construction: terminal states are absorbing (no action
takes a terminal state as its source), and each operator action targets
one request by identity. AP2 (only an operator approve yields Approved)
holds because Approve is the only action producing the Approved state.

The module intentionally omits FIFO fairness of the delivery queue (the
turn is a single token; Progress only asserts eventual termination, not
queue order), real timer durations (timeout is a nondeterministic event),
token-provisioning issuance policy (it shares the same turn and fail-all),
explicit signer lock, and the policy verdict that decides whether the
operator is consulted at all (FORMAL_POLICY_MODEL.md).
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
    turnHeld,                    \* BOOLEAN: the single delivery turn is held
    badPendingAfterFailAll,      \* BOOLEAN: AP6 regression-guard flag
    orphanedDelivery             \* BOOLEAN: AP7 regression-guard flag

vars == <<procState, turnHeld, badPendingAfterFailAll, orphanedDelivery>>

DeliveredSet == {r \in Requests : procState[r] = "Delivered"}

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ procState = [r \in Requests |-> "New"]
    /\ turnHeld = FALSE
    /\ badPendingAfterFailAll = FALSE
    /\ orphanedDelivery = FALSE

----------------------------------------------------------------------------
(* Request lifecycle actions *)

\* Request models a consult reaching the coordinator: a New request joins
\* the delivery queue.
Request(r) ==
    /\ procState[r] = "New"
    /\ procState' = [procState EXCEPT ![r] = "Queued"]
    /\ UNCHANGED <<turnHeld, badPendingAfterFailAll, orphanedDelivery>>

\* Deliver takes the single delivery turn and shows the request to the
\* operator. It requires the turn to be free, which is the AP4 serialization
\* guard.
Deliver(r) ==
    /\ procState[r] = "Queued"
    /\ ~turnHeld
    /\ turnHeld' = TRUE
    /\ procState' = [procState EXCEPT ![r] = "Delivered"]
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* Approve is the operator approving the delivered request; it releases the
\* turn.
Approve(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Approved"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* Reject is the operator rejecting the delivered request.
Reject(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Rejected"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* Timeout fires when no operator decision arrives within the request timeout.
Timeout(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "TimedOut"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* Cancel models /sign/cancel. It terminates a request in any non-terminal
\* state -- queued, delivered, or not yet waiting (New) -- and releases the
\* turn only if the request was the delivered one.
Cancel(r) ==
    /\ procState[r] \in NonTerminal
    /\ procState' = [procState EXCEPT ![r] = "Canceled"]
    /\ turnHeld' = IF procState[r] = "Delivered" THEN FALSE ELSE turnHeld
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* OperatorDisconnect models the apadmin client dropping: FailAllPendingRequests
\* fails the (single) delivered request and releases the turn. Later requests
\* may still proceed.
OperatorDisconnect ==
    /\ DeliveredSet # {}
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
    /\ badPendingAfterFailAll' =
        (badPendingAfterFailAll \/ \E r \in Requests : procState'[r] = "Delivered")
    /\ UNCHANGED orphanedDelivery

\* Displace models a new apadmin client replacing the active one after the
\* operator confirms displacement (daemon/ipc.go calls
\* FailAllPendingApprovals("apadmin displaced") before DisplaceSession).
\* A delivered prompt was shown to the OLD client only -- the replacement
\* has no way to render or answer it -- so it must be failed in the same
\* step that the client is replaced. Otherwise the prompt is orphaned: it
\* holds the delivery turn, invisible to the new client, and every later
\* request queues behind it until the timer frees the turn.
\*
\* The orphanedDelivery disjunct is the AP7 regression guard. It is
\* tautologically FALSE here because
\* the delivered request is failed by this same action. If a future edit
\* lets a delivered request survive client replacement, the flag flips and
\* AP7 fires.
Displace ==
    /\ DeliveredSet # {}
    /\ procState' = [r \in Requests |->
                        IF procState[r] = "Delivered" THEN "Failed" ELSE procState[r]]
    /\ turnHeld' = FALSE
    /\ badPendingAfterFailAll' =
        (badPendingAfterFailAll \/ \E r \in Requests : procState'[r] = "Delivered")
    /\ orphanedDelivery' = (orphanedDelivery \/ \E r \in Requests : procState'[r] = "Delivered")

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
    /\ badPendingAfterFailAll \in BOOLEAN
    /\ orphanedDelivery \in BOOLEAN
    /\ turnHeld <=> (DeliveredSet # {})

\* AP4: at most one request is delivered to the operator at a time.
AP4_SingleDelivery ==
    Cardinality(DeliveredSet) <= 1

\* AP5: a non-terminal request can always be canceled.
AP5_CancelAlwaysEnabled ==
    \A r \in Requests : procState[r] \in NonTerminal => ENABLED Cancel(r)

\* AP6: neither fail-all action may leave a delivered request behind. The
\* sticky flag makes a one-step mutation visible in all successor states.
AP6_FailAllLeavesNoPending ==
    ~badPendingAfterFailAll

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
    /\ AP6_FailAllLeavesNoPending
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
\* Request carries no fairness either: submitting a consult is the client's
\* choice, which is why Progress is scoped to requests that reached Queued.
Fairness ==
    /\ WF_vars(\E r \in Requests : Deliver(r))
    /\ WF_vars(\E r \in Requests : Timeout(r))

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
