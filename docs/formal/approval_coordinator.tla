---------------------- MODULE approval_coordinator ----------------------
(*
Fifth machine-checkable model in the APlane formalization roadmap (M4),
and the machine-checked counterpart to FORMAL_APPROVAL_COORDINATOR_MODEL.md
(Track B2).

It models the runtime approval coordinator's per-request state machine.
Each approval request -- transaction signing or SSH client-access token
provisioning -- moves through Queued (waiting for the single delivery turn)
and Delivered (shown to the one operator, awaiting a decision) to exactly
one terminal outcome: Approved, Rejected, TimedOut, Canceled, Failed, or
(token requests only) Preempted.

Signing has priority over token provisioning: a queued signing request is
delivered before any queued token request, and a delivered token prompt is
withdrawn (Preempted) as soon as a signing request is queued. Token
requests come from unauthenticated SSH clients, so without priority they
could hold the turn for their whole timeout ahead of every signing request.

Several requests interleave over a shared single-delivery turn, with
operator decisions, timeouts, cancellation, and two fail-all events:
operator-client disconnect and operator-client displacement.

Invariants:
  - AP4 : at most one request is delivered to the operator at a time.
  - AP5 : a non-terminal request can always be canceled.
  - AP6 : a fail-all event leaves no delivered (pending) request.
  - AP7 : no delivered request survives replacement of the operator client
          (history flag orphanedDelivery; the displacement regression guard).
  - AP8 : a token request is never delivered while a signing request is
          queued (history flag tokenOvertookSigning).

Liveness (checked by approval_coordinator_liveness.cfg under LiveSpec):
  - Progress : every request that reaches the coordinator (Queued or
    Delivered) eventually reaches a terminal outcome, under fairness on
    Deliver (the delivery loop retries), Timeout (the ApprovalWait timer
    fires), and Preempt (a queued signing request withdraws a delivered
    token prompt). Operator decisions carry no fairness: they are choices, not
    guarantees.

AP1 (single terminal resolution) and AP3 (response-to-request ID binding)
are modeled by construction: terminal states are absorbing (no action
takes a terminal state as its source), and each operator action targets
one request by identity. AP2 (only an operator approve yields Approved)
holds because Approve is the only action producing the Approved state.

The module intentionally omits FIFO fairness of the delivery queue (the
turn is a single token; Progress only asserts eventual termination, not
queue order), real timer durations (timeout is a nondeterministic event),
token-provisioning issuance policy (enrollment and token delivery happen
after Approved), the SSH-side limit of one pending token request (a
refinement that only shrinks the token request set), explicit signer lock, and the policy verdict that decides whether the
operator is consulted at all (FORMAL_POLICY_MODEL.md).
Composing the derived approval outcome with policy_precedence.tla is the
further Track B3 step.

See FORMAL_APPROVAL_COORDINATOR_MODEL.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    SignRequests,    \* transaction-signing request model values, e.g. {s1, s2}
    TokenRequests    \* token-provisioning request model values, e.g. {t1}

ASSUME SignRequests \cap TokenRequests = {}

Requests == SignRequests \cup TokenRequests

----------------------------------------------------------------------------
(* State sets *)

NonTerminal == {"New", "Queued", "Delivered"}
Terminal    == {"Approved", "Rejected", "TimedOut", "Canceled", "Failed", "Preempted"}
ReqState    == NonTerminal \cup Terminal

----------------------------------------------------------------------------
(* Variables *)

VARIABLES
    procState,                    \* function: Requests -> ReqState
    turnHeld,                    \* BOOLEAN: the single delivery turn is held
    badPendingAfterFailAll,      \* BOOLEAN: AP6 regression-guard flag
    orphanedDelivery,            \* BOOLEAN: AP7 regression-guard flag
    tokenOvertookSigning         \* BOOLEAN: AP8 regression-guard flag

vars == <<procState, turnHeld, badPendingAfterFailAll, orphanedDelivery,
          tokenOvertookSigning>>

DeliveredSet == {r \in Requests : procState[r] = "Delivered"}

SigningQueued == \E s \in SignRequests : procState[s] = "Queued"

----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ procState = [r \in Requests |-> "New"]
    /\ turnHeld = FALSE
    /\ badPendingAfterFailAll = FALSE
    /\ orphanedDelivery = FALSE
    /\ tokenOvertookSigning = FALSE

----------------------------------------------------------------------------
(* Request lifecycle actions *)

\* Request models a consult reaching the coordinator: a New request joins
\* the delivery queue.
Request(r) ==
    /\ procState[r] = "New"
    /\ procState' = [procState EXCEPT ![r] = "Queued"]
    /\ UNCHANGED <<turnHeld, badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

\* Deliver takes the single delivery turn and shows the request to the
\* operator. It requires the turn to be free, which is the AP4 serialization
\* guard. A token request is delivered only when no signing request is
\* queued: the coordinator inserts signing waiters ahead of token waiters,
\* and a token request that wins the turn while a signing waiter is queued
\* gives it up before showing a prompt (holdTokenTurn).
\*
\* The tokenOvertookSigning disjunct is the AP8 regression guard. It is
\* FALSE here because of the priority conjunct; dropping that conjunct
\* flips the flag and AP8 fires.
Deliver(r) ==
    /\ procState[r] = "Queued"
    /\ ~turnHeld
    /\ r \in TokenRequests => ~SigningQueued
    /\ turnHeld' = TRUE
    /\ procState' = [procState EXCEPT ![r] = "Delivered"]
    /\ tokenOvertookSigning' = (tokenOvertookSigning \/ (r \in TokenRequests /\ SigningQueued))
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery>>

\* Approve is the operator approving the delivered request; it releases the
\* turn.
Approve(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Approved"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

\* Reject is the operator rejecting the delivered request.
Reject(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "Rejected"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

\* Timeout fires when no operator decision arrives within the request timeout.
Timeout(r) ==
    /\ procState[r] = "Delivered"
    /\ procState' = [procState EXCEPT ![r] = "TimedOut"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

\* Preempt withdraws a delivered token prompt once a signing request is
\* queued. The coordinator notifies the operator client that the prompt was
\* withdrawn before releasing the turn, so the withdrawal and the release
\* are one step and AP4 still holds. The SSH client is told to retry.
Preempt(t) ==
    /\ t \in TokenRequests
    /\ procState[t] = "Delivered"
    /\ SigningQueued
    /\ procState' = [procState EXCEPT ![t] = "Preempted"]
    /\ turnHeld' = FALSE
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

\* Cancel models /sign/cancel (or the SSH client dropping its session). It terminates a request in any non-terminal
\* state -- queued, delivered, or not yet waiting (New) -- and releases the
\* turn only if the request was the delivered one.
Cancel(r) ==
    /\ procState[r] \in NonTerminal
    /\ procState' = [procState EXCEPT ![r] = "Canceled"]
    /\ turnHeld' = IF procState[r] = "Delivered" THEN FALSE ELSE turnHeld
    /\ UNCHANGED <<badPendingAfterFailAll, orphanedDelivery, tokenOvertookSigning>>

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
    /\ UNCHANGED <<orphanedDelivery, tokenOvertookSigning>>

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
    /\ UNCHANGED tokenOvertookSigning

----------------------------------------------------------------------------
(* Next and Spec *)

Next ==
    \/ \E r \in Requests : Request(r)
    \/ \E r \in Requests : Deliver(r)
    \/ \E r \in Requests : Approve(r)
    \/ \E r \in Requests : Reject(r)
    \/ \E r \in Requests : Timeout(r)
    \/ \E r \in Requests : Cancel(r)
    \/ \E t \in TokenRequests : Preempt(t)
    \/ OperatorDisconnect
    \/ Displace

Spec == Init /\ [][Next]_vars

\* Requests of the same kind are interchangeable for the safety invariants;
\* TLC prunes the state space by treating any permutation within a kind as
\* the same state. Signing and token requests are not interchangeable.
RequestSymmetry == Permutations(SignRequests) \cup Permutations(TokenRequests)

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
    /\ tokenOvertookSigning \in BOOLEAN
    /\ \A s \in SignRequests : procState[s] # "Preempted"
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

\* AP8: a token request is never delivered while a signing request is
\* queued. Together with Preempt this bounds how long an unauthenticated
\* client-access request can delay a signing prompt: not past the step that
\* queues the signing request.
AP8_SigningNotOvertaken ==
    ~tokenOvertookSigning

Safety ==
    /\ TypeOK
    /\ AP4_SingleDelivery
    /\ AP5_CancelAlwaysEnabled
    /\ AP6_FailAllLeavesNoPending
    /\ AP7_NoOrphanedDelivery
    /\ AP8_SigningNotOvertaken

----------------------------------------------------------------------------
(* Liveness *)

\* Fairness assumptions for the liveness check (approval_coordinator_liveness.cfg):
\*  - Deliver: the coordinator's delivery loop always retries while a queued
\*    request exists and the turn is free.
\*  - Timeout: the ApprovalWait timer always eventually fires on a delivered
\*    request. This is the only guaranteed exit from Delivered -- operator
\*    Approve/Reject and client Cancel are choices, not guarantees, so they
\*    carry no fairness.
\*  - Preempt: a queued signing request always withdraws a delivered token
\*    prompt (the coordinator closes the token holder's channel).
\* Request carries no fairness either: submitting a consult is the client's
\* choice, which is why Progress is scoped to requests that reached Queued.
Fairness ==
    /\ WF_vars(\E r \in Requests : Deliver(r))
    /\ WF_vars(\E r \in Requests : Timeout(r))
    /\ WF_vars(\E t \in TokenRequests : Preempt(t))

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
