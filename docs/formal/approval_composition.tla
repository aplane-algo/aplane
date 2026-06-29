----------------------- MODULE approval_composition -----------------------
(*
Sixth machine-checkable model in the APlane formalization roadmap (M4),
and the Track B3 step that completes the approval seam.

composition.tla derived the policy `verdict` (which sign_boundary treats
as a free oracle) from rule matches, but still treated the operator
`approval` channel as a free four-valued oracle. This module replaces that
free oracle with the *terminal outcome* of the approval coordinator modeled
in approval_coordinator.tla: the coordinator outcome (Approved, Rejected,
TimedOut, Canceled, Failed, or NotConsulted) is mapped to the policy
approval value and fed end to end into the planned-group signing output.

The coordinator is consulted only when the verdict is review-class (Review
or DefaultReview); for every other verdict it is NotConsulted. The
coordinator's own temporal invariants (AP1-AP6 and lifecycle L8 -- single
delivery, single resolution, fail-all, no-approval-after-decommission) are
machine-checked in approval_coordinator.tla; this module consumes only the
terminal outcome, so it stays one-shot like composition.tla. The new claims
live at the seam between that outcome and the signing pipeline.

New seam invariants:
  - CoordinatorApproveRequiredToSign : a review-class request signs only if
    the coordinator outcome is Approved (AP2 lifted to the pipeline).
  - NonApproveCoordinatorRejects : every non-approve coordinator outcome
    (Rejected, TimedOut, Canceled, Failed) yields a rejected policy outcome
    -- the refinement that makes policy_precedence's coarser four-valued
    oracle sound.
  - FailAllProducesNoSignedOutput : a fail-all outcome (the L8 mechanism:
    operator-client disconnect or successful decommission) yields no signed
    output end to end.
  - HardDenyDominatesCoordinator : an AlwaysDeny match yields no output,
    regardless of the coordinator outcome (I9 with the coordinator in the
    loop).

The per-slot sign_boundary rules (foreign slots empty, passthrough
preserved) are unchanged by the approval source and are checked in
sign_boundary.tla and composition.tla; they are not re-stated here.

Operators are copied from sign_boundary.tla, policy_precedence.tla, and
composition.tla rather than imported, for the same reason composition.tla
copies them (both component modules declare colliding variable names under
EXTENDS/INSTANCE). Keeping the copies in sync with the component modules is
a code-review responsibility, not a machine-checked property.

See FORMAL_APPROVAL_COORDINATOR_MODEL.md and
FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md (Extension plan) for context.
*)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxRequestEntries,  \* upper bound on caller request length (TLC bound)
    MaxDummies          \* upper bound on planner-added dummies (TLC bound)

ASSUME MaxRequestEntries \in Nat /\ MaxRequestEntries >= 1
ASSUME MaxDummies        \in Nat

----------------------------------------------------------------------------
(* Copied from sign_boundary.tla *)

RequestMode == {"sign", "passthrough", "foreign"}
SlotClass   == {"sign", "passthrough", "foreign", "dummy"}

RequestEntry == [ mode : RequestMode, signed_id : 1..3 ]

ValidRequest(r) ==
    /\ Len(r) >= 1
    /\ ~(\E i,j \in 1..Len(r) :
            r[i].mode = "passthrough" /\ r[j].mode = "foreign")
    /\ ~(\A i \in 1..Len(r) : r[i].mode = "foreign")

PlannedSlot == [ class : SlotClass, source : 0..MaxRequestEntries ]

Plan(r, d) ==
    [i \in 1..(Len(r) + d) |->
        IF i <= Len(r)
        THEN [class |-> r[i].mode,  source |-> i]
        ELSE [class |-> "dummy",    source |-> 0]
    ]

SignOutput(r, p) ==
    [i \in 1..Len(p) |->
        CASE p[i].class = "sign"        -> "signed_" \o ToString(i)
          [] p[i].class = "passthrough" -> "preserved_" \o ToString(r[p[i].source].signed_id)
          [] p[i].class = "foreign"     -> ""
          [] p[i].class = "dummy"       -> "dummy_signed_" \o ToString(i)]

BoundedRequests ==
    UNION { [1..n -> RequestEntry] : n \in 1..MaxRequestEntries }

----------------------------------------------------------------------------
(* Copied from policy_precedence.tla *)

RuleMatches   == [deny: BOOLEAN, review: BOOLEAN, approve: BOOLEAN]
PolicyVerdict == {"Reject", "Review", "Approve", "DefaultReview", "DefaultApprove"}
Approval      == {"approve", "reject", "timeout", "none"}
Outcome       == {"signed", "rejected"}

Decide(matches, auto_approve) ==
    IF matches.deny THEN "Reject"
    ELSE IF matches.review THEN "Review"
    ELSE IF matches.approve THEN "Approve"
    ELSE IF auto_approve THEN "DefaultApprove"
    ELSE "DefaultReview"

ApplyApproval(v, a) ==
    CASE v = "Reject"         -> "rejected"
      [] v = "Approve"        -> "signed"
      [] v = "DefaultApprove" -> "signed"
      [] v = "Review"         -> IF a = "approve" THEN "signed" ELSE "rejected"
      [] v = "DefaultReview"  -> IF a = "approve" THEN "signed" ELSE "rejected"

----------------------------------------------------------------------------
(* Approval-coordinator terminal outcome -> policy approval input *)

\* The terminal outcome of the approval coordinator (the OUTPUT of
\* approval_coordinator.tla) for one request. NotConsulted means the verdict
\* did not require operator input, so the coordinator was never asked.
CoordinatorOutcome ==
    {"Approved", "Rejected", "TimedOut", "Canceled", "Failed", "NotConsulted"}

\* The coordinator is consulted only for review-class verdicts.
ConsultRequired(v) == v \in {"Review", "DefaultReview"}

ConsultedOutcomes == {"Approved", "Rejected", "TimedOut", "Canceled", "Failed"}

\* Map a coordinator terminal outcome to the policy approval value. Every
\* non-approve outcome -- operator reject, timeout, /sign/cancel, and fail-all
\* (operator-client disconnect or successful decommission) -- maps to a
\* not-approved value; only Approved maps to "approve". This mapping is the
\* refinement that makes policy_precedence's four-valued oracle sound.
CoordToApproval(co) ==
    CASE co = "Approved"     -> "approve"
      [] co = "Rejected"     -> "reject"
      [] co = "TimedOut"     -> "timeout"
      [] co = "Canceled"     -> "reject"
      [] co = "Failed"       -> "reject"
      [] co = "NotConsulted" -> "none"

----------------------------------------------------------------------------
(* State *)

VARIABLES
    request,            \* sign_boundary input
    dummies,            \* sign_boundary input
    matches,            \* policy_precedence input
    user_auto_approve,  \* policy_precedence input
    coordOutcome,       \* approval_coordinator terminal outcome (input here)
    policy_verdict,     \* derived
    approval,           \* derived from coordOutcome (no longer a free oracle)
    policy_outcome,     \* derived
    planned,            \* derived
    output              \* derived

vars == <<request, dummies, matches, user_auto_approve, coordOutcome,
          policy_verdict, approval, policy_outcome, planned, output>>

----------------------------------------------------------------------------
(* Initial states and stuttering Next *)

\* Init enumerates the inputs and derives the rest. coordOutcome is
\* constrained to be consistent with whether the verdict requires a consult:
\* a review-class verdict yields a real consulted outcome; any other verdict
\* yields NotConsulted. approval is derived from coordOutcome, not free.
Init ==
    /\ request \in {r \in BoundedRequests : ValidRequest(r)}
    /\ dummies \in 0..MaxDummies
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ policy_verdict = Decide(matches, user_auto_approve)
    /\ coordOutcome \in (IF ConsultRequired(policy_verdict)
                         THEN ConsultedOutcomes
                         ELSE {"NotConsulted"})
    /\ approval = CoordToApproval(coordOutcome)
    /\ policy_outcome = ApplyApproval(policy_verdict, approval)
    /\ planned = Plan(request, dummies)
    /\ output = IF policy_outcome = "signed"
                THEN SignOutput(request, planned)
                ELSE <<>>

\* One-shot model: each initial state is one end-to-end request execution,
\* with both the verdict and the approval derived rather than free.
Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ request \in Seq(RequestEntry)
    /\ ValidRequest(request)
    /\ dummies \in 0..MaxDummies
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ coordOutcome \in CoordinatorOutcome
    /\ policy_verdict \in PolicyVerdict
    /\ approval \in Approval
    /\ policy_outcome \in Outcome
    /\ planned \in Seq(PlannedSlot)
    /\ Len(planned) = Len(request) + dummies
    /\ output \in Seq(STRING)

\* The coordinator is consulted exactly for review-class verdicts.
ConsultedIffReview ==
    ConsultRequired(policy_verdict) <=> (coordOutcome # "NotConsulted")

\* approval is the coordinator's outcome, not a free oracle.
ApprovalDerivedFromCoordinator ==
    approval = CoordToApproval(coordOutcome)

\* AP2 at the seam: a review-class request produces signed output only when
\* the coordinator outcome is Approved.
CoordinatorApproveRequiredToSign ==
    (ConsultRequired(policy_verdict) /\ output # <<>>) =>
        coordOutcome = "Approved"

\* The refinement soundness: every non-approve coordinator outcome -- reject,
\* timeout, cancel, fail-all -- yields a rejected policy outcome.
NonApproveCoordinatorRejects ==
    coordOutcome \in {"Rejected", "TimedOut", "Canceled", "Failed"} =>
        policy_outcome = "rejected"

\* L8 at the seam: a fail-all outcome (operator-client disconnect or
\* successful decommission) yields no signed output end to end.
FailAllProducesNoSignedOutput ==
    coordOutcome = "Failed" => output = <<>>

\* I9 with the coordinator in the loop: an AlwaysDeny match yields no output,
\* regardless of the coordinator outcome.
HardDenyDominatesCoordinator ==
    matches.deny => output = <<>>

\* Carried bridge from composition.tla: policy outcome flows to signing
\* output -- signed outcomes produce the planned output, rejected produce none.
PolicyOutcomeBindsOutput ==
    /\ (policy_outcome = "signed"   => output = SignOutput(request, planned))
    /\ (policy_outcome = "rejected" => output = <<>>)

Safety ==
    /\ TypeOK
    /\ ConsultedIffReview
    /\ ApprovalDerivedFromCoordinator
    /\ CoordinatorApproveRequiredToSign
    /\ NonApproveCoordinatorRejects
    /\ FailAllProducesNoSignedOutput
    /\ HardDenyDominatesCoordinator
    /\ PolicyOutcomeBindsOutput

============================================================================
