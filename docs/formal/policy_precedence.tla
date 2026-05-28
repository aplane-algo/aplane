------------------------- MODULE policy_precedence -------------------------
(*
Second machine-checkable model in the APlane formalization roadmap (M4).

This module formalizes the policy decision procedure from
FORMAL_POLICY_MODEL.md and verifies the precedence ladder by deriving
`verdict` from rule application rather than treating it as an oracle
(which is what `sign_boundary.tla` does).

It is the companion check for the following invariants:

  - P4 : Deny Dominance
  - P5 : Review Dominance Over Approval
  - P6 : Explicit Approval Only After Deny/Review Pass
  - P7 : Operator Default Is Last
  - I9 : Hard Deny Dominance (real check, not by-construction)

The English model treats P4-P7 as `derived` because they follow by
construction from the short-circuit decision procedure. This module
makes that derivation TLC-verified over every valid input combination.

I9 is the centerpiece. The sign-boundary module's `DenyOutputSuppression`
predicate was true by construction of `Init` (output was computed from a
free-oracle verdict). Here `verdict` is derived from rule matches and
`outcome` from `verdict` + approval input, so the claim
"matches.deny => outcome = rejected, regardless of approval or
user_auto_approve" becomes a real property to check.

The model intentionally omits:

  - specific rule families (max_fee, transfer routing, self-noop, etc.):
    rule matches are abstract booleans per tier.
  - rule-ID selection when multiple rules in the same tier match.
  - transfer routing internals (a routing deny is just an AlwaysDeny
    match for the precedence ladder).
  - passthrough/foreign slot exclusion (P8): checked in
    sign_boundary.tla via slot classes.
  - approval coordinator state machine (timeout transitions,
    cancellations, mid-flight decommission). The approval channel is a
    coarse four-valued input here.
  - planned request shape: rule matches are an abstract function of
    "whatever the planned group looks like."
  - snapshot stability (P1, P2): requires modeling reload as a
    transition; separate concern.

If those concerns become security-critical for a particular check, add
a separate module rather than extending this one.

See FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md for the prose companion.
*)
EXTENDS Naturals, FiniteSets, TLC

----------------------------------------------------------------------------
(* Domains *)

\* Rule-tier match flags. Each tier is either matched or not, abstractly,
\* over the planned request. The model enumerates every 2^3 combination,
\* including the "all three tiers match" case that P4-P6 exclude.
RuleMatches == [deny: BOOLEAN, review: BOOLEAN, approve: BOOLEAN]

\* The five possible verdicts from the decision procedure. The first
\* three are policy verdicts; the last two are the operator-default
\* fallback used when no policy verdict applies.
Verdict == {"Reject", "Review", "Approve", "DefaultReview", "DefaultApprove"}

\* The operator approval channel as seen by the signer.
\*   "approve"  : operator approved the request.
\*   "reject"   : operator explicitly rejected the request.
\*   "timeout"  : approval waited and never received a response.
\*   "none"     : no approval channel was consulted for this verdict.
\* All non-"approve" values produce a rejected outcome for review-class
\* verdicts. The distinction between reject/timeout/none is preserved so
\* future audit-trail invariants can use them; the precedence properties
\* themselves do not depend on which non-approve value is supplied.
Approval == {"approve", "reject", "timeout", "none"}

\* The final outcome after verdict + approval are applied.
Outcome == {"signed", "rejected"}

----------------------------------------------------------------------------
(* Decision procedure *)

\* Decide implements the short-circuit decision procedure from
\* FORMAL_POLICY_MODEL.md "Decision Procedure":
\*   1. Always Deny  -> Reject
\*   2. Always Review -> Review
\*   3. Always Approve -> Approve
\*   4. Operator Default (user_auto_approve)
\*
\* The precedence Always Deny > Always Review > Always Approve >
\* Operator Default is encoded by the IF/ELSE IF ordering.
Decide(matches, auto_approve) ==
    IF matches.deny THEN "Reject"
    ELSE IF matches.review THEN "Review"
    ELSE IF matches.approve THEN "Approve"
    ELSE IF auto_approve THEN "DefaultApprove"
    ELSE "DefaultReview"

\* ApplyApproval maps (verdict, approval) -> outcome.
\*
\* Reject, Approve, and DefaultApprove are determined by the verdict
\* alone. Review and DefaultReview require an "approve" response; any
\* other value (reject, timeout, none) yields a rejected outcome.
ApplyApproval(v, a) ==
    CASE v = "Reject"         -> "rejected"
      [] v = "Approve"        -> "signed"
      [] v = "DefaultApprove" -> "signed"
      [] v = "Review"         -> IF a = "approve" THEN "signed" ELSE "rejected"
      [] v = "DefaultReview"  -> IF a = "approve" THEN "signed" ELSE "rejected"

----------------------------------------------------------------------------
(* State *)

VARIABLES
    matches,            \* RuleMatches: which tiers matched
    user_auto_approve,  \* BOOLEAN: operator default
    approval,           \* Approval: operator channel response
    verdict,            \* Verdict: derived from matches + user_auto_approve
    outcome             \* Outcome: derived from verdict + approval

vars == <<matches, user_auto_approve, approval, verdict, outcome>>

----------------------------------------------------------------------------
(* Initial states and stuttering Next *)

\* Init enumerates every combination of:
\*   - rule-tier matches (2^3 = 8)
\*   - user_auto_approve (2)
\*   - approval response (4)
\* Total: 64 initial states. verdict and outcome are derived; their
\* values are not enumerated, they are determined by the inputs.
Init ==
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ approval \in Approval
    /\ verdict = Decide(matches, user_auto_approve)
    /\ outcome = ApplyApproval(verdict, approval)

\* One-shot model: every initial state describes one accepted (or
\* rejected) signing decision. There are no transitions. If a future
\* invariant requires reasoning across multiple decisions (e.g. an
\* operator changing user_auto_approve between requests), this will
\* need real next-state transitions.
Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ approval \in Approval
    /\ verdict \in Verdict
    /\ outcome \in Outcome

\* P4: Deny Dominance.
\* Any AlwaysDeny match rejects the request before approval and cannot
\* be overridden by any later phase.
P4_DenyDominance ==
    matches.deny => verdict = "Reject" /\ outcome = "rejected"

\* P5: Review Dominance Over Approval.
\* If no AlwaysDeny matches and at least one AlwaysReview matches,
\* manual review is required. AlwaysApprove cannot skip the prompt.
\* Note: this asserts verdict = "Review", not outcome — review can be
\* operator-approved into a signed outcome.
P5_ReviewDominance ==
    ~matches.deny /\ matches.review => verdict = "Review"

\* P6: Explicit Approval Only After Deny/Review Pass.
\* AlwaysApprove signs without manual review only when no AlwaysDeny or
\* AlwaysReview matched.
P6_ApproveAfterDenyReview ==
    ~matches.deny /\ ~matches.review /\ matches.approve =>
        verdict = "Approve" /\ outcome = "signed"

\* P7: Operator Default Is Last.
\* The operator default is reached only when no policy verdict matched.
\* user_auto_approve=true -> DefaultApprove (auto-sign).
\* user_auto_approve=false -> DefaultReview (require operator).
P7_OperatorDefaultLast ==
    /\ (~matches.deny /\ ~matches.review /\ ~matches.approve =>
            verdict \in {"DefaultReview", "DefaultApprove"})
    /\ (~matches.deny /\ ~matches.review /\ ~matches.approve /\ user_auto_approve =>
            verdict = "DefaultApprove")
    /\ (~matches.deny /\ ~matches.review /\ ~matches.approve /\ ~user_auto_approve =>
            verdict = "DefaultReview")

\* I9: Hard Deny Dominance (centerpiece).
\* Stated independently of verdict so it's checked regardless of how
\* later phases or approvals could in principle alter the outcome.
\* Even if matches.review is also true, even if approval = "approve",
\* even if user_auto_approve = true: a deny match rejects.
I9_HardDenyDominance ==
    matches.deny => outcome = "rejected"

\* ApprovalResolution: full verdict-to-outcome table.
\* P4-P7 constrain the verdict alone; I9 constrains outcome only for
\* deny matches. This invariant pins down what every (verdict, approval)
\* pair must resolve to. Without it, a regression in ApplyApproval (for
\* example, ApplyApproval("Review", "approve") returning "rejected")
\* would not be caught by the precedence invariants.
ApprovalResolution ==
    /\ verdict = "Reject"                       => outcome = "rejected"
    /\ verdict \in {"Approve", "DefaultApprove"} => outcome = "signed"
    /\ verdict \in {"Review", "DefaultReview"}   =>
            (outcome = "signed" <=> approval = "approve")

Safety ==
    /\ TypeOK
    /\ P4_DenyDominance
    /\ P5_ReviewDominance
    /\ P6_ApproveAfterDenyReview
    /\ P7_OperatorDefaultLast
    /\ I9_HardDenyDominance
    /\ ApprovalResolution

============================================================================
