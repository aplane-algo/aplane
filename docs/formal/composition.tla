--------------------------- MODULE composition ---------------------------
(*
Third machine-checkable model in the APlane formalization roadmap (M4).

Joins the sign_boundary and policy_precedence modules: the verdict that
sign_boundary previously treated as a free oracle is here derived by
running policy_precedence on rule matches and operator default. The
joint Init enumerates inputs from both modules and computes the planned
group + signing output as a function of the derived policy outcome.

The new claim this module pins down is the bridge between the two:
sign-boundary output is structurally well-formed when policy outcome =
"signed" and empty when policy outcome = "rejected". This promotes
sign_boundary's DenyOutputSuppression (previously true by construction
of a free-oracle verdict) into a derived consequence of running
policy_precedence on the matches.

The module does not re-state every invariant from the two component
modules. sign_boundary.tla and policy_precedence.tla each run TLC on
their own Init/Safety and check their own internal properties; this
module adds the joint properties that only exist at the seam.

Module operators are copied from the two component modules rather than
imported via EXTENDS / INSTANCE. TLA+'s import mechanisms would force
either variable-name collisions (both modules declare a `verdict`
variable) or extensive renaming machinery. Since both component modules
are small and the operators are pure functions, copying keeps this
module self-contained.

If sign_boundary.tla or policy_precedence.tla changes its operators or
domains, this module must be updated by hand to match. TLC cannot
detect this kind of drift: the three modules are independent specs,
and a stale copy here may still pass against its own (stale)
definitions while the component modules pass against the new ones.
Keeping the three in sync is a code-review responsibility, not a
machine-checked property. If mechanical linkage becomes important,
the right move is to extract shared operators into a fourth module
and have all three modules INSTANCE-import from it.

See FORMAL_TLA_COMPOSITION_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxRequestEntries,  \* upper bound on caller request length (TLC bound)
    MaxDummies          \* upper bound on planner-added dummies (TLC bound)

ASSUME MaxRequestEntries \in Nat /\ MaxRequestEntries >= 1
ASSUME MaxDummies        \in Nat

----------------------------------------------------------------------------
(* Imported (copied) from sign_boundary.tla *)

RequestMode == {"sign", "passthrough", "foreign"}
SlotClass   == {"sign", "passthrough", "foreign", "dummy"}

RequestEntry == [
    mode      : RequestMode,
    signed_id : 1..3
]

ValidRequest(r) ==
    /\ Len(r) >= 1
    /\ ~(\E i,j \in 1..Len(r) :
            r[i].mode = "passthrough" /\ r[j].mode = "foreign")
    /\ ~(\A i \in 1..Len(r) : r[i].mode = "foreign")

PlannedSlot == [
    class  : SlotClass,
    source : 0..MaxRequestEntries
]

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
(* Imported (copied) from policy_precedence.tla *)

RuleMatches == [deny: BOOLEAN, review: BOOLEAN, approve: BOOLEAN]
PolicyVerdict == {"Reject", "Review", "Approve", "DefaultReview", "DefaultApprove"}
Approval    == {"approve", "reject", "timeout", "none"}
Outcome     == {"signed", "rejected"}

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
(* State *)

VARIABLES
    request,            \* sign_boundary input
    dummies,            \* sign_boundary input
    matches,            \* policy_precedence input
    user_auto_approve,  \* policy_precedence input
    approval,           \* policy_precedence input
    policy_verdict,     \* policy_precedence derived
    policy_outcome,     \* policy_precedence derived
    planned,            \* sign_boundary derived
    output              \* sign_boundary derived

vars == <<request, dummies, matches, user_auto_approve, approval,
          policy_verdict, policy_outcome, planned, output>>

----------------------------------------------------------------------------
(* Initial states and stuttering Next *)

\* Init enumerates every (request, dummies, matches, user_auto_approve,
\* approval) combination and derives the rest. The bridge is in the
\* `output` clause: it consults policy_outcome rather than a free
\* oracle verdict.
Init ==
    /\ request \in {r \in BoundedRequests : ValidRequest(r)}
    /\ dummies \in 0..MaxDummies
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ approval \in Approval
    /\ policy_verdict = Decide(matches, user_auto_approve)
    /\ policy_outcome = ApplyApproval(policy_verdict, approval)
    /\ planned = Plan(request, dummies)
    /\ output = IF policy_outcome = "signed"
                THEN SignOutput(request, planned)
                ELSE <<>>

\* One-shot model: every initial state is one accepted (or rejected)
\* end-to-end request execution. There are no transitions.
Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Joint invariants *)

TypeOK ==
    /\ request \in Seq(RequestEntry)
    /\ ValidRequest(request)
    /\ dummies \in 0..MaxDummies
    /\ matches \in RuleMatches
    /\ user_auto_approve \in BOOLEAN
    /\ approval \in Approval
    /\ policy_verdict \in PolicyVerdict
    /\ policy_outcome \in Outcome
    /\ planned \in Seq(PlannedSlot)
    /\ Len(planned) = Len(request) + dummies
    /\ output \in Seq(STRING)

\* The bridging claim: policy outcome flows into signing output.
\* When the policy approves a request, the signer produces output
\* according to sign_boundary's SignOutput rules. When the policy
\* rejects, the signer produces no output.
PolicyOutcomeBindsOutput ==
    /\ (policy_outcome = "signed" =>
            output = SignOutput(request, planned))
    /\ (policy_outcome = "rejected" =>
            output = <<>>)

\* Real I9 over the full pipeline. Any AlwaysDeny match means no
\* signer-produced output, regardless of operator default, approval
\* response, or other tier matches. sign_boundary.tla's
\* DenyOutputSuppression checked this against a free oracle and was
\* true by construction; here it is a derived consequence of running
\* policy_precedence on matches and feeding the outcome into
\* sign_boundary.
HardDenyProducesNoOutput ==
    matches.deny => output = <<>>

\* Symmetric: any signer-produced output requires the policy outcome
\* to be "signed". A non-empty output cannot exist when policy
\* rejected the request.
SignedOutputRequiresPolicyApproval ==
    output # <<>> => policy_outcome = "signed"

\* Sign-boundary's per-slot output rules continue to hold under the
\* derived verdict. Foreign slots remain empty; passthrough bytes
\* remain preserved. These are not new claims, but they should not
\* regress when the verdict source changes from oracle to derivation.
ForeignSlotsEmpty ==
    \/ output = <<>>
    \/ \A i \in 1..Len(planned) :
           planned[i].class = "foreign" => output[i] = ""

PassthroughPreserved ==
    \/ output = <<>>
    \/ \A i \in 1..Len(planned) :
           planned[i].class = "passthrough" =>
               output[i] = "preserved_" \o ToString(request[planned[i].source].signed_id)

Safety ==
    /\ TypeOK
    /\ PolicyOutcomeBindsOutput
    /\ HardDenyProducesNoOutput
    /\ SignedOutputRequiresPolicyApproval
    /\ ForeignSlotsEmpty
    /\ PassthroughPreserved

============================================================================
