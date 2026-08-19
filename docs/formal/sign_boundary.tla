---------------------------- MODULE sign_boundary ----------------------------
(*
First machine-checkable model in the APlane formalization roadmap (M4).

This module formalizes a narrow slice of the transaction-planning and
signing boundary: enough to state and check the following invariants from
FORMAL_TXN_PLANNING_MODEL.md:

  - I1  : Mode Totality (encoded as a structural type)
  - I2  : Passthrough-Foreign Exclusion (via ValidRequest)
  - I3  : All-Foreign Rejection (via ValidRequest)
  - I7  : Foreign Slots Are Never Signed
  - I8  : Passthrough Byte Preservation
  - M4  : every signer-produced output belongs to a sign-mode slot, a
          signer-generated dummy slot, an unchanged passthrough slot,
          or is the empty string at a foreign slot.

This module does NOT prove I9 (Hard Deny Dominance). The `verdict`
variable is a free oracle, not derived from policy rule tiers, so the
weaker DenyOutputSuppression invariant below is true by construction of
Init — it does not show that an Always Deny match cannot be overridden
by approval. Real I9 verification requires a separate module that
derives verdicts from rule application (planned for the M4 extension
step "Policy precedence").

The model intentionally omits:

  - cryptography (signature correctness, address derivation),
  - msgpack decode and Algorand transaction layout,
  - post-signing client routing to algod submission or simulation,
  - approval coordinator state (always-review, operator decision),
  - server shutdown ordering and runtime destruction,
  - LogicSig budget, fee adjustment, group-id recomputation,
  - HTTP authentication and fixed runtime binding,
  - filesystem reload ordering.

If those concerns become security-critical for a particular check,
add a separate module rather than extending this one.

See FORMAL_TLA_SIGN_BOUNDARY_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxRequestEntries,  \* upper bound on caller request length (TLC bound)
    MaxDummies          \* upper bound on planner-added dummies (TLC bound)

ASSUME MaxRequestEntries \in Nat /\ MaxRequestEntries >= 1
ASSUME MaxDummies        \in Nat

----------------------------------------------------------------------------
(* Modes and slot classes *)

\* The caller's per-entry mode trichotomy.
RequestMode == {"sign", "passthrough", "foreign"}

\* Finalized group positions add a fourth class for server-added dummies.
SlotClass   == {"sign", "passthrough", "foreign", "dummy"}

----------------------------------------------------------------------------
(* Request entries and the request *)

\* `signed_id` is an opaque token standing in for `signed_txn_hex` on
\* passthrough entries. The model never inspects bytes; it only checks
\* preservation by token equality.
RequestEntry == [
    mode      : RequestMode,
    signed_id : 1..3
]

\* Validity rules from FORMAL_TXN_PLANNING_MODEL.md Mode Validation:
\* I2 (passthrough/foreign exclusion) and I3 (no all-foreign).
ValidRequest(r) ==
    /\ Len(r) >= 1
    /\ ~(\E i,j \in 1..Len(r) :
            r[i].mode = "passthrough" /\ r[j].mode = "foreign")
    /\ ~(\A i \in 1..Len(r) : r[i].mode = "foreign")

----------------------------------------------------------------------------
(* Planning *)

\* A finalized position remembers its slot class and, for non-dummy
\* positions, the originating request index. Server-added dummies have
\* source = 0.
PlannedSlot == [
    class  : SlotClass,
    source : 0..MaxRequestEntries
]

\* Plan(r, d) appends d dummy slots after the caller positions in order.
\* This abstracts away the planner's decision of *how many* dummies to add;
\* the model only constrains the shape, not the budget logic.
Plan(r, d) ==
    [i \in 1..(Len(r) + d) |->
        IF i <= Len(r)
        THEN [class |-> r[i].mode,  source |-> i]
        ELSE [class |-> "dummy",    source |-> 0]
    ]

----------------------------------------------------------------------------
(* Signing output *)

\* Per the planning model's Signing Output Rules, the output array
\* aligns 1:1 with finalized positions, with class-determined content.
\* String values are opaque tokens used only for equality checks.
SignOutput(r, p) ==
    [i \in 1..Len(p) |->
        CASE p[i].class = "sign"        -> "signed_" \o ToString(i)
          [] p[i].class = "passthrough" -> "preserved_" \o ToString(r[p[i].source].signed_id)
          [] p[i].class = "foreign"     -> ""
          [] p[i].class = "dummy"       -> "dummy_signed_" \o ToString(i)]

----------------------------------------------------------------------------
(* State *)

VARIABLES
    request,       \* the caller's request
    dummies,       \* planner-added dummy count
    verdict,       \* "deny" or "approve"
    planned,       \* finalized planned group
    output         \* /sign output array, or <<>> when verdict = "deny"

vars == <<request, dummies, verdict, planned, output>>

----------------------------------------------------------------------------
(* Initial state: every valid (request, dummies, verdict) combination *)

\* Bounded set of caller request sequences. `Seq(RequestEntry)` would
\* be infinite; this is the TLC-friendly truncation.
BoundedRequests ==
    UNION { [1..n -> RequestEntry] : n \in 1..MaxRequestEntries }

Init ==
    /\ request \in {r \in BoundedRequests : ValidRequest(r)}
    /\ dummies \in 0..MaxDummies
    /\ verdict \in {"deny", "approve"}
    /\ planned = Plan(request, dummies)
    /\ output  = IF verdict = "approve" THEN SignOutput(request, planned)
                                        ELSE <<>>

\* No transitions; every initial state describes one accepted
\* (or denied) sign-request execution.
Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

\* I1 : Mode Totality
\* Every caller-request entry has exactly one mode. Encoded structurally:
\* RequestEntry.mode is drawn from RequestMode, which is a partition.

TypeOK ==
    /\ request \in Seq(RequestEntry)
    /\ ValidRequest(request)
    /\ dummies \in 0..MaxDummies
    /\ verdict \in {"deny", "approve"}
    /\ planned \in Seq(PlannedSlot)
    /\ Len(planned) = Len(request) + dummies
    /\ output \in Seq(STRING)

\* I7 : Foreign Slots Are Never Signed
ForeignSlotsEmpty ==
    \/ output = <<>>
    \/ \A i \in 1..Len(planned) :
           planned[i].class = "foreign" => output[i] = ""

\* I8 : Passthrough Byte Preservation
PassthroughPreserved ==
    \/ output = <<>>
    \/ \A i \in 1..Len(planned) :
           planned[i].class = "passthrough" =>
               output[i] = "preserved_" \o ToString(request[planned[i].source].signed_id)

\* DenyOutputSuppression: a "deny" verdict produces empty output.
\* This is NOT I9 (Hard Deny Dominance). I9 requires that no approval
\* path can override an Always Deny match; here `verdict` is a free
\* oracle, so the invariant is true by construction of Init. A future
\* module that derives verdicts from rule tiers can promote this to a
\* real I9 statement.
DenyOutputSuppression ==
    verdict = "deny" => output = <<>>

\* Alignment: output length matches finalized positions when present.
OutputAligned ==
    output # <<>> => Len(output) = Len(planned)

\* M4 first target invariant
\* Every signer-produced output is either:
\*   - a signature on a sign-mode slot, or
\*   - a signature on a signer-generated dummy slot, or
\*   - a verbatim passthrough preservation, or
\*   - the empty string at a foreign slot.
SignerOutputBelongsToOwnedClass ==
    output # <<>> =>
        \A i \in 1..Len(output) :
            \/ (output[i] # "" /\ planned[i].class \in {"sign", "dummy"})
            \/ (output[i] # "" /\ planned[i].class = "passthrough"
                              /\ output[i] = "preserved_" \o ToString(request[planned[i].source].signed_id))
            \/ (output[i] = "" /\ planned[i].class = "foreign")

\* The conjunction the model should preserve.
Safety ==
    /\ TypeOK
    /\ ForeignSlotsEmpty
    /\ PassthroughPreserved
    /\ DenyOutputSuppression
    /\ OutputAligned
    /\ SignerOutputBelongsToOwnedClass

============================================================================
