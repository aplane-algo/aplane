---------------------- MODULE plugin_signing ----------------------
(*
Tenth machine-checkable model in the APlane formalization roadmap (M4),
and the machine-checked counterpart to FORMAL_PLUGIN_SIGNING_MODEL.md.

It machine-checks the plugin signing trust boundary's decision procedure:
which combinations of validation outcomes and gate decisions allow a
plugin-produced transaction group to reach submission.

  - PS2 : group digest integrity — a pregrouped group submits only if the
          recomputed group ID matches the embedded digest (and the group
          has valid size / uniform group field).
  - PS3 : mandatory decoded review, fail-closed — pregrouped-signed
          submits only on an explicit interactive approval; the
          non-interactive outcome never submits.
  - PS4 : plan preservation — presign-plan submits only if every slot's
          canonical transaction preserved the draft (group ID and fee
          excepted).
  - PS5 : signed-slot byte match and index discipline — presign-plan
          submits only if every plugin-returned slot byte-matches its
          canonical transaction and the returned index set is exact.
  - PS6 : managed slots are approval-gated — presign-plan submits only
          with apsigner approval over the canonical group.
  - PS7 : no ungated submission — every submission carries the operator
          review (pregrouped) or the apsigner approval (presign-plan).

PS1 (constructor byte binding) is structural — a property of the Go type
(unexported fields, sole constructor) — and is not restated as a TLC
predicate.

Like sign_boundary.tla this is a ONE-SHOT spec: Init enumerates every
combination of mode, per-slot validation outcomes, and gate decisions;
Next is UNCHANGED. The Submitted decision procedure is a transcription of
the code's accept/reject logic (apshellcli/external_plugins.go,
engine/plugin_pregrouped.go, engine/plugin_presign.go); a dropped check
surfaces as a counterexample, confirmed by the documented mutations
(removing the digest conjunct violates PS2; removing the review conjunct
violates PS3/PS7).

Validation outcomes are abstracted to booleans the standard way: the model
checks the CHECKS and their gating, not msgpack or cryptography. Honest
gaps (no local signature verification, fee exemption from preservation,
self-consistent malicious groups, non-canonical encoding) are documented
in FORMAL_PLUGIN_SIGNING_MODEL.md and deliberately not claimed here.

See FORMAL_TLA_PLUGIN_SIGNING_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS MaxSlots   \* presign-plan group size bound (TLC bound)

ASSUME MaxSlots \in Nat /\ MaxSlots >= 2

----------------------------------------------------------------------------
(* Domains *)

\* The pregrouped-signed client review outcome. "noninteractive" is the
\* AutoConfirm/MCP context, which must fail closed.
Review == {"approved", "rejected", "noninteractive"}

\* The presign-plan client review outcome. Unlike pregrouped-signed, the
\* display-only draft review proceeds without a prompt in non-interactive
\* contexts ("auto") because apsigner is the authoritative gate.
ClientReview == {"approved", "rejected", "auto"}

\* apsigner's approval decision over the canonical group.
Approval == {"approved", "denied"}

\* A pregrouped-signed submission attempt: group-shape validity (size
\* 2..MaxTxGroupSize, uniform non-zero group field), the group-ID
\* recomputation outcome, and the review outcome.
PregroupedCase == [
    mode     : {"pregrouped_signed"},
    shapeOK  : BOOLEAN,
    digestOK : BOOLEAN,
    review   : Review
]

\* Presign-plan slots: plugin-owned (signed by the plugin callback against
\* the canonical bytes) or managed (signed by apsigner). planPreserved is
\* the draft-vs-canonical comparison with Group and Fee zeroed; txnMatch is
\* the plugin-returned slot's byte match against the canonical transaction.
PluginSlot  == [owner : {"plugin"},  planPreserved : BOOLEAN, txnMatch : BOOLEAN]
ManagedSlot == [owner : {"managed"}, planPreserved : BOOLEAN]
Slot == PluginSlot \cup ManagedSlot

BoundedSlots ==
    UNION { [1..n -> Slot] : n \in 2..MaxSlots }

\* Presign-plan requires at least one plugin slot and at least one managed
\* slot (all-plugin groups are told to use pregrouped-signed).
ValidPresignSlots(sl) ==
    /\ \E i \in 1..Len(sl) : sl[i].owner = "plugin"
    /\ \E i \in 1..Len(sl) : sl[i].owner = "managed"

\* A presign-plan submission attempt: the slots, the plugin-response index
\* discipline (exact count, no duplicate or unexpected indices, every
\* declared signer owns a slot), the client draft review, apsigner's
\* pre-grouped digest recomputation, and apsigner's approval.
PresignCase == [
    mode          : {"presign_plan"},
    slots         : {sl \in BoundedSlots : ValidPresignSlots(sl)},
    indexOK       : BOOLEAN,
    clientReview  : ClientReview,
    signerDigestOK : BOOLEAN,
    approval      : Approval
]

Case == PregroupedCase \cup PresignCase

----------------------------------------------------------------------------
(* The submission decision procedure — a transcription of the code. *)

\* Pregrouped-signed (engine/plugin_pregrouped.go + apshellcli
\* reviewPregroupedSigned): decode/shape/digest validation, then mandatory
\* interactive review; RequiresApproval is ignored; non-interactive fails
\* closed; submission is byte-verbatim (PS1, structural).
PregroupedSubmitted(c) ==
    /\ c.shapeOK
    /\ c.digestOK
    /\ c.review = "approved"

\* Presign-plan (engine/plugin_presign.go + plugin_signing.go): plan
\* preservation on every slot, byte match on every plugin slot, index
\* discipline, client draft review not rejected, apsigner's pre-grouped
\* digest recomputation, and apsigner approval for the managed slots.
PresignSubmitted(c) ==
    /\ \A i \in 1..Len(c.slots) : c.slots[i].planPreserved
    /\ \A i \in 1..Len(c.slots) :
           c.slots[i].owner = "plugin" => c.slots[i].txnMatch
    /\ c.indexOK
    /\ c.clientReview # "rejected"
    /\ c.signerDigestOK
    /\ c.approval = "approved"

Submitted(c) ==
    IF c.mode = "pregrouped_signed" THEN PregroupedSubmitted(c)
                                    ELSE PresignSubmitted(c)

----------------------------------------------------------------------------
(* State *)

VARIABLES
    kase,       \* the enumerated submission attempt
    submitted   \* whether bytes reached submission

vars == <<kase, submitted>>

Init ==
    /\ kase \in Case
    /\ submitted = Submitted(kase)

Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ kase \in Case
    /\ submitted \in BOOLEAN

\* PS2: no submission without group digest integrity (pregrouped client
\* check; apsigner's independent recomputation in presign-plan).
PS2_GroupDigestVerified ==
    submitted =>
        IF kase.mode = "pregrouped_signed"
        THEN kase.shapeOK /\ kase.digestOK
        ELSE kase.signerDigestOK

\* PS3: pregrouped submission requires an explicit interactive approval;
\* in particular the non-interactive outcome never submits (fail-closed).
PS3_MandatoryReviewFailClosed ==
    (submitted /\ kase.mode = "pregrouped_signed") =>
        /\ kase.review = "approved"
        /\ kase.review # "noninteractive"

\* PS4: presign submission preserved every slot through /plan.
PS4_PlanPreserved ==
    (submitted /\ kase.mode = "presign_plan") =>
        \A i \in 1..Len(kase.slots) : kase.slots[i].planPreserved

\* PS5: presign submission byte-matched every plugin slot and the returned
\* index set was exact.
PS5_SignedSlotByteMatch ==
    (submitted /\ kase.mode = "presign_plan") =>
        /\ \A i \in 1..Len(kase.slots) :
               kase.slots[i].owner = "plugin" => kase.slots[i].txnMatch
        /\ kase.indexOK

\* PS6: presign submission carries apsigner approval.
PS6_ManagedApprovalGated ==
    (submitted /\ kase.mode = "presign_plan") =>
        kase.approval = "approved"

\* PS7 (central): every submission passed a human gate — the operator's
\* decoded review (pregrouped) or apsigner's approval pipeline (presign).
PS7_NoUngatedSubmission ==
    submitted =>
        \/ kase.mode = "pregrouped_signed" /\ kase.review = "approved"
        \/ kase.mode = "presign_plan"      /\ kase.approval = "approved"

Safety ==
    /\ TypeOK
    /\ PS2_GroupDigestVerified
    /\ PS3_MandatoryReviewFailClosed
    /\ PS4_PlanPreserved
    /\ PS5_SignedSlotByteMatch
    /\ PS6_ManagedApprovalGated
    /\ PS7_NoUngatedSubmission

============================================================================
