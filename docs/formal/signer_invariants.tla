-------------------------- MODULE signer_invariants --------------------------
(*
The signer invariants and where they stand in the gate sequence, and a
cosigner document's external checks after them.

internal/signerapp/signing/gate.go::runApprovalGates and
cosigner_policy.go::runCosignerGates call
invariant_gate.go::rejectSignerInvariants before any policy verdict and
before any approval. An invariant is not a policy setting: no rule, no User
Auto-Approve and no operator approval lifts it.

Two kinds of invariant differ in the positions they judge:

  - the valid rekey target invariant judges every position of the group as
    it will go on chain: the positions this signer signs, passthrough,
    foreign and contextual positions, and the signer's own dummies. The
    signer puts no signature into a group that makes one of its aplane keys
    that is not a valid rekey target an account's authority.
  - the rotating rekey and nonparticipation invariants judge the positions
    this signer signs.

On a cosigner, runCosignerGates ends with
external_checks.go::runExternalChecks: once the invariants have passed and
the policy verdict is sign, the document's external checks run, and they can
only refuse. Nothing is looked up for a request the invariants or the policy
refused. A signer-role request and a cosigner document without checks have
no external checks and make no lookup.

Invariants:

  - SI1 : no signature is released for a group in which any position rekeys
          an account to a held aplane key that is not a valid rekey target.
  - SI2 : no signature is released for a group in which a position this
          signer signs breaks a signed-position invariant.
  - SI3 : a group an invariant refuses reaches neither the policy verdict
          nor the operator.
  - SI4 : a refusal by the valid-target invariant names the first position
          that breaks it.
  - SI5 : no signature is released for a request unless the policy would
          sign it and its external checks, if it has any, pass. The external
          answer can remove a signature, never add one.
  - SI6 : a request the invariants or the policy refuse makes no external
          lookup.
  - SI7 : a group whose cross-slot network parameters are invalid (mismatched
          genesis hashes or non-overlapping validity windows) reaches neither
          policy, external lookups, nor signature release.

`policy_precedence.tla` derives the policy verdict and `sign_boundary.tla`
the output per slot class; here the policy and the operator are one free
oracle (would_sign), since the claim is that the invariants hold whatever
they answer. The external checks are a second free oracle (external): none,
pass or refuse, where none stands for a request with no external checks.

The model intentionally omits:

  - which key set the valid-target invariant reads (the key snapshot the
    request was planned with; a Go test pins it),
  - the rotating invariant as a check of its own: every rotating aplane key
    records that it is not a valid rekey target, so the valid-target
    invariant refuses such a rekey first, and the rotating check is a second
    line folded into the signed-position flag here,
  - the cosigner's key lookup, which runs before the invariants there, and
    transaction bounds validation, which runs before both,
  - what the external checks look up, how many lookups a request makes, and
    the order the checks run in (the runner stops at the first refusal); a
    lookup that fails, a node that cannot run its document's checks, a lock
    and a canceled request all end the step without a signature, so each is
    the answer refuse here,
  - the key use the external step holds while it runs, which is
    key_use_lock.tla's subject.

See FORMAL_TLA_SIGNER_INVARIANTS_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
    MaxPositions,               \* upper bound on the group's length (TLC bound)
    InvariantsBeforePolicy,     \* the invariants run before the policy verdict
    TargetJudgesEveryPosition,  \* the valid-target invariant reads every position
    ExternalAfterPolicy,        \* external lookups follow a sign verdict only
    NetworkParamsBeforeGates    \* cross-slot genesis/window check runs first

ASSUME MaxPositions \in Nat /\ MaxPositions >= 1
ASSUME InvariantsBeforePolicy \in BOOLEAN
ASSUME TargetJudgesEveryPosition \in BOOLEAN
ASSUME ExternalAfterPolicy \in BOOLEAN
ASSUME NetworkParamsBeforeGates \in BOOLEAN

\* A position of the group as it will go on chain. "sign" is a position this
\* signer signs; the others are not its signatures.
SlotClass == {"sign", "passthrough", "foreign", "contextual", "dummy"}

Position == [
    class : SlotClass,
    invalid_target : BOOLEAN,   \* rekeys to a held aplane key that is not a
                                \* valid rekey target
    signed_breach : BOOLEAN     \* a nonparticipating keyreg or a rekey to a
                                \* rotating account
]

Groups == UNION {[1..n -> Position] : n \in 1..MaxPositions}

\* What the request's external checks would answer. "none": it has none (a
\* signer-role request, or a cosigner document without checks).
ExternalAnswer == {"none", "pass", "refuse"}

VARIABLES
    group,                  \* the whole group
    valid_network_params,   \* uniform GenesisHash and overlapping validity window
    would_sign,             \* what policy and the operator would answer, if asked
    external,               \* what the external checks would answer, if asked
    decided,                \* the gate sequence has run
    refused_by,             \* "none", "network", "target" or "signed"
    refused_at,             \* the position a refusal names, 0 when none
    asked,                  \* the policy verdict (and so the operator) was consulted
    looked_up,              \* an external lookup was made
    released                \* the signer released its signatures

vars == <<group, valid_network_params, would_sign, external, decided,
          refused_by, refused_at, asked, looked_up, released>>

----------------------------------------------------------------------------
\* The positions the valid-target invariant reads.
TargetScope(g) ==
    IF TargetJudgesEveryPosition
        THEN DOMAIN g
        ELSE {i \in DOMAIN g : g[i].class = "sign"}

TargetBreaches(g) == {i \in TargetScope(g) : g[i].invalid_target}
SignedBreaches(g) == {i \in DOMAIN g : g[i].class = "sign" /\ g[i].signed_breach}

Min(S) == CHOOSE i \in S : \A j \in S : i <= j

\* rejectSignerInvariants: the valid-target invariant first, then the
\* signed-position ones. Each names its first breaking position.
RefusedBy(g) ==
    IF TargetBreaches(g) # {} THEN "target"
    ELSE IF SignedBreaches(g) # {} THEN "signed"
    ELSE "none"

RefusedAt(g) ==
    IF TargetBreaches(g) # {} THEN Min(TargetBreaches(g))
    ELSE IF SignedBreaches(g) # {} THEN Min(SignedBreaches(g))
    ELSE 0

\* The invariants or the policy refuse the request.
GatesRefuse == RefusedBy(group) # "none" \/ ~would_sign

Init ==
    /\ group \in Groups
    /\ valid_network_params \in BOOLEAN
    /\ would_sign \in BOOLEAN
    /\ external \in ExternalAnswer
    /\ decided = FALSE
    /\ refused_by = "none"
    /\ refused_at = 0
    /\ asked = FALSE
    /\ looked_up = FALSE
    /\ released = FALSE

\* One request's gate decision. validateNetworkParams runs before invariants,
\* policy and external checks; signs is the answer of the invariants and the
\* policy; the external checks come last and can only refuse.
Decide ==
    /\ ~decided
    /\ decided' = TRUE
    /\ IF NetworkParamsBeforeGates /\ ~valid_network_params
          THEN /\ refused_by' = "network"
               /\ refused_at' = 0
               /\ asked' = FALSE
               /\ looked_up' = FALSE
               /\ released' = FALSE
          ELSE LET signs == IF InvariantsBeforePolicy
                               THEN RefusedBy(group) = "none" /\ would_sign
                               ELSE would_sign
               IN
               /\ IF InvariantsBeforePolicy
                     THEN /\ refused_by' = RefusedBy(group)
                          /\ refused_at' = RefusedAt(group)
                          /\ asked' = (RefusedBy(group) = "none")
                     \* The mutation: the policy verdict first, and an approval skips
                     \* the invariants.
                     ELSE /\ asked' = TRUE
                          /\ refused_by' = IF would_sign THEN "none" ELSE RefusedBy(group)
                          /\ refused_at' = IF would_sign THEN 0 ELSE RefusedAt(group)
               \* runExternalChecks: a request with checks is looked up once the
               \* earlier gates say sign. The mutation looks it up whatever they say.
               /\ looked_up' = (external # "none" /\ (signs \/ ~ExternalAfterPolicy))
               /\ released' = (signs /\ external # "refuse")
    /\ UNCHANGED <<group, valid_network_params, would_sign, external>>

Next == Decide \/ (decided /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
TypeOK ==
    /\ group \in Groups
    /\ valid_network_params \in BOOLEAN
    /\ would_sign \in BOOLEAN
    /\ external \in ExternalAnswer
    /\ decided \in BOOLEAN
    /\ refused_by \in {"none", "network", "target", "signed"}
    /\ refused_at \in 0..MaxPositions
    /\ asked \in BOOLEAN
    /\ looked_up \in BOOLEAN
    /\ released \in BOOLEAN

\* SI1: every position, whatever its class.
SI1_NoReleaseWithInvalidRekeyTarget ==
    released => \A i \in DOMAIN group : ~group[i].invalid_target

\* SI2: the positions this signer signs.
SI2_NoReleaseWithSignedBreach ==
    released => \A i \in DOMAIN group :
        group[i].class = "sign" => ~group[i].signed_breach

\* SI3: a refused group is never put to policy or the operator.
SI3_RefusalBeforePolicy ==
    refused_by # "none" => (~asked /\ ~released)

\* SI4: the valid-target refusal names the first breaking position.
SI4_RefusalNamesFirstPosition ==
    refused_by = "target" =>
        /\ refused_at \in DOMAIN group
        /\ group[refused_at].invalid_target
        /\ \A j \in 1..(refused_at - 1) : ~group[j].invalid_target

\* SI5: the external checks can refuse a signature, never add one.
SI5_ExternalChecksOnlyRefuse ==
    released => (would_sign /\ external # "refuse")

\* SI6: nothing is looked up for a request an earlier gate refuses.
SI6_NoLookupForARefusedRequest ==
    GatesRefuse => ~looked_up

\* SI7: a group with invalid cross-slot network parameters never reaches
\* policy, external checks, or signature release.
SI7_NoReleaseOrLookupWithInvalidNetworkParams ==
    ~valid_network_params => (~asked /\ ~looked_up /\ ~released)

Safety ==
    /\ TypeOK
    /\ SI1_NoReleaseWithInvalidRekeyTarget
    /\ SI2_NoReleaseWithSignedBreach
    /\ SI3_RefusalBeforePolicy
    /\ SI4_RefusalNamesFirstPosition
    /\ SI5_ExternalChecksOnlyRefuse
    /\ SI6_NoLookupForARefusedRequest
    /\ SI7_NoReleaseOrLookupWithInvalidNetworkParams

=============================================================================
