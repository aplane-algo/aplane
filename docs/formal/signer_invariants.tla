-------------------------- MODULE signer_invariants --------------------------
(*
The signer invariants and where they stand in the gate sequence.

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

Invariants:

  - SI1 : no signature is released for a group in which any position rekeys
          an account to a held aplane key that is not a valid rekey target.
  - SI2 : no signature is released for a group in which a position this
          signer signs breaks a signed-position invariant.
  - SI3 : a group an invariant refuses reaches neither the policy verdict
          nor the operator.
  - SI4 : a refusal by the valid-target invariant names the first position
          that breaks it.

`policy_precedence.tla` derives the policy verdict and `sign_boundary.tla`
the output per slot class; here the policy and the operator are one free
oracle (would_sign), since the claim is that the invariants hold whatever
they answer.

The model intentionally omits:

  - which key set the valid-target invariant reads (the key snapshot the
    request was planned with; a Go test pins it),
  - the rotating invariant as a check of its own: every rotating aplane key
    records that it is not a valid rekey target, so the valid-target
    invariant refuses such a rekey first, and the rotating check is a second
    line folded into the signed-position flag here,
  - the cosigner's key lookup, which runs before the invariants there, and
    transaction bounds validation, which runs before both.

See FORMAL_TLA_SIGNER_INVARIANTS_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
    MaxPositions,               \* upper bound on the group's length (TLC bound)
    InvariantsBeforePolicy,     \* the invariants run before the policy verdict
    TargetJudgesEveryPosition   \* the valid-target invariant reads every position

ASSUME MaxPositions \in Nat /\ MaxPositions >= 1
ASSUME InvariantsBeforePolicy \in BOOLEAN
ASSUME TargetJudgesEveryPosition \in BOOLEAN

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

VARIABLES
    group,          \* the whole group
    would_sign,     \* what policy and the operator would answer, if asked
    decided,        \* the gate sequence has run
    refused_by,     \* "none", "target" or "signed": the invariant that refused
    refused_at,     \* the position a refusal names, 0 when none
    asked,          \* the policy verdict (and so the operator) was consulted
    released        \* the signer released its signatures

vars == <<group, would_sign, decided, refused_by, refused_at, asked, released>>

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

Init ==
    /\ group \in Groups
    /\ would_sign \in BOOLEAN
    /\ decided = FALSE
    /\ refused_by = "none"
    /\ refused_at = 0
    /\ asked = FALSE
    /\ released = FALSE

\* One request's gate decision.
Decide ==
    /\ ~decided
    /\ decided' = TRUE
    /\ IF InvariantsBeforePolicy
          THEN /\ refused_by' = RefusedBy(group)
               /\ refused_at' = RefusedAt(group)
               /\ asked' = (RefusedBy(group) = "none")
               /\ released' = (RefusedBy(group) = "none" /\ would_sign)
          \* The mutation: the policy verdict first, and an approval ends
          \* the gate sequence.
          ELSE /\ asked' = TRUE
               /\ released' = would_sign
               /\ refused_by' = IF would_sign THEN "none" ELSE RefusedBy(group)
               /\ refused_at' = IF would_sign THEN 0 ELSE RefusedAt(group)
    /\ UNCHANGED <<group, would_sign>>

Next == Decide \/ (decided /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
TypeOK ==
    /\ group \in Groups
    /\ would_sign \in BOOLEAN
    /\ decided \in BOOLEAN
    /\ refused_by \in {"none", "target", "signed"}
    /\ refused_at \in 0..MaxPositions
    /\ asked \in BOOLEAN
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

Safety ==
    /\ TypeOK
    /\ SI1_NoReleaseWithInvalidRekeyTarget
    /\ SI2_NoReleaseWithSignedBreach
    /\ SI3_RefusalBeforePolicy
    /\ SI4_RefusalNamesFirstPosition

=============================================================================
