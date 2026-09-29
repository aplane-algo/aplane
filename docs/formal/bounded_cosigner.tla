---------------------- MODULE bounded_cosigner ----------------------
(*
Machine-checkable model for the bounded-cosigner1 planning and assembly
choreography implemented by internal/engine/guarded/submit.go and
internal/signerapp/signing/bounded_cosigner.go.

The model checks the security-bearing order and final acceptance boundary:

  BS1 : a cosigner request can occur only after finalized classification,
        signer policy, operator approval, and base-component release.
  BS2 : the external-admin path never requests or consumes a cosigner.
  BS3 : spend output requires a valid assembly receipt plus valid base and
        cosigner signatures.
  BS4 : output requires exact target coverage and a path-valid argument-source
        layout; spend additionally requires successful derived arguments.
  BS5 : output preserves passthrough entries and exact canonical bytes.
  BS6 : invalid or rejected paths never produce output.
  BS7 : output is atomic: failure at any stage produces no partial result.

Cryptography, transaction classification, metadata validation, argument
derivation, and byte comparison are abstracted to booleans. The model checks
that the implementation's gates consume those outcomes in the required order;
it does not prove Falcon, msgpack, Merkle proofs, or TEAL semantics.

Unlike the one-shot guarded_assembly model, this is a transition system. TLC
explores the base-release, cosigner-release, bounded assembly, and external-admin
completion stages. Validation outcomes are group-wide: a false value means at
least one target failed.

See FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md for the prose companion.
*)
EXTENDS TLC

----------------------------------------------------------------------------
(* Inputs and state *)

Path == {"spend", "admin", "invalid"}

Input == [
    path         : Path,
    finalized    : BOOLEAN,
    classified   : BOOLEAN,
    metadata     : BOOLEAN,
    userPolicy   : BOOLEAN,
    approval     : BOOLEAN,
    receipt      : BOOLEAN,
    baseSig      : BOOLEAN,
    cosignerPolicy : BOOLEAN,
    cosignerSig    : BOOLEAN,
    coverage     : BOOLEAN,
    sourceLayout : BOOLEAN,
    derived      : BOOLEAN,
    passthrough  : BOOLEAN,
    bytes        : BOOLEAN,
    adminSig     : BOOLEAN
]

Stage == {
    "planned",
    "base_released",
    "cosigner_released",
    "admin_partial",
    "output",
    "rejected"
}

VARIABLES
    input,
    stage,
    baseReleased,
    cosignerRequested,
    cosignerReleased,
    output

vars == <<input, stage, baseReleased, cosignerRequested, cosignerReleased, output>>

BaseGate(i) ==
    /\ i.finalized
    /\ i.classified
    /\ i.metadata
    /\ i.userPolicy
    /\ i.approval

Init ==
    /\ input \in Input
    /\ stage = "planned"
    /\ baseReleased = FALSE
    /\ cosignerRequested = FALSE
    /\ cosignerReleased = FALSE
    /\ output = FALSE

----------------------------------------------------------------------------
(* Choreography *)

(* POST /sign/component (bounded-base) for spend, or /sign/bounded-admin for admin.
   An invalid shape and every failed signer-domain gate reject before release. *)
BaseStep ==
    /\ stage = "planned"
    /\ baseReleased' = (input.path \in {"spend", "admin"} /\ BaseGate(input))
    /\ stage' =
        IF input.path = "spend" /\ BaseGate(input) THEN "base_released"
        ELSE IF input.path = "admin" /\ BaseGate(input) THEN "admin_partial"
        ELSE "rejected"
    /\ cosignerRequested' = FALSE
    /\ cosignerReleased' = FALSE
    /\ output' = FALSE
    /\ UNCHANGED input

(* The client may request the cosigner only after successful user-side release. *)
CosignerStep ==
    /\ stage = "base_released"
    /\ input.path = "spend"
    /\ cosignerRequested' = TRUE
    /\ cosignerReleased' = input.cosignerPolicy
    /\ stage' = IF input.cosignerPolicy THEN "cosigner_released" ELSE "rejected"
    /\ UNCHANGED <<input, baseReleased, output>>

(* POST /sign/assemble revalidates metadata, verifies the Falcon-signed
   assembly receipt against the bounded spending public key before accepting
   the base or cosigner component, then checks exact target coverage, both
   signatures, source/path masks, derived arguments, passthrough binding,
   and canonical transaction bytes before returning one atomic group. *)
AssembleStep ==
    /\ stage = "cosigner_released"
    /\ LET success ==
            /\ input.path = "spend"
            /\ input.metadata
            /\ input.receipt
            /\ input.baseSig
            /\ input.cosignerSig
            /\ input.coverage
            /\ input.sourceLayout
            /\ input.derived
            /\ input.passthrough
            /\ input.bytes
       IN
            /\ output' = success
            /\ stage' = IF success THEN "output" ELSE "rejected"
    /\ UNCHANGED <<input, baseReleased, cosignerRequested, cosignerReleased>>

(* External completion consumes the base and admin authorities. It deliberately
   bypasses cosigner policy, cosigner signature, and spend-only derivation. *)
AdminCompleteStep ==
    /\ stage = "admin_partial"
    /\ LET success ==
            /\ input.path = "admin"
            /\ input.metadata
            /\ input.baseSig
            /\ input.adminSig
            /\ input.coverage
            /\ input.sourceLayout
            /\ input.passthrough
            /\ input.bytes
       IN
            /\ output' = success
            /\ stage' = IF success THEN "output" ELSE "rejected"
    /\ UNCHANGED <<input, baseReleased, cosignerRequested, cosignerReleased>>

Next == BaseStep \/ CosignerStep \/ AssembleStep \/ AdminCompleteStep

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ input \in Input
    /\ stage \in Stage
    /\ baseReleased \in BOOLEAN
    /\ cosignerRequested \in BOOLEAN
    /\ cosignerReleased \in BOOLEAN
    /\ output \in BOOLEAN

BS1_UserFirst ==
    cosignerRequested =>
        /\ input.path = "spend"
        /\ baseReleased
        /\ BaseGate(input)

BS2_AdminBypassesCosigner ==
    input.path = "admin" =>
        /\ ~cosignerRequested
        /\ ~cosignerReleased

BS3_SpendAuthoritiesVerified ==
    (output /\ input.path = "spend") =>
        /\ baseReleased
        /\ cosignerRequested
        /\ cosignerReleased
        /\ input.receipt
        /\ input.baseSig
        /\ input.cosignerSig
        /\ input.cosignerPolicy

BS4_DeclaredArgumentsOnly ==
    output =>
        /\ input.coverage
        /\ input.sourceLayout
        /\ (input.path = "spend" => input.derived)

BS5_CanonicalGroupBound ==
    output =>
        /\ input.passthrough
        /\ input.bytes

BS6_InvalidNeverOutputs ==
    (input.path = "invalid" \/ ~BaseGate(input)) => ~output

BS7_AtomicOutput ==
    /\ output => stage = "output"
    /\ stage = "rejected" => ~output
    /\ stage = "output" =>
        \/ input.path = "spend"
        \/ input.path = "admin" /\ input.adminSig /\ ~cosignerRequested

Safety ==
    /\ TypeOK
    /\ BS1_UserFirst
    /\ BS2_AdminBypassesCosigner
    /\ BS3_SpendAuthoritiesVerified
    /\ BS4_DeclaredArgumentsOnly
    /\ BS5_CanonicalGroupBound
    /\ BS6_InvalidNeverOutputs
    /\ BS7_AtomicOutput

============================================================================
