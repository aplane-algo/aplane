---------------------- MODULE bounded_cosigner ----------------------
(*
Machine-checkable model for the cosigned1 planning and assembly choreography
implemented by internal/engine/guarded/submit.go and
internal/signerapp/signing/bounded_cosigner.go.

A cosigned account's target takes one of three paths: a spend and a declared
(cosigned) rekey need the spending key and the cosigner; a listed rekey needs
the spending key and the rekey-to list's proof, and never the cosigner. The
paths are the same on a bounded host (contract bounded2) and a plain host
(plain1): the host decides which transactions classify onto which path, which
this model abstracts as the classified input. An account without a cosigner
signs through /sign, not this flow. The
signer's base component names the path, and the client asks the cosigner only
when that path needs it; but the client may also ask or skip wrongly, and may
present or drop a cosigner signature it holds, so both choices are inputs here,
and assembly decides the path again.

The model checks the security-bearing order and final acceptance boundary:

  BS1 : a cosigner request can occur only after finalized classification,
        signer policy, operator approval, and base-component release.
  BS2 : a listed rekey outputs only with the assembly receipt, the base
        signature and a valid list proof, and with no cosigner signature
        presented at assembly. Assembly cannot see whether the client asked
        the cosigner; that the first-party client never asks for a listed rekey
        is a client property, tested in Go. (The number once covered the
        external-admin path; this branch takes its place.)
  BS3 : spend and cosigned-rekey output require a valid assembly receipt plus
        valid base and cosigner signatures and cosigner policy.
  BS4 : output requires exact target coverage and a path-valid argument-source
        layout; spend and listed rekey additionally require successful derived
        arguments (the Merkle proof, and the list proof).
  BS5 : output preserves the exact canonical bytes.
  A8  : passthrough bytes are kept only when their decoded transaction ID is
        the canonical entry's, a signature is present, and the effective signer
        is not a cosigned account this signer holds, which must be assembled
        instead. (Moved here from the retired guarded_assembly model with the
        dedicated cosigned account; the cosigned flow keeps the check.)
  BS6 : invalid or rejected paths never produce output.
  BS7 : output is atomic: failure at any stage produces no partial result.

Cryptography, transaction classification, metadata validation, argument
derivation, and byte comparison are abstracted to booleans. The model checks
that the implementation's gates consume those outcomes in the required order;
it does not prove Falcon, msgpack, Merkle proofs, or TEAL semantics.

This is a transition system. TLC explores the base-release, cosigner-release,
and bounded assembly stages. Validation outcomes are group-wide: a false value
means at least one target or passthrough entry failed.

See FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md for the prose companion.
*)
EXTENDS TLC

----------------------------------------------------------------------------
(* Inputs and state *)

Path == {"spend", "cosigned_rekey", "listed_rekey", "invalid"}

(* The paths the cosigned flow carries, and those the cosigner signs. *)
AdmittedPath == {"spend", "cosigned_rekey", "listed_rekey"}
CosignedPath == {"spend", "cosigned_rekey"}

Input == [
    path         : Path,
    finalized    : BOOLEAN,
    classified   : BOOLEAN,
    metadata     : BOOLEAN,
    userPolicy   : BOOLEAN,
    approval     : BOOLEAN,
    receipt      : BOOLEAN,
    baseSig      : BOOLEAN,
    askCosigner  : BOOLEAN,
    presentCosigner : BOOLEAN,
    cosignerPolicy : BOOLEAN,
    cosignerSig    : BOOLEAN,
    coverage     : BOOLEAN,
    sourceLayout : BOOLEAN,
    derived      : BOOLEAN,
    ptTxid       : BOOLEAN,
    ptHasSig     : BOOLEAN,
    ptLocalCosigned : BOOLEAN,
    bytes        : BOOLEAN
]

Stage == {
    "planned",
    "base_released",
    "cosigner_released",
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

(* POST /sign/component (bounded-base) for an admitted path. An invalid shape
   and every failed signer-domain gate reject before release. *)
BaseStep ==
    /\ stage = "planned"
    /\ baseReleased' = (input.path \in AdmittedPath /\ BaseGate(input))
    /\ stage' = IF input.path \in AdmittedPath /\ BaseGate(input) THEN "base_released" ELSE "rejected"
    /\ cosignerRequested' = FALSE
    /\ cosignerReleased' = FALSE
    /\ output' = FALSE
    /\ UNCHANGED input

(* The client may request the cosigner only after successful user-side release.
   It asks when the component's path needs the cosigner; askCosigner lets it ask
   or skip wrongly, which assembly must catch. The cosigner judges the target by
   its own policy and does not know the path. *)
CosignerStep ==
    /\ stage = "base_released"
    /\ input.askCosigner
    /\ cosignerRequested' = TRUE
    /\ cosignerReleased' = input.cosignerPolicy
    /\ stage' = IF input.cosignerPolicy THEN "cosigner_released" ELSE "rejected"
    /\ UNCHANGED <<input, baseReleased, output>>

(* The cosigner signature reaches assembly only when the cosigner released one
   and the client sends it. *)
Presented == cosignerReleased /\ input.presentCosigner

(* POST /sign/assemble revalidates metadata, classifies the canonical
   transaction against the stored contract again, verifies the Falcon-signed
   assembly receipt against the bounded spending public key, and then checks
   exact target coverage, the base signature, the cosigner signature where the
   path needs one and its absence where it does not, source/path masks,
   derived arguments, passthrough binding (validateGuardedPassthrough: the
   decoded txid, a signature, and no locally held cosigned signer), and
   canonical transaction bytes before returning one atomic group. A client
   that skipped the cosigner assembles from base_released. *)
AssembleStep ==
    /\ \/ stage = "cosigner_released"
       \/ stage = "base_released" /\ ~input.askCosigner
    /\ LET success ==
            /\ input.path \in AdmittedPath
            /\ input.metadata
            /\ input.receipt
            /\ input.baseSig
            /\ (input.path \in CosignedPath => Presented /\ input.cosignerSig)
            /\ (input.path = "listed_rekey" => ~Presented)
            /\ input.coverage
            /\ input.sourceLayout
            /\ (input.path \in {"spend", "listed_rekey"} => input.derived)
            /\ input.ptTxid
            /\ input.ptHasSig
            /\ ~input.ptLocalCosigned
            /\ input.bytes
       IN
            /\ output' = success
            /\ stage' = IF success THEN "output" ELSE "rejected"
    /\ UNCHANGED <<input, baseReleased, cosignerRequested, cosignerReleased>>

Next == BaseStep \/ CosignerStep \/ AssembleStep

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
        /\ input.path \in AdmittedPath
        /\ baseReleased
        /\ BaseGate(input)

BS2_ListedRekeyWithoutCosigner ==
    (output /\ input.path = "listed_rekey") =>
        /\ baseReleased
        /\ ~Presented
        /\ input.receipt
        /\ input.baseSig
        /\ input.derived

BS3_CosignedAuthoritiesVerified ==
    (output /\ input.path \in CosignedPath) =>
        /\ baseReleased
        /\ cosignerRequested
        /\ Presented
        /\ input.receipt
        /\ input.baseSig
        /\ input.cosignerSig
        /\ input.cosignerPolicy

BS4_DeclaredArgumentsOnly ==
    output =>
        /\ input.coverage
        /\ input.sourceLayout
        /\ (input.path \in {"spend", "listed_rekey"} => input.derived)

BS5_CanonicalGroupBound ==
    output => input.bytes

A8_PassthroughTxidBound ==
    output =>
        /\ input.ptTxid
        /\ input.ptHasSig
        /\ ~input.ptLocalCosigned

BS6_InvalidNeverOutputs ==
    (input.path = "invalid" \/ ~BaseGate(input)) => ~output

BS7_AtomicOutput ==
    /\ output => stage = "output"
    /\ stage = "rejected" => ~output
    /\ stage = "output" => input.path \in AdmittedPath

Safety ==
    /\ TypeOK
    /\ BS1_UserFirst
    /\ BS2_ListedRekeyWithoutCosigner
    /\ BS3_CosignedAuthoritiesVerified
    /\ BS4_DeclaredArgumentsOnly
    /\ BS5_CanonicalGroupBound
    /\ A8_PassthroughTxidBound
    /\ BS6_InvalidNeverOutputs
    /\ BS7_AtomicOutput

============================================================================
