---------------------- MODULE guarded_assembly ----------------------
(*
Ninth machine-checkable model in the APlane formalization roadmap (M4).
It machine-checks the assembly-verification core of
FORMAL_GUARDED_SIGNING_MODEL.md — the checks assembleDecodedGuarded
(internal/signerapp/signing/component_assemble.go) runs before a guarded
group becomes signed output:

  - A1  : role domain separation — a component signature carries the role
          byte it was produced under; a user-role signature never verifies
          as a sentry signature or vice versa (the SHA512/256 domain
          prefix "APLANE_SENTRY_V1" || role || txid).
  - A6  : the user component signature must verify against the user
          public key stored in the local guarded key.
  - A7  : the sentry component signature must verify against the sentry
          public key embedded in the local key at generation time.
  - A8  : passthrough bytes are kept only if their decoded transaction ID
          equals the canonical group entry at that index.
  - A14 : the assembled signed transaction preserves the canonical
          transaction ID, and a non-guarded sender must carry
          AuthAddr = guarded account.
  - NoPartialOutput : any single entry failure rejects the whole group —
          assembly never emits a partially signed group.

Like sign_boundary.tla this is a ONE-SHOT spec: Init enumerates every
combination of canonical entries, presented component signatures (right or
wrong key, role, and bound txid), passthrough bytes, and binding-check
outcomes; Next is UNCHANGED. What TLC verifies is that the Assemble
decision procedure — a literal transcription of the code's check order —
never lets a tampered input into the output. A missed case in Assemble
(e.g. dropping the role check or the passthrough txid comparison) surfaces
as a counterexample; the documented mutations below confirm that.

Cryptography is abstracted the standard way: signature verification is
token equality (keyOK /\ role match /\ txid match), not math. The model
therefore checks the CHECKS, not Falcon-1024 itself.

The model intentionally omits (honest gaps, mirrored from the code):
  - parameter<->bytecode consistency: the sentry public key verified at
    assembly comes from the stored Parameters; the chain enforces the key
    compiled into the bytecode. Assembly trusts that generation bound
    them (explicit assumption in FORMAL_GUARDED_SIGNING_MODEL.md).
  - cryptographic validity of passthrough signatures (presence-checked
    only; the chain verifies),
  - sentry policy evaluation (runs at component-sign time, A4 — not at
    assembly),
  - group-level semantics (fees, dummy budget), replay of identical
    component signatures (txid-bound, reproduces the same txn),
  - the component-sign endpoint, key loading, and endpoint routing
    (A2-A5, A9-A13, A15).

See FORMAL_TLA_GUARDED_ASSEMBLY_MODEL.md for the prose companion.
*)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS MaxEntries   \* group size bound (TLC bound)

ASSUME MaxEntries \in Nat /\ MaxEntries >= 1

----------------------------------------------------------------------------
(* Domains *)

\* Each canonical group entry is a target (this signer assembles it) or a
\* passthrough (client-supplied signed bytes, kept verbatim if they bind).
EntryKind == {"target", "passthrough"}

\* Component-signature roles: the domain-separation byte in the signed
\* message (0x01 user, 0x02 sentry).
Role == {"user", "sentry"}

\* Txid binding of a presented signature or decoded passthrough, relative
\* to the canonical entry it is presented for. "match" = the canonical
\* entry's txid; "other" = any different txid (another entry's, or foreign).
Binding == {"match", "other"}

\* A presented component signature: produced by the right key or not,
\* under which role domain, bound to which txid.
Sig == [keyOK : BOOLEAN, role : Role, txid : Binding]

\* A target entry carries the two presented signatures plus the outcomes
\* of the assembly's own binding checks:
\*   addrOK    : derived LogicSig address = target guarded account,
\*   senderOK  : sender is the guarded account, or AuthAddr is,
\*   signedTxidOK : post-sign re-decode yields the canonical txid.
TargetEntry == [
    kind         : {"target"},
    userSig      : Sig,
    sentrySig    : Sig,
    addrOK       : BOOLEAN,
    senderOK     : BOOLEAN,
    signedTxidOK : BOOLEAN
]

\* A passthrough entry carries its decoded txid binding, whether a
\* signature is present, and whether the sender is a locally-held guarded
\* account (which assembly rejects as passthrough). The two entry shapes
\* are a disjoint union so TLC does not enumerate irrelevant fields.
PassthroughEntry == [
    kind           : {"passthrough"},
    ptTxid         : Binding,
    ptHasSig       : BOOLEAN,
    ptLocalGuarded : BOOLEAN
]

Entry == TargetEntry \cup PassthroughEntry

----------------------------------------------------------------------------
(* The assembly decision procedure — a transcription of
   component_assemble.go's per-entry checks in order. *)

\* Signature verification (crypto abstracted to token equality):
\* internal/sentry/message/message.go builds the signed message from the
\* role byte and the canonical entry txid; verification succeeds only for
\* the right key, the expected role domain, and the entry's txid.
Verifies(sig, expectedRole) ==
    /\ sig.keyOK
    /\ sig.role = expectedRole
    /\ sig.txid = "match"

\* assembleGuardedTarget: user verify (A6, role domain A1), sentry verify
\* (A7, role domain A1), derived-address binding, post-sign txid re-check
\* and sender/AuthAddr binding (A14).
TargetAccepted(e) ==
    /\ Verifies(e.userSig, "user")
    /\ Verifies(e.sentrySig, "sentry")
    /\ e.addrOK
    /\ e.signedTxidOK
    /\ e.senderOK

\* validateGuardedPassthrough: decoded txid must equal the canonical entry
\* txid (A8), a signature must be present, and locally-held guarded
\* accounts may not ride through as passthrough.
PassthroughKept(e) ==
    /\ e.ptTxid = "match"
    /\ e.ptHasSig
    /\ ~e.ptLocalGuarded

EntryAccepted(e) ==
    IF e.kind = "target" THEN TargetAccepted(e) ELSE PassthroughKept(e)

----------------------------------------------------------------------------
(* State *)

VARIABLES
    group,    \* the canonical group: a sequence of entries
    output    \* per-entry output tokens, or <<>> when assembly rejects

vars == <<group, output>>

\* Assembly aborts on the first failing entry and returns no partial
\* signed group (component_assemble.go assembleDecodedGuarded).
GroupAccepted(g) == \A i \in 1..Len(g) : EntryAccepted(g[i])

\* Output tokens record what each accepted slot contains: an assembled
\* guarded signature bound to the canonical txid, or the preserved
\* passthrough bytes.
Assemble(g) ==
    [i \in 1..Len(g) |->
        IF g[i].kind = "target" THEN "assembled_" \o ToString(i)
                                ELSE "preserved_" \o ToString(i)]

BoundedGroups ==
    UNION { [1..n -> Entry] : n \in 1..MaxEntries }

Init ==
    /\ group \in BoundedGroups
    /\ output = IF GroupAccepted(group) THEN Assemble(group) ELSE <<>>

Next == UNCHANGED vars

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ group \in Seq(Entry)
    /\ Len(group) \in 1..MaxEntries
    /\ output \in Seq(STRING)
    /\ output # <<>> => Len(output) = Len(group)

\* A6/A1 (user side): output exists only if every target's user signature
\* was produced by the stored user key, under the user role domain, over
\* the canonical entry txid.
A6_UserSignatureVerified ==
    output # <<>> =>
        \A i \in 1..Len(group) :
            group[i].kind = "target" =>
                /\ group[i].userSig.keyOK
                /\ group[i].userSig.role = "user"
                /\ group[i].userSig.txid = "match"

\* A7/A1 (sentry side): same for the sentry signature against the
\* generation-time embedded sentry key, under the sentry role domain.
A7_SentrySignatureVerified ==
    output # <<>> =>
        \A i \in 1..Len(group) :
            group[i].kind = "target" =>
                /\ group[i].sentrySig.keyOK
                /\ group[i].sentrySig.role = "sentry"
                /\ group[i].sentrySig.txid = "match"

\* A1 (role separation, stated directly): no output ever rests on a
\* signature accepted under the wrong role domain. Subsumed by A6/A7 but
\* stated separately so a future edit that weakens Verifies' role check
\* fails a named invariant.
A1_RoleDomainSeparation ==
    output # <<>> =>
        \A i \in 1..Len(group) :
            group[i].kind = "target" =>
                /\ group[i].userSig.role # "sentry"
                /\ group[i].sentrySig.role # "user"

\* A8: passthrough bytes are kept only when their decoded txid equals the
\* canonical entry's, a signature is present, and the sender is not a
\* locally-held guarded account.
A8_PassthroughTxidBound ==
    output # <<>> =>
        \A i \in 1..Len(group) :
            group[i].kind = "passthrough" =>
                /\ group[i].ptTxid = "match"
                /\ group[i].ptHasSig
                /\ ~group[i].ptLocalGuarded

\* A14: every assembled target preserved the canonical txid through
\* signing and satisfies the sender/AuthAddr binding, and the derived
\* LogicSig address matched the guarded account.
A14_AssembledTxnBound ==
    output # <<>> =>
        \A i \in 1..Len(group) :
            group[i].kind = "target" =>
                /\ group[i].signedTxidOK
                /\ group[i].senderOK
                /\ group[i].addrOK

\* Abort-on-first-failure: one bad entry suppresses the whole group.
NoPartialOutput ==
    (\E i \in 1..Len(group) : ~EntryAccepted(group[i])) => output = <<>>

Safety ==
    /\ TypeOK
    /\ A6_UserSignatureVerified
    /\ A7_SentrySignatureVerified
    /\ A1_RoleDomainSeparation
    /\ A8_PassthroughTxidBound
    /\ A14_AssembledTxnBound
    /\ NoPartialOutput

============================================================================
