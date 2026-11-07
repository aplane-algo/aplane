---------------------------- MODULE key_use_lock ----------------------------
EXTENDS Naturals, TLC

(***************************************************************************
Key-use window model: how a lock ends every use of loaded key material, and
what may still leave the signer while it does.

Two holders use the same mechanism. A rotating sign holds a seed, signs,
closes the seed, writes its audit entry, and only then returns the signature.
A mnemonic export holds the key while it reads the credential and delivers
the phrase, and releases afterwards. Both register a key use
(Runtime.KeyUseContext) whose context the lock cancels and whose release the
lock waits for before it clears the session.

A lock has three steps, transcribed separately because registration is
atomic with only some of them:

  LockState   the state becomes locked and the lock generation moves
              (runtime.Runtime.Lock or BeginMaintenance, under stateMu);
  DrainBegin  every registered key use is cancelled and the drain starts
              waiting for them (drainKeyUsers, under keyUseMu);
  Wipe        the drain returns and the session is cleared
              (performLockCleanup).

Registration checks the state and joins the wait group under keyUseMu, so it
lands wholly before or wholly after DrainBegin, but a LockState can come
between a holder's start and its registration.

Four guards are switchable:

  RegisterChecksLock  registration refuses once the state is locked. Without
                      it, a holder registering after DrainBegin gets a fresh,
                      uncancelled context the drain does not wait for.
  DrainWaits          Wipe waits for every key use registered before
                      DrainBegin.
  FinalRecheck        a rotating sign rechecks after its audit write and
                      returns nothing when the signer locked (releaseRefused).
  GenerationCheck     that recheck compares the lock generation captured at
                      the start, not just the current state, so a lock and an
                      unlock in between still refuse.

Properties:

  KU1  a rotating signature is never returned once a lock has begun after
       its sign started and before its final check;
  KU2  the session is never cleared while a key use is registered;
  KU3  an export never delivers after the session was cleared.

The final check and the return are separate in the code; a lock landing
between them is indistinguishable from one landing just after the return, so
the model makes them one step. The same holds for an export's last context
check and its delivery: a lock that begins during delivery waits for it,
which KU2 covers.

Scope: one rotating sign and one export, repeating. The stage table worker is
a third holder of the same kind; KU2 covers any holder. The sign's leaf choice
and release memory are rotating_leaf_release.tla's. Shutdown (Runtime.Destroy)
is not modeled: it drains and clears only after every service has stopped and
skips teardown when a handler may still run, so no holder can exist or start.

Code anchors:
  - SStart/SRegister/SMake/SRelease/SReturn transcribe
    internal/signerapp/signing/rotating_flow.go SignRotatingWithContext: the
    lockGeneration capture, deps.keyUse, releaseRefused before the seed is
    used, rs.close and endKeyUse before the audit write, and releaseRefused
    on the request context before the response.
  - EStart/ERegister/ERead/EDeliver/ERelease transcribe
    internal/signerapp/keyadmin/export.go ExportKey.
  - LockState transcribes internal/signerapp/runtime/runtime.go Lock and
    BeginMaintenance; DrainBegin and Wipe transcribe
    internal/signerapp/productruntime/runtime.go drainKeyUsers and
    performLockCleanup; registration transcribes KeyUseContext.

See FORMAL_TLA_KEY_USE_LOCK_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS
    RegisterChecksLock,  \* BOOLEAN: registration refuses while locked
    DrainWaits,          \* BOOLEAN: Wipe waits for registered key uses
    FinalRecheck,        \* BOOLEAN: the sign rechecks before returning
    GenerationCheck,     \* BOOLEAN: the recheck compares lock generations
    MaxLocks             \* bound on lock transitions (keeps the space finite)

Holders == {"sign", "export"}

VARIABLES
    life,       \* "unlocked" | "locking" | "draining" | "locked"
    locks,      \* lock transitions so far
    pc,         \* each holder's step
    stale,      \* a LockState came after the holder started (generation moved)
    cancelled,  \* the holder's key-use context is cancelled
    waited,     \* the drain will wait for the holder's key use
    leaked,     \* ghost: a signature was returned although stale
    wipedHeld,  \* ghost: the session was cleared while a key use was registered
    lateExport  \* ghost: an export delivered after the session was cleared

vars == <<life, locks, pc, stale, cancelled, waited, leaked, wipedHeld, lateExport>>

\* Steps at which a holder has a registered key use.
SignHolds == {"held", "made"}
ExportHolds == {"held", "made", "delivered"}

Holding(h) ==
    IF h = "sign" THEN pc[h] \in SignHolds ELSE pc[h] \in ExportHolds

Init ==
    /\ life = "unlocked"
    /\ locks = 0
    /\ pc = [h \in Holders |-> "idle"]
    /\ stale = [h \in Holders |-> FALSE]
    /\ cancelled = [h \in Holders |-> FALSE]
    /\ waited = [h \in Holders |-> FALSE]
    /\ leaked = FALSE
    /\ wipedHeld = FALSE
    /\ lateExport = FALSE

----------------------------------------------------------------------------
(* Registration (KeyUseContext), shared by both holders *)

\* A registration lands wholly before or after DrainBegin (keyUseMu). Before
\* it, the drain will cancel and wait for this key use. After it, the
\* registration gets a fresh context the drain never sees.
Register(h, next) ==
    /\ IF RegisterChecksLock /\ life # "unlocked"
       THEN /\ pc' = [pc EXCEPT ![h] = "idle"]  \* a cancelled context: refused
            /\ UNCHANGED <<cancelled, waited>>
       ELSE /\ pc' = [pc EXCEPT ![h] = next]
            /\ waited' = [waited EXCEPT ![h] = life \in {"unlocked", "locking"}]
            /\ cancelled' = [cancelled EXCEPT ![h] = FALSE]
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld, lateExport>>

\* Ending a key use (release).
Release(h, next) ==
    /\ pc' = [pc EXCEPT ![h] = next]
    /\ waited' = [waited EXCEPT ![h] = FALSE]
    /\ cancelled' = [cancelled EXCEPT ![h] = FALSE]

----------------------------------------------------------------------------
(* Rotating sign *)

\* releaseRefused: the signer is unlocked, the lock generation is the one
\* captured at the start, and the request has not been cancelled.
SignMayGoOn ==
    /\ life = "unlocked"
    /\ ~stale["sign"]
    /\ ~cancelled["sign"]

SStart ==
    /\ pc["sign"] = "idle"
    /\ life = "unlocked"
    /\ pc' = [pc EXCEPT !["sign"] = "started"]
    /\ stale' = [stale EXCEPT !["sign"] = FALSE]
    /\ UNCHANGED <<life, locks, cancelled, waited, leaked, wipedHeld, lateExport>>

SRegister ==
    /\ pc["sign"] = "started"
    /\ Register("sign", "held")

\* The seed is opened, the leaf chosen and the signature made.
SMake ==
    /\ pc["sign"] = "held"
    /\ IF SignMayGoOn
       THEN /\ pc' = [pc EXCEPT !["sign"] = "made"]
            /\ UNCHANGED <<waited, cancelled>>
       ELSE Release("sign", "idle")
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld, lateExport>>

\* The seed is closed and the key use ends, before the audit write.
SRelease ==
    /\ pc["sign"] = "made"
    /\ Release("sign", "released")
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld, lateExport>>

\* After the audit write: the last recheck and the return.
SReturn ==
    /\ pc["sign"] = "released"
    /\ LET refused == FinalRecheck /\
                      (life # "unlocked" \/ (GenerationCheck /\ stale["sign"]))
       IN  leaked' = (leaked \/ (~refused /\ stale["sign"]))
    /\ pc' = [pc EXCEPT !["sign"] = "idle"]
    /\ UNCHANGED <<life, locks, stale, cancelled, waited, wipedHeld, lateExport>>

----------------------------------------------------------------------------
(* Mnemonic export *)

\* The passphrase verified and the mutation lock taken, on an unlocked signer.
EStart ==
    /\ pc["export"] = "idle"
    /\ life = "unlocked"
    /\ pc' = [pc EXCEPT !["export"] = "started"]
    /\ stale' = [stale EXCEPT !["export"] = FALSE]
    /\ UNCHANGED <<life, locks, cancelled, waited, leaked, wipedHeld, lateExport>>

ERegister ==
    /\ pc["export"] = "started"
    /\ Register("export", "held")

\* The context check, then the credential read and the phrase built.
ERead ==
    /\ pc["export"] = "held"
    /\ IF ~cancelled["export"]
       THEN /\ pc' = [pc EXCEPT !["export"] = "made"]
            /\ UNCHANGED <<waited, cancelled>>
       ELSE Release("export", "idle")
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld, lateExport>>

\* The second context check and the delivery, still holding the key.
EDeliver ==
    /\ pc["export"] = "made"
    /\ IF ~cancelled["export"]
       THEN /\ pc' = [pc EXCEPT !["export"] = "delivered"]
            /\ lateExport' = (lateExport \/ life = "locked")
            /\ UNCHANGED <<waited, cancelled>>
       ELSE /\ Release("export", "idle")
            /\ UNCHANGED lateExport
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld>>

ERelease ==
    /\ pc["export"] = "delivered"
    /\ Release("export", "idle")
    /\ UNCHANGED <<life, locks, stale, leaked, wipedHeld, lateExport>>

----------------------------------------------------------------------------
(* Lock and unlock *)

\* The state locks and the generation moves for every holder in flight.
LockState ==
    /\ life = "unlocked"
    /\ locks < MaxLocks
    /\ life' = "locking"
    /\ locks' = locks + 1
    /\ stale' = [h \in Holders |-> stale[h] \/ pc[h] # "idle"]
    /\ UNCHANGED <<pc, cancelled, waited, leaked, wipedHeld, lateExport>>

\* drainKeyUsers cancels every registered key use and starts waiting.
DrainBegin ==
    /\ life = "locking"
    /\ life' = "draining"
    /\ cancelled' = [h \in Holders |-> cancelled[h] \/ (Holding(h) /\ waited[h])]
    /\ UNCHANGED <<locks, pc, stale, waited, leaked, wipedHeld, lateExport>>

\* The drain returns and the session is cleared.
Wipe ==
    /\ life = "draining"
    /\ DrainWaits => \A h \in Holders : ~(Holding(h) /\ waited[h])
    /\ life' = "locked"
    /\ wipedHeld' = (wipedHeld \/ \E h \in Holders : Holding(h))
    /\ UNCHANGED <<locks, pc, stale, cancelled, waited, leaked, lateExport>>

Unlock ==
    /\ life = "locked"
    /\ life' = "unlocked"
    /\ UNCHANGED <<locks, pc, stale, cancelled, waited, leaked, wipedHeld, lateExport>>

----------------------------------------------------------------------------
Next ==
    \/ SStart \/ SRegister \/ SMake \/ SRelease \/ SReturn
    \/ EStart \/ ERegister \/ ERead \/ EDeliver \/ ERelease
    \/ LockState \/ DrainBegin \/ Wipe \/ Unlock

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ life \in {"unlocked", "locking", "draining", "locked"}
    /\ locks \in 0..MaxLocks
    /\ pc["sign"] \in {"idle", "started", "held", "made", "released"}
    /\ pc["export"] \in {"idle", "started", "held", "made", "delivered"}
    /\ \A h \in Holders : stale[h] \in BOOLEAN /\ cancelled[h] \in BOOLEAN /\ waited[h] \in BOOLEAN
    /\ leaked \in BOOLEAN /\ wipedHeld \in BOOLEAN /\ lateExport \in BOOLEAN

\* KU1: no rotating signature is returned after a lock began during its sign.
KU1_NoSignatureAfterLock == ~leaked

\* KU2: the session is never cleared while a key use is registered.
KU2_NoKeyMaterialAtWipe == ~wipedHeld

\* KU3: an export never delivers after the session was cleared.
KU3_NoExportAfterWipe == ~lateExport

Safety ==
    /\ TypeOK
    /\ KU1_NoSignatureAfterLock
    /\ KU2_NoKeyMaterialAtWipe
    /\ KU3_NoExportAfterWipe

=============================================================================
