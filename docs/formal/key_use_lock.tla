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

Recovery is a second way out of the unlocked state. The signer enters it
when a store change ends in doubt and leaves it when a reconcile succeeds. It
keeps the keyring, so nothing is drained or cleared, but it ends the
unlocked session all the same, and cancels the key uses that session handed
out: signing is blocked while it lasts, and the
store the session signed under may have changed by the time it ends.

An unlock waits for a lock's cleanup. The state mutex is released between
LockState and Wipe, so an unlock could otherwise read the generation the lock
had already moved, pass the unlock fence, and publish a session that the
cleanup still running would then clear.

An unlock is two steps, because its unlock function (passphrase check and key
load) runs outside the state mutex: UnlockStart reads the lock generation and
UnlockFinish compares it. Two unlocks may run at once, from two admin
sessions or an automatic unlock beside one. An unlock that finds the
generation moved has lost to a lock, and its function may have loaded keys
after that lock's cleanup, so it clears them. The other unlock may meanwhile
have published a session those keys now serve, or may publish one before the
loser's clear runs; so the loser locks the signer as a lock does before it
clears.

Seven guards are switchable:

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
  RecoveryEndsSession entering recovery from the unlocked state moves the
                      session generation (runtime.Runtime.SetRecovery and
                      TryRecovery) and cancels the registered key uses, so a
                      recovery and a reconcile in between refuse as well.
  UnlockWaitsForCleanup
                      an unlock starts only once the lock's cleanup has
                      returned (runtime.Runtime.TryUnlock, TryRecovery and
                      FinishMaintenance wait for it). Without it, an unlock
                      may land between LockState and Wipe, and the rest of
                      that cleanup runs against the new session.
  LoserLocks          an unlock that lost to a lock locks the signer, moving
                      the generation, before its cleanup clears what it
                      loaded (runtime.Runtime loseUnlockLocked). Without it,
                      the cleanup runs in whatever state the signer is in, and
                      clears a session another unlock published.

Properties:

  KU1  a rotating signature is never returned once a lock or a recovery has
       begun after its sign started and before its final check;
  KU2  the session is never cleared while a key use is registered;
  KU3  an export never delivers after the session was cleared;
  KU4  the session is never cleared while the signer is unlocked.

The final check and the return are separate in the code; a lock landing
between them is indistinguishable from one landing just after the return, so
the model makes them one step. The same holds for an export's last context
check and its delivery: a lock that begins during delivery waits for it,
which KU2 covers.

Scope: one rotating sign and one export, repeating. The stage table worker is
a third holder of the same kind; KU2 covers any holder. The sign's leaf choice
and release memory are rotating_leaf_release.tla's. Shutdown
(Runtime.EndKeyUses, then Runtime.Destroy) is not modeled: the process exits
right after it. It refuses new key uses as a lock does, drains like a lock
but only until its deadline, then clears the session whether or not the
holders released; a holder still running then
keeps its own decrypted copy until it releases or the process exits, and
shutdown records the stop as incomplete.

Code anchors:
  - SStart/SRegister/SMake/SRelease/SReturn transcribe
    internal/signerapp/signing/rotating_flow.go SignRotatingWithContext: the
    lockGeneration capture, deps.keyUse, releaseRefused before the seed is
    used, rs.close and endKeyUse before the audit write, and releaseRefused
    on the request context before the response.
  - EStart/ERegister/ERead/EDeliver/ERelease transcribe
    internal/signerapp/keyadmin/export.go ExportKey.
  - LockState transcribes internal/signerapp/runtime/runtime.go Lock and
    BeginMaintenance; EnterRecovery and LeaveRecovery transcribe SetRecovery
    and TryRecovery, and PromoteRecoveryToUnlocked, there, with
    productruntime's cancelKeyUses on the way in; DrainBegin and Wipe transcribe
    internal/signerapp/productruntime/runtime.go drainKeyUsers and
    performLockCleanup; registration transcribes KeyUseContext.
  - UnlockStart's guard transcribes awaitCleanups in
    internal/signerapp/runtime/runtime.go, which TryUnlock, TryRecovery and
    FinishMaintenance call before they read the lock generation;
    UnlockFinish transcribes the fence after the unlock function and, when
    the generation moved, loseUnlockLocked and the cleanup it decides.
    LockInactive transcribes Lock on a signer that is already locked or
    locking: the generation moves and no cleanup runs.

See FORMAL_TLA_KEY_USE_LOCK_MODEL.md for the prose companion.
***************************************************************************)

CONSTANTS
    RegisterChecksLock,  \* BOOLEAN: registration refuses while locked
    DrainWaits,          \* BOOLEAN: Wipe waits for registered key uses
    FinalRecheck,        \* BOOLEAN: the sign rechecks before returning
    GenerationCheck,     \* BOOLEAN: the recheck compares lock generations
    RecoveryEndsSession, \* BOOLEAN: entering recovery moves the lock generation
    UnlockWaitsForCleanup, \* BOOLEAN: an unlock waits for the lock's cleanup
    LoserLocks,          \* BOOLEAN: an unlock that lost to a lock locks first
    MaxLocks             \* bound on lock transitions (keeps the space finite)

Holders == {"sign", "export"}

\* Two unlock attempts that may overlap.
Unlockers == {"u1", "u2"}

VARIABLES
    life,       \* "unlocked" | "recovery" | "locking" | "draining" | "locked"
    locks,      \* lock and recovery transitions so far
    pc,         \* each holder's step
    stale,      \* the generation moved after the holder started
    ended,      \* ghost: the unlocked session ended after the holder started
    cancelled,  \* the holder's key-use context is cancelled
    waited,     \* the drain will wait for the holder's key use
    leaked,     \* ghost: a signature was returned although stale
    wipedHeld,  \* ghost: the session was cleared while a key use was registered
    lateExport, \* ghost: an export delivered after the session was cleared
    late,       \* the step of a cleanup that runs apart from the signer's
                \* state: one an early unlock overtook, or a losing unlock's
                \* without LoserLocks: "none" | "locking" | "draining"
    wipedLive,  \* ghost: the session was cleared while the signer was unlocked
    ul,         \* each unlock attempt: "idle" | "deriving"
    ulStale     \* the lock generation moved after the attempt read it

vars == <<life, locks, pc, stale, ended, cancelled, waited, leaked, wipedHeld,
          lateExport, late, wipedLive, ul, ulStale>>

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
    /\ ended = [h \in Holders |-> FALSE]
    /\ cancelled = [h \in Holders |-> FALSE]
    /\ waited = [h \in Holders |-> FALSE]
    /\ leaked = FALSE
    /\ wipedHeld = FALSE
    /\ lateExport = FALSE
    /\ late = "none"
    /\ wipedLive = FALSE
    /\ ul = [u \in Unlockers |-> "idle"]
    /\ ulStale = [u \in Unlockers |-> FALSE]

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
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld, lateExport>>

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
    /\ ended' = [ended EXCEPT !["sign"] = FALSE]
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
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld, lateExport>>

\* The seed is closed and the key use ends, before the audit write.
SRelease ==
    /\ pc["sign"] = "made"
    /\ Release("sign", "released")
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld, lateExport>>

\* After the audit write: the last recheck and the return.
SReturn ==
    /\ pc["sign"] = "released"
    /\ LET refused == FinalRecheck /\
                      (life # "unlocked" \/ (GenerationCheck /\ stale["sign"]))
       IN  leaked' = (leaked \/ (~refused /\ ended["sign"]))
    /\ pc' = [pc EXCEPT !["sign"] = "idle"]
    /\ UNCHANGED <<life, locks, stale, ended, cancelled, waited, wipedHeld, lateExport>>

----------------------------------------------------------------------------
(* Mnemonic export *)

\* The passphrase verified and the mutation lock taken, on an unlocked signer.
EStart ==
    /\ pc["export"] = "idle"
    /\ life = "unlocked"
    /\ pc' = [pc EXCEPT !["export"] = "started"]
    /\ stale' = [stale EXCEPT !["export"] = FALSE]
    /\ ended' = [ended EXCEPT !["export"] = FALSE]
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
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld, lateExport>>

\* The second context check and the delivery, still holding the key.
EDeliver ==
    /\ pc["export"] = "made"
    /\ IF ~cancelled["export"]
       THEN /\ pc' = [pc EXCEPT !["export"] = "delivered"]
            /\ lateExport' = (lateExport \/ life = "locked")
            /\ UNCHANGED <<waited, cancelled>>
       ELSE /\ Release("export", "idle")
            /\ UNCHANGED lateExport
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld>>

ERelease ==
    /\ pc["export"] = "delivered"
    /\ Release("export", "idle")
    /\ UNCHANGED <<life, locks, stale, ended, leaked, wipedHeld, lateExport>>

----------------------------------------------------------------------------
(* Lock and unlock *)

\* Every unlock attempt in flight finds the lock generation moved.
GenerationMoves == [u \in Unlockers |-> ulStale[u] \/ ul[u] = "deriving"]

\* The state locks and the generation moves for every holder in flight. A
\* signer in recovery locks the same way.
LockState ==
    /\ life \in {"unlocked", "recovery"}
    /\ locks < MaxLocks
    /\ life' = "locking"
    /\ locks' = locks + 1
    /\ stale' = [h \in Holders |-> stale[h] \/ pc[h] # "idle"]
    /\ ended' = [h \in Holders |-> ended[h] \/ pc[h] # "idle"]
    /\ ulStale' = GenerationMoves
    /\ UNCHANGED <<pc, cancelled, waited, leaked, wipedHeld, lateExport>>

\* A Lock on a signer already locked or locking: the generation still moves,
\* and no cleanup runs. Every holder in flight is stale already.
LockInactive ==
    /\ life \in {"locking", "draining", "locked"}
    /\ ulStale' = GenerationMoves
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked,
                   wipedHeld, lateExport>>

\* SetRecovery, or TryRecovery, from the unlocked state. The session ends for
\* every holder in flight. Under RecoveryEndsSession the generation moves with
\* it and every registered key use is cancelled (cancelKeyUses), so the
\* session's work stops; nothing waits for it and nothing is cleared, because
\* recovery keeps the keyring.
EnterRecovery ==
    /\ life = "unlocked"
    /\ locks < MaxLocks
    /\ life' = "recovery"
    /\ locks' = locks + 1
    /\ ended' = [h \in Holders |-> ended[h] \/ pc[h] # "idle"]
    /\ stale' = [h \in Holders |->
                    stale[h] \/ (RecoveryEndsSession /\ pc[h] # "idle")]
    /\ cancelled' = [h \in Holders |->
                        cancelled[h] \/ (RecoveryEndsSession /\ Holding(h))]
    /\ UNCHANGED <<pc, waited, leaked, wipedHeld, lateExport>>

\* PromoteRecoveryToUnlocked: a reconcile succeeded.
LeaveRecovery ==
    /\ life = "recovery"
    /\ life' = "unlocked"
    /\ UNCHANGED <<locks, pc, stale, ended, cancelled, waited, leaked, wipedHeld, lateExport>>

\* drainKeyUsers cancels every registered key use and starts waiting.
DrainBegin ==
    /\ life = "locking"
    /\ life' = "draining"
    /\ cancelled' = [h \in Holders |-> cancelled[h] \/ (Holding(h) /\ waited[h])]
    /\ UNCHANGED <<locks, pc, stale, ended, waited, leaked, wipedHeld, lateExport>>

\* The drain returns and the session is cleared.
Wipe ==
    /\ life = "draining"
    /\ DrainWaits => \A h \in Holders : ~(Holding(h) /\ waited[h])
    /\ life' = "locked"
    /\ wipedHeld' = (wipedHeld \/ \E h \in Holders : Holding(h))
    /\ UNCHANGED <<locks, pc, stale, ended, cancelled, waited, leaked, lateExport>>

\* TryUnlock reads the lock generation, then runs its unlock function. It
\* waits for every cleanup in progress first, so it starts from the locked
\* state; without the wait it may also start between LockState and Wipe.
UnlockStart(u) ==
    /\ ul[u] = "idle"
    /\ IF UnlockWaitsForCleanup
       THEN life = "locked" /\ late = "none"
       ELSE life \in {"locking", "draining", "locked"}
    /\ ul' = [ul EXCEPT ![u] = "deriving"]
    /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked,
                   wipedHeld, lateExport, late, wipedLive>>

\* The unlock function has returned. With the generation unchanged the
\* attempt publishes a session; a cleanup it overtook carries on as `late`.
\* With the generation moved the attempt lost to a lock and clears what it
\* loaded: under LoserLocks it first locks as LockState does, moving the
\* generation for the other attempt and the holders; otherwise its cleanup
\* carries on as `late`, whatever the signer's state.
UnlockFinish(u) ==
    /\ ul[u] = "deriving"
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ IF ~ulStale[u]
       THEN /\ life \in {"locking", "draining"} => late = "none"
            /\ late' = IF life \in {"locking", "draining"} THEN life ELSE late
            /\ life' = "unlocked"
            /\ UNCHANGED <<stale, ended, ulStale>>
       ELSE IF LoserLocks
       THEN /\ life' = "locking"
            /\ stale' = [h \in Holders |-> stale[h] \/ pc[h] # "idle"]
            /\ ended' = [h \in Holders |-> ended[h] \/ pc[h] # "idle"]
            /\ ulStale' = [v \in Unlockers |->
                             IF v = u THEN FALSE ELSE GenerationMoves[v]]
            /\ UNCHANGED late
       ELSE /\ late = "none"
            /\ late' = "locking"
            /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
            /\ UNCHANGED <<life, stale, ended>>
    /\ UNCHANGED <<locks, pc, cancelled, waited, leaked, wipedHeld, lateExport,
                   wipedLive>>

\* The late cleanup's drainKeyUsers.
LateDrainBegin ==
    /\ late = "locking"
    /\ late' = "draining"
    /\ cancelled' = [h \in Holders |-> cancelled[h] \/ (Holding(h) /\ waited[h])]
    /\ UNCHANGED <<life, locks, pc, stale, ended, waited, leaked, wipedHeld,
                   lateExport, wipedLive>>

\* The late cleanup clears the session, whatever state the signer is in.
LateWipe ==
    /\ late = "draining"
    /\ DrainWaits => \A h \in Holders : ~(Holding(h) /\ waited[h])
    /\ late' = "none"
    /\ wipedHeld' = (wipedHeld \/ \E h \in Holders : Holding(h))
    /\ wipedLive' = (wipedLive \/ life = "unlocked")
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked, lateExport>>

----------------------------------------------------------------------------
Next ==
    \/ /\ \/ SStart \/ SRegister \/ SMake \/ SRelease \/ SReturn
          \/ EStart \/ ERegister \/ ERead \/ EDeliver \/ ERelease
          \/ DrainBegin \/ Wipe
          \* Recovery moves the session generation, not the lock generation
          \* the unlock fence compares.
          \/ EnterRecovery \/ LeaveRecovery
       /\ UNCHANGED <<late, wipedLive, ul, ulStale>>
    \/ /\ LockState \/ LockInactive
       /\ UNCHANGED <<late, wipedLive, ul>>
    \/ \E u \in Unlockers : UnlockStart(u) \/ UnlockFinish(u)
    \/ /\ LateDrainBegin \/ LateWipe
       /\ UNCHANGED <<ul, ulStale>>

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

TypeOK ==
    /\ life \in {"unlocked", "recovery", "locking", "draining", "locked"}
    /\ locks \in 0..MaxLocks
    /\ pc["sign"] \in {"idle", "started", "held", "made", "released"}
    /\ pc["export"] \in {"idle", "started", "held", "made", "delivered"}
    /\ \A h \in Holders : stale[h] \in BOOLEAN /\ ended[h] \in BOOLEAN
    /\ \A h \in Holders : cancelled[h] \in BOOLEAN /\ waited[h] \in BOOLEAN
    /\ leaked \in BOOLEAN /\ wipedHeld \in BOOLEAN /\ lateExport \in BOOLEAN
    /\ late \in {"none", "locking", "draining"}
    /\ wipedLive \in BOOLEAN
    /\ \A u \in Unlockers : ul[u] \in {"idle", "deriving"} /\ ulStale[u] \in BOOLEAN

\* KU1: no rotating signature is returned after a lock or a recovery began
\* during its sign.
KU1_NoSignatureAfterLock == ~leaked

\* KU2: the session is never cleared while a key use is registered.
KU2_NoKeyMaterialAtWipe == ~wipedHeld

\* KU3: an export never delivers after the session was cleared.
KU3_NoExportAfterWipe == ~lateExport

\* KU4: the session is never cleared while the signer is unlocked.
KU4_NoWipeWhileUnlocked == ~wipedLive

Safety ==
    /\ TypeOK
    /\ KU1_NoSignatureAfterLock
    /\ KU2_NoKeyMaterialAtWipe
    /\ KU3_NoExportAfterWipe
    /\ KU4_NoWipeWhileUnlocked

=============================================================================
