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

An unlock (TryUnlock) is four steps, because its unlock function (the
passphrase check, a check of the state, and the key load) runs outside the
state mutex: UnlockStart reads the lock generation and the session
generation; UnlockCheck takes the store mutation lock and checks the state;
UnlockLoaded is the end of the load, where that lock is released; and
UnlockFinish compares the generations. An attempt that finds the signer
already unlocked at its check answers from the session in service and ends
there: it loads nothing, publishes nothing and clears nothing. The code
answers only for a session the signer stayed unlocked in across the
passphrase check, and UnlockCheck is the step that confirms it: an attempt
whose session ended during the passphrase check loads, as one that found
the signer locked does. The load
replaces the keyring and the key maps, and a load that fails validation
publishes an empty key snapshot, so a load under a session in service could
leave a signer that says unlocked and cannot sign.
Unlock attempts run one at a time (unlockMu), and the check and the load
hold the store mutation lock, which a store change holds when it enters
recovery and a reconcile holds when it lifts one; so no other way to the
unlocked state lands between an attempt's check and the end of its load.

A recovery unlock (TryRecovery, from productruntime's Unlock when a reconcile or the
selected generation fails) is two steps, RecoveryStart and RecoveryFinish,
and does not take unlockMu, so it may run beside an unlock or another
recovery unlock. It opens the keyring and enters recovery; its keyring open
replaces nothing when it fails, so a failure closes nothing.

An attempt of either kind that finds the lock generation moved has lost to
a lock, and its function may have loaded keys after that lock's cleanup, so
it clears them. The other attempt may meanwhile have published a session
those keys now serve, or may publish one before the loser's clear runs; so
the loser locks the signer as a lock does before it clears. An unlock that
finds the session generation moved with the lock generation unmoved met an
entry into recovery, and publishes nothing.

Thirteen guards are switchable:

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
                      an attempt starts only once the lock's cleanup has
                      returned (runtime.Runtime.TryUnlock, TryRecovery and
                      FinishMaintenance wait for it). Without it, an attempt
                      may land between LockState and Wipe, and the rest of
                      that cleanup runs against the new session.
  LoserLocks          an attempt that lost to a lock locks the signer, moving
                      the generation, before its cleanup clears what it
                      loaded (runtime.Runtime lockForCleanupLocked). Without it,
                      the cleanup runs in whatever state the signer is in, and
                      clears a session another attempt published.
  UnlockFencesRecovery
                      an unlock whose session generation moved while its
                      unlock function ran publishes nothing and runs no
                      cleanup (runtime.Runtime TryUnlock). Without it, an
                      unlock publishes unlocked over a recovery a store
                      change entered after the unlock began.
  RecoveryReentryMovesSession
                      an entry into recovery from recovery moves the session
                      too (enterRecoveryLocked), not only one from the
                      unlocked state. Without it, an unlock begun in
                      recovery misses a restore, rollback or reconcile that
                      entered recovery again, and publishes over it.
  AnswersFromSession  an unlock checks the state before it loads, and one
                      that finds the signer unlocked loads nothing
                      (productruntime performUnlock, AnswerFromSession).
                      Without it, the attempt loads under the session in
                      service.
  AnswerEndsAtCheck   an attempt that answered from the session ends at its
                      check, before the fence (errAnsweredFromSession).
                      Without it, the attempt goes on to the fence with
                      nothing loaded, and when a lock came in after its
                      check it locks the signer and runs a cleanup as a
                      loser does, which can end a session published since.
  UnlocksOneAtATime   an unlock starts only when no other unlock is in
                      flight (productruntime unlockMu). Without it, a second
                      unlock checks while the first has loaded and not yet
                      published, loads, and the first publishes under it.
  LoadHoldsStoreLock  the check and the load hold the store mutation lock,
                      so no store change enters recovery and no reconcile
                      lifts one between them. Without it, a reconcile
                      promotes the signer out of recovery during an unlock's
                      load.

Properties:

  KU1  a rotating signature is never returned once a lock or a recovery has
       begun after its sign started and before its final check;
  KU2  the session is never cleared while a key use is registered;
  KU3  an export never delivers after the session was cleared;
  KU4  the session is never cleared while the signer is unlocked;
  KU5  an unlock never publishes unlocked over a recovery entered after it
       began;
  KU6  an unlock never loads keys while the signer is unlocked: no load runs
       under a session in service;
  KU7  an unlock that answered from the session never locks the signer or
       runs a cleanup.

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
    BeginMaintenance; EnterRecovery transcribes SetRecovery, RecoveryStart
    and RecoveryFinish TryRecovery, and LeaveRecovery
    PromoteRecoveryToUnlocked, there, with productruntime's cancelKeyUses on
    the way in; DrainBegin and Wipe transcribe
    internal/signerapp/productruntime/runtime.go drainKeyUsers and
    performLockCleanup; registration transcribes KeyUseContext.
  - UnlockStart's and RecoveryStart's guard transcribes awaitCleanups in
    internal/signerapp/runtime/runtime.go, which TryUnlock and TryRecovery
    call before they read the lock generation (FinishMaintenance calls it
    too, before it compares the generation its token recorded), and
    UnlockStart's read of the session with it; UnlockStart's other guard
    is productruntime's unlockMu, which TryUnlock holds across the attempt.
    UnlockCheck and UnlockLoaded transcribe productruntime's performUnlock:
    lockStoreMutation and AnswerFromSession, which reads the session
    generation, checks the passphrase and confirms the signer is still
    unlocked in that session, and, when it is, the return of
    errAnsweredFromSession, which ends the attempt before the fence;
    otherwise the passphrase check, ReloadWithPassphrase, and the release
    of the store mutation lock. UnlockCheck is that confirmation, or the
    read when the signer was not unlocked: under unlockMu and the store
    mutation lock nothing returns the signer to unlocked between it and the
    end of the load. UnlockFinish and RecoveryFinish
    transcribe the fences after the unlock function: when the lock
    generation moved, lockForCleanupLocked and the cleanup it decides, and
    otherwise, for TryUnlock, when the session moved, the return with
    ErrRecoveryDuringUnlock, and for TryRecovery enterRecoveryLocked.
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
    UnlockFencesRecovery, \* BOOLEAN: an unlock does not publish over a later recovery
    RecoveryReentryMovesSession, \* BOOLEAN: an entry from recovery moves the session
    AnswersFromSession,  \* BOOLEAN: an unlock of an unlocked signer loads nothing
    AnswerEndsAtCheck,   \* BOOLEAN: such an unlock ends before the fence
    UnlocksOneAtATime,   \* BOOLEAN: unlocks run one at a time
    LoadHoldsStoreLock,  \* BOOLEAN: the check and the load hold the store lock
    MaxLocks             \* bound on lock transitions (keeps the space finite)

Holders == {"sign", "export"}

\* Two attempts that may overlap: each is an unlock (TryUnlock) or a recovery
\* unlock (TryRecovery), chosen when it starts.
Unlockers == {"u1", "u2"}

\* An unlock's steps between its start and its fence: "deriving" until it
\* checks the state, "loading" while it loads under the store mutation lock,
\* "loaded" once it has released it, and "answered" for an attempt that found
\* the signer unlocked and, without AnswerEndsAtCheck, goes on to the fence.
\* "recovering" is a recovery unlock in flight.
UnlockSteps == {"deriving", "loading", "loaded", "answered"}

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
    ul,         \* each attempt: "idle", one of UnlockSteps, or "recovering"
    ulStale,    \* the lock generation moved after the attempt read it
    ulRecov,    \* the session moved after the attempt read it (the guard's flag)
    ulSawRecov, \* ghost: recovery was entered after the attempt began
    overRecovery, \* ghost: an unlock published over a recovery entered after
                  \* it began
    answeredDisturbed \* ghost: an unlock that answered from the session
                      \* locked the signer or ran a cleanup

vars == <<life, locks, pc, stale, ended, cancelled, waited, leaked, wipedHeld,
          lateExport, late, wipedLive, ul, ulStale, ulRecov, ulSawRecov,
          overRecovery, answeredDisturbed>>

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
    /\ ulRecov = [u \in Unlockers |-> FALSE]
    /\ ulSawRecov = [u \in Unlockers |-> FALSE]
    /\ overRecovery = FALSE
    /\ answeredDisturbed = FALSE

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

\* An attempt is in flight from its start to its finish.
InFlight(u) == ul[u] # "idle"

\* An unlock (TryUnlock) is in flight.
Unlocking(u) == ul[u] \in UnlockSteps

\* An unlock is loading: it holds the store mutation lock and passphraseLock.
Loading == \E u \in Unlockers : ul[u] = "loading"

\* Every attempt in flight finds the lock generation moved.
GenerationMoves == [u \in Unlockers |-> ulStale[u] \/ InFlight(u)]

\* The state locks and the generation moves for every holder in flight. A
\* signer in recovery locks the same way. From the locked state this is
\* BeginMaintenance, which runs a cleanup there too, and a maintenance that
\* ends without republishing, which clears what it reloaded.
\* BeginMaintenance does not wait for cleanups, so in the code it may also
\* start a second cleanup while a lock's is running (life "locking" or
\* "draining" here). That is left out: the signer stays locked throughout,
\* registration is refused, and an unlock waits for both cleanups.
LockState ==
    /\ life \in {"unlocked", "recovery", "locked"}
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

\* An entry into recovery from `from` moves the session generation unless it
\* comes from recovery without RecoveryReentryMovesSession.
SessionMoves(from) ==
    RecoveryEndsSession /\ (from # "recovery" \/ RecoveryReentryMovesSession)

\* Entering recovery from `from`. The session ends for every holder in
\* flight. Under RecoveryEndsSession the generation moves with it and every
\* registered key use is cancelled (cancelKeyUses), so the session's work
\* stops; nothing waits for it and nothing is cleared, because recovery
\* keeps the keyring. The generation moving is also what every other attempt
\* in flight later finds (ulRecov); ulSawRecov records every entry, whatever
\* moved, for KU5. self is the recovery unlock that enters, which finishes
\* with the step.
EnterRecoveryFrom(from, self) ==
    /\ life' = "recovery"
    /\ locks' = locks + 1
    /\ ended' = [h \in Holders |-> ended[h] \/ pc[h] # "idle"]
    /\ stale' = [h \in Holders |->
                    stale[h] \/ (RecoveryEndsSession /\ pc[h] # "idle")]
    /\ cancelled' = [h \in Holders |->
                        cancelled[h] \/ (RecoveryEndsSession /\ Holding(h))]
    /\ ulRecov' = [u \in Unlockers |->
                      IF u = self THEN FALSE
                      ELSE ulRecov[u] \/ (SessionMoves(from) /\ InFlight(u))]
    /\ ulSawRecov' = [u \in Unlockers |->
                         IF u = self THEN FALSE
                         ELSE ulSawRecov[u] \/ InFlight(u)]

\* SetRecovery from the unlocked state or from recovery: a store change that
\* ends in doubt, a restore, rollback or reconcile that enters recovery
\* again, or a reload without the passphrase that finds a content defect in
\* the selected generation, a failed validation or an address collision
\* (productruntime's Reload, for the watcher and the in-place writes). Each holds the store mutation lock, so under
\* LoadHoldsStoreLock none lands while an unlock loads. From recovery there is no session left to
\* end: every holder in flight started before the first entry. A recovery
\* unlock's entry is RecoveryFinish.
EnterRecovery ==
    /\ life \in {"unlocked", "recovery"}
    /\ locks < MaxLocks
    /\ LoadHoldsStoreLock => ~Loading
    /\ EnterRecoveryFrom(life, "none")
    /\ UNCHANGED <<pc, waited, leaked, wipedHeld, lateExport>>

\* PromoteRecoveryToUnlocked: a reconcile succeeded. The reconcile holds the
\* store mutation lock from its reload to the promotion.
LeaveRecovery ==
    /\ life = "recovery"
    /\ LoadHoldsStoreLock => ~Loading
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

\* TryUnlock and TryRecovery wait for every cleanup in progress first, so an
\* attempt never starts while one runs; it may start on a signer already
\* unlocked or in recovery. Without the wait it may also start between
\* LockState and Wipe.
CleanupsDone ==
    UnlockWaitsForCleanup =>
        (life \in {"locked", "unlocked", "recovery"} /\ late = "none")

\* An attempt starts: it reads the lock generation and the session.
StartAttempt(u, step) ==
    /\ ul[u] = "idle"
    /\ CleanupsDone
    /\ ul' = [ul EXCEPT ![u] = step]
    /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
    /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
    /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked,
                   wipedHeld, lateExport, late, wipedLive, overRecovery,
                   answeredDisturbed>>

\* TryUnlock begins. Under UnlocksOneAtATime it holds unlockMu across the
\* attempt, so it starts only when no other unlock is in flight; a recovery
\* unlock does not take it.
UnlockStart(u) ==
    /\ UnlocksOneAtATime => \A v \in Unlockers \ {u} : ~Unlocking(v)
    /\ StartAttempt(u, "deriving")

\* TryRecovery begins.
RecoveryStart(u) == StartAttempt(u, "recovering")

\* The unlock function takes the store mutation lock, which another unlock's
\* load holds (and passphraseLock with it, whatever LoadHoldsStoreLock says),
\* checks the passphrase and the state, and loads unless the signer is
\* unlocked. Under AnswersFromSession an attempt that finds it unlocked loads
\* nothing; under AnswerEndsAtCheck it ends here, answering from the session,
\* and otherwise goes on to the fence with nothing loaded.
UnlockCheck(u) ==
    /\ ul[u] = "deriving"
    /\ ~Loading
    /\ IF AnswersFromSession /\ life = "unlocked"
       THEN IF AnswerEndsAtCheck
            THEN /\ ul' = [ul EXCEPT ![u] = "idle"]
                 /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
                 /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
                 /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
            ELSE /\ ul' = [ul EXCEPT ![u] = "answered"]
                 /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov>>
       ELSE /\ ul' = [ul EXCEPT ![u] = "loading"]
            /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov>>
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked,
                   wipedHeld, lateExport, late, wipedLive, overRecovery,
                   answeredDisturbed>>

\* The load ends and the store mutation lock is released.
UnlockLoaded(u) ==
    /\ ul[u] = "loading"
    /\ ul' = [ul EXCEPT ![u] = "loaded"]
    /\ UNCHANGED <<life, locks, pc, stale, ended, cancelled, waited, leaked,
                   wipedHeld, lateExport, late, wipedLive, ulStale, ulRecov,
                   ulSawRecov, overRecovery, answeredDisturbed>>

\* An attempt that lost to a lock clears what it loaded: under LoserLocks it
\* first locks as LockState does, moving the generation for the other
\* attempt and the holders; otherwise its cleanup carries on as `late`,
\* whatever the signer's state.
LoseToLock(u) ==
    IF LoserLocks
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

\* The unlock function has returned. With the generation unchanged the
\* attempt publishes a session; a cleanup it overtook carries on as `late`.
\* Under UnlockFencesRecovery an attempt that met an entry into recovery
\* (the session moved, the generation did not) publishes nothing and runs no
\* cleanup instead; without it, it publishes over that recovery.
\* With the generation moved the attempt lost to a lock (LoseToLock). One
\* that answered from the session and came here without AnswerEndsAtCheck
\* loaded nothing, and its loss disturbs whatever session there is by then.
UnlockFinish(u) ==
    /\ ul[u] \in {"loaded", "answered"}
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
    /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
    /\ IF ~ulStale[u]
       THEN IF UnlockFencesRecovery /\ ulRecov[u]
            THEN UNCHANGED <<life, late, stale, ended, ulStale, overRecovery,
                             answeredDisturbed>>
            ELSE /\ life \in {"locking", "draining"} => late = "none"
                 /\ late' = IF life \in {"locking", "draining"} THEN life ELSE late
                 /\ life' = "unlocked"
                 /\ overRecovery' = (overRecovery \/ (ulSawRecov[u] /\ life = "recovery"))
                 /\ UNCHANGED <<stale, ended, ulStale, answeredDisturbed>>
       ELSE /\ LoseToLock(u)
            /\ answeredDisturbed' = (answeredDisturbed \/ ul[u] = "answered")
            /\ UNCHANGED overRecovery
    /\ UNCHANGED <<locks, pc, cancelled, waited, leaked, wipedHeld, lateExport,
                   wipedLive>>

\* TryRecovery's keyring unlock has returned. With the generation unchanged
\* it enters recovery (enterRecoveryLocked, whatever the state, the locked
\* one included); a cleanup it overtook carries on as `late`. With the
\* generation moved it lost to a lock, as an unlock does.
RecoveryFinish(u) ==
    /\ ul[u] = "recovering"
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ IF ~ulStale[u]
       THEN /\ locks < MaxLocks
            /\ life \in {"locking", "draining"} => late = "none"
            /\ late' = IF life \in {"locking", "draining"} THEN life ELSE late
            /\ EnterRecoveryFrom(life, u)
            /\ UNCHANGED ulStale
       ELSE /\ LoseToLock(u)
            /\ UNCHANGED locks
            /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
            /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
            /\ UNCHANGED cancelled
    /\ UNCHANGED <<pc, waited, leaked, wipedHeld, lateExport, wipedLive,
                   overRecovery, answeredDisturbed>>

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
          \/ DrainBegin \/ Wipe \/ LeaveRecovery
       /\ UNCHANGED <<late, wipedLive, ul, ulStale, ulRecov, ulSawRecov,
                      overRecovery, answeredDisturbed>>
    \* Recovery moves the session generation, which the unlock's second fence
    \* compares, not the lock generation its first one does.
    \/ /\ EnterRecovery
       /\ UNCHANGED <<late, wipedLive, ul, ulStale, overRecovery, answeredDisturbed>>
    \/ /\ LockState \/ LockInactive
       /\ UNCHANGED <<late, wipedLive, ul, ulRecov, ulSawRecov, overRecovery,
                      answeredDisturbed>>
    \/ \E u \in Unlockers :
          \/ UnlockStart(u) \/ UnlockCheck(u) \/ UnlockLoaded(u) \/ UnlockFinish(u)
          \/ RecoveryStart(u) \/ RecoveryFinish(u)
    \/ /\ LateDrainBegin \/ LateWipe
       /\ UNCHANGED <<ul, ulStale, ulRecov, ulSawRecov, overRecovery, answeredDisturbed>>

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
    /\ \A u \in Unlockers : ul[u] \in {"idle", "recovering"} \cup UnlockSteps
    /\ \A u \in Unlockers : ulStale[u] \in BOOLEAN
    /\ \A u \in Unlockers : ulRecov[u] \in BOOLEAN /\ ulSawRecov[u] \in BOOLEAN
    /\ overRecovery \in BOOLEAN
    /\ answeredDisturbed \in BOOLEAN

\* KU1: no rotating signature is returned after a lock or a recovery began
\* during its sign.
KU1_NoSignatureAfterLock == ~leaked

\* KU2: the session is never cleared while a key use is registered.
KU2_NoKeyMaterialAtWipe == ~wipedHeld

\* KU3: an export never delivers after the session was cleared.
KU3_NoExportAfterWipe == ~lateExport

\* KU4: the session is never cleared while the signer is unlocked.
KU4_NoWipeWhileUnlocked == ~wipedLive

\* KU5: an unlock never publishes unlocked over a recovery entered after it
\* began.
KU5_NoUnlockOverLaterRecovery == ~overRecovery

\* KU6: an unlock never loads keys while the signer is unlocked. A load
\* replaces the keyring and the key maps, and one that fails validation
\* publishes an empty key snapshot, so a load under a session in service
\* could leave a signer unlocked and unable to sign.
KU6_NoLoadUnderSession ==
    \A u \in Unlockers : ul[u] = "loading" => life # "unlocked"

\* KU7: an unlock that answered from the session never locks the signer or
\* runs a cleanup: it loaded nothing for a cleanup to clear.
KU7_AnsweredUnlockLeavesSession == ~answeredDisturbed

Safety ==
    /\ TypeOK
    /\ KU1_NoSignatureAfterLock
    /\ KU2_NoKeyMaterialAtWipe
    /\ KU3_NoExportAfterWipe
    /\ KU4_NoWipeWhileUnlocked
    /\ KU5_NoUnlockOverLaterRecovery
    /\ KU6_NoLoadUnderSession
    /\ KU7_AnsweredUnlockLeavesSession

=============================================================================
