---------------------------- MODULE key_use_lock ----------------------------
EXTENDS Naturals, TLC

(***************************************************************************
Key-use window model: how a lock ends every use of loaded key material, and
what may still leave the signer while it does.

Two holders use the same mechanism. A signing request (rotating sign, ordinary
/sign, base or cosigner /sign/component, or /sign/assemble) holds key
material after approval and gates, produces its signature, zeroes the key,
ends its key use before any blocking audit write, and rechecks the session
before returning the signature. A mnemonic export holds the key while it reads
the credential and delivers the phrase, and releases afterwards. Both register
a key use (Runtime.KeyUseContext) whose context the lock cancels and whose
release the lock waits for before it clears the session.

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

An unlock request is one attempt, and the attempt holds the store mutation
lock from its start to its end (productruntime's Unlock). AttemptStart
takes the lock, waits for any lock cleanup in progress, and reads the lock
generation, the session generation and the state once
(runtime.Runtime.BeginAttempt): every later check and both of the attempt's
ends compare that reading. An attempt that finds the signer unlocked checks
the passphrase and answers from the session in service, or, when a lock
came during the check, that the signer locked; either way it ends there
(AnswerCheck): it loads nothing, publishes nothing and clears nothing. A
load builds and then installs, and the install would replace the keyring,
the key maps, the policy and the token index of a session in service that
concurrent changes had moved on from; a build that fails closes nothing.

An attempt on a signer locked or in recovery opens the store root and
reconciles (Reconcile), loads (Load) and publishes (Publish), or, when the
reconcile or the load finds the store needing it, takes its second end and
enters recovery (RecoveryOpen, RecoveryFinish). The keyring it opens is the
one it reconciles, builds and installs with: one derivation per attempt.
Before the reconcile, before the load and before the recovery
open it checks its reading, and an attempt that has lost to a lock stops
there with nothing to clear.

Every entry into recovery and every reconcile's promotion out of it hold
the store mutation lock too, as does a passphrase change's republish, so
none lands inside an attempt, and two attempts never overlap. The fences
compare the session as well as the lock generation; under the hold no entry
into recovery reaches them, so they are layered guards, and their negative
controls switch the hold off.

An attempt that finds the lock generation moved at a fence has lost to a
lock, and may have loaded keys, or opened a keyring, after that lock's
cleanup ran, so it clears them; it locks the signer as a lock does first.
An attempt that finds the session generation moved with the lock
generation unmoved met an entry into recovery, and publishes nothing.

Thirteen guards are switchable:

  RegisterChecksLock  registration refuses once the state is locked. Without
                      it, a holder registering after DrainBegin gets a fresh,
                      uncancelled context the drain does not wait for.
  DrainWaits          Wipe waits for every key use registered before
                      DrainBegin.
  FinalRecheck        a sign rechecks after its release (and after any audit
                      write) and returns nothing when the signer locked
                      (releaseRefused for rotating, keyUseRefused for the
                      others).
  GenerationCheck     that recheck compares the session generation captured at
                      the start (LockGeneration / inSession), not just the
                      current state, so a lock and an unlock in between still
                      refuse.
  RecoveryEndsSession entering recovery from the unlocked state moves the
                      session generation (runtime.Runtime.SetRecovery and
                      EnterRecovery) and cancels the registered key uses, so
                      a recovery and a reconcile in between refuse as well.
  UnlockWaitsForCleanup
                      an attempt starts only once the lock's cleanup has
                      returned (runtime.Runtime.BeginAttempt and
                      FinishMaintenance wait for it). Without it, an attempt
                      may land between LockState and Wipe, and the rest of
                      that cleanup runs against the new session.
  LoserLocks          an attempt that lost to a lock locks the signer, moving
                      the generation, before its cleanup clears what it
                      loaded (runtime.Runtime lockForCleanupLocked). Without it,
                      the cleanup runs in whatever state the signer is in, and
                      clears a session another attempt published.
  UnlockFencesRecovery
                      an attempt whose session generation moved since its
                      reading publishes nothing and runs no
                      cleanup (runtime.Runtime PublishUnlocked). Without it,
                      and without the hold, an unlock publishes unlocked over
                      a recovery a store change entered after it began.
  RecoveryReentryMovesSession
                      an entry into recovery from recovery moves the session
                      too (enterRecoveryLocked), not only one from the
                      unlocked state. Without it, and without the hold, an
                      unlock begun in recovery misses a restore, rollback or
                      reconcile that entered recovery again, and publishes
                      over it.
  AnswersFromSession  an attempt that finds the signer unlocked answers
                      from the session and loads nothing (productruntime
                      answerFromSession). Without it, the attempt loads
                      under the session in service.
  AnswerEndsAtCheck   an attempt that answered from the session ends at its
                      check, before the fence (answerFromSession compares
                      the reading itself).
                      Without it, the attempt goes on to the fence with
                      nothing loaded, and when a lock came in after its
                      check it locks the signer and runs a cleanup as a
                      loser does, which can end a session published since.
  AttemptHoldsStoreLock
                      the attempt holds the store mutation lock from its
                      start to its end (productruntime Unlock), so no other
                      attempt runs, no store change enters recovery and no
                      reconcile lifts one inside it. Without it, a second
                      attempt loads under the session the first published,
                      and a first attempt's entry into recovery ends a
                      session a second published.
  ExitsShareReading   the recovery end compares the attempt's reading taken
                      at its start (runtime.Runtime EnterRecovery), not one
                      of its own. Without it, a lock that lands during the
                      reconcile or the load passes the recovery end's fence,
                      and the attempt moves the locked signer into recovery.

Properties:

  KU1  a signature (rotating, ordinary /sign, base or cosigner
       /sign/component, or /sign/assemble) is never returned once a lock or a
       recovery has begun after its request started and before its final check;
  KU2  the session is never cleared while a key use is registered;
  KU3  an export never delivers after the session was cleared;
  KU4  the session is never cleared while the signer is unlocked;
  KU5  an unlock never publishes unlocked over a recovery entered after it
       began;
  KU6  an unlock never loads keys while the signer is unlocked: no load runs
       under a session in service;
  KU7  an unlock that answered from the session never locks the signer or
       runs a cleanup;
  KU8  a lock that lands during an attempt stands: the attempt neither
       publishes unlocked nor enters recovery after it;
  KU9  an attempt's entry into recovery never ends a session another
       attempt published while it ran.

The final check and the return are separate in the code; a lock landing
between them is indistinguishable from one landing just after the return, so
the model makes them one step. The same holds for an export's last context
check and its delivery: a lock that begins during delivery waits for it,
which KU2 covers.

Scope: one signing request and one export, repeating. The stage table worker,
rotating prepare and a cosigner's external check step are holders of the same
kind; KU2 covers any holder. The rotating sign's leaf choice and release memory
are rotating_leaf_release.tla's. Shutdown
(Runtime.EndKeyUses, then Runtime.Destroy) is not modeled: the process exits
right after it. It refuses new key uses as a lock does, drains like a lock
but only until its deadline, then clears the session whether or not the
holders released; a holder still running then
keeps its own decrypted copy until it releases or the process exits, and
shutdown records the stop as incomplete.

Code anchors:
  - SStart/SRegister/SMake/SRelease/SReturn transcribe:
    * internal/signerapp/signing/rotating_flow.go SignRotatingWithContext: the
      lockGeneration capture, deps.keyUse, releaseRefused before the seed is
      used, rs.close and endKeyUse before the audit write, and releaseRefused
      on the request context before the response.
    * internal/signerapp/daemon/signing_service.go newSigningServiceWithAudit
      (inSession capturing UnlockedGeneration) together with the post-approval
      / post-gate key-use windows in internal/signerapp/signing/service.go
      (openKeyUse, keyUseRefused, signGroupWithPlanContext,
      signComponentWithContext, AssembleWithContext), execution.go
      (executeGroupSigning), host_cosigner.go
      (PrepareHostComponentWithContext, assembleHostTarget),
      component_sign.go (signPreparedCosignerComponents), and
      component_assemble.go (assembleDecoded, rejectLocalCosignedPassthrough).
      Every route releases its key use before SReturn's final keyUseRefused
      check (after SIGN_APPROVED on the audited routes, directly on
      /sign/assemble).
  - EStart/ERegister/ERead/EDeliver/ERelease transcribe
    internal/signerapp/keyadmin/export.go ExportKey.
  - LockState transcribes internal/signerapp/runtime/runtime.go Lock and
    BeginMaintenance; EnterRecovery transcribes SetRecovery,
    RecoveryFinish EnterRecovery, and LeaveRecovery
    PromoteRecoveryToUnlocked, there, with productruntime's cancelKeyUses on
    SetRecovery's way in. An attempt's own entry (RecoveryFinish) cancels
    nothing in the code: it begins locked or in recovery, where no key use
    is registered, so the model's cancellation there changes nothing; DrainBegin and Wipe transcribe
    internal/signerapp/productruntime/runtime.go drainKeyUsers and
    performLockCleanup; registration transcribes KeyUseContext.
  - AttemptStart transcribes productruntime's Unlock taking the store
    mutation lock (lockStoreMutation) and runtime.Runtime.BeginAttempt:
    awaitCleanups, then the reading. AnswerCheck transcribes
    answerFromSession: the passphrase check and the comparison with the
    reading. Reconcile transcribes unlockHeld's store root open, its first
    LostToLock check and the reconcile; Load its second check, the build
    on the keyring that open gave it (productruntime/view.go buildOpened),
    which changes nothing live, and its install (publishUnlock), which replaces
    the keyring, the key maps, the policy and the token index; Publish
    runtime.Runtime.PublishUnlocked; RecoveryOpen productruntime's
    unlockIntoRecovery (its LostToLock check and the install of recovery's
    view, keyring included) and RecoveryFinish the fence of
    runtime.Runtime EnterRecovery. At the fences, when the lock generation moved,
    lockForCleanupLocked and the cleanup it decides; otherwise, for the
    publish, when the session moved, the return with
    ErrRecoveryDuringUnlock, and for the recovery end enterRecoveryLocked.
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
    AttemptHoldsStoreLock, \* BOOLEAN: an attempt holds the store lock throughout
    ExitsShareReading,   \* BOOLEAN: the recovery end fences on the attempt's reading
    MaxLocks             \* bound on lock transitions (keeps the space finite)

Holders == {"sign", "export"}

\* Two unlock requests, which under AttemptHoldsStoreLock never overlap.
Unlockers == {"u1", "u2"}

\* An attempt's steps: "checking" for one that found the signer unlocked,
\* until its answer; "reconciling" for one that found it locked or in
\* recovery, until its reconcile; "loading" until its load ends; "loaded"
\* until its publish; "answered" for one that answered from the session and,
\* without AnswerEndsAtCheck, goes on to the fence; "recovering" and "opened"
\* on its way into recovery, before and after the keyring open.
UnlockSteps == {"checking", "reconciling", "loading", "loaded", "answered",
                "recovering", "opened"}

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
    ul,         \* each attempt: "idle" or one of UnlockSteps
    ulStale,    \* the lock generation moved after the attempt read it
    ulRecov,    \* the session moved after the attempt read it (the guard's flag)
    ulSawRecov, \* ghost: recovery was entered after the attempt began
    overRecovery, \* ghost: an unlock published over a recovery entered after
                  \* it began
    answeredDisturbed, \* ghost: an unlock that answered from the session
                      \* locked the signer or ran a cleanup
    ulLocked,   \* ghost: a lock landed after the attempt began
    lockUndone, \* ghost: an attempt published or entered recovery after a
                \* lock landed during it
    ulSawPublish, \* ghost: another attempt published while this one ran
    endedPublished \* ghost: an attempt's entry into recovery ended a session
                   \* another attempt published while it ran

vars == <<life, locks, pc, stale, ended, cancelled, waited, leaked, wipedHeld,
          lateExport, late, wipedLive, ul, ulStale, ulRecov, ulSawRecov,
          overRecovery, answeredDisturbed, ulLocked, lockUndone, ulSawPublish,
          endedPublished>>

\* The ghosts KU8 and KU9 read, which only the attempt actions change.
attemptGhosts == <<ulLocked, lockUndone, ulSawPublish, endedPublished>>

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
    /\ ulLocked = [u \in Unlockers |-> FALSE]
    /\ lockUndone = FALSE
    /\ ulSawPublish = [u \in Unlockers |-> FALSE]
    /\ endedPublished = FALSE

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
(* Signing request (rotating and non-rotating) *)

\* releaseRefused / keyUseRefused: the signer is unlocked, the session
\* generation is the one captured at the start, and the key use has not been
\* cancelled.
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

\* Under AttemptHoldsStoreLock an attempt in flight holds the store mutation
\* lock, which every entry into recovery and every promotion out of it take.
StoreLockFree ==
    AttemptHoldsStoreLock => \A u \in Unlockers : ~InFlight(u)

\* Every attempt in flight finds the lock generation moved.
GenerationMoves == [u \in Unlockers |-> ulStale[u] \/ InFlight(u)]

\* The ghost of the same: a lock landed during every attempt in flight.
LockLands == [u \in Unlockers |-> ulLocked[u] \/ InFlight(u)]

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
    /\ ulLocked' = LockLands
    /\ UNCHANGED <<pc, cancelled, waited, leaked, wipedHeld, lateExport>>

\* A Lock on a signer already locked or locking: the generation still moves,
\* and no cleanup runs. Every holder in flight is stale already.
LockInactive ==
    /\ life \in {"locking", "draining", "locked"}
    /\ ulStale' = GenerationMoves
    /\ ulLocked' = LockLands
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
\* moved, for KU5. self is the attempt whose recovery end enters, which
\* finishes with the step.
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
\* (productruntime's Reload, for the watcher and the in-place writes). Each
\* holds the store mutation lock, so under AttemptHoldsStoreLock none lands
\* inside an attempt. From recovery there is no session left to end: every
\* holder in flight started before the first entry. An attempt's own entry
\* is RecoveryFinish.
EnterRecovery ==
    /\ life \in {"unlocked", "recovery"}
    /\ locks < MaxLocks
    /\ StoreLockFree
    /\ EnterRecoveryFrom(life, "none")
    /\ UNCHANGED <<pc, waited, leaked, wipedHeld, lateExport>>

\* PromoteRecoveryToUnlocked: a reconcile succeeded. The reconcile holds the
\* store mutation lock from its reload to the promotion.
LeaveRecovery ==
    /\ life = "recovery"
    /\ StoreLockFree
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

\* An attempt waits for every cleanup in progress first (awaitCleanups), so it
\* never starts while one runs; it may start on a signer already unlocked or
\* in recovery. Without the wait it may also start between LockState and
\* Wipe.
CleanupsDone ==
    UnlockWaitsForCleanup =>
        (life \in {"locked", "unlocked", "recovery"} /\ late = "none")

\* An attempt in flight returns to idle with its flags cleared.
Finish(u) ==
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
    /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
    /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
    /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
    /\ ulSawPublish' = [ulSawPublish EXCEPT ![u] = FALSE]

\* Holders, the lock's cleanup and the counters an attempt step leaves.
HolderVars == <<locks, pc, cancelled, waited, leaked, wipedHeld, lateExport,
                wipedLive>>

\* The attempt takes the store mutation lock, waits for cleanups, and reads
\* the lock state.
AttemptStart(u) ==
    /\ ul[u] = "idle"
    /\ StoreLockFree
    /\ CleanupsDone
    /\ ul' = [ul EXCEPT ![u] = IF life = "unlocked" THEN "checking" ELSE "reconciling"]
    /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
    /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
    /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
    /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
    /\ ulSawPublish' = [ulSawPublish EXCEPT ![u] = FALSE]
    /\ UNCHANGED <<life, HolderVars, stale, ended, late, overRecovery,
                   answeredDisturbed, lockUndone, endedPublished>>

\* An attempt that found the signer unlocked checks the passphrase and
\* answers: from the session, or, when its reading moved during the check,
\* that the signer locked. Under AnswersFromSession it loads nothing; under
\* AnswerEndsAtCheck it ends here, and otherwise it goes on to the fence with
\* nothing loaded.
AnswerCheck(u) ==
    /\ ul[u] = "checking"
    /\ IF AnswersFromSession
       THEN IF AnswerEndsAtCheck
            THEN Finish(u)
            ELSE /\ ul' = [ul EXCEPT ![u] = "answered"]
                 /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
       ELSE /\ ul' = [ul EXCEPT ![u] = "loading"]
            /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
    /\ UNCHANGED <<life, HolderVars, stale, ended, late, overRecovery,
                   answeredDisturbed, lockUndone, endedPublished>>

\* The store root opened and the reading checked, the reconcile runs. An
\* attempt that lost to a lock stops with nothing to clear. A reconcile that
\* passes leads to the load, one that fails to the recovery end.
Reconcile(u) ==
    /\ ul[u] = "reconciling"
    /\ IF ulStale[u]
       THEN Finish(u)
       ELSE /\ \/ ul' = [ul EXCEPT ![u] = "loading"]
               \/ ul' = [ul EXCEPT ![u] = "recovering"]
            /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
    /\ UNCHANGED <<life, HolderVars, stale, ended, late, overRecovery,
                   answeredDisturbed, lockUndone, endedPublished>>

\* The reading checked again, the load runs and ends: it may find a content
\* defect, which leads to the recovery end.
Load(u) ==
    /\ ul[u] = "loading"
    /\ IF ulStale[u]
       THEN Finish(u)
       ELSE /\ \/ ul' = [ul EXCEPT ![u] = "loaded"]
               \/ ul' = [ul EXCEPT ![u] = "recovering"]
            /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
    /\ UNCHANGED <<life, HolderVars, stale, ended, late, overRecovery,
                   answeredDisturbed, lockUndone, endedPublished>>

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
         /\ ulLocked' = [v \in Unlockers |->
                           IF v = u THEN FALSE ELSE LockLands[v]]
         /\ UNCHANGED late
    ELSE /\ late = "none"
         /\ late' = "locking"
         /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
         /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
         /\ UNCHANGED <<life, stale, ended>>

\* The publish and its fence. With the reading unmoved the attempt publishes
\* a session; a cleanup it overtook carries on as `late`. Under
\* UnlockFencesRecovery an attempt that met an entry into recovery (the
\* session moved, the generation did not) publishes nothing and runs no
\* cleanup instead; without it, it publishes over that recovery. With the
\* generation moved the attempt lost to a lock (LoseToLock). One that
\* answered from the session and came here without AnswerEndsAtCheck loaded
\* nothing, and its loss disturbs whatever session there is by then.
Publish(u) ==
    /\ ul[u] \in {"loaded", "answered"}
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
    /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
    /\ ulSawPublish' = [v \in Unlockers |->
                          IF v = u THEN FALSE
                          ELSE ulSawPublish[v] \/ (InFlight(v) /\ ~ulStale[u]
                                                    /\ ~(UnlockFencesRecovery /\ ulRecov[u]))]
    /\ IF ~ulStale[u]
       THEN IF UnlockFencesRecovery /\ ulRecov[u]
            THEN /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
                 /\ UNCHANGED <<life, late, stale, ended, ulStale, overRecovery,
                                answeredDisturbed, lockUndone>>
            ELSE /\ life \in {"locking", "draining"} => late = "none"
                 /\ late' = IF life \in {"locking", "draining"} THEN life ELSE late
                 /\ life' = "unlocked"
                 /\ overRecovery' = (overRecovery \/ (ulSawRecov[u] /\ life = "recovery"))
                 /\ lockUndone' = (lockUndone \/ ulLocked[u])
                 /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
                 /\ UNCHANGED <<stale, ended, ulStale, answeredDisturbed>>
       ELSE /\ LoseToLock(u)
            /\ answeredDisturbed' = (answeredDisturbed \/ ul[u] = "answered")
            /\ UNCHANGED <<overRecovery, lockUndone>>
    /\ UNCHANGED <<locks, pc, cancelled, waited, leaked, wipedHeld, lateExport,
                   wipedLive, endedPublished>>

\* The recovery end's check and keyring open. Under ExitsShareReading it
\* checks the attempt's reading, and an attempt that lost to a lock stops
\* with nothing opened. Without it, the end reads the lock state anew, as
\* an entry into recovery that took its own reading did, and a lock that
\* came before is missed.
RecoveryOpen(u) ==
    /\ ul[u] = "recovering"
    /\ IF ExitsShareReading
       THEN IF ulStale[u]
            THEN Finish(u)
            ELSE /\ ul' = [ul EXCEPT ![u] = "opened"]
                 /\ UNCHANGED <<ulStale, ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
       ELSE /\ ul' = [ul EXCEPT ![u] = "opened"]
            /\ ulStale' = [ulStale EXCEPT ![u] = FALSE]
            /\ UNCHANGED <<ulRecov, ulSawRecov, ulLocked, ulSawPublish>>
    /\ UNCHANGED <<life, HolderVars, stale, ended, late, overRecovery,
                   answeredDisturbed, lockUndone, endedPublished>>

\* The recovery end's fence. With the generation unchanged it enters recovery
\* (enterRecoveryLocked, whatever the state, the locked one included); a
\* cleanup it overtook carries on as `late`. With the generation moved it
\* lost to a lock, as a publish does.
RecoveryFinish(u) ==
    /\ ul[u] = "opened"
    /\ ul' = [ul EXCEPT ![u] = "idle"]
    /\ ulSawPublish' = [ulSawPublish EXCEPT ![u] = FALSE]
    /\ IF ~ulStale[u]
       THEN /\ locks < MaxLocks
            /\ life \in {"locking", "draining"} => late = "none"
            /\ late' = IF life \in {"locking", "draining"} THEN life ELSE late
            /\ EnterRecoveryFrom(life, u)
            /\ lockUndone' = (lockUndone \/ ulLocked[u])
            /\ endedPublished' = (endedPublished \/ (life = "unlocked" /\ ulSawPublish[u]))
            /\ ulLocked' = [ulLocked EXCEPT ![u] = FALSE]
            /\ UNCHANGED ulStale
       ELSE /\ LoseToLock(u)
            /\ UNCHANGED locks
            /\ ulRecov' = [ulRecov EXCEPT ![u] = FALSE]
            /\ ulSawRecov' = [ulSawRecov EXCEPT ![u] = FALSE]
            /\ UNCHANGED <<cancelled, lockUndone, endedPublished>>
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
                      overRecovery, answeredDisturbed, attemptGhosts>>
    \* Recovery moves the session generation, which the unlock's second fence
    \* compares, not the lock generation its first one does.
    \/ /\ EnterRecovery
       /\ UNCHANGED <<late, wipedLive, ul, ulStale, overRecovery, answeredDisturbed,
                      attemptGhosts>>
    \/ /\ LockState \/ LockInactive
       /\ UNCHANGED <<late, wipedLive, ul, ulRecov, ulSawRecov, overRecovery,
                      answeredDisturbed, lockUndone, ulSawPublish, endedPublished>>
    \/ \E u \in Unlockers :
          \/ AttemptStart(u) \/ AnswerCheck(u) \/ Reconcile(u) \/ Load(u)
          \/ Publish(u) \/ RecoveryOpen(u) \/ RecoveryFinish(u)
    \/ /\ LateDrainBegin \/ LateWipe
       /\ UNCHANGED <<ul, ulStale, ulRecov, ulSawRecov, overRecovery, answeredDisturbed,
                      attemptGhosts>>

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
    /\ \A u \in Unlockers : ul[u] \in {"idle"} \cup UnlockSteps
    /\ \A u \in Unlockers : ulStale[u] \in BOOLEAN
    /\ \A u \in Unlockers : ulRecov[u] \in BOOLEAN /\ ulSawRecov[u] \in BOOLEAN
    /\ overRecovery \in BOOLEAN
    /\ answeredDisturbed \in BOOLEAN
    /\ \A u \in Unlockers : ulLocked[u] \in BOOLEAN /\ ulSawPublish[u] \in BOOLEAN
    /\ lockUndone \in BOOLEAN /\ endedPublished \in BOOLEAN

\* KU1: no signature (rotating or non-rotating) is returned after a lock or a
\* recovery began during its request.
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
\* builds and then installs, and the install would replace the keyring, the
\* key maps, the policy and the token index of a session in service that
\* concurrent changes had moved on from; a build that fails closes nothing.
KU6_NoLoadUnderSession ==
    \A u \in Unlockers : ul[u] = "loading" => life # "unlocked"

\* KU7: an unlock that answered from the session never locks the signer or
\* runs a cleanup: it loaded nothing for a cleanup to clear.
KU7_AnsweredUnlockLeavesSession == ~answeredDisturbed

\* KU8: a lock that lands during an attempt stands: the attempt neither
\* publishes unlocked nor enters recovery after it.
KU8_LockStands == ~lockUndone

\* KU9: an attempt's entry into recovery never ends a session another attempt
\* published while it ran.
KU9_RecoveryKeepsAnotherSession == ~endedPublished

Safety ==
    /\ TypeOK
    /\ KU1_NoSignatureAfterLock
    /\ KU2_NoKeyMaterialAtWipe
    /\ KU3_NoExportAfterWipe
    /\ KU4_NoWipeWhileUnlocked
    /\ KU5_NoUnlockOverLaterRecovery
    /\ KU6_NoLoadUnderSession
    /\ KU7_AnsweredUnlockLeavesSession
    /\ KU8_LockStands
    /\ KU9_RecoveryKeepsAnotherSession

=============================================================================
