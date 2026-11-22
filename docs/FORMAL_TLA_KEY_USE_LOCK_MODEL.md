# Key-Use Window Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one rotating sign
> and one mnemonic export, each repeating, two attempts that may overlap,
> each an unlock or a recovery unlock, at most two lock or recovery
> transitions); the recorded positive run generated 25296 distinct states at
> depth 22 with no counterexamples, and the deep configuration (three
> transitions) 43105 distinct states at depth 22.
> Fourteen expected-failure negative controls must keep producing their exact
> counterexamples:
> `key_use_lock_negative_recheck.cfg` (`FinalRecheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 1314 distinct states at depth 7),
> `key_use_lock_negative_generation.cfg` (`GenerationCheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 2888 distinct states at depth 8),
> `key_use_lock_negative_recovery.cfg` (`RecoveryEndsSession = FALSE`,
> violates `KU1_NoSignatureAfterLock`, 2857 distinct states at depth 8),
> `key_use_lock_negative_drain.cfg` (`DrainWaits = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 588 distinct states at depth 6),
> `key_use_lock_negative_register.cfg` (`RegisterChecksLock = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 831 distinct states at depth 6),
> `key_use_lock_negative_register_export.cfg` (`RegisterChecksLock = FALSE`,
> violates `KU3_NoExportAfterWipe`, 6118 distinct states at depth 8),
> `key_use_lock_negative_unlock.cfg` (`UnlockWaitsForCleanup = FALSE`,
> violates `KU4_NoWipeWhileUnlocked`, 3874 distinct states at depth 7),
> `key_use_lock_negative_loser.cfg` (`LoserLocks = FALSE`, violates
> `KU4_NoWipeWhileUnlocked`, 18449 distinct states at depth 11),
> `key_use_lock_negative_publish.cfg` (`UnlockFencesRecovery = FALSE`,
> violates `KU5_NoUnlockOverLaterRecovery`, 1238 distinct states at depth 6),
> `key_use_lock_negative_reentry.cfg` (`RecoveryReentryMovesSession = FALSE`,
> violates `KU5_NoUnlockOverLaterRecovery`, 3032 distinct states at depth 7),
> `key_use_lock_negative_answer.cfg` (`AnswersFromSession = FALSE`, violates
> `KU6_NoLoadUnderSession`, 35 distinct states at depth 3),
> `key_use_lock_negative_serial.cfg` (`UnlocksOneAtATime = FALSE`, violates
> `KU6_NoLoadUnderSession`, 6247 distinct states at depth 8),
> `key_use_lock_negative_storelock.cfg` (`LoadHoldsStoreLock = FALSE`,
> violates `KU6_NoLoadUnderSession`, 423 distinct states at depth 5) and
> `key_use_lock_negative_answer_fence.cfg` (`AnswerEndsAtCheck = FALSE`,
> violates `KU7_AnsweredUnlockLeavesSession`, 498 distinct states at depth 5).

The holders of loaded key material that register a key use with
`Runtime.KeyUseContext` are the rotating key paths (prepare, sign and the stage
table worker), mnemonic export, and a cosigner's external check step
(`runExternalChecks`), which holds one while it reads its source tokens and
makes its lookups so that a lock ends them and waits for it to let go. That
step releases nothing to a caller: when its key use is canceled the request
is refused as locked.
Ordinary `/sign`, component signing (bounded-base and cosigner-role) and
assembly hold a decrypted key too but register none (see the limits below). For a rotating seed that is every load in
prepare and sign: the identity read (`rotatingAccount`) and each stage
derivation (`requestDeriver`) in both, and the sign's signing window after
approval; the stage table fill and the release restore use the same identity
read and deriver, and the fill's build of the next tree (`treeFrontier`) is a
key use of its own. Every one of them opens its window through
`RotatingDeps.keyUse`, which refuses to open one without `KeyUse`, so none of
them loads a seed unregistered. A lock cancels every registered key use and
waits for each to release before it clears the session. Two holders release
something to a caller: a rotating sign returns a signature, and a mnemonic
export delivers a recovery phrase. This model asks what a lock guarantees
about both, and what an unlock may do to the session in service.

The spec lives at [formal/key_use_lock.tla](formal/key_use_lock.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| KU1 | A rotating signature is never returned once a lock or a recovery began after its sign started and before its final check | `KU1_NoSignatureAfterLock` |
| KU2 | The session is never cleared while a key use is registered | `KU2_NoKeyMaterialAtWipe` |
| KU3 | An export never delivers a phrase after the session was cleared | `KU3_NoExportAfterWipe` |
| KU4 | The session is never cleared while the signer is unlocked | `KU4_NoWipeWhileUnlocked` |
| KU5 | An unlock never publishes unlocked over a recovery entered after it began | `KU5_NoUnlockOverLaterRecovery` |
| KU6 | An unlock never loads keys while the signer is unlocked: no load runs under a session in service | `KU6_NoLoadUnderSession` |
| KU7 | An unlock that answered from the session never locks the signer or runs a cleanup | `KU7_AnsweredUnlockLeavesSession` |

KU6 is what an unlock of an unlocked signer must not break. A load replaces
the keyring, and one that fails after the keyring opened closes it again
(`templates/reload.go::Reload`, `ClearKeys`); under a session in service
that left a signer that said unlocked and could not sign, and the load also
republished the policy, the key maps and the source token index over
changes made since it read them. KU7 says that an attempt that found the
signer unlocked, and so loaded nothing, does not lock or clear either: it
has nothing to clear, and a loser's lock there could end a session another
path published after the attempt's check.

KU1 is not "nothing leaves after a lock starts". Both holders check and then
release, and those two steps are not atomic in the code, so a lock landing
between them is indistinguishable from one landing just after. The export
delivers while it still holds the key, so a lock that begins during delivery
waits for it; KU2 and KU3 cover that case.

## What TLC actually verifies

- `SStart`, `SRegister`, `SMake`, `SRelease`, and `SReturn` transcribe
  the signing window of `SignRotatingWithContext` in
  `internal/signerapp/signing/rotating_flow.go`, after approval:
  the lock generation captured at the start, `deps.keyUse`, `releaseRefused`
  before the seed is used, `rs.close` and `endKeyUse` before the audit write,
  and `releaseRefused` on the request context before the response.
- `EStart`, `ERegister`, `ERead`, `EDeliver`, and `ERelease` transcribe
  `ExportKey` in `internal/signerapp/keyadmin/export.go`: the key use taken
  under the mutation lock, the context check before the read, the second check
  before delivery, and the release after it.
- `LockState` transcribes `Runtime.Lock` and `BeginMaintenance` in
  `internal/signerapp/runtime/runtime.go`: the state locks and the generation
  moves under `stateMu`. `DrainBegin` and `Wipe` transcribe `drainKeyUsers` and
  `performLockCleanup` in `internal/signerapp/productruntime/runtime.go`.
  `Wipe` also stands for zeroing the source token index there
  (`sourceTokens.Clear`), after the drain and with the session, so KU2 covers
  the tokens the external check step reads as it covers the session's keys.
- `EnterRecovery` transcribes `SetRecovery` from the unlocked state or from
  recovery, and `LeaveRecovery` `PromoteRecoveryToUnlocked`, in the same
  file. An entry from recovery is a restore, rollback or reconcile entering
  it again; it moves the session generation as the first entry did
  (`enterRecoveryLocked`), which every attempt in flight later finds.
  `SetRecovery` does nothing on a locked signer, as `EnterRecovery`'s guard
  requires: a store mutation that a lock overtook calls it after the lock,
  and the signer stays locked. Every `SetRecovery` caller and the reconcile
  that promotes hold the store mutation lock (`commitAndReload`,
  `mutateASASet`, restore, rollback, `reconcileLocked`), so neither action
  lands while an unlock loads under that lock. Recovery keeps the keyring:
  nothing drains and nothing is cleared. It ends the unlocked session: the
  session generation moves, and `productruntime`'s `SetRecovery` and
  `TryRecoveryUnlock` cancel the key uses that session handed out
  (`cancelKeyUses`), without waiting for them. The session generation is a
  counter of its own, apart from the lock generation the unlock's first
  fence compares, so an unlock that overlaps an entry into recovery does not
  run the lock's cleanup. Its second fence compares the session, so it does
  not publish over that recovery either. A signer in recovery can be locked
  like an unlocked one. `KeyUseContext` refuses a new key use in recovery,
  since the signer is not unlocked.
- `UnlockStart`, `UnlockCheck`, `UnlockLoaded` and `UnlockFinish` transcribe
  `productruntime.Runtime.TryUnlock` around `runtime.Runtime.TryUnlock`.
  `UnlockStart` is the wait for cleanups and the read of `lockGen` and the
  session before the unlock function; it also requires that no other unlock
  is in flight, since `TryUnlock` holds `unlockMu` across the attempt.
  `UnlockCheck` is the unlock function's start (`performUnlock`): it takes
  the store mutation lock (`lockStoreMutation`), which another unlock's load
  holds, with `passphraseLock`, and asks the session (`AnswerFromSession`).
  That reads the session generation, verifies the passphrase, and confirms
  the signer is still unlocked in that session; `UnlockCheck` is the
  confirmation, or the read when the signer was not unlocked. A session that
  a lock or an entry into recovery ended during the passphrase check does
  not answer, and the attempt loads, as one that found the signer not
  unlocked does: under `unlockMu` and the store mutation lock nothing
  returns the signer to unlocked between the confirmation and the end of
  the load. An attempt the session answers
  records the session's key count and returns `errAnsweredFromSession`,
  which ends the attempt before the fence (`runtime.Runtime.TryUnlock`
  returns on an unlock function's error without touching the state);
  `TryUnlock` answers from the record: a success with the session's key
  count, or the refusal of a wrong passphrase. Otherwise the attempt
  verifies the passphrase and loads (`ReloadWithPassphrase`), and
  `UnlockLoaded` is the end of the load, where the store mutation lock is
  released. `UnlockFinish` is the fence after the unlock function. An
  attempt that finds `lockGen` moved has lost to a lock; its unlock function
  may have loaded keys after that lock's cleanup ran, so it clears them. It
  first locks as `Lock` does (`lockForCleanupLocked`: the state locks and
  `lockGen` and the session move, in the critical section that decides the
  cleanup), because another attempt may have published a session those keys
  now serve, or may publish one before the clear runs; moving `lockGen`
  makes that attempt lose too. An attempt that finds `lockGen` where it was
  but the session moved met an entry into recovery: a store change on
  another connection ended in doubt after the attempt read its generations
  and before its check, or after its load and before its fence (the load
  holds the store mutation lock, so not during it). It publishes nothing
  and runs no cleanup, so the signer stays in recovery with the keyring
  recovery administration needs, and `UnlockIdentity` answers from the
  state it then finds, `recovery_blocked` while the recovery lasts.
- `RecoveryStart` and `RecoveryFinish` transcribe `TryRecovery`, which
  `UnlockIdentity` calls when the reconcile or the selected generation
  fails and a second ask finds no session to answer from, and which does
  not take `unlockMu`: the wait for cleanups and the read of `lockGen`, then
  the fence. One that finds `lockGen` moved loses as an unlock does;
  otherwise it enters recovery from whatever state the
  signer is in, the locked one included (`enterRecoveryLocked`), moving the
  session, so an unlock in flight beside it does not publish over it. Its
  keyring open (`KeyStore.Unlock`) is not a step of its own: it takes
  `passphraseLock`, and a failure there replaces nothing, so no invariant
  depends on where it falls.
- `LockState` from the locked state is `BeginMaintenance`, which runs a
  cleanup there too, and a maintenance that ends without republishing:
  `FinishMaintenance` then locks with `lockForCleanupLocked` and clears what
  the maintenance reloaded, since no later `Lock` of a locked signer would.
  Republication itself is not modeled. It is a Go-level contract:
  `FinishMaintenance` publishes unlocked only if the signer was unlocked when
  the maintenance began and `lockGen` has not moved since, so a lock that
  landed before the maintenance began, or a losing attempt during it, keeps
  the signer locked (`TestMaintenanceBegunLockedStaysLocked`,
  `TestInFlightUnlockLosesToRacingMaintenance`,
  `TestRefusedMaintenanceClearsWhatItReloaded`).
- `LockInactive` transcribes `Lock` on a signer already locked or locking:
  `lockGen` moves and no cleanup runs. This is how an attempt can lose with
  no cleanup left for the next attempt to wait for.
- `Register` transcribes `KeyUseContext`: it checks the state and joins the
  wait group under `keyUseMu`, so it lands wholly before or after `DrainBegin`,
  which takes the same mutex. A `LockState` can still land between a holder's
  start and its registration.

The guards are constants:

| Constant | In the code | Role |
|---|---|---|
| `RegisterChecksLock` | TRUE: `KeyUseContext` returns a cancelled context and a no-op release while locked | Without it a holder registering after the drain began gets a fresh context the drain neither cancels nor waits for |
| `DrainWaits` | TRUE: `drainKeyUsers` waits on `keyUsers` before the session is cleared | Without it the session is cleared under a holder |
| `FinalRecheck` | TRUE: `releaseRefused(requestCtx, ...)` after the audit write | Without it a lock during the audit write still lets the signature out |
| `GenerationCheck` | TRUE: `releaseRefused` compares `LockGeneration()` with the value captured at the start | Without it a lock and an unlock between the release and the return go unnoticed |
| `RecoveryEndsSession` | TRUE: `SetRecovery` and `TryRecovery` advance the session generation when they leave the unlocked state, and the key uses handed out are cancelled | Without it a recovery and a reconcile between the release and the return go unnoticed: the signer reads unlocked with the generation the sign captured |
| `UnlockWaitsForCleanup` | TRUE: `TryUnlock` and `TryRecovery` wait (`awaitCleanups`) until every on-lock cleanup already decided has returned, and only then read the lock generation; `FinishMaintenance` waits the same way before it compares the generation its token recorded | Without it an unlock that begins between a lock's state change and its session clear passes the unlock fence, and the cleanup clears the session it published |
| `LoserLocks` | TRUE: a losing `TryUnlock` or `TryRecovery` locks the runtime and moves `lockGen` and the session (`lockForCleanupLocked`) before its cleanup runs | Without it the losing attempt's cleanup runs in whatever state the signer is in, and clears a session another attempt published |
| `UnlockFencesRecovery` | TRUE: `TryUnlock` reads the session with `lockGen` and, when only the session moved, returns `RecoveryDuringUnlockMessage` without publishing or cleaning up | Without it an unlock publishes unlocked over a recovery a store change entered after the unlock began, lifting it without the reconcile it needs |
| `RecoveryReentryMovesSession` | TRUE: `enterRecoveryLocked` moves the session on every entry, one from recovery included | Without it an unlock begun in recovery misses a restore, rollback or reconcile that entered recovery again, and publishes over it |
| `AnswersFromSession` | TRUE: `performUnlock` asks the session before it loads (`AnswerFromSession`), and an attempt the session answers loads nothing; `UnlockIdentity` asks first too, in the same hold of the store mutation lock as its reconcile (`AnswerIfUnlocked`), so a request on an unlocked signer reconciles nothing either | Without it an unlock of an unlocked signer loads under the session in service |
| `AnswerEndsAtCheck` | TRUE: such an attempt returns `errAnsweredFromSession`, and `runtime.Runtime.TryUnlock` returns before its fence | Without it the attempt goes on to the fence with nothing loaded, and when a lock came in after its check it locks the signer and runs a cleanup as a loser does |
| `UnlocksOneAtATime` | TRUE: `productruntime.Runtime.TryUnlock` holds `unlockMu` from before its generation read to after its fence | Without it a second unlock checks while the first has loaded and not yet published, loads, and the first publishes under it |
| `LoadHoldsStoreLock` | TRUE: `performUnlock` holds the store mutation lock from its passphrase check to the end of its load (`lockStoreMutation`), the lock every `SetRecovery` caller, the reconcile's promotion and the passphrase change's republish hold | Without it a reconcile promotes the signer out of recovery while an unlock begun there loads |

The negative controls:

| Mutation | Result |
|---|---|
| `FinalRecheck = FALSE` | KU1 fails: the sign releases its seed, the signer locks during the audit write, and the signature is returned |
| `GenerationCheck = FALSE` | KU1 fails: the sign releases its seed, a lock drains and clears the session, the signer unlocks, and a recheck of only the current state lets the signature out |
| `RecoveryEndsSession = FALSE` | KU1 fails: the sign releases its seed, the signer enters recovery and a reconcile unlocks it again during the audit write, and the recheck finds the state and the generation it started with |
| `DrainWaits = FALSE` | KU2 fails: the lock clears the session while the sign still holds its seed |
| `RegisterChecksLock = FALSE` | KU2 fails: a sign starts, the lock begins and starts draining, and the sign registers afterwards with a context nobody cancels; it holds its seed when the session is cleared |
| `RegisterChecksLock = FALSE` | KU3 fails: an export registers the same way, reads the credential, and delivers the phrase after the session was cleared |
| `UnlockWaitsForCleanup = FALSE` | KU4 fails: the signer locks, a recovery unlock lands while the lock's cleanup drains and enters recovery, a reconcile lifts it, and the cleanup then clears the session of the unlocked signer |
| `LoserLocks = FALSE` | KU4 fails: a recovery unlock starts on the unlocked signer, a lock locks it and clears the session, a second recovery unlock starts with no cleanup to wait for, the first loses and starts its cleanup, the second enters recovery, a reconcile lifts it, and the cleanup clears that session |
| `UnlockFencesRecovery = FALSE` | KU5 fails in five steps: a second unlock starts on the unlocked signer, a store change enters recovery before its check, and the unlock, finding the signer not unlocked, loads and publishes unlocked over it |
| `RecoveryReentryMovesSession = FALSE` | KU5 fails in six steps: the signer enters recovery, an unlock starts in it, a restore enters recovery again without moving the session, and the unlock loads and publishes unlocked over it |
| `AnswersFromSession = FALSE` | KU6 fails in two steps: an unlock starts on the unlocked signer and loads |
| `UnlocksOneAtATime = FALSE` | KU6 fails: the signer enters recovery, an unlock starts and loads, a second starts and, finding the signer still in recovery, loads, and the first publishes under it |
| `LoadHoldsStoreLock = FALSE` | KU6 fails in four steps: the signer enters recovery, an unlock starts and loads, and a reconcile lifts the recovery during the load |
| `AnswerEndsAtCheck = FALSE` | KU7 fails in four steps: an unlock starts on the unlocked signer and answers from the session at its check, a lock comes in, and the attempt goes on to its fence, loses, and locks |

KU5's history is its own: `ulSawRecov` records every entry into recovery
while an attempt runs, whatever moved, and is not the flag the fence reads
(`ulRecov`, the session moving). So a mutation of either half of the guard,
the fence or the session move, is caught. KU6 reads the attempt's step and
the signer's state, not a guard's flag, and KU7 its own history,
`answeredDisturbed`, set when an attempt that answered from the session
takes a loser's lock.

The harness (`scripts/run-formal-tests.py`) requires exactly that violation
for each.

## Modeling choices and limits

- One rotating sign and one export, each repeating. The stage table worker is
  a third holder of the same mechanism; KU2 holds for any number of holders
  because the drain waits for each registered key use. Prepare's seed loads
  and the sign's two loads before approval are holders of the same kind: each
  registers, loads, zeroes the seed and releases, returns nothing to a caller
  while it holds the seed, and answers locked when its key use is refused or
  cut short (the deriver reports that as `errKeyUseRefused`, decided where the
  window was stopped). `Register`, a held step and `Release` describe them, so
  KU2 covers them without new actions.
- Ordinary `/sign`, component signing (bounded-base and cosigner-role) and
  assembly are not key uses, and the model does not cover them. Their check
  after the gates (`Service.beforeExecute` in
  `internal/signerapp/signing/service.go`; the production `BeforeExecute` hook
  adds nothing to it) is a moment, not a hold: a lock that begins after it
  clears the session while a key decrypted before it is still signing. The
  request returns that signature when it needs no later key load; a load after
  the session is cleared fails, and the request answers locked (an assembly's
  passthrough key lookup answers internal). An entry into recovery clears
  nothing, so such a request signs to completion. KU2 is about
  registered key uses only. Making those paths key uses would be an extension
  of this model.
- The source token index counts readers of its own: an index that a reload
  or a token change replaces is zeroed when its last reader releases
  (`internal/sourcetokens/index.go`). The model does not represent
  those readers. Its claim needs only that the step reads tokens inside its
  key use, so at `Wipe` the drain has ended every reader and the index is
  zeroed at once. A step whose key use the lock refused may still read the
  index before the cleanup clears it: its reader keeps that index intact
  until it releases, and its context is already cancelled, so the lookup
  sends nothing and the request is refused as locked. An unlock that the
  fence refuses for a later recovery (KU5) runs no cleanup and is not
  `Wipe`: it leaves the index its reload published, as recovery leaves the
  keyring, and the next lock's `Wipe` clears both.
- The model takes as given that every load of key material is registered; it
  cannot see a load that is not. For rotating seeds,
  `TestLockWaitsForEveryRotatingSeedLoad` parks each load of prepare and sign
  under the real `Runtime.Lock` and fails if one of them is not a key use.
- The sign's leaf choice, audit write and release memory belong to
  [FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md](FORMAL_TLA_ROTATING_LEAF_RELEASE_MODEL.md)
  and are not repeated here. The audit write is the gap between `SRelease` and
  `SReturn`, where any lock step may land.
- The sign's recheck before the seed is closed is folded into `SMake`'s check
  and the final one: it changes what is recorded, not what is returned.
- A refusal at the final check writes a `SIGN_FAILED` entry
  (`logWithheldSignature`) after the check. Nothing leaves on that path, so it
  too changes only what is recorded, and `SReturn` leaves it out.
- A check and the release it guards are one step (`SReturn`, `EDeliver`), for
  the reason above.
- `Wipe` is one step, but its `ClearKeys` waits, without a bound, for the
  `FileKeyStore.WithKeyring` callbacks still using the keyring (admin
  operations, not registered key uses), with `passphraseLock` held. The
  model does not represent those callbacks; the keyring is detached first,
  so the store reads as locked while it waits, and zeroed after they return.
- Shutdown (`Runtime.EndKeyUses`, then `Runtime.Destroy`) is not modeled; the
  process exits right after it. `startup/lifecycle.go` skips the teardown when
  a request handler may still run. Otherwise `EndKeyUses` first makes
  `KeyUseContext` refuse every new key use (its `destroyed` flag, set under
  `keyUseMu`, so a registration lands wholly before it and is drained, or
  after it and is refused, as with `RegisterChecksLock`), without locking the
  signer. It then drains the registered key users as a lock does
  (`drainKeyUsers`), but only until its deadline, and `Destroy` clears the
  session whether or not they released. `Destroy` sets the same flag and
  stops the key watcher itself (`refuseKeyUses`, idempotent, which
  `EndKeyUses` also runs), then cancels the registered key uses' context, so
  it is safe without `EndKeyUses`, but it never waits for a key user. A holder
  still running then (the stage table worker, an export) keeps its own
  decrypted copy, which no clear can reach, until it releases or the process
  exits, and lifecycle records `SERVER_STOP_INCOMPLETE`.
- Recovery is modeled as leaving and re-entering the unlocked state. What a
  reconcile does to the store in between (the keys and policy it reloads) is
  not: KU1 says only that a signature made before it is not returned after
  it. An export in flight has its key use cancelled and stops at its next
  check; recovery clears nothing, so KU3 has nothing to say about it.
- The sign reads its session before the plan, the policy verdict and the
  approval (`SStart` is that read). A session end, a lock or an entry into
  recovery alike, withdraws a pending approval (`endSignRequests`), but a
  reconcile can have the signer unlocked again before a withdrawn request
  returns, so the session read is what withholds a signature approved
  across a recovery.
- `MaxLocks` bounds the number of lock and recovery transitions together, so
  the claim is over executions with at most that many. The locks a losing
  attempt makes and `LockInactive` are not counted; they do not grow the
  state space.
- Two attempts, each chosen as an unlock or a recovery unlock when it
  starts. Two unlocks never overlap (`UnlocksOneAtATime`), but an unlock and
  a recovery unlock, or two recovery unlocks, may: `UnlockIdentity` calls
  `TryRecoveryUnlock` outside `unlockMu`. A third attempt adds nothing a
  second does not: an attempt that loses moves `lockGen` for every other
  attempt in flight.
- A recovery unlock's entry into recovery counts toward `MaxLocks`, as
  `EnterRecovery` does; one that cannot enter within the bound stays in
  flight, which only removes runs.
- A winning `TryUnlock` publishes over the state it finds, recovery included,
  only when no entry into recovery came after it began: an unlock that starts
  in recovery is the recovery exit once its reconcile passed (KU5 is about
  recoveries entered later). A first unlock of a locked signer is not fenced:
  `SetRecovery` does nothing there and the session does not move. Store
  mutations refuse a signer that is not unlocked (or, for restore, rollback
  and the recovery reconcile, in recovery), checked under the store mutation
  lock, so none commits or reloads under such an unlock; that is a Go-level
  contract pinned by the `admin`, `backupadmin` and `daemon` tests
  (`TestAReconcileOfALockedSignerIsRefusedUnderTheLock` for the reconcile).
- A `TryRecovery` from the locked state moves the session too
  (`enterRecoveryLocked`), so a `TryUnlock` in flight beside it does not
  publish over the recovery it enters: `RecoveryFinish` from the locked state
  is that branch, and `TestAnUnlockInFlightDoesNotPublishOverALaterRecovery`
  pins it in Go.
- An unlock request on an unlocked signer is answered before it becomes an
  attempt: `UnlockIdentity` first calls `AnswerIfUnlocked`, which, under one
  hold of the store mutation lock, answers from the session
  (`AnswerFromSession`) or, when the signer is not unlocked, runs the
  request's reconcile. The answer reads and changes nothing the model has,
  so it is not an action; `UnlockCheck`'s answer covers the request that
  found the signer locked or in recovery there and unlocked by the time
  `TryUnlock` checks (another request published, or a reconcile promoted, in
  the gap between the two holds, which is accepted). An unlock's publish
  does not take the store mutation lock, so another request can publish
  while this one reconciles. A request whose reconcile failed, or whose
  load failed validation, asks the session again before it enters recovery
  (`enterRecoveryUnlessUnlocked`), and answers from a session published
  meanwhile instead of ending it
  (`TestAFailedReconcileLeavesASessionPublishedBesideIt`). The second ask
  and `TryRecoveryUnlock` are separate steps, so a publish between them is
  still ended: `RecoveryStart` may start on an unlocked signer, which the
  model allows.
- `LoadHoldsStoreLock` also keeps a passphrase change's republish
  (`FinishStoreMaintenance`) from landing during a load: the change holds
  the store mutation lock from `BeginStoreMaintenance` to its finish.
  Republication is not modeled (see above), so this is a Go-level contract;
  `TestAnUnlockLoadsUnderTheStoreMutationLock` pins that the load holds the
  lock. The startup unlock (`Signer.unlockAtStartup`) reloads and publishes
  with `SetUnlocked` outside `TryUnlock`, before the admin listener starts,
  so no attempt runs beside it.
- An unlock function that fails returns before the fence and changes no
  modeled state; a load that fails after the keyring opened closes it
  itself. KU6 is what keeps that close off a session in service. The
  request-level answer of a failed unlock is `UnlockIdentity`'s.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/key_use_lock.cfg \
  docs/formal/key_use_lock.tla
java -jar tla2tools.jar -config docs/formal/key_use_lock_negative_register.cfg \
  docs/formal/key_use_lock.tla
```

`make formal-test-deep` runs `key_use_lock_deep.cfg` (three transitions).
