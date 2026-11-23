# Key-Use Window Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one rotating sign
> and one mnemonic export, each repeating, two unlock attempts, at most two
> lock or recovery transitions); the recorded positive run generated 3537
> distinct states at depth 15 with no counterexamples, and the deep
> configuration (three transitions) 5682 distinct states at depth 16.
> Fifteen expected-failure negative controls must keep producing their exact
> counterexamples:
> `key_use_lock_negative_recheck.cfg` (`FinalRecheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 479 distinct states at depth 7),
> `key_use_lock_negative_generation.cfg` (`GenerationCheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 927 distinct states at depth 8),
> `key_use_lock_negative_recovery.cfg` (`RecoveryEndsSession = FALSE`,
> violates `KU1_NoSignatureAfterLock`, 914 distinct states at depth 8),
> `key_use_lock_negative_drain.cfg` (`DrainWaits = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 257 distinct states at depth 6),
> `key_use_lock_negative_register.cfg` (`RegisterChecksLock = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 363 distinct states at depth 6),
> `key_use_lock_negative_register_export.cfg` (`RegisterChecksLock = FALSE`,
> violates `KU3_NoExportAfterWipe`, 1953 distinct states at depth 8),
> `key_use_lock_negative_unlock.cfg` (`UnlockWaitsForCleanup = FALSE`,
> violates `KU4_NoWipeWhileUnlocked`, 2323 distinct states at depth 8),
> `key_use_lock_negative_loser.cfg` (`LoserLocks = FALSE` and
> `AttemptHoldsStoreLock = FALSE`, violates `KU4_NoWipeWhileUnlocked`, 73714
> distinct states at depth 15),
> `key_use_lock_negative_publish.cfg` (`UnlockFencesRecovery = FALSE` and
> `AttemptHoldsStoreLock = FALSE`, violates `KU5_NoUnlockOverLaterRecovery`,
> 2138 distinct states at depth 7),
> `key_use_lock_negative_reentry.cfg` (`RecoveryReentryMovesSession = FALSE`
> and `AttemptHoldsStoreLock = FALSE`, violates
> `KU5_NoUnlockOverLaterRecovery`, 2202 distinct states at depth 7),
> `key_use_lock_negative_answer.cfg` (`AnswersFromSession = FALSE`, violates
> `KU6_NoLoadUnderSession`, 26 distinct states at depth 3),
> `key_use_lock_negative_storelock.cfg` (`AttemptHoldsStoreLock = FALSE`,
> violates `KU6_NoLoadUnderSession`, 270 distinct states at depth 5),
> `key_use_lock_negative_answer_fence.cfg` (`AnswerEndsAtCheck = FALSE`,
> violates `KU7_AnsweredUnlockLeavesSession`, 231 distinct states at depth 5),
> `key_use_lock_negative_exits.cfg` (`ExitsShareReading = FALSE`, violates
> `KU8_LockStands`, 2215 distinct states at depth 9) and
> `key_use_lock_negative_serial.cfg` (`AttemptHoldsStoreLock = FALSE`,
> violates `KU9_RecoveryKeepsAnotherSession`, 16840 distinct states at depth
> 10).

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
| KU8 | A lock that lands during an unlock attempt stands: the attempt neither publishes unlocked nor enters recovery after it | `KU8_LockStands` |
| KU9 | An attempt's entry into recovery never ends a session another attempt published while it ran | `KU9_RecoveryKeepsAnotherSession` |

KU6 is what an unlock of an unlocked signer must not break. A load builds
the whole view with the keyring the attempt opened from the passphrase, the
one its reconcile used, and then installs it
(`productruntime/view.go::buildOpened`, `::publishUnlock`); the
install replaces the keyring, the policy, the key maps and the source token
index. A build that fails closes and installs nothing, so the reason KU6 once
had, a failed load that closed the keyring under a session in service and
left a signer that said unlocked and could not sign, is gone. What remains
is the install: under a session in service it would replace what concurrent
changes had moved on since the build read them. KU7 says that an attempt that found the
signer unlocked, and so loaded nothing, does not lock or clear either: it
has nothing to clear, and a loser's lock there could end a session another
path published after the attempt's check.

KU8 and KU9 are what the one-hold unlock closes. An unlock request once
took the store mutation lock twice, for its reconcile and for its load, and
entered recovery in a third step that read the lock generation afresh. A
lock that landed during the reconcile or the load was then undone by that
entry, which moved the locked signer into recovery (KU8), and a request
whose reconcile failed beside another's publish ended the session that
publish had just made (KU9).

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
  and the signer stays locked. Every entry into recovery outside an unlock
  publishes recovery's view (`productruntime.Runtime.enterRecoveryViewLocked`,
  the state first and then the view; for a store in doubt the state before
  the build, in `reloadViewLocked`), and every one of them and the
  reconcile that promotes hold the store mutation lock
  (`productruntime.Runtime.FollowCommit`, for policy apply, the ASA set,
  restore and rollback, and the restore's checkpoint failures;
  `productruntime.Runtime.Reconcile`; and `productruntime.Runtime.Reload`,
  which enters recovery by the same failure rule, for a content defect in
  the selected generation, a root that moved or no longer authenticates, or
  a role conflict, under the lock its callers hold: the watcher's
  `reloadFromWatcher`, and key and template administration), so
  neither action lands inside an unlock attempt, which holds that lock
  throughout. Recovery keeps the keyring and nothing drains; its view drops
  the key maps, the key cache and the source token index, which nothing
  reads in recovery. It ends the unlocked session: the session generation
  moves, and the entry cancels the key uses that session handed out
  (`cancelKeyUses`, in `afterReload`, once the passphrase lock is released),
  without waiting for them; an attempt's own entry begins locked or in
  recovery, with no session left to end. The session generation is a
  counter of its own, apart from the lock generation the unlock's first
  fence compares, so an unlock that overlaps an entry into recovery does not
  run the lock's cleanup. Its second fence compares the session, so it does
  not publish over that recovery either. A signer in recovery can be locked
  like an unlocked one. `KeyUseContext` refuses a new key use in recovery,
  since the signer is not unlocked.
- An unlock request is one attempt, which holds the store mutation lock from
  its start to its end (`productruntime.Runtime.Unlock`). `AttemptStart`
  takes the lock (`lockStoreMutation`), waits for cleanups and reads
  `lockGen`, the session and the state together
  (`runtime.Runtime.BeginAttempt`); under `AttemptHoldsStoreLock` no other
  attempt is in flight, and no entry into recovery (`EnterRecovery`) or
  promotion out of it (`LeaveRecovery`) lands until the attempt ends.
- `AnswerCheck` transcribes `answerFromSession`, for an attempt that found
  the signer unlocked: the passphrase check, then the comparison with the
  reading (`runtime.Runtime.Unchanged`). Either way the attempt ends there,
  answering from the session or, when a lock came during the check, that
  the signer locked; it loads, publishes and clears nothing.
- `Reconcile` transcribes `unlockHeld` for an attempt that found the signer
  locked or in recovery: the store root opened with the passphrase, the
  check of the reading (`LostToLock`), and the reconcile with the keyring
  that opening gave. An attempt that lost stops there with nothing to
  clear; a reconcile that fails leads to the recovery end. `Load` is the
  second check, the build from the passphrase, which changes nothing live,
  and its install; a content defect the build finds leads to the recovery
  end instead, and any other failure ends the attempt with nothing
  installed and the keyring it opened zeroed. An attempt begun in recovery
  whose build fails keeps recovery's keyring.
- `Publish` transcribes `runtime.Runtime.PublishUnlocked`, the fence. An
  attempt that finds `lockGen` moved has lost to a lock; it may have loaded
  keys after that lock's cleanup ran, so it clears them. It first locks as
  `Lock` does (`lockForCleanupLocked`: the state locks and `lockGen` and the
  session move, in the critical section that decides the cleanup). An
  attempt that finds `lockGen` where it was but the session moved met an
  entry into recovery and publishes nothing; under the hold none reaches
  it, so the comparison is a layered guard.
- `RecoveryOpen` and `RecoveryFinish` transcribe the attempt's second end:
  `unlockIntoRecovery`'s check of the reading and its install of recovery's
  view under `passphraseLock` (bound to what the build found the root
  selecting, the keyring the build opened for an attempt begun locked,
  recovery's own for one begun in recovery, read under the same hold, since
  a lock's cleanup clears it under that lock), then the fence of
  `runtime.Runtime.EnterRecovery`. One that lost before the open stops with
  nothing opened; one whose fence finds `lockGen` moved loses as a publish
  does; otherwise it enters recovery from whatever state the signer is in
  (`enterRecoveryLocked`), moving the session. Both ends compare the one
  reading the attempt took at its start (`ExitsShareReading`).
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
| `RecoveryEndsSession` | TRUE: `SetRecovery` and `EnterRecovery` advance the session generation when they leave the unlocked state, and the key uses handed out are cancelled | Without it a recovery and a reconcile between the release and the return go unnoticed: the signer reads unlocked with the generation the sign captured |
| `UnlockWaitsForCleanup` | TRUE: `BeginAttempt` waits (`awaitCleanups`) until every on-lock cleanup already decided has returned, and only then reads the lock generation; `FinishMaintenance` waits the same way before it compares the generation its token recorded | Without it an attempt that begins between a lock's state change and its session clear passes the fence, and the cleanup clears the session it published |
| `LoserLocks` | TRUE: an attempt that loses at a fence (`PublishUnlocked`, `EnterRecovery`) locks the runtime and moves `lockGen` and the session (`lockForCleanupLocked`) before its cleanup runs | Without it, and without the hold, the losing attempt's cleanup runs in whatever state the signer is in, and clears a session another attempt published. Under the hold no other attempt runs, so it is layered there |
| `UnlockFencesRecovery` | TRUE: `PublishUnlocked` compares the session with the reading and, when only the session moved, returns `ErrRecoveryDuringUnlock` without publishing or cleaning up | Without it, and without the hold, an unlock publishes unlocked over a recovery a store change entered after it began. Under the hold no entry into recovery lands inside an attempt, so it is layered there |
| `RecoveryReentryMovesSession` | TRUE: `enterRecoveryLocked` moves the session on every entry, one from recovery included | Without it, and without the hold, an unlock begun in recovery misses a restore, rollback or reconcile that entered recovery again, and publishes over it |
| `AnswersFromSession` | TRUE: an attempt that finds the signer unlocked answers from the session (`answerFromSession`) and loads nothing | Without it an unlock of an unlocked signer loads under the session in service |
| `AnswerEndsAtCheck` | TRUE: `answerFromSession` compares the reading itself and returns, so such an attempt never reaches a fence | Without it the attempt goes on to the fence with nothing loaded, and when a lock came in after its check it locks the signer and runs a cleanup as a loser does |
| `AttemptHoldsStoreLock` | TRUE: `Unlock` holds the store mutation lock from before `BeginAttempt` to after its fence (`lockStoreMutation`), the lock every `SetRecovery` caller, the reconcile's promotion and the passphrase change's republish hold | Without it a second attempt loads under the session a first published while it ran, and a first attempt's entry into recovery ends a session a second published |
| `ExitsShareReading` | TRUE: `EnterRecovery` checks and fences on the attempt's reading from `BeginAttempt`, as `PublishUnlocked` does | Without it the recovery end reads the lock state anew, as `TryRecovery` once did, and a lock that landed during the reconcile or the load passes its fence: the attempt moves the locked signer into recovery |

The negative controls:

| Mutation | Result |
|---|---|
| `FinalRecheck = FALSE` | KU1 fails: the sign releases its seed, the signer locks during the audit write, and the signature is returned |
| `GenerationCheck = FALSE` | KU1 fails: the sign releases its seed, a lock drains and clears the session, the signer unlocks, and a recheck of only the current state lets the signature out |
| `RecoveryEndsSession = FALSE` | KU1 fails: the sign releases its seed, the signer enters recovery and a reconcile unlocks it again during the audit write, and the recheck finds the state and the generation it started with |
| `DrainWaits = FALSE` | KU2 fails: the lock clears the session while the sign still holds its seed |
| `RegisterChecksLock = FALSE` | KU2 fails: a sign starts, the lock begins and starts draining, and the sign registers afterwards with a context nobody cancels; it holds its seed when the session is cleared |
| `RegisterChecksLock = FALSE` | KU3 fails: an export registers the same way, reads the credential, and delivers the phrase after the session was cleared |
| `UnlockWaitsForCleanup = FALSE` | KU4 fails: the signer locks, an attempt starts while the lock's cleanup drains, and the cleanup then clears the session of the signer the attempt left unlocked |
| `LoserLocks = FALSE`, without the hold | KU4 fails: an attempt that lost to a lock runs its cleanup without locking first, and clears the session another attempt published. With the hold on, no violation is found |
| `UnlockFencesRecovery = FALSE`, without the hold | KU5 fails: a store change enters recovery while an attempt runs, and the attempt publishes unlocked over it |
| `RecoveryReentryMovesSession = FALSE`, without the hold | KU5 fails: an attempt begins in recovery, a restore enters recovery again without moving the session, and the attempt publishes unlocked over it |
| `AnswersFromSession = FALSE` | KU6 fails in two steps: an unlock starts on the unlocked signer and loads |
| `AttemptHoldsStoreLock = FALSE` | KU9 fails: one attempt's reconcile or load fails while a second attempt publishes, and the first's entry into recovery ends that session (`key_use_lock_negative_serial.cfg`) |
| `AttemptHoldsStoreLock = FALSE` | KU6 fails: a second attempt loads under the session a first published while it ran (`key_use_lock_negative_storelock.cfg`) |
| `AnswerEndsAtCheck = FALSE` | KU7 fails in four steps: an unlock starts on the unlocked signer and answers from the session at its check, a lock comes in, and the attempt goes on to its fence, loses, and locks |
| `ExitsShareReading = FALSE` | KU8 fails: a lock lands during an attempt's reconcile or load, the recovery end reads the lock state anew and passes its fence, and the attempt moves the locked signer into recovery |

KU5's history is its own: `ulSawRecov` records every entry into recovery
while an attempt runs, whatever moved, and is not the flag the fence reads
(`ulRecov`, the session moving). So a mutation of either half of the guard,
the fence or the session move, is caught. KU6 reads the attempt's step and
the signer's state, not a guard's flag, and KU7 its own history,
`answeredDisturbed`, set when an attempt that answered from the session
takes a loser's lock. KU8 reads `ulLocked`, set when a lock lands during an
attempt and never reset by the attempt's own reading, so a recovery end
that reads anew is caught. Its publish half holds by construction: the
publish fence reads `ulStale`, which every lock sets and nothing resets
during an attempt, so only the recovery end has a negative control. An
attempt that found the signer unlocked ends at `AnswerCheck` either way;
that it answers locked after a lock during its check is Go-level
(`TestALockDuringThePassphraseCheckIsNotAnsweredFromTheSession`); KU9 reads `ulSawPublish`, set when another
attempt publishes while this one runs.

The hold makes three guards layered: `LoserLocks`, `UnlockFencesRecovery`
and `RecoveryReentryMovesSession` protect against another attempt or an
entry into recovery inside an attempt, which the hold already excludes.
Their negative controls switch the hold off too, to show what each still
guards without it.

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
- Two attempts, two unlock requests. Under `AttemptHoldsStoreLock` they
  never overlap; the second is there so that switching the hold off shows
  what it excludes (KU6, KU9). A third adds nothing a second does not: an
  attempt that loses moves `lockGen` for every other attempt in flight.
- An attempt's entry into recovery counts toward `MaxLocks`, as
  `EnterRecovery` does; one that cannot enter within the bound stays in
  flight, which only removes runs.
- An attempt that began in recovery and publishes is the recovery exit once
  its reconcile passed (KU5 is about recoveries entered later). A first
  unlock of a locked signer is not fenced by `SetRecovery`, which does
  nothing there. Store mutations refuse a signer that is not unlocked (or,
  for restore, rollback and the recovery reconcile, in recovery), checked
  under the store mutation lock; under the hold no attempt has an open
  keyring on a locked signer when one runs, and the refusal stays a
  Go-level contract pinned by the `admin`, `backupadmin` and `daemon` tests
  (`TestAReconcileOfALockedSignerIsRefusedUnderTheLock` for the reconcile).
- The hold also keeps a passphrase change's republish
  (`FinishStoreMaintenance`) out of an attempt: the change holds the store
  mutation lock from `BeginStoreMaintenance` to its finish, so an unlock
  that arrives during it waits and meets the new store root
  (`TestAnUnlockDuringAPassphraseChangeWaitsForIt`). Republication is not
  modeled (see above), so this is a Go-level contract;
  `TestAnUnlockLoadsUnderTheStoreMutationLock` pins that the load and the
  publish hold the lock. The startup unlock (`Signer.unlockAtStartup`) runs
  the same request (`productruntime.Runtime.Unlock`) before the admin
  listener starts.
- The wait for cleanups (`AttemptStart`) runs with the store mutation lock
  held, so nothing a lock's cleanup waits for may wait for that lock. The
  model does not hold that ordering; it is a Go-level contract
  (`TestALocksCleanupCompletesWhileTheStoreMutationLockIsHeld`,
  `TestAnUnlockWaitsForALocksCleanupUnderTheStoreMutationLock`).
- A load that fails after the keyring opened closes it itself, when it found
  none open; one that fails for another reason ends the attempt with no
  modeled state changed. KU6 is what keeps that close off a session in
  service. The request-level answer of a failed unlock is `Unlock`'s, which
  `UnlockIdentity` maps to a result code.

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
