# Key-Use Window Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one rotating sign
> and one mnemonic export, each repeating, two unlock attempts that may
> overlap, at most two lock or recovery transitions); the recorded positive
> run generated 3616 distinct states at depth 18 with no counterexamples, and
> the deep configuration (three transitions) 5588 distinct states at depth 19.
> Eight expected-failure negative controls must keep producing their exact
> counterexamples:
> `key_use_lock_negative_recheck.cfg` (`FinalRecheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 392 distinct states at depth 7),
> `key_use_lock_negative_generation.cfg` (`GenerationCheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 715 distinct states at depth 8),
> `key_use_lock_negative_recovery.cfg` (`RecoveryEndsSession = FALSE`,
> violates `KU1_NoSignatureAfterLock`, 701 distinct states at depth 8),
> `key_use_lock_negative_drain.cfg` (`DrainWaits = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 226 distinct states at depth 6),
> `key_use_lock_negative_register.cfg` (`RegisterChecksLock = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 302 distinct states at depth 6),
> `key_use_lock_negative_register_export.cfg` (`RegisterChecksLock = FALSE`,
> violates `KU3_NoExportAfterWipe`, 1379 distinct states at depth 8),
> `key_use_lock_negative_unlock.cfg` (`UnlockWaitsForCleanup = FALSE`,
> violates `KU4_NoWipeWhileUnlocked`, 544 distinct states at depth 6) and
> `key_use_lock_negative_loser.cfg` (`LoserLocks = FALSE`, violates
> `KU4_NoWipeWhileUnlocked`, 2700 distinct states at depth 10).

Code that holds loaded key material outside an admin session registers a key
use with `Runtime.KeyUseContext`. For a rotating seed that is every load in
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
about both.

The spec lives at [formal/key_use_lock.tla](formal/key_use_lock.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| KU1 | A rotating signature is never returned once a lock or a recovery began after its sign started and before its final check | `KU1_NoSignatureAfterLock` |
| KU2 | The session is never cleared while a key use is registered | `KU2_NoKeyMaterialAtWipe` |
| KU3 | An export never delivers a phrase after the session was cleared | `KU3_NoExportAfterWipe` |
| KU4 | The session is never cleared while the signer is unlocked | `KU4_NoWipeWhileUnlocked` |

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
- `EnterRecovery` and `LeaveRecovery` transcribe `SetRecovery` and
  `TryRecovery` from the unlocked state, and `PromoteRecoveryToUnlocked`, in
  the same file. Recovery keeps the keyring: nothing drains and nothing is
  cleared. It ends the unlocked session: the session generation moves, and
  `productruntime`'s `SetRecovery` and `TryRecoveryUnlock` cancel the key
  uses that session handed out (`cancelKeyUses`), without waiting for them.
  The session generation is a counter of its own, apart from the one the
  unlock fence compares, so an unlock that overlaps an entry into recovery
  does not run the lock's cleanup. A signer in recovery can be locked like an unlocked
  one. `KeyUseContext` refuses a new key use in recovery, since the signer is
  not unlocked.
- `UnlockStart` and `UnlockFinish` transcribe `TryUnlock` and `TryRecovery`
  in `internal/signerapp/runtime/runtime.go`: the wait for cleanups and the
  read of `lockGen` before the unlock function, and the fence after it. An
  attempt that finds `lockGen` moved has lost to a lock; its unlock function
  may have loaded keys after that lock's cleanup ran, so it clears them. It
  first locks as `Lock` does (`lockForCleanupLocked`: the state locks and
  `lockGen` and the session move, in the critical section that decides the
  cleanup), because another attempt may have published a session those keys
  now serve, or may publish one before the clear runs; moving `lockGen` makes
  that attempt lose too.
  Both attempts are modeled as `TryUnlock`; a `TryRecovery` that wins enters
  recovery instead, which clears nothing.
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
| `UnlockWaitsForCleanup` | TRUE: `TryUnlock`, `TryRecovery` and `FinishMaintenance` wait (`awaitCleanups`) until every on-lock cleanup already decided has returned, and only then read the lock generation | Without it an unlock that begins between a lock's state change and its session clear passes the unlock fence, and the cleanup clears the session it published |
| `LoserLocks` | TRUE: a losing `TryUnlock` or `TryRecovery` locks the runtime and moves `lockGen` and the session (`lockForCleanupLocked`) before its cleanup runs | Without it the losing attempt's cleanup runs in whatever state the signer is in, and clears a session another attempt published |

The negative controls:

| Mutation | Result |
|---|---|
| `FinalRecheck = FALSE` | KU1 fails: the sign releases its seed, the signer locks during the audit write, and the signature is returned |
| `GenerationCheck = FALSE` | KU1 fails: the sign releases its seed, a lock drains and clears the session, the signer unlocks, and a recheck of only the current state lets the signature out |
| `RecoveryEndsSession = FALSE` | KU1 fails: the sign releases its seed, the signer enters recovery and a reconcile unlocks it again during the audit write, and the recheck finds the state and the generation it started with |
| `DrainWaits = FALSE` | KU2 fails: the lock clears the session while the sign still holds its seed |
| `RegisterChecksLock = FALSE` | KU2 fails: a sign starts, the lock begins and starts draining, and the sign registers afterwards with a context nobody cancels; it holds its seed when the session is cleared |
| `RegisterChecksLock = FALSE` | KU3 fails: an export registers the same way, reads the credential, and delivers the phrase after the session was cleared |
| `UnlockWaitsForCleanup = FALSE` | KU4 fails: the signer locks, an unlock lands before the lock's cleanup has cleared the session, and the cleanup then clears the session of the unlocked signer |
| `LoserLocks = FALSE` | KU4 fails: an unlock starts on the locked signer, a lock on the locked signer moves `lockGen`, a second unlock starts with no cleanup to wait for, the first loses and starts its cleanup, the second publishes, and the cleanup clears its session |

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
  approval (`SStart` is that read). A lock fails a pending approval itself;
  recovery does not, and the session read is what withholds a signature
  approved across a recovery.
- `MaxLocks` bounds the number of lock and recovery transitions together, so
  the claim is over executions with at most that many. The locks a losing
  attempt makes and `LockInactive` are not counted; they do not grow the
  state space.
- Two unlock attempts. A third adds nothing a second does not: an attempt
  that loses moves `lockGen` for every other attempt in flight.
- A winning `TryUnlock` publishes over whatever state it finds, recovery
  included, since entering recovery moves the session and not `lockGen`. No
  property here depends on it: a holder from before the recovery is stale
  by the session generation.

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
