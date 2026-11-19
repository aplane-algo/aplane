# Rotating Leaf Release Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one account that
> may be absent from the signer's inventory, three stages, two leaves per
> stage, three transaction IDs per stage, at most four memory records, a
> status pass whose chain read may lag, recovery round trips); the recorded
> positive run generated 14,592,306 distinct states at depth 31 with no
> counterexamples, and the deep configuration (five records) 100,666,564
> distinct states at depth 35. Six expected-failure negative controls
> each violate `LF1_NoReuseBeforeExhaustion` and must keep producing that exact
> counterexample: `rotating_leaf_release_negative_wait.cfg` (no restore check
> at all, 605 distinct states at depth 7),
> `rotating_leaf_release_negative_recheck.cfg` (`RecheckAtChoice = FALSE`, 468
> distinct states at depth 8), `rotating_leaf_release_negative_cut.cfg`
> (`CutRestoreHolds = FALSE`, 3,085 distinct states at depth 10),
> `rotating_leaf_release_negative_seq.cfg` (`SeqGuard = FALSE` and
> `NextStageGuard = FALSE`, no lagging node, 14,863 distinct states at depth
> 12), `rotating_leaf_release_negative_lag.cfg` (`NextStageGuard = FALSE`
> with a lagging node, 15,008 distinct states at depth 12) and
> `rotating_leaf_release_negative_recovery.cfg` (`RecoveryEndsSession =
> FALSE`, 12,942 distinct states at depth 12).

A rotating account of a leaf family (`rotatingkey.Profile.LeavesPerStage > 1`,
today the XMSS and WOTS+C triples) holds several one-time leaves per stage. Signing the
same leaf for two different transactions spends a one-time key twice. The
signer chooses the leaf from the stage's release history, kept in process
memory (`ReleaseMemory`) and rebuilt from the audit log at unlock. This model
asks whether that memory is a complete record whenever the signer can sign.

The spec lives at
[formal/rotating_leaf_release.tla](formal/rotating_leaf_release.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| LF1 | While no loss source has fired, a leaf is never reused for a different transaction while an unused leaf remains in the stage | `LF1_NoReuseBeforeExhaustion` |
| LF2 | While no loss source has fired, a retry of a released transaction signs on the leaf it already used | `LF2_RetryKeepsLeaf` |
| LF3 | Whenever the signer can sign for the account and nothing was lost, the memory lists every release the live stage has made | `LF3_MemoryCompleteWhenOpen` |
| (support) | The memory lists only releases that happened | `MemoryIsTruthful` |

LF3 is the reason LF1 and LF2 hold: `chooseLeaf` is correct given a complete
history, so the question is whether the history is complete.

## What TLC actually verifies

- `Admit(tx)`, `Sign` and `Refuse` transcribe `SignRotatingWithContext` in
  `internal/signerapp/signing/rotating_flow.go`. `Admit` is the wait for the
  restore (`AwaitRestored`, leaf families only), before the account lock. `Sign`
  is the leaf choice from `ForLeafChoice` under the lock (`chooseLeaf`: the
  transaction's own leaf, else the first unused leaf from the TxID's pick
  wrapping, else the pick again), the best-effort audit write, and
  `Releases.Record`. `Refuse` ends a sign that may no longer go on. Anything can
  happen between `Admit` and `Sign`. The ghost `truth` records every release
  whose signature left the signer.
- `SawLocked` and `DelayedReset` are the stage table worker seeing the lock and
  running `ReleaseMemory.Reset` as two separate steps, so the reset can land after
  a later unlock.
- `CutRestoreEnds` is a restore that a lock interrupted returning, possibly after
  the next unlock. `Lock` starts it, including while armed, because the worker
  binds a restore to its session before it reads the log. No new restore begins
  until it ends.
- `Land` is a release confirming: the authorizer moves to the next stage.
- `Lock`, `Unlock`, `RestoreBegin`, `RestoreApply`, and `RestoreFail`
  transcribe `ReleaseMemory.Reset`/`Restoring`/`RecordAudited`/`Restored` and
  `Service.RebuildReleaseMemory` in `rotating_release.go`. The merge keeps
  every leaf either side knows, ignores an audited release from an earlier
  stage than the memory's, and replaces an entry from an earlier stage.
- `Unlock` may load a generation that lacks the account (`absent`): a store
  change that ended in doubt, or a rollback. A restore skips an account the
  signer does not hold (`RebuildReleaseMemory`), and a request for it is
  refused, so `Admit` and the leaf choice need the account present.
- `Recover` is a recovery round trip in one step: `SetRecovery` from the
  unlocked state, a reconcile, and `PromoteRecoveryToUnlocked`
  (`internal/signerapp/runtime/runtime.go`). The account is in the inventory
  afterwards. With `RecoveryEndsSession` the session generation moved, so the
  memory restored for the earlier session is not used
  (`ReleaseMemory.ServeSession`, `ForLeafChoice`, `AwaitRestored`) and the
  worker resets it and restores again for the new session; the step folds
  that reset in, and cuts a restore in flight as a lock does.
- `Observe` and `ApplyObservation` transcribe the stage-table pass capturing
  `Seq` before its chain read (`rotating_tables.go`) and
  `Service.RotatingStatus` clearing an entry through `clearIfUnchanged` when
  the read shows the stage the entry hands the account to (the authorizer is
  the record's `NextAddr`). With `NodeMayLag` the read may show any stage the
  account has already left: a node that is behind, for example after an
  endpoint failover. The chain only moves forward, so it never shows a later
  stage than the true one.

The guards are constants:

| Constant | In the code | Role |
|---|---|---|
| `WaitForRestore` | TRUE: `AwaitRestored` before the account lock | Without it the first sign after an unlock picks from an empty memory |
| `RecheckAtChoice` | TRUE: `ForLeafChoice` under the account lock | Without it a delayed reset empties the memory after a sign was admitted |
| `CutRestoreHolds` | TRUE: the wait opens only after `rebuildReleaseMemory` sees a restore finish, bound to the generation read before its context and session | Without it a restore a lock cut short opens the wait with the history missing |
| `SeqGuard` | TRUE: `rec.Seq > r.ObservedSeq` skips the clear | Without it, and without `NextStageGuard`, a pass that read the chain before a release erases it |
| `NextStageGuard` | TRUE: `RotatingStatus` clears only when `r.Authorizer == rec.NextAddr` | Without it a read from a node that is behind, made after the release, shows an earlier stage and erases the live stage's history |
| `RecoveryEndsSession` | TRUE: an entry into recovery (`SetRecovery`, `TryRecovery`) advances the session generation, and the memory serves only the session named by `ServeSession` | Without it an account that was absent at the restore and came back through a recovery signs with its history missing and the wait open |

`NextStageGuard` covers what `SeqGuard` covers in this model: a read made
before a release shows the stage the account was at then, which is never the
one the later release hands the account to, so it clears nothing. With
`NextStageGuard = TRUE` and `SeqGuard = FALSE` the positive run still finds no
counterexample. The code keeps both. The sequence guard needs no address to be
right, and it also covers a sign whose own chain read was behind, which this
model does not have (see the limits).

Loss is separate. `AuditMayFail`, `AuditMayLose`, and `RestoreMayFail` model
the best-effort audit write (a failure is reported, not fatal), a log that
rotated past old entries, and a restore that fails for a reason other than a
lock and opens the wait. Each
sets the ghost `lossy`, and LF1 and LF2 are claimed only while it is FALSE.
This is the stated contract in the code ("state chooses the leaf, never
whether to sign"): the scheme is an interlock over the history the signer can
see, not a guarantee against a history it lost.

The negative controls (each with every loss source off):

| Mutation | Result |
|---|---|
| `WaitForRestore = FALSE`, `RecheckAtChoice = FALSE` | LF1 fails: with no restore check at all, a sign picks from an empty memory |
| `RecheckAtChoice = FALSE` | LF1 fails: the worker sees a lock, an unlock and restore follow, one transaction signs, a second is admitted, the delayed reset lands, and the second picks from the empty memory |
| `CutRestoreHolds = FALSE` | LF1 fails: a lock cuts a restore short, the signer unlocks, the restore returns and opens the wait, and a sign picks from the empty memory |
| `SeqGuard = FALSE`, `NextStageGuard = FALSE`, `NodeMayLag = FALSE` | LF1 fails: a status pass reads the chain, the release lands, the next stage signs, the stale pass clears that release, and the next transaction reuses its leaf |
| `NextStageGuard = FALSE` (with `NodeMayLag = TRUE`) | LF1 fails: a release lands, the next stage signs, a status pass then reads a node that is behind and sees the earlier stage, clears the live stage's release, and the next transaction reuses its leaf |
| `RecoveryEndsSession = FALSE` | LF1 fails: a stage signs, the signer locks and unlocks into a generation without the account, the restore skips it and opens the wait, a recovery brings the account back, and the next transaction signs with no history |

The harness (`scripts/run-formal-tests.py`) requires exactly that violation
for each.

## Modeling choices and limits

- One account and one signer. Several signers sharing a seed and no memory
  collide with probability one in `LeavesPerStage` by design, for TxIDs nobody
  chose (`chooseLeaf`), and are not modeled.
- Stateless-hash families (SLH-DSA) keep no leaf history, so the wait and the
  leaf choice do not apply to them (`leafProfile.StatelessHash`); they are not
  modeled.
- A stage holds two leaves and a transaction's pick is `tx % 2`; three
  transaction IDs per stage give pick collisions, which the negative controls
  need. The real stage holds 64 leaves; the rotation logic is the same for any
  count.
- A restore reads the log once, at `RestoreBegin`; the audited release names
  the highest stage in the log with every leaf the log holds for it. The
  reader keeps that promise (`readRotatingReleasesFrom`, which both
  `AuditLogger.ReadRotatingReleases` and the path-based reader use): an
  entry from an earlier stage, which a sign on a lagging chain read can log
  after a later stage's, never replaces the later stage's list, and the list
  holds every logged pair of leaf and transaction once, as the model's
  `<<leaf, tx>>` set does (`releaseAccumulator.add`). The memory merge
  (`mergeLeaves`) and a live record dedupe on the same pair, as
  `RestoreApply`'s and `Sign`'s unions do. `RestoreBegin` takes the
  log at one instant, and so does the signer's read
  (`AuditLogger.ReadRotatingReleases`): it opens the current file and both
  rotated ones under the logger's mutex, which every rotation holds, so a
  rotation cannot move a file between two opens and hide it. It reads them
  after the mutex is released and may see entries appended since, which are
  releases the memory records live anyway: a sign from the session before
  the restore, whose signature is withheld, or a stateless one. The model
  adds no audit entry while a restore is armed; the code may, and these are
  the entries it adds.
- `Lock` cuts a restore in flight short. It also stands for recovery, which stops a
  restore the same way without moving the generation: the model has no generation
  to tell them apart. The lock-generation fence on the sign path stops a release, not a leaf choice, and is
  modeled here only as `Sign` needing an unlocked signer; the fence itself, the
  key-use window and the recheck after the audit write are in
  [FORMAL_TLA_KEY_USE_LOCK_MODEL.md](FORMAL_TLA_KEY_USE_LOCK_MODEL.md). At most one sign is in flight,
  because the account lock serializes them.
- A lagging node is modeled for the status pass's read only. A sign always
  reads the true chain, so `ReleaseMemory.record`'s rule that a release from an
  earlier stage never replaces a later stage's history is not exercised; a Go
  test covers it (`TestEarlierStageReleaseKeepsALaterStagesHistory`).
- An account comes back only through a recovery. One that comes back by a
  plain reload in the same session (a key imported, or a restore that commits
  cleanly, after the session's restore skipped it) is not modeled, and the
  code has no hold for it. The operator's step is in `USER_STORE_MGMT.md`
  ("Restoring rotating accounts"): lock and unlock after such a restore.
- An observation is always a stage. An authorizer that is not a stage (an
  unknown address, a held key) clears nothing in the code, like an earlier or
  a further stage; a retained entry for a retired stage is harmless, because
  the leaf choice reads the memory only when it is about the live stage.
- Validity windows, expiry, the stage-table recovery grants, and the one-time
  warning text are not modeled; they change what the signer reports, not the
  leaf it picks.
- The reuse flag (`Reused`) is not modeled, and the model claims nothing
  once a loss has fired. A transaction listed on two leaves is such a case:
  LF2 rules it out while nothing is lost, and after a loss a retry can sign
  from a memory the loss emptied. A Go test runs it from the audit log
  through the restore to the reuse warning and the next leaf choice
  (`TestRestoreAfterLossesKeepsEveryLoggedLeaf`).
- The state space is bounded by `MaxSeq` (the memory's record counter), so
  the claim is over executions with at most that many record events, not an
  unbounded history.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/rotating_leaf_release.cfg \
  docs/formal/rotating_leaf_release.tla
java -jar tla2tools.jar -config docs/formal/rotating_leaf_release_negative_wait.cfg \
  docs/formal/rotating_leaf_release.tla
java -jar tla2tools.jar -config docs/formal/rotating_leaf_release_negative_seq.cfg \
  docs/formal/rotating_leaf_release.tla
java -jar tla2tools.jar -config docs/formal/rotating_leaf_release_negative_lag.cfg \
  docs/formal/rotating_leaf_release.tla
```

`make formal-test-deep` runs `rotating_leaf_release_deep.cfg` (five records).
