# Rotating Leaf Release Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one account, three
> stages, two leaves per stage, three transaction IDs per stage, at most four
> memory records); the recorded positive run generated 1,408,640 distinct
> states at depth 28 with no counterexamples, and the deep configuration
> (five records) 8,553,448 distinct states at depth 30. Two expected-failure
> negative controls each violate `LF1_NoReuseBeforeExhaustion` and must keep
> producing that exact counterexample: `rotating_leaf_release_negative_wait.cfg`
> (`WaitForRestore = FALSE`, 259 distinct states at depth 6) and
> `rotating_leaf_release_negative_seq.cfg` (`SeqGuard = FALSE`, 1,918 distinct
> states at depth 9).

A rotating account of a leaf family (`rotatingkey.Profile.LeavesPerStage > 1`,
today the XMSS triple) holds several one-time leaves per stage. Signing the
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
| LF3 | Whenever the signer can sign and nothing was lost, the memory lists every release the live stage has made | `LF3_MemoryCompleteWhenOpen` |
| (support) | The memory lists only releases that happened | `MemoryIsTruthful` |

LF3 is the reason LF1 and LF2 hold: `chooseLeaf` is correct given a complete
history, so the question is whether the history is complete.

## What TLC actually verifies

- `Sign(tx)` transcribes `SignRotatingWithContext` in
  `internal/signerapp/signing/rotating_flow.go`: the wait for the restore
  (`AwaitRestored`, leaf families only), the leaf choice from `Releases.Get`
  (`chooseLeaf`: the transaction's own leaf, else the first unused leaf from
  the TxID's pick wrapping, else the pick again), the best-effort audit write,
  and `Releases.Record`. The ghost `truth` records every release whose
  signature left the signer.
- `Land` is a release confirming: the authorizer moves to the next stage.
- `Lock`, `Unlock`, `RestoreBegin`, `RestoreApply`, and `RestoreFail`
  transcribe `ReleaseMemory.Reset`/`Restoring`/`RecordAudited`/`Restored` and
  `Service.RebuildReleaseMemory` in `rotating_release.go`. The merge keeps
  every leaf either side knows, ignores an audited release from an earlier
  stage than the memory's, and replaces an entry from an earlier stage.
- `Observe` and `ApplyObservation` transcribe the stage-table pass capturing
  `Seq` before its chain read (`rotating_tables.go`) and
  `Service.RotatingStatus` clearing an entry whose stage the chain no longer
  shows through `clearIfUnchanged`.

The guards are constants:

| Constant | In the code | Role |
|---|---|---|
| `WaitForRestore` | TRUE: `AwaitRestored` before the account lock | Without it the first sign after an unlock picks from an empty memory |
| `SeqGuard` | TRUE: `rec.Seq > r.ObservedSeq` skips the clear | Without it a stale observation erases a newer release |

Loss is separate. `AuditMayFail`, `AuditMayLose`, and `RestoreMayFail` model
the best-effort audit write (a failure is reported, not fatal), a log that
rotated past old entries, and a restore that fails and opens the wait. Each
sets the ghost `lossy`, and LF1 and LF2 are claimed only while it is FALSE.
This is the stated contract in the code ("state chooses the leaf, never
whether to sign"): the scheme is an interlock over the history the signer can
see, not a guarantee against a history it lost.

The negative controls (each with every loss source off):

| Mutation | Result |
|---|---|
| `WaitForRestore = FALSE` | LF1 fails in six steps: sign, lock, unlock, then a second transaction with the same pick signs before the restore and takes the same leaf |
| `SeqGuard = FALSE` | LF1 fails in nine steps: a status pass reads the chain, the release lands, the next stage signs, the stale pass clears that release, and the next transaction reuses its leaf |

The harness (`scripts/run-formal-tests.py`) requires exactly that violation
for both.

## Modeling choices and limits

- One account and one signer. Several signers sharing a seed and no memory
  collide with probability one in `LeavesPerStage` by design (`chooseLeaf`)
  and are not modeled.
- Stateless-hash families (SLH-DSA) keep no leaf history, so the wait and the
  leaf choice do not apply to them (`leafProfile.StatelessHash`); they are not
  modeled.
- A stage holds two leaves and a transaction's pick is `tx % 2`; three
  transaction IDs per stage give pick collisions, which the negative controls
  need. The real stage holds 64 leaves; the rotation logic is the same for any
  count.
- A restore reads the log once, at `RestoreBegin`; the audited release names
  the highest stage in the log with every leaf the log holds for it.
- `Lock` abandons a restore in flight. The lock-generation fence on the sign
  path is the stateless family's check and is not modeled.
- Validity windows, expiry, the stage-table recovery grants, and the one-time
  warning text are not modeled; they change what the signer reports, not the
  leaf it picks.
- The seam between `AwaitRestored` (before the account lock) and the leaf
  choice (under it) is modeled as one step because a restore only adds to the
  memory and the state it waits on is monotone; the interleaving with
  `Record` is covered by the merge.
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
```

`make formal-test-deep` runs `rotating_leaf_release_deep.cfg` (five records).
