# Recovery Binding Machine-Checkable Model

> Status: TLC checked over the full finite state space; the recorded positive
> run generated 45 distinct reachable states at depth 10 with no
> counterexamples. The expected-failure negative control
> (`recovery_binding_negative.cfg`, `BindBeforeValidate = FALSE` and
> `MaintenanceReadsRoot = FALSE`) violates `RB1_MaintenanceFollowsRoot` after
> 15 distinct states at depth 5 and must keep producing that exact
> counterexample.

This model picks up where [the store-root commit
model](FORMAL_TLA_STORE_ROOT_COMMIT_MODEL.md) leaves off. That model says how
a new generation becomes the authenticated root selection. This one asks
which generation the runtime then acts on, when the reload that follows a
root commit fails: the keystore's cached binding, the key cache the signer
serves from, and the generation that recovery maintenance (deleted-archive
list and prune) operates on.

The spec lives at [formal/recovery_binding.tla](formal/recovery_binding.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| RB1 | Recovery maintenance acts only on the generation the root selects, never the superseded, sealed one | `RB1_MaintenanceFollowsRoot` |
| RB2 | Once a mutation has released the store lock, no signing request or key write is served from a key cache behind the root | `RB2_NoStaleServiceAfterMutation` |
| RB3 | A key cache behind the root means the runtime is mid-mutation or in recovery | `RB3_StaleCacheImpliesRecoveryOrMutation` |
| RB4 | Outside a mutation, the keystore's binding is the root's generation | `RB4_BindingFollowsRoot` |

## What TLC actually verifies

The transitions transcribe the post-commit reload and the recovery paths:

- `CommitRoot` and `BeginReload` take the store mutation lock; the first
  also moves the root selection (the commit itself is
  `store_root_commit.tla`, collapsed to one step here). They stand for
  `ApplyPolicy` in `internal/signerapp/admin/policy.go`, the ASA set
  confirm/remove mint in `internal/signerapp/admin/asaset.go`
  (`mutateASASet`), the restore and rollback paths in
  `internal/signerapp/backupadmin`, and the recovery reconcile in
  `internal/signerapp/daemon/admin_services.go`. `BeginReload` also stands
  for the reloads with no commit that run on an unlocked signer: the
  watcher's (`productruntime.Runtime.reloadFromWatcher`) and an in-place
  write's (key generation and deletion in `internal/signerapp/keyadmin`,
  template administration in `internal/signerapp/templateadmin`), each under
  the store mutation lock. Restore and rollback write a
  restored cosigner key's source token file inside their mint, beside its
  credential and per-key policy, so the token file is one more member of the
  generation they commit and the reload that follows publishes it; the
  transition and its guard order are unchanged.
- The offline template repair (`internal/signerapp/templaterepair`, run by
  `apstore template repair`) is outside `Next`: it commits with no runtime.
  apstore's exclusive store lock refuses a running signer, so no binding or
  key cache exists to fall behind the root, and nothing can `Serve` or
  `Maintain` until a signer starts. That signer is locked until its first
  unlock, whose reload binds the authenticated root selection before anything
  can fail (`BindStoreRootSelection`, as `ReloadBind`), so it begins as `Init`
  does, with the repaired generation, or the old one after a repair that did
  not commit, as `root`.
- `ReloadBind` is the reload's first step in
  `internal/signerapp/templates/reload.go`: `BindStoreRootSelection`
  authenticates a fresh exact root read and binds what it selects before
  validation or scanning can fail (`internal/keystore/file.go`, over
  `genstore.AuthenticateStoreRootSelection`). A root that no longer
  authenticates clears the binding.
- `ReloadSucceed` rebuilds the key cache from the root's generation and lifts
  recovery. `ReloadFail` leaves the cache on the generation it last scanned
  and, with `RecoveryBeforeRelease`, enters recovery in the same step the
  lock is released (`commitAndReload` sets `Uncertain` and calls
  `SetRecovery` itself, inside `ApplyPolicy`'s `WithStoreMutation`, as
  `mutateASASet` does for the ASA set; restore does the same, and so does
  the recovery reconcile, whose locked work `reconcileLocked` enters recovery
  itself; it once did so only after `ReconcileStore` had released the lock).
  A reload with no commit that finds a content defect in the selected
  generation (a failed validation, or two key files that resolve to one
  address) enters recovery itself, in `productruntime.Runtime.Reload`,
  before its caller releases the lock; it once published an empty key
  snapshot and left the signer unlocked.
  Policy apply and the ASA set change commit only on an unlocked signer,
  and restore, rollback and the recovery reconcile run only on one unlocked
  or in recovery, each checked under the lock, as the watcher's reload and
  the in-place writes run only on one unlocked: a lock that landed while the
  request waited for the lock leaves the keyring open until its cleanup has
  run, and a commit there whose reload failed would call `SetRecovery` on a
  locked signer, which does nothing. A second unlock of an unlocked signer answers from
  the session and loads nothing (KU6 in
  [the key-use model](FORMAL_TLA_KEY_USE_LOCK_MODEL.md)), so it rebinds
  nothing. One that found the signer locked or in recovery holds the store
  mutation lock from its state read to its publish, as every entry into
  recovery does, so it never publishes over a recovery entered after it
  began, and its fence (`PublishUnlocked`) compares the session generation,
  which every entry into recovery moves, as well (KU5).
- `Serve` is a signing request or key write, gated by the runtime state
  (`IsUnlocked`; recovery is a distinct state that refuses both). A key write
  is an in-place write of the selected generation that mints nothing: key
  generation, key deletion, and a source token set or remove
  (`internal/signerapp/keyadmin/source_tokens.go`), each of which rechecks
  `IsUnlocked` under the store mutation lock (`lockUnlockedMutation`). None
  of them is a store-commit caller. `Maintain` is deleted-archive list or
  prune through `authenticatedSelection`, which reads and authenticates the
  root itself. Its `~lockHeld` guard is the store
  mutation lock both take: prune through `withStoreMutation`, list through
  `withStoreInspection`, whose `TryLock` answers `store_busy` instead of
  reading the archive while a mutation holds the lock.
- `RootDamaged` and `RootRepaired` stand for a `store-root.enc` that stops or
  resumes authenticating.

The three constants are the three guards the code has. Each is
load-bearing for a different invariant, confirmed by mutation:

| Mutation | Result |
|---|---|
| `BindBeforeValidate = FALSE` alone | RB4 fails: a failed reload leaves the binding on the old generation |
| `MaintenanceReadsRoot = FALSE` alone | all hold: with the binding fixed, the cached binding is the root |
| `RecoveryBeforeRelease = FALSE` alone | RB2 and RB3 fail: a request is served from the stale cache between lock release and recovery entry |
| both of the first two `FALSE` (negative control) | RB1 fails in five steps: commit, bind (no-op), reload fails, prune acts on the old generation |

The negative control is the code before commit `b0e51275` and reproduces
the bug that commit fixed. The harness (`scripts/run-formal-tests.py`)
requires exactly that `RB1_MaintenanceFollowsRoot` violation.

## Modeling choices and limits

- One commit, from `old` to `new`; later mutations are reloads. The root
  commit protocol, publication durability, and quarantine are
  `store_root_commit.tla` and are not repeated here.
- Signing is gated by the runtime state, not by the store mutation lock, so
  during a mutation a request may still be served from the key cache of the
  generation last scanned. That window is the accepted cost of a non-atomic
  runtime swap and is not flagged; RB2 is about the state after the lock is
  released, which is what recovery-before-release guarantees.
- Validation and scan failures are one nondeterministic outcome. Which
  generation content is invalid, and the exact error, are
  `internal/genstore` and `internal/keystore` concerns.
- `ReloadFail` always enters recovery. A reload with no commit (the
  watcher's, an in-place write's) enters it only for a content defect in the
  selected generation; any other failure, an unreadable `keys/` for
  one, leaves the signer unlocked on the view it had. No commit moved the
  root, so that view's key cache is the root's generation, and RB2 and RB3
  hold for both outcomes. The property the entry exists for, that a
  generation with a content defect is never served, is not checked: the
  model has no generation content. A recovery entered by a reload with no
  commit, for content found defective, is a model-extension candidate.
- `CommitRoot` stands for policy apply, the ASA set, restore, and rollback,
  and also for a commit whose outcome is uncertain: the candidate is visible
  but not confirmed durable, or the root cannot be read back or matches
  neither the old record nor the candidate (`genstore.RootCommitUncertain`). The caller
  cannot tell whether the root moved, so it takes the path of a commit that
  did, and its reload or recovery follows. Policy apply and the ASA set
  change are refused unless the runtime is unlocked
  (`admin/policy.go::commitAndReload`, `admin/asaset.go::mutateASASet`), so
  only restore and rollback commit from recovery. A refused mutation never
  takes `CommitRoot`, a run the model already has. The offline template
  repair, outside `Next`, repairs a store whose unlock entered recovery,
  and an uncertain repair is settled by the next unlock. A passphrase change
  withdraws signing up front (`BeginStoreMaintenance`) and a failure leaves
  the runtime locked rather than in recovery; locked refuses signing as
  recovery does, so RB2 and RB3 hold for it in substance. The same holds for
  a lock that lands during any mutation: `SetRecovery` does nothing on a
  locked signer, whose keys the lock cleared, and it stays locked.
- The offline `apstore` tools (`rebuild`, `policy sign`, `generations
  prune`, `source token discard`) run only with the daemon stopped, under the
  exclusive store lock, so there is no runtime key cache for them to leave
  behind the root; they are outside the model. `rebuild`'s first-generation
  commit is `store_root_commit.tla`'s.
- Recovery exit (`PromoteRecoveryToUnlocked`, the lock fence) is modeled as
  the successful reload lifting recovery; the race with a concurrent lock is
  a Go-level contract pinned by `internal/signerapp/runtime` tests.
- An unlock that begins in recovery is a second way out of it, not modeled
  here: it reconciles, reloads and publishes under one hold of the store
  mutation lock, so no commit lands inside it and it cannot publish over a
  recovery entered after it began (KU5). Which generation its own reload
  bound when it publishes is not checked by any model; it is a
  model-extension candidate.
  Its reload replaces recovery's keyring with one opened from the same store
  root. One that then fails keeps that keyring and the binding it made
  (`ReloadBind`), so recovery maintenance and the reconcile still run; it
  once closed the keyring, and with it the binding, leaving recovery unable
  to act until a later unlock.
- The normal configuration already exhausts the model's full finite state
  space, so no deep configuration exists for this module; this note is the
  record required by the roadmap working rules.

## How to check

```sh
make formal-test
```

For the focused runs:

```sh
java -jar tla2tools.jar -config docs/formal/recovery_binding.cfg \
  docs/formal/recovery_binding.tla
java -jar tla2tools.jar -config docs/formal/recovery_binding_negative.cfg \
  docs/formal/recovery_binding.tla
```

The negative run is expected to fail with an `RB1_MaintenanceFollowsRoot`
counterexample; the make harness asserts that expectation.

## Linking back

- Architecture: [ARCH_STORE.md](ARCH_STORE.md#generations) (reload binding
  and recovery maintenance) and [ARCH_STORE.md](ARCH_STORE.md#ownership-and-access).
- Traceability: the Recovery Binding section and the Recovery binding
  module section in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/keystore/scan_binding_test.go`,
  `internal/signerapp/daemon/archive_selection_test.go`, and
  `internal/signerapp/admin/policy_test.go`.
