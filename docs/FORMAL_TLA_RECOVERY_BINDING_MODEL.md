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
  `ApplyPolicy` in `internal/signerapp/admin/policy.go`, the restore and
  rollback paths in `internal/signerapp/backupadmin`, and the recovery
  reconcile in `internal/signerapp/daemon/admin_services.go`.
- `ReloadBind` is the reload's first step in
  `internal/signerapp/templates/reload.go`: `BindStoreRootSelection`
  authenticates a fresh exact root read and binds what it selects before
  validation or scanning can fail (`internal/keystore/file.go`, over
  `genstore.AuthenticateStoreRootSelection`). A root that no longer
  authenticates clears the binding.
- `ReloadSucceed` rebuilds the key cache from the root's generation and lifts
  recovery. `ReloadFail` leaves the cache on the generation it last scanned
  and, with `RecoveryBeforeRelease`, enters recovery in the same step the
  lock is released (`commitAndReload` sets `Uncertain`, `ApplyPolicy` calls
  `SetRecovery` inside `WithStoreMutation`; restore does the same).
- `Serve` is a signing request or key write, gated by the runtime state
  (`IsUnlocked`; recovery is a distinct state that refuses both). `Maintain`
  is deleted-archive list or prune through `authenticatedSelection`, which
  reads and authenticates the root itself.
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
- Recovery exit (`PromoteRecoveryToUnlocked`, the lock fence) is modeled as
  the successful reload lifting recovery; the race with a concurrent lock is
  a Go-level contract pinned by `internal/signerapp/runtime` tests.
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

- Architecture: [ARCH_GENERATIONS.md](ARCH_GENERATIONS.md) (reload binding
  and recovery maintenance) and [ARCH_STORE_OWNERSHIP.md](ARCH_STORE_OWNERSHIP.md).
- Traceability: the Recovery Binding section and the Recovery binding
  module section in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- Concrete tests: `internal/keystore/scan_binding_test.go`,
  `internal/signerapp/daemon/archive_selection_test.go`, and
  `internal/signerapp/admin/policy_test.go`.
