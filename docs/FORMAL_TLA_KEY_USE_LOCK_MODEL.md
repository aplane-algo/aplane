# Key-Use Window Machine-Checkable Model

> Status: TLC checked over the bounded finite state space (one rotating sign
> and one mnemonic export, each repeating, at most two lock transitions); the
> recorded positive run generated 373 distinct states at depth 17 with no
> counterexamples, and the deep configuration (three lock transitions) 547
> distinct states at depth 21. Five expected-failure negative controls must
> keep producing their exact counterexamples:
> `key_use_lock_negative_recheck.cfg` (`FinalRecheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 70 distinct states at depth 7),
> `key_use_lock_negative_generation.cfg` (`GenerationCheck = FALSE`, violates
> `KU1_NoSignatureAfterLock`, 184 distinct states at depth 10),
> `key_use_lock_negative_drain.cfg` (`DrainWaits = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 51 distinct states at depth 6),
> `key_use_lock_negative_register.cfg` (`RegisterChecksLock = FALSE`, violates
> `KU2_NoKeyMaterialAtWipe`, 55 distinct states at depth 6) and
> `key_use_lock_negative_register_export.cfg` (`RegisterChecksLock = FALSE`,
> violates `KU3_NoExportAfterWipe`, 160 distinct states at depth 8).

Code that holds loaded key material outside an admin session registers a key
use with `Runtime.KeyUseContext`. A lock cancels every registered key use and
waits for each to release before it clears the session. Two holders release
something to a caller: a rotating sign returns a signature, and a mnemonic
export delivers a recovery phrase. This model asks what a lock guarantees
about both.

The spec lives at [formal/key_use_lock.tla](formal/key_use_lock.tla).

## What it covers

| Invariant | Meaning | TLA+ predicate |
|---|---|---|
| KU1 | A rotating signature is never returned once a lock began after its sign started and before its final check | `KU1_NoSignatureAfterLock` |
| KU2 | The session is never cleared while a key use is registered | `KU2_NoKeyMaterialAtWipe` |
| KU3 | An export never delivers a phrase after the session was cleared | `KU3_NoExportAfterWipe` |

KU1 is not "nothing leaves after a lock starts". Both holders check and then
release, and those two steps are not atomic in the code, so a lock landing
between them is indistinguishable from one landing just after. The export
delivers while it still holds the key, so a lock that begins during delivery
waits for it; KU2 and KU3 cover that case.

## What TLC actually verifies

- `SStart`, `SRegister`, `SMake`, `SRelease`, and `SReturn` transcribe
  `SignRotatingWithContext` in `internal/signerapp/signing/rotating_flow.go`:
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

The negative controls:

| Mutation | Result |
|---|---|
| `FinalRecheck = FALSE` | KU1 fails: the sign releases its seed, the signer locks during the audit write, and the signature is returned |
| `GenerationCheck = FALSE` | KU1 fails: the sign releases its seed, a lock drains and clears the session, the signer unlocks, and a recheck of only the current state lets the signature out |
| `DrainWaits = FALSE` | KU2 fails: the lock clears the session while the sign still holds its seed |
| `RegisterChecksLock = FALSE` | KU2 fails: a sign starts, the lock begins and starts draining, and the sign registers afterwards with a context nobody cancels; it holds its seed when the session is cleared |
| `RegisterChecksLock = FALSE` | KU3 fails: an export registers the same way, reads the credential, and delivers the phrase after the session was cleared |

The harness (`scripts/run-formal-tests.py`) requires exactly that violation
for each.

## Modeling choices and limits

- One rotating sign and one export, each repeating. The stage table worker is
  a third holder of the same mechanism; KU2 holds for any number of holders
  because the drain waits for each registered key use.
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
  session whether or not they released. A holder
  still running then (the stage table worker, an export) keeps its own
  decrypted copy, which no clear can reach, until it releases or the process
  exits, and lifecycle records `SERVER_STOP_INCOMPLETE`.
- `MaxLocks` bounds the number of lock transitions, so the claim is over
  executions with at most that many locks.

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

`make formal-test-deep` runs `key_use_lock_deep.cfg` (three lock transitions).
