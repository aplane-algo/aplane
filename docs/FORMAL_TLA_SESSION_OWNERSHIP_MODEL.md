# Admin Session Ownership Machine-Checkable Model

> Status: TLC checked with `Sessions = {a1, a2, a3}` and symmetry over the
> session set; the recorded run generated 90 distinct reachable states,
> reached depth 8, and found no counterexamples for `Safety`.

This is the eighth machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). Unlike the earlier
modules it has no separate prose companion: it is the machine-checked form of
the admin-session ownership design shipped in the "Preserve admin unlock
ownership" change (`daemon/ipc.go` `handleRegisteredClient`,
`adminserver.SessionManager`, and the displacement flow). It was written
immediately after that fix rather than spec-first; its pre-fix mutation
reproduces the audit finding that motivated the fix, which is what makes it a
regression guard rather than an after-the-fact illustration.

The spec lives at [formal/session_ownership.tla](formal/session_ownership.tla).

## The invariant at stake

Admin authentication unlocks the product runtime as a side effect of verifying the
passphrase (`adminserver/session.go` `AuthenticateOutcome`), *before* the
session becomes the active owner. Ownership is only established afterwards
(`BindPreAuthPending` for IPC, optional displacement offer,
`PromoteToActive`).
Any failure in that window — pending-slot contention, displacement rejection,
promotion failure, connection drop — must not strand the product runtime unlocked
with no session left whose exit re-locks it. That is exactly the hole the
second-review audit found in the pre-fix code: `lock_on_disconnect` cleanup
was gated on `authenticated && wasActiveClient`, so an unlock whose session
never became owner was nobody's responsibility.

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| SO1: at most one active owner session | `SessionManager` single `active` slot | `SO1_SingleActiveOwner` |
| SO2: no stranded unlock — an unlocked product runtime (with `lock_on_disconnect`) always has a live authenticated session | `daemon/ipc.go` disconnect defer | `SO2_UnlockedHasOwner` |
| state/authentication consistency | (TypeOK) | `TypeOK` |

**SO2 is the point of the module.** It holds because of two code mechanisms,
both modeled exactly:

1. **The cleanup condition.** The disconnect defer runs owner cleanup (fail
   pending approvals, lock under `lock_on_disconnect`) iff
   `authenticated && (wasActiveClient || !HasClient())`. The second
   disjunct is the load-bearing half: a session that unlocked but never became
   owner still re-locks on its way out, unless another session already owns
   the identity.
2. **The displacement ordering.** `PromoteToActive` is an atomic swap under
   the `SessionManager` mutex — the replacement holds the owner slot in the
   same step the old owner is removed, and only then is the old session
   notified and closed (`DisplaceSession`). There is no window where a
   confirmed displacement has removed the owner before the replacement owns
   the slot.

## Mutation validation

- **Pre-fix cleanup condition** (drop the `~othersActive` disjunct in `Exit`,
  restoring `authenticated && wasActiveClient`): TLC violates SO2 in three
  states — `AuthSucceed` (identity unlocked), `Exit` while merely `Authed`
  (no cleanup), leaving the identity unlocked with every session gone. This
  is the audit scenario, machine-reproduced.
- **Pre-fix displacement ordering with the fixed condition** (change
  `PromoteReplace` to clear the owner without installing the replacement, as
  the pre-fix `OfferDisplacement` did at confirm time): `Safety` still holds
  — the fixed cleanup condition covers the gap — but the displaced session's
  exit then runs owner cleanup while the replacement is still `Authed`,
  locking the identity out from under the incoming client. That over-lock is
  why the fix changed both the condition and the ordering; the model makes
  the asymmetry visible (the condition is correctness, the ordering is
  behavior).

The restored spec passes.

## Modeling choices

- **One product runtime.** The implementation now has one process-wide owner
  slot, matching the model directly.
- **Unlock is only the auth side effect.** The operator's explicit
  unlock/lock IPC commands, passphrase retries, and keystore state machine are
  outside this model. Here `unlocked` exists solely to express SO2.
- **One uniform `Exit` action.** Failed auth, pending-slot loss, displacement
  rejection, promotion failure, displaced close, and plain disconnect all
  leave through the same code path (the `handleRegisteredClient` defer), so
  the model has a single `Exit` action evaluating the defer's condition at
  exit time. Auth failure is `Exit` from `PreAuth` with
  `authenticated = FALSE`.
- **Displacement confirmation has no state effect.** Post-fix, confirmation
  only authorizes the atomic swap, so it is not a separate action;
  `PromoteReplace` is the swap.
- **`lock_on_disconnect` chosen at Init, never changed.** SO2 is vacuous when
  it is FALSE (the operator opted out of re-locking); TLC explores both.
- **`AuthSucceed` models `auth`, not `auth_only`.** The current admin protocol
  v5 retains `auth_only` (`adminserver/session.go` `AuthenticateOutcome`,
  `transport/protocol_flow.go` `authenticateOnly`), which verifies the
  passphrase and binds the runtime without authorizing or invoking
  `identity.unlock`. It is a non-owning, authenticated read-only observer:
  it does not enter or replace the active-owner slot and does not run owner
  disconnect cleanup. It therefore changes none of this model's variables;
  its lifecycle and request allowlist are pinned by Go tests and documented in
  [FORMAL_TEST_GAPS.md](FORMAL_TEST_GAPS.md).

## How to check

```sh
java -jar tla2tools.jar -config docs/formal/session_ownership.cfg \
    docs/formal/session_ownership.tla
```

Expected: `Model checking completed. No error has been found.`, 90 distinct
states, depth 8, sub-second runtime. `make formal-test` includes the module.

## What this proves vs. doesn't

It proves that over every interleaving of up to three admin sessions —
concurrent authentications, displacement chains, exits at any point — the
modeled daemon never ends up with an unlocked product runtime, `lock_on_disconnect`
set, and no live authenticated session responsible for re-locking. It does
not model the keystore itself (a "locked" identity here is the daemon having
called `Lock()`; the keystore's own session/term-key destruction is
lifecycle territory), and the mapping from this abstract state machine to the
Go daemon is a code-review responsibility, anchored by the Go tests in the
traceability SO rows (`TestAdminAuthPromotionFailureCleansUnlockedIdentity`,
`TestDisplacementReplacementAuthFailureKeepsOldOwner`,
`TestOfferDisplacementKeepsExistingClientUntilReplacementPromoted`,
`TestAdminDisconnectAppliesLockOnDisconnect`).

## Linking back

- The fix this models: "Preserve admin unlock ownership" (`daemon/ipc.go`,
  `adminserver/displacement.go`, `adminserver/manager.go`).
- The approval-prompt half of displacement (failing the delivered prompt so
  it cannot orphan the delivery turn) is AP7 in
  [formal/approval_coordinator.tla](formal/approval_coordinator.tla) /
  [FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md](FORMAL_TLA_APPROVAL_COORDINATOR_MODEL.md);
  this module covers the lock-state half.
- Traceability rows: SO1, SO2 in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).

## Extension plan

- **Liveness** (an authenticated session eventually owns or exits; an
  unlocked product runtime with no live session is eventually locked) would need
  fairness choices for operator behavior that the safety story does not; add
  only if a real progress question arises.
- **Provisional-unlock redesign.** If unlock is ever moved after promotion
  (verify-then-commit), this module is where the new ordering gets checked
  before the code changes.
