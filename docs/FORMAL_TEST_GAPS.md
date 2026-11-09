# Formalization Test Gaps

> Status: working backlog. Each entry corresponds to a row in
> [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) where the invariant's
> status is `implemented*`, `intended`, or `deferred`. The point of this
> doc is to make the missing test concrete enough that someone can pick
> any one entry and add the test without rereading the whole model.

For each entry:

- **Invariant.** Which formal-model invariant is at stake.
- **What to assert.** The minimal property a test must verify.
- **Where it should live.** Suggested file (existing if possible).
- **Setup needed.** What runtime/fixture wiring the test requires.
- **Skeleton.** A pseudocode sketch.
- **Why now.** Whether this should be written soon or held.

Order is by recommended write order for the remaining backlog.

---

## Pending Test Coverage

**Model drift: signer-domain gating of user components and client-routed
cosigned simulation.**
The retired cosigned signing model (its surviving invariants are now in
[FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md](FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md)) and the
TLA+ sign-boundary and retired cosigned-assembly models predate two behaviors that are now
implemented and unit-tested but not yet modeled:

- user-role `/sign/component` runs the signer-domain approval gates (hard
  rejection, always-review, operator approval) before component signing
  (`internal/signerapp/signing/component_gate.go`),
- cosigned simulation runs ordinary user and cosigner component signing plus
  `/sign/assemble`, then sends the released executable group from the client to
  algod simulation (`internal/engine/cosigned/submit.go`).

The models remain sound for what they cover (assembly invariants, two-party
signature requirements); they under-approximate the gate sequence and the
post-assembly client route. A future audit pass should extend the cosigned
signing model with the gate states and assert that every released cosigned group
passed the same user gate regardless of whether the client submits or
simulates it. This gap is limited to the legacy `cosigner1` choreography;
`cosigned1` user-first ordering and assembly, for spends, cosigned rekeys and
listed rekeys, are covered by
[formal/bounded_cosigner.tla](formal/bounded_cosigner.tla). Its simulation route is
covered by the concrete Go test
`TestBoundedCosignerSimulateUsesUserFirstChoreography`; the TLA+ model does not
represent client submission or simulation transport.

**Model drift: SSH authentication boundary.**
Normal SSH connections authenticate possession of a supported enrolled public
key under username `aplane`. API connections carry its verified fingerprint,
and HTTP rechecks enrollment per request. There is no token proof stage or
header credential. Existing formal models do not model the SSH handshake;
a future transport model must describe this enrolled-key boundary.

**Model drift: lock-during-unlock race handling.**
The runtime lock state machine gained a lock-generation counter: `TryUnlock`
detects a `Lock()` that raced the unlock sequence, re-runs lock cleanup, and
fails with `LockedDuringUnlockMessage` (`internal/signerapp/runtime/runtime.go`).
The current formal inventory deliberately omits the lock/unlock state machine,
so no modeled invariant is affected; a future lock-state model must include
this generation-counter transition.

**Model drift: recovery state and the store-maintenance fence.**
The same lock state machine has since grown from a boolean to three states
(`SignerStateLocked`, `SignerStateUnlocked`, `SignerStateRecovery`) plus a
maintenance fence (`activeMaintenanceID` paired with the lock generation) in
`internal/signerapp/runtime/runtime.go`. Recovery is entered by
`TryRecoveryUnlock` when generation reconciliation or generation validation
fails during unlock: the store root opens but signing stays
blocked, and `PromoteRecoveryToUnlocked` is the only upward exit.
`BeginMaintenance`/`FinishMaintenance` bracket a store-wide passphrase change,
clearing published runtime state without emitting a user-visible lock decision
and refusing to republish if a `Lock()` raced the window.

No modeled invariant diverged, for two reasons worth recording because they are
load-bearing rather than incidental:

- Signing remains fail-closed because every sign-path gate tests `IsUnlocked()`,
  which is true only in `SignerStateUnlocked`; recovery is not a permissive
  state.
- `session_ownership.tla`'s SO2 (never stranded unlocked with nobody
  responsible) still holds because a recovery-blocked unlock returns
  `AuthOutcomeAuthenticated`, so the disconnect defer runs owner cleanup, and
  `Lock()` counts recovery as active (`wasActive`) and therefore performs the
  full lock transition. Both halves are asserted by
  `internal/signerapp/runtime/runtime_test.go::TestTryRecoveryBlocksSigningAndLockRunsCleanup`.
  A future lock-state model must preserve that collapse: if recovery ever
  stopped counting as active in `Lock()`, SO2's argument would break even
  though the spec text would still read as satisfied.

The maintenance fence adds no new concurrency actor because its only caller
brackets it inside `WithIdentityMutation`, the process-wide writer critical
section.

**Out of model: non-owning authenticate-without-unlock (`auth_only`).**
The admin protocol retains a second pre-auth message, `auth_only`, in the
current v6.0 surface. `auth_only`
(`internal/signerapp/adminserver/session.go` `AuthenticateOutcome`,
`internal/transport/protocol_flow.go` `authenticateOnly`) verifies the
passphrase and binds the session runtime but never authorizes or invokes
`identity.unlock`; `apadmin`'s read-only cosigner, generation-inventory, and
endpoint-settings reads use it. `session_ownership.tla`'s `AuthSucceed`
couples authentication to `unlocked' = TRUE`, so it now models the `auth`
message only.

The path is deliberately excluded from ownership: after authentication the
daemon clears its pending slot and serves it as a non-owning observer. It does
not promote or replace an active owner, receive approval notifications, fail
pending approvals, or run lock-on-disconnect cleanup. Because it changes none
of the model's ownership or lock-state variables, adding it as an
`AuthSucceed` variant would add a stuttering actor rather than widen the SO1/SO2
state space. Daemon lifecycle tests pin non-displacement and lock preservation;
adminserver tests pin the explicit server-side request allowlist.

The related non-blocking `store_busy` result
(`internal/signerapp/daemon/server.go` `tryWithStoreInspection`) is a plain `TryLock` on the
existing store-mutation lock with client-side retry in
`internal/apadminapp/catalog.go` (`requestInspectionWithRetry`). A failed
acquire never becomes in-flight
work, so it adds no actor and no new fairness obligation.

Otherwise, no actionable formal test gaps remain. Per-invariant status lives
in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md). Shutdown, key-session,
approval fail-all, and session-ownership contracts are covered by their Go
race tests and AP/SO formal invariants.

The former bounded DSA planning/argument-assembly drift entry is closed by
[formal/bounded_cosigner.tla](formal/bounded_cosigner.tla): its BS1-BS7 transition
system covers finalized classification, signer gates, user-first cosigner
routing, the listed rekey that skips the cosigner, exact target coverage,
source/path-mask assembly, canonical bytes, and atomic failure. Concrete effect classification,
slot encodings, Merkle derivation, and TEAL remain verified by Go/compiler tests
rather than abstracted as cryptographic or byte-level TLC claims.

The cosigned signing audit added the cosigned signing model (retired in phase 5
of the account overlays; its surviving invariants are in
[FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md](FORMAL_TLA_BOUNDED_COSIGNER_MODEL.md)) and
closed the new A-series gaps in the same pass. The focused tests added for that
audit cover:

- wrong user component signature rejection during `/sign/assemble`,
- passthrough signed-transaction txid mismatch rejection during
  `/sign/assemble`,
- direct `/sign` rejection for all cosigned account key types,
- malformed component-sign response rejection before forwarding opaque signatures
  to signer assembly.

## Deferred until design decision

No deferred gaps remain. Decisions previously parked here (S10
cross-read atomicity, S13 address-collision rejection) have shipped;
their resolutions are recorded in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) and the relevant
`FORMAL_*_MODEL.md` open-questions sections.

## Update Workflow

When closing a gap:

1. Add or rename the test to make the invariant's claim explicit.
2. Update the row's test anchor in
   [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md); promote the row to
   `implemented`.
3. Remove the corresponding entry from "Open Cross-Cutting Gaps" in
   the traceability doc.
4. Delete or strike through the entry in this file.

When opening a new gap:

1. Add the row to [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md)
   with status `implemented*` or `intended`.
2. Add an entry to "Open Cross-Cutting Gaps" in that file.
3. Add a numbered section here with a concrete skeleton.
