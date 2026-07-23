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
guarded simulation.**
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) and the
TLA+ sign-boundary/guarded-assembly models predate two behaviors that are now
implemented and unit-tested but not yet modeled:

- user-role `/sign/component` runs the signer-domain approval gates (hard
  rejection, always-review, operator approval) before component signing
  (`internal/signerapp/signing/component_gate.go`),
- guarded simulation runs ordinary user and sentry component signing plus
  `/sign/assemble`, then sends the released executable group from the client to
  algod simulation (`internal/engine/guarded/submit.go`).

The models remain sound for what they cover (assembly invariants, two-party
signature requirements); they under-approximate the gate sequence and the
post-assembly client route. A future audit pass should extend the guarded
signing model with the gate states and assert that every released guarded group
passed the same user gate regardless of whether the client submits or
simulates it. This gap is limited to the legacy `sentry1` choreography;
`bounded-sentry1` user-first ordering and assembly are covered by
[formal/bounded_sentry.tla](formal/bounded_sentry.tla). Its simulation route is
covered by the concrete Go test
`TestBoundedSentrySimulateUsesUserFirstChoreography`; the TLA+ model does not
represent client submission or simulation transport.

**Model drift: SSH authentication boundary.**
The runtime now authenticates normal SSH connections with verified public-key
partial success followed by a mutual, host-key-and-nonce-bound token proof.
Clients also enforce a postcondition that rejects servers which skip the proof
stage. Existing formal models do not model SSH transport authentication, so no
modeled invariant changed, but any future transport-boundary model must use
this two-stage boundary rather than the former token-in-username assumption.

**Model drift: lock-during-unlock race handling.**
The runtime lock state machine gained a lock-generation counter: `TryUnlock`
detects a `Lock()` that raced the unlock sequence, re-runs lock cleanup, and
fails with `LockedDuringUnlockMessage` (`internal/signerapp/runtime/runtime.go`).
The lifecycle models deliberately omit the lock/unlock state machine (only
decommission's lock-interacting steps are modeled), so no modeled invariant is
affected; a future lock-state model must include this generation-counter
transition.

Otherwise, no actionable test gaps remain. Per-invariant status lives in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md). The lifecycle L4-L7
audit is closed by the explicit lease-release and writer-pending tests
named in the L4 and L5 rows.

The former bounded DSA planning/argument-assembly drift entry is closed by
[formal/bounded_sentry.tla](formal/bounded_sentry.tla): its BS1-BS7 transition
system covers finalized classification, signer gates, user-first sentry
routing, exact target coverage, source/path-mask assembly, canonical bytes,
the external-admin bypass, and atomic failure. Concrete effect classification,
slot encodings, Merkle derivation, and TEAL remain verified by Go/compiler tests
rather than abstracted as cryptographic or byte-level TLC claims.

The guarded signing audit added
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) and
closed the new A-series gaps in the same pass. The focused tests added for that
audit cover:

- wrong user component signature rejection during `/sign/assemble`,
- passthrough signed-transaction txid mismatch rejection during
  `/sign/assemble`,
- direct `/sign` rejection for all guarded account key types,
- malformed component-sign response rejection before local sentry signature
  verification.

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
