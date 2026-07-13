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

**Model drift: signer-domain gating of user components and contained guarded
simulation.**
[FORMAL_GUARDED_SIGNING_MODEL.md](FORMAL_GUARDED_SIGNING_MODEL.md) and the
TLA+ sign-boundary/guarded-assembly models predate two behaviors that are now
implemented and unit-tested but not yet modeled:

- user-role `/sign/component` runs the signer-domain approval gates (hard
  rejection, always-review, operator approval) before component signing
  (`internal/signerapp/signing/component_gate.go`),
- `/simulate/guarded` produces user component signatures in-process with
  simulation gate semantics and never releases them or assembled bytes
  (`internal/signerapp/signing/guarded_simulate.go`).

The models remain sound for what they cover (assembly invariants, two-party
signature requirements); they under-approximate the gate sequence. A future
audit pass should extend the guarded signing model with the gate states and
add the containment invariant: no submittable guarded bytes exit the signer
unless the user gate approved a non-simulation request.

**Model drift: SSH authentication boundary.**
The runtime now authenticates normal SSH connections with verified public-key
partial success followed by a mutual, host-key-and-nonce-bound token proof.
Clients also enforce a postcondition that rejects servers which skip the proof
stage. Existing formal models do not model SSH transport authentication, so no
modeled invariant changed, but any future transport-boundary model must use
this two-stage boundary rather than the former token-in-username assumption.

Otherwise, no actionable test gaps remain. Per-invariant status lives in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md). The lifecycle L4-L7
audit is closed by the explicit lease-release and writer-pending tests
named in the L4 and L5 rows.

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
