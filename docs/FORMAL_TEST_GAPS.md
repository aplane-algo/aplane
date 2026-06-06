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

No actionable test gaps remain. Per-invariant status lives in
[FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md). The lifecycle L4-L7
audit is closed by the explicit lease-release and writer-pending tests
named in the L4 and L5 rows.

The attested signing audit added
[FORMAL_ATTESTED_SIGNING_MODEL.md](FORMAL_ATTESTED_SIGNING_MODEL.md) and
closed the new A-series gaps in the same pass. The focused tests added for that
audit cover:

- wrong user component signature rejection during `/sign/assemble`,
- passthrough signed-transaction txid mismatch rejection during
  `/sign/assemble`,
- direct `/sign` rejection for both attested account key types,
- malformed component-sign response rejection before local attestor signature
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
