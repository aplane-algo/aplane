# Lifecycle-Aware Composition Machine-Checkable Model

> Status: TLC checked with `SignerProcs = {s1, s2}`, `admin = a`, `NONE = none`,
> and symmetry over the signers; the recorded run generated 226 distinct states,
> reached depth 12, and found no counterexamples for `Safety`. The liveness run
> (`lifecycle_composition_liveness.cfg`, no symmetry — TLC liveness checking is
> unsound under symmetry reduction) generated 392 distinct states at depth 12
> and verified the `Progress` temporal property under `LiveSpec` (weak fairness
> per signer on `SignerSign` and `SignerRelease` and on the admin decommission
> steps): every held lease eventually completes — no accepted request is left
> forever neither signed nor rejected — and a queued decommission finishes.
> Mutation: dropping the `SignerSign` fairness conjunct (a holding signer that
> never signs) produces a lasso counterexample. The writer-starvation dimension
> is exercised in `lifecycle_liveness.cfg`, not duplicated here.

This is the seventh machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). It joins the temporal
lifecycle lock model ([formal/lifecycle.tla](formal/lifecycle.tla)) with the
signing-output layer to machine-check the end-to-end claim that a signer produces
signing output only while holding a lifecycle lease it acquired before
decommission — "lifecycle unavailability implies no new signer output."

The spec lives at [formal/lifecycle_composition.tla](formal/lifecycle_composition.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| L4: Final signing uses runtime lease | FORMAL_LIFECYCLE_MODEL.md | `L4_LeaseGatesSigning` |
| L5: Decommission waits for held lease | FORMAL_LIFECYCLE_MODEL.md | `L5_DecommissionWaitsForHeldLease` |
| L6: Decommission wins race before lease | FORMAL_LIFECYCLE_MODEL.md | `L6_NoAcquireAfterDecommission` |
| L7: Registry removal doesn't prevent completion | FORMAL_LIFECYCLE_MODEL.md | `L7_RegistryRemoveDoesNotPreventCompletion` |
| Output requires a held lease + signing policy | (seam) | `LifecycleGatesOutput` |
| A rejected (post-decommission) signer produces no output | (seam) | `RejectedProducesNoOutput` |

The headline is the **end-to-end lifecycle gate**: `lifecycle.tla` proved the
lock-ordering race (L4–L7) but stopped at the lease; this module adds a per-signer
`Sign` step, gated on holding the lease, and checks that signing output exists only
for a signer that (a) held a lease it acquired while not decommissioned, and (b)
had a signing policy decision. Combined with L6 (no acquire after decommission), a
signer that arrives after the decommission mark is rejected and produces no output
— "lifecycle unavailability implies no new signer output."

Validated by mutation test: making `SignerSign` set output unconditionally
(ignoring `policySigned`) produces a counterexample where a signer signs without a
signing policy decision. The restored spec passes.

## Modeling choices

### Temporal base, abstracted policy

This is a temporal-transition spec (real `Next`, like `lifecycle.tla`): two signer
processes and one admin race over the writer-priority RWMutex, and each holding
signer signs before releasing. The policy/approval pipeline is **not** re-modeled
here; its decision is consumed as the per-signer boolean `policySigned`, whose
derivation is machine-checked in [formal/composition.tla](formal/composition.tla)
and [formal/approval_composition.tla](formal/approval_composition.tla). This is the
same factoring `approval_composition.tla` uses to consume the coordinator's
terminal outcome: each layer's internals stay in their own module, and this module
checks only the new seam — the lease gate on signing output. It is also how the
roadmap's "temporal-vs-one-shot reconciliation" is resolved: the temporal layer
(this lock race) stays temporal, and the one-shot policy layer is consumed as a
boolean rather than merged transition-by-transition.

### The lease is held through signing

A signer takes the read lease at `SignerAcquire` (Holding), signs at `SignerSign`
(Signed, still holding), and releases at `SignerRelease` (Done). `readers` is tied
to the `{Holding, Signed}` signers in `TypeOK`, so `AdminAcquireWrite` (which
requires `readers = {}`) cannot proceed while a signer is mid-sign — preserving L5.

### Copied operators

The lifecycle lock operators are copied from `lifecycle.tla`, not imported. Keeping
the copies in sync is handled by `make formal-copy-sync-check`, which also runs
before TLC in `make formal-test`.

## How to check

```sh
make formal-test TLA2TOOLS_JAR=/path/to/tla2tools.jar
```

or directly:

```sh
java -jar tla2tools.jar -config docs/formal/lifecycle_composition.cfg \
    docs/formal/lifecycle_composition.tla
```

Expected: `Model checking completed. No error has been found.`, 226 distinct
states, depth 12.

## What this proves vs. doesn't

It proves, over every interleaving of two signers and an admin, that the lifecycle
invariants L4–L7 still hold when signing is modeled, and that signing output is
gated on both a validly-acquired lease and a signing policy decision — so a
decommissioned runtime admits no new signer output. It does not re-prove the
policy/approval derivation (that is `composition.tla` / `approval_composition.tla`,
consumed here as `policySigned`) and it does not add liveness (that a signer
eventually completes). The lock operators are kept in sync with `lifecycle.tla` by
the copied-operator sync check before TLC runs.

## Linking back

- Lock model: [formal/lifecycle.tla](formal/lifecycle.tla),
  [FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md).
- Policy → output pipeline: [formal/composition.tla](formal/composition.tla),
  [FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md), and the
  approval seam [formal/approval_composition.tla](formal/approval_composition.tla).
