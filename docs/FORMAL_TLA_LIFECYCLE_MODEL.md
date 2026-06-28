# Lifecycle Machine-Checkable Model

> Status: TLC checked with `SignerProcs = {s1, s2}`, `admin = a`,
> `NONE = none`, and symmetry over the signer set; the recorded run
> generated 48 distinct reachable states, reached depth 10, and found
> no counterexamples for `Safety`.

This is the fourth machine-checkable artifact under the M4 milestone
in [FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). It models the
lifecycle lock-ordering claims from
[FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md): the race
between a signer holding the read side of the lifecycle lock via
`BeginOperation`, and an admin acquiring the write side via
`Decommission`.

The spec lives at [formal/lifecycle.tla](formal/lifecycle.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| L4: Final Signing Uses Runtime Lease | FORMAL_LIFECYCLE_MODEL.md | `L4_LeaseGatesSigning` |
| L5: Decommission Waits For Held Lease | FORMAL_LIFECYCLE_MODEL.md | `L5_DecommissionWaitsForHeldLease` |
| L6: Decommission Wins Race Before Lease | FORMAL_LIFECYCLE_MODEL.md | `L6_NoAcquireAfterDecommission` |
| L7: Registry Removal Doesn't Prevent Completion | FORMAL_LIFECYCLE_MODEL.md | `L7_RegistryRemoveDoesNotPreventCompletion` |
| RWMutex exclusion + state consistency | (TypeOK) | `TypeOK` |

L4 and L6 are checked via history variables (`heldEver` and
`badAcquireAfterDecommission`). L5 is a direct state predicate. L7
uses `ENABLED`-style reasoning over the
`SignerCompleteAndRelease` action.

The L5 invariant has been validated by mutation testing: removing the
`readers = {}` guard from `AdminAcquireWrite` produces a 4-step TLC
counterexample where a signer holds the read side while the admin
grabs the write side. The restored spec passes.

## What it deliberately does not cover

- **L1** (Decommission is Logical), **L2** (Persist Before Runtime
  Disable), **L3** (Decommissioned Rejects New Work), **L9** (Watcher
  Stops On Decommission), **L10** (Startup Skips Stored-Decommissioned
  Identities), **L11** (Reload Step Order Is Fixed). These are
  sequential properties already covered by Go tests; not concurrency
  claims, and not worth the modeling cost here.
- **L8** (Pending Approvals Fail On Successful Decommission).
  Deferred to a future approval-coordinator model. The claim
  crosses the lifecycle/approval boundary — pending approvals are
  owned by the approval coordinator, not the lifecycle subsystem —
  and needs an explicit state machine for pending approvals to model
  meaningfully. Currently covered by `TestDecommissionFailsPendingApprovals`
  in Go.
- The full 9-step Decommission sequence. Only the steps that interact
  with the lock (acquire write, set `decommissioned`, release) are
  modeled. Persistence failure, runtime locking, watcher stop, and
  pending-approval cleanup are out of scope.
- The signer's actual signing work. Holding the lease and then
  releasing it is enough for the lock-ordering claim; what happens
  during the held window is opaque.
- Liveness. Showing `Decommission` *eventually* completes when admins
  are fair is a real follow-up but requires fairness assumptions.
  Safety-only first slice.
- Composition with `sign_boundary`, `policy_precedence`, or
  `composition`. Those are one-shot Init-only specs; composing a
  temporal-transition model with them requires re-architecting the
  composition spec. Separate slice if desired.
- Multiple identities or the approval coordinator state machine.

If those concerns become security-critical for a particular check,
add a separate module rather than extending this one.

## Modeling choices

### Real transitions, not one-shot

Unlike the first three TLA+ modules (sign_boundary, policy_precedence,
composition) which are one-shot Init-only specs, this module has a
real `Next` relation. Two signer processes and one admin process race
over a writer-priority RWMutex. The state space is small thanks to
symmetry reduction (48 reachable states), but the temporal-transition
structure is the key novelty.

### Process abstraction

Two signer processes (`s1`, `s2`) and one admin process (`a`).

- Two signers is the minimum to exercise the "one signer holds while
  another tries to acquire" interleaving.
- One admin is enough because the admin's sequence is the same
  regardless of how many admins exist serially.
- Signer processes are assumed to already hold a Runtime pointer
  before calling `BeginOperation`. This matches the production code:
  an in-flight HTTP request has already resolved its identity through
  the registry. The `registry_member` flag and `AdminRegistryRemove`
  action exist to verify L7's claim that already-resolved runtime
  pointers remain useful even after registry removal. The model
  deliberately does not represent the registry-lookup step itself.

### Writer-priority RWMutex

Go's `sync.RWMutex` is writer-priority: once `Lock()` is called and
readers exist, subsequent `RLock()` calls block until the writer has
acquired and released. The model encodes this via the `WriterPending`
predicate, which `SignerAcquire` checks alongside `writer = NONE`.
Without this, TLC would explore interleavings where new signers
acquire the read side while admin is already queued — interleavings
the production code does not permit.

### History variables for L4 and L6

- `heldEver[s]` is set `TRUE` when a signer first transitions to
  `"Holding"`. Used by `L4_LeaseGatesSigning` to assert that no
  signer reaches `"Done"` without having held the lease. Direct
  state-predicate check, not a structural argument.
- `badAcquireAfterDecommission` is updated in the Holding-branch of
  `SignerAcquire` to `badAcquireAfterDecommission \/ decommissioned`.
  Under the current spec the disjunct is tautologically `FALSE`
  because the action's own guard requires `~decommissioned`. The
  explicit assignment is the load-bearing piece: if a future spec
  edit weakens or removes the guard, the disjunct fires and TLC
  reports `L6_NoAcquireAfterDecommission` violated.

### Consistency in `TypeOK`

The model has two redundant lock-state representations: `readers` +
`writer` (the RWMutex state) and `procState` (the per-process state
machine). `TypeOK` includes consistency clauses:

```text
readers = {s \in SignerProcs : procState[s] = "Holding"}
(writer = admin) <=> (procState[admin] \in {"WriteHeld", "Marked"})
```

These tie the redundant representations together. Without them, a
future spec edit could update one without the other and slip past
the higher-level invariants.

### `NONE` as a model-value constant

`NONE` is declared as a `CONSTANT` and bound to a TLC model value in
the cfg, alongside `admin` and `SignerProcs`. This keeps it
deliberately separate from string literals and lets TLC handle
symmetry cleanly.

### Symmetry reduction

The cfg declares `SYMMETRY SignerSymmetry`, with `SignerSymmetry`
defined in the spec as `Permutations(SignerProcs)`. TLC treats any
swap of `s1 <-> s2` as the same state, halving the reachable state
count. The 48-state result reflects this reduction.

### Deadlock checking disabled

The lifecycle workflow naturally terminates: admin reaches
`"Finished"`, both signers reach `"Done"` or `"Rejected"`,
`registry_member` is `FALSE`. With no actions enabled in the terminal
state, TLC's default deadlock check would flag this as an error. The
cfg sets `CHECK_DEADLOCK FALSE` because this is a workflow-completion
model, not a continuously-running system. Safety is what we care
about; termination of the workflow is not an error condition.

## How to check

The spec is standard TLA+. To check it manually:

1. Install the TLA+ Toolbox or the `tla2tools` jar.
2. A ready-to-use TLC config lives at
   [formal/lifecycle.cfg](formal/lifecycle.cfg). It declares
   `SPECIFICATION Spec`, sets `CONSTANTS SignerProcs = {s1, s2},
   admin = a, NONE = none`, enables `SYMMETRY SignerSymmetry`,
   disables `CHECK_DEADLOCK`, and asks for `INVARIANT Safety`.
3. Run TLC, e.g.:

   ```
   java -cp tla2tools.jar tlc2.TLC -config docs/formal/lifecycle.cfg docs/formal/lifecycle.tla
   ```

The recorded TLC run generated 48 distinct reachable states, reached
depth 10, and found no counterexamples for `Safety`. The depth
matches the longest interleaving sequence (admin's 5-step lifecycle
+ a few signer interleavings + the registry-remove step).

## What this proves vs. doesn't

**Proves:**

- L4: No signer reaches `"Done"` without having held the lease.
- L5: While any signer holds the read side, the admin cannot have
  acquired the write side. TLC verifies this under every
  interleaving, not just the ones tests happen to exercise.
- L6: No signer transitions `Idle -> Holding` while `decommissioned`
  is `TRUE`. Currently structural (guarded by the action) but pinned
  by the regression-guard flag.
- L7: A signer holding the read side can always complete its work,
  regardless of `registry_member` state. TLC verifies this stays true
  after `AdminRegistryRemove` has fired in arbitrary interleavings.
- RWMutex exclusion: a writer and any reader cannot hold the lock
  simultaneously.

**Does not prove:**

- The Go implementation matches this spec. That is the test suite's
  job; the L4–L7 row anchors in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) name the relevant
  tests.
- Liveness: `Decommission` *eventually* completes when admins are
  fair. The spec models stutter via `[Next]_vars` and does not
  encode fairness.
- L1, L2, L3, L8–L11. Out of scope as documented above.
- Composition with the other three modules. A future composition
  module could join lifecycle-aware state with sign-boundary output
  (e.g., when admin reaches `Finished` and `decommissioned` is set,
  signer output should be empty).

## Linking back

- [FORMAL_LIFECYCLE_MODEL.md](FORMAL_LIFECYCLE_MODEL.md) is the
  English source for L1–L11. This module is a precision layer over
  L4–L7 specifically.
- [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) Machine-Checkable
  Coverage section records the L4–L7 anchors.
- [FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](FORMAL_TLA_SIGN_BOUNDARY_MODEL.md),
  [FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md),
  and [FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md)
  are the prior modules; this module adds the lifecycle slice.

## Extension plan

Already shipped: this module.

Next likely modules, in order of value:

1. **Lifecycle-aware composition.** Compose this module with the
   existing composition module so that lifecycle unavailability
   (admin `Finished` and `decommissioned`) forces empty signer
   output. Requires reconciling temporal-transition state with
   one-shot Init state — non-trivial but valuable.
2. **Approval coordinator state machine (M3 prerequisite).** Models
   pending approvals, timeouts, cancellations, and mid-flight
   decommission. Would compose with this lifecycle module to verify
   L8 (pending approvals fail on successful decommission).
3. **Liveness.** Add weak fairness on `AdminAcquireWrite` and
   `AdminMarkDecommissioned`; verify that `Decommission` eventually
   completes given fair admin progress. Safety-only is the right
   first slice; liveness is a meaningful follow-up.

The current `lifecycle.tla` should not absorb any of these; each gets
its own module and either composes or refines.
