# Composition Machine-Checkable Model

> Status: TLC checked with `MaxRequestEntries = 3` and `MaxDummies = 2`;
> the recorded bounded run generated 84,096 distinct initial states and
> found no counterexamples for `Safety`.

This is the third machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). It joins
[formal/sign_boundary.tla](formal/sign_boundary.tla) and
[formal/policy_precedence.tla](formal/policy_precedence.tla): the verdict
that `sign_boundary` treats as a free oracle is here
derived by running `policy_precedence` on rule matches and operator
default, and the joint Init feeds that derived outcome into
`sign_boundary`'s output computation.

The spec lives at [formal/composition.tla](formal/composition.tla).

## What it covers

The composition module checks mostly seam properties, plus a small
number of sign-boundary output rules re-verified under the derived
policy outcome. Each component module runs TLC on its own Init/Safety
and checks its own internal properties; the composition does not
duplicate those.

| Joint claim | TLA+ predicate | Kind |
|---|---|---|
| Policy outcome binds signing output | `PolicyOutcomeBindsOutput` | Seam |
| Hard deny produces no output (real I9 over full pipeline) | `HardDenyProducesNoOutput` | Seam |
| Signed output requires policy approval | `SignedOutputRequiresPolicyApproval` | Seam |
| Foreign slots remain empty under derived verdict | `ForeignSlotsEmpty` | Recheck |
| Passthrough bytes remain preserved under derived verdict | `PassthroughPreserved` | Recheck |

The three **seam** rows only exist because the two modules are joined
in this file — none of them is meaningful in either component module
alone. The two **recheck** rows are properties already verified in
`sign_boundary.tla` under a free-oracle verdict; they are re-checked
here against the derived verdict so a regression that breaks them
specifically under real policy precedence would still be caught.
(Strictly speaking, since the slot-class structure of `planned` is
unchanged by the verdict source, the recheck rows are guaranteed to
hold whenever they held in sign-boundary. They are kept as cheap
regression guards rather than because new behavior is being verified.)

`HardDenyProducesNoOutput` is the most consequential of the seam
properties. In `sign_boundary.tla` the analogous
`DenyOutputSuppression` predicate is true by construction of `Init`
(output is computed from a free oracle verdict). Here the verdict is
derived from rule matches through `policy_precedence`, so the
deny-to-no-output property is a real derived consequence rather than
a tautology.

## What it deliberately does not cover

- Component-internal invariants. P4-P7, I9, ApprovalResolution, I1, I2,
  I3, I7, I8, OutputAligned, SignerOutputBelongsToOwnedClass — these
  are all checked by their respective modules and not duplicated here.
- Specific rule families, transfer routing internals, rule-ID
  selection: same scope decisions as
  [FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md).
- Approval coordinator state machine: same coarse four-valued input
  as the policy-precedence module.
- Lifecycle leases, snapshot stability across reload, planning details
  beyond the request-mode trichotomy and dummy appending.

If those concerns become security-critical for a particular check, add
a separate module rather than extending this one.

## Modeling choices

### Operators copied, not imported

TLA+'s `EXTENDS` would inherit variables from both component modules
(both modules declare a `verdict` variable, which would collide).
`INSTANCE` with renaming works but adds parameterization machinery for
what is structurally a small module. Since both component modules are
small and the operators are pure functions (`Plan`, `SignOutput`,
`Decide`, `ApplyApproval`, plus a few domain definitions), copying
them keeps this module self-contained and readable.

If `sign_boundary.tla` or `policy_precedence.tla` changes its
operators or domains, this module must be updated to match. TLC
cannot detect this kind of drift: the three modules are independent
specs, and a stale copy here can still pass against its own (stale)
definitions while the component modules pass against the new ones.
Running all three through TLC catches *internal* inconsistency within
each module, not divergence between modules. Copy drift is checked by
`make formal-copy-sync-check`, which also runs before TLC in
`make formal-test`. If deeper mechanical linkage becomes important,
the right move is to extract the shared operators into a fourth module
and have all three modules `INSTANCE`-import from it.

### The bridge

The single point of bridging is in `Init`:

```text
output = IF policy_outcome = "signed"
         THEN SignOutput(request, planned)
         ELSE <<>>
```

`sign_boundary.tla` uses:

```text
output = IF verdict = "approve" THEN SignOutput(...) ELSE <<>>
```

with `verdict \in {"deny", "approve"}` as a free oracle. The
composition replaces the oracle with `policy_outcome`, which is
derived from `Decide` and `ApplyApproval` running on
`policy_precedence`'s inputs (`matches`, `user_auto_approve`,
`approval`).

### State space

With `MaxRequestEntries = 3` and `MaxDummies = 2`, the composition has
roughly `(sign_boundary inputs) x (policy_precedence inputs)` states.
The recorded bounded run generated 84,096 distinct initial states.
That is the multiplicative product of the two component state spaces
minus deduplication. TLC enumerates the full space in under a second.

If a future invariant requires reasoning across multiple decisions
(e.g. a sequence of requests, or an operator changing
`user_auto_approve` between requests), this will need real next-state
transitions. The current `Next` is a stutter.

## How to check

The spec is standard TLA+. To check it manually:

1. Install the TLA+ Toolbox or the `tla2tools` jar.
2. A ready-to-use TLC config lives at
   [formal/composition.cfg](formal/composition.cfg). It declares
   `SPECIFICATION Spec`, sets `MaxRequestEntries = 3` and
   `MaxDummies = 2`, and asks for `INVARIANT Safety`.
3. Run TLC, e.g.:

   ```
   java -cp tla2tools.jar tlc2.TLC -config docs/formal/composition.cfg docs/formal/composition.tla
   ```

The recorded TLC run at these bounds generated 84,096 distinct initial
states, reached depth 1, and found no counterexamples for `Safety`.
Depth 1 is expected: this is a one-shot model where `Next` only
stutters.

## What this proves vs. doesn't

**Proves:**

- The bridge between `policy_precedence` and `sign_boundary` holds:
  signer output structure exactly tracks policy outcome.
- Hard deny dominance is preserved end-to-end. An `AlwaysDeny` match
  produces no signer-produced output, regardless of approval response,
  operator default, or which other tiers also match.
- The signed-output direction also holds: any non-empty signer output
  implies the policy outcome was `"signed"`.
- Sign-boundary's per-slot output rules (`ForeignSlotsEmpty`,
  `PassthroughPreserved`) continue to hold when the verdict source is
  the real `policy_precedence` derivation rather than a free oracle.

**Does not prove:**

- The Go implementation matches this spec. That is the test suite's
  job; the relevant test anchors are listed in
  [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md).
- The component invariants. P4-P7, I9, ApprovalResolution, I1, I2,
  I3, I7, I8, OutputAligned, SignerOutputBelongsToOwnedClass are
  checked by their respective modules under their own Init/Safety.
- Properties involving specific rule families, transfer routing
  internals, or lifecycle/snapshot transitions.

## Linking back

- [FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](FORMAL_TLA_SIGN_BOUNDARY_MODEL.md)
  is the first module. Its extension plan covers this composition step.
- [FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md](FORMAL_TLA_POLICY_PRECEDENCE_MODEL.md)
  is the second module. Its extension plan also covers this composition
  step.
- [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) Machine-Checkable
  Coverage section records the run state count, depth, and result for
  this module.
- [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md) and
  [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md) are the English
  sources for the invariants exercised here.

## Extension plan

Already shipped:

- **Lifecycle lease.** [formal/lifecycle.tla](formal/lifecycle.tla)
  models `BeginOperation` / `Decommission` as real transitions and
  verifies L4-L7 plus the writer-priority RWMutex ordering. It is
  the first temporal-transition spec; composing it with this
  one-shot composition module is a separate, harder slice. See
  [FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md).

Next likely TLA+ modules, in order of value:

1. **Lifecycle-aware composition** — *shipped* as
   [formal/lifecycle_composition.tla](formal/lifecycle_composition.tla)
   ([FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md](FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md)):
   a lease-gated signing step on the lifecycle race that checks lifecycle
   unavailability admits no new signer output, consuming the policy decision
   as a boolean rather than merging the one-shot pipeline.
2. **Approval coordinator state machine (M3 prerequisite).** State
   machine for pending approvals, including timeout and cancellation.
   Would refine the four-valued `approval` input here into a proper
   transition system.
3. **Reload-during-request stability.** Adds real transitions to the
   composition: a reload between approval and final-sign should not
   change the snapshot used by the request. This is the P2 leg that
   the Go test `TestSignGroupWithPlanDoesNotReevaluatePolicyAfterApproval`
   currently covers; promoting it into a TLA+ refinement check is the
   natural future move.

The current `composition.tla` should not absorb any of these; each
gets its own module and either composes or refines.
