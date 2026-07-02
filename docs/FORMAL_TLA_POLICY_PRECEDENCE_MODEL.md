# Policy Precedence Machine-Checkable Model

> Status: TLC checked with no bounds (every domain is finite by
> construction); the recorded bounded run generated 64 distinct initial
> states and found no counterexamples for `Safety`.

This is the second machine-checkable artifact under the M4 milestone in
[FORMALIZATION_ROADMAP.md](FORMALIZATION_ROADMAP.md). It formalizes the
policy decision procedure from [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md)
and verifies the precedence ladder by deriving `verdict` from rule
application rather than treating it as a free oracle (which is what
[formal/sign_boundary.tla](formal/sign_boundary.tla) does for
`DenyOutputSuppression`).

The spec lives at [formal/policy_precedence.tla](formal/policy_precedence.tla).

## What it covers

| Invariant | Source | TLA+ predicate |
|---|---|---|
| P4: Deny Dominance | FORMAL_POLICY_MODEL.md | `P4_DenyDominance` |
| P5: Review Dominance Over Approval | FORMAL_POLICY_MODEL.md | `P5_ReviewDominance` |
| P6: Explicit Approval Only After Deny/Review Pass | FORMAL_POLICY_MODEL.md | `P6_ApproveAfterDenyReview` |
| P7: Operator Default Is Last | FORMAL_POLICY_MODEL.md | `P7_OperatorDefaultLast` |
| I9: Hard Deny Dominance | FORMAL_TXN_PLANNING_MODEL.md | `I9_HardDenyDominance` |
| Approval resolution table | (this module) | `ApprovalResolution` |

The I9 check is the centerpiece. The sign-boundary module's
`DenyOutputSuppression` predicate is true by construction of `Init`
(output is computed from a free-oracle verdict). Here `verdict` is
derived from rule matches and `outcome` from `verdict` plus approval
input, so the claim "matches.deny ⇒ outcome = rejected, regardless of
approval or user_auto_approve" becomes a real property that TLC
verifies over every input combination.

## What it deliberately does not cover

The module excludes anything not strictly needed for the precedence
ladder and I9:

- **Specific rule families.** `max_fee_microalgos`, transfer routing
  rules, `auto_approve_self_noop_transfer`, and others are abstracted
  into three boolean tier-match flags. The precedence properties don't
  depend on which rules fired, only on which tiers matched.
- **Rule-ID selection** when multiple rules in the same tier match
  (Open Question 1 in `FORMAL_POLICY_MODEL.md`). Orthogonal to
  precedence.
- **Transfer routing internals.** A routing-derived deny is just an
  `AlwaysDeny` match from this model's perspective.
- **Passthrough/foreign slot exclusion (P8).** Naturally checked in
  `sign_boundary.tla` via slot classes; abstracted away here.
- **Approval coordinator state machine.** The approval channel is a
  coarse four-valued input (`approve | reject | timeout | none`).
  Timeouts, cancellations, and mid-flight decommission belong to the
  deferred M3 approval-coordinator companion model.
- **Planned request shape.** Rule matches are an abstract function of
  "whatever the planned group looks like."
- **Snapshot stability (P1, P2).** Requires modeling reload as a
  transition; separate concern.

If you find yourself adding any of these to `policy_precedence.tla`,
stop and create a separate module instead.

## Modeling choices

### Rule-match abstraction

The most important choice. Each tier (`deny`, `review`, `approve`) is a
single boolean over the planned request. The model enumerates all
2³ = 8 combinations, including the "all three tiers match" case that
P4-P6 exclude.

The precedence ladder is about tier ordering, not within-tier behavior
or specific rule semantics. Modeling concrete rule families would
multiply the state space without adding coverage to the precedence
claim.

### Verdict derived, not enumerated

`verdict` and `outcome` are state variables, but their values are
determined by `Decide(matches, user_auto_approve)` and
`ApplyApproval(verdict, approval)` in `Init`. They are not separately
quantified. This is what gives I9 its teeth: the predicate
"matches.deny ⇒ outcome = rejected" is a non-trivial claim about the
derivation, not a tautology over a free oracle.

### One-shot model

Like `sign_boundary.tla`, this module is one-shot: `Init` enumerates
every input combination, and `Next` is a stutter. The checked
predicates are properties of a single signing decision, not of
sequences of decisions. If a future invariant requires reasoning across
multiple decisions (e.g. an operator changing `user_auto_approve`
between requests), the spec will need real next-state transitions.

### Approval as coarse input

`approval ∈ {"approve", "reject", "timeout", "none"}`. All non-approve
values produce a rejected outcome for review-class verdicts. The
distinction between `reject`, `timeout`, and `none` is preserved so
future audit-trail or approval-state-machine invariants can use them;
the precedence properties themselves do not depend on which non-approve
value is supplied.

## How to check

The spec is standard TLA+. To check it manually:

1. Install the TLA+ Toolbox or the `tla2tools` jar.
2. A ready-to-use TLC config lives at
   [formal/policy_precedence.cfg](formal/policy_precedence.cfg). It
   declares `SPECIFICATION Spec` and `INVARIANT Safety`. No constants
   are declared by the module — every domain is finite by construction.
3. Run TLC, e.g.:

   ```
   java -cp tla2tools.jar tlc2.TLC -config docs/formal/policy_precedence.cfg docs/formal/policy_precedence.tla
   ```

   The whole state space is enumerable without bounds; the run
   completes in under a second.

The recorded TLC run generated 64 distinct initial states, reached
depth 1, and found no counterexamples for `Safety`. Depth 1 is
expected: this is a one-shot model where `Next` only stutters. State
count matches the prediction (2³ × 2 × 4 = 64 input combinations).

The value is in re-running TLC when the spec changes — drift in the
decision procedure that violates P4-P7 or I9 will surface as a
counterexample trace.

## What this proves vs. doesn't

**Proves:**

- The decision procedure (`Decide`) produces the right verdict for every
  combination of tier matches and operator default. Checked via P4-P7.
- The approval-resolution step (`ApplyApproval`) maps every (verdict,
  approval) pair to the right outcome. Checked via `ApprovalResolution`.
  P4-P7 alone constrain `verdict` but say nothing about how each verdict
  resolves to an outcome under different approval inputs; without
  `ApprovalResolution`, a regression like `ApplyApproval("Review",
  "approve") -> "rejected"` would slip through.
- I9 (Hard Deny Dominance) holds: an Always Deny match always rejects,
  regardless of approval response, regardless of operator default,
  regardless of which other tiers also match.
- P4-P7 follow by construction from the short-circuit decision procedure
  ordering.

**Does not prove:**

- The Go implementation matches this spec. That is the test suite's
  job; the I9 row in [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md)
  points at `TestSignGroupWithPlanUserAutoApproveStillRejectsPolicyViolation`
  and related tests.
- Properties involving specific rule families. The abstract matches
  cover precedence, not rule semantics.
- Snapshot stability (P1, P2), passthrough/foreign scope (P8), routing
  verdict exclusion (P9), or auth-key-type selection (P10). These would
  require additional state or composition with other modules.
- That the sign-boundary output rules hold under a real (non-oracle)
  verdict. That is the composition with `sign_boundary.tla` discussed
  below.

## Linking back

- [FORMAL_POLICY_MODEL.md](FORMAL_POLICY_MODEL.md) is the source of
  truth for the policy decision procedure and the P4-P7 invariants.
  This module is a precision layer on top of those, not a replacement.
- [FORMAL_TXN_PLANNING_MODEL.md](FORMAL_TXN_PLANNING_MODEL.md) is the
  source for I9. The English statement (in §I9) is now a TLC-verified
  claim under this module.
- [FORMAL_TRACEABILITY.md](FORMAL_TRACEABILITY.md) Machine-Checkable
  Coverage section records which invariants have TLA+ predicates and
  whether TLC has run.
- [FORMAL_TLA_SIGN_BOUNDARY_MODEL.md](FORMAL_TLA_SIGN_BOUNDARY_MODEL.md)
  is the first machine-checkable artifact; its extension plan listed
  this module as the next slice.

## Extension plan

Already shipped:

- **Composition with `sign_boundary.tla`.**
  [formal/composition.tla](formal/composition.tla) joins the two
  modules. The verdict that `sign_boundary` treats as a
  free oracle is here derived through `policy_precedence`, and the
  joint Init feeds that derived outcome into sign-boundary's output
  computation. The bridge invariant `PolicyOutcomeBindsOutput` ties
  policy outcome to signing output; sign-boundary's
  `DenyOutputSuppression` is a derived consequence of running
  real precedence on rule matches. See
  [FORMAL_TLA_COMPOSITION_MODEL.md](FORMAL_TLA_COMPOSITION_MODEL.md).

Already shipped (continued):

- **Lifecycle lease.** [formal/lifecycle.tla](formal/lifecycle.tla)
  models `BeginOperation` / `Decommission` as real transitions and
  verifies L4-L7 plus the writer-priority RWMutex ordering. See
  [FORMAL_TLA_LIFECYCLE_MODEL.md](FORMAL_TLA_LIFECYCLE_MODEL.md).

Next likely modules, in order of value:

1. **Lifecycle-aware composition** — *shipped* as
   [formal/lifecycle_composition.tla](formal/lifecycle_composition.tla)
   ([FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md](FORMAL_TLA_LIFECYCLE_COMPOSITION_MODEL.md)):
   it checks end to end that lifecycle unavailability admits no new signer
   output.
2. **Approval coordinator (M3 prerequisite).** State machine for
   pending approvals, including timeout and cancellation. Would refine
   the four-valued `approval` input into a proper transition system.
3. **Reload-during-request stability.** Adds real transitions to the
   composition module so that reloads between approval and final-sign
   do not change the snapshot used by the request.

The current `policy_precedence.tla` should not absorb any of these;
each gets its own module and either composes or refines.
